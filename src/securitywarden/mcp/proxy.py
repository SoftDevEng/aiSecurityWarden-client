"""The approval proxy: any MCP server's tools, behind SecurityWarden's action gate.

A **mapping file** (``*.swproxy``, JSON, format ``sw-proxy/1``) says how to reach the upstream MCP server (a local
program over stdio, or an https URL) and which of its tools are which actions::

    {"format": "sw-proxy/1", "name": "github", "title": "GitHub", "secrets": ["GITHUB_PAT"],
     "upstream": {"stdio": {"command": "github-mcp-server", "args": ["stdio"],
                            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${secret:GITHUB_PAT}"}}},
     "tools": {"create_issue": {"action": "github.issue.create", "risk": "medium",
                                "scope": {"repo": "{owner}/{repo}"},
                                "summary": {"title": "Open an issue in {owner}/{repo}", "fields": [["Title", "{title}"]],
                                            "preview": "{body}"}}},
     "hide": [], "suggested_rules": ["github.read.*=allow", "*=each"]}

``sw-mcp`` turns a mapping into a connector class (:func:`proxy_class`), so everything connectors have applies:
waiting for approval, ``check_approval``, deny with comment, the digest binding exactly what is forwarded, rules,
and results returned as untrusted content. The upstream's credential is a project secret; it goes only into the
upstream's environment or request headers, never to the agent.

Tools the mapping doesn't name are offered as ``<name>.unmapped.<tool>`` (read-only ones as
``<name>.unmapped.read.<tool>``), so a rule like ``github.read.*=allow`` never covers them: the upstream's own
"read-only" hint can't loosen anything. See DESIGN.md "Approval proxy".
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from typing import Any, Callable, ClassVar

from ..approval import ACTION_RE, RISKS, SUMMARY_LIMITS, clip
from .framework import Connector, Plan, Summary, ToolError, ToolSpec, untrusted

FORMAT = "sw-proxy/1"
EXTENSION = ".swproxy"
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
SECRET_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
SECRET_REF_RE = re.compile(r"\$\{secret:([A-Za-z_][A-Za-z0-9_]{0,63})\}")
TEMPLATE_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]{0,63})\}")
SCOPE_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
MAX_MAPPING_BYTES = 256 * 1024
MAX_TOOLS = 500
MAX_RESULT_CHARS = 200_000
PROTOCOL = "2025-06-18"
CALL_TIMEOUT = 120.0
START_TIMEOUT = 30.0


class MappingError(ValueError):
    pass


# ---------------------------------------------------------------------------
# the mapping file
# ---------------------------------------------------------------------------

def _str_list(v: Any, what: str, limit: int = 200) -> list[str]:
    if v is None:
        return []
    if not isinstance(v, list) or len(v) > limit or not all(isinstance(x, str) and len(x) <= 2000 for x in v):
        raise MappingError(f"{what} must be a list of strings")
    return list(v)


def _str_map(v: Any, what: str) -> dict[str, str]:
    if v is None:
        return {}
    if not isinstance(v, dict) or len(v) > 100 or not all(isinstance(k, str) and isinstance(x, str) and len(x) <= 4000
                                                          for k, x in v.items()):
        raise MappingError(f"{what} must map names to strings")
    return dict(v)


def validate_mapping(m: Any) -> dict[str, Any]:
    """Check a mapping file's shape. Returns it; raises MappingError with a message for the person."""
    if not isinstance(m, dict) or m.get("format") != FORMAT:
        raise MappingError(f"not an aiSecurityWarden proxy mapping (format {FORMAT})")
    if len(json.dumps(m)) > MAX_MAPPING_BYTES:
        raise MappingError("the mapping file is too large")
    name = m.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise MappingError("name: lowercase letters, digits and _, starting with a letter (e.g. github)")
    secrets = _str_list(m.get("secrets"), "secrets", 20)
    if not all(SECRET_RE.match(s) for s in secrets):
        raise MappingError("secrets: names like GITHUB_PAT")
    up = m.get("upstream")
    if not isinstance(up, dict) or not (set(up) <= {"stdio", "http"}) or not up:
        raise MappingError("upstream needs stdio, http or both")
    refs: set[str] = set()
    if "stdio" in up:
        s = up["stdio"]
        if not isinstance(s, dict) or not isinstance(s.get("command"), str) or not s["command"].strip():
            raise MappingError("upstream.stdio needs a command")
        if SECRET_REF_RE.search(s["command"]):
            raise MappingError("upstream.stdio.command can't hold a secret (it would show in the process list)")
        args, env = _str_list(s.get("args"), "upstream.stdio.args", 50), _str_map(s.get("env"), "upstream.stdio.env")
        if any(SECRET_REF_RE.search(a) for a in args):
            raise MappingError("upstream.stdio.args can't hold a secret (it would show in the process list); "
                               "pass it in env")
        refs |= {r for v in env.values() for r in SECRET_REF_RE.findall(v)}
    if "http" in up:
        h = up["http"]
        if not isinstance(h, dict) or not isinstance(h.get("url"), str):
            raise MappingError("upstream.http needs a url")
        url = h["url"]
        if SECRET_REF_RE.search(url):
            raise MappingError("upstream.http.url can't hold a secret; pass it in headers")
        if not (url.startswith("https://") or re.match(r"^http://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(/|$)", url)):
            raise MappingError("upstream.http.url must be https (or http on localhost)")
        refs |= {r for v in _str_map(h.get("headers"), "upstream.http.headers").values()
                 for r in SECRET_REF_RE.findall(v)}
    unknown = sorted(refs - set(secrets))
    if unknown:
        raise MappingError(f"the upstream uses secret(s) not listed in secrets: {', '.join(unknown)}")
    tools = m.get("tools") or {}
    if not isinstance(tools, dict) or len(tools) > MAX_TOOLS:
        raise MappingError("tools must map upstream tool names to their action")
    for tname, t in tools.items():
        if not isinstance(t, dict) or not isinstance(t.get("action"), str) or not ACTION_RE.match(t["action"]):
            raise MappingError(f"tools.{tname}: needs an action like {name}.issue.create")
        if t["action"].split(".", 1)[0] != name or t["action"].split(".")[1] == "unmapped":
            raise MappingError(f"tools.{tname}: the action must start with {name}. (and not {name}.unmapped)")
        if t.get("risk", "high") not in RISKS:
            raise MappingError(f"tools.{tname}: risk is low, medium or high")
        scope = t.get("scope") or {}
        if not isinstance(scope, dict) or len(scope) > 4 or not all(
                SCOPE_KEY_RE.match(k) and isinstance(v, str) and len(v) <= 200 for k, v in scope.items()):
            raise MappingError(f"tools.{tname}: scope maps names like repo to a template like {{owner}}/{{repo}}")
        s = t.get("summary")
        if s is not None and (not isinstance(s, dict) or not isinstance(s.get("title", ""), str)
                              or not all(isinstance(f, list) and len(f) == 2 and all(isinstance(x, str) for x in f)
                                         for f in s.get("fields") or [])
                              or not isinstance(s.get("preview", ""), str)):
            raise MappingError(f"tools.{tname}: summary is {{title, fields: [[label, template]], preview}}")
        if t.get("description") is not None and not isinstance(t["description"], str):
            raise MappingError(f"tools.{tname}: description must be text")
    _str_list(m.get("hide"), "hide", MAX_TOOLS)
    _str_list(m.get("suggested_rules"), "suggested_rules", 50)
    for k in ("title", "description"):
        if m.get(k) is not None and not isinstance(m[k], str):
            raise MappingError(f"{k} must be text")
    return m


def mapped_tools(m: dict[str, Any]) -> list[dict[str, Any]]:
    """The tools a mapping names, as connector descriptions list them (the upstream may offer more)."""
    return [{"name": f"{m['name']}_{tool_word(t)}", "action": e["action"], "risk": e.get("risk", "high"),
             "description": e.get("description", "")} for t, e in sorted((m.get("tools") or {}).items())]


def load_mapping_file(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return validate_mapping(json.load(f))


def resolve(text: str, secret: Callable[[str], str]) -> str:
    """Put the secrets into an env value or header (only ever for the upstream)."""
    return SECRET_REF_RE.sub(lambda mt: secret(mt.group(1)), text)


# ---------------------------------------------------------------------------
# names, summaries, scope, fingerprints
# ---------------------------------------------------------------------------

def action_word(tool: str) -> str:
    """An upstream tool name as one part of an action name: lowercase, letters/digits/_, max 32."""
    w = re.sub(r"[^a-z0-9_]", "_", tool.lower()).strip("_") or "tool"
    if not w[0].isalpha():
        w = "t_" + w
    return w[:32]


def tool_word(tool: str) -> str:
    """An upstream tool name as the local part of an MCP tool name (the agent sees ``<name>_<this>``)."""
    w = re.sub(r"[^A-Za-z0-9_-]", "_", tool)[:48]
    return w or "tool"


def classify(name: str, tool: dict[str, Any], entry: dict[str, Any] | None) -> tuple[str, str]:
    """(action, risk) for one upstream tool. Hints from the upstream only decide for tools the mapping doesn't
    name, and only under <name>.unmapped, so they can't loosen a rule written for mapped actions."""
    if entry:
        return entry["action"], entry.get("risk", "high")
    hints = tool.get("annotations") or {}
    word = action_word(str(tool.get("name", "")))
    if hints.get("destructiveHint") is True:
        return f"{name}.unmapped.{word}", "high"
    if hints.get("readOnlyHint") is True:
        return f"{name}.unmapped.read.{word}", "low"
    return f"{name}.unmapped.{word}", "medium"


def _fill(template: str, args: dict[str, Any]) -> str:
    def one(mt: re.Match[str]) -> str:
        v = args.get(mt.group(1))
        if v is None:
            return ""
        return v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    return TEMPLATE_RE.sub(one, template)


def summarize(title: str, tool: str, entry: dict[str, Any] | None, args: dict[str, Any]) -> Summary:
    lim = SUMMARY_LIMITS
    s = (entry or {}).get("summary")
    if s:
        return Summary(_fill(s.get("title") or f"{title}: {tool}", args) or f"{title}: {tool}",
                       [(label, _fill(t, args)) for label, t in s.get("fields") or []],
                       _fill(s["preview"], args) if s.get("preview") else None)
    # unmapped (or no template): the tool and its simple arguments; the longest text as the preview
    fields, longest = [], ("", "")
    for k, v in args.items():
        if isinstance(v, str) and len(v) > len(longest[1]) and len(v) > 80:
            longest = (k, v)
    for k, v in args.items():
        if k == longest[0] or isinstance(v, (dict, list)):
            continue
        fields.append((k, v if isinstance(v, str) else json.dumps(v)))
    for k, v in args.items():
        if isinstance(v, (dict, list)) and len(fields) < lim["fields"]:
            fields.append((k, clip(json.dumps(v, ensure_ascii=False), lim["value"])))
    return Summary(f"{title}: {tool}", fields[: lim["fields"]], longest[1] or None)


def scope_values(entry: dict[str, Any] | None, args: dict[str, Any]) -> dict[str, str]:
    """The scope a rule can match on (e.g. {"repo": "SoftDevEng/sandbox"}). Empty parts drop the key."""
    out = {}
    for k, t in ((entry or {}).get("scope") or {}).items():
        v = _fill(t, args)
        if v and all(args.get(n) not in (None, "") for n in TEMPLATE_RE.findall(t)):
            out[k] = v
    return out


def tool_fingerprint(tool: dict[str, Any]) -> str:
    """SHA-256 of what the agent is told about a tool: name, description, input schema and hints."""
    canon = json.dumps({"name": tool.get("name"), "description": tool.get("description"),
                        "inputSchema": tool.get("inputSchema"), "annotations": tool.get("annotations")},
                       sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


# floats can't be in an action digest (canonical JSON has no floats): carry them as text, forward them as numbers
def encode_args(v: Any) -> Any:
    if isinstance(v, float):
        return {"$float": repr(v)}
    if isinstance(v, dict):
        if set(v) == {"$float"}:
            raise ToolError("An argument uses the reserved key $float.")
        return {k: encode_args(x) for k, x in v.items()}
    if isinstance(v, list):
        return [encode_args(x) for x in v]
    return v


def decode_args(v: Any) -> Any:
    if isinstance(v, dict):
        if set(v) == {"$float"} and isinstance(v["$float"], str):
            return float(v["$float"])
        return {k: decode_args(x) for k, x in v.items()}
    if isinstance(v, list):
        return [decode_args(x) for x in v]
    return v


def check_args(schema: dict[str, Any], args: dict[str, Any]) -> str | None:
    """A light check against the upstream's input schema: required arguments, no unknown ones when the schema
    forbids them. The upstream checks the rest."""
    props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    missing = [k for k in schema.get("required") or [] if isinstance(k, str) and k not in args]
    if missing:
        return f"Missing argument(s): {', '.join(missing)}."
    if schema.get("additionalProperties") is False:
        unknown = sorted(set(args) - set(props))
        if unknown:
            return f"Unknown argument(s): {', '.join(unknown)}."
    return None


def result_text(result: Any) -> tuple[str, bool]:
    """An upstream tools/call result as (text, is_error). Images and other binary parts are named, not passed."""
    if not isinstance(result, dict):
        return json.dumps(result, ensure_ascii=False), False
    parts = []
    for c in result.get("content") or []:
        if not isinstance(c, dict):
            continue
        kind = c.get("type")
        if kind == "text" and isinstance(c.get("text"), str):
            parts.append(c["text"])
        elif kind == "resource" and isinstance(c.get("resource"), dict):
            r = c["resource"]
            parts.append(r["text"] if isinstance(r.get("text"), str) else f"[resource {r.get('uri', '')} omitted]")
        elif kind == "resource_link":
            parts.append(f"[link: {c.get('uri', '')}]")
        else:
            parts.append(f"[{kind or 'unknown'} content omitted]")
    if not parts and result.get("structuredContent") is not None:
        parts.append(json.dumps(result["structuredContent"], ensure_ascii=False))
    text = "\n\n".join(parts)
    if len(text) > MAX_RESULT_CHARS:
        text = text[:MAX_RESULT_CHARS] + f"\n[… cut at {MAX_RESULT_CHARS} characters]"
    return text, result.get("isError") is True


# ---------------------------------------------------------------------------
# talking to the upstream
# ---------------------------------------------------------------------------

class UpstreamError(Exception):
    pass


class Upstream:
    """One MCP server we're a client of. ``tools()`` and ``call()`` are thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._next = 0
        self._tools: list[dict[str, Any]] | None = None
        self.changed = False             # the upstream said its tool list changed

    def _id(self) -> int:
        self._next += 1
        return self._next

    def request(self, method: str, params: dict[str, Any] | None = None, timeout: float = CALL_TIMEOUT) -> Any:
        raise NotImplementedError

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        raise NotImplementedError

    def handshake(self) -> None:
        self.request("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                    "clientInfo": {"name": "aiSecurityWarden sw-mcp", "version": "1"}},
                     timeout=START_TIMEOUT)
        self.notify("notifications/initialized")

    def tools(self, *, fresh: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            if self._tools is None or fresh or self.changed:
                self.changed = False
                out: list[dict[str, Any]] = []
                cursor = None
                for _ in range(50):
                    r = self.request("tools/list", {"cursor": cursor} if cursor else {})
                    page = r.get("tools") if isinstance(r, dict) else None
                    if not isinstance(page, list):
                        raise UpstreamError("the upstream sent no tool list")
                    out += [t for t in page if isinstance(t, dict) and isinstance(t.get("name"), str)]
                    cursor = r.get("nextCursor")
                    if not cursor or len(out) > MAX_TOOLS:
                        break
                self._tools = out[:MAX_TOOLS]
            return self._tools

    def call(self, tool: str, args: dict[str, Any]) -> Any:
        with self._lock:
            return self.request("tools/call", {"name": tool, "arguments": args})

    def close(self) -> None:
        pass


class StdioUpstream(Upstream):
    """A local MCP server program, started by sw-mcp, one JSON-RPC message per line."""

    def __init__(self, command: str, args: list[str], env: dict[str, str]) -> None:
        super().__init__()
        self.command, self.args, self.env = command, args, env
        self.proc: subprocess.Popen[bytes] | None = None
        self._inbox: queue.Queue[dict[str, Any] | None] = queue.Queue()

    def start(self) -> None:
        # the upstream gets the usual environment without sw-mcp's own token settings, plus its own values
        base = {k: v for k, v in os.environ.items() if not k.upper().startswith("SW_")}
        try:
            self.proc = subprocess.Popen([self.command, *self.args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, env={**base, **self.env})
        except OSError as e:
            raise UpstreamError(f"couldn't start {self.command} ({type(e).__name__})") from None
        threading.Thread(target=self._read, name="sw-proxy-read", daemon=True).start()
        self.handshake()

    def _read(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if isinstance(msg, dict):
                self._inbox.put(msg)
        self._inbox.put(None)

    def _send(self, msg: dict[str, Any]) -> None:
        if not self.proc or not self.proc.stdin or self.proc.poll() is not None:
            raise UpstreamError("the upstream program isn't running")
        try:
            self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
            self.proc.stdin.flush()
        except OSError:
            raise UpstreamError("the upstream program stopped") from None

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})})

    def request(self, method: str, params: dict[str, Any] | None = None, timeout: float = CALL_TIMEOUT) -> Any:
        rid = self._id()
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        deadline = time.monotonic() + timeout
        while True:
            try:
                msg = self._inbox.get(timeout=max(0.01, deadline - time.monotonic()))
            except queue.Empty:
                raise UpstreamError(f"the upstream didn't answer {method} in time") from None
            if msg is None:
                raise UpstreamError("the upstream program stopped")
            if msg.get("method") == "notifications/tools/list_changed":
                self.changed = True
                continue
            if "method" in msg and "id" in msg:      # the upstream asks us something (sampling, roots...): no
                self._send({"jsonrpc": "2.0", "id": msg["id"],
                            "error": {"code": -32601, "message": "not supported by aiSecurityWarden"}})
                continue
            if msg.get("id") != rid:
                continue
            if "error" in msg:
                err = msg["error"] if isinstance(msg["error"], dict) else {}
                raise UpstreamError(f"upstream error {err.get('code', '')}: {str(err.get('message', ''))[:300]}")
            return msg.get("result")

    def close(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                if self.proc.stdin:
                    self.proc.stdin.close()
                self.proc.wait(timeout=3)
            except Exception:  # noqa: BLE001
                self.proc.kill()


class HttpUpstream(Upstream):
    """A remote MCP server over Streamable HTTP: JSON-RPC by POST, the answer as JSON or an SSE stream."""

    def __init__(self, url: str, headers: dict[str, str], http: Any = None) -> None:
        super().__init__()
        import httpx
        self.url, self.headers = url, headers
        self.http = http or httpx.Client(timeout=httpx.Timeout(CALL_TIMEOUT, connect=15.0), follow_redirects=False)
        self.session: str | None = None
        self.version = PROTOCOL

    def start(self) -> None:
        self.handshake()

    def _post(self, msg: dict[str, Any], timeout: float) -> Any:
        import httpx
        h = {**self.headers, "Accept": "application/json, text/event-stream", "Content-Type": "application/json",
             "MCP-Protocol-Version": self.version}
        if self.session:
            h["Mcp-Session-Id"] = self.session
        try:
            r = self.http.post(self.url, json=msg, headers=h, timeout=timeout)
        except httpx.HTTPError as e:
            raise UpstreamError(f"couldn't reach the upstream ({type(e).__name__})") from None
        if r.status_code in (401, 403):
            raise UpstreamError(f"the upstream refused the credential (HTTP {r.status_code}): check the secret")
        if r.status_code == 404 and self.session:
            self.session = None
            raise UpstreamError("the upstream ended the session; try again")
        if r.status_code >= 400:
            raise UpstreamError(f"the upstream answered HTTP {r.status_code}")
        if r.headers.get("mcp-session-id"):
            self.session = r.headers["mcp-session-id"]
        if "id" not in msg or r.status_code == 202:
            return None
        ctype = r.headers.get("content-type", "")
        if ctype.startswith("text/event-stream"):
            for event in r.text.split("\n\n"):
                data = "\n".join(line[5:].lstrip() for line in event.splitlines() if line.startswith("data:"))
                if not data:
                    continue
                try:
                    m = json.loads(data)
                except ValueError:
                    continue
                if isinstance(m, dict) and m.get("method") == "notifications/tools/list_changed":
                    self.changed = True
                if isinstance(m, dict) and m.get("id") == msg["id"]:
                    return m
            raise UpstreamError("the upstream's answer was missing from its event stream")
        try:
            return r.json()
        except ValueError:
            raise UpstreamError("the upstream's answer wasn't JSON") from None

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._post({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})}, 15.0)

    def request(self, method: str, params: dict[str, Any] | None = None, timeout: float = CALL_TIMEOUT) -> Any:
        m = self._post({"jsonrpc": "2.0", "id": self._id(), "method": method, "params": params or {}}, timeout)
        if not isinstance(m, dict):
            raise UpstreamError("the upstream sent no answer")
        if method == "initialize" and isinstance(m.get("result"), dict):
            v = m["result"].get("protocolVersion")
            if isinstance(v, str):
                self.version = v
        if "error" in m:
            err = m["error"] if isinstance(m["error"], dict) else {}
            raise UpstreamError(f"upstream error {err.get('code', '')}: {str(err.get('message', ''))[:300]}")
        return m.get("result")

    def close(self) -> None:
        if self.session:
            try:
                self.http.request("DELETE", self.url, headers={**self.headers, "Mcp-Session-Id": self.session},
                                  timeout=5.0)
            except Exception:  # noqa: BLE001
                pass


def chosen_transport(name: str) -> str | None:
    """SW_PROXY_TRANSPORT="github=http,slack=stdio": which upstream to use when a mapping offers both."""
    for part in os.environ.get("SW_PROXY_TRANSPORT", "").split(","):
        k, _, v = part.partition("=")
        if k.strip() == name and v.strip() in ("stdio", "http"):
            return v.strip()
    return None


def same_user_as_parent() -> bool | None:
    """Does sw-mcp (and so a stdio upstream) run as the same OS user as the program that started it (the agent)?
    Then the agent's own tools could read the upstream's environment, credential included. None: can't tell."""
    if not sys.platform.startswith("linux"):
        return None
    try:
        with open(f"/proc/{os.getppid()}/status", encoding="ascii") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[1]) == os.getuid()
    except (OSError, ValueError, IndexError):
        return None
    return None


# ---------------------------------------------------------------------------
# a mapping as a connector
# ---------------------------------------------------------------------------

class ProxyConnector(Connector):
    """Base for the classes :func:`proxy_class` makes. Unbound (no client): only the mapped tools, for listings.
    Bound to a client (:meth:`bind`): the upstream's live tools."""

    mapping: ClassVar[dict[str, Any]] = {}
    transport: ClassVar[str | None] = None        # "stdio" or "http"; None: the first the mapping has
    _bound: ClassVar[dict[Any, type["ProxyConnector"]]] = {}
    _client: ClassVar[Any] = None
    _log: ClassVar[Callable[[str], None]] = staticmethod(lambda m: None)
    _upstream: ClassVar[Upstream | None] = None
    _problem: ClassVar[str | None] = None
    _problem_at: ClassVar[float] = 0.0
    RETRY_AFTER: ClassVar[float] = 30.0
    #: approved tool fingerprints (None: not pinned, e.g. an older server); see :meth:`_sync_pins`
    approved: ClassVar[set[str] | None] = None
    _pins_off: ClassVar[bool] = False
    _pin_request: ClassVar[dict[str, Any] | None] = None
    _pin_denied: ClassVar[list[str] | None] = None
    _pin_polled: ClassVar[float] = 0.0
    PIN_POLL: ClassVar[float] = 15.0
    upstream_factory: ClassVar[Callable[..., Upstream] | None] = None   # tests

    @classmethod
    def bind(cls, client: Any, log: Callable[[str], None]) -> type["ProxyConnector"]:
        key = (id(client), cls.name, json.dumps(cls.mapping, sort_keys=True))
        got = ProxyConnector._bound.get(key)
        if got is None:
            got = type(cls.__name__, (cls,), {"_client": client, "_log": staticmethod(log), "_upstream": None,
                                               "_problem": None, "_problem_at": 0.0, "approved": None,
                                               "_pins_off": False, "_pin_request": None, "_pin_denied": None,
                                               "_pin_polled": 0.0})
            ProxyConnector._bound[key] = got
        return got

    @classmethod
    def _secret(cls, name: str) -> str:
        if name not in cls.secrets:
            raise UpstreamError(f"{name} isn't one of this mapping's secrets")
        values = cls._client.fetch()
        if name not in values:
            raise UpstreamError(f"the project has no secret called {name}; add it in aiSecurityWarden")
        return values[name]

    @classmethod
    def upstream(cls) -> Upstream:
        if cls._upstream is not None:
            return cls._upstream
        up = cls.mapping["upstream"]
        kind = cls.transport or chosen_transport(cls.name) or ("stdio" if "stdio" in up else "http")
        if kind not in up:
            raise UpstreamError(f"this mapping has no {kind} upstream")
        if cls.upstream_factory is not None:
            u = cls.upstream_factory(cls, kind)
        elif kind == "stdio":
            s = up["stdio"]
            env = {k: resolve(v, cls._secret) for k, v in (s.get("env") or {}).items()}
            u = StdioUpstream(s["command"], list(s.get("args") or []), env)
            if same_user_as_parent():
                cls._log(f"{cls.name}: the upstream runs as the agent's own OS user, so the agent could read its "
                         "credential from the process environment; run sw-mcp as its own user (see the docs)")
                notice = getattr(cls._client, "notice", None)
                if notice:
                    try:
                        notice("proxy_same_user", cls.name)
                    except Exception:  # noqa: BLE001 - a warning must not stop the tools
                        pass
        else:
            h = up["http"]
            u = HttpUpstream(h["url"], {k: resolve(v, cls._secret) for k, v in (h.get("headers") or {}).items()})
        u.start()
        cls._upstream = u
        return u

    @classmethod
    def live_tools(cls) -> list[dict[str, Any]] | None:
        """The upstream's tools, or None when it can't be reached yet (the reason in ``_problem``)."""
        if cls._client is None:
            return None
        if cls._problem and time.monotonic() - cls._problem_at < cls.RETRY_AFTER:
            return None
        try:
            tools = cls.upstream().tools()
            cls._problem = None
            return tools
        except Exception as e:  # noqa: BLE001 - reported, retried at the next refresh
            msg = str(e).splitlines()[0][:200] if str(e) else type(e).__name__
            if cls._problem != msg:
                cls._log(f"{cls.name}: upstream not available ({msg})")
            cls._problem, cls._problem_at = msg, time.monotonic()
            if cls._upstream is not None:
                cls._upstream.close()
                cls._upstream = None
            return None

    @classmethod
    def needs_refresh(cls) -> bool:
        """The hub should list this proxy's tools again: its upstream came back or changed its tools, or a
        tool-change approval is waiting to be checked."""
        up = cls._upstream
        return bool(cls._problem) or (up is not None and up.changed) or (
            cls._pin_request is not None and time.monotonic() - cls._pin_polled >= cls.PIN_POLL)

    @classmethod
    def _sync_pins(cls, live: list[dict[str, Any]]) -> None:
        """Tool-list fingerprints: tools are offered only once a person approved exactly what the agent will
        read about them. A new or changed tool raises a high-risk "<name>.tools.approve" request; the server
        stores the new list only when that request, for exactly this list, was approved."""
        if cls._pins_off or cls._client is None:
            return
        from ..client.api import ApprovalError, SecurityWardenError
        hidden = set(cls.mapping.get("hide") or [])
        offered = [t for t in live if t["name"] not in hidden]
        fps = sorted({tool_fingerprint(t) for t in offered})
        try:
            if cls.approved is None:
                got = cls._client.proxy_pins(cls.name)
                cls.approved = set(got or [])
        except SecurityWardenError as e:
            if str(e) == "unsupported":
                cls._pins_off, cls.approved = True, None
                cls._log(f"{cls.name}: this aiSecurityWarden server doesn't pin proxy tools yet; offering them all")
                return
            cls._log(f"{cls.name}: couldn't read the approved tools ({str(e)[:200]}); offering none for now")
            cls.approved = cls.approved or set()
            return
        if set(fps) <= cls.approved:
            cls._pin_request = None
            return
        req = cls._pin_request
        try:
            if req is not None and req["fps"] == fps:
                cls._pin_polled = time.monotonic()
                if cls._client.store_proxy_pins(cls.name, req["request_id"], req["nonce"], fps) == "stored":
                    cls.approved, cls._pin_request = set(fps), None
                    cls._log(f"{cls.name}: tool changes approved")
                return
            if fps == cls._pin_denied:
                return
            new = [t for t in offered if tool_fingerprint(t) not in cls.approved]
            title = cls.mapping.get("title") or cls.name
            names = ", ".join(t["name"] for t in new)
            summary = Summary(clip(f"{title}: allow {len(new)} new or changed tool{'s' if len(new) != 1 else ''}",
                                   SUMMARY_LIMITS["title"]),
                              [("Tools", clip(names, SUMMARY_LIMITS["value"])), ("Offered in all", str(len(fps)))],
                              clip(" | ".join(f"{t['name']}: {t.get('description') or ''}" for t in new),
                                   SUMMARY_LIMITS["preview"]))
            r = cls._client.request_action(f"{cls.name}.tools.approve", {"fingerprints": fps}, summary.as_dict(),
                                           risk="high")
            cls._pin_request = {"request_id": r["request_id"], "nonce": r["nonce"], "fps": fps}
            cls._pin_polled = time.monotonic()
            cls._log(f"{cls.name}: asked the user to approve {len(new)} new or changed tool(s) "
                     f"(request {r['request_id']})")
        except ApprovalError as e:
            cls._pin_request, cls._pin_denied = None, fps
            cls._log(f"{cls.name}: tool changes not approved ({e.reason}); they stay hidden until the list changes")
        except SecurityWardenError as e:
            cls._log(f"{cls.name}: couldn't ask about tool changes ({str(e)[:200]})")

    @classmethod
    def tool_specs(cls) -> list[ToolSpec]:
        m = cls.mapping
        mapped: dict[str, dict[str, Any]] = m.get("tools") or {}
        hidden = set(m.get("hide") or [])
        live = cls.live_tools()
        if live is None:
            # unbound (catalog listings) or not reachable yet: only what the mapping says, offered once reachable
            source = [] if cls._client is not None else [{"name": t, "description": e.get("description", "")}
                                                         for t, e in mapped.items()]
        else:
            source = live
            cls._sync_pins(live)
        specs, words = [], set()
        for t in source:
            tname = t["name"]
            if tname in hidden:
                continue
            if live is not None and cls.approved is not None and tool_fingerprint(t) not in cls.approved:
                continue                 # new or changed since approved: offered once a person approves it
            entry = mapped.get(tname)
            action, risk = classify(cls.name, t, entry)
            word = tool_word(tname)
            if word in words:
                continue
            words.add(word)
            schema = t.get("inputSchema") if isinstance(t.get("inputSchema"), dict) else {"type": "object"}
            desc = (entry or {}).get("description") or str(t.get("description") or "")[:2000]
            spec = ToolSpec(word, desc, dict(schema.get("properties") or {}), tuple(
                k for k in schema.get("required") or [] if isinstance(k, str)), action, risk, cls._planner(tname))
            spec.input_schema = schema            # type: ignore[attr-defined]
            spec.loose = True                     # type: ignore[attr-defined]
            specs.append(spec)
        return sorted(specs, key=lambda s: s.name)

    @classmethod
    def _planner(cls, tname: str) -> Callable[..., Plan]:
        entry = (cls.mapping.get("tools") or {}).get(tname)
        title = cls.mapping.get("title") or cls.name

        def plan(self: "ProxyConnector", **args: Any) -> Plan:
            p = Plan(encode_args(args), summarize(title, tname, entry, args),
                     lambda a: self.forward(tname, decode_args(a)))
            p.scope = scope_values(entry, args)   # type: ignore[attr-defined]
            return p
        return plan

    def forward(self, tname: str, args: dict[str, Any]) -> Any:
        title = self.mapping.get("title") or self.name
        try:
            result = type(self).upstream().call(tname, args)
        except UpstreamError as e:
            raise ToolError(f"{title} couldn't be reached, so nothing was done ({e}).") from None
        text, is_error = result_text(result)
        if is_error:
            from .framework import render
            raise ToolError(f"{title} reported an error:\n" + render(untrusted(text, title)))
        return untrusted(text, title)

    def close(self) -> None:
        u = type(self)._upstream
        if u is not None:
            u.close()
            type(self)._upstream = None


def proxy_class(mapping: dict[str, Any], *, transport: str | None = None) -> type[ProxyConnector]:
    """A connector class for a mapping file. ``transport``: "stdio" or "http" when the mapping offers both."""
    m = validate_mapping(mapping)
    if transport is not None and transport not in m["upstream"]:
        raise MappingError(f"this mapping has no {transport} upstream")
    attrs = {"name": m["name"], "title": m.get("title") or m["name"].capitalize(),
             "description": m.get("description") or f"{m.get('title') or m['name']} through its MCP server, with "
                                                     "every action approved through aiSecurityWarden.",
             "secrets": tuple(m.get("secrets") or ()), "suggested_rules": tuple(m.get("suggested_rules") or ()),
             "mapping": m, "transport": transport}
    return type(f"Proxy_{m['name']}", (ProxyConnector,), attrs)
