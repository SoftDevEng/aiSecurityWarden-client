"""sw-mcp: run SecurityWarden connectors as an MCP server for an AI agent (Hermes, Claude Desktop, ...).

    sw-mcp serve --connector gmail                  # stdio MCP server; SW_SERVER_URL + SW_ACCESS_TOKEN_FILE
    sw-mcp serve --config ~/.config/sw/mcp.json
    sw-mcp tools [--connector gmail]                # what the agent will see, with actions and risks
    sw-mcp login gmail                              # one-time Google sign-in for the Gmail connector
    sw-mcp call gmail_search query=is:unread limit=5    # try one tool by hand (waits for approval)
    sw-mcp setup --token-file ~/.config/securitywarden/gmail-token   # store the token from a setup code
    sw-mcp pack notes                                # pack a connector to upload on the website

Connectors turned on for the token's project on the SecurityWarden website (Connectors) are loaded too, and
updated while running when uploaded with "go live now" (SW_MCP_REMOTE=0 turns this off).

Config file (JSON; every key optional, environment variables and options win):
    {"server": "https://vault.example.com", "token_file": "~/.config/sw/jarvis.token",
     "ca_bundle": null, "connectors": ["gmail"]}
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import sys
import time
from typing import Any

from .. import __version__
from ..client.api import ApprovalPending, SecurityWardenClient, SecurityWardenError, _check_url
from ..client.cli import _read_cred_file
from ..client.setup import setup_from_code, setup_into_store, token_file_exists
from ..client.tokens import TokenStore
from .catalog import BUILTIN, load_builtin
from .bundle import EXTENSION, BundleError, bundle_bytes, pack
from .framework import Connector, Hub, SetupTarget
from .remote import RemoteConnectors, default_state_path
from .server import StdioServer

ENTRY_POINT_GROUP = "securitywarden.connectors"     # pip-installed connectors register themselves here


def available_connectors() -> dict[str, str]:
    """Connector name -> "module:Class": built in, plus every installed package that declares
    [project.entry-points."securitywarden.connectors"]."""
    from importlib.metadata import entry_points
    found = dict(BUILTIN)
    try:
        for ep in entry_points(group=ENTRY_POINT_GROUP):
            found.setdefault(ep.name, ep.value)
    except Exception:  # noqa: BLE001 - a broken package must not stop sw-mcp
        pass
    return found


def _die(msg: str, code: int = 1) -> "NoReturn":  # type: ignore[name-defined]
    print(f"sw-mcp: {msg}", file=sys.stderr)
    raise SystemExit(code)


def load_connector(ref: str) -> type[Connector]:
    """A connector by name ("gmail", or any installed connector package's name) or "package.module:ClassName"."""
    if ref in BUILTIN:          # includes approval proxies ("mapping:github"), which aren't importable classes
        return load_builtin(ref)
    known = available_connectors()
    target = known.get(ref, ref)
    mod_name, sep, cls_name = target.partition(":")
    if not sep:
        _die(f"unknown connector {ref!r} (installed: {', '.join(sorted(known))}; or package.module:ClassName)")
    try:
        cls = getattr(importlib.import_module(mod_name), cls_name)
    except (ImportError, AttributeError) as e:
        _die(f"can't load connector {ref!r}: {e}")
    if not (isinstance(cls, type) and issubclass(cls, Connector) and cls.name):
        _die(f"{ref!r} is not a SecurityWarden connector")
    return cls


def _config(args: argparse.Namespace) -> dict[str, Any]:
    path = args.config or os.environ.get("SW_MCP_CONFIG")
    if not path:
        return {}
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        _die(f"can't read config {path}: {e}")
    if not isinstance(cfg, dict) or set(cfg) - {"server", "token_file", "token_name", "token_id", "ca_bundle",
                                                 "connectors"}:
        _die(f"{path}: expected an object with server, token_id, token_name, token_file, ca_bundle, connectors")
    if any(str(v).startswith("sw1.") for v in cfg.values()):
        _die(f"{path}: put the token in its own file (chmod 600) and name that file in token_file")
    return cfg


def _connectors(args: argparse.Namespace, cfg: dict[str, Any]) -> list[type[Connector]]:
    """Connectors named in the MCP settings. Those turned on for the token's project on the SecurityWarden
    website are added on top (see remote.py)."""
    refs = args.connector or (os.environ.get("SW_MCP_CONNECTORS", "").split(",") if os.environ.get("SW_MCP_CONNECTORS")
                              else cfg.get("connectors") or [])
    refs = [r.strip() for r in refs if r.strip()]
    return [load_connector(r) for r in dict.fromkeys(refs)]


def _source(state_path: Any) -> RemoteConnectors | None:
    if os.environ.get("SW_MCP_REMOTE", "1").strip().lower() in ("0", "no", "false", "off"):
        return None
    return RemoteConnectors({n: (lambda n=n: load_builtin(n)) for n in BUILTIN},
                            state_path() and state_path or default_state_path(None))


def _settings(args: argparse.Namespace, cfg: dict[str, Any]) -> tuple[str | None, str | None, bool | str]:
    url = args.server or os.environ.get("SW_SERVER_URL") or cfg.get("server")
    token_file = args.token_file or os.environ.get("SW_ACCESS_TOKEN_FILE") or cfg.get("token_file")
    verify = args.ca_bundle or os.environ.get("SW_CA_BUNDLE") or cfg.get("ca_bundle") or True
    return url, token_file, verify


def _token_name(args: argparse.Namespace, cfg: dict[str, Any]) -> str | None:
    return getattr(args, "token_name", None) or os.environ.get("SW_TOKEN_NAME") or cfg.get("token_name") or None


def _token_id(args: argparse.Namespace, cfg: dict[str, Any]) -> str | None:
    return getattr(args, "token_id", None) or os.environ.get("SW_TOKEN_ID") or cfg.get("token_id") or None


def _store_pick(store: TokenStore, args: argparse.Namespace, cfg: dict[str, Any], url: str | None) -> str | None:
    """The stored token's id for this program (SW_TOKEN_ID, else SW_TOKEN_NAME + server, else the only one)."""
    try:
        return store.pick(_token_name(args, cfg), token_id=_token_id(args, cfg), server=url)
    except SecurityWardenError as e:
        _die(str(e))


def _announce(info: dict) -> None:
    print(f"sw-mcp: waiting for a person to approve this {'session' if info['kind'] == 'auth' else 'fetch'} "
          f"(match code {info['match']}, up to {info['expires_in']} s)...", file=sys.stderr, flush=True)


def _client(args: argparse.Namespace, cfg: dict[str, Any], *, wait: bool = True) -> SecurityWardenClient:
    url, token_file, verify = _settings(args, cfg)
    if not url:
        _die("no server URL (use --server, SW_SERVER_URL or \"server\" in the config)")
    if token_file:
        cred = _read_cred_file(token_file)
    elif os.environ.get("SW_ACCESS_TOKEN"):
        cred = os.environ["SW_ACCESS_TOKEN"]
    else:
        store = TokenStore()
        tid = _store_pick(store, args, cfg, url)
        if not tid:
            name = _token_name(args, cfg)
            _die(f"no token {'called ' + repr(name) + ' ' if name else ''}in {store.path} yet: run sw-mcp setup "
                 "with a setup code from the website")
        try:
            cred = store.credential(tid)
        except SecurityWardenError as e:
            _die(str(e))
    try:
        return SecurityWardenClient(url, cred, verify=verify, on_approval=_announce, wait_for_approval=wait)
    except (SecurityWardenError, ValueError) as e:
        _die(str(e))


def _hub(args: argparse.Namespace, cfg: dict[str, Any]) -> Hub:
    """Tool calls never wait for a person: approvals come back as "waiting_for_approval" at once, so the
    agent's own tool timeout never matters. securitywarden_setup takes a one-time code: the first time, and
    again once the server rejects the stored token (revoked or expired). The token lives in SW_Tokens.json
    under its name (SW_TOKEN_NAME), or in a file of its own (SW_ACCESS_TOKEN_FILE, as before)."""
    url, token_file, verify = _settings(args, cfg)
    connectors = _connectors(args, cfg)
    if os.environ.get("SW_ACCESS_TOKEN") and not token_file:
        return Hub(_client(args, cfg, wait=False), connectors, source=_source(lambda: None))
    if url:
        try:
            _check_url(url)
        except SecurityWardenError as e:
            _die(str(e))

    def make(cred: Any) -> SecurityWardenClient:
        return SecurityWardenClient(url, cred, verify=verify, on_approval=_announce, wait_for_approval=False)
    if token_file:
        target = SetupTarget(url, token_file, make, verify)
        state = (lambda: default_state_path(token_file))
    else:
        store = TokenStore()
        target = SetupTarget(url, None, make, verify, store=store, token_name=_token_name(args, cfg),
                             token_id=_token_id(args, cfg))
        state = (lambda: _versions_path(store, target))
    client = None
    try:
        if target.has_token():
            client = make(target.load())
    except SecurityWardenError as e:
        print(f"sw-mcp: {e}", file=sys.stderr, flush=True)
    return Hub(client, connectors, setup=target, source=_source(state))


def _versions_path(store: TokenStore, target: SetupTarget) -> str:
    """Where this token's highest connector versions are kept (rollback protection), by token id. Before
    0.6.0.dev19 the file was named after the token; it's carried over once."""
    folder = os.path.join(os.path.dirname(store.path), "connector-versions")
    safe = (lambda s: re.sub(r"[^A-Za-z0-9._-]", "_", s))
    tid = None
    try:
        tid = target._pick()
    except SecurityWardenError:
        pass
    by_name = os.path.join(folder, safe(target.token_name or "default") + ".json")
    if not tid:
        return by_name
    by_id = os.path.join(folder, "id-" + safe(tid) + ".json")
    if not os.path.exists(by_id) and os.path.exists(by_name):
        try:
            import shutil
            shutil.copyfile(by_name, by_id)
        except OSError:
            pass
    return by_id


def cmd_serve(args: argparse.Namespace) -> None:
    cfg = _config(args)
    hub = _hub(args, cfg)
    if hub.client is None:
        print("sw-mcp: no token yet: the agent can set up with a one-time code (securitywarden_setup), or run "
              "sw-mcp setup", file=sys.stderr, flush=True)
    hub.refresh(force=True)            # connectors turned on for the token's project on the website
    if not hub.tools and hub.client is not None:
        print("sw-mcp: no connectors yet: turn one on for this token's project on the SecurityWarden website "
              "(Connectors), or name one with --connector", file=sys.stderr, flush=True)
    print(f"sw-mcp {__version__}: serving {', '.join(i.name for i in hub.instances)} "
          f"({len(hub.tools)} tools) on stdio", file=sys.stderr, flush=True)
    StdioServer(hub).serve()


def cmd_tools(args: argparse.Namespace) -> None:
    cfg = _config(args)
    if getattr(args, "live", False):
        # exactly what the agent is offered now: connectors from the settings and the website, approval proxies
        # connected to their upstream (and asking to approve their tools, the first time or after a change)
        hub = _hub(args, cfg)
        try:
            hub.refresh(force=True)
            for t in hub.list_tools():
                spec = hub.tools.get(t["name"], (None, None))[1]
                act = f"{spec.action:<34} {spec.risk:<6}" if spec else f"{'':<41}"
                print(f"  {t['name']:<40} {act} {t['description'].split('.')[0][:60]}")
            for inst in hub.instances:
                req = getattr(type(inst), "_pin_request", None)
                if req:
                    print(f"\n{inst.name}: waiting for you to approve its tools (request {req['request_id']}); "
                          "approve it on the website or your phone, then run this again")
                problem = getattr(type(inst), "_problem", None)
                if problem:
                    print(f"\n{inst.name}: upstream not available ({problem})")
        finally:
            hub.close()
        return
    if not (args.connector or os.environ.get("SW_MCP_CONNECTORS") or cfg.get("connectors")):
        print("Installed connectors:")
        for name, target in sorted(available_connectors().items()):
            print(f"  {name:<12} {target}")
        print("Show one: sw-mcp tools --connector NAME")
        return
    for cls in _connectors(args, cfg):
        print(f"{cls.name}: {cls.description}")
        for spec in cls.tool_specs():
            print(f"  {cls.name}_{spec.name:<18} {spec.action:<22} {spec.risk:<6} {spec.description.split('.')[0]}")
        if cls.suggested_rules:
            print("  suggested rules:  swctl admin token set-actions TOKEN_ID " +
                  " ".join(f"--rule {r}" for r in cls.suggested_rules))
    print("  check_approval     (built in: check on, and then do, an action waiting for approval)")


def cmd_doctor(args: argparse.Namespace) -> None:
    """Check, step by step, what this MCP server would offer an agent with these settings (the same environment
    as the agent's MCP entry): which token, whether the server answers and accepts it, whether a person must
    approve first, which connectors the server gives this token, and the tools that come out. Never prints a
    secret. Tells whether a short tool list comes from us or from the agent app."""
    import httpx
    from ..client.api import TokenRejected
    from ..client.setup import file_token_id
    cfg = _config(args)
    url, token_file, verify = _settings(args, cfg)
    problems = 0
    test_http = getattr(args, "_http", None)        # tests: an in-process server

    def say(mark: str, text: str) -> None:
        nonlocal problems
        problems += mark == "FAIL"
        print(f"[{mark:<4}] {text}", flush=True)

    # 1. settings and token
    print("sw-mcp doctor: what an agent with these MCP settings is offered\n")
    if not url:
        say("FAIL", "no server URL: set SW_SERVER_URL in the MCP entry (or --server)")
        sys.exit(1)
    say("ok", f"server {url}")
    if token_file:
        tid = file_token_id(token_file)
        say("ok" if tid else "FAIL", f"token file {token_file}" + (f": token {tid}" if tid else ": no token in it yet"))
        cred: Any = _read_cred_file(token_file) if tid else None
    elif os.environ.get("SW_ACCESS_TOKEN"):
        say("ok", "token from SW_ACCESS_TOKEN")
        cred = os.environ["SW_ACCESS_TOKEN"]
    else:
        store = TokenStore()
        asked = ", ".join(f"{k}={v}" for k, v in (("SW_TOKEN_ID", _token_id(args, cfg)),
                                                    ("SW_TOKEN_NAME", _token_name(args, cfg))) if v) or "nothing"
        try:
            tid = store.pick(_token_name(args, cfg), token_id=_token_id(args, cfg), server=url)
        except SecurityWardenError as e:
            say("FAIL", f"which token: {e}")
            sys.exit(1)
        if not tid:
            say("FAIL", f"no token in {store.path} for {asked} (see: swctl tokens list). The agent offers only "
                "securitywarden_setup until it gets a setup code")
            sys.exit(1)
        e = store.entry(tid)
        say("ok", f"token {e['name']!r} (id {tid}, project {e.get('project') or '?'}) from {store.path}, found by {asked}")
        if e.get("server") and e["server"].rstrip("/").lower() != url.rstrip("/").lower():
            say("WARN", f"that token was set up for {e['server']}, but this entry uses {url}")
        cred = store.credential(tid)
    if cred is None:
        sys.exit(1)

    # 2. the server
    try:
        if test_http is not None:
            r = test_http.get(url.rstrip("/") + "/v1/health")
        else:
            with httpx.Client(timeout=15, verify=verify) as h:
                r = h.get(url.rstrip("/") + "/v1/health")
        info = r.json() if r.status_code == 200 else {}
        say("ok" if r.status_code == 200 else "FAIL", f"server answers ({r.status_code})"
            + (f", version {info.get('version')}" if info.get("version") else ""))
    except (httpx.HTTPError, ValueError) as e:
        say("FAIL", f"server unreachable: {type(e).__name__}")
        sys.exit(1)

    # 3. the token, and approval
    client = SecurityWardenClient(url, cred, verify=verify, wait_for_approval=False,
                                  **({"http": test_http} if test_http is not None else {}))
    deadline = time.monotonic() + max(0, args.wait)
    told = None
    while True:
        try:
            client.check_token()
            say("ok", "token accepted; session open")
            break
        except ApprovalPending as e:
            if time.monotonic() >= deadline:
                say("WAIT", f"a person must approve this token's session first (match code {e.match}). Until then "
                    "the agent gets only check_approval and securitywarden_setup. Approve it, then run this again "
                    "(or add --wait 300 to wait here)")
                sys.exit(2)
            if told != e.approval_id:
                told = e.approval_id
                print(f"       waiting for approval of this session (match code {e.match})...", flush=True)
            time.sleep(3)
        except TokenRejected:
            say("FAIL", "the server rejects this token (revoked or expired): make a new token and give the agent "
                "its setup code")
            sys.exit(1)
        except SecurityWardenError as e:
            say("FAIL", f"sign-in failed: {e}")
            sys.exit(1)

    # 4. what the server gives this token
    try:
        listing = client.connectors()
    except SecurityWardenError as e:
        say("FAIL", f"connector list: {e}")
        sys.exit(1)
    builtin = listing.get("builtin") or []
    custom = listing.get("custom") or []
    say("ok" if builtin or custom else "WARN",
        f"server gives this token: built-in {', '.join(builtin) or 'none'}; uploaded {len(custom)}"
        + ("" if builtin or custom else ". Tick connectors for this token on the website (Tokens, Manage, "
                                       "Connectors), with the connector switched on for its project"))
    named = _connectors(args, cfg)
    if named:
        say("ok", f"named in the MCP settings: {', '.join(c.name for c in named)}")

    # 5. the tools that come out, built the way `serve` builds them (its rollback records go to a scratch folder,
    # so this check never changes what the agent's own server has seen)
    import tempfile
    scratch = tempfile.mkdtemp(prefix="sw-mcp-doctor-")
    hub = Hub(client, named, source=_source(lambda: os.path.join(scratch, "versions.json")), log=lambda m: None)
    try:
        hub.refresh(force=True)
        tools = hub.list_tools()
        extra = [t["name"] for t in tools if t["name"] not in (Hub.CHECK_TOOL, Hub.SETUP_TOOL)]
        say("ok" if extra else "FAIL", f"{len(tools)} tools offered ({len(extra)} from connectors)")
        for inst in hub.instances:
            n = sum(1 for t in extra if t.startswith(inst.name + "_"))
            print(f"         {inst.name:<14} {n} tools")
            req = getattr(type(inst), "_pin_request", None)
            if req:
                say("WAIT", f"{inst.name}: waiting for you to approve its tool list (request {req['request_id']})")
            problem = getattr(type(inst), "_problem", None)
            if problem:
                say("FAIL", f"{inst.name}: its MCP server isn't available ({problem})")
    finally:
        hub.close()
        import shutil
        shutil.rmtree(scratch, ignore_errors=True)
    print()
    if problems:
        print("Something on our side needs fixing first: see FAIL above.")
    else:
        print(f"aiSecurityWarden offers {len(tools)} tools for this token. If the agent app shows fewer, it read the "
              "list before the session was approved: refresh its tools or start a new session (Hermes keeps a "
              "session's tool list).")
    sys.exit(1 if problems else 0)


def _parse_call_args(hub: Hub, tool_name: str, pairs: list[str]) -> dict[str, Any]:
    """name=value pairs typed on the command line, converted using the tool's schema (lists: commas)."""
    schema = next((t["inputSchema"] for t in hub.list_tools() if t["name"] == tool_name), None)
    if schema is None:
        _die(f"unknown tool {tool_name} (see: sw-mcp tools)")
    out: dict[str, Any] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or key not in schema["properties"]:
            _die(f"expected NAME=VALUE with NAME one of: {', '.join(schema['properties'])}")
        kind = schema["properties"][key].get("type")
        if kind == "array":
            out[key] = [v.strip() for v in value.split(",") if v.strip()]
        elif kind == "integer":
            try:
                out[key] = int(value)
            except ValueError:
                _die(f"{key} must be a whole number")
        elif kind == "boolean":
            if value.lower() not in ("true", "false", "yes", "no", "1", "0"):
                _die(f"{key} must be true or false")
            out[key] = value.lower() in ("true", "yes", "1")
        else:
            out[key] = value.replace("\\n", "\n")
    return out


def cmd_call(args: argparse.Namespace) -> None:
    """Run one tool as an agent would, and wait for a person's approval if it needs one."""
    import time
    cfg = _config(args)
    hub = _hub(args, cfg)
    try:
        res = hub.call(args.tool, _parse_call_args(hub, args.tool, args.values))
        deadline = time.monotonic() + args.wait
        while res.data.get("status") == "waiting_for_approval":
            rid = res.data["request_id"]
            if time.monotonic() > deadline:
                _die(f"still waiting for approval after {args.wait} s (request {rid}); nothing was done")
            print(f"sw-mcp: waiting for approval of {res.data['action']} (match code {res.data.get('match')})...",
                  file=sys.stderr, flush=True)
            time.sleep(min(10, max(2, int(res.data.get("check_after") or 5))))
            res = hub.call(hub.CHECK_TOOL, {"request_id": rid})
        print(res.text)
        if res.is_error:
            raise SystemExit(1)
    finally:
        hub.close()


def cmd_proxy_init(args: argparse.Namespace) -> None:
    """Write a starter .swproxy mapping for an MCP server, from its live tool list, to check and then upload."""
    import getpass
    from .proxy import EXTENSION as PX, NAME_RE, SECRET_RE, HttpUpstream, MappingError, StdioUpstream, \
        UpstreamError, draft_mapping, resolve
    name = args.name
    if not NAME_RE.match(name):
        _die("NAME: lowercase letters, digits and _, starting with a letter (e.g. acme)")
    if bool(args.command) == bool(args.url):
        _die("give the server as --command PROGRAM (a local MCP server) or --url https://... (a remote one)")

    def pairs(values: list[str] | None, what: str) -> dict[str, str]:
        out = {}
        for v in values or []:
            k, sep, secret = v.partition("=")
            if not sep or not k or not SECRET_RE.match(secret):
                _die(f"{what} {v!r}: use NAME=SECRET_NAME (the secret's name in aiSecurityWarden, not its value)")
            out[k] = secret
        return out
    env, header_secrets = pairs(args.env, "--env"), pairs(args.header, "--header")
    if args.bearer and not SECRET_RE.match(args.bearer):
        _die("--bearer takes the secret's name in aiSecurityWarden, e.g. ACME_TOKEN")
    if args.command and (header_secrets or args.bearer):
        _die("--header and --bearer are for --url servers; use --env for a --command server")
    if args.url and env:
        _die("--env is for --command servers; use --header or --bearer for a --url server")
    headers = {k: f"${{secret:{v}}}" for k, v in header_secrets.items()}
    if args.bearer:
        headers["Authorization"] = f"Bearer ${{secret:{args.bearer}}}"
    secrets = sorted(set(env.values()) | set(header_secrets.values()) | ({args.bearer} if args.bearer else set()))
    if args.command:
        upstream = {"stdio": {"command": args.command, "args": list(args.arg or []),
                              "env": {k: f"${{secret:{v}}}" for k, v in env.items()}}}
    else:
        upstream = {"http": {"url": args.url, "headers": headers}}
    out = args.output or f"{name}{PX}"
    if os.path.exists(out) and not args.force:
        _die(f"{out} already exists (use --force to replace it)")

    # the secrets' values, only to connect now: from the environment (same name) or typed at a prompt
    values: dict[str, str] = {}
    for s in secrets:
        values[s] = os.environ.get(s) or getpass.getpass(f"{s} (only used now, to read the tool list; not saved): ")
    try:
        if args.command:
            u = StdioUpstream(args.command, list(args.arg or []), {k: values[s] for k, s in env.items()})
        else:
            u = HttpUpstream(args.url, {k: resolve(v, lambda n: values[n]) for k, v in headers.items()})
        u.start()
        tools = u.tools()
        u.close()
    except UpstreamError as e:
        _die(f"couldn't read the server's tools: {e}")
    try:
        mapping, report = draft_mapping(name, args.title or name.capitalize(), upstream, secrets, tools)
    except MappingError as e:
        _die(str(e))
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(mapping, f, indent=1, ensure_ascii=False)
        f.write("\n")
    width = max([len(r[0]) for r in report] + [10])
    print(f"{len(report)} tools from the server:")
    for tname, action, risk, why in report:
        print(f"  {tname:<{width}}  {action:<40} {risk:<6}  {why}")
    print(f"\nWrote {out}. Check each tool's risk (high: always asks; the server's hints aren't trusted for you),\n"
          "add summaries and scopes if you like (docs/mcp-proxy.md), then upload it on the aiSecurityWarden website\n"
          f"(Connectors) and add the secret{'s' if len(secrets) != 1 else ''} {', '.join(secrets) or '(none)'} to the "
          "project.")


def cmd_pack(args: argparse.Namespace) -> None:
    """Pack a connector into one file to upload on the SecurityWarden website (Connectors)."""
    cls = load_connector(args.connector_name)
    try:
        bundle = pack(cls)
    except (BundleError, OSError, UnicodeDecodeError) as e:
        _die(str(e))
    out = args.output or f"{cls.name}{EXTENSION}"
    raw = bundle_bytes(bundle)
    with open(out, "wb") as f:
        f.write(raw)
    print(f"wrote {out}: connector {cls.name}, {len(bundle['files'])} files, {len(raw) / 1024:.1f} KB, "
          f"{len(bundle['tools'])} tools.\nUpload it on the SecurityWarden website: Connectors > Upload, then turn "
          "it on for the projects whose agents should have it.")


def cmd_setup(args: argparse.Namespace) -> None:
    """Store this machine's token from a one-time setup code, then print what to give the agent."""
    import getpass
    import shutil
    cfg = _config(args)
    url, token_file, verify = _settings(args, cfg)
    if not url:
        _die("no server URL (use --server, SW_SERVER_URL or \"server\" in the config)")
    if token_file and token_file_exists(token_file) and not args.replace:
        _die(f"{os.path.expanduser(token_file)} already holds a token (use --replace to swap it for a new one)")
    name, tid = _token_name(args, cfg), _token_id(args, cfg)
    store = TokenStore()
    if not token_file and (name or tid) and _store_pick(store, args, cfg, url) is not None and not args.replace:
        _die(f"{store.path} already holds this program's token (use --replace to swap it for a new one)")
    code = sys.stdin.readline() if args.code_stdin else getpass.getpass("Setup code (SWS1-..., not shown): ")
    try:
        if token_file:
            cred, where = setup_from_code(url, code, token_file, replace=args.replace, verify=verify)
        else:
            cred, name = setup_into_store(url, code, store, name, token_id=tid, replace=args.replace, verify=verify)
            where = store.path
    except (SecurityWardenError, OSError) as e:
        _die(str(e))
    print(f"Token {name or cred.id} stored in {where} (readable by you only).", file=sys.stderr)
    exe = shutil.which("sw-mcp") or os.path.abspath(sys.argv[0])
    conns = args.connector or (cfg.get("connectors") or [])
    print("\nFor Hermes or Claude: command", exe, "with arguments: serve" +
          "".join(f" --connector {c}" for c in conns), file=sys.stderr)
    print(f"and environment SW_SERVER_URL={url} " + (f"SW_ACCESS_TOKEN_FILE={where}" if token_file
                                                     else f"SW_TOKEN_ID={cred.id} SW_TOKEN_NAME={name}"),
          file=sys.stderr)


def cmd_check(args: argparse.Namespace) -> None:
    """Check connectors for mistakes before using them (for people and for AI writing connectors)."""
    from .lint import check_connector
    refs = args.connector or sorted(available_connectors())
    errors = 0
    for ref in refs:
        cls = load_connector(ref)
        problems = check_connector(cls)
        errors += sum(1 for level, _ in problems if level == "error")
        print(f"{ref}: " + ("OK" if not problems else f"{len(problems)} problem(s)"))
        for level, msg in problems:
            print(f"  {level}: {msg}")
    if errors:
        raise SystemExit(1)


def cmd_guide(args: argparse.Namespace) -> None:
    """Print the connector guide (Markdown), e.g. to give to an AI that writes a connector."""
    from importlib.resources import files
    sys.stdout.write((files("securitywarden.mcp") / "CONNECTORS.md").read_text(encoding="utf-8"))


def cmd_new_connector(args: argparse.Namespace) -> None:
    from .scaffold import create_connector_project
    try:
        where = create_connector_project(args.name, args.dir, title=args.title)
    except (ValueError, FileExistsError) as e:
        _die(str(e))
    print(f"Created {where}", file=sys.stderr)
    print("Next: read AGENTS.md there (or give it to your AI), then:\n"
          f"  pip install -e {where}\n  sw-mcp check --connector {args.name}\n  pytest {where}", file=sys.stderr)


def cmd_login(args: argparse.Namespace) -> None:
    cls = load_connector(args.connector_name)
    login = getattr(cls, "login", None)
    if login is None:
        _die(f"{cls.name} has no login step")
    login(args)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="sw-mcp", description="SecurityWarden connectors as an MCP server")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser, connectors: bool = True) -> None:
        sp.add_argument("--config", help="JSON config file (default: $SW_MCP_CONFIG)")
        sp.add_argument("--server", help="server URL (default: $SW_SERVER_URL)")
        sp.add_argument("--token-name", help="the token's name in SW_Tokens.json (default: $SW_TOKEN_NAME)")
        sp.add_argument("--token-id", help="the token's id in SW_Tokens.json (default: $SW_TOKEN_ID)")
        sp.add_argument("--token-file", help="a token file of its own instead (default: $SW_ACCESS_TOKEN_FILE)")
        sp.add_argument("--ca-bundle", help="CA bundle for a private certificate (default: $SW_CA_BUNDLE)")
        if connectors:
            sp.add_argument("--connector", action="append", help="connector to enable (repeat): gmail or module:Class")

    s = sub.add_parser("serve", help="run the MCP server on stdio")
    common(s)
    s.set_defaults(fn=cmd_serve)
    t = sub.add_parser("tools", help="list the tools, their actions and risks")
    common(t)
    t.add_argument("--live", action="store_true",
                   help="sign in and list exactly what the agent is offered now (incl. connectors from the website)")
    t.set_defaults(fn=cmd_tools)
    d = sub.add_parser("doctor", help="check what an agent with these MCP settings is offered, step by step")
    common(d)
    d.add_argument("--wait", type=int, default=0, help="seconds to wait for a person to approve (default: don't wait)")
    d.set_defaults(fn=cmd_doctor)
    c = sub.add_parser("call", help="run one tool by hand, waiting for approval if needed (for testing)")
    c.add_argument("tool", help="tool name, e.g. gmail_search (see: sw-mcp tools)")
    c.add_argument("values", nargs="*", help="arguments as NAME=VALUE; lists separated by commas; \\n for a new line")
    c.add_argument("--wait", type=int, default=900, help="seconds to wait for an approval (default 900)")
    common(c)
    c.set_defaults(fn=cmd_call)
    ck = sub.add_parser("check", help="check connectors for mistakes (all installed, or --connector NAME)")
    ck.add_argument("--connector", action="append", help="connector to check (repeat)")
    ck.set_defaults(fn=cmd_check)
    gd = sub.add_parser("guide", help="print the guide to writing a connector (give it to your AI)")
    gd.set_defaults(fn=cmd_guide)
    nc = sub.add_parser("new-connector", help="create a connector project to fill in")
    nc.add_argument("name", help="connector name: lowercase, e.g. notion or my_crm (prefixes its actions)")
    nc.add_argument("--dir", default=".", help="where to create the project folder (default: here)")
    nc.add_argument("--title", help="the application's display name, e.g. Notion")
    nc.set_defaults(fn=cmd_new_connector)
    pi = sub.add_parser("proxy-init", help="write a starter .swproxy mapping for an MCP server, from its tool list")
    pi.add_argument("name", help="short name, lowercase: prefixes its tools and actions (e.g. acme)")
    pi.add_argument("--title", help="display name, e.g. Acme")
    pi.add_argument("--command", help="a local MCP server: the program to run (stdio)")
    pi.add_argument("--arg", action="append", help="an argument for --command (repeat)")
    pi.add_argument("--env", action="append", metavar="VAR=SECRET",
                    help="give the program a secret: environment variable VAR = the aiSecurityWarden secret SECRET")
    pi.add_argument("--url", help="a remote MCP server: its https URL (Streamable HTTP)")
    pi.add_argument("--bearer", metavar="SECRET", help="send the secret SECRET as 'Authorization: Bearer ...'")
    pi.add_argument("--header", action="append", metavar="HEADER=SECRET", help="send the secret SECRET in HEADER")
    pi.add_argument("-o", "--output", help="file to write (default: NAME.swproxy)")
    pi.add_argument("--force", action="store_true", help="replace the file if it exists")
    pi.set_defaults(fn=cmd_proxy_init)
    pk = sub.add_parser("pack", help="pack a connector into one file to upload on the SecurityWarden website")
    pk.add_argument("connector_name", help="installed connector name, or package.module:ClassName")
    pk.add_argument("-o", "--output", help=f"file to write (default: NAME{EXTENSION})")
    pk.set_defaults(fn=cmd_pack)
    su = sub.add_parser("setup", help="store this machine's token from a one-time setup code")
    common(su)
    su.add_argument("--replace", action="store_true", help="replace a token that is already stored")
    su.add_argument("--code-stdin", action="store_true", help="read the code from stdin instead of asking")
    su.set_defaults(fn=cmd_setup)
    lg = sub.add_parser("login", help="one-time sign-in for a connector (e.g. gmail)")
    lg.add_argument("connector_name")
    common(lg, connectors=False)
    lg.add_argument("--project", help="store the result in this project with the admin credential")
    lg.add_argument("--admin-file", help="admin credential file (default: $SW_ADMIN_CREDENTIAL_FILE)")
    lg.add_argument("--no-browser", action="store_true", help="print the sign-in link instead of opening it")
    lg.set_defaults(fn=cmd_login)

    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
