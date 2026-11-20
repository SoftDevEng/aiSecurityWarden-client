"""``sw-mcp connect APP``: add aiSecurityWarden's MCP server to an agent app's settings, for the token stored here.

The entry is the same the website shows when a token is made (server repo ``web/src/lib/mcpConfig.ts``): the command
that starts ``sw-mcp serve`` and three environment variables naming the token. Nothing secret goes in: the token
itself stays in this machine's token store (``sw-mcp setup``).

Every file it changes is backed up first, an entry that is already there is left alone (``--replace`` swaps it), and
a file it can't safely edit is never guessed at: the entry is printed to paste instead. It restarts nothing.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import unicodedata

APPS = ("claude-desktop", "claude-code", "hermes", "other")


class ConnectError(Exception):
    """Something the person has to sort out; the message says what."""


def entry_name(token_name: str) -> str:
    """Same rule as the website: aisecuritywarden-<slug of the token name>."""
    slug = unicodedata.normalize("NFKD", token_name.lower())
    slug = re.sub(r"[^a-z0-9]+", "-", slug).strip("-")[:40].strip("-")
    return f"aisecuritywarden-{slug}" if slug else "aisecuritywarden"


def sw_mcp_command() -> str:
    return shutil.which("sw-mcp") or os.path.abspath(sys.argv[0])


def entry(command: str, server: str, token_id: str, token_name: str, connectors: list[str] | None = None) -> dict:
    args = ["serve"] + [x for c in (connectors or []) for x in ("--connector", c)]
    return {"command": command, "args": args,
            "env": {"SW_SERVER_URL": server, "SW_TOKEN_ID": token_id, "SW_TOKEN_NAME": token_name}}


# -- where each app keeps its settings ---------------------------------------------------------

def claude_desktop_config() -> str:
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        return os.path.join(os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming"), "Claude",
                            "claude_desktop_config.json")
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
    return os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config"), "Claude",
                        "claude_desktop_config.json")


def hermes_config() -> str:
    from ..client.hermes import hermes_home
    return os.path.join(hermes_home(), "config.yaml")


def _backup(path: str) -> str | None:
    if not os.path.exists(path):
        return None
    dest = f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(path, dest)
    return dest


def _write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".sw-tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    os.replace(tmp, path)


# -- Claude Desktop (and other apps with the same JSON) ----------------------------------------

def add_json(path: str, name: str, e: dict, *, replace: bool = False, dry_run: bool = False) -> str:
    text = ""
    if os.path.exists(path):
        with open(path, encoding="utf-8-sig") as f:
            text = f.read()
    try:
        data = json.loads(text) if text.strip() else {}
    except ValueError:
        raise ConnectError(f"{path} isn't valid JSON, so it wasn't changed. Fix it (or paste the entry by hand: "
                           "sw-mcp connect other).") from None
    if not isinstance(data, dict) or not isinstance(data.get("mcpServers", {}), dict):
        raise ConnectError(f"{path} doesn't look like Claude Desktop's settings, so it wasn't changed.")
    servers = data.setdefault("mcpServers", {})
    if name in servers:
        if servers[name] == e:
            return f"{path} already has {name}; nothing to change."
        if not replace:
            raise ConnectError(f"{path} already has a different {name} entry. Use --replace to swap it.")
    servers[name] = e
    if dry_run:
        return f"Would add {name} to {path}:\n" + json.dumps({"mcpServers": {name: e}}, indent=2)
    bak = _backup(path)
    _write(path, json.dumps(data, indent=2) + "\n")
    return f"Added {name} to {path}" + (f" (backup: {bak})" if bak else "") + "."


# -- Hermes (YAML, edited as text: no YAML library, nothing else in the file touched) ---------

def _yq(v: str) -> str:
    return json.dumps(v)          # a JSON string is a valid YAML double-quoted scalar


def hermes_block(name: str, e: dict) -> list[str]:
    lines = [f"  {name}:", f"    command: {_yq(e['command'])}", f"    args: {json.dumps(e['args'])}", "    env:"]
    lines += [f"      {k}: {_yq(v)}" for k, v in e["env"].items()]
    return lines


def add_hermes(path: str, name: str, e: dict, *, replace: bool = False, dry_run: bool = False) -> str:
    lines: list[str] = []
    if os.path.exists(path):
        with open(path, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()
    block = hermes_block(name, e)
    top = [i for i, ln in enumerate(lines) if re.match(r"^mcp_servers\s*:", ln)]
    if len(top) > 1:
        raise ConnectError(f"{path} has mcp_servers twice, so it wasn't changed.")
    if top:
        i = top[0]
        rest = lines[i].split(":", 1)[1].split("#", 1)[0].strip()
        if rest:      # flow style ({...}) or a value on the same line: not something to edit as text
            raise ConnectError(f"{path} writes mcp_servers on one line, so it wasn't changed. Add the entry by hand:\n"
                               + "\n".join(["mcp_servers:"] + block))
        end = i + 1
        while end < len(lines) and (not lines[end].strip() or lines[end].startswith((" ", "\t"))):
            end += 1
        section = lines[i + 1:end]
        indents = {len(ln) - len(ln.lstrip()) for ln in section if ln.strip() and not ln.lstrip().startswith("#")}
        if section and indents and min(indents) != 2:
            raise ConnectError(f"{path} indents mcp_servers with {min(indents)} spaces, so it wasn't changed. Add the "
                               "entry by hand:\n" + "\n".join(["mcp_servers:"] + block))
        at = next((j for j in range(i + 1, end) if re.match(rf"^  {re.escape(name)}\s*:", lines[j])), None)
        if at is not None:
            stop = at + 1
            while stop < end and (not lines[stop].strip() or lines[stop].startswith("    ")):
                stop += 1
            if lines[at:stop] == block or [ln for ln in lines[at:stop] if ln.strip()] == block:
                return f"{path} already has {name}; nothing to change."
            if not replace:
                raise ConnectError(f"{path} already has a different {name} entry. Use --replace to swap it.")
            new = lines[:at] + block + lines[stop:]
        else:
            last = end
            while last > i + 1 and not lines[last - 1].strip():
                last -= 1
            new = lines[:last] + block + lines[last:]
    else:
        new = lines + ([""] if lines and lines[-1].strip() else []) + ["mcp_servers:"] + block
    if dry_run:
        return f"Would add {name} to {path}:\n" + "\n".join(["mcp_servers:"] + block)
    bak = _backup(path)
    _write(path, "\n".join(new) + "\n")
    return f"Added {name} to {path}" + (f" (backup: {bak})" if bak else "") + "."


# -- Claude Code (its own command) -------------------------------------------------------------

def claude_code_args(name: str, e: dict) -> list[str]:
    out = ["claude", "mcp", "add", "--scope", "user", name]
    for k, v in e["env"].items():
        out += ["-e", f"{k}={v}"]
    return out + ["--", e["command"], *e["args"]]


def add_claude_code(name: str, e: dict, *, dry_run: bool = False) -> str:
    args = claude_code_args(name, e)
    shown = " ".join(a if re.fullmatch(r"[A-Za-z0-9_./:=@%+-]+", a) else json.dumps(a) for a in args)
    exe = shutil.which("claude")
    if dry_run or not exe:
        return ("Would run:\n  " if dry_run else "Claude Code's `claude` command isn't on the PATH. Run this where it "
                "is:\n  ") + shown
    r = subprocess.run([exe, *args[1:]], capture_output=True, text=True, timeout=60, check=False)
    msg = (r.stdout or "").strip() or (r.stderr or "").strip()
    if r.returncode != 0:
        if "already exists" in msg.lower():
            return f"Claude Code already has {name}; nothing to change. (To swap it: claude mcp remove {name}, then " \
                   "run this again.)"
        raise ConnectError(f"claude mcp add failed: {msg[:300]}")
    return f"Added {name} to Claude Code (for your user, every project)."


# -- what to do next ----------------------------------------------------------------------------

NEXT = {
    "claude-desktop": "Quit Claude Desktop completely and start it again (closing the window isn't enough).",
    "claude-code": "Start a new Claude Code session (or run /mcp in an open one).",
    "hermes": "Restart Hermes's gateway (and its dashboard, if you use one), then open a new chat: an open chat keeps "
              "its old tool list.",
    "other": "Paste it into the app's MCP settings and restart the app.",
}


def next_steps(app: str) -> str:
    return (f"Next (the user does this): {NEXT[app]} The first tool call asks for approval in aiSecurityWarden "
            "(phone or website); approve it. Check with: sw-mcp doctor")
