"""sw-mcp: run SecurityWarden connectors as an MCP server for an AI agent (Hermes, Claude Desktop, ...).

    sw-mcp serve --connector gmail                  # stdio MCP server; SW_SERVER_URL + SW_ACCESS_TOKEN_FILE
    sw-mcp serve --config ~/.config/sw/mcp.json
    sw-mcp tools [--connector gmail]                # what the agent will see, with actions and risks
    sw-mcp login gmail                              # one-time Google sign-in for the Gmail connector
    sw-mcp call gmail_search query=is:unread limit=5    # try one tool by hand (waits for approval)

Config file (JSON; every key optional, environment variables and options win):
    {"server": "https://vault.example.com", "token_file": "~/.config/sw/jarvis.token",
     "ca_bundle": null, "connectors": ["gmail"]}
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from typing import Any

from .. import __version__
from ..client.api import SecurityWardenClient, SecurityWardenError
from ..client.cli import _read_cred_file
from .framework import Connector, Hub
from .server import StdioServer

BUILTIN = {"gmail": "securitywarden.mcp.gmail:Gmail"}


def _die(msg: str, code: int = 1) -> "NoReturn":  # type: ignore[name-defined]
    print(f"sw-mcp: {msg}", file=sys.stderr)
    raise SystemExit(code)


def load_connector(ref: str) -> type[Connector]:
    """"gmail" or "package.module:ClassName" (a third-party connector)."""
    target = BUILTIN.get(ref, ref)
    mod_name, sep, cls_name = target.partition(":")
    if not sep:
        _die(f"unknown connector {ref!r} (built in: {', '.join(BUILTIN)}; or package.module:ClassName)")
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
    if not isinstance(cfg, dict) or set(cfg) - {"server", "token_file", "ca_bundle", "connectors"}:
        _die(f"{path}: expected an object with server, token_file, ca_bundle, connectors")
    if any(str(v).startswith("sw1.") for v in cfg.values()):
        _die(f"{path}: put the token in its own file (chmod 600) and name that file in token_file")
    return cfg


def _connectors(args: argparse.Namespace, cfg: dict[str, Any]) -> list[type[Connector]]:
    refs = args.connector or (os.environ.get("SW_MCP_CONNECTORS", "").split(",") if os.environ.get("SW_MCP_CONNECTORS")
                              else cfg.get("connectors") or [])
    refs = [r.strip() for r in refs if r.strip()]
    if not refs:
        _die("no connectors enabled (use --connector gmail, SW_MCP_CONNECTORS or \"connectors\" in the config)")
    return [load_connector(r) for r in dict.fromkeys(refs)]


def _client(args: argparse.Namespace, cfg: dict[str, Any]) -> SecurityWardenClient:
    url = args.server or os.environ.get("SW_SERVER_URL") or cfg.get("server")
    if not url:
        _die("no server URL (use --server, SW_SERVER_URL or \"server\" in the config)")
    token_file = args.token_file or os.environ.get("SW_ACCESS_TOKEN_FILE") or cfg.get("token_file")
    if token_file:
        cred = _read_cred_file(token_file)
    elif os.environ.get("SW_ACCESS_TOKEN"):
        cred = os.environ["SW_ACCESS_TOKEN"]
    else:
        _die("no machine token (use --token-file, SW_ACCESS_TOKEN_FILE or \"token_file\" in the config)")
    verify = args.ca_bundle or os.environ.get("SW_CA_BUNDLE") or cfg.get("ca_bundle") or True

    def announce(info: dict) -> None:
        print(f"sw-mcp: waiting for a person to approve this {'session' if info['kind'] == 'auth' else 'fetch'} "
              f"(match code {info['match']}, up to {info['expires_in']} s)...", file=sys.stderr, flush=True)
    try:
        return SecurityWardenClient(url, cred, verify=verify, on_approval=announce)
    except (SecurityWardenError, ValueError) as e:
        _die(str(e))


def cmd_serve(args: argparse.Namespace) -> None:
    cfg = _config(args)
    hub = Hub(_client(args, cfg), _connectors(args, cfg))
    print(f"sw-mcp {__version__}: serving {', '.join(i.name for i in hub.instances)} "
          f"({len(hub.tools)} tools) on stdio", file=sys.stderr, flush=True)
    StdioServer(hub).serve()


def cmd_tools(args: argparse.Namespace) -> None:
    cfg = _config(args)
    for cls in _connectors(args, cfg):
        print(f"{cls.name}: {cls.description}")
        for spec in cls.tool_specs():
            print(f"  {cls.name}_{spec.name:<18} {spec.action:<22} {spec.risk:<6} {spec.description.split('.')[0]}")
        if cls.suggested_rules:
            print("  suggested rules:  swctl admin token set-actions TOKEN_ID " +
                  " ".join(f"--rule {r}" for r in cls.suggested_rules))
    print("  check_approval     (built in: check on, and then do, an action waiting for approval)")


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
    hub = Hub(_client(args, cfg), _connectors(args, cfg))
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
        sp.add_argument("--token-file", help="machine token file (default: $SW_ACCESS_TOKEN_FILE)")
        sp.add_argument("--ca-bundle", help="CA bundle for a private certificate (default: $SW_CA_BUNDLE)")
        if connectors:
            sp.add_argument("--connector", action="append", help="connector to enable (repeat): gmail or module:Class")

    s = sub.add_parser("serve", help="run the MCP server on stdio")
    common(s)
    s.set_defaults(fn=cmd_serve)
    t = sub.add_parser("tools", help="list the tools, their actions and risks")
    common(t)
    t.set_defaults(fn=cmd_tools)
    c = sub.add_parser("call", help="run one tool by hand, waiting for approval if needed (for testing)")
    c.add_argument("tool", help="tool name, e.g. gmail_search (see: sw-mcp tools)")
    c.add_argument("values", nargs="*", help="arguments as NAME=VALUE; lists separated by commas; \\n for a new line")
    c.add_argument("--wait", type=int, default=900, help="seconds to wait for an approval (default 900)")
    common(c)
    c.set_defaults(fn=cmd_call)
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
