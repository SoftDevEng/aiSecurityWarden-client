"""swctl — SecurityWarden command-line client.

Machine use (e.g. as a Hermes Agent command helper)::

    SW_SERVER_URL=https://vault.example.com SW_ACCESS_TOKEN_FILE=~/.config/sw/token swctl export

Admin use::

    swctl admin project create hermes-webull
    swctl admin secret set hermes-webull WEBULL_APP_KEY        # prompts, value never in argv
    swctl admin token create hermes-webull --name jarvis --expires-days 180
    swctl admin token set-approval <token-id> --approval session --session-ttl 8h --channel admin_ui
    swctl admin approvals list
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shlex
import stat
import subprocess
import sys
from datetime import datetime, timezone

from .. import __version__
from ..approval import CHANNELS, DEFAULTS, describe, parse_duration
from .api import SecurityWardenClient, SecurityWardenError
from ..crypto import CryptoError

ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DEFAULT_ADMIN_FILE = os.path.join("~", ".config", "securitywarden", "admin.cred")


def _die(msg: str, code: int = 1) -> "NoReturn":  # type: ignore[name-defined]
    print(f"swctl: {msg}", file=sys.stderr)
    raise SystemExit(code)


def _read_cred_file(path: str) -> str:
    path = os.path.expanduser(path)
    try:
        st = os.stat(path)
    except FileNotFoundError:
        _die(f"credential file not found: {path}")
    if os.name == "posix" and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        print(f"swctl: warning: {path} is readable by group/others; run: chmod 600 {path}", file=sys.stderr)
    with open(path, encoding="utf-8") as f:
        return f.read().strip()


def _server(args: argparse.Namespace) -> str:
    url = args.server or os.environ.get("SW_SERVER_URL")
    if not url:
        _die("no server URL (use --server or SW_SERVER_URL)")
    return url


def _machine_client(args: argparse.Namespace) -> SecurityWardenClient:
    if args.token_file:
        cred = _read_cred_file(args.token_file)
    elif os.environ.get("SW_ACCESS_TOKEN_FILE"):
        cred = _read_cred_file(os.environ["SW_ACCESS_TOKEN_FILE"])
    elif os.environ.get("SW_ACCESS_TOKEN"):
        cred = os.environ["SW_ACCESS_TOKEN"]
    else:
        _die("no machine token (use --token-file, SW_ACCESS_TOKEN_FILE or SW_ACCESS_TOKEN)")
    return SecurityWardenClient(_server(args), cred, verify=_verify(args), on_approval=_announce_approval)


def _announce_approval(info: dict) -> None:
    """Only the match code goes to stderr; stdout stays clean for `export`."""
    what = "this session" if info["kind"] == "auth" else "this fetch"
    print(f"swctl: waiting for a person to approve {what} (match code {info['match']}, "
          f"up to {info['expires_in']} s)...", file=sys.stderr, flush=True)


def _admin_client(args: argparse.Namespace) -> SecurityWardenClient:
    if args.admin_file:
        cred = _read_cred_file(args.admin_file)
    elif os.environ.get("SW_ADMIN_CREDENTIAL_FILE"):
        cred = _read_cred_file(os.environ["SW_ADMIN_CREDENTIAL_FILE"])
    elif os.environ.get("SW_ADMIN_CREDENTIAL"):
        cred = os.environ["SW_ADMIN_CREDENTIAL"]
    elif os.path.exists(os.path.expanduser(DEFAULT_ADMIN_FILE)):
        cred = _read_cred_file(DEFAULT_ADMIN_FILE)
    else:
        _die(f"no admin credential (use --admin-file, SW_ADMIN_CREDENTIAL_FILE, or {DEFAULT_ADMIN_FILE})")
    return SecurityWardenClient(_server(args), cred, verify=_verify(args))


def _verify(args: argparse.Namespace) -> bool | str:
    return args.ca_bundle or os.environ.get("SW_CA_BUNDLE") or True


def _ts(v: int | None) -> str:
    return datetime.fromtimestamp(v, timezone.utc).strftime("%Y-%m-%d %H:%M") if v else "-"


# ---------------------------------------------------------------------------
# machine commands
# ---------------------------------------------------------------------------

def _validated(secrets: dict[str, str]) -> dict[str, str]:
    for name in secrets:
        if not ENV_NAME_RE.match(name):
            _die(f"secret name {name!r} is not a valid environment variable name")
    return secrets


def cmd_export(args: argparse.Namespace) -> int:
    secrets = _validated(_machine_client(args).fetch())
    if args.format == "json":
        print(json.dumps(secrets, indent=2))
    elif args.format == "shell":
        for k in sorted(secrets):
            print(f"export {k}={shlex.quote(secrets[k])}")
    else:  # dotenv: plain KEY=VALUE lines (Hermes command-helper format)
        for k in sorted(secrets):
            v = secrets[k]
            if "\n" in v or "\r" in v:
                _die(f"secret {k} contains a newline; use --format json or shell")
            print(f"{k}={v}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not cmd:
        _die("usage: swctl run -- <command> [args...]")
    env = {**os.environ, **_validated(_machine_client(args).fetch())}
    if os.name == "posix":
        os.execvpe(cmd[0], cmd, env)
    return subprocess.call(cmd, env=env)


# ---------------------------------------------------------------------------
# admin commands
# ---------------------------------------------------------------------------

def cmd_project(args: argparse.Namespace) -> int:
    c = _admin_client(args)
    if args.action == "create":
        pid = c.create_project(args.name)
        print(f"created project {args.name} ({pid})")
    elif args.action == "list":
        for p in c.list_projects():
            print(f"{p['name']:<30} {p['id']}  created {_ts(p['created_at'])}")
    elif args.action == "delete":
        if not args.yes:
            _die("deleting a project destroys its secrets and revokes its tokens; re-run with --yes")
        c.delete_project(args.name)
        print(f"deleted project {args.name}")
    return 0


def cmd_secret(args: argparse.Namespace) -> int:
    c = _admin_client(args)
    if args.action == "set":
        if not ENV_NAME_RE.match(args.name):
            _die("secret names must be valid environment variable names (A-Z, 0-9, _)")
        if sys.stdin.isatty():
            value = getpass.getpass(f"Value for {args.name}: ")
            if getpass.getpass("Repeat: ") != value:
                _die("values did not match")
        else:
            value = sys.stdin.read().rstrip("\n")
        if not value:
            _die("empty value")
        c.set_secret(args.project, args.name, value)
        print(f"set {args.project}/{args.name}")
    elif args.action == "list":
        for name in sorted(c.get_secrets(args.project)):
            print(name)
    elif args.action == "get":
        secrets = c.get_secrets(args.project)
        if args.name not in secrets:
            _die(f"no secret {args.name} in {args.project}")
        print(secrets[args.name])
    elif args.action == "delete":
        c.delete_secret(args.project, args.name)
        print(f"deleted {args.project}/{args.name}")
    return 0


def _policy_from_args(args: argparse.Namespace) -> dict | None:
    """Build an approval policy from --approval and friends. None means 'no approval'."""
    extras = [args.session_ttl, args.channel, args.approval_timeout, args.max_pending, args.max_per_hour]
    if args.approval in (None, "none"):
        if any(x is not None for x in extras):
            _die("approval options need --approval session or --approval every_fetch")
        return None
    policy: dict = {"mode": args.approval, "channels": args.channel or list(DEFAULTS["channels"])}
    try:
        if args.session_ttl is not None:
            policy["session_ttl"] = parse_duration(args.session_ttl)
        if args.approval_timeout is not None:
            policy["timeout"] = parse_duration(args.approval_timeout)
    except ValueError as e:
        _die(str(e))
    if args.max_pending is not None:
        policy["max_pending"] = args.max_pending
    if args.max_per_hour is not None:
        policy["max_per_hour"] = args.max_per_hour
    return policy


def cmd_token(args: argparse.Namespace) -> int:
    c = _admin_client(args)
    if args.action == "create":
        tok = c.create_token(args.project, args.name, args.expires_days, args.allow_ip, _policy_from_args(args))
        print(f"Machine token for {args.name} (project {args.project}). Shown ONCE:\n", file=sys.stderr)
        print(str(tok))
        print("\nStore it on the machine in a chmod 600 file and point SW_ACCESS_TOKEN_FILE at it.",
              file=sys.stderr)
        if args.allow_ip:
            print(f"It only works from: {', '.join(args.allow_ip)}", file=sys.stderr)
        if args.approval not in (None, "none"):
            print("A person must approve its use (see: swctl admin approvals list).", file=sys.stderr)
    elif args.action == "list":
        rows = c.list_tokens(args.project)
        names = {p["id"]: p["name"] for p in c.list_projects()}
        for t in rows:
            state = "REVOKED" if t["revoked_at"] else "active"
            print(f"{t['id']}  {t['name']:<20} {names.get(t['project_id'], '-'):<20} {state:<8} "
                  f"expires {_ts(t['expires_at'])}  last used {_ts(t['last_used_at'])} {t['last_ip'] or ''}"
                  f"  from {', '.join(t.get('allowed_ips') or ['any'])}  approval {describe(t.get('approval'))}"
                  + (f" ({t['approvals_this_hour']}/{t['approval']['max_per_hour']} this hour)" if t.get("approval") else ""))
    elif args.action == "set-ips":
        if bool(args.allow_ip) == args.any:
            _die("give either --allow-ip (one or more) or --any")
        ips = c.set_token_ips(args.id, None if args.any else args.allow_ip)
        print(f"{args.id} usable from: {', '.join(ips or ['any'])}")
    elif args.action == "set-approval":
        if args.approval is None:
            _die("give --approval none, session or every_fetch")
        policy = c.set_token_approval(args.id, _policy_from_args(args))
        print(f"{args.id} approval: {describe(policy)} (pending requests and approved sessions were cancelled)")
    elif args.action == "reset-approval-limits":
        n = c.reset_approval_limits(args.id)
        print(f"{args.id} may ask for approval again now ({n} pending request(s) cancelled)")
    elif args.action == "revoke":
        c.revoke_token(args.id)
        print(f"revoked {args.id}")
    return 0


def cmd_approvals(args: argparse.Namespace) -> int:
    c = _admin_client(args)
    if args.action == "list":
        rows = c.list_approvals()
        if not rows:
            print("no pending approval requests", file=sys.stderr)
        for a in rows:
            what = "session" if a["kind"] == "auth" else "fetch"
            note = "" if a["decidable"] else "  (not decidable here: admin_ui is not a channel)"
            print(f"{a['id']}  match {a['match']}  {a['token_name']:<20} {what:<8} from {a['ip']:<16} "
                  f"expires {_ts(a['expires_at'])}{note}")
    else:
        if args.match is not None:
            pending = {a["id"]: a for a in c.list_approvals()}
            if args.id not in pending:
                _die("no such pending request (already decided or expired?)")
            if pending[args.id]["match"] != args.match:
                _die("the match code does not match; nothing was decided")
        status = c.decide_approval(args.id, args.action == "approve")
        print(f"{args.id} {status}")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    for e in reversed(_admin_client(args).audit(args.limit)):
        print(f"{_ts(e['ts'])}  {'ok ' if e['ok'] else 'FAIL'} {e['action']:<15} "
              f"{e['cred_id'] or '-':<24} {e['ip'] or '-':<16} {e['detail'] or ''}")
    return 0


# ---------------------------------------------------------------------------

def _approval_args(x: argparse.ArgumentParser) -> None:
    x.add_argument("--approval", choices=["none", "session", "every_fetch"],
                   help="require a person to approve: once per session, or every fetch (default: none)")
    x.add_argument("--session-ttl", metavar="DURATION", help="how long an approved session lasts, e.g. 8h (default 8h)")
    x.add_argument("--channel", action="append", choices=CHANNELS,
                   help="where approval requests go (repeatable; default admin_ui)")
    x.add_argument("--approval-timeout", metavar="DURATION", help="how long a request waits, e.g. 120s (default 120s)")
    x.add_argument("--max-pending", type=int, help="outstanding requests allowed per token (default 1)")
    x.add_argument("--max-per-hour", type=int, help="requests allowed per token per hour (default 6)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="swctl", description="SecurityWarden client")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--server", help="server URL (default: $SW_SERVER_URL)")
    p.add_argument("--token-file", help="machine token file (default: $SW_ACCESS_TOKEN_FILE)")
    p.add_argument("--admin-file", help="admin credential file")
    p.add_argument("--ca-bundle", help="custom CA bundle for TLS verification")
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("export", help="print secrets for this machine token")
    e.add_argument("--format", choices=["dotenv", "shell", "json"], default="dotenv")
    e.set_defaults(func=cmd_export)

    r = sub.add_parser("run", help="run a command with secrets in its environment")
    r.add_argument("command", nargs=argparse.REMAINDER)
    r.set_defaults(func=cmd_run)

    a = sub.add_parser("admin", help="administer projects, secrets and tokens").add_subparsers(
        dest="area", required=True)

    pr = a.add_parser("project")
    prs = pr.add_subparsers(dest="action", required=True)
    x = prs.add_parser("create"); x.add_argument("name")
    prs.add_parser("list")
    x = prs.add_parser("delete"); x.add_argument("name"); x.add_argument("--yes", action="store_true")
    pr.set_defaults(func=cmd_project)

    se = a.add_parser("secret")
    ses = se.add_subparsers(dest="action", required=True)
    for act in ("set", "get", "delete"):
        x = ses.add_parser(act); x.add_argument("project"); x.add_argument("name")
    x = ses.add_parser("list"); x.add_argument("project")
    se.set_defaults(func=cmd_secret)

    to = a.add_parser("token")
    tos = to.add_subparsers(dest="action", required=True)
    x = tos.add_parser("create"); x.add_argument("project"); x.add_argument("--name", required=True)
    x.add_argument("--expires-days", type=float)
    x.add_argument("--allow-ip", action="append", metavar="ADDR",
                   help="address or CIDR range the token may connect from (repeatable; default: any)")
    x = tos.add_parser("set-ips", help="replace the addresses a token may connect from")
    x.add_argument("id")
    x.add_argument("--allow-ip", action="append", metavar="ADDR")
    x.add_argument("--any", action="store_true", help="remove the restriction")
    _approval_args(tos.choices["create"])
    x = tos.add_parser("set-approval", help="require (or stop requiring) a person to approve this token's use")
    x.add_argument("id")
    _approval_args(x)
    x = tos.add_parser("reset-approval-limits",
                       help="let a token ask for approval again now (restarts its hourly limit, cancels pending)")
    x.add_argument("id")
    x = tos.add_parser("list"); x.add_argument("project", nargs="?")
    x = tos.add_parser("revoke"); x.add_argument("id")
    to.set_defaults(func=cmd_token)

    ap = a.add_parser("approvals", help="pending human-approval requests")
    aps = ap.add_subparsers(dest="action", required=True)
    aps.add_parser("list")
    for act in ("approve", "deny"):
        x = aps.add_parser(act); x.add_argument("id")
        x.add_argument("--match", help="refuse unless the request shows this match code")
    ap.set_defaults(func=cmd_approvals)

    au = a.add_parser("audit"); au.add_argument("--limit", type=int, default=50)
    au.set_defaults(func=cmd_audit)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (SecurityWardenError, CryptoError) as e:
        _die(str(e))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
