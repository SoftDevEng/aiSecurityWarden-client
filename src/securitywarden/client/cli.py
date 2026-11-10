"""swctl — SecurityWarden command-line client.

Machine use (e.g. as a Hermes Agent command helper)::

    SW_SERVER_URL=https://vault.example.com SW_ACCESS_TOKEN_FILE=~/.config/sw/token swctl export

This machine's stored tokens (never their secrets), and moving an older token file into SW_Tokens.json::

    swctl tokens list
    swctl --server https://vault.example.com tokens import --file ~/.config/securitywarden/gmail-token   # name asked

Admin use::

    swctl admin project create hermes-webull
    swctl admin secret set hermes-webull WEBULL_APP_KEY        # prompts, value never in argv
    swctl admin token create hermes-webull --name jarvis --expires-days 180
    swctl admin token set-approval <token-id> --approval session --session-ttl 8h --channel admin_ui
    swctl admin token set-actions <token-id> --rule 'gmail.read.*=allow' --rule 'gmail.label=window:30m' \
          --rule 'gmail.send=each' --channel admin_ui --channel push:telegram
    swctl admin approvals list
    swctl admin 2fa status            # the admin credential's two-factor sign-in
    swctl admin signout               # end the cached 2FA session now

The admin credential needs a code from an authenticator app (Microsoft Authenticator, Google Authenticator,
...) when the server requires it (the default). The first sign-in sets the app up. One code starts a 2FA session
that later commands reuse until it ends; its token is cached next to the admin credential file (owner-only),
and is useless without the credential.
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
from ..approval import CHANNELS, DEFAULTS, describe, describe_actions, parse_action_rule, parse_duration
from .api import SecurityWardenClient, SecurityWardenError, action_lines
from ..crypto import CryptoError

ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DEFAULT_ADMIN_FILE = os.path.join("~", ".config", "securitywarden", "admin.cred")
MFA_CACHE_FILE = os.path.join("~", ".config", "securitywarden", "admin-2fa-sessions.json")


class TerminalSecondFactor:
    """Asks for the admin credential's second factor in the terminal (prompts on stderr)."""

    def code(self, retry: bool) -> str:
        if retry:
            print("swctl: that code was wrong (or already used); wait for the next one.", file=sys.stderr)
        return _ask("Code from your authenticator app (or a recovery code): ")

    def setup(self, key_text: str, uri: str, retry: bool) -> str:
        if retry:
            print("swctl: that code didn't match; check the key and try the next code.", file=sys.stderr)
        else:
            print("\nThis admin credential needs two-factor sign-in. Add it to your authenticator app\n"
                  "(Microsoft Authenticator: + > Other account > Enter code manually) with this key:\n\n"
                  f"    {key_text}\n\n"
                  "Or open this link on the phone, or turn it into a QR code:\n"
                  f"    {uri}\n", file=sys.stderr)
        return _ask("Code the app shows now: ")

    def recovery_codes(self, codes: list[str]) -> None:
        print("\nTwo-factor sign-in is on. Save these single-use recovery codes somewhere safe (a password\n"
              "manager). Each one signs in once if you lose your phone. They won't be shown again:\n", file=sys.stderr)
        for c in codes:
            print(f"    {c}", file=sys.stderr)
        print("", file=sys.stderr)


def _ask(prompt: str) -> str:
    print(prompt, end="", file=sys.stderr, flush=True)
    line = sys.stdin.readline()
    if not line:
        _die("no code given")
    return line.strip()


def _mfa_cache() -> tuple[str, dict]:
    path = os.path.expanduser(MFA_CACHE_FILE)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return path, data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return path, {}


def _mfa_cache_key(server: str, cred_id: str) -> str:
    return f"{server.rstrip('/')}|{cred_id}"


def _save_mfa_session(c: SecurityWardenClient) -> None:
    path, data = _mfa_cache()
    key = _mfa_cache_key(c.base, c.cred.id)
    token = c.mfa_session
    if data.get(key) == token:
        return
    if token:
        data[key] = token
    else:
        data.pop(key, None)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)


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
        from .tokens import TokenStore
        store = TokenStore()
        try:
            tid = store.pick(args.token_name or os.environ.get("SW_TOKEN_NAME"),
                             token_id=args.token_id or os.environ.get("SW_TOKEN_ID"), server=_server(args))
            if not tid:
                _die(f"no machine token: none for this program in {store.path} (swctl setup), and no --token-file, "
                     "SW_ACCESS_TOKEN_FILE or SW_ACCESS_TOKEN")
            cred = str(store.credential(tid))
        except SecurityWardenError as e:
            _die(str(e))
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
    server = _server(args)
    from ..crypto import parse_credential
    cached = _mfa_cache()[1].get(_mfa_cache_key(server, parse_credential(cred).id))
    c = SecurityWardenClient(server, cred, verify=_verify(args), second_factor=TerminalSecondFactor(),
                             mfa_session=cached if isinstance(cached, str) else None)
    _ADMIN_CLIENTS.append(c)
    return c


_ADMIN_CLIENTS: list[SecurityWardenClient] = []   # their 2FA sessions are cached when the command ends


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

def cmd_setup(args: argparse.Namespace) -> int:
    """Put this machine's token in place from a one-time setup code (made on the website or with
    ``swctl admin token create --setup-code``): in SW_Tokens.json under its name, or with --token-file (or
    SW_ACCESS_TOKEN_FILE) in a file of its own."""
    from .setup import setup_from_code, setup_into_store, token_file_exists
    from .tokens import TokenStore
    path = args.token_file or os.environ.get("SW_ACCESS_TOKEN_FILE")
    name = args.token_name or os.environ.get("SW_TOKEN_NAME")
    tid = args.token_id or os.environ.get("SW_TOKEN_ID")
    store = TokenStore()
    if path and token_file_exists(path) and not args.replace:
        _die(f"{os.path.expanduser(path)} already holds a token (use --replace to swap it for a new one)")
    try:
        have = not path and (name or tid) and store.pick(name, token_id=tid, server=_server(args)) is not None
    except SecurityWardenError as e:
        _die(str(e))
    if have and not args.replace:
        _die(f"{store.path} already holds this program's token (use --replace to swap it for a new one)")
    code = sys.stdin.readline() if args.code_stdin else getpass.getpass("Setup code (SWS1-..., not shown): ")
    try:
        if path:
            cred, where = setup_from_code(_server(args), code, path, replace=args.replace, verify=_verify(args))
            print(f"Token {cred.id} stored in {where} (readable by you only).", file=sys.stderr)
        else:
            cred, name = setup_into_store(_server(args), code, store, name, token_id=tid, replace=args.replace,
                                          verify=_verify(args))
            print(f"Token {name!r} stored in {store.path} (readable by you only). Programs use it with "
                  f"SW_TOKEN_ID={cred.id} SW_TOKEN_NAME={name} (or alone, while it's the only token there).",
                  file=sys.stderr)
    except (SecurityWardenError, OSError) as e:
        _die(str(e))
    return 0



def cmd_tokens(args: argparse.Namespace) -> int:
    """The tokens in SW_Tokens.json on this machine (never their secrets), and moving a token file of its own
    (SW_ACCESS_TOKEN_FILE, from older setups) into it."""
    import time
    from ..crypto import CryptoError, parse_credential
    from .tokens import TokenStore
    store = TokenStore()
    if args.action == "list":
        try:
            rows = store.entries()
        except SecurityWardenError as e:
            _die(str(e))
        if not rows:
            print(f"no tokens in {store.path}")
        for e in rows:
            when = time.strftime("%Y-%m-%d", time.localtime(e["saved_at"])) if e.get("saved_at") else "-"
            print(f"{e['id']}  {e['name']:<24} {e.get('project') or '-':<16} {e.get('server') or '-'}  saved {when}")
        return 0
    # import
    path = args.file
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as f:
            cred = parse_credential(f.read())
    except FileNotFoundError:
        _die(f"no token file at {path}")
    except (OSError, CryptoError, ValueError) as e:
        _die(f"{path} doesn't hold a machine token ({e})")
    if cred.kind != "m":
        _die(f"{path} holds an admin credential, not a machine token; it doesn't belong in SW_Tokens.json")
    server = _server(args)
    from .api import token_identity
    name, project, account = args.name, None, None
    try:
        if store.entry(cred.id) is not None:
            name = store.entry(cred.id)["name"]
            print(f"{store.path} already holds this token ({name!r}); nothing to do.", file=sys.stderr)
        else:
            if not name:                    # ask the server, with the token itself
                who = token_identity(server, cred, verify=_verify(args))
                name, project, account = who["name"], who["project"], who["account"]
                print(f"The server knows this token as {name!r}" + (f" (project {project})" if project else "") + ".",
                      file=sys.stderr)
            store.put(cred, name=name, server=server, project=project, account=account)
            print(f"Token {name!r} ({cred.id}) copied into {store.path} (readable by you only).", file=sys.stderr)
    except SecurityWardenError as e:
        _die(str(e))
    print(f"\nIn the program's MCP settings, replace SW_ACCESS_TOKEN_FILE with:\n  SW_TOKEN_ID={cred.id}\n"
          f"  SW_TOKEN_NAME={name}\nand use the arguments: serve (without --connector, if the website ticks the "
          f"connectors for this token). Once it works, delete {path}.", file=sys.stderr)
    return 0


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
            policy["timeout"] = _limit(args.approval_timeout, parse_duration)
    except ValueError as e:
        _die(str(e))
    if args.max_pending is not None:
        policy["max_pending"] = args.max_pending
    if args.max_per_hour is not None:
        policy["max_per_hour"] = None if args.max_per_hour == NO_LIMIT else args.max_per_hour
    return policy


NO_LIMIT = "none"


def _limit(text: str, parse):  # noqa: ANN001, ANN202
    """A limit from the command line; "none" means no limit."""
    return None if str(text).strip().lower() in ("none", "no-limit", "unlimited") else parse(text)


def _per_hour(text: str):  # noqa: ANN202
    t = str(text).strip().lower()
    if t in ("none", "no-limit", "unlimited"):
        return NO_LIMIT
    try:
        return int(t)
    except ValueError:
        raise argparse.ArgumentTypeError("a whole number, or none for no limit") from None


def cmd_token(args: argparse.Namespace) -> int:
    c = _admin_client(args)
    if args.action == "create":
        if args.approval is None:
            # new tokens need a person's OK to read secrets unless that is turned off on purpose
            args.approval = "session"
            print("Approval: once per session (the default; --approval none turns it off).", file=sys.stderr)
        tok = c.create_token(args.project, args.name, args.expires_days, args.allow_ip, _policy_from_args(args))
        if args.setup_code:
            code = c.create_setup_code(tok.id, tok)
            print(f"Setup code for {args.name} (project {args.project}); works once, for 10 minutes:\n",
                  file=sys.stderr)
            print(code)
            print("\nOn the machine: swctl setup (or sw-mcp setup), or tell its AI agent to set up SecurityWarden "
                  "with this code.", file=sys.stderr)
        else:
            print(f"Machine token for {args.name} (project {args.project}). Shown ONCE:\n", file=sys.stderr)
            print(str(tok))
            print("\nOn the machine, swctl setup is easier: create the token with --setup-code instead. Or store "
                  "it in a file only its user can read and point SW_ACCESS_TOKEN_FILE at it.", file=sys.stderr)
        if args.allow_ip:
            print(f"It only works from: {', '.join(args.allow_ip)}", file=sys.stderr)
        else:
            print("Warning: it works from any address. Limit it to the machine that uses it with --allow-ip.",
                  file=sys.stderr)
        if args.approval not in (None, "none"):
            print("A person must approve its use (see: swctl admin approvals list).", file=sys.stderr)
        else:
            print("Warning: no approval. Anyone with this token can read the project's secrets without asking.",
                  file=sys.stderr)
    elif args.action == "list":
        rows = c.list_tokens(args.project)
        names = {p["id"]: p["name"] for p in c.list_projects()}
        for t in rows:
            state = "REVOKED" if t["revoked_at"] else "active"
            print(f"{t['id']}  {t['name']:<20} {names.get(t['project_id'], '-'):<20} {state:<8} "
                  f"expires {_ts(t['expires_at'])}  last used {_ts(t['last_used_at'])} {t['last_ip'] or ''}"
                  f"  from {', '.join(t.get('allowed_ips') or ['any'])}  approval {describe(t.get('approval'))}"
                  + ((f" ({t['approvals_this_hour']} this hour, no hourly limit)" if t["approval"].get("max_per_hour") is None
                      else f" ({t['approvals_this_hour']}/{t['approval']['max_per_hour']} this hour)")
                     if t.get("approval") else "")
                  + f"  actions {describe_actions(t.get('actions'))}")
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
    elif args.action == "set-actions":
        if args.default and (args.rule or args.channel or args.action_timeout):
            _die("--default replaces the whole action policy; give it alone")
        policy = None
        if not args.default:
            try:
                policy = {"rules": [parse_action_rule(r) for r in args.rule or []]}
                if args.channel:
                    policy["channels"] = args.channel
                if args.action_timeout:
                    policy["timeout"] = _limit(args.action_timeout, parse_duration)
                for key in ("max_pending", "max_per_hour"):
                    if getattr(args, key) is not None:
                        policy[key] = None if getattr(args, key) == NO_LIMIT else getattr(args, key)
            except ValueError as e:
                _die(str(e))
        policy = c.set_token_actions(args.id, policy)
        print(f"{args.id} actions: {describe_actions(policy)} (pending action requests and open windows ended)")
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
            what = {"auth": "session", "fetch": "fetch"}.get(a["kind"], "action")
            note = "" if a["decidable"] else "  (not decidable here: admin_ui is not a channel)"
            print(f"{a['id']}  match {a['match']}  {a['token_name']:<20} {what:<8} from {a['ip']:<16} "
                  f"expires {_ts(a['expires_at'])}{note}")
            if a["kind"] == "action":
                print(f"    {_action_text(c, a)}")
            elif a.get("origin"):
                print(f"    started by {' <- '.join(a['origin'])} (as the machine reports it)")
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


def _action_text(c: SecurityWardenClient, a: dict) -> str:
    """What an action request wants (decrypted here when the project keeps summaries encrypted)."""
    return action_lines(a["action"], c.action_summary(a)).replace("\n", "\n    ")


def cmd_2fa(args: argparse.Namespace) -> int:
    c = _admin_client(args)
    if args.action == "status":
        st = c.second_factor_status()
        print(f"two-factor sign-in: {'on' if st['enabled'] else 'off'}"
              f"{' (required by this server)' if st['required'] else ''}")
        if st["enabled"]:
            print(f"recovery codes left: {st['recovery_codes_left']}")
    elif args.action == "recovery-codes":
        c.check_token()        # sign in first, so the code asked for below is a fresh one
        TerminalSecondFactor().recovery_codes(c.new_recovery_codes(_ask("Current code from your authenticator app: ")))
    return 0


def cmd_signout(args: argparse.Namespace) -> int:
    c = _admin_client(args)
    c.sign_out()
    print("Signed out: the next admin command asks for a code again.", file=sys.stderr)
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    for e in reversed(_admin_client(args).audit(args.limit)):
        print(f"{_ts(e['ts'])}  {'ok ' if e['ok'] else 'FAIL'} {e['action']:<15} "
              f"{e['cred_id'] or '-':<24} {e['ip'] or '-':<16} {e['detail'] or ''}")
    return 0


# ---------------------------------------------------------------------------

def _approval_args(x: argparse.ArgumentParser) -> None:
    x.add_argument("--approval", choices=["none", "session", "every_fetch"],
                   help="require a person to approve: once per session, or every fetch (new tokens: session; "
                        "none turns it off)")
    x.add_argument("--session-ttl", metavar="DURATION", help="how long an approved session lasts, e.g. 8h (default 8h)")
    x.add_argument("--channel", action="append", choices=CHANNELS,
                   help="where approval requests go (repeatable; default admin_ui)")
    x.add_argument("--approval-timeout", metavar="DURATION", help="how long a request waits, e.g. 120s (default 120s; none: no limit)")
    x.add_argument("--max-pending", type=int, help="outstanding requests allowed per token (default 1)")
    x.add_argument("--max-per-hour", type=_per_hour, help="requests allowed per token per hour (default 6; none: no limit)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="swctl", description="SecurityWarden client")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--server", help="server URL (default: $SW_SERVER_URL)")
    p.add_argument("--token-file", help="machine token file (default: $SW_ACCESS_TOKEN_FILE)")
    p.add_argument("--token-name", help="the token's name in SW_Tokens.json (default: $SW_TOKEN_NAME)")
    p.add_argument("--token-id", help="the token's id in SW_Tokens.json (default: $SW_TOKEN_ID)")
    p.add_argument("--admin-file", help="admin credential file")
    p.add_argument("--ca-bundle", help="custom CA bundle for TLS verification")
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("export", help="print secrets for this machine token")
    e.add_argument("--format", choices=["dotenv", "shell", "json"], default="dotenv")
    e.set_defaults(func=cmd_export)

    r = sub.add_parser("run", help="run a command with secrets in its environment")
    r.add_argument("command", nargs=argparse.REMAINDER)
    r.set_defaults(func=cmd_run)

    st = sub.add_parser("setup", help="store this machine's token from a one-time setup code")
    st.add_argument("--replace", action="store_true", help="replace a token that is already stored")
    st.add_argument("--code-stdin", action="store_true", help="read the code from stdin instead of asking")
    st.set_defaults(func=cmd_setup)

    tk = sub.add_parser("tokens", help="the tokens stored on this machine (SW_Tokens.json)")
    tks = tk.add_subparsers(dest="action", required=True)
    tks.add_parser("list", help="list them (ids, names, servers; never the secrets)")
    x = tks.add_parser("import", help="move a token file of its own (SW_ACCESS_TOKEN_FILE) into SW_Tokens.json")
    x.add_argument("--file", required=True, help="the token file")
    x.add_argument("--name", help="the token's name on the website (default: ask the server, with the token itself)")
    tk.set_defaults(func=cmd_tokens)

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
    x.add_argument("--setup-code", action="store_true",
                   help="print a one-time setup code for the machine instead of the token itself")
    x = tos.add_parser("set-ips", help="replace the addresses a token may connect from")
    x.add_argument("id")
    x.add_argument("--allow-ip", action="append", metavar="ADDR")
    x.add_argument("--any", action="store_true", help="remove the restriction")
    _approval_args(tos.choices["create"])
    x = tos.add_parser("set-approval", help="require (or stop requiring) a person to approve this token's use")
    x.add_argument("id")
    _approval_args(x)
    x = tos.add_parser("set-actions", help="which actions this token's AI agent may take, and how a person approves them")
    x.add_argument("id")
    x.add_argument("--rule", action="append", metavar="ACTION=MODE",
                   help="first match wins: gmail.send=each, gmail.read.*=allow, gmail.label=window:30m, *=deny "
                        "(repeatable; anything unmatched asks every time)")
    x.add_argument("--channel", action="append", choices=CHANNELS, help="where action requests go (default admin_ui)")
    x.add_argument("--action-timeout", metavar="DURATION", help="how long a request waits for a person (default 1h; none: no limit)")
    x.add_argument("--max-pending", type=int, help="outstanding action requests allowed (default 5)")
    x.add_argument("--max-per-hour", type=_per_hour, help="action requests allowed per hour (default 60; none: no limit)")
    x.add_argument("--default", action="store_true", help="back to the defaults: ask for every action")
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

    tf = a.add_parser("2fa", help="the admin credential's two-factor sign-in")
    tfs = tf.add_subparsers(dest="action", required=True)
    tfs.add_parser("status", help="on or off, and recovery codes left")
    tfs.add_parser("recovery-codes", help="replace the recovery codes (needs a current code)")
    tf.set_defaults(func=cmd_2fa)
    so = a.add_parser("signout", help="end the 2FA session cached for this server")
    so.set_defaults(func=cmd_signout)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (SecurityWardenError, CryptoError) as e:
        _die(str(e))
    except KeyboardInterrupt:
        return 130
    finally:
        for c in _ADMIN_CLIENTS:    # keep (or forget) the 2FA session for the next command
            try:
                _save_mfa_session(c)
            except OSError as e:
                print(f"swctl: couldn't cache the 2FA session: {e}", file=sys.stderr)
        _ADMIN_CLIENTS.clear()


if __name__ == "__main__":
    raise SystemExit(main())
