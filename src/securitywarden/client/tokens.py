"""SW_Tokens.json: every machine token on this machine, in one file only this user can read, by token id.

Each bot's MCP settings (or swctl) say which token they use: ``SW_TOKEN_ID`` (what the software goes by) and
``SW_TOKEN_NAME`` (the token's name on the website, for people and as a fallback). Keying by id means two
accounts or servers with a token of the same name never collide in one file::

    {"format": "sw-tokens-2",
     "tokens": {"xRSfLsPmlCXH0TRes8Jl3w": {"name": "jarvis-gmail", "token": "sw1.m....",
                                           "server": "https://vault.example.com", "project": "Gmail",
                                           "saved_at": 1793400000},
                "OldIdOfARevokedToken0": {"name": "jarvis-gmail", "server": "https://vault.example.com",
                                          "replaced_by": "xRSfLsPmlCXH0TRes8Jl3w", "replaced_at": 1793400000}}}

**Replacing a token** keeps every bot's settings working: when a setup code stores a new token with the same name
and server as a stored one (allowed only once the old token is rejected, i.e. revoked), the old entry keeps just a
``replaced_by`` pointer (its secret is removed), and settings naming the old id follow it.

**Finding the token** (:meth:`TokenStore.pick`): by ``SW_TOKEN_ID`` when given (following ``replaced_by``); else
by name, matched with the server when one is given; several matches is an error, never a guess. Nothing given: the
only token stored.

Files in the older ``sw-tokens-1`` format (keyed by name) are read as before and converted on the next write; the
old file is kept next to it as ``SW_Tokens.json.v1.bak`` (owner-only).

Location: ``SW_TOKENS_FILE``, else ``%APPDATA%\\SecurityWarden\\SW_Tokens.json`` (Windows) or
``$XDG_CONFIG_HOME/securitywarden/SW_Tokens.json`` (default ``~/.config/securitywarden``). Several processes may
set up at once: writes take a lock file and replace the file in one step.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from ..crypto import ID_RE, Credential, CryptoError, parse_credential
from .api import SecurityWardenError

FILE_NAME = "SW_Tokens.json"
FORMAT = "sw-tokens-2"
OLD_FORMAT = "sw-tokens-1"
NAME_MAX = 100
LOCK_STALE = 30.0
MAX_HOPS = 20


def default_tokens_path() -> str:
    if os.environ.get("SW_TOKENS_FILE"):
        return os.path.expanduser(os.environ["SW_TOKENS_FILE"])
    if os.name == "nt" and os.environ.get("APPDATA"):
        return os.path.join(os.environ["APPDATA"], "SecurityWarden", FILE_NAME)
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "securitywarden", FILE_NAME)


def check_name(name: str) -> str:
    name = (name or "").strip()
    if not name or len(name) > NAME_MAX or any(ord(ch) < 32 for ch in name):
        raise SecurityWardenError("a token name is 1-100 characters, as on the SecurityWarden website")
    return name


def check_id(token_id: str) -> str:
    token_id = (token_id or "").strip()
    if not ID_RE.match(token_id):
        raise SecurityWardenError(f"{token_id!r} isn't a token id (copy it from the website)")
    return token_id


def _same_server(a: str | None, b: str | None) -> bool:
    return (a or "").rstrip("/").lower() == (b or "").rstrip("/").lower()


def _same_account(a: str | None, b: str | None) -> bool:
    """Unknown (older entries and servers) counts as the same, as before accounts were recorded."""
    return not a or not b or a == b


class TokenStore:
    def __init__(self, path: str | None = None) -> None:
        self.path = os.path.abspath(os.path.expanduser(path)) if path else default_tokens_path()
        self._old_format = False

    # -- reading ---------------------------------------------------------------------------

    def _load(self) -> dict[str, dict[str, Any]]:
        """Every entry by id: live ones (with "token") and replaced ones (with "replaced_by")."""
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            raise SecurityWardenError(f"can't read {self.path}: {e}") from None
        if not isinstance(data, dict) or not isinstance(data.get("tokens"), dict) \
                or data.get("format") not in (FORMAT, OLD_FORMAT):
            raise SecurityWardenError(f"{self.path} isn't a SecurityWarden token file ({FORMAT})")
        if data["format"] == OLD_FORMAT:
            self._old_format = True
            out: dict[str, dict[str, Any]] = {}
            for name, e in data["tokens"].items():
                if not isinstance(e, dict) or not isinstance(e.get("token"), str):
                    continue
                try:
                    tid = parse_credential(e["token"]).id
                except CryptoError:
                    tid = e.get("id")
                if isinstance(tid, str) and ID_RE.match(tid):
                    out[tid] = {k: v for k, v in e.items() if k != "id"} | {"name": name}
            return out
        return {k: v for k, v in data["tokens"].items()
                if ID_RE.match(k) and isinstance(v, dict) and isinstance(v.get("name"), str)
                and (isinstance(v.get("token"), str) or isinstance(v.get("replaced_by"), str))}

    def _live(self) -> dict[str, dict[str, Any]]:
        return {k: v for k, v in self._load().items() if isinstance(v.get("token"), str)}

    def names(self) -> list[str]:
        return sorted(v["name"] for v in self._live().values())

    def entries(self) -> list[dict[str, Any]]:
        """The stored tokens without their secrets: id, name, server, project, saved_at."""
        return [{"id": k, **{f: v.get(f) for f in ("name", "server", "project", "saved_at")}}
                for k, v in sorted(self._live().items(), key=lambda kv: kv[1]["name"])]

    def entry(self, token_id: str) -> dict[str, Any] | None:
        e = self._live().get(token_id)
        return {**e, "id": token_id} if e else None

    def credential(self, token_id: str) -> Credential:
        e = self.entry(token_id)
        if e is None:
            raise SecurityWardenError(f"no token {token_id} in {self.path}")
        try:
            return parse_credential(e["token"])
        except CryptoError as err:
            raise SecurityWardenError(f"the token {e['name']!r} in {self.path} is damaged ({err})") from None

    def resolve(self, token_id: str) -> str | None:
        """The live token for ``token_id``, following replacements; None if there is none."""
        all_ = self._load()
        cur, hops = token_id, 0
        while cur in all_ and hops <= MAX_HOPS:
            if isinstance(all_[cur].get("token"), str):
                return cur
            cur, hops = all_[cur].get("replaced_by"), hops + 1
        return None

    def pick(self, name: str | None = None, *, token_id: str | None = None, server: str | None = None) -> str | None:
        """The id of the token to use, or None when there is none yet. Raises when it's ambiguous."""
        if token_id:
            found = self.resolve(check_id(token_id))
            if found or not name:
                return found
        live = self._live()
        if name:
            name = check_name(name)
            hits = [k for k, v in live.items() if v["name"] == name
                    and (not server or not v.get("server") or _same_server(v.get("server"), server))]
            if len(hits) > 1:
                raise SecurityWardenError(f"{self.path} holds {len(hits)} tokens called {name!r} (from different "
                                          "accounts or servers): set SW_TOKEN_ID to the one this program uses")
            return hits[0] if hits else None
        if len(live) > 1:
            raise SecurityWardenError(f"{self.path} holds several tokens ({', '.join(self.names())}): set "
                                      "SW_TOKEN_ID (and SW_TOKEN_NAME) to the one this program uses")
        return next(iter(live), None)

    # -- writing ---------------------------------------------------------------------------

    def put(self, cred: Credential, *, name: str, server: str | None = None, project: str | None = None,
            account: str | None = None, replace: bool = False) -> str:
        """Store a token under its id. A stored token with the same name, server and account is replaced (with
        ``replace`` only): its entry keeps a pointer to the new one. Another account's token with the same name is a
        separate entry. Returns the id."""
        name = check_name(name)
        with self._locked():
            tokens = self._load()
            if cred.id in tokens and isinstance(tokens[cred.id].get("token"), str) and not replace:
                raise SecurityWardenError(f"{self.path} already holds this token ({name!r})")
            same = [k for k, v in tokens.items() if k != cred.id and isinstance(v.get("token"), str)
                    and v["name"] == name and _same_server(v.get("server"), server)
                    and _same_account(v.get("account"), account)]
            if same and not replace:
                raise SecurityWardenError(f"{self.path} already holds a token called {name!r} for this server "
                                          "(revoke it on the website, then set up again to replace it)")
            t = int(time.time())
            for k in same:
                tokens[k] = {"name": name, "server": tokens[k].get("server"), "replaced_by": cred.id,
                             "replaced_at": t, **({"account": tokens[k]["account"]} if tokens[k].get("account") else {})}
            for k, v in list(tokens.items()):     # older pointers to the replaced ones now lead here directly
                if v.get("replaced_by") in same:
                    tokens[k] = {**v, "replaced_by": cred.id}
            tokens[cred.id] = {"name": name, "token": str(cred), "server": server, "project": project,
                               "saved_at": t, **({"account": account} if account else {})}
            self._write(tokens)
        return cred.id

    def remove(self, token_id: str) -> bool:
        with self._locked():
            tokens = self._load()
            if tokens.pop(token_id, None) is None:
                return False
            self._write(tokens)
            return True

    def _write(self, tokens: dict[str, dict[str, Any]]) -> None:
        from .setup import write_private
        if self._old_format and os.path.exists(self.path) and not os.path.exists(self.path + ".v1.bak"):
            with open(self.path, encoding="utf-8") as f:
                write_private(self.path + ".v1.bak", f.read())
        write_private(self.path, json.dumps({"format": FORMAT, "tokens": tokens}, indent=1, sort_keys=True) + "\n")
        self._old_format = False

    def _locked(self) -> "_Lock":
        return _Lock(self.path + ".lock")


class _Lock:
    """A lock file made with O_EXCL (works the same on Linux and Windows). A lock older than LOCK_STALE
    seconds is left over from a crash and is taken over."""

    def __init__(self, path: str) -> None:
        self.path = path

    def __enter__(self) -> "_Lock":
        folder = os.path.dirname(self.path)
        os.makedirs(folder, mode=0o700, exist_ok=True)
        deadline = time.monotonic() + 15
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                return self
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self.path) > LOCK_STALE:
                        os.unlink(self.path)
                        continue
                except OSError:
                    continue
                if time.monotonic() > deadline:
                    raise SecurityWardenError(f"{self.path} is locked by another program; try again") from None
                time.sleep(0.05)

    def __exit__(self, *exc: object) -> None:
        try:
            os.unlink(self.path)
        except OSError:
            pass
