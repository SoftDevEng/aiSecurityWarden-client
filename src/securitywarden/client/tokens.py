"""SW_Tokens.json: every machine token on this machine, in one file only this user can read, by name.

Each bot's MCP settings (or swctl) name the token they use (``SW_TOKEN_NAME``), so every set-up looks the same
apart from that name, and replacing one bot's token never touches another's. The name is the token's name on
the SecurityWarden website, which allows one active token per name.

    {"format": "sw-tokens-1",
     "tokens": {"jarvis-gmail": {"token": "sw1.m....", "server": "https://vault.example.com",
                                 "project": "Gmail", "id": "...", "saved_at": 1793400000}}}

Location: ``SW_TOKENS_FILE``, else ``%APPDATA%\\SecurityWarden\\SW_Tokens.json`` (Windows) or
``$XDG_CONFIG_HOME/securitywarden/SW_Tokens.json`` (default ``~/.config/securitywarden``). Several processes may
set up at once: writes take a lock file and replace the file in one step.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from ..crypto import Credential, CryptoError, parse_credential
from .api import SecurityWardenError

FILE_NAME = "SW_Tokens.json"
FORMAT = "sw-tokens-1"
NAME_MAX = 100
LOCK_STALE = 30.0


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


class TokenStore:
    def __init__(self, path: str | None = None) -> None:
        self.path = os.path.abspath(os.path.expanduser(path)) if path else default_tokens_path()

    # -- reading ---------------------------------------------------------------------------

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            raise SecurityWardenError(f"can't read {self.path}: {e}") from None
        if not isinstance(data, dict) or data.get("format") != FORMAT or not isinstance(data.get("tokens"), dict):
            raise SecurityWardenError(f"{self.path} isn't a SecurityWarden token file ({FORMAT})")
        return {k: v for k, v in data["tokens"].items() if isinstance(v, dict) and isinstance(v.get("token"), str)}

    def names(self) -> list[str]:
        return sorted(self._load())

    def entry(self, name: str) -> dict[str, Any] | None:
        return self._load().get(name)

    def credential(self, name: str) -> Credential:
        e = self.entry(name)
        if e is None:
            raise SecurityWardenError(f"no token called {name!r} in {self.path}")
        try:
            return parse_credential(e["token"])
        except CryptoError as err:
            raise SecurityWardenError(f"the token {name!r} in {self.path} is damaged ({err})") from None

    def pick(self, name: str | None) -> str | None:
        """The name to use: ``name`` if given, else the only token stored. None: nothing (unambiguous) stored.
        Raises when several are stored and none is named."""
        if name:
            return check_name(name)
        names = self.names()
        if len(names) > 1:
            raise SecurityWardenError(f"{self.path} holds several tokens ({', '.join(names)}): set SW_TOKEN_NAME "
                                      "to the one this program uses")
        return names[0] if names else None

    # -- writing ---------------------------------------------------------------------------

    def put(self, name: str, cred: Credential, *, server: str | None = None, project: str | None = None,
            replace: bool = False) -> str:
        name = check_name(name)
        with self._locked():
            tokens = self._load()
            if name in tokens and not replace:
                raise SecurityWardenError(f"{self.path} already holds a token called {name!r} (revoke it on the "
                                          "website and replace it)")
            tokens[name] = {"token": str(cred), "id": cred.id, "server": server, "project": project,
                            "saved_at": int(time.time())}
            self._write(tokens)
        return self.path

    def remove(self, name: str) -> bool:
        with self._locked():
            tokens = self._load()
            if tokens.pop(name, None) is None:
                return False
            self._write(tokens)
            return True

    def _write(self, tokens: dict[str, dict[str, Any]]) -> None:
        from .setup import write_private
        write_private(self.path, json.dumps({"format": FORMAT, "tokens": tokens}, indent=1, sort_keys=True) + "\n")

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
