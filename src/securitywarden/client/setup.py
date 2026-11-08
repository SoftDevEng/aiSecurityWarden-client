"""Putting a machine token on a machine: from a one-time setup code to a file only this user can read.

Used by ``swctl setup``, ``sw-mcp setup`` and the MCP ``securitywarden_setup`` tool, so nobody has to create
the file or set its permissions by hand.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

import httpx
from typing import TYPE_CHECKING

from ..crypto import Credential
from .api import SecurityWardenError, redeem_setup_code_info

if TYPE_CHECKING:
    from .tokens import TokenStore


def token_file_exists(path: str) -> bool:
    p = os.path.expanduser(path)
    return os.path.isfile(p) and os.path.getsize(p) > 0


def store_credential(path: str, cred: Credential, *, replace: bool = False) -> str:
    """Write the token to ``path`` readable by this user only (POSIX mode 600 in a 700 folder; on
    Windows, an access list with only this user). Returns the full path."""
    p = os.path.abspath(os.path.expanduser(path))
    if token_file_exists(p) and not replace:
        raise SecurityWardenError(f"{p} already holds a token (revoke it on the website and use --replace)")
    write_private(p, str(cred) + "\n")
    return p


def write_private(path: str, text: str) -> None:
    """Replace ``path`` in one step with a file only this user can read."""
    p = os.path.abspath(os.path.expanduser(path))
    folder = os.path.dirname(p)
    if not os.path.isdir(folder):
        os.makedirs(folder, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".sw-token-", dir=folder)      # created with mode 600 on POSIX
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        if os.name == "nt":
            _windows_owner_only(tmp)
        else:
            os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _windows_owner_only(path: str) -> None:
    """Remove inherited permissions and grant only the current user (plus nothing else)."""
    user = os.environ.get("USERNAME") or ""
    domain = os.environ.get("USERDOMAIN") or ""
    who = f"{domain}\\{user}" if domain and user else user
    if not who:
        return
    try:
        subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", f"{who}:F"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    except (OSError, subprocess.SubprocessError):
        print("securitywarden: couldn't restrict the token file to your user; it's in your profile folder, "
              "which other users can't read by default", file=sys.stderr)


def file_token_id(token_file: str) -> str | None:
    """The id of the token in a token file of its own, or None (no file, or not a token)."""
    from ..crypto import CryptoError, parse_credential
    try:
        with open(os.path.expanduser(token_file), encoding="utf-8") as f:
            return parse_credential(f.read()).id
    except (OSError, CryptoError, ValueError):
        return None


def setup_from_code(server_url: str, code: str, token_file: str, *, replace: bool = False,
                    http: httpx.Client | None = None, verify: bool | str = True) -> tuple[Credential, str]:
    """Collect the token behind ``code`` into a token file of its own. Checks the file first, so a code isn't used up
    when the token couldn't be stored. Replacing the token in the file (``replace``) only takes a code for a token
    with the same name and owner as the old one: a code meant for another program is refused, not used up."""
    if token_file_exists(token_file) and not replace:
        raise SecurityWardenError(f"{os.path.expanduser(token_file)} already holds a token")
    old = file_token_id(token_file) if replace else None
    cred, _info = redeem_setup_code_info(server_url, code, replaces=old, http=http, verify=verify)
    return cred, store_credential(token_file, cred, replace=replace)


def setup_into_store(server_url: str, code: str, store: "TokenStore", name: str | None = None, *,
                     token_id: str | None = None, replace: bool = False, http: httpx.Client | None = None,
                     verify: bool | str = True) -> tuple[Credential, str]:
    """Collect the token behind ``code`` into SW_Tokens.json (keyed by token id). With ``name`` (the token this
    program is set up for), a code for another token is refused before it is used up. A stored token with the same
    name and server is replaced only with ``replace`` (the caller found it rejected, i.e. revoked); settings that
    name its id then follow the new one. Returns (credential, the name stored)."""
    from .tokens import check_name
    if name:
        name = check_name(name)
    elif token_id:
        name = store.name_of(token_id)          # set up by id only: the stored entry knows the name
    current = store.pick(name, token_id=token_id, server=server_url) if (name or token_id) else None
    if current is not None and not replace:
        raise SecurityWardenError(f"{store.path} already holds the token {store.entry(current)['name']!r} for this "
                                  "program (revoke it on the website first to replace it)")
    # what the code must be for: this program's token name, else its id (a first setup by id), and when replacing,
    # a token with the old one's name and owner. Anything else is refused before the code is used up.
    cred, info = redeem_setup_code_info(server_url, code, name=name, token_id=None if name else token_id,
                                        replaces=current if replace else None, http=http, verify=verify)
    final = name or info.get("name") or cred.id
    try:
        store.put(cred, name=final, server=server_url, project=info.get("project"), account=info.get("account"),
                  replace=replace)
    except SecurityWardenError as e:
        raise SecurityWardenError(f"{e}; the code is used up: make a new one once that's sorted out") from None
    return cred, final
