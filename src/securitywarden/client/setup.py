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

from ..crypto import Credential
from .api import SecurityWardenError, redeem_setup_code


def token_file_exists(path: str) -> bool:
    p = os.path.expanduser(path)
    return os.path.isfile(p) and os.path.getsize(p) > 0


def store_credential(path: str, cred: Credential, *, replace: bool = False) -> str:
    """Write the token to ``path`` readable by this user only (POSIX mode 600 in a 700 folder; on
    Windows, an access list with only this user). Returns the full path."""
    p = os.path.abspath(os.path.expanduser(path))
    if token_file_exists(p) and not replace:
        raise SecurityWardenError(f"{p} already holds a token (revoke it on the website and use --replace)")
    folder = os.path.dirname(p)
    if not os.path.isdir(folder):
        os.makedirs(folder, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".sw-token-", dir=folder)      # created with mode 600 on POSIX
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(str(cred) + "\n")
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
    return p


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


def setup_from_code(server_url: str, code: str, token_file: str, *, replace: bool = False,
                    http: httpx.Client | None = None, verify: bool | str = True) -> tuple[Credential, str]:
    """Collect the token behind ``code`` and store it. Checks the file first, so a code isn't used up
    when the token couldn't be stored."""
    if token_file_exists(token_file) and not replace:
        raise SecurityWardenError(f"{os.path.expanduser(token_file)} already holds a token")
    cred = redeem_setup_code(server_url, code, http=http, verify=verify)
    return cred, store_credential(token_file, cred, replace=replace)
