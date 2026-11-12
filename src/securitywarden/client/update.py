"""Client updates: find out whether a newer aiSecurityWarden client is out, and install it safely.

Used by ``sw-mcp update`` / ``swctl update`` and by the MCP tools ``securitywarden_check_update`` and
``securitywarden_update`` (the second one only after the owner approves it, like any high-risk action).

What makes it safe (DESIGN.md "Client updates"):

- the server only hands out files; whether to install one is decided here, with the release keys built into
  this client (:mod:`securitywarden.release`): a release must be signed, match its SHA-256 and size, and be newer
  than what is installed (no downgrades);
- the agent can't choose the version, the file or where it comes from: the update tool takes no arguments, and
  the approved action names the exact version and SHA-256;
- pip installs into the same Python environment this client runs from, with nothing on the command line but
  the downloaded wheel's path.

On Windows a running ``sw-mcp.exe`` / ``swctl.exe`` can't be replaced, so the install runs in a small helper
process that waits for this one to exit. Elsewhere it installs at once; the running process keeps the old code
until it restarts.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .. import __version__
from ..release import ReleaseError, check_wheel, is_newer, verify, version_key
from .api import SecurityWardenError

PIP_TIMEOUT = 900
WAIT_FOR_EXIT = 3600        # how long the Windows helper waits for the old process to stop


@dataclass
class UpdateInfo:
    installed: str
    latest: str | None = None
    min_supported: str | None = None
    notes: str = ""
    sha256: str | None = None
    file: str | None = None
    available: bool = False           # a newer, correctly signed release is offered
    required: bool = False            # the server no longer supports this client's version
    problem: str | None = None        # why it can't be installed from here (dev install, no pip, bad signature...)
    doc: dict[str, Any] | None = field(default=None, repr=False)   # the verified .swrel document
    on_disk: str | None = None        # a newer version already installed, which this process isn't running yet

    @property
    def restart_needed(self) -> bool:
        return self.on_disk is not None

    @property
    def current(self) -> str:
        """The newest version on this machine: installed on disk, else the running one."""
        return self.on_disk or self.installed

    def as_dict(self) -> dict[str, Any]:
        return {"installed": self.installed, "latest": self.latest, "min_supported": self.min_supported,
                "update_available": self.available, "update_required": self.required, "notes": self.notes,
                "sha256": self.sha256, "can_install": self.available and not self.problem,
                "problem": self.problem, "installed_on_disk": self.on_disk, "restart_needed": self.restart_needed}

    def text(self) -> str:
        restart = (f"aiSecurityWarden {self.on_disk} is installed; restart the agent app (or its MCP servers) to use "
                   f"it (this program still runs {self.installed}).") if self.on_disk else ""
        if restart and not self.available:
            return restart
        if self.latest is None and not self.problem:
            return f"aiSecurityWarden client {self.installed}: the server offers no client updates."
        if self.problem and not self.available:
            return f"aiSecurityWarden client {self.installed}: can't check for updates ({self.problem})."
        if not self.available:
            return f"aiSecurityWarden client {self.installed} is up to date."
        out = (f"{restart} " if restart else "") + (
               f"aiSecurityWarden client update {'REQUIRED' if self.required else 'available'}: "
               f"{self.current} -> {self.latest}.")
        if self.required:
            out += f" The server no longer supports clients older than {self.min_supported}."
        if self.notes:
            out += f" What changed: {self.notes}"
        out += (f" It can't be installed from here: {self.problem}." if self.problem else "")
        return out


def install_problem() -> str | None:
    """Why this client can't update itself, or None."""
    try:
        from importlib.metadata import distribution
        direct = distribution("aisecuritywarden").read_text("direct_url.json")
        if direct and json.loads(direct).get("dir_info", {}).get("editable"):
            return "this is a development install (pip install -e); update it with git instead"
    except Exception:  # noqa: BLE001 - not installed as a package (e.g. run from a source tree)
        return "this client isn't installed as a package; update it by hand"
    import importlib.util
    if importlib.util.find_spec("pip") is None:
        return f"pip isn't available in {sys.executable}; reinstall with pipx or a virtual environment"
    return None


def disk_version() -> str | None:
    """The version installed on disk now (it changes when an update installs while this process runs)."""
    try:
        from importlib.metadata import version
        return version("aisecuritywarden")
    except Exception:  # noqa: BLE001 - not installed as a package
        return None


def check(client: Any, *, installed: str = __version__, keys: dict[str, str] | None = None,
          problem: Callable[[], str | None] | None = None,
          on_disk: Callable[[], str | None] | None = None) -> UpdateInfo:
    """Ask the server what it offers and check the signature. Never installs anything."""
    info = UpdateInfo(installed=installed)
    disk = (on_disk or disk_version)()
    try:
        if disk and is_newer(disk, installed):
            info.on_disk = disk            # updated while running: restart to use it
    except ValueError:
        pass
    offer = client.client_release()
    if offer is None:
        return info                          # server older than client updates
    ms = offer.get("min_supported")
    if isinstance(ms, str):
        try:
            version_key(ms)
            info.min_supported = ms
            info.required = version_key(info.current) < version_key(ms)
        except ValueError:
            pass
    doc = offer.get("release")
    if not doc:
        return info
    try:
        m = verify(doc, keys)
    except ReleaseError as e:
        info.problem = str(e)
        return info
    info.latest, info.notes, info.sha256, info.file, info.doc = m["version"], m["notes"], m["sha256"], m["file"], doc
    info.available = is_newer(m["version"], info.current)
    if info.required and not info.available:
        info.required = False                # nothing newer to install; don't nag
    if info.available:
        info.problem = (problem or install_problem)()
    return info


def updates_dir() -> str:
    from .tokens import default_tokens_path
    return os.path.join(os.path.dirname(default_tokens_path()), "updates")


def download(client: Any, info: UpdateInfo, *, want_version: str | None = None, want_sha256: str | None = None,
             keys: dict[str, str] | None = None, folder: str | None = None) -> str:
    """Download the wheel, check it against the signed manifest (and, from an approved action, against the exact
    version and SHA-256 the owner approved), and return its path."""
    if not info.available or not info.doc:
        raise ReleaseError("no newer client release to install")
    m = verify(info.doc, keys)               # again: never trust an earlier check alone
    if want_version is not None and (m["version"] != want_version or m["sha256"] != want_sha256):
        raise ReleaseError("the release on offer changed after it was approved; ask again")
    if not is_newer(m["version"], info.current):
        raise ReleaseError("refusing to install an older or equal version")
    data = client.download_client_release(m["file"])
    check_wheel(m, data)
    folder = folder or updates_dir()
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, m["file"])
    fd, tmp = tempfile.mkstemp(dir=folder, suffix=".part")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    return path


def pip_command(wheel: str) -> list[str]:
    # only-if-needed: new dependencies are fetched, the ones already there are left alone
    return [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
            "--upgrade-strategy", "only-if-needed", wheel]


def install(wheel: str, version: str, *, run: Callable[..., Any] = subprocess.run, windows: bool | None = None,
            pid: int | None = None) -> str:
    """Install the checked wheel into this Python environment. Returns what happened, for the user."""
    windows = os.name == "nt" if windows is None else windows
    if windows:
        log = wheel + ".log"
        cmd = [sys.executable, "-m", "securitywarden.client.update", "--apply", wheel, "--version", version,
               "--wait-pid", str(pid or os.getpid()), "--log", log]
        flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        subprocess.Popen(cmd, creationflags=flags, close_fds=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return (f"aiSecurityWarden {version} is downloaded and checked. It installs as soon as this program stops: "
                "restart the agent app (or its MCP servers). The install log is " + log)
    r = run(pip_command(wheel), capture_output=True, text=True, timeout=PIP_TIMEOUT)
    if r.returncode != 0:
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-3:]
        raise SecurityWardenError("pip couldn't install the update: " + " / ".join(tail))
    return (f"aiSecurityWarden {version} is installed. Restart the agent app (or its MCP servers) to use it; until "
            "then this program keeps running the old version.")


def _wait_for_exit(pid: int, timeout: float) -> None:
    """Windows: wait until process ``pid`` has stopped (its .exe can be replaced then)."""
    if os.name != "nt":
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except OSError:
                return
            time.sleep(1)
        return
    import ctypes
    SYNCHRONIZE = 0x00100000
    k32 = ctypes.windll.kernel32           # type: ignore[attr-defined]
    h = k32.OpenProcess(SYNCHRONIZE, False, pid)
    if h:
        k32.WaitForSingleObject(h, int(timeout * 1000))
        k32.CloseHandle(h)
    time.sleep(2)                           # let the launcher release its files


def _apply_main(argv: list[str]) -> int:
    """The Windows helper: wait for the old process, then run pip, logging to a file."""
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--wait-pid", type=int, required=True)
    ap.add_argument("--log", required=True)
    a = ap.parse_args(argv)
    with open(a.log, "a", encoding="utf-8") as log:
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} waiting for process {a.wait_pid} to stop\n")
        log.flush()
        _wait_for_exit(a.wait_pid, WAIT_FOR_EXIT)
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} installing {a.apply}\n")
        log.flush()
        r = subprocess.run(pip_command(a.apply), stdout=log, stderr=subprocess.STDOUT, timeout=PIP_TIMEOUT)
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} pip exit code {r.returncode}"
                  f"{' (installed ' + a.version + ')' if r.returncode == 0 else ''}\n")
    return r.returncode


class Updater:
    """What the MCP Hub uses (check, download, install); tests pass their own."""

    def check(self, client: Any) -> UpdateInfo:
        return check(client)

    def download(self, client: Any, info: UpdateInfo, **kw: Any) -> str:
        return download(client, info, **kw)

    def install(self, wheel: str, version: str) -> str:
        return install(wheel, version)


def run_cli(client: Any, *, check_only: bool, yes: bool, prog: str,
            ask: Callable[[str], str] = input) -> int:
    """``sw-mcp update`` / ``swctl update``: the person at the terminal is the approval."""
    try:
        info = check(client)
    except SecurityWardenError as e:
        print(f"{prog}: can't check for updates: {e}", file=sys.stderr)
        return 1
    print(info.text())
    if check_only or not info.available:
        return 2 if info.available else 0
    if info.problem:
        return 1
    if not yes and ask(f"Install aiSecurityWarden {info.latest}? [y/N] ").strip().lower() not in ("y", "yes"):
        print("Not installed.")
        return 1
    try:
        wheel = download(client, info)
        print(install(wheel, info.latest or ""))
    except (ReleaseError, SecurityWardenError, OSError, subprocess.SubprocessError) as e:
        print(f"{prog}: update failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_apply_main(sys.argv[1:]))
