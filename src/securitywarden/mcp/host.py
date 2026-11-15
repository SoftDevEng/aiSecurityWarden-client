"""Which program runs this MCP server, so an update can tell the user exactly what to restart.

Agents guessed wrong ("restart the desktop app" when the tools lived in a separate Hermes dashboard process) and then
tried to restart things themselves. ``sw-mcp`` walks up from its parent process, past shells and launchers, to the
first real program, and names it. Read-only: nothing here stops, starts or signals anything.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from typing import Any

# Programs that only start something else: the host is further up.
LAUNCHERS = frozenset([
    "sh", "bash", "zsh", "dash", "fish", "ksh", "tcsh", "csh", "env", "nohup", "setsid", "timeout", "stdbuf",
    "nice", "ionice", "script", "uv", "uvx", "pipx", "sw-mcp", "aisecuritywarden", "npx", "npm", "cmd.exe",
    "cmd", "powershell.exe", "powershell", "pwsh.exe", "pwsh", "conhost.exe", "conhost", "wsl.exe",
])
SECRET_ARG = re.compile(r"(?i)(--?[a-z0-9_-]*(?:key|token|secret|passw(?:or)?d|auth)[a-z0-9_-]*)(=|\s+)(\S+)")
MAX_DEPTH = 8


def agent_host() -> dict[str, Any] | None:
    """{"pid", "command", "service"?} of the program that runs sw-mcp, or None if it can't be found."""
    try:
        pid = os.getppid()
        for _ in range(MAX_DEPTH):
            if pid <= 1:
                return None
            info = _proc(pid)
            if info is None:
                return None
            ppid, argv = info
            if argv and not _is_launcher(argv):
                out: dict[str, Any] = {"pid": pid, "command": _command(argv)}
                svc = _service(pid)
                if svc:
                    out["service"] = svc
                return out
            pid = ppid
    except Exception:  # noqa: BLE001 - only advice; never fail an update over it
        return None
    return None


def _is_launcher(argv: list[str]) -> bool:
    name = os.path.basename(argv[0]).lower()
    if name in LAUNCHERS:
        return True
    if re.match(r"^(python[0-9.]*|python[0-9.]*\.exe|node|node\.exe)$", name):
        rest = " ".join(argv[1:3]).lower()
        return not argv[1:] or any(w in rest for w in ("sw-mcp", "securitywarden", "aisecuritywarden", "pipx", "uvx"))
    return False


def _command(argv: list[str]) -> str:
    text = " ".join(argv)
    text = SECRET_ARG.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)
    return text if len(text) <= 200 else text[:199] + "…"


def _proc(pid: int) -> tuple[int, list[str]] | None:
    if os.path.isdir("/proc/self"):
        try:
            with open(f"/proc/{pid}/stat", "rb") as f:
                stat = f.read().decode("utf-8", "replace")
            ppid = int(stat.rsplit(")", 1)[1].split()[1])
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = [a.decode("utf-8", "replace") for a in f.read().split(b"\0") if a]
            return ppid, argv
        except (OSError, ValueError, IndexError):
            return None
    if sys.platform == "win32":
        return _proc_windows(pid)
    try:
        out = subprocess.run(["ps", "-o", "ppid=,command=", "-p", str(pid)], capture_output=True, text=True,
                             timeout=5, check=False).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.match(r"\s*(\d+)\s+(.*)", out)
    return (int(m.group(1)), m.group(2).split()) if m else None


def _proc_windows(pid: int) -> tuple[int, list[str]] | None:
    import ctypes
    from ctypes import wintypes

    class Entry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_wchar * 260)]

    k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    if snap in (-1, 0xFFFFFFFF):
        return None
    try:
        e = Entry()
        e.dwSize = ctypes.sizeof(Entry)
        ok = k32.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            if e.th32ProcessID == pid:
                return int(e.th32ParentProcessID), [e.szExeFile]
            ok = k32.Process32NextW(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return None


def _service(pid: int) -> str | None:
    """The systemd unit a Linux process belongs to (e.g. hermes-dashboard.service), if any."""
    try:
        with open(f"/proc/{pid}/cgroup", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return None
    m = re.findall(r"/([A-Za-z0-9@._-]+\.service)(?:/|$)", text)
    units = [u for u in m if not u.startswith(("user@", "session-")) and u != "init.scope"]
    if not units:
        return None
    unit = units[-1]
    return f"{unit} (user service)" if "/user@" in text else unit


def restart_advice(host: dict[str, Any] | None = None, *, lookup: bool = True) -> str:
    """What to tell the user after an update, ending with the rule that the agent restarts nothing itself."""
    if host is None and lookup:
        host = agent_host()
    rule = ("Tell the user this, then stop: don't kill, restart or relaunch sw-mcp, the agent app, its gateway or "
            "dashboard, and don't write scripts to do it.")
    if not host:
        return ("To use it, the program that runs this MCP server (the agent app, or its gateway or dashboard if it "
                "has one) has to be restarted by the user. " + rule)
    what = f"`{host['command']}` (PID {host['pid']})"
    svc = host.get("service")
    if svc:
        unit = svc.replace(" (user service)", "")
        cmd = f"systemctl --user restart {unit}" if "user service" in svc else f"sudo systemctl restart {unit}"
        how = f"It runs as the service {svc}: `{cmd}`."
    else:
        how = "Restart it the way it is normally started."
    text = f"To use it, the user restarts {what}, the program that runs this MCP server. {how}"
    if "hermes" in host["command"].lower():
        text += (" If the agent still shows the old tools afterwards: stop it, delete "
                 "~/.hermes/cache/mcp_schema_cache.json, then start it again, and open a new chat.")
    else:
        text += " Then open a new chat or refresh the tool list."
    return text + " " + rule
