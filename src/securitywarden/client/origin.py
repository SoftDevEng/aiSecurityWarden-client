"""What started this client: a few program names, its parent first, for the person approving its session.

``["hermes gateway", "systemd"]`` for an MCP server Hermes started, ``["python -c", "bash", "hermes gateway"]``
when an agent's own code started it. Names only: a program's file name, a script's file name and at most one
plain sub-command word. No paths, no other arguments, nothing that could hold a secret. The machine reports it,
so it can't be verified; it helps a person notice a request they didn't expect. Never raises.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Callable

MAX_DEPTH = 3
_WORD = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,30}$")
_INTERPRETERS = re.compile(r"^(python[0-9.]*|pythonw|py|node|nodejs|bun|deno|ruby|perl|php|bash|sh|dash|zsh|fish|"
                           r"pwsh|powershell|cmd|uv|uvx|npx|pipx)$", re.IGNORECASE)
_SHELLS = re.compile(r"^(bash|sh|dash|zsh|fish)$", re.IGNORECASE)
_INLINE = {"-c", "-e", "--eval", "-command", "/c", "/k"}


def _base(path: str) -> str:
    name = re.split(r"[\\/]", path.strip())[-1]
    return re.sub(r"\.(exe|cmd|bat|com)$", "", name, flags=re.IGNORECASE)[:40]


def label(argv: list[str]) -> str:
    """One process, as a short name: "hermes gateway", "python -c", "python -m pkg", "bash", "Claude"."""
    argv = [a for a in argv if a]
    if not argv:
        return ""
    exe = _base(argv[0])
    rest = argv[1:]
    if _INTERPRETERS.match(exe):
        for i, a in enumerate(rest):
            low = a.lower()
            if low in _INLINE or (_SHELLS.match(exe) and re.match(r"^-[a-z]*c[a-z]*$", a)):
                return f"{exe} -c" if a.startswith("-") and low not in _INLINE else f"{exe} {a}"
            if low == "-m" and i + 1 < len(rest):
                return f"{exe} -m {_base(rest[i + 1])}"
            if a.startswith("-"):
                continue
            if any(ch.isspace() for ch in a):      # inline code, not a script file
                return exe
            script = _base(a)
            sub = rest[i + 1] if i + 1 < len(rest) else ""
            return f"{script} {sub}" if _WORD.match(sub) else script
        return exe
    sub = rest[0] if rest else ""
    return f"{exe} {sub}" if _WORD.match(sub) and not sub.startswith("-") else exe


def _linux(pid: int) -> tuple[int, list[str]] | None:
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            stat = f.read().decode("utf-8", "replace")
        ppid = int(stat[stat.rindex(")") + 2:].split()[1])
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            argv = f.read().decode("utf-8", "replace").split("\0")
        if not any(argv):
            argv = [stat[stat.index("(") + 1:stat.rindex(")")]]
        return ppid, argv
    except (OSError, ValueError, IndexError):
        return None


def _psutil(pid: int) -> tuple[int, list[str]] | None:
    try:
        import psutil  # type: ignore[import-not-found]
        p = psutil.Process(pid)
        try:
            argv = p.cmdline()
        except Exception:  # noqa: BLE001 - access denied: the name will do
            argv = []
        return p.ppid(), argv or [p.name()]
    except Exception:  # noqa: BLE001 - not installed, or the process is gone
        return None


def _windows_table() -> dict[int, tuple[int, str]]:
    """pid -> (parent pid, program file name), from a Toolhelp snapshot (no arguments)."""
    import ctypes
    from ctypes import wintypes

    class Entry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_wchar * 260)]
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    out: dict[int, tuple[int, str]] = {}
    if not snap or snap == wintypes.HANDLE(-1).value:
        return out
    try:
        e = Entry()
        e.dwSize = ctypes.sizeof(Entry)
        ok = k32.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            out[e.th32ProcessID] = (e.th32ParentProcessID, e.szExeFile)
            ok = k32.Process32NextW(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return out


def ancestry(pid: int | None = None, *, lookup: Callable[[int], tuple[int, list[str]] | None] | None = None,
             depth: int = MAX_DEPTH) -> list[str]:
    """Labels of this process's parent, grandparent... (``depth`` of them), parent first."""
    try:
        pid = os.getppid() if pid is None else pid
        if lookup is None:
            if sys.platform.startswith("linux"):
                lookup = (lambda p: _linux(p) or _psutil(p))
            elif sys.platform == "win32":
                table = _windows_table()
                lookup = (lambda p: (table[p][0], [table[p][1]]) if p in table else _psutil(p))
            else:
                lookup = _psutil
        out: list[str] = []
        seen: set[int] = set()
        while pid and pid not in seen and len(out) < depth:
            seen.add(pid)
            found = lookup(pid)
            if not found:
                break
            ppid, argv = found
            name = label(argv)
            if name:
                out.append(name)
            if pid == 1:
                break
            pid = ppid
        return out
    except Exception:  # noqa: BLE001 - this is a courtesy for the approver; never stop a client over it
        return []


_cached: list[str] | None = None


def origin() -> list[str]:
    """This process's ancestry, worked out once."""
    global _cached
    if _cached is None:
        _cached = [] if os.environ.get("SW_SEND_ORIGIN", "1") == "0" else ancestry()
    return _cached
