"""The ``system_run`` tool: root commands through sw-sudo, for agents that run as a limited user (Linux).

Offered by sw-mcp only when sw-sudo is set up on this machine for the user sw-mcp runs as
(``/etc/securitywarden/sw-sudo.json`` names this user). The tool doesn't hold or use any aiSecurityWarden token: it
runs ``sudo -n <sw-sudo> --json --no-wait -- COMMAND``, and sw-sudo (as root, with its own root-only token) checks
the command, asks the owner and runs it once approved. So the agent gets the usual "waiting_for_approval" answer at
once and checks back with ``check_approval``, like any other aiSecurityWarden action.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any, Callable

from ..sudo import CONFIG_PATH, EXIT_PENDING
from .framework import Result, render, untrusted

TOOL = "system_run"
MAX_TEXT = 20_000          # characters of output passed to the AI (sw-sudo itself caps at its own limit)
MAX_PENDING = 50

DESCRIPTION = (
    "Run one command as root on this machine, after the user approves that exact command in aiSecurityWarden "
    "(sw-sudo). Use it for anything that needs root (installing packages, restarting services, reading root-only "
    "logs) instead of sudo. Pass the command as a list of arguments, e.g. [\"apt\", \"install\", \"-y\", \"ffmpeg\"], "
    "and a short reason the user will see. No shell: no pipes, redirects, globs or variables; shells, interpreters, "
    "editors and user management are refused. You usually get status waiting_for_approval with a request_id and a "
    "match code: tell the user, carry on with other work and call check_approval with the request_id later. A "
    "denial means don't run it; a denial with a comment says what to change.")

SCHEMA = {
    "type": "object",
    "properties": {
        "command": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 64,
                    "description": "The program and its arguments, one per item."},
        "reason": {"type": "string", "maxLength": 200, "description": "Why it's needed, shown to the user."},
    },
    "required": ["command"],
    "additionalProperties": False,
}


class SudoTool:
    """``available()`` decides whether the tool is offered; ``run`` and ``check`` call sw-sudo through sudo."""

    def __init__(self, *, config_path: str = CONFIG_PATH, runner: Callable[..., Any] = subprocess.run,
                 uid: Callable[[], int] | None = None, sudo: str = "/usr/bin/sudo") -> None:
        self.config_path, self.runner, self.sudo = config_path, runner, sudo
        self._uid = uid or (os.getuid if hasattr(os, "getuid") else (lambda: -1))
        self.pending: dict[str, str] = {}       # request id -> the command line, for the messages

    def _config(self) -> dict[str, Any] | None:
        if not sys.platform.startswith("linux"):
            return None
        try:
            with open(self.config_path, encoding="utf-8") as f:
                cfg = json.load(f)
        except (OSError, ValueError):
            return None
        if not isinstance(cfg, dict) or cfg.get("agent_uid") != self._uid() or not cfg.get("exe"):
            return None
        return cfg

    def available(self) -> bool:
        return self._config() is not None

    def spec(self) -> dict[str, Any]:
        return {"name": TOOL, "description": DESCRIPTION, "inputSchema": SCHEMA,
                "annotations": {"readOnlyHint": False, "destructiveHint": True}}

    def _call(self, extra: list[str], timeout: float) -> tuple[dict[str, Any] | None, str]:
        cfg = self._config()
        if cfg is None:
            return None, "sw-sudo isn't set up for this user on this machine any more."
        try:
            p = self.runner([self.sudo, "-n", cfg["exe"], "--json", *extra], capture_output=True, text=True,
                            timeout=timeout, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return None, "sw-sudo didn't answer in time."
        except OSError as e:
            return None, f"couldn't start sudo ({e.strerror or type(e).__name__})."
        last = (p.stdout or "").strip().splitlines()[-1:] or [""]
        try:
            out = json.loads(last[0])
            if isinstance(out, dict) and "status" in out:
                return out, ""
        except ValueError:
            pass
        err = (p.stderr or "").strip().splitlines()[-1:] or [""]
        return None, f"sudo refused to run sw-sudo ({err[0][:200] or f'exit {p.returncode}'}). Is the sudoers line " \
                     "from 'sw-sudo install' still in place?"

    def run(self, arguments: dict[str, Any]) -> Result:
        cmd, reason = arguments.get("command"), arguments.get("reason")
        if set(arguments) - {"command", "reason"} or not isinstance(cmd, list) or not cmd or len(cmd) > 64 \
                or not all(isinstance(a, str) and a for a in cmd) or (reason is not None and not isinstance(reason, str)):
            return Result("system_run takes command (a list of strings: the program and its arguments) and an "
                          "optional reason.", True)
        if len(cmd) == 1 and " " in cmd[0].strip():
            return Result("Pass the command as separate arguments, e.g. [\"apt\", \"install\", \"-y\", \"ffmpeg\"], "
                          "not one string. There is no shell.", True)
        extra = ["--no-wait"] + (["--reason", reason[:200]] if reason else []) + ["--", *cmd]
        out, problem = self._call(extra, timeout=120)
        if out is None:
            return Result(problem, True)
        return self._result(out, " ".join(cmd))

    def handles(self, rid: Any) -> bool:
        return isinstance(rid, str) and rid in self.pending

    def check(self, rid: str) -> Result:
        line = self.pending.get(rid, "the command")
        cfg = self._config() or {}
        out, problem = self._call(["--status", rid], timeout=float(cfg.get("command_timeout") or 600) + 60)
        if out is None:
            return Result(problem, True)
        if out["status"] != "waiting_for_approval":
            self.pending.pop(rid, None)
        return self._result(out, line)

    def _result(self, out: dict[str, Any], line: str) -> Result:
        st = out["status"]
        if st == "waiting_for_approval":
            rid = str(out.get("request_id", ""))
            if rid:
                while len(self.pending) >= MAX_PENDING:
                    self.pending.pop(next(iter(self.pending)))
                self.pending[rid] = line
            match = f" (match code {out['match']})" if out.get("match") else ""
            return Result(f"status: waiting_for_approval. request_id: {rid}. The user has been asked to approve "
                          f"running `{line}` as root{match}. Tell them, carry on with other work, and call "
                          f"check_approval with this request_id in about {int(out.get('check_after') or 15)} seconds.",
                          False, {"status": "waiting_for_approval", "request_id": rid, "match": out.get("match")})
        if st == "denied":
            comment = out.get("comment")
            if comment:
                return Result(f"The user denied running `{line}` as root, with this comment: \"{comment}\". Change "
                              "what they asked for before asking again, or ask them.", True)
            return Result(f"Running `{line}` as root was not approved ({out.get('reason')}). Don't run it; ask the "
                          "user if it's needed.", True)
        if st in ("refused", "unknown"):
            return Result(f"sw-sudo refused `{line}`: {out.get('reason')}.", True)
        if st == "done":
            code = out.get("exit_code")
            text = ""
            for name in ("stdout", "stderr"):
                v = str(out.get(name) or "")
                if v:
                    cut = "\n[… cut]" if len(v) > MAX_TEXT else ""
                    text += "\n\n" + render(untrusted(v[:MAX_TEXT] + cut, f"the command's {name}"))
            note = " (output was cut)" if out.get("cut") else ""
            return Result(f"Ran `{line}` as root: exit code {code}{note}.{text or ' No output.'}", code != 0,
                          {"exit_code": code})
        return Result(f"sw-sudo answered something unexpected ({st}).", True)


def default_tool() -> SudoTool | None:
    """The tool sw-mcp offers: Linux only (it just reports unavailable elsewhere)."""
    return SudoTool() if sys.platform.startswith("linux") else None


__all__ = ["SudoTool", "TOOL", "default_tool", "EXIT_PENDING"]
