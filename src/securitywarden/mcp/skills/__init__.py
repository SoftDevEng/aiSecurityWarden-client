"""Skills that teach an AI agent how to use aiSecurityWarden's tools (approvals, untrusted content, setup codes,
updates). The MCP server's own instructions (server.INSTRUCTIONS) give every agent the short version; a skill gives
agents that support skills (Hermes Agent, Claude) the full one.

    sw-mcp skill show hermes                 # print it
    sw-mcp skill install hermes              # ~/.hermes/skills/aisecuritywarden/SKILL.md ($HERMES_HOME)
    sw-mcp skill install claude              # ~/.claude/skills/aisecuritywarden/SKILL.md (Claude Code; $CLAUDE_CONFIG_DIR)
    sw-mcp skill zip claude                  # a .zip to upload in the Claude app's Skills settings

``sw-mcp serve`` refreshes skills this command installed in the agents' default folders when it starts, so they
follow client updates by themselves. A SKILL.md that wasn't written by this command is never touched (install
replaces one only with --force).
"""

from __future__ import annotations

import io
import os
import zipfile
from importlib import resources

from ... import __version__

NAME = "aisecuritywarden"
AGENTS = ("hermes", "claude")
MARKER = "<!-- Installed by sw-mcp skill install"
HERMES_DESCRIPTION_LIMIT = 60       # Hermes' skill index clips longer descriptions
CLAUDE_DESCRIPTION_LIMIT = 1024


class SkillError(Exception):
    """Shown to the person running the command."""


def _read(name: str) -> str:
    return resources.files(__package__).joinpath(name).read_text(encoding="utf-8")


def text(agent: str) -> str:
    """The complete SKILL.md for an agent: its header (name, description), a marker line, then the shared body."""
    if agent not in AGENTS:
        raise SkillError(f"unknown agent {agent!r} (one of: {', '.join(AGENTS)})")
    marker = (f"{MARKER} (aiSecurityWarden client {__version__}). Run it again after an update to refresh this file; "
              "edits here are replaced. -->")
    return _read(f"{agent}.md").rstrip("\n") + "\n\n" + marker + "\n\n" + _read("body.md")


def frontmatter(skill: str) -> dict[str, str]:
    """The name/description header of a SKILL.md (simple ``key: value`` lines between ``---`` lines)."""
    lines = skill.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    out: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return out
        key, sep, value = line.partition(":")
        if sep:
            out[key.strip()] = value.strip()
    return {}


def default_dir(agent: str) -> str:
    if agent == "hermes":
        home = os.environ.get("HERMES_HOME") or os.path.join(os.path.expanduser("~"), ".hermes")
    elif agent == "claude":
        home = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")
    else:
        raise SkillError(f"unknown agent {agent!r} (one of: {', '.join(AGENTS)})")
    return os.path.join(home, "skills", NAME)


def install(agent: str, folder: str | None = None, *, force: bool = False) -> tuple[str, str]:
    """Write the skill. Returns (path, "installed" | "updated" | "unchanged")."""
    new = text(agent)
    folder = os.path.abspath(os.path.expanduser(folder or default_dir(agent)))
    path = os.path.join(folder, "SKILL.md")
    status = "installed"
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            old = f.read()
        if old == new:
            return path, "unchanged"
        if MARKER not in old and not force:
            raise SkillError(f"{path} exists and wasn't written by sw-mcp skill install; not replacing it (use --force)")
        status = "updated"
    os.makedirs(folder, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(new)
    os.replace(tmp, path)
    return path, status


def zip_bytes(agent: str) -> bytes:
    """The skill as a .zip (a folder named after the skill holding SKILL.md), for apps that take an upload."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{NAME}/SKILL.md", text(agent))
    return buf.getvalue()


def refresh_installed() -> list[str]:
    """Bring skills installed by this command (in the agents' default folders) up to date with this client. Files
    without our marker are left alone. Returns the paths rewritten; never raises."""
    done = []
    for agent in AGENTS:
        try:
            path = os.path.join(default_dir(agent), "SKILL.md")
            if not os.path.isfile(path):
                continue
            with open(path, encoding="utf-8") as f:
                old = f.read()
            if MARKER in old and old != text(agent):
                install(agent)
                done.append(path)
        except (OSError, SkillError, UnicodeDecodeError):
            continue
    return done
