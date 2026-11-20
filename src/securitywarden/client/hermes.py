"""Install the aiSecurityWarden secret source into Hermes Agent (``swctl hermes-plugin``).

The plugin itself is ``securitywarden/hermes_plugin/`` (``__init__.py`` and ``plugin.yaml``). This copies those
two files into ``$HERMES_HOME/plugins/aisecuritywarden/`` so they match the installed client, and prints the
Hermes commands that turn it on. It never edits Hermes's config.yaml itself (``hermes config set`` does that).
"""

from __future__ import annotations

import os
import shlex
import shutil
import sys
from importlib import resources

PLUGIN = "aisecuritywarden"
FILES = ("__init__.py", "plugin.yaml")


class HermesError(Exception):
    pass


def hermes_home() -> str:
    """Where Hermes keeps its files: $HERMES_HOME, else ~/.hermes (on Windows %LOCALAPPDATA%\\hermes, unless only
    ~/.hermes exists), as Hermes itself decides."""
    if os.environ.get("HERMES_HOME", "").strip():
        return os.path.expanduser(os.path.expandvars(os.environ["HERMES_HOME"].strip()))
    dot = os.path.join(os.path.expanduser("~"), ".hermes")
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", "").strip() or os.path.join(os.path.expanduser("~"), "AppData", "Local")
        local = os.path.join(base, "hermes")
        if os.path.isdir(local) or not os.path.isdir(dot):
            return local
    return dot


def plugin_files() -> dict[str, bytes]:
    # as files, without importing the plugin (it imports Hermes, which isn't installed here)
    pkg = resources.files("securitywarden") / "hermes_plugin"
    return {name: (pkg / name).read_bytes() for name in FILES}


def install(home: str | None = None, *, dry_run: bool = False) -> tuple[str, bool]:
    """Copy the plugin into Hermes. Returns (folder, changed)."""
    home = home or hermes_home()
    folder = os.path.join(home, "plugins", PLUGIN)
    if os.path.islink(folder) or (os.path.exists(folder) and not os.path.isdir(folder)):
        raise HermesError(f"{folder} isn't a plain folder, so it wasn't changed.")
    files = plugin_files()
    current = {}
    for name in FILES:
        path = os.path.join(folder, name)
        if os.path.isfile(path):
            with open(path, "rb") as f:
                current[name] = f.read()
    if current == files:
        return folder, False
    if dry_run:
        return folder, True
    os.makedirs(folder, exist_ok=True)
    for name, data in files.items():
        tmp = os.path.join(folder, f".{name}.tmp")
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, os.path.join(folder, name))
    shutil.rmtree(os.path.join(folder, "__pycache__"), ignore_errors=True)
    return folder, True


def swctl_path() -> str:
    """The swctl that's running now, so Hermes finds the same one even with a different PATH (a service)."""
    found = shutil.which("swctl")
    argv0 = sys.argv[0] if sys.argv and sys.argv[0] else ""
    if argv0 and os.path.basename(argv0).lower() in ("swctl", "swctl.exe", "swctl-script.py") and os.path.isfile(argv0):
        return os.path.abspath(argv0)
    return found or "swctl"


def _found_without_setting(swctl: str) -> bool:
    """Whether the plugin finds this swctl on its own: pipx's folder (~/.local/bin) is where it looks after PATH."""
    if not os.path.isabs(swctl):
        return True
    # pipx's folder, and system folders that are on every service's PATH
    folders = [os.path.join(os.path.expanduser("~"), ".local", "bin")]
    if os.name != "nt":
        folders += ["/usr/local/bin", "/usr/bin", "/bin"]
    return os.path.normcase(os.path.dirname(swctl)) in {os.path.normcase(f) for f in folders}


def _q(value: str) -> str:
    if sys.platform == "win32":
        return f'"{value}"' if any(c in value for c in ' &|<>^"') else value
    return shlex.quote(value)


def next_steps(*, server: str | None, token_name: str | None, token_id: str | None, swctl: str,
               stored: list[dict] | None = None) -> list[str]:
    """The Hermes commands that turn the source on, with only the settings this computer needs."""
    stored = stored or []
    sets = [("enabled", "true")]
    if not _found_without_setting(swctl):
        sets.append(("swctl", swctl))
    if token_id:
        sets.append(("token_id", token_id))
    elif token_name:
        sets.append(("token_name", token_name))
    elif len(stored) > 1:
        sets.append(("token_name", "<one of: " + ", ".join(e["name"] for e in stored) + ">"))
    # swctl setup records each token's server, so the server is only needed for a token kept elsewhere
    if server and not any(e.get("server") for e in stored):
        sets.append(("server_url", server))
    lines: list[str] = []
    if not stored:
        lines += ["No machine token is stored on this computer yet. Create one on the website, then run:",
                  "  swctl --server https://app.aisecuritywarden.com setup      # or your own server",
                  "and paste the one-time setup code. Then:", ""]
    lines += ["Turn it on (the Hermes commands edit config.yaml for you):",
              f"  hermes plugins enable {PLUGIN}"]
    lines += [f"  hermes config set secrets.{PLUGIN}.{k} {_q(v) if not v.startswith('<') else v}" for k, v in sets]
    if len(stored) > 1 and not (token_id or token_name):
        lines.append("  (several tokens are stored here: name the one whose project holds Hermes's keys)")
    lines += ["",
              "Then restart Hermes (the gateway and the dashboard, if they run). At start-up it loads every",
              "secret the token's project holds into its environment; Hermes keeps them out of the agent's",
              "terminal. If the token needs a phone approval, approve it within the server's time (120 s);",
              f"raise secrets.{PLUGIN}.timeout_seconds (default 180) if you need longer.",
              "",
              "If you used secrets.command with swctl export before, turn that off:",
              "  hermes config set secrets.command.enabled false",
              "",
              "Run this again after updating aiSecurityWarden to update the plugin."]
    return lines
