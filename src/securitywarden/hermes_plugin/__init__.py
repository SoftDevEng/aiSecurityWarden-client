"""aiSecurityWarden secret source for Hermes Agent.

Hermes loads this at start-up and asks it for secrets. It gets here one of three ways: installed from
https://github.com/SoftDevEng/aiSecurityWarden-hermes (``hermes plugins install SoftDevEng/aiSecurityWarden-hermes``,
or Install from Git in the desktop app; updates with Update all), copied by ``swctl hermes-plugin``, or as the client
package's ``hermes_agent.plugins`` entry point when the client is installed in Hermes's own Python.

The source of truth is the aiSecurityWarden client (``securitywarden/hermes_plugin/``); the aiSecurityWarden-hermes
repository is a copy made at each release. Change it in the client.
It runs ``swctl export --format json`` and hands the result to Hermes, which puts it in the environment.

Why a separate process: the machine token stays in swctl. This file never reads the token store, the token or a
key; it sees only the secrets the token may read, which is what it hands to Hermes anyway. It also needs nothing
from this package, so the same file works copied into a plugins folder, installed from Git, or imported as an
entry point.

Configuration (``config.yaml``)::

    plugins:
      enabled: [aisecuritywarden]
    secrets:
      aisecuritywarden:
        enabled: true
        # all optional:
        token_name: jarvis          # needed only when several tokens are stored (or token_id / token_file)
        server_url: https://...     # default: the server the token was set up with (swctl setup records it)
        swctl: /opt/sw/bin/swctl    # default: PATH, next to this Python, then ~/.local/bin (pipx)
        timeout_seconds: 180        # room for a phone approval (the server waits up to 120 s)
        allow_names: []             # LD_PRELOAD, PATH, HTTPS_PROXY ... are refused unless listed here

Read-only, never prompts, never raises: every failure comes back as a ``FetchResult`` error with a kind.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Optional

from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    coerce_float,
    is_valid_env_name,
)

try:            # the per-fetch environment view (multi-profile gateways); older Hermes builds lack it
    from agent.secret_sources.base import build_minimal_provider_env as _provider_env
except ImportError:  # pragma: no cover - depends on the Hermes version
    _provider_env = None

try:
    from agent.secret_sources.base import run_cli as _run_cli, scrub_ansi as _scrub_ansi
except ImportError:  # pragma: no cover - depends on the Hermes version
    _run_cli = None
    _scrub_ansi = None

NAME = "aisecuritywarden"

# The server waits up to 120 s for a person to approve a fetch (its default); leave room for that plus TLS.
DEFAULT_TIMEOUT = 180.0
MAX_OUTPUT = 4 * 1024 * 1024

# What swctl reads from the environment. Nothing else from the agent's environment reaches it.
SW_ENV = ("SW_SERVER_URL", "SW_TOKEN_ID", "SW_TOKEN_NAME", "SW_ACCESS_TOKEN_FILE", "SW_ACCESS_TOKEN",
          "SW_TOKENS_FILE", "SW_CA_BUNDLE", "SW_ALLOW_HTTP")

# Names that change how programs load code, find files or reach the network. A secret with one of these names would
# take effect for Hermes and everything it starts (an `LD_PRELOAD` in the vault runs code in every process), so they
# are refused unless the owner lists them in `secrets.aisecuritywarden.allow_names`. The same list is in the client
# (securitywarden.client.envnames); a test keeps the two equal.
DANGEROUS_NAMES = frozenset({
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE",
    "NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS",
    "PERL5LIB", "PERL5OPT", "RUBYLIB", "RUBYOPT", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
    "BASH_ENV", "ENV", "PATH", "PATHEXT", "COMSPEC", "SHELL", "HOME", "USERPROFILE",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXEC_PATH",
})
DANGEROUS_PREFIXES = ("DYLD_",)


def dangerous_name(name: str) -> bool:
    """Whether a secret's name is one that changes how programs load or connect (case-insensitive: Windows)."""
    up = name.upper()
    return up in DANGEROUS_NAMES or up.startswith(DANGEROUS_PREFIXES)


def _allowed_names(cfg: dict) -> set[str]:
    raw = cfg.get("allow_names")
    if isinstance(raw, str):
        raw = [raw]
    return {n.strip().upper() for n in raw if isinstance(n, str) and n.strip()} if isinstance(raw, list) else set()


# swctl exit codes (0.7.13 and later); older versions exit 1 for everything and the text decides.
EXIT_NETWORK, EXIT_TOKEN, EXIT_APPROVAL, EXIT_CONFIG = 3, 4, 5, 6

_TEXT_RULES: tuple[tuple[ErrorKind, tuple[str, ...]], ...] = (
    (ErrorKind.NOT_CONFIGURED, ("no machine token", "no server url", "credential file not found",
                                "not a valid environment variable")),
    (ErrorKind.AUTH_FAILED, ("approval", "denied", "not allowed from")),
    (ErrorKind.AUTH_EXPIRED, ("401", "expired", "revoked")),
    (ErrorKind.NETWORK, ("can't reach", "connecterror", "connection", "timed out", "name resolution",
                         "temporary failure", "ssl", "certificate")),
)


def _text_kind(message: str) -> ErrorKind:
    low = message.lower()
    for kind, words in _TEXT_RULES:
        if any(w in low for w in words):
            return kind
    return ErrorKind.INTERNAL


def _str(cfg: dict, key: str) -> str:
    v = cfg.get(key)
    return v.strip() if isinstance(v, str) else ""


def find_swctl(cfg: dict) -> Optional[str]:
    """The configured swctl, else the one on PATH, else the one next to this Python (a shared venv)."""
    configured = _str(cfg, "swctl")
    if configured:
        path = os.path.expanduser(configured)
        return path if os.path.isfile(path) else None
    found = shutil.which("swctl")
    if found:
        return found
    names = ("swctl.exe", "swctl") if os.name == "nt" else ("swctl",)
    # next to this Python (a shared venv), then pipx's folder: a service often runs without ~/.local/bin on PATH
    for folder in (Path(sys.executable).parent, Path.home() / ".local" / "bin"):
        for name in names:
            if (folder / name).is_file():
                return str(folder / name)
    return None


def _last_line(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    line = lines[-1] if lines else ""
    if line.startswith("swctl: "):
        line = line[len("swctl: "):]
    return line[:300]


class AiSecurityWardenSource(SecretSource):
    """Every secret the machine token's project holds, as environment variables (a bulk source)."""

    name = NAME
    label = "aiSecurityWarden"
    shape = "bulk"
    remediation_hints = {
        ErrorKind.NOT_CONFIGURED: "Store a machine token on this computer (`swctl --server URL setup` with the "
                                  "website's setup code); with several stored, set secrets.aisecuritywarden.token_name.",
        ErrorKind.BINARY_MISSING: "Install the client (`pipx install aisecuritywarden`) or set "
                                  "secrets.aisecuritywarden.swctl to the full path of swctl.",
        ErrorKind.AUTH_FAILED: "The approval was denied or expired, or this address isn't on the token's list: "
                               "check the token on the aiSecurityWarden website, then restart Hermes.",
        ErrorKind.AUTH_EXPIRED: "The server refused the machine token (revoked, expired or wrong): make a new "
                                "one on the website and run `swctl setup` again.",
        ErrorKind.NETWORK: "Couldn't reach the aiSecurityWarden server: check the network (and "
                           "secrets.aisecuritywarden.server_url, if set).",
        ErrorKind.TIMEOUT: "No answer in time. If the token needs a phone approval, approve it sooner or "
                           "raise secrets.aisecuritywarden.timeout_seconds (default 180).",
        ErrorKind.INTERNAL: "Run `swctl export --format json` in a shell (its output is your secrets: don't share it) to see "
                            "swctl's own error.",
    }

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Load this computer's aiSecurityWarden secrets at start-up", "default": False},
            "swctl": {"description": "Full path of swctl (default: PATH, next to Hermes's Python, ~/.local/bin)",
                      "default": ""},
            "server_url": {"description": "Server URL (default: SW_SERVER_URL, else the token's own server)",
                           "default": ""},
            "token_name": {"description": "Which stored token, when several are (default: SW_TOKEN_NAME)",
                           "default": ""},
            "token_id": {"description": "The token's id in SW_Tokens.json (default: SW_TOKEN_ID)", "default": ""},
            "token_file": {"description": "A file holding the machine token (default: SW_ACCESS_TOKEN_FILE)",
                           "default": ""},
            "ca_bundle": {"description": "Custom CA bundle for TLS (default: SW_CA_BUNDLE)", "default": ""},
            "allow_names": {"description": "Secret names to load even though they change how programs load or "
                                           "connect (LD_PRELOAD, PATH, HTTPS_PROXY ...); refused otherwise",
                            "default": []},
            "timeout_seconds": {"description": "Longest wait, including a phone approval", "default": DEFAULT_TIMEOUT},
            "override_existing": {"description": "Replace values already set in .env or the shell", "default": False},
        }

    def protected_env_vars(self, cfg: dict) -> frozenset[str]:
        # a secret in the vault must never redirect or replace how this source reaches the vault
        return frozenset(SW_ENV)

    def fetch_timeout_seconds(self, cfg: dict) -> float:
        cfg = cfg if isinstance(cfg, dict) else {}
        val = coerce_float(cfg.get("timeout_seconds", DEFAULT_TIMEOUT), DEFAULT_TIMEOUT)
        return val if val > 0 else DEFAULT_TIMEOUT

    def argv(self, swctl: str, cfg: dict) -> list[str]:
        argv = [swctl]
        for key, flag in (("server_url", "--server"), ("token_name", "--token-name"), ("token_id", "--token-id"),
                          ("token_file", "--token-file"), ("ca_bundle", "--ca-bundle")):
            value = _str(cfg, key)
            if value:
                argv += [flag, os.path.expanduser(value) if key in ("token_file", "ca_bundle") else value]
        return argv + ["export", "--format", "json"]

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        result = FetchResult()
        try:
            return self._fetch(cfg if isinstance(cfg, dict) else {}, result)
        except Exception as e:   # the contract: never raise
            return result.fail(f"aiSecurityWarden source failed: {type(e).__name__}", ErrorKind.INTERNAL)

    def _fetch(self, cfg: dict, result: FetchResult) -> FetchResult:
        swctl = find_swctl(cfg)
        if not swctl:
            where = f" at {_str(cfg, 'swctl')}" if _str(cfg, "swctl") else " on PATH"
            return result.fail(f"swctl not found{where}", ErrorKind.BINARY_MISSING)
        result.binary_path = Path(swctl)
        # finish a little before Hermes's own deadline, so the answer is ours and not a bare timeout
        total = self.fetch_timeout_seconds(cfg)
        budget = total - 5.0 if total > 10 else total * 0.9
        try:
            proc = self._run(self.argv(swctl, cfg), budget)
        except RuntimeError as e:
            text = str(e)
            kind = ErrorKind.TIMEOUT if "timed out" in text else ErrorKind.BINARY_MISSING
            return result.fail(text, kind)
        if proc.returncode != 0:
            message = _last_line(proc.stderr) or f"swctl exited with {proc.returncode}"
            kind = {EXIT_NETWORK: ErrorKind.NETWORK, EXIT_TOKEN: ErrorKind.AUTH_EXPIRED,
                    EXIT_APPROVAL: ErrorKind.AUTH_FAILED, EXIT_CONFIG: ErrorKind.NOT_CONFIGURED}.get(
                        proc.returncode) or _text_kind(message)
            return result.fail(message, kind)
        if len(proc.stdout) > MAX_OUTPUT:
            return result.fail("swctl printed more than 4 MB", ErrorKind.INTERNAL)
        try:
            data: Any = json.loads(proc.stdout or "")
        except ValueError:
            return result.fail("swctl didn't print JSON (is it aiSecurityWarden's swctl?)", ErrorKind.INTERNAL)
        if not isinstance(data, dict):
            return result.fail("swctl printed JSON that isn't an object", ErrorKind.INTERNAL)
        allowed = _allowed_names(cfg)
        for key, value in data.items():
            if not isinstance(key, str) or not is_valid_env_name(key):
                result.warnings.append("skipped a secret whose name isn't an environment variable name")
            elif dangerous_name(key) and key.upper() not in allowed:
                result.warnings.append(f"refused {key}: it changes how programs load or connect "
                                       f"(allow it with secrets.aisecuritywarden.allow_names if you meant it)")
            elif not isinstance(value, str) or value == "":
                result.warnings.append(f"skipped {key}: empty value")
            else:
                result.secrets[key] = value
        if not result.secrets and not data:
            result.warnings.append("the token's project has no secrets")
        return result

    @staticmethod
    def _run(argv: list[str], timeout: float):
        if _provider_env is not None:
            env = _provider_env(allow_env=SW_ENV)
        else:  # pragma: no cover - older Hermes
            env = {k: v for k, v in os.environ.items()
                   if k in SW_ENV or k in ("PATH", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "SYSTEMROOT",
                                           "SystemRoot", "TEMP", "TMP", "TMPDIR", "XDG_CONFIG_HOME")}
        env["NO_COLOR"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        if _run_cli is not None:
            proc = _run_cli(argv, env=env, timeout=timeout, label="swctl",
                            timeout_message=f"swctl timed out after {timeout:.0f}s (an approval still waiting?)")
        else:  # pragma: no cover - older Hermes
            import subprocess
            try:
                proc = subprocess.run(argv, env=env, capture_output=True, text=True, encoding="utf-8",
                                      errors="replace", timeout=timeout, stdin=subprocess.DEVNULL, check=False)
            except subprocess.TimeoutExpired as e:
                raise RuntimeError(f"swctl timed out after {timeout:.0f}s (an approval still waiting?)") from e
            except OSError as e:
                raise RuntimeError(f"failed to invoke swctl: {e}") from e
        proc.stdout = proc.stdout or ""
        proc.stderr = _scrub_ansi(proc.stderr or "") if _scrub_ansi else (proc.stderr or "")
        return proc


def register(ctx) -> None:
    ctx.register_secret_source(AiSecurityWardenSource())
