"""A stand-in for Hermes Agent's ``agent.secret_sources.base`` (API version 1), for testing the secret source
without Hermes installed. It copies the parts of Hermes's contract the plugin uses; with Hermes installed the
tests use the real module instead (and Hermes's own conformance kit can run against the plugin)."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import types
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

SECRET_SOURCE_API_VERSION = 1
DEFAULT_FETCH_TIMEOUT_SECONDS = 120.0


class ErrorKind(str, Enum):
    NOT_CONFIGURED = "not_configured"
    BINARY_MISSING = "binary_missing"
    AUTH_FAILED = "auth_failed"
    AUTH_EXPIRED = "auth_expired"
    REF_INVALID = "ref_invalid"
    NETWORK = "network"
    EMPTY_VALUE = "empty_value"
    TIMEOUT = "timeout"
    INTERNAL = "internal"


def coerce_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


@dataclass
class FetchResult:
    secrets: dict = field(default_factory=dict)
    applied: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    error: Optional[str] = None
    error_kind: Optional[ErrorKind] = None
    binary_path: Optional[Path] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def fail(self, error: str, kind: ErrorKind) -> "FetchResult":
        self.error, self.error_kind = error, kind
        return self


class SecretSource(ABC):
    api_version = SECRET_SOURCE_API_VERSION
    name = ""
    label = ""
    shape = "mapped"
    scheme = None
    token_env_key = None
    default_token_env = ""
    override_existing_default = False
    remediation_hints: dict = {}

    @abstractmethod
    def fetch(self, cfg: dict, home_path: Path) -> FetchResult: ...

    def is_enabled(self, cfg: dict) -> bool:
        return bool(isinstance(cfg, dict) and cfg.get("enabled"))

    def protected_env_vars(self, cfg: dict) -> frozenset:
        return frozenset()

    def fetch_timeout_seconds(self, cfg: dict) -> float:
        val = coerce_float((cfg or {}).get("timeout_seconds", DEFAULT_FETCH_TIMEOUT_SECONDS),
                           DEFAULT_FETCH_TIMEOUT_SECONDS)
        return val if val > 0 else DEFAULT_FETCH_TIMEOUT_SECONDS

    def remediation(self, kind, cfg: dict) -> str:
        return self.remediation_hints.get(kind, "") if kind else ""


_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ANSI_RE = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?)")


def is_valid_env_name(name: str) -> bool:
    return bool(name) and bool(_ENV_NAME_RE.match(name))


def scrub_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text or "")


_PROVIDER_ENV_BASE = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "SystemRoot", "APPDATA", "LOCALAPPDATA",
                      "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "LC_CTYPE", "XDG_CONFIG_HOME")


def build_minimal_provider_env(source_env=None, *, allow_env=(), extra_env=None) -> dict:
    source = source_env if source_env is not None else os.environ
    env = {k: source[k] for k in (*_PROVIDER_ENV_BASE, *allow_env) if k in source}
    if extra_env:
        env.update(extra_env)
    env["NO_COLOR"] = "1"
    return env


def run_cli(argv, *, env, timeout, label, timeout_message, stdin=subprocess.DEVNULL):
    try:
        return subprocess.run(list(argv), env=env, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, stdin=stdin, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(timeout_message) from exc
    except OSError as exc:
        raise RuntimeError(f"failed to invoke {label}: {exc}") from exc


def install() -> bool:
    """Make ``agent.secret_sources.base`` importable. Returns False if the real Hermes is installed."""
    try:
        import agent.secret_sources.base  # noqa: F401
        return False
    except ImportError:
        pass
    base = types.ModuleType("agent.secret_sources.base")
    for name in ("SECRET_SOURCE_API_VERSION", "ErrorKind", "FetchResult", "SecretSource", "coerce_float",
                 "is_valid_env_name", "scrub_ansi", "build_minimal_provider_env", "run_cli"):
        setattr(base, name, globals()[name])
    agent = types.ModuleType("agent")
    sources = types.ModuleType("agent.secret_sources")
    agent.secret_sources = sources
    sources.base = base
    sys.modules.update({"agent": agent, "agent.secret_sources": sources, "agent.secret_sources.base": base})
    return True
