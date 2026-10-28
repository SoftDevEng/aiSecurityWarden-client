"""Human-approval policies for machine tokens. Standard library only; shared by server and client.

A policy is a small JSON object stored on the token row (NULL = no approval needed)::

    {"mode": "session", "session_ttl": 28800, "channels": ["admin_ui", "push:ntfy"],
     "timeout": 120, "max_pending": 1, "max_per_hour": 6}

Parsing is strict, like :mod:`securitywarden.ipallow`: unknown keys, unknown channels and
out-of-range numbers are rejected rather than ignored or clamped.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

MODES = ("session", "every_fetch")
CHANNELS = ("admin_ui", "push:ntfy", "push:telegram")
PUSH_CHANNELS = tuple(c for c in CHANNELS if c.startswith("push:"))

MAX_SESSION_TTL = 7 * 86400  # hard ceiling; servers may lower it (SW_MAX_SESSION_TTL)

DEFAULTS: dict[str, Any] = {
    "mode": "session",
    "session_ttl": 8 * 3600,
    "channels": ["admin_ui"],
    "timeout": 120,
    "max_pending": 1,
    "max_per_hour": 6,
}

# (minimum, maximum) for every numeric field
RANGES: dict[str, tuple[int, int]] = {
    "session_ttl": (60, MAX_SESSION_TTL),
    "timeout": (15, 600),
    "max_pending": (1, 5),
    "max_per_hour": (1, 120),
}

_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$", re.IGNORECASE)
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(text: str | int) -> int:
    """``90`` / ``"90"`` / ``"90s"`` / ``"30m"`` / ``"8h"`` / ``"2d"`` -> seconds."""
    if isinstance(text, bool):
        raise ValueError("invalid duration")
    if isinstance(text, int):
        return text
    m = _DURATION_RE.match(text or "")
    if not m:
        raise ValueError(f"invalid duration: {text!r} (use e.g. 90s, 30m, 8h, 2d)")
    return int(m.group(1)) * _UNITS[m.group(2).lower()]


def normalize_policy(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Validate a policy and return it with every field filled in, or None for 'no approval'.

    Raises ValueError with a message suitable for the user.
    """
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("approval policy must be an object")
    unknown = set(value) - set(DEFAULTS)
    if "approvers" in unknown:
        raise ValueError("device approvers are not supported yet (planned for a later release)")
    if unknown:
        raise ValueError(f"unknown approval policy field(s): {', '.join(sorted(unknown))}")

    out = {**DEFAULTS, **value}
    if out["mode"] not in MODES:
        raise ValueError(f"approval mode must be one of: {', '.join(MODES)}")

    channels = out["channels"]
    if not isinstance(channels, (list, tuple)) or not channels:
        raise ValueError("at least one approval channel is required")
    seen: list[str] = []
    for ch in channels:
        if ch not in CHANNELS:
            raise ValueError(f"unknown approval channel {ch!r} (use: {', '.join(CHANNELS)})")
        if ch not in seen:
            seen.append(ch)
    out["channels"] = seen

    for key, (lo, hi) in RANGES.items():
        v = out[key]
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(f"{key} must be a whole number")
        if not lo <= v <= hi:
            raise ValueError(f"{key} must be between {lo} and {hi}")
    if out["max_pending"] > out["max_per_hour"]:
        raise ValueError("max_pending cannot exceed max_per_hour")
    return out


def describe(policy: Mapping[str, Any] | None) -> str:
    """One-line summary for lists and audit entries."""
    if not policy:
        return "none"
    mode = "every fetch" if policy["mode"] == "every_fetch" else f"session {_fmt(policy['session_ttl'])}"
    return f"{mode} via {', '.join(policy['channels'])}"


def _fmt(seconds: int) -> str:
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % n == 0:
            return f"{seconds // n}{unit}"
    return f"{seconds}s"
