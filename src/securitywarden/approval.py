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
CHANNELS = ("admin_ui", "push:ntfy", "push:telegram", "push:discord")
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


# ---------------------------------------------------------------------------
# action approval: what an AI agent's tools may do (see DESIGN.md "Action approval")
# ---------------------------------------------------------------------------
#
# A token's action policy (NULL = defaults: ask a person for every action, on the website):
#
#     {"channels": ["admin_ui", "push:telegram"], "timeout": 3600, "max_pending": 5, "max_per_hour": 60,
#      "rules": [{"match": "gmail.send", "mode": "each"},
#                {"match": "gmail.label", "mode": "window", "window": 1800},
#                {"match": "gmail.read.*", "mode": "allow"},
#                {"match": "*", "mode": "each"}]}
#
# Rules are tried in order; the first match decides. Nothing matched: "each".

ACTION_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}(\.[a-z][a-z0-9_]{0,31}){1,5}$")
ACTION_MATCH_RE = re.compile(r"^(\*|[a-z][a-z0-9_]{0,31}(\.[a-z][a-z0-9_]{0,31}){0,5}(\.\*)?)$")
ACTION_MODES = ("allow", "each", "window", "deny")
RISKS = ("low", "medium", "high")
MAX_RULES = 50

ACTION_DEFAULTS: dict[str, Any] = {
    "channels": ["admin_ui"],
    "timeout": 3600,
    "max_pending": 5,
    "max_per_hour": 60,
    "rules": [],
}

ACTION_RANGES: dict[str, tuple[int, int]] = {
    "timeout": (60, 86400),          # the agent checks back, so a person may take hours
    "max_pending": (1, 50),
    "max_per_hour": (1, 1000),
}
WINDOW_RANGE = (60, 86400)


def normalize_action_policy(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Validate a token's action policy; None means the defaults. Raises ValueError for the user."""
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("action policy must be an object")
    unknown = set(value) - set(ACTION_DEFAULTS)
    if unknown:
        raise ValueError(f"unknown action policy field(s): {', '.join(sorted(unknown))}")
    out = {**ACTION_DEFAULTS, **value}

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

    for key, (lo, hi) in ACTION_RANGES.items():
        v = out[key]
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(f"{key} must be a whole number")
        if not lo <= v <= hi:
            raise ValueError(f"{key} must be between {lo} and {hi}")
    if out["max_pending"] > out["max_per_hour"]:
        raise ValueError("max_pending cannot exceed max_per_hour")

    rules = out["rules"]
    if not isinstance(rules, (list, tuple)):
        raise ValueError("rules must be a list")
    if len(rules) > MAX_RULES:
        raise ValueError(f"at most {MAX_RULES} rules")
    clean = []
    for r in rules:
        if not isinstance(r, Mapping):
            raise ValueError("each rule must be an object")
        if set(r) - {"match", "mode", "window"}:
            raise ValueError(f"unknown rule field(s): {', '.join(sorted(set(r) - {'match', 'mode', 'window'}))}")
        match, mode = r.get("match"), r.get("mode")
        if not isinstance(match, str) or not ACTION_MATCH_RE.match(match):
            raise ValueError(f"invalid action pattern {match!r} (e.g. gmail.send, gmail.read.*, *)")
        if mode not in ACTION_MODES:
            raise ValueError(f"rule mode must be one of: {', '.join(ACTION_MODES)}")
        rule: dict[str, Any] = {"match": match, "mode": mode}
        if mode == "window":
            w = r.get("window")
            if isinstance(w, bool) or not isinstance(w, int) or not WINDOW_RANGE[0] <= w <= WINDOW_RANGE[1]:
                raise ValueError(f"window must be a whole number of seconds between {WINDOW_RANGE[0]} and "
                                 f"{WINDOW_RANGE[1]}")
            rule["window"] = w
        elif "window" in r:
            raise ValueError("window only applies to mode 'window'")
        clean.append(rule)
    out["rules"] = clean
    return out


def effective_action_policy(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """The policy in force: the token's, or the defaults when it has none."""
    return normalize_action_policy(value) or dict(ACTION_DEFAULTS, rules=[])


def rule_matches(pattern: str, action: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith(".*"):
        prefix = pattern[:-2]
        return action == prefix or action.startswith(prefix + ".")
    return action == pattern


def action_decision(policy: Mapping[str, Any] | None, action: str, risk: str) -> tuple[str, int | None]:
    """(mode, window seconds) for an action. A high-risk action is never allowed without asking and
    never covered by a time window: such rules are tightened to "each". Risk only ever tightens."""
    if not ACTION_RE.match(action or ""):
        raise ValueError("invalid action name (e.g. gmail.send: lowercase words joined by dots)")
    if risk not in RISKS:
        raise ValueError(f"risk must be one of: {', '.join(RISKS)}")
    mode, window = "each", None
    for r in effective_action_policy(policy)["rules"]:
        if rule_matches(r["match"], action):
            mode, window = r["mode"], r.get("window")
            break
    if risk == "high" and mode in ("allow", "window"):
        return "each", None
    return mode, window


def describe_actions(policy: Mapping[str, Any] | None) -> str:
    """One-line summary for lists and audit entries."""
    p = effective_action_policy(policy)
    parts = []
    for r in p["rules"]:
        parts.append(f"{r['match']}={r['mode']}" + (f":{_fmt(r['window'])}" if r["mode"] == "window" else ""))
    rules = ", ".join(parts) if parts else "ask for every action"
    return f"{rules} via {', '.join(p['channels'])}" + ("" if policy else " (default)")


def parse_action_rule(text: str) -> dict[str, Any]:
    """``gmail.send=each``, ``gmail.read.*=allow``, ``gmail.label=window:30m``, ``*=deny`` -> a rule."""
    match, sep, mode = (text or "").partition("=")
    if not sep:
        raise ValueError(f"invalid rule {text!r} (use ACTION=allow|each|deny or ACTION=window:30m)")
    mode, _, dur = mode.strip().partition(":")
    rule: dict[str, Any] = {"match": match.strip(), "mode": mode}
    if mode == "window":
        rule["window"] = parse_duration(dur or "")
    return rule


# -- the summary a person sees ---------------------------------------------------------------

SUMMARY_LIMITS = {"title": 100, "label": 40, "value": 300, "preview": 500, "fields": 10}


def normalize_action_summary(value: Any) -> dict[str, Any]:
    """{"title": str, "fields": [[label, value], ...], "preview": str?, "count": int?} -> checked copy."""
    if not isinstance(value, Mapping):
        raise ValueError("summary must be an object")
    if set(value) - {"title", "fields", "preview", "count"}:
        raise ValueError("unknown summary field(s)")
    title = value.get("title")
    if not isinstance(title, str) or not title.strip() or len(title) > SUMMARY_LIMITS["title"]:
        raise ValueError(f"summary title is required (max {SUMMARY_LIMITS['title']} characters)")
    fields = value.get("fields", [])
    if not isinstance(fields, (list, tuple)) or len(fields) > SUMMARY_LIMITS["fields"]:
        raise ValueError(f"summary fields: a list of at most {SUMMARY_LIMITS['fields']} [label, value] pairs")
    clean_fields = []
    for f in fields:
        if (not isinstance(f, (list, tuple)) or len(f) != 2 or not all(isinstance(x, str) for x in f)
                or len(f[0]) > SUMMARY_LIMITS["label"] or len(f[1]) > SUMMARY_LIMITS["value"]):
            raise ValueError("each summary field is [label, value]: short strings")
        clean_fields.append([f[0], f[1]])
    out: dict[str, Any] = {"title": title.strip(), "fields": clean_fields}
    preview = value.get("preview")
    if preview is not None:
        if not isinstance(preview, str) or len(preview) > SUMMARY_LIMITS["preview"]:
            raise ValueError(f"summary preview: at most {SUMMARY_LIMITS['preview']} characters")
        out["preview"] = preview
    count = value.get("count", 1)
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 100000:
        raise ValueError("summary count must be a whole number from 1")
    out["count"] = count
    return out


def clip(text: str, limit: int) -> str:
    """Shorten text for a summary field (single line, with an ellipsis when cut)."""
    t = " ".join(str(text).split())
    return t if len(t) <= limit else t[: limit - 1] + "…"
