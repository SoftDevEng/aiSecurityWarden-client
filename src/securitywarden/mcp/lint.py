"""Static checks for a connector class: what ``sw-mcp check`` reports. Errors stop ``sw-mcp`` from serving
the connector correctly; warnings are things a person approving actions would trip over."""

from __future__ import annotations

import inspect
import re
from typing import Any

from ..approval import ACTION_RE, normalize_action_policy, parse_action_rule, rule_matches
from .framework import Connector

NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
SECRET_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
JSON_TYPES = {"string", "integer", "boolean", "array", "object", "number"}
TOOL_NAME_BUDGET = 40      # agents add a prefix (Hermes: mcp_<server>_); many providers cap names at 64


def check_connector(cls: Any) -> list[tuple[str, str]]:
    """[(level, message)], level "error" or "warning". Empty: all good."""
    out: list[tuple[str, str]] = []

    def err(msg: str) -> None:
        out.append(("error", msg))

    def warn(msg: str) -> None:
        out.append(("warning", msg))

    if not (isinstance(cls, type) and issubclass(cls, Connector)):
        return [("error", "not a subclass of securitywarden.mcp.Connector")]
    if not NAME_RE.match(cls.name or ""):
        err(f"name {cls.name!r}: lowercase letters, digits and _, starting with a letter (it prefixes every "
            "action and tool name)")
        return out
    if not cls.description:
        warn("no description: agents and `sw-mcp tools` show it")
    for s in cls.secrets:
        if not SECRET_RE.match(s):
            err(f"secret name {s!r}: use UPPER_CASE like {cls.name.upper()}_API_KEY")
    try:
        specs = cls.tool_specs()
    except ValueError as e:
        err(str(e))
        return out
    if not specs:
        err("no tools: decorate methods with @tool(...)")
    actions: dict[str, str] = {}
    for spec in specs:
        where = f"tool {spec.name}"
        full = f"{cls.name}_{spec.name}"
        if not NAME_RE.match(spec.name):
            err(f"{where}: tool names are lowercase letters, digits and _")
        if len(full) > TOOL_NAME_BUDGET:
            warn(f"{where}: {full!r} is long; with the agent's prefix it may pass 64 characters")
        if not spec.description.strip() or len(spec.description) < 15:
            err(f"{where}: describe what it does and what it returns (the AI chooses tools by this text)")
        if not ACTION_RE.match(spec.action):
            err(f"{where}: invalid action {spec.action!r}")
        actions[spec.action] = spec.risk
        if spec.action.split(".")[1] == "read" and spec.risk != "low":
            warn(f"{where}: a {spec.action} action is usually risk low (reads change nothing)")
        for k, p in spec.params.items():
            if not isinstance(p, dict) or p.get("type") not in JSON_TYPES:
                err(f"{where}: parameter {k!r} needs a JSON type ({', '.join(sorted(JSON_TYPES))})")
                continue
            if p["type"] == "number":
                err(f"{where}: parameter {k!r}: use integer or string, not number (action arguments may not "
                    "contain floats)")
            if p["type"] == "array" and not isinstance(p.get("items"), dict):
                warn(f"{where}: parameter {k!r}: say what the list holds, e.g. \"items\": {{\"type\": \"string\"}}")
            if not p.get("description") and len(spec.params) > 1:
                warn(f"{where}: parameter {k!r} has no description")
        for r in spec.required:
            if r not in spec.params:
                err(f"{where}: required {r!r} is not a parameter")
        _check_signature(spec, err)
    for rule_text in cls.suggested_rules:
        try:
            rule = parse_action_rule(rule_text)
            normalize_action_policy({"rules": [rule]})
        except ValueError as e:
            err(f"suggested rule {rule_text!r}: {e}")
            continue
        hits = [a for a in actions if rule_matches(rule["match"], a)]
        if not hits:
            warn(f"suggested rule {rule_text!r} matches none of this connector's actions")
        if rule["mode"] in ("allow", "window") and any(actions[a] == "high" for a in hits):
            warn(f"suggested rule {rule_text!r} covers high-risk actions, which always ask anyway")
    if specs and not cls.suggested_rules:
        warn("no suggested_rules: give users a sensible starting policy (reads allow, risky actions each)")
    return out


def _check_signature(spec: Any, err: Any) -> None:
    try:
        sig = inspect.signature(spec.method)
    except (TypeError, ValueError):
        return
    params = [p for p in sig.parameters.values() if p.name != "self"]
    if any(p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD) for p in params):
        return
    names = {p.name for p in params}
    for k in spec.params:
        if k not in names:
            err(f"tool {spec.name}: parameter {k!r} is in params but not an argument of the method")
    for p in params:
        if p.name not in spec.params:
            err(f"tool {spec.name}: method argument {p.name!r} is missing from params")
        elif p.name in spec.required and p.default is not p.empty:
            err(f"tool {spec.name}: required parameter {p.name!r} shouldn't have a default")
        elif p.name not in spec.required and p.default is p.empty:
            err(f"tool {spec.name}: optional parameter {p.name!r} needs a default value in the method")
