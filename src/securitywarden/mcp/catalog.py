"""The built-in connectors: made by SecurityWarden and shipped with the client. Any account can turn them on
for a project on the website; they don't count against the account's custom connector limit."""

from __future__ import annotations

import importlib
from typing import Any

BUILTIN = {"gmail": "securitywarden.mcp.gmail:Gmail"}


def load_builtin(name: str) -> Any:
    mod_name, _, cls_name = BUILTIN[name].partition(":")
    return getattr(importlib.import_module(mod_name), cls_name)


def builtin_catalog() -> list[dict[str, Any]]:
    """What the website shows about each built-in connector."""
    out = []
    for name in sorted(BUILTIN):
        cls = load_builtin(name)
        out.append({"name": name, "title": getattr(cls, "title", "") or name.capitalize(),
                    "description": cls.description, "secrets": list(cls.secrets),
                    "suggested_rules": list(cls.suggested_rules),
                    "tools": [{"name": f"{name}_{s.name}", "action": s.action, "risk": s.risk,
                               "description": s.description} for s in cls.tool_specs()]})
    return out
