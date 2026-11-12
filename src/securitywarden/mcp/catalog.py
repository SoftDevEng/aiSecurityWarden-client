"""The built-in connectors: made by aiSecurityWarden and shipped with the client. Any account can turn them on
for a project on the website; they don't count against the account's custom connector limit."""

from __future__ import annotations

import importlib
import json
from typing import Any

# "module:Class" for a connector; "mapping:<file>" for an approval proxy (mcp/mappings/<file>.swproxy)
BUILTIN = {"gmail": "securitywarden.mcp.gmail:Gmail", "github": "mapping:github"}


def load_builtin(name: str) -> Any:
    kind, _, rest = BUILTIN[name].partition(":")
    if kind == "mapping":
        from importlib import resources
        from .proxy import proxy_class
        text = resources.files("securitywarden.mcp").joinpath("mappings", f"{rest}.swproxy").read_text("utf-8")
        return proxy_class(json.loads(text))
    return getattr(importlib.import_module(kind), rest)


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
