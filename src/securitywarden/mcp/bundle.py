"""Connector bundles: a connector's Python code packed into one JSON document, so it can be stored
(encrypted) in SecurityWarden and loaded by ``sw-mcp`` on every machine that uses it, without pip.

    sw-mcp pack --connector notes -o notes.swconnector     # then upload it on the SecurityWarden website

A bundle holds the connector's package (``.py`` files and small text data files), the entry point
(``package.module:Class``), and a description of its tools for the website to show before upload. Bundled
connectors may use only the standard library and what the SecurityWarden client already installs (httpx,
cryptography). They are imported from memory: nothing is written to disk.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import json
import os
import re
import sys
import threading
from typing import Any

from .. import __version__
from .framework import Connector

FORMAT = "sw-connector-1"
EXTENSION = ".swconnector"
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(/[A-Za-z_][A-Za-z0-9_]*)*\.(py|json|txt|md)$")
ENTRY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*$")
MAX_FILES = 200
MAX_BYTES = 10 * 1024 * 1024          # the largest any plan allows; the server enforces the account's own limit
# packages a bundle may never provide: they would replace code sw-mcp itself runs on
RESERVED = {"securitywarden", "securitywarden_server", "httpx", "httpcore", "cryptography", "anyio", "certifi",
            "idna", "h11", "sniffio", "cffi", "_cffi_backend", "pip", "setuptools", "site", "sitecustomize",
            "usercustomize", "encodings"}


class BundleError(ValueError):
    pass


def bundle_bytes(bundle: dict[str, Any]) -> bytes:
    """The canonical bytes of a bundle (what its size and SHA-256 are taken over)."""
    return json.dumps(bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def top_levels(bundle: dict[str, Any]) -> set[str]:
    return {p.split("/", 1)[0].removesuffix(".py") for p in bundle["files"]}


def validate_bundle(bundle: Any) -> dict[str, Any]:
    """Check a bundle's shape (not its code). Returns it; raises BundleError."""
    if not isinstance(bundle, dict) or bundle.get("format") != FORMAT:
        raise BundleError(f"not a SecurityWarden connector bundle (format {FORMAT})")
    name, entry, files = bundle.get("name"), bundle.get("entry"), bundle.get("files")
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise BundleError("the bundle's connector name must be lowercase letters, digits and _")
    if not isinstance(entry, str) or not ENTRY_RE.match(entry):
        raise BundleError("the bundle's entry must look like package.module:ClassName")
    if not isinstance(files, dict) or not files or len(files) > MAX_FILES:
        raise BundleError(f"the bundle must contain 1 to {MAX_FILES} files")
    for path, text in files.items():
        if not isinstance(path, str) or not PATH_RE.match(path) or not isinstance(text, str):
            raise BundleError(f"bad file in the bundle: {str(path)[:80]!r} (only .py, .json, .txt, .md under "
                              "plain package folders)")
    for opt in ("title", "description"):
        if opt in bundle and not isinstance(bundle[opt], str):
            raise BundleError(f"the bundle's {opt} must be text")
    if len(bundle_bytes(bundle)) > MAX_BYTES:
        raise BundleError("the bundle is larger than 10 MB")
    mod = entry.partition(":")[0]
    if _module_path(files, mod) is None:
        raise BundleError(f"the entry module {mod} is not in the bundle")
    for top in top_levels(bundle):
        if top in RESERVED or top in sys.stdlib_module_names:
            raise BundleError(f"the bundle may not provide the package {top!r}")
    return bundle


def _module_path(files: dict[str, str], module: str) -> tuple[str, bool] | None:
    base = module.replace(".", "/")
    if f"{base}/__init__.py" in files:
        return f"{base}/__init__.py", True
    if f"{base}.py" in files:
        return f"{base}.py", False
    return None


# ---------------------------------------------------------------------------
# packing
# ---------------------------------------------------------------------------

def pack(cls: type[Connector]) -> dict[str, Any]:
    """Bundle the package (or single module) a connector class lives in."""
    from .lint import check_connector
    errors = [m for level, m in check_connector(cls) if level == "error"]
    if errors:
        raise BundleError("the connector has errors (see sw-mcp check):\n  " + "\n  ".join(errors))
    top = cls.__module__.split(".", 1)[0]
    spec = importlib.util.find_spec(top)
    if spec is None or not spec.origin:
        raise BundleError(f"can't find the files of {top}")
    files: dict[str, str] = {}
    if spec.submodule_search_locations:              # a package: every file under its folder
        root = list(spec.submodule_search_locations)[0]
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith((".", "__pycache__")))
            for fn in sorted(filenames):
                rel = os.path.relpath(os.path.join(dirpath, fn), os.path.dirname(root)).replace(os.sep, "/")
                if PATH_RE.match(rel):
                    with open(os.path.join(dirpath, fn), encoding="utf-8") as f:
                        files[rel] = f.read()
    else:
        with open(spec.origin, encoding="utf-8") as f:
            files[f"{top}.py"] = f.read()
    tools = [{"name": f"{cls.name}_{s.name}", "action": s.action, "risk": s.risk, "description": s.description}
             for s in cls.tool_specs()]
    bundle = {
        "format": FORMAT, "name": cls.name, "title": getattr(cls, "title", "") or cls.name.capitalize(),
        "description": cls.description or "", "entry": f"{cls.__module__}:{cls.__qualname__}",
        "secrets": list(cls.secrets), "suggested_rules": list(cls.suggested_rules), "tools": tools,
        "packed_with": __version__, "files": files,
    }
    return validate_bundle(bundle)


def summary(bundle: dict[str, Any]) -> dict[str, Any]:
    raw = bundle_bytes(bundle)
    if bundle.get("format") == "sw-proxy/1":        # an approval proxy's mapping file
        from .proxy import mapped_tools
        return {"name": bundle["name"], "title": bundle.get("title") or bundle["name"], "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(), "tools": mapped_tools(bundle), "kind": "proxy",
                "secrets": bundle.get("secrets") or [], "suggested_rules": bundle.get("suggested_rules") or []}
    return {"name": bundle["name"], "title": bundle.get("title") or bundle["name"], "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(), "tools": bundle.get("tools") or [],
            "secrets": bundle.get("secrets") or [], "suggested_rules": bundle.get("suggested_rules") or []}


# ---------------------------------------------------------------------------
# loading from memory
# ---------------------------------------------------------------------------

class _Loader(importlib.abc.Loader):
    def __init__(self, files: dict[str, str], path: str, label: str) -> None:
        self.files, self.path, self.label = files, path, label

    def create_module(self, spec: Any) -> None:
        return None

    def exec_module(self, module: Any) -> None:
        code = compile(self.files[self.path], f"<{self.label}>/{self.path}", "exec", dont_inherit=True)
        exec(code, module.__dict__)  # noqa: S102 - the user's own connector, uploaded by them

    def get_resource_reader(self, fullname: str) -> Any:
        return None


class _Finder(importlib.abc.MetaPathFinder):
    """Serves the modules of loaded bundles, ahead of anything installed, for their package names only."""

    def __init__(self) -> None:
        self.bundles: dict[str, tuple[dict[str, str], str]] = {}       # top-level name -> (files, label)

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        owner = self.bundles.get(fullname.split(".", 1)[0])
        if owner is None:
            return None
        files, label = owner
        found = _module_path(files, fullname)
        if found is None:
            return None
        rel, is_pkg = found
        spec = importlib.machinery.ModuleSpec(fullname, _Loader(files, rel, label), is_package=is_pkg)
        if is_pkg:
            spec.submodule_search_locations = []
        return spec


_finder = _Finder()
_lock = threading.Lock()


def load_bundle(bundle: dict[str, Any], label: str) -> type[Connector]:
    """Import a bundle's connector class from memory. Loading a newer version of the same connector
    replaces the old modules (objects already made from the old version keep working until closed)."""
    validate_bundle(bundle)
    tops = top_levels(bundle)
    with _lock:
        for top in tops:
            other = _finder.bundles.get(top)
            if other is not None and other[1].split("@", 1)[0] != label.split("@", 1)[0]:
                raise BundleError(f"another connector already provides the package {top!r}")
            if other is None and top in sys.modules:
                raise BundleError(f"the package {top!r} is already installed here; uninstall it or rename it")
        if _finder not in sys.meta_path:
            sys.meta_path.insert(0, _finder)
        for top in tops:
            for mod in [m for m in sys.modules if m == top or m.startswith(top + ".")]:
                del sys.modules[mod]
            _finder.bundles[top] = (bundle["files"], label)
        mod_name, _, cls_name = bundle["entry"].partition(":")
        try:
            cls = getattr(importlib.import_module(mod_name), cls_name)
        except Exception as e:  # noqa: BLE001 - report, don't crash sw-mcp
            for top in tops:
                _finder.bundles.pop(top, None)
            raise BundleError(f"the connector's code failed to load ({type(e).__name__}: {e})") from None
    if not (isinstance(cls, type) and issubclass(cls, Connector)) or cls.name != bundle["name"]:
        raise BundleError(f"{bundle['entry']} is not the connector {bundle['name']!r}")
    return cls


def unload_bundle(bundle: dict[str, Any]) -> None:
    with _lock:
        for top in top_levels(bundle):
            _finder.bundles.pop(top, None)
            for mod in [m for m in sys.modules if m == top or m.startswith(top + ".")]:
                del sys.modules[mod]
