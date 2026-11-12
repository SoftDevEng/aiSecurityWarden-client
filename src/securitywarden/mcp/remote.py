"""Connectors turned on for the token's project in aiSecurityWarden: built-in ones (shipped with this client)
and custom ones (uploaded by the account, stored encrypted, loaded from memory).

A custom connector's new version is loaded by a running ``sw-mcp`` when it was uploaded with "go live now";
"on next restart" versions wait until ``sw-mcp`` starts again. Each machine remembers the highest version it
has loaded of every connector and refuses a lower one, so the server can't roll a connector back.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from typing import Any, Callable

from ..client.api import SecurityWardenError
from .bundle import BundleError, load_bundle, unload_bundle
from .framework import Connector
from .proxy import FORMAT as PROXY_FORMAT, proxy_class

LogFn = Callable[[str], None]


@dataclass
class _Loaded:
    version: int
    cls: type[Connector]
    bundle: dict[str, Any]


def default_state_path(token_file: str | None) -> str:
    if token_file:
        return os.path.expanduser(token_file) + ".connectors.json"
    return os.path.join(os.path.expanduser("~"), ".config", "securitywarden", "connector-versions.json")


class RemoteConnectors:
    def __init__(self, builtin: dict[str, Callable[[], type[Connector]]], state_path: str | Callable[[], str]) -> None:
        self.builtin = builtin                  # name -> loader, for the connectors this client ships
        self._state_path = state_path
        self.loaded: dict[str, _Loaded] = {}
        self.started = False
        self.policy: dict[str, Any] | None = None     # the token's action rules (to hide denied tools)
        self._told: set[tuple[str, int, str]] = set()
        self._state: dict[str, int] | None = None

    @property
    def state_path(self) -> str:
        return self._state_path() if callable(self._state_path) else self._state_path

    # -- highest version seen, per connector (rollback protection) --------------------------------

    def _seen(self) -> dict[str, int]:
        if self._state is None:
            try:
                with open(self.state_path, encoding="utf-8") as f:
                    data = json.load(f)
                self._state = {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, int)}
            except (OSError, ValueError, AttributeError):
                self._state = {}
        return self._state

    def _remember(self, cid: str, version: int) -> None:
        seen = self._seen()
        if seen.get(cid, 0) >= version:
            return
        seen[cid] = version
        folder = os.path.dirname(self.state_path) or "."
        os.makedirs(folder, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=folder, prefix=".sw-connectors-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(seen, f)
            os.replace(tmp, self.state_path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _tell(self, log: LogFn, cid: str, version: int, what: str, msg: str) -> None:
        if (cid, version, what) not in self._told:
            self._told.add((cid, version, what))
            log(msg)

    # -- what to run ------------------------------------------------------------------------------

    def classes(self, client: Any, log: LogFn) -> list[type[Connector]]:
        try:
            listing = client.connectors()
        except SecurityWardenError as e:
            if "(404)" not in str(e):
                raise
            self._tell(log, "", 0, "old-server", "this aiSecurityWarden server doesn't offer connectors yet; using only "
                       "the connectors named in the MCP settings")
            return []
        self.policy = listing.get("actions") if isinstance(listing.get("actions"), dict) else None
        startup = not self.started
        out: list[type[Connector]] = []
        for name in listing.get("builtin") or []:
            make = self.builtin.get(name)
            if make is None:
                self._tell(log, name, 0, "unknown", f"the project uses the built-in connector {name!r}, which this "
                           "client doesn't have yet: update the aiSecurityWarden client")
                continue
            try:
                out.append(make())
            except Exception as e:  # noqa: BLE001
                self._tell(log, name, 0, "broken", f"built-in connector {name} not loaded: {type(e).__name__}")
        keep: dict[str, _Loaded] = {}
        for entry in listing.get("custom") or []:
            cid, version = entry.get("id"), entry.get("version")
            if not isinstance(cid, str) or not isinstance(version, int):
                continue
            cur = self.loaded.get(cid)
            if cur is not None and cur.version == version:
                keep[cid] = cur
                continue
            if version < self._seen().get(cid, 0):
                self._tell(log, cid, version, "rollback", f"refused connector {cid} version {version}: this machine "
                           f"already ran version {self._seen()[cid]} (an older version is never loaded)")
                if cur is not None:
                    keep[cid] = cur
                continue
            try:
                meta = client.connector_meta(entry)
                if cur is not None and not startup and meta.get("activation") != "now":
                    self._tell(log, cid, version, "restart", f"connector {meta.get('name')} version {version} is "
                               "ready and goes live when sw-mcp restarts")
                    keep[cid] = cur
                    continue
                bundle = client.connector_bundle(entry)
                if bundle.get("name") != meta.get("name"):
                    raise BundleError("the code and its description name different connectors")
                if bundle.get("format") == PROXY_FORMAT:     # an approval proxy's mapping file: no code to import
                    cls = proxy_class(bundle)
                else:
                    cls = load_bundle(bundle, f"{cid}@{version}")
                self._remember(cid, version)
            except Exception as e:  # noqa: BLE001 - one bad connector must not stop the others
                self._tell(log, cid, version, "failed", f"connector {cid} version {version} not loaded: "
                           f"{str(e).splitlines()[0][:200] if str(e) else type(e).__name__}")
                if cur is not None:
                    keep[cid] = cur
                continue
            log(f"loaded connector {cls.name} version {version}" + ("" if cur is None else f" (was {cur.version})"))
            keep[cid] = _Loaded(version, cls, bundle)
        for cid, old in self.loaded.items():
            if cid not in keep:
                if old.bundle.get("format") != PROXY_FORMAT:
                    unload_bundle(old.bundle)
                log(f"connector {old.cls.name} was turned off for this project")
        self.loaded = keep
        self.started = True
        return out + [x.cls for x in keep.values()]
