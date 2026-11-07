"""Testing helpers for connectors: a stand-in for the SecurityWarden server, so a connector's tests run
without a server, a token or a network.

    from securitywarden.mcp.testing import FakeSecurityWarden, make_hub

    def test_delete_asks_first():
        sw = FakeSecurityWarden(secrets={"NOTES_API_KEY": "k"})
        hub = make_hub(Notes, sw)
        r = hub.call("notes_delete", {"id": "n1"})
        assert r.data["status"] == "waiting_for_approval"
        sw.approve(r.data["request_id"])
        assert not hub.call("check_approval", {"request_id": r.data["request_id"]}).is_error

The fake decides like the server: an action whose rule is "allow" (and whose risk isn't high) runs at once,
"deny" is refused, anything else waits for ``approve``/``deny``. It records every request, so tests can check
the summary a person would see and the exact arguments that were approved.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..client.api import ApprovalError, TokenRejected
from .. import crypto
from ..crypto import action_digest
from .framework import Connector, Hub


class FakeSecurityWarden:
    """Rules: action name (or ``prefix.*`` / ``*``) -> "allow" | "ask" | "deny". Unlisted actions ask."""

    def __init__(self, rules: Mapping[str, str] | None = None, *, secrets: Mapping[str, str] | None = None,
                 pins: bool = False):
        self.pins_on = pins                     # approval proxies: pin their tools (as current servers do)
        self.pins: dict[str, list[str]] = {}
        self.rules = dict(rules or {})
        self.secrets = dict(secrets or {})
        self.requests: dict[str, dict[str, Any]] = {}
        self.revoked = False
        self.fetches = 0
        self._n = 0
        # connectors turned on for the token's project (see publish())
        self.builtin: list[str] = []
        self.actions: dict[str, Any] | None = None      # the token's action rules as the server sends them
        self.custom: dict[str, dict[str, Any]] = {}
        self._pid, self._pkey = crypto.new_id(), crypto.new_key()

    # what a test calls

    def approve(self, request_id: str) -> None:
        self.requests[request_id]["state"] = "approved"

    def deny(self, request_id: str, comment: str | None = None) -> None:
        """Deny it; with ``comment``, as "deny with comment" does (the agent may change it and ask again)."""
        self.requests[request_id]["state"] = "denied"
        self.requests[request_id]["comment"] = comment

    def last(self) -> dict[str, Any]:
        """The most recent request: action, args, risk, summary, digest, state."""
        return list(self.requests.values())[-1]

    def publish(self, bundle: dict[str, Any], *, activation: str = "now", connector_id: str | None = None,
                version: int | None = None) -> str:
        """Store a connector bundle as the website would (encrypted, next version) and turn it on."""
        from .bundle import summary
        cid = connector_id or crypto.new_id()
        cur = self.custom.get(cid)
        ckey = cur["key"] if cur else crypto.new_connector_key()
        ver = version if version is not None else (cur["version"] + 1 if cur else 1)
        meta = dict(summary(bundle), activation=activation)
        blob, mblob = crypto.encrypt_connector(ckey, cid, ver, bundle, meta)
        self.custom[cid] = {"key": ckey, "version": ver, "blob": blob, "meta": mblob,
                            "wrapped_key": crypto.wrap_connector_key_for_project(ckey, self._pkey, self._pid, cid)}
        return cid

    # what the framework calls (the SecurityWardenClient interface)

    def connectors(self) -> dict[str, Any]:
        self._alive()
        return {"actions": self.actions, "builtin": list(self.builtin),
                "custom": [{"id": cid, "version": c["version"], "wrapped_key": c["wrapped_key"], "meta": c["meta"]}
                           for cid, c in self.custom.items()]}

    def _ckey(self, entry: dict[str, Any]) -> bytes:
        return crypto.unwrap_connector_key_for_project(entry["wrapped_key"], self._pkey, self._pid, entry["id"])

    def connector_meta(self, entry: dict[str, Any]) -> dict[str, Any]:
        return crypto.decrypt_connector_meta(self._ckey(entry), entry["id"], entry["version"], entry["meta"])

    def connector_bundle(self, entry: dict[str, Any]) -> dict[str, Any]:
        self._alive()
        c = self.custom[entry["id"]]
        return crypto.decrypt_connector_bundle(self._ckey(entry), entry["id"], entry["version"], c["blob"])

    def _rule(self, action: str) -> str:
        if action in self.rules:
            return self.rules[action]
        best = ""
        for pattern in self.rules:
            if pattern == "*" or (pattern.endswith(".*") and action.startswith(pattern[:-1])):
                if len(pattern) > len(best):
                    best = pattern
        return self.rules[best] if best else "ask"

    def _alive(self) -> None:
        if self.revoked:
            raise TokenRejected("authentication failed (401): invalid credential (the token was revoked)")

    def check_token(self) -> None:
        self._alive()

    def fetch(self) -> dict[str, str]:
        self._alive()
        self.fetches += 1
        return dict(self.secrets)

    def request_action(self, action: str, args: Any, summary: dict[str, Any], *, risk: str = "high",
                       scope: dict[str, str] | None = None) -> dict[str, Any]:
        self._alive()
        self.last_scope = scope
        rule = self._rule(action)
        if rule == "deny":
            raise ApprovalError("action_denied")
        self._n += 1
        rid = f"req{self._n}"
        allowed = rule == "allow" and risk != "high"
        self.requests[rid] = {"action": action, "args": args, "risk": risk, "summary": summary,
                              "digest": action_digest(action, args), "nonce": f"n{self._n}",
                              "state": "used" if allowed else "pending"}
        return {"status": "approved" if allowed else "pending", "request_id": rid, "nonce": f"n{self._n}",
                "digest": self.requests[rid]["digest"], "match": "42", "expires_in": 3600, "check_after": 5}

    def proxy_pins(self, name: str) -> list[str] | None:
        from ..client.api import SecurityWardenError
        if not self.pins_on:
            raise SecurityWardenError("unsupported")
        return self.pins.get(name)

    def store_proxy_pins(self, name: str, request_id: str, nonce: str, fingerprints: list[str]) -> str:
        r = self.requests[request_id]
        if r["action"] != f"{name}.tools.approve" or r["digest"] != action_digest(r["action"], {"fingerprints": fingerprints}):
            raise ApprovalError("action_mismatch")
        if self.check_action(request_id, nonce, r["digest"]) == "pending":
            return "pending"
        self.pins[name] = list(fingerprints)
        return "stored"

    def check_action(self, request_id: str, nonce: str, digest: str) -> str:
        self._alive()
        r = self.requests[request_id]
        if r["nonce"] != nonce or r["digest"] != digest:
            raise ApprovalError("action_mismatch")
        if r["state"] == "pending":
            return "pending"
        if r["state"] == "denied":
            raise ApprovalError("approval_denied", r.get("comment"))
        if r["state"] == "used":
            raise ApprovalError("approval_used")
        r["state"] = "used"
        return "approved"


def make_hub(connectors: type[Connector] | Sequence[type[Connector]], sw: FakeSecurityWarden | None = None) -> Hub:
    """A Hub with the fake server, logging nowhere. Pass several connector classes to test them together."""
    classes = [connectors] if isinstance(connectors, type) else list(connectors)
    return Hub(sw or FakeSecurityWarden(), classes, log=lambda m: None)
