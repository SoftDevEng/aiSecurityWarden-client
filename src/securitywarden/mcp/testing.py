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
from ..crypto import action_digest
from .framework import Connector, Hub


class FakeSecurityWarden:
    """Rules: action name (or ``prefix.*`` / ``*``) -> "allow" | "ask" | "deny". Unlisted actions ask."""

    def __init__(self, rules: Mapping[str, str] | None = None, *, secrets: Mapping[str, str] | None = None):
        self.rules = dict(rules or {})
        self.secrets = dict(secrets or {})
        self.requests: dict[str, dict[str, Any]] = {}
        self.revoked = False
        self.fetches = 0
        self._n = 0

    # what a test calls

    def approve(self, request_id: str) -> None:
        self.requests[request_id]["state"] = "approved"

    def deny(self, request_id: str) -> None:
        self.requests[request_id]["state"] = "denied"

    def last(self) -> dict[str, Any]:
        """The most recent request: action, args, risk, summary, digest, state."""
        return list(self.requests.values())[-1]

    # what the framework calls (the SecurityWardenClient interface)

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

    def request_action(self, action: str, args: Any, summary: dict[str, Any], *, risk: str = "high") -> dict[str, Any]:
        self._alive()
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

    def check_action(self, request_id: str, nonce: str, digest: str) -> str:
        self._alive()
        r = self.requests[request_id]
        if r["nonce"] != nonce or r["digest"] != digest:
            raise ApprovalError("action_mismatch")
        if r["state"] == "pending":
            return "pending"
        if r["state"] == "denied":
            raise ApprovalError("approval_denied")
        if r["state"] == "used":
            raise ApprovalError("approval_used")
        r["state"] = "used"
        return "approved"


def make_hub(connectors: type[Connector] | Sequence[type[Connector]], sw: FakeSecurityWarden | None = None) -> Hub:
    """A Hub with the fake server, logging nowhere. Pass several connector classes to test them together."""
    classes = [connectors] if isinstance(connectors, type) else list(connectors)
    return Hub(sw or FakeSecurityWarden(), classes, log=lambda m: None)
