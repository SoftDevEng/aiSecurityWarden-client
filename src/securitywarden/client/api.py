"""Python client. All encryption and decryption happens here, never on the server."""

from __future__ import annotations

import os
import time
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from .. import crypto
from ..crypto import Credential, CryptoError
from ..approval import ACTION_RE, RISKS, normalize_action_policy, normalize_action_summary, normalize_policy
from ..ipallow import normalize_allowed_ips


class SecurityWardenError(Exception):
    pass


class ApprovalError(SecurityWardenError):
    """A human approval was denied, expired, cancelled or could not be redeemed."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(_APPROVAL_TEXT.get(reason, f"approval failed: {reason}"))


_APPROVAL_TEXT = {
    "approval_denied": "the approval request was denied",
    "approval_expired": "the approval request expired before anyone approved it",
    "approval_cancelled": "the approval request was cancelled (token revoked or its policy changed)",
    "approval_used": "the approval was already used",
    "approval_mismatch": "the approval belongs to a different process or address",
    "action_denied": "this token's policy does not allow that action",
    "action_mismatch": "the approval was for a different action",
}

ApprovalCallback = Callable[[dict[str, Any]], None]


_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _check_url(url: str) -> str:
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise SecurityWardenError(f"invalid server URL: {url!r}")
    if u.scheme == "http" and u.hostname not in _LOCAL_HOSTS and os.environ.get("SW_ALLOW_HTTP") != "1":
        raise SecurityWardenError("refusing plain http to a non-local server (set SW_ALLOW_HTTP=1 to override)")
    return url.rstrip("/")


class SecurityWardenClient:
    def __init__(self, server_url: str, credential: str | Credential, *,
                 http: httpx.Client | None = None, timeout: float = 15.0, verify: bool | str = True,
                 on_approval: ApprovalCallback | None = None, sleep: Callable[[float], None] = time.sleep):
        """``on_approval`` is called once when the server asks for a human approval, with
        ``{"approval_id", "match", "expires_in", "kind"}``; show the match code to the operator.
        The client then waits (up to the server's timeout) for the decision."""
        self.cred = credential if isinstance(credential, Credential) else crypto.parse_credential(credential)
        if http is None:
            self.base = _check_url(server_url)
            http = httpx.Client(timeout=timeout, verify=verify)
        else:
            self.base = server_url.rstrip("/")
        self.http = http
        self._token: str | None = None
        self._token_exp = 0.0
        self.on_approval = on_approval
        self._sleep = sleep
        self._action_cfg: dict[str, Any] | None = None

    # -- transport --------------------------------------------------------------

    def _authenticate(self) -> None:
        proof = {"id": self.cred.id, "secret": self.cred.secret, "nonce": crypto.new_nonce()}
        r = self.http.post(f"{self.base}/v1/auth", json=proof)
        if r.status_code == 202:  # a person has to approve this session first
            r = self._await_approval(r.json(), "auth",
                                     lambda aid: self.http.post(f"{self.base}/v1/auth/approvals/{aid}", json=proof))
        if r.status_code != 200:
            raise SecurityWardenError(f"authentication failed ({r.status_code}): {_detail(r)}")
        data = r.json()
        self._token = data["access_token"]
        self._token_exp = time.monotonic() + max(0, int(data.get("expires_in", 60)) - 10)

    def _req(self, method: str, path: str, *, headers: dict[str, str] | None = None,
             accept_403: bool = False, **kw: Any) -> httpx.Response:
        for attempt in (1, 2):
            if not self._token or time.monotonic() >= self._token_exp:
                self._authenticate()
            r = self.http.request(method, f"{self.base}{path}",
                                  headers={**(headers or {}), "Authorization": f"Bearer {self._token}"}, **kw)
            if r.status_code == 401 and attempt == 1:
                self._token = None
                continue
            if accept_403 and r.status_code == 403:
                return r
            if r.status_code >= 400:
                raise SecurityWardenError(f"{method} {path} failed ({r.status_code}): {_detail(r)}")
            return r
        raise SecurityWardenError("unreachable")

    def _await_approval(self, info: dict[str, Any], kind: str,
                        poll: Callable[[str], httpx.Response]) -> httpx.Response:
        """Wait for a person to decide. Returns the final 200 response or raises ApprovalError."""
        aid = info["approval_id"]
        if self.on_approval:
            self.on_approval({"approval_id": aid, "match": info["match"], "expires_in": info["expires_in"],
                              "kind": kind})
        deadline = time.monotonic() + float(info["expires_in"]) + 5
        interval = max(0.0, min(float(info.get("poll_interval", 2)), 10.0))
        while True:
            self._sleep(interval)
            r = poll(aid)
            if r.status_code != 202:
                break
            if time.monotonic() > deadline:
                raise ApprovalError("approval_expired")
        if r.status_code == 403 and _detail(r).startswith("approval_"):
            raise ApprovalError(_detail(r))
        return r

    # -- machine ----------------------------------------------------------------

    def fetch(self) -> dict[str, str]:
        """Fetch and decrypt every secret visible to this machine token."""
        if self.cred.kind != crypto.KIND_MACHINE:
            raise SecurityWardenError("fetch() needs a machine token")
        nonce = crypto.new_nonce()
        r = self._req("GET", "/v1/secrets", headers={"X-SW-Nonce": nonce})
        if r.status_code == 202:  # this token needs an approval for every fetch
            r = self._await_approval(r.json(), "fetch", lambda aid: self._req(
                "POST", f"/v1/secrets/approvals/{aid}", json={"nonce": nonce}, accept_403=True))
            if r.status_code != 200:
                raise SecurityWardenError(f"fetch failed ({r.status_code}): {_detail(r)}")
        data = r.json()
        pid = data["project_id"]
        pkey = crypto.unwrap_project_key_for_token(data["wrapped_key"], self.cred, pid)
        out: dict[str, str] = {}
        for s in data["secrets"]:
            name, value = crypto.decrypt_secret(pkey, pid, s["mac"], s["blob"])
            out[name] = value
        return out

    # -- machine: action approval (see DESIGN.md "Action approval") ------------------

    def action_config(self) -> dict[str, Any]:
        """{"project_id", "wrapped_key", "summaries": "plain"|"encrypted"} for this token's project.
        Cached: it only changes when the project's settings change."""
        if self.cred.kind != crypto.KIND_MACHINE:
            raise SecurityWardenError("actions need a machine token")
        if self._action_cfg is None:
            cfg = self._req("GET", "/v1/actions/config").json()
            cfg["project_key"] = crypto.unwrap_project_key_for_token(cfg["wrapped_key"], self.cred, cfg["project_id"])
            self._action_cfg = cfg
        return self._action_cfg

    def request_action(self, action: str, args: Any, summary: dict[str, Any], *, risk: str = "high") -> dict[str, Any]:
        """Ask whether this token may perform ``action`` with exactly ``args`` now.

        Returns ``{"status": "approved" | "pending", "request_id", "nonce", "digest", "match",
        "expires_in", "check_after"}``. "approved": go ahead now (allowed by policy, or inside an approved
        time window); the approval is already used up. "pending": a person has been asked; keep
        ``request_id``, ``nonce`` and ``digest`` and call :meth:`check_action` later. Raises
        :class:`ApprovalError` ("action_denied") when the policy forbids the action."""
        if not ACTION_RE.match(action or ""):
            raise SecurityWardenError("invalid action name (e.g. gmail.send)")
        if risk not in RISKS:
            raise SecurityWardenError(f"risk must be one of: {', '.join(RISKS)}")
        try:
            summary = normalize_action_summary(summary)
        except ValueError as e:
            raise SecurityWardenError(str(e)) from None
        cfg = self.action_config()
        rid, nonce = crypto.new_id(), crypto.new_nonce()
        digest = crypto.action_digest(action, args)
        body: dict[str, Any] = {"id": rid, "action": action, "risk": risk, "digest": digest, "nonce": nonce,
                                "summary_enc": crypto.encrypt_action_summary(cfg["project_key"], cfg["project_id"],
                                                                             rid, summary)}
        if cfg.get("summaries") != "encrypted":
            body["summary"] = summary
        r = self._req("POST", "/v1/actions", json=body, accept_403=True)
        if r.status_code == 403:
            raise ApprovalError(_detail(r) if _detail(r).startswith("action_") else "action_denied")
        data = r.json()
        return {"status": data["status"], "request_id": rid, "nonce": nonce, "digest": digest,
                "match": data.get("match"), "expires_in": data.get("expires_in"),
                "check_after": data.get("check_after", 30)}

    def check_action(self, request_id: str, nonce: str, digest: str) -> str:
        """"approved" (and used up: perform the action now, once) or "pending". Raises
        :class:`ApprovalError` when it was denied, expired, cancelled or already used."""
        r = self._req("POST", f"/v1/actions/{request_id}", json={"nonce": nonce, "digest": digest}, accept_403=True)
        if r.status_code == 202:
            return "pending"
        if r.status_code == 403:
            reason = _detail(r)
            raise ApprovalError(reason if reason.startswith(("approval_", "action_")) else "approval_denied")
        return "approved"

    # -- admin: projects ----------------------------------------------------------

    def _require_admin(self) -> None:
        if self.cred.kind != crypto.KIND_ADMIN:
            raise SecurityWardenError("this operation needs the admin credential")

    def list_projects(self) -> list[dict[str, Any]]:
        self._require_admin()
        return self._req("GET", "/v1/admin/projects").json()

    def _project(self, ref: str) -> dict[str, Any]:
        for p in self.list_projects():
            if ref in (p["id"], p["name"]):
                return p
        raise SecurityWardenError(f"project not found: {ref}")

    def _project_key(self, proj: dict[str, Any]) -> bytes:
        return crypto.unwrap_project_key_for_admin(proj["wrapped_key"], self.cred, proj["id"])

    def create_project(self, name: str) -> str:
        self._require_admin()
        pid, pkey = crypto.new_id(), crypto.new_key()
        wk = crypto.wrap_project_key_for_admin(pkey, self.cred, pid)
        self._req("POST", "/v1/admin/projects", json={"id": pid, "name": name, "wrapped_key": wk})
        return pid

    def delete_project(self, ref: str) -> None:
        self._req("DELETE", f"/v1/admin/projects/{self._project(ref)['id']}")

    # -- admin: secrets -----------------------------------------------------------

    def set_secret(self, project: str, name: str, value: str) -> None:
        # e.g. Ctrl+V at a hidden console prompt on Windows arrives as the single character \x16
        if any((ord(ch) < 32 and ch not in "\t\n\r") or ord(ch) == 127 for ch in value):
            raise SecurityWardenError("the value contains an invisible control character (a paste that did not "
                                      "work?); nothing was stored")
        proj = self._project(project)
        mac, blob = crypto.encrypt_secret(self._project_key(proj), proj["id"], name, value)
        self._req("PUT", f"/v1/admin/projects/{proj['id']}/secrets/{mac}", json={"blob": blob})

    def get_secrets(self, project: str) -> dict[str, str]:
        proj = self._project(project)
        pkey = self._project_key(proj)
        rows = self._req("GET", f"/v1/admin/projects/{proj['id']}/secrets").json()
        return dict(crypto.decrypt_secret(pkey, proj["id"], r["mac"], r["blob"]) for r in rows)

    def delete_secret(self, project: str, name: str) -> None:
        proj = self._project(project)
        mac = crypto.name_mac(self._project_key(proj), name)
        self._req("DELETE", f"/v1/admin/projects/{proj['id']}/secrets/{mac}")

    # -- admin: tokens ------------------------------------------------------------

    def create_token(self, project: str, name: str, expires_days: float | None = None,
                     allowed_ips: list[str] | None = None, approval: dict[str, Any] | None = None,
                     actions: dict[str, Any] | None = None) -> Credential:
        ips = _normalize_ips(allowed_ips)
        policy = _normalize_policy(approval)
        action_policy = _normalize_actions(actions)
        proj = self._project(project)
        tok = crypto.new_credential(crypto.KIND_MACHINE)
        wk = crypto.wrap_project_key_for_token(self._project_key(proj), tok, proj["id"])
        expires_at = int(time.time() + expires_days * 86400) if expires_days else None
        body = {"id": tok.id, "name": name, "secret": tok.secret, "project_id": proj["id"],
                "wrapped_key": wk, "expires_at": expires_at}
        if ips:
            body["allowed_ips"] = ips
        if policy:
            body["approval"] = policy
        if action_policy:
            body["actions"] = action_policy
        r = self._req("POST", "/v1/admin/tokens", json=body)
        if ips and r.json().get("allowed_ips") != ips:
            # a pre-0.2 server ignores the field; never hand back a token that is silently unrestricted
            self.revoke_token(tok.id)
            raise SecurityWardenError("server did not apply the address restriction (upgrade the server); "
                                      "the token was revoked")
        if policy and r.json().get("approval") != policy:
            # same for a pre-0.4 server and the approval policy
            self.revoke_token(tok.id)
            raise SecurityWardenError("server did not apply the approval policy (upgrade the server to 0.4.0); "
                                      "the token was revoked")
        if action_policy and r.json().get("actions") != action_policy:
            self.revoke_token(tok.id)
            raise SecurityWardenError("server did not apply the action policy (upgrade the server to 0.6.0); "
                                      "the token was revoked")
        return tok

    def set_token_actions(self, token_id: str, actions: dict[str, Any] | None) -> dict[str, Any] | None:
        """Set, change or (with None) reset to the defaults a token's action policy: which actions its
        agent may take, and how a person approves them. Pending action requests and open approval
        windows for the token end."""
        self._require_admin()
        policy = _normalize_actions(actions)
        self._req("PUT", f"/v1/admin/tokens/{token_id}/actions", json={"actions": policy})
        return policy

    def set_token_approval(self, token_id: str, approval: dict[str, Any] | None) -> dict[str, Any] | None:
        """Set, change or (with None) remove a token's approval policy. Pending requests and
        approved sessions for the token are cancelled."""
        self._require_admin()
        policy = _normalize_policy(approval)
        self._req("PUT", f"/v1/admin/tokens/{token_id}/approval", json={"approval": policy})
        return policy

    def reset_approval_limits(self, token_id: str) -> int:
        """Restart a token's hourly approval window and cancel its pending requests.
        Returns how many pending requests were cancelled."""
        self._require_admin()
        return self._req("POST", f"/v1/admin/tokens/{token_id}/approval/reset").json()["cancelled"]

    def list_approvals(self) -> list[dict[str, Any]]:
        """Pending approval requests (all tokens)."""
        self._require_admin()
        return self._req("GET", "/v1/admin/approvals").json()

    def action_summary(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """The summary of a pending action request, decrypted here when its project keeps summaries
        encrypted. None if there is none or it can't be decrypted."""
        if request.get("summary"):
            return request["summary"]
        if not (request.get("summary_enc") and request.get("project_id")):
            return None
        try:
            proj = next(p for p in self.list_projects() if p["id"] == request["project_id"])
            # written by the agent's side: show it only if it has the expected shape
            return normalize_action_summary(crypto.decrypt_action_summary(
                self._project_key(proj), proj["id"], request["id"], request["summary_enc"]))
        except (StopIteration, CryptoError, KeyError, ValueError):
            return None

    def decide_approval(self, approval_id: str, approve: bool) -> str:
        self._require_admin()
        r = self._req("POST", f"/v1/admin/approvals/{approval_id}/decision",
                      json={"decision": "approve" if approve else "deny"})
        return r.json()["status"]

    def set_token_ips(self, token_id: str, allowed_ips: list[str] | None) -> list[str] | None:
        self._require_admin()
        ips = _normalize_ips(allowed_ips)
        self._req("PUT", f"/v1/admin/tokens/{token_id}/allowed-ips", json={"allowed_ips": ips})
        return ips

    def list_tokens(self, project: str | None = None) -> list[dict[str, Any]]:
        self._require_admin()
        params = {"project_id": self._project(project)["id"]} if project else None
        return self._req("GET", "/v1/admin/tokens", params=params).json()

    def revoke_token(self, token_id: str) -> None:
        self._require_admin()
        self._req("DELETE", f"/v1/admin/tokens/{token_id}")

    def audit(self, limit: int = 100) -> list[dict[str, Any]]:
        self._require_admin()
        return self._req("GET", "/v1/admin/audit", params={"limit": limit}).json()


def action_lines(action: str, summary: dict[str, Any] | None) -> str:
    """A pending action as plain text lines, for terminals and dialogs."""
    if not summary:
        return f"{action} (no readable summary)"
    head = f"{summary['title']} ({action})" + (f", {summary['count']} items" if summary.get("count", 1) > 1 else "")
    lines = [head] + [f"{k}: {v}" for k, v in summary.get("fields", [])]
    if summary.get("preview"):
        lines.append(f"“{summary['preview']}”")
    return "\n".join(lines)


def _normalize_actions(actions: dict[str, Any] | None) -> dict[str, Any] | None:
    try:
        return normalize_action_policy(actions)
    except ValueError as e:
        raise SecurityWardenError(f"invalid action policy: {e}") from None


def _normalize_ips(allowed_ips: list[str] | None) -> list[str] | None:
    if allowed_ips is None:
        return None
    try:
        return normalize_allowed_ips(allowed_ips)
    except ValueError as e:
        raise SecurityWardenError(str(e)) from None


def _normalize_policy(approval: dict[str, Any] | None) -> dict[str, Any] | None:
    try:
        return normalize_policy(approval)
    except ValueError as e:
        raise SecurityWardenError(str(e)) from None


def _detail(r: httpx.Response) -> str:
    try:
        d = r.json().get("detail")
        return d if isinstance(d, str) else str(d)
    except Exception:
        return r.text[:200]


__all__ = ["SecurityWardenClient", "SecurityWardenError", "ApprovalError", "CryptoError"]
