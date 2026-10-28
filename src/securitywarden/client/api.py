"""Python client. All encryption and decryption happens here, never on the server."""

from __future__ import annotations

import os
import time
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from .. import crypto
from ..crypto import Credential, CryptoError
from ..approval import normalize_policy
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
                     allowed_ips: list[str] | None = None, approval: dict[str, Any] | None = None) -> Credential:
        ips = _normalize_ips(allowed_ips)
        policy = _normalize_policy(approval)
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
        return tok

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
