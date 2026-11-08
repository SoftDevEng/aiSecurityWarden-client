"""Python client. All encryption and decryption happens here, never on the server."""

from __future__ import annotations

import os
import time
from typing import Any, Callable, Protocol
from urllib.parse import urlparse

import httpx

from .. import crypto
from ..crypto import Credential, CryptoError
from ..approval import ACTION_RE, RISKS, normalize_action_policy, normalize_action_summary, normalize_policy
from ..ipallow import normalize_allowed_ips


class SecurityWardenError(Exception):
    pass


class ApprovalError(SecurityWardenError):
    """A human approval was denied, expired, cancelled or could not be redeemed. ``comment``: what the person
    who denied an action asked to change instead ("deny with comment"), if anything."""

    def __init__(self, reason: str, comment: str | None = None):
        self.reason = reason
        self.comment = comment
        super().__init__(_APPROVAL_TEXT.get(reason, f"approval failed: {reason}"))


class ApprovalPending(SecurityWardenError):
    """A person has to approve this token's session or fetch first (raised instead of waiting when the
    client was made with ``wait_for_approval=False``). Call the same method again later to continue."""

    def __init__(self, info: dict[str, Any], kind: str):
        self.approval_id: str = info["approval_id"]
        self.match: str | None = info.get("match")
        self.expires_in: int = int(info.get("expires_in") or 0)
        self.kind = kind
        super().__init__(f"waiting for a person to approve this {'session' if kind == 'auth' else 'fetch'} "
                         f"(match code {self.match})")


class TokenRejected(SecurityWardenError):
    """The server rejected the credential itself (HTTP 401 on sign-in): revoked, expired, deleted or wrong.
    Not raised for network trouble, rate limits, address lists or pending approvals."""


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

# Server answers (403 details) when the admin credential needs its second factor.
SECOND_FACTOR_REQUIRED = "second_factor_required"     # send a code (or a recovery code)
SECOND_FACTOR_SETUP = "second_factor_setup"           # set up an authenticator app first
CODE_ATTEMPTS = 3


class SecondFactor(Protocol):
    """How a client asks the person at the keyboard for their second factor (admin credential only).
    swctl prompts in the terminal, swadmin opens dialogs, tests compute codes."""

    def code(self, retry: bool) -> str:
        """The 6-digit code from the authenticator app, or a recovery code. ``retry``: the last one was wrong."""
        ...

    def setup(self, key_text: str, uri: str, retry: bool) -> str:
        """Show the new key (``key_text`` to type in, ``uri`` for a QR code) and return the first code."""
        ...

    def recovery_codes(self, codes: list[str]) -> None:
        """Show the new single-use recovery codes once, to be saved somewhere safe."""
        ...


class SecondFactorRequired(SecurityWardenError):
    """The admin credential needs a code from an authenticator app and this client has no way to ask."""


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
                 on_approval: ApprovalCallback | None = None, sleep: Callable[[float], None] = time.sleep,
                 wait_for_approval: bool = True, second_factor: SecondFactor | None = None,
                 mfa_session: str | None = None):
        """``second_factor`` asks for the authenticator code when an admin credential signs in (the server
        requires it unless its operator turned it off); one code starts a 2FA session that later sign-ins reuse
        until it ends (idle or maximum age), so the person isn't asked every few minutes.

        ``on_approval`` is called once when the server asks for a human approval, with
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
        # wait_for_approval=False (agents' tools): raise ApprovalPending at once and resume on the next call
        self.wait_for_approval = wait_for_approval
        self._pending_auth: tuple[dict[str, Any], dict[str, Any]] | None = None     # (info, proof)
        self._pending_fetch: tuple[dict[str, Any], str] | None = None              # (info, nonce)
        self.second_factor = second_factor
        self._mfa_session: str | None = mfa_session

    # -- transport --------------------------------------------------------------

    def _authenticate(self) -> None:
        if self._pending_auth:        # an earlier attempt is waiting for a person: check on it once
            info, proof = self._pending_auth
            r = self.http.post(f"{self.base}/v1/auth/approvals/{info['approval_id']}", json=proof)
            if r.status_code == 202:
                raise ApprovalPending(info, "auth")
            self._pending_auth = None
            if r.status_code == 403 and _detail(r).startswith("approval_"):
                raise ApprovalError(_detail(r))
            if r.status_code == 200:
                return self._take_session(r)
        proof = {"id": self.cred.id, "secret": self.cred.secret, "nonce": crypto.new_nonce()}
        if self._mfa_session:
            proof["mfa_session"] = self._mfa_session
        r = self.http.post(f"{self.base}/v1/auth", json=proof)
        if r.status_code == 403 and _detail(r) in (SECOND_FACTOR_REQUIRED, SECOND_FACTOR_SETUP):
            self._mfa_session = None
            r = self._second_factor(_detail(r), proof)
        if r.status_code == 202:  # a person has to approve this session first
            if not self.wait_for_approval:
                self._pending_auth = (r.json(), proof)
                self._announce(r.json(), "auth")
                raise ApprovalPending(r.json(), "auth")
            r = self._await_approval(r.json(), "auth",
                                     lambda aid: self.http.post(f"{self.base}/v1/auth/approvals/{aid}", json=proof))
        if r.status_code != 200:
            if r.status_code == 401:
                raise TokenRejected(f"authentication failed (401): {_detail(r)} (the token was revoked, expired or is wrong)")
            raise SecurityWardenError(f"authentication failed ({r.status_code}): {_detail(r)}")
        self._take_session(r)

    def _second_factor(self, need: str, proof: dict[str, Any]) -> httpx.Response:
        """Ask for the code (or set up the app) and sign in with it. Returns the sign-in response."""
        sf = self.second_factor
        if sf is None:
            raise SecondFactorRequired(
                "this admin credential needs a code from your authenticator app; sign in with swctl or swadmin"
                if need == SECOND_FACTOR_REQUIRED else
                "this admin credential needs two-factor sign-in set up first; sign in with swctl, swadmin or the website")
        base = {"id": proof["id"], "secret": proof["secret"]}
        if need == SECOND_FACTOR_SETUP:
            r = self.http.post(f"{self.base}/v1/auth/2fa/setup", json=base)
            if r.status_code != 200:
                raise SecurityWardenError(f"two-factor setup failed ({r.status_code}): {_detail(r)}")
            info = r.json()
            for attempt in range(CODE_ATTEMPTS):
                code = sf.setup(info["key"], info["uri"], attempt > 0)
                r = self.http.post(f"{self.base}/v1/auth/2fa/confirm", json={**base, "code": code})
                if r.status_code != 401:
                    break
            if r.status_code != 200:
                raise SecurityWardenError(f"two-factor setup failed ({r.status_code}): {_detail(r)}")
            sf.recovery_codes(r.json()["recovery_codes"])
        else:
            for attempt in range(CODE_ATTEMPTS):
                r = self.http.post(f"{self.base}/v1/auth", json={**proof, "code": sf.code(attempt > 0)})
                if r.status_code != 401 or _detail(r) != "wrong code":
                    break
            if r.status_code == 401 and _detail(r) == "wrong code":
                raise SecurityWardenError("sign-in failed: the code was wrong")
        if r.status_code == 200:
            self._mfa_session = r.json().get("mfa_session") or None
        return r

    @property
    def mfa_session(self) -> str | None:
        """The current 2FA session token (admin credential), e.g. for swctl to reuse in its next run.
        Useless without the credential itself."""
        return self._mfa_session

    def sign_out(self) -> None:
        """End the 2FA session (if any) on the server and forget the access token."""
        if self._mfa_session:
            try:
                self.http.post(f"{self.base}/v1/auth/2fa/signout", json={"mfa_session": self._mfa_session})
            except httpx.HTTPError:
                pass
        self._mfa_session = None
        self._token = None

    def check_token(self) -> None:
        """Sign in afresh. Raises TokenRejected if the server no longer accepts this credential
        (ApprovalPending if a person must approve the session: the token is alive)."""
        self._token = None
        self._authenticate()

    def _take_session(self, r: httpx.Response) -> None:
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
        self._announce(info, kind)
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

    def _announce(self, info: dict[str, Any], kind: str) -> None:
        if self.on_approval:
            self.on_approval({"approval_id": info["approval_id"], "match": info["match"],
                              "expires_in": info["expires_in"], "kind": kind})

    # -- machine ----------------------------------------------------------------

    def fetch(self) -> dict[str, str]:
        """Fetch and decrypt every secret visible to this machine token."""
        if self.cred.kind != crypto.KIND_MACHINE:
            raise SecurityWardenError("fetch() needs a machine token")
        r = None
        if self._pending_fetch:       # an earlier fetch is waiting for a person: check on it once
            info, nonce = self._pending_fetch
            r = self._req("POST", f"/v1/secrets/approvals/{info['approval_id']}", json={"nonce": nonce},
                          accept_403=True)
            if r.status_code == 202:
                raise ApprovalPending(info, "fetch")
            self._pending_fetch = None
            if r.status_code == 403:
                raise ApprovalError(_detail(r) if _detail(r).startswith("approval_") else "approval_denied")
            if r.status_code != 200:
                r = None              # gone (e.g. the server restarted): ask afresh
        if r is None:
            nonce = crypto.new_nonce()
            r = self._req("GET", "/v1/secrets", headers={"X-SW-Nonce": nonce})
        if r.status_code == 202 and not self.wait_for_approval:
            self._pending_fetch = (r.json(), nonce)
            self._announce(r.json(), "fetch")
            raise ApprovalPending(r.json(), "fetch")
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

    # -- machine: connectors stored in SecurityWarden (see DESIGN.md "Connector distribution") --

    def connectors(self) -> dict[str, Any]:
        """The connectors chosen for this token: {"builtin": [names], "custom": [{"id", "version",
        "wrapped_key", "meta"}], "actions": the token's action rules}. Custom entries are still encrypted; see :meth:`connector_meta` and :meth:`connector_bundle`."""
        if self.cred.kind != crypto.KIND_MACHINE:
            raise SecurityWardenError("connectors need a machine token")
        return self._req("GET", "/v1/connectors").json()

    def _connector_key(self, entry: dict[str, Any]) -> bytes:
        cfg = self.action_config()
        return crypto.unwrap_connector_key_for_project(entry["wrapped_key"], cfg["project_key"], cfg["project_id"],
                                                       entry["id"])

    def connector_meta(self, entry: dict[str, Any]) -> dict[str, Any]:
        """The decrypted description of one entry from :meth:`connectors` (name, activation, tools, ...)."""
        return crypto.decrypt_connector_meta(self._connector_key(entry), entry["id"], entry["version"], entry["meta"])

    def connector_bundle(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Download and decrypt the code of the version named in ``entry``. Raises SecurityWardenError if the
        server now has another version (call :meth:`connectors` again)."""
        r = self._req("GET", f"/v1/connectors/{entry['id']}", params={"version": entry["version"]}).json()
        if r.get("version") != entry["version"]:
            raise SecurityWardenError("the connector changed meanwhile; try again")
        return crypto.decrypt_connector_bundle(self._connector_key(entry), entry["id"], entry["version"], r["blob"])

    def proxy_pins(self, name: str) -> list[str] | None:
        """The tool fingerprints approved for this token's approval proxy ``name`` (None: none approved yet).
        Raises SecurityWardenError("unsupported") on servers without tool pinning."""
        if not self.action_config().get("pins"):
            raise SecurityWardenError("unsupported")
        return self._req("GET", f"/v1/proxy-pins/{name}").json().get("fingerprints")

    def store_proxy_pins(self, name: str, request_id: str, nonce: str, fingerprints: list[str]) -> str:
        """Replace the approved fingerprints, using an approved ``<name>.tools.approve`` request for exactly this
        list (the server checks its digest and uses it up). "stored" or "pending"; raises ApprovalError."""
        r = self._req("POST", f"/v1/proxy-pins/{name}", accept_403=True,
                      json={"request_id": request_id, "nonce": nonce, "fingerprints": fingerprints})
        if r.status_code == 202:
            return "pending"
        if r.status_code == 403:
            reason = _detail(r)
            raise ApprovalError(reason if reason.startswith(("approval_", "action_")) else "approval_denied",
                                self._denial_comment(r, request_id))
        return "stored"

    def notice(self, code: str, subject: str) -> None:
        """Put a warning about this machine in the activity log (fixed codes only, e.g. "proxy_same_user").
        Older servers don't have it: nothing happens."""
        r = self._req("POST", "/v1/notices", json={"code": code, "subject": subject}, accept_403=True) \
            if self.action_config().get("notices") else None
        if r is not None and r.status_code >= 400:
            raise SecurityWardenError(f"notice refused ({r.status_code})")

    def request_action(self, action: str, args: Any, summary: dict[str, Any], *, risk: str = "high",
                       scope: dict[str, str] | None = None) -> dict[str, Any]:
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
        if scope and cfg.get("scopes"):
            # rules by argument: keyed hashes only, so the server can match rules without learning the values
            body["scope"] = {k: crypto.scope_macs(cfg["project_key"], k, v) for k, v in sorted(scope.items())[:4]}
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
            reason = reason if reason.startswith(("approval_", "action_")) else "approval_denied"
            raise ApprovalError(reason, self._denial_comment(r, request_id) if reason == "approval_denied" else None)
        return "approved"

    def _denial_comment(self, r: httpx.Response, request_id: str) -> str | None:
        """The comment that came with a denial: encrypted under the project key (from the website), or plain
        (typed in Telegram or Discord, for projects whose phone messages show the details). A comment that
        doesn't decrypt or isn't valid text is dropped: the denial itself still stands."""
        try:
            body = r.json()
        except ValueError:
            return None
        if not isinstance(body, dict):
            return None
        try:
            if isinstance(body.get("comment_enc"), str):
                cfg = self.action_config()
                return crypto.decrypt_approval_comment(cfg["project_key"], cfg["project_id"], request_id,
                                                       body["comment_enc"])
            if isinstance(body.get("comment"), str):
                return crypto.normalize_approval_comment(body["comment"])
        except (CryptoError, ValueError, SecurityWardenError):
            return None
        return None

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

    def create_setup_code(self, token_id: str, credential: str | Credential, *, expires_in: int = 600) -> str:
        """A one-time setup code (SWS1-...) for a machine token you just created: the machine runs
        ``sw-mcp setup`` / ``swctl setup`` with it (or its AI agent calls the setup tool) and gets the token.
        The token is encrypted here under the code; the server never sees the code or the token."""
        self._require_admin()
        secret = crypto.new_setup_secret()
        sid, blob = crypto.encrypt_for_setup(secret, credential)
        self._req("POST", f"/v1/admin/tokens/{token_id}/setup-codes",
                  json={"id": sid, "blob": blob, "expires_in": expires_in})
        return crypto.format_setup_code(secret)

    def revoke_token(self, token_id: str) -> None:
        self._require_admin()
        self._req("DELETE", f"/v1/admin/tokens/{token_id}")

    # -- admin: connectors stored in SecurityWarden (the operator's own; accounts use the website) --

    def list_connectors(self) -> dict[str, Any]:
        """{"builtin": [...], "custom": [{..., "meta": decrypted}], "limits": {...}}."""
        self._require_admin()
        data = self._req("GET", "/v1/admin/connectors").json()
        for c in data["custom"]:
            ck = crypto.unwrap_connector_key_for_admin(c["wrapped_key"], self.cred, c["id"])
            c["meta"] = crypto.decrypt_connector_meta(ck, c["id"], c["version"], c["meta"])
        return data

    def _admin_ckey(self, cid: str) -> tuple[bytes, dict[str, Any]]:
        c = next((x for x in self._req("GET", "/v1/admin/connectors").json()["custom"] if x["id"] == cid), None)
        if c is None:
            raise SecurityWardenError(f"no connector {cid}")
        return crypto.unwrap_connector_key_for_admin(c["wrapped_key"], self.cred, cid), c

    def upload_connector(self, bundle: dict[str, Any], *, activation: str = "now",
                         connector_id: str | None = None) -> dict[str, Any]:
        """Store a packed connector (``sw-mcp pack``): a new one, or the next version of ``connector_id``.
        ``activation``: "now" (running agents switch at once) or "restart"."""
        from ..mcp.bundle import summary, validate_bundle
        self._require_admin()
        validate_bundle(bundle)
        meta = dict(summary(bundle), activation=activation)
        if connector_id is None:
            cid, ck = crypto.new_id(), crypto.new_connector_key()
            blob, mblob = crypto.encrypt_connector(ck, cid, 1, bundle, meta)
            self._req("POST", "/v1/admin/connectors", json={
                "id": cid, "blob": blob, "meta": mblob,
                "wrapped_key": crypto.wrap_connector_key_for_admin(ck, self.cred, cid)})
            return {"id": cid, "version": 1}
        ck, cur = self._admin_ckey(connector_id)
        old = crypto.decrypt_connector_meta(ck, connector_id, cur["version"], cur["meta"])
        if old.get("name") != bundle["name"]:
            raise SecurityWardenError(f"connector {connector_id} is {old.get('name')!r}, not {bundle['name']!r}")
        version = cur["version"] + 1
        blob, mblob = crypto.encrypt_connector(ck, connector_id, version, bundle, meta)
        self._req("PUT", f"/v1/admin/connectors/{connector_id}", json={"version": version, "blob": blob, "meta": mblob})
        return {"id": connector_id, "version": version}

    def download_connector(self, connector_id: str, *, previous: bool = False) -> dict[str, Any]:
        """The decrypted bundle of the current (or the replaced, backup) version."""
        ck, _cur = self._admin_ckey(connector_id)
        r = self._req("GET", f"/v1/admin/connectors/{connector_id}/download",
                      params={"which": "previous" if previous else "current"}).json()
        return crypto.decrypt_connector_bundle(ck, connector_id, r["version"], r["blob"])

    def set_token_connectors(self, token_id: str, connectors: list[str]) -> list[str]:
        """The connectors a token's agent gets (custom ids, or built-in names), from those on for its project."""
        self._require_admin()
        refs = [c if crypto.CONNECTOR_ID_RE.match(c) else f"builtin:{c}" for c in connectors]
        return self._req("PUT", f"/v1/admin/tokens/{token_id}/connectors", json={"connectors": refs}).json()["connectors"]

    def delete_connector(self, connector_id: str) -> None:
        self._require_admin()
        self._req("DELETE", f"/v1/admin/connectors/{connector_id}")

    def enable_connector(self, project: str, connector: str, enabled: bool = True) -> None:
        """Turn a connector on (or off) for a project: a custom connector's id, or a built-in's name."""
        proj = self._project(project)
        builtin = not crypto.CONNECTOR_ID_RE.match(connector)
        path = (f"/v1/admin/projects/{proj['id']}/builtin-connectors/{connector}" if builtin
                else f"/v1/admin/projects/{proj['id']}/connectors/{connector}")
        if not enabled:
            self._req("DELETE", path)
            return
        body = None
        if not builtin:
            ck, _cur = self._admin_ckey(connector)
            body = {"wrapped_key": crypto.wrap_connector_key_for_project(ck, self._project_key(proj), proj["id"],
                                                                         connector)}
        self._req("PUT", path, json=body)

    # -- admin: the operator's own second factor --------------------------------------

    def second_factor_status(self) -> dict[str, Any]:
        """{"enabled", "required", "recovery_codes_left"} for this admin credential."""
        self._require_admin()
        return self._req("GET", "/v1/admin/2fa").json()

    def new_recovery_codes(self, code: str) -> list[str]:
        """Replace the recovery codes (the old ones stop working). Needs a current authenticator code."""
        self._require_admin()
        return self._req("POST", "/v1/admin/2fa/recovery-codes", json={"code": code}).json()["recovery_codes"]

    def audit(self, limit: int = 100) -> list[dict[str, Any]]:
        self._require_admin()
        return self._req("GET", "/v1/admin/audit", params={"limit": limit}).json()


def redeem_setup_code(server_url: str, code: str, *, http: httpx.Client | None = None,
                      verify: bool | str = True, timeout: float = 30.0) -> Credential:
    """Collect the machine token behind a one-time setup code. The code works once."""
    return redeem_setup_code_info(server_url, code, http=http, verify=verify, timeout=timeout)[0]


class WrongTokenCode(SecurityWardenError):
    """The setup code is for another token than this program's; it was NOT used up. ``other``: its token's name."""

    def __init__(self, message: str, other: str):
        super().__init__(message)
        self.other = other


def redeem_setup_code_info(server_url: str, code: str, *, name: str | None = None, token_id: str | None = None,
                           replaces: str | None = None, http: httpx.Client | None = None, verify: bool | str = True,
                           timeout: float = 30.0) -> tuple[Credential, dict[str, Any]]:
    """(credential, {"name", "project", "account"}) behind a one-time setup code ("account": an opaque tag of the
    owning account, from servers 0.6.0.dev16 on). What this program is set up for: ``name``, ``token_id`` and/or
    ``replaces`` (the id of the revoked token being replaced: same name and owner required). A code for another
    token is refused by the server before it is used up (:class:`WrongTokenCode`)."""
    try:
        secret = crypto.parse_setup_code(code)
    except CryptoError as e:
        raise SecurityWardenError(str(e)) from None
    base = server_url.rstrip("/") if http is not None else _check_url(server_url)
    own = http is None
    client = http or httpx.Client(timeout=timeout, verify=verify)
    try:
        params = {k: v for k, v in (("name", name), ("token_id", token_id), ("replaces", replaces)) if v}
        r = client.post(f"{base}/v1/setup/{crypto.setup_id(secret)}", params=params or None)
    except httpx.HTTPError as e:
        raise SecurityWardenError(f"couldn't reach {base} ({type(e).__name__})") from None
    finally:
        if own:
            client.close()
    if r.status_code == 409 and _detail(r).startswith("setup_code_for_another_token"):
        other = _detail(r).partition(":")[2].strip()
        mine = repr(name) if name else "another token"
        raise WrongTokenCode(f"that setup code is for the token {other!r}, but this program is set up for {mine}; "
                             f"the code wasn't used and still works where {other!r} belongs", other)
    if r.status_code == 404:
        raise SecurityWardenError("that setup code is unknown, already used or expired: make a new one")
    if r.status_code == 403:
        raise SecurityWardenError("this machine's address isn't allowed for that token (the code is used up)")
    if r.status_code == 429:
        raise SecurityWardenError("too many failed attempts from this address; try again later")
    if r.status_code != 200:
        raise SecurityWardenError(f"setup failed ({r.status_code}): {_detail(r)}")
    try:
        data = r.json()
        cred = crypto.decrypt_from_setup(secret, data["blob"])
    except (CryptoError, KeyError, ValueError):
        raise SecurityWardenError("the server's answer didn't decrypt with that code") from None
    info = {k: data.get(k) if isinstance(data.get(k), str) and len(data.get(k)) <= 200 else None
            for k in ("name", "project", "account")}
    if (name and info["name"] and info["name"] != name) or (token_id and cred.id != token_id and not name):
        # a server that ignored the check
        raise SecurityWardenError(f"that setup code was for the token {info['name']!r}, not {name or token_id!r}; "
                                  "nothing was stored (the code is used up: make a new one)")
    return cred, info


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


__all__ = ["SecurityWardenClient", "SecurityWardenError", "ApprovalError", "CryptoError", "SecondFactor",
           "SecondFactorRequired"]
