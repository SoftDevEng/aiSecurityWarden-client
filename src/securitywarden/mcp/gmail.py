"""Gmail connector: an AI agent reads and manages a mailbox, and every action goes through SecurityWarden.

Secrets (in the token's SecurityWarden project): GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET (a Google Cloud
"Desktop app" OAuth client) and GMAIL_REFRESH_TOKEN (from ``sw-mcp login gmail``). No Gmail password.

Actions and their risk (the token's rules in SecurityWarden decide what asks a person):

    gmail.read.search / .message / .thread / .labels   low     reading
    gmail.label, gmail.archive, gmail.mark_read         low     organizing (a time window may cover these)
    gmail.draft                                          medium  a draft the user sends themselves
    gmail.send, gmail.reply, gmail.forward, gmail.trash  high    always one approval each

Everything read from the mailbox goes back to the AI marked as untrusted data.
"""

from __future__ import annotations

import base64
import email.utils
import getpass
import html
import http.server
import json
import os
import re
import sys
import threading
import time
import urllib.parse
import webbrowser
from email.message import EmailMessage
from html.parser import HTMLParser
from typing import Any

import httpx

from .. import crypto
from .framework import Connector, Plan, Summary, ToolError, tool, untrusted

API = "https://gmail.googleapis.com/gmail/v1/users/me"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPES = ("https://www.googleapis.com/auth/gmail.modify",)   # read, organize, draft, send, trash (no permanent delete)

ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ADDR_RE = re.compile(r"^[^@\s<>,;\"]+@[^@\s<>,;\"]+\.[^@\s<>,;\"]+$")
MAX_IDS = 100
MAX_RECIPIENTS = 50
MAX_BODY = 50_000
MAX_READ = 20_000
SYSTEM_LABELS = {"INBOX", "UNREAD", "STARRED", "IMPORTANT", "SPAM", "TRASH", "SENT", "DRAFT",
                 "CATEGORY_PERSONAL", "CATEGORY_SOCIAL", "CATEGORY_PROMOTIONS", "CATEGORY_UPDATES", "CATEGORY_FORUMS"}

_IDS = {"type": "array", "items": {"type": "string"}, "description": "Gmail message ids (from gmail_search)."}
_ADDRS = {"type": "array", "items": {"type": "string"}, "description": "Email addresses."}


class Gmail(Connector):
    name = "gmail"
    description = "Read and manage a Gmail mailbox."
    secrets = ("GMAIL_CLIENT_ID", "GMAIL_CLIENT_SECRET", "GMAIL_REFRESH_TOKEN")
    suggested_rules = ("gmail.read.*=allow", "gmail.label=window:30m", "gmail.mark_read=window:30m",
                       "gmail.archive=window:30m", "gmail.draft=each", "gmail.send=each", "gmail.reply=each",
                       "gmail.forward=each", "gmail.trash=each")
    transport: httpx.BaseTransport | None = None      # tests replace Google with a fake

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self.http = httpx.Client(timeout=30, transport=self.transport)
        self._access: str | None = None
        self._access_exp = 0.0
        self._labels: dict[str, str] | None = None     # name -> id
        self._me: str | None = None

    def close(self) -> None:
        self.http.close()

    # -- reading ---------------------------------------------------------------------------

    @tool("Search the mailbox with Gmail search syntax (e.g. 'from:bob is:unread newer_than:7d'). Returns "
          "message ids, senders, subjects, dates and snippets.", action="gmail.read.search", risk="low",
          params={"query": {"type": "string", "description": "Gmail search query."},
                  "limit": {"type": "integer", "minimum": 1, "maximum": 50, "description": "Default 20."}},
          required=["query"])
    def search(self, query: str, limit: int = 20) -> Plan:
        q = query.strip()
        if len(q) > 500:
            raise ToolError("The query is too long (500 characters at most).")
        return Plan({"query": q, "limit": limit}, Summary("Search mail", [("Query", q or "(everything)")]),
                    self._search)

    def _search(self, a: dict[str, Any]) -> Any:
        r = self._get("/messages", params={"q": a["query"], "maxResults": a["limit"]})
        out = [self._overview(m["id"]) for m in r.get("messages", [])]
        return untrusted({"messages": out, "more": bool(r.get("nextPageToken"))}, "Gmail")

    @tool("Read one email: headers, text and the names of its attachments.", action="gmail.read.message",
          risk="low", params={"message_id": {"type": "string"}}, required=["message_id"])
    def read(self, message_id: str) -> Plan:
        _check_id(message_id)
        return Plan({"id": message_id}, Summary("Read an email", [("Message", message_id)]), self._read)

    def _read(self, a: dict[str, Any]) -> Any:
        return untrusted(self._message(self._get(f"/messages/{a['id']}", params={"format": "full"})), "Gmail")

    @tool("Read a whole conversation (thread), oldest first.", action="gmail.read.thread", risk="low",
          params={"thread_id": {"type": "string"}}, required=["thread_id"])
    def read_thread(self, thread_id: str) -> Plan:
        _check_id(thread_id)
        return Plan({"id": thread_id}, Summary("Read a conversation", [("Thread", thread_id)]), self._read_thread)

    def _read_thread(self, a: dict[str, Any]) -> Any:
        t = self._get(f"/threads/{a['id']}", params={"format": "full"})
        return untrusted({"thread_id": t.get("id"), "messages": [self._message(m) for m in t.get("messages", [])]},
                         "Gmail")

    @tool("List the mailbox's labels.", action="gmail.read.labels", risk="low", params={})
    def labels(self) -> Plan:
        return Plan({}, Summary("List labels"), self._list_labels)

    def _list_labels(self, a: dict[str, Any]) -> Any:
        self._labels = None
        return untrusted({"labels": sorted(self._label_ids())}, "Gmail")

    # -- organizing ------------------------------------------------------------------------

    @tool("Add and/or remove labels on emails (label names as shown by gmail_labels).", action="gmail.label",
          risk="low", params={"message_ids": _IDS, "add": {"type": "array", "items": {"type": "string"}},
                              "remove": {"type": "array", "items": {"type": "string"}}},
          required=["message_ids"])
    def label(self, message_ids: list[str], add: list[str] | None = None, remove: list[str] | None = None) -> Plan:
        ids = _check_ids(message_ids)
        add_ids, remove_ids = self._resolve(add or []), self._resolve(remove or [])
        if not add_ids and not remove_ids:
            raise ToolError("Give at least one label to add or remove.")
        fields = ([("Add", ", ".join(add or []))] if add else []) + ([("Remove", ", ".join(remove or []))] if remove else [])
        return Plan({"ids": ids, "add": add_ids, "remove": remove_ids},
                    self._batch_summary("Label", ids, fields), self._modify)

    @tool("Archive emails (remove them from the inbox; they stay in All Mail).", action="gmail.archive",
          risk="low", params={"message_ids": _IDS}, required=["message_ids"])
    def archive(self, message_ids: list[str]) -> Plan:
        ids = _check_ids(message_ids)
        return Plan({"ids": ids, "add": [], "remove": ["INBOX"]}, self._batch_summary("Archive", ids), self._modify)

    @tool("Mark emails as read (or unread with read=false).", action="gmail.mark_read", risk="low",
          params={"message_ids": _IDS, "read": {"type": "boolean"}}, required=["message_ids"])
    def mark_read(self, message_ids: list[str], read: bool = True) -> Plan:
        ids = _check_ids(message_ids)
        a = {"ids": ids, "add": [] if read else ["UNREAD"], "remove": ["UNREAD"] if read else []}
        return Plan(a, self._batch_summary("Mark as read" if read else "Mark as unread", ids), self._modify)

    @tool("Move emails to Trash (Gmail deletes them for good after 30 days).", action="gmail.trash", risk="high",
          params={"message_ids": _IDS}, required=["message_ids"])
    def trash(self, message_ids: list[str]) -> Plan:
        ids = _check_ids(message_ids)
        return Plan({"ids": ids}, self._batch_summary("Move to Trash", ids), self._trash)

    def _modify(self, a: dict[str, Any]) -> Any:
        self._post("/messages/batchModify", {"ids": a["ids"], "addLabelIds": a["add"], "removeLabelIds": a["remove"]})
        return {"done": True, "messages": len(a["ids"])}

    def _trash(self, a: dict[str, Any]) -> Any:
        for mid in a["ids"]:
            self._post(f"/messages/{mid}/trash", None)
        return {"trashed": len(a["ids"])}

    # -- writing ---------------------------------------------------------------------------

    @tool("Send a new email.", action="gmail.send", risk="high",
          params={"to": _ADDRS, "subject": {"type": "string"}, "body": {"type": "string", "description": "Plain text."},
                  "cc": _ADDRS, "bcc": _ADDRS}, required=["to", "subject", "body"])
    def send(self, to: list[str], subject: str, body: str, cc: list[str] | None = None,
             bcc: list[str] | None = None) -> Plan:
        a = _mail_args(to, cc or [], bcc or [], subject, body)
        return Plan(a, _mail_summary("Send an email", a), self._send)

    @tool("Save a draft in Gmail for the user to review and send themselves.", action="gmail.draft", risk="medium",
          params={"to": _ADDRS, "subject": {"type": "string"}, "body": {"type": "string"}, "cc": _ADDRS},
          required=["to", "subject", "body"])
    def draft(self, to: list[str], subject: str, body: str, cc: list[str] | None = None) -> Plan:
        a = _mail_args(to, cc or [], [], subject, body)
        return Plan(a, _mail_summary("Save a draft", a), self._draft)

    @tool("Reply to an email (to its sender, or everyone with reply_all).", action="gmail.reply", risk="high",
          params={"message_id": {"type": "string"}, "body": {"type": "string"}, "reply_all": {"type": "boolean"}},
          required=["message_id", "body"])
    def reply(self, message_id: str, body: str, reply_all: bool = False) -> Plan:
        _check_id(message_id)
        m = self._get(f"/messages/{message_id}", params={"format": "metadata", "metadataHeaders": [
            "From", "Reply-To", "To", "Cc", "Subject", "Message-ID", "References"]})
        h = _headers(m)
        me = self._my_address().lower()
        to = [a for _, a in email.utils.getaddresses([h.get("reply-to") or h.get("from", "")]) if a]
        cc: list[str] = []
        if reply_all:
            cc = [a for _, a in email.utils.getaddresses([h.get("to", ""), h.get("cc", "")])
                  if a and a.lower() != me and a.lower() not in {x.lower() for x in to}]
        subject = _one_line(h.get("subject", ""))
        if not subject.lower().startswith("re:"):
            subject = f"Re: {subject}".strip()
        a = _mail_args(to, cc, [], subject, body)
        refs = " ".join(x for x in (h.get("references", ""), h.get("message-id", "")) if x).strip()
        a.update({"thread_id": m.get("threadId", ""), "in_reply_to": h.get("message-id", ""), "references": refs[-2000:]})
        return Plan(a, _mail_summary("Reply to an email", a), self._send)

    @tool("Forward an email (with its attachments) to new recipients, with an optional note.",
          action="gmail.forward", risk="high",
          params={"message_id": {"type": "string"}, "to": _ADDRS, "note": {"type": "string"}},
          required=["message_id", "to"])
    def forward(self, message_id: str, to: list[str], note: str = "") -> Plan:
        _check_id(message_id)
        m = self._get(f"/messages/{message_id}", params={"format": "metadata", "metadataHeaders": ["From", "Subject"]})
        h = _headers(m)
        a = _mail_args(to, [], [], f"Fwd: {_one_line(h.get('subject', ''))}".strip(), note)
        a["forward_id"] = message_id
        s = _mail_summary("Forward an email", a)
        fields = list(s.fields) + [("Original from", h.get("from", "")), ("Attachments", "the original email, in full")]
        return Plan(a, Summary(s.title, fields, s.preview), self._send)

    def _mime(self, a: dict[str, Any]) -> EmailMessage:
        msg = EmailMessage()
        msg["To"] = ", ".join(a["to"])
        if a["cc"]:
            msg["Cc"] = ", ".join(a["cc"])
        if a["bcc"]:
            msg["Bcc"] = ", ".join(a["bcc"])
        msg["Subject"] = a["subject"]
        if a.get("in_reply_to"):
            msg["In-Reply-To"] = a["in_reply_to"]
            msg["References"] = a.get("references") or a["in_reply_to"]
        msg.set_content(a["body"])
        if a.get("forward_id"):
            raw = self._get(f"/messages/{a['forward_id']}", params={"format": "raw"})["raw"]
            msg.add_attachment(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)), maintype="message",
                               subtype="rfc822", filename="forwarded.eml")
        return msg

    def _send(self, a: dict[str, Any]) -> Any:
        body: dict[str, Any] = {"raw": _b64(self._mime(a).as_bytes())}
        if a.get("thread_id"):
            body["threadId"] = a["thread_id"]
        r = self._post("/messages/send", body)
        return {"sent": True, "message_id": r.get("id"), "thread_id": r.get("threadId")}

    def _draft(self, a: dict[str, Any]) -> Any:
        r = self._post("/drafts", {"message": {"raw": _b64(self._mime(a).as_bytes())}})
        return {"draft_saved": True, "draft_id": r.get("id"), "note": "The user can review and send it from Gmail."}

    # -- helpers ---------------------------------------------------------------------------

    def _batch_summary(self, verb: str, ids: list[str], extra: list[tuple[str, str]] | None = None) -> Summary:
        subjects = []
        for mid in ids[:3]:
            h = _headers(self._get(f"/messages/{mid}", params={"format": "metadata",
                                                                "metadataHeaders": ["From", "Subject"]}))
            subjects.append(f"{h.get('subject', '(no subject)')} ({_name(h.get('from', ''))})")
        n = len(ids)
        fields = list(extra or []) + [("Email" if n == 1 else f"Emails ({n})",
                                       "; ".join(subjects) + (f"; and {n - 3} more" if n > 3 else ""))]
        return Summary(f"{verb} {n} email{'s' if n != 1 else ''}", fields, count=n)

    def _overview(self, mid: str) -> dict[str, Any]:
        m = self._get(f"/messages/{mid}", params={"format": "metadata",
                                                  "metadataHeaders": ["From", "To", "Subject", "Date"]})
        h = _headers(m)
        labels = m.get("labelIds", [])
        return {"id": m.get("id"), "thread_id": m.get("threadId"), "from": h.get("from"), "to": h.get("to"),
                "subject": h.get("subject"), "date": h.get("date"), "snippet": html.unescape(m.get("snippet", "")),
                "unread": "UNREAD" in labels, "labels": labels}

    def _message(self, m: dict[str, Any]) -> dict[str, Any]:
        h = _headers(m)
        text, attachments = _body(m.get("payload", {}))
        if len(text) > MAX_READ:
            text = text[:MAX_READ] + f"\n[... {len(text) - MAX_READ} more characters not shown]"
        return {"id": m.get("id"), "thread_id": m.get("threadId"), "from": h.get("from"), "to": h.get("to"),
                "cc": h.get("cc"), "subject": h.get("subject"), "date": h.get("date"),
                "labels": m.get("labelIds", []), "text": text, "attachments": attachments}

    def _label_ids(self) -> dict[str, str]:
        if self._labels is None:
            self._labels = {lb["name"]: lb["id"] for lb in self._get("/labels").get("labels", [])}
        return self._labels

    def _resolve(self, names: list[str]) -> list[str]:
        out = []
        for n in names:
            if n.upper() in SYSTEM_LABELS:
                out.append(n.upper())
                continue
            ids = self._label_ids()
            if n not in ids:
                raise ToolError(f"There is no label called {n!r}. Use gmail_labels to see them.")
            out.append(ids[n])
        return sorted(set(out))

    def _my_address(self) -> str:
        if self._me is None:
            self._me = self._get("/profile").get("emailAddress", "")
        return self._me

    # -- Google ----------------------------------------------------------------------------

    def _token(self) -> str:
        if self._access and time.monotonic() < self._access_exp:
            return self._access
        r = self.http.post(TOKEN_URL, data={
            "grant_type": "refresh_token", "client_id": self.secret("GMAIL_CLIENT_ID"),
            "client_secret": self.secret("GMAIL_CLIENT_SECRET"), "refresh_token": self.secret("GMAIL_REFRESH_TOKEN")})
        if r.status_code != 200:
            err = _json(r).get("error", r.status_code)
            self.ctx.forget_secrets()        # perhaps the refresh token was replaced since: fetch again next time
            if err == "invalid_grant":
                raise ToolError("Gmail access has expired or was revoked. Ask the user to run: sw-mcp login gmail")
            raise ToolError(f"Couldn't sign in to Gmail ({err}).")
        data = r.json()
        self._access = data["access_token"]
        self._access_exp = time.monotonic() + max(0, int(data.get("expires_in", 3600)) - 60)
        return self._access

    def _call(self, method: str, path: str, **kw: Any) -> dict[str, Any]:
        for attempt in (1, 2):
            r = self.http.request(method, API + path, headers={"Authorization": f"Bearer {self._token()}"}, **kw)
            if r.status_code == 401 and attempt == 1:
                self._access = None
                continue
            if r.status_code == 404:
                raise ToolError("Gmail says that message, thread or label doesn't exist.")
            if r.status_code == 429 or r.status_code >= 500:
                raise ToolError(f"Gmail is busy or unavailable ({r.status_code}); try again in a minute.")
            if r.status_code >= 400:
                msg = (_json(r).get("error") or {}).get("message", "") if isinstance(_json(r).get("error"), dict) else ""
                raise ToolError(f"Gmail refused the request ({r.status_code}{': ' + msg[:200] if msg else ''}).")
            return _json(r) if r.content else {}
        raise ToolError("Gmail sign-in failed.")

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._call("GET", path, params=params)

    def _post(self, path: str, body: dict[str, Any] | None) -> dict[str, Any]:
        return self._call("POST", path, json=body) if body is not None else self._call("POST", path)

    # -- one-time sign-in ------------------------------------------------------------------

    @classmethod
    def login(cls, args: Any) -> None:
        """Google sign-in in the browser (loopback + PKCE), once. The refresh token goes to SecurityWarden."""
        client_id, client_secret = _oauth_client(args)
        verifier, challenge = crypto.pkce_pair()
        state = crypto.new_nonce()
        got: dict[str, str] = {}
        done = threading.Event()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
                if q.get("state") != state:
                    self.send_response(400)
                    self.end_headers()
                    return
                got.update(q)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<p>SecurityWarden: done. You can close this tab and go back to the terminal.</p>")
                done.set()

            def log_message(self, *a: Any) -> None:
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        redirect = f"http://127.0.0.1:{srv.server_port}"
        url = AUTH_URL + "?" + urllib.parse.urlencode({
            "client_id": client_id, "redirect_uri": redirect, "response_type": "code", "scope": " ".join(SCOPES),
            "access_type": "offline", "prompt": "consent", "state": state,
            "code_challenge": challenge, "code_challenge_method": "S256"})
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print("Sign in with the Google account the agent should use, and allow access:\n\n  " + url + "\n",
              file=sys.stderr)
        if not getattr(args, "no_browser", False):
            webbrowser.open(url)
        try:
            if not done.wait(600):
                raise SystemExit("sw-mcp: no answer from Google within 10 minutes")
        finally:
            srv.shutdown()
        if "code" not in got:
            raise SystemExit(f"sw-mcp: Google sign-in failed: {got.get('error', 'no code')}")
        r = httpx.post(TOKEN_URL, data={"grant_type": "authorization_code", "code": got["code"],
                                        "client_id": client_id, "client_secret": client_secret,
                                        "redirect_uri": redirect, "code_verifier": verifier}, timeout=30)
        data = _json(r)
        if r.status_code != 200 or not data.get("refresh_token"):
            raise SystemExit(f"sw-mcp: Google didn't give a refresh token ({data.get('error', r.status_code)})")
        who = httpx.get(API + "/profile", headers={"Authorization": f"Bearer {data['access_token']}"},
                        timeout=30).json().get("emailAddress", "your account")
        _store_refresh_token(args, data["refresh_token"], who)


# ---------------------------------------------------------------------------
# helpers (no network)
# ---------------------------------------------------------------------------

def _one_line(text: str) -> str:
    return " ".join(text.split())[:400]


def _check_id(mid: str) -> str:
    if not ID_RE.match(mid or ""):
        raise ToolError(f"{mid!r} isn't a Gmail id.")
    return mid


def _check_ids(ids: list[str]) -> list[str]:
    if not ids:
        raise ToolError("Give at least one message id.")
    if len(ids) > MAX_IDS:
        raise ToolError(f"At most {MAX_IDS} messages at a time.")
    return sorted({_check_id(i) for i in ids})


def _check_addrs(addrs: list[str], what: str) -> list[str]:
    out = []
    for a in addrs:
        a = a.strip()
        name, addr = email.utils.parseaddr(a)
        if not ADDR_RE.match(addr) or "\r" in a or "\n" in a:
            raise ToolError(f"{a!r} isn't an email address ({what}).")
        out.append(email.utils.formataddr((name, addr)) if name else addr)
    return out


def _mail_args(to: list[str], cc: list[str], bcc: list[str], subject: str, body: str) -> dict[str, Any]:
    to, cc, bcc = _check_addrs(to, "to"), _check_addrs(cc, "cc"), _check_addrs(bcc, "bcc")
    if not to:
        raise ToolError("Give at least one recipient.")
    if len(to) + len(cc) + len(bcc) > MAX_RECIPIENTS:
        raise ToolError(f"At most {MAX_RECIPIENTS} recipients.")
    if "\n" in subject or "\r" in subject or len(subject) > 500:
        raise ToolError("The subject must be one line (500 characters at most).")
    if len(body) > MAX_BODY:
        raise ToolError(f"The body is too long ({MAX_BODY} characters at most).")
    return {"to": to, "cc": cc, "bcc": bcc, "subject": subject, "body": body}


def _mail_summary(title: str, a: dict[str, Any]) -> Summary:
    fields = [("To", ", ".join(a["to"]))]
    if a["cc"]:
        fields.append(("Cc", ", ".join(a["cc"])))
    if a["bcc"]:
        fields.append(("Bcc", ", ".join(a["bcc"])))
    fields.append(("Subject", a["subject"] or "(no subject)"))
    return Summary(title, fields, preview=a["body"] or None)


def _headers(m: dict[str, Any]) -> dict[str, str]:
    return {h["name"].lower(): h["value"] for h in m.get("payload", {}).get("headers", [])
            if isinstance(h, dict) and "name" in h and "value" in h}


def _name(addr: str) -> str:
    name, a = email.utils.parseaddr(addr)
    return name or a or "unknown sender"


def _decode(data: str) -> str:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace")


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in ("script", "style", "head"):
            self.skip += 1
        elif tag in ("br", "p", "div", "tr", "li", "h1", "h2", "h3"):
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "head") and self.skip:
            self.skip -= 1

    def handle_data(self, data: str) -> None:
        if not self.skip:
            self.parts.append(data)


def _html_text(markup: str) -> str:
    p = _Text()
    p.feed(markup)
    return re.sub(r"\n\s*\n+", "\n\n", "".join(p.parts)).strip()


def _body(payload: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    plain: list[str] = []
    htmls: list[str] = []
    attachments: list[dict[str, Any]] = []

    def walk(part: dict[str, Any]) -> None:
        mime = part.get("mimeType", "")
        body = part.get("body", {})
        if part.get("filename"):
            attachments.append({"name": part["filename"], "type": mime, "size": body.get("size", 0)})
        elif mime == "text/plain" and body.get("data"):
            plain.append(_decode(body["data"]))
        elif mime == "text/html" and body.get("data"):
            htmls.append(_decode(body["data"]))
        for p in part.get("parts", []) or []:
            walk(p)
    walk(payload)
    text = "\n".join(plain).strip() or "\n".join(_html_text(h) for h in htmls).strip()
    return text, attachments


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _json(r: httpx.Response) -> dict[str, Any]:
    try:
        v = r.json()
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


def _oauth_client(args: Any) -> tuple[str, str]:
    """The OAuth client id and secret: from the bot's SecurityWarden project if a token is set up, else asked."""
    from .cli import _client, _config
    if any(getattr(args, k, None) for k in ("token_file",)) or os.environ.get("SW_ACCESS_TOKEN_FILE") or \
            os.environ.get("SW_ACCESS_TOKEN"):
        try:
            s = _client(args, _config(args)).fetch()
            if s.get("GMAIL_CLIENT_ID") and s.get("GMAIL_CLIENT_SECRET"):
                print("Using GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET from SecurityWarden.", file=sys.stderr)
                return s["GMAIL_CLIENT_ID"], s["GMAIL_CLIENT_SECRET"]
        except Exception as e:  # noqa: BLE001
            print(f"sw-mcp: couldn't read them from SecurityWarden ({e}); asking instead.", file=sys.stderr)
    cid = input("Google OAuth client ID: ").strip()
    secret = getpass.getpass("Google OAuth client secret (not shown): ").strip()
    if not cid or not secret:
        raise SystemExit("sw-mcp: both are needed")
    return cid, secret


def _store_refresh_token(args: Any, token: str, who: str) -> None:
    if getattr(args, "project", None):
        from ..client.api import SecurityWardenClient
        from ..client.cli import DEFAULT_ADMIN_FILE, _read_cred_file
        path = getattr(args, "admin_file", None) or os.environ.get("SW_ADMIN_CREDENTIAL_FILE") or DEFAULT_ADMIN_FILE
        url = getattr(args, "server", None) or os.environ.get("SW_SERVER_URL")
        if not url:
            raise SystemExit("sw-mcp: --project needs the server (--server or SW_SERVER_URL)")
        admin = SecurityWardenClient(url, _read_cred_file(path),
                                     verify=getattr(args, "ca_bundle", None) or os.environ.get("SW_CA_BUNDLE") or True)
        admin.set_secret(args.project, "GMAIL_REFRESH_TOKEN", token)
        print(f"Signed in as {who}. Stored GMAIL_REFRESH_TOKEN in project {args.project}.", file=sys.stderr)
        return
    print(f"Signed in as {who}.\n\nAdd this to the bot's SecurityWarden project as the secret GMAIL_REFRESH_TOKEN "
          "(website: the project's Secrets tab). It's shown once and gives access to the mailbox: don't save it "
          "anywhere else, and clear this terminal afterwards.\n", file=sys.stderr)
    print(token)
    sys.stdout.flush()
