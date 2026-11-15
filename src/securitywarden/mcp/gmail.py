"""Gmail connector: an AI agent reads and manages a mailbox, and every action goes through aiSecurityWarden.

Secrets (in the token's aiSecurityWarden project): GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET (a Google Cloud
"Desktop app" OAuth client) and GMAIL_REFRESH_TOKEN (from ``sw-mcp login gmail``). No Gmail password.

Actions and their risk (the token's rules in aiSecurityWarden decide what asks a person):

    gmail.read.search / .message / .thread / .labels   low     reading
    gmail.read.attachment                                low     an attachment's text (text, PDF, .docx)
    gmail.label, gmail.archive, gmail.mark_read         low     organizing (a time window may cover these)
    gmail.draft                                          medium  a draft the user sends themselves
    gmail.send, gmail.reply, gmail.forward, gmail.trash  high    always one approval each
    gmail.read.drive_shared                              low     files this connector shared on Google Drive
    gmail.drive_unshare                                  low     stop sharing one of them (only ever reduces access)

Files too big for Gmail (or sent with delivery "drive") go to the user's Google Drive, in a folder "aiSecurityWarden
shared", shared view-only with the email's To and Cc recipients only (never "anyone with the link"; the connector,
not the AI, decides who). The email carries the links. Needs the drive.file scope (the connector sees only files it
uploaded); a draft with Drive links is high risk because the files are shared when the draft is saved.

Send, reply, forward and draft take ``attachments``: text or a small base64 file the AI made, an attachment of
an email in the mailbox (``message_id`` + ``part`` from gmail_read), or a file the AI saved in the aiSecurityWarden
outbox folder (``path``; also folders the user lists in SW_ATTACHMENT_FOLDERS). Each file's name, size and SHA-256 are part
of what a person approves; an attachment from the mailbox is fetched again and checked when the action runs.

Everything read from the mailbox goes back to the AI marked as untrusted data.
"""

from __future__ import annotations

import base64
import email.utils
import getpass
import hashlib
import html
import http.server
import json
import os
import re
import sys
import threading
import time
import urllib.parse
import uuid
import webbrowser
from collections.abc import Callable
from email.message import EmailMessage
from html.parser import HTMLParser
from typing import Any

import httpx

from .. import crypto
from . import mailfiles
from .framework import Connector, Plan, Summary, ToolError, tool, untrusted

API = "https://gmail.googleapis.com/gmail/v1/users/me"
UPLOAD = "https://gmail.googleapis.com/upload/gmail/v1/users/me"
UPLOAD_OVER = 4_000_000              # bytes of email: bigger ones go through Gmail's upload endpoint
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify"   # read, organize, draft, send, trash (no permanent delete)
DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file"     # only files this app uploaded
SCOPES = (GMAIL_SCOPE, DRIVE_SCOPE)
DRIVE = "https://www.googleapis.com/drive/v3"
DRIVE_UPLOAD = "https://www.googleapis.com/upload/drive/v3"
DRIVE_FOLDER = "aiSecurityWarden shared"
DRIVE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{10,128}$")
NO_DRIVE = ("Drive links need Google Drive access, which this Gmail sign-in doesn't have. Ask the user to reconnect "
            "Gmail on the aiSecurityWarden website (Connectors, Gmail, Reconnect) and tick Google Drive, or run "
            "sw-mcp login gmail on a computer with a browser.")

ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
PART_RE = re.compile(r"^[0-9]{1,4}(\.[0-9]{1,4}){0,7}$")
ADDR_RE = re.compile(r"^[^@\s<>,;\"]+@[^@\s<>,;\"]+\.[^@\s<>,;\"]+$")
MAX_IDS = 100
MAX_RECIPIENTS = 50
MAX_BODY = 50_000
MAX_READ = 20_000
SYSTEM_LABELS = {"INBOX", "UNREAD", "STARRED", "IMPORTANT", "SPAM", "TRASH", "SENT", "DRAFT",
                 "CATEGORY_PERSONAL", "CATEGORY_SOCIAL", "CATEGORY_PROMOTIONS", "CATEGORY_UPDATES", "CATEGORY_FORUMS"}

_IDS = {"type": "array", "items": {"type": "string"}, "description": "Gmail message ids (from gmail_search)."}
_ADDRS = {"type": "array", "items": {"type": "string"}, "description": "Email addresses."}
_MID = {"type": "string", "description": "A Gmail message id (from gmail_search)."}
_SUBJECT = {"type": "string", "description": "Subject line (one line)."}
_BODY = {"type": "string", "description": "Plain-text body."}
_DELIVERY = {"type": "string", "enum": ["auto", "attach", "drive"], "description": (
    "How files travel: auto (default) attaches them and uses Google Drive links only for what Gmail can't carry; "
    "attach never uses Drive; drive sends every file as a Drive link, view-only for the To and Cc recipients "
    "(use it when the user asks for a Drive link). Drive links can't be combined with Bcc.")}
_PART = {"type": "string", "description": "The attachment's part, as gmail_read lists it (e.g. \"1\")."}
_FILES = {"type": "array", "maxItems": mailfiles.MAX_FILES, "description": (
    "Files to attach (at most 10, 18 MB together). Each is one of: {\"path\": \"report.pdf\"} for a file you saved in "
    f"the aiSecurityWarden outbox folder {mailfiles.outbox()} (save files you make or download there first; a bare "
    "name means a file in that folder); {\"name\": \"summary.md\", \"text\": \"...\"} for short text you wrote; "
    "{\"message_id\": \"...\", \"part\": \"1\"} (optional \"name\") for an attachment of an email, as gmail_read "
    "lists it; or {\"name\": \"icon.png\", \"base64\": \"...\"} for a tiny file (1 MB). Files too big for Gmail "
    "(18 MB together) go as Google Drive links shared only with the To and Cc recipients (up to 100 MB each)."),
    "items": {"type": "object", "additionalProperties": False, "properties": {
        "path": {"type": "string"}, "name": {"type": "string"}, "text": {"type": "string"},
        "base64": {"type": "string"}, "message_id": {"type": "string"}, "part": {"type": "string"}}}}


class Gmail(Connector):
    name = "gmail"
    title = "Gmail"
    description = "Read and manage a Gmail mailbox."
    secrets = ("GMAIL_CLIENT_ID", "GMAIL_CLIENT_SECRET", "GMAIL_REFRESH_TOKEN")
    suggested_rules = ("gmail.read.*=allow", "gmail.label=window:30m", "gmail.mark_read=window:30m",
                       "gmail.archive=window:30m", "gmail.draft=each", "gmail.send=each", "gmail.reply=each",
                       "gmail.forward=each", "gmail.trash=each", "gmail.drive_unshare=allow")
    transport: httpx.BaseTransport | None = None      # tests replace Google with a fake

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self.http = httpx.Client(timeout=30, transport=self.transport)
        self._access: str | None = None
        self._access_exp = 0.0
        self._labels: dict[str, str] | None = None     # name -> id
        self._me: str | None = None
        self._scopes: set[str] | None = None            # what the Google sign-in allows
        self._folder: str | None = None

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

    @tool("Read one email: headers, text and its attachments (name, type, size and part; read one with "
          "gmail_attachment).", action="gmail.read.message",
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

    @tool("Read the text of an email's attachment (text, CSV, Markdown, HTML, PDF, Word .docx). Long text comes "
          "in pieces: pass offset to read on.", action="gmail.read.attachment", risk="low",
          params={"message_id": _MID, "part": _PART,
                  "offset": {"type": "integer", "minimum": 0, "maximum": 100_000_000,
                             "description": "Character to start at (default 0)."}},
          required=["message_id", "part"])
    def attachment(self, message_id: str, part: str, offset: int = 0) -> Plan:
        _check_id(message_id)
        _check_part(part)
        return Plan({"id": message_id, "part": part, "offset": offset},
                    Summary("Read an attachment", [("Message", message_id), ("Part", part)]), self._attachment)

    def _attachment(self, a: dict[str, Any]) -> Any:
        info, data = self._part(a["id"], a["part"], limit=mailfiles.MAX_READ_FILE)
        out: dict[str, Any] = {"message_id": a["id"], "part": a["part"], "name": info["name"], "type": info["type"],
                               "size": len(data)}
        text, how = mailfiles.read_text(info["name"], info["type"], data, _html_text)
        if text is None:
            out["text"] = None
            out["note"] = how
            return untrusted(out, "Gmail attachment")
        start = min(a["offset"], len(text))
        piece = text[start:start + MAX_READ]
        out.update({"text": piece, "offset": start, "length": len(text)})
        if start + len(piece) < len(text):
            out["next_offset"] = start + len(piece)
        return untrusted(out, "Gmail attachment")

    @tool("List the files aiSecurityWarden shared as Google Drive links, newest first, with who can open each.",
          action="gmail.read.drive_shared", risk="low", params={})
    def drive_shared(self) -> Plan:
        return Plan({}, Summary("List files shared on Google Drive"), self._drive_shared)

    def _drive_shared(self, a: dict[str, Any]) -> Any:
        if not self._has_drive():
            raise ToolError(NO_DRIVE)
        q = f"'{self._drive_folder()}' in parents and trashed = false"
        r = self._drive_ok(self._drive("GET", DRIVE + "/files", params={
            "q": q, "orderBy": "createdTime desc", "pageSize": 100,
            "fields": "files(id,name,size,createdTime,webViewLink,permissions(id,type,role,emailAddress))"}))
        out = []
        for f in r.get("files") or []:
            people = sorted(p.get("emailAddress", "") for p in f.get("permissions") or []
                            if p.get("role") != "owner")
            out.append({"file_id": f.get("id"), "name": f.get("name"), "size": int(f.get("size", 0) or 0),
                        "created": f.get("createdTime"), "link": f.get("webViewLink"), "shared_with": people})
        return untrusted({"files": out}, "Google Drive")

    @tool("Stop sharing a file aiSecurityWarden shared on Google Drive (everyone loses access); optionally move it "
          "to the Drive trash. Only ever reduces access.", action="gmail.drive_unshare", risk="low",
          params={"file_id": {"type": "string", "description": "From gmail_drive_shared or a send result."},
                  "trash": {"type": "boolean", "description": "Also move the file to the Drive trash. Default false."}},
          required=["file_id"])
    def drive_unshare(self, file_id: str, trash: bool = False) -> Plan:
        if not DRIVE_ID_RE.match(file_id or ""):
            raise ToolError(f"{file_id!r} isn't a Google Drive file id.")
        if not self._has_drive():
            raise ToolError(NO_DRIVE)
        f = self._drive_ok(self._drive("GET", f"{DRIVE}/files/{file_id}", params={
            "fields": "id,name,permissions(id,role,emailAddress)"}))
        people = [p.get("emailAddress", "") for p in f.get("permissions") or [] if p.get("role") != "owner"]
        fields = [("File", f.get("name", file_id)), ("Shared with", ", ".join(people) or "nobody")]
        if trash:
            fields.append(("Also", "move it to the Drive trash"))
        return Plan({"file_id": file_id, "trash": bool(trash)},
                    Summary("Stop sharing a Drive file", fields), self._unshare)

    def _unshare(self, a: dict[str, Any]) -> Any:
        f = self._drive_ok(self._drive("GET", f"{DRIVE}/files/{a['file_id']}",
                                       params={"fields": "id,permissions(id,role)"}))
        removed = 0
        for p in f.get("permissions") or []:
            if p.get("role") != "owner":
                self._drive_ok(self._drive("DELETE", f"{DRIVE}/files/{a['file_id']}/permissions/{p['id']}"))
                removed += 1
        if a["trash"]:
            self._drive_ok(self._drive("PATCH", f"{DRIVE}/files/{a['file_id']}", json={"trashed": True}))
        return {"unshared": True, "people_removed": removed, "trashed": a["trash"]}

    # -- organizing ------------------------------------------------------------------------

    @tool("Add and/or remove labels on emails (label names as shown by gmail_labels).", action="gmail.label",
          risk="low", params={"message_ids": _IDS,
                              "add": {"type": "array", "items": {"type": "string"}, "description": "Label names to add."},
                              "remove": {"type": "array", "items": {"type": "string"},
                                         "description": "Label names to remove."}},
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
          params={"message_ids": _IDS, "read": {"type": "boolean", "description": "False marks them unread. Default true."}},
          required=["message_ids"])
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
          params={"to": _ADDRS, "subject": _SUBJECT, "body": _BODY, "cc": _ADDRS, "bcc": _ADDRS,
                  "attachments": _FILES, "delivery": _DELIVERY},
          required=["to", "subject", "body"])
    def send(self, to: list[str], subject: str, body: str, cc: list[str] | None = None,
             bcc: list[str] | None = None, attachments: list[dict[str, Any]] | None = None,
             delivery: str = "auto") -> Plan:
        a = _mail_args(to, cc or [], bcc or [], subject, body)
        self._add_files(a, attachments, delivery)
        return Plan(a, _mail_summary("Send an email", a), self._send)

    @tool("Save a draft in Gmail for the user to review and send themselves.", action="gmail.draft", risk="medium",
          params={"to": _ADDRS, "subject": _SUBJECT, "body": _BODY, "cc": _ADDRS, "attachments": _FILES,
                  "delivery": _DELIVERY},
          required=["to", "subject", "body"])
    def draft(self, to: list[str], subject: str, body: str, cc: list[str] | None = None,
              attachments: list[dict[str, Any]] | None = None, delivery: str = "auto") -> Plan:
        a = _mail_args(to, cc or [], [], subject, body)
        self._add_files(a, attachments, delivery)
        drive = any(f["delivery"] == "drive" for f in a["files"])     # shared now, whatever happens to the draft
        return Plan(a, _mail_summary("Save a draft", a), self._draft, risk="high" if drive else None)

    @tool("Reply to an email (to its sender, or everyone with reply_all).", action="gmail.reply", risk="high",
          params={"message_id": _MID, "body": _BODY,
                  "reply_all": {"type": "boolean", "description": "Also reply to everyone in To and Cc. Default false."},
                  "attachments": _FILES, "delivery": _DELIVERY},
          required=["message_id", "body"])
    def reply(self, message_id: str, body: str, reply_all: bool = False,
              attachments: list[dict[str, Any]] | None = None, delivery: str = "auto") -> Plan:
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
        self._add_files(a, attachments, delivery)
        refs = " ".join(x for x in (h.get("references", ""), h.get("message-id", "")) if x).strip()
        a.update({"thread_id": m.get("threadId", ""), "in_reply_to": h.get("message-id", ""), "references": refs[-2000:]})
        return Plan(a, _mail_summary("Reply to an email", a), self._send)

    @tool("Forward an email (with its attachments) to new recipients, with an optional note and extra files.",
          action="gmail.forward", risk="high",
          params={"message_id": _MID, "to": _ADDRS,
                  "note": {"type": "string", "description": "Optional text above the forwarded email."},
                  "attachments": _FILES, "delivery": _DELIVERY},
          required=["message_id", "to"])
    def forward(self, message_id: str, to: list[str], note: str = "",
                attachments: list[dict[str, Any]] | None = None, delivery: str = "auto") -> Plan:
        _check_id(message_id)
        m = self._get(f"/messages/{message_id}", params={"format": "metadata", "metadataHeaders": ["From", "Subject"]})
        h = _headers(m)
        a = _mail_args(to, [], [], f"Fwd: {_one_line(h.get('subject', ''))}".strip(), note)
        self._add_files(a, attachments, delivery)
        a["forward_id"] = message_id
        s = _mail_summary("Forward an email", a)
        fields = list(s.fields) + [("Original from", h.get("from", "")), ("Forwarding", "the original email, in full")]
        return Plan(a, Summary(s.title, fields, s.preview), self._send)

    def _files(self, items: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        """Checked attachments for ``Plan.args``. Text and base64 files carry their bytes (so the digest covers
        them); an attachment from the mailbox carries its SHA-256 and is fetched again when the action runs."""
        items = items or []
        if not isinstance(items, list) or len(items) > mailfiles.MAX_FILES:
            raise ToolError(f"At most {mailfiles.MAX_FILES} attachments.")
        out: list[dict[str, Any]] = []
        for i, it in enumerate(items, 1):
            if not isinstance(it, dict) or set(it) - {"name", "text", "base64", "message_id", "part", "path"}:
                raise ToolError(f"Attachment {i}: use path, name + text, name + base64, or message_id + part.")
            if any(not isinstance(v, str) for v in it.values()):
                raise ToolError(f"Attachment {i}: every value is a string.")
            kinds = [k for k in ("text", "base64", "message_id", "path") if k in it]
            if len(kinds) != 1 or ("part" in it) != ("message_id" in it):
                raise ToolError(f"Attachment {i}: give exactly one of path, text, base64, or message_id + part.")
            try:
                if "path" in it:
                    real = mailfiles.check_path(it["path"])
                    data = mailfiles.read_path(real, mailfiles.MAX_DRIVE)
                    name = mailfiles.clean_name(it.get("name") or os.path.basename(real))
                    entry = {"path": real}
                elif "message_id" in it:
                    _check_id(it["message_id"])
                    _check_part(it["part"])
                    info, data = self._part(it["message_id"], it["part"], limit=mailfiles.MAX_DRIVE)
                    name = mailfiles.clean_name(it.get("name") or info["name"])
                    entry: dict[str, Any] = {"message_id": it["message_id"], "part": it["part"]}
                else:
                    name = mailfiles.clean_name(it.get("name", ""))
                    if "text" in it:
                        data = it["text"].encode("utf-8")
                    else:
                        data = _unb64(it["base64"], i)
                    if len(data) > mailfiles.MAX_INLINE:
                        raise ToolError(f"Attachment {i} ({name}) is over 1 MB; files that big can't be passed "
                                        "inline.")
                    entry = {"data": base64.b64encode(data).decode("ascii")}
                try:
                    mailfiles.check_sendable(name, data)
                    sendable = True
                except mailfiles.FileProblem as e:
                    sendable, why = False, str(e)
            except mailfiles.FileProblem as e:
                raise ToolError(f"Attachment {i}: {e}") from None
            entry.update({"name": name, "type": mailfiles.mime_type(name), "size": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()})
            if not sendable:
                entry["_blocked"] = why
            out.append(entry)
        if len({f["name"].lower() for f in out}) != len(out):
            raise ToolError("Two attachments have the same name; give each its own.")
        return out

    def _add_files(self, a: dict[str, Any], items: list[dict[str, Any]] | None, delivery: str) -> None:
        """Checked files, each with how it travels ("attach" or "drive"), and the Drive share list. The share list
        is computed here from To and Cc, never passed by the AI."""
        if delivery not in ("auto", "attach", "drive"):
            raise ToolError("delivery is auto, attach or drive.")
        files = self._files(items)
        blocked = [f for f in files if "_blocked" in f]
        if delivery == "attach":
            if blocked:
                raise ToolError(f"{blocked[0]['_blocked']} Use delivery drive to send it as a Google Drive link.")
            for f in files:
                f["delivery"] = "attach"
        elif delivery == "drive":
            for f in files:
                f["delivery"] = "drive"
        else:
            for f in files:
                f["delivery"] = "drive" if "_blocked" in f else "attach"
            for f in sorted([f for f in files if f["delivery"] == "attach"], key=lambda f: -f["size"]):
                if sum(x["size"] for x in files if x["delivery"] == "attach") <= mailfiles.MAX_TOTAL:
                    break
                f["delivery"] = "drive"            # the biggest files go by Drive until the rest fits
        for f in files:
            f.pop("_blocked", None)
        attached = sum(f["size"] for f in files if f["delivery"] == "attach")
        if attached > mailfiles.MAX_TOTAL:
            raise ToolError("The attachments are over 18 MB together, more than Gmail can send. Use delivery auto or "
                            "drive to send the big ones as Google Drive links.")
        drive = [f for f in files if f["delivery"] == "drive"]
        a["files"] = files
        a["share"] = []
        if not drive:
            return
        if any(f["size"] > mailfiles.MAX_DRIVE for f in drive):
            raise ToolError(f"Files over {mailfiles.size_text(mailfiles.MAX_DRIVE)} can't be sent, even by Drive.")
        if a["bcc"]:
            raise ToolError("Drive links can't go to Bcc recipients: everyone with access can see who else has it. "
                            "Send the Bcc recipients a separate email.")
        if not self._has_drive():
            raise ToolError(NO_DRIVE)
        a["share"] = sorted({addr.lower() for _, addr in email.utils.getaddresses(a["to"] + a["cc"]) if addr})

    def _has_drive(self) -> bool:
        if self._scopes is None:
            self._access = None
            self._token()
        return DRIVE_SCOPE in (self._scopes or set())

    def _file_bytes(self, f: dict[str, Any]) -> bytes:
        if "data" in f:
            data = base64.b64decode(f["data"])
        elif "path" in f:
            try:
                data = mailfiles.read_path(mailfiles.check_path(f["path"]), mailfiles.MAX_DRIVE)
            except mailfiles.FileProblem as e:
                raise ToolError(f"{f['name']}: {e} Nothing was sent.") from None
        else:
            _, data = self._part(f["message_id"], f["part"], limit=mailfiles.MAX_DRIVE)
        if len(data) != f["size"] or hashlib.sha256(data).hexdigest() != f["sha256"]:
            raise ToolError(f"{f['name']} changed after it was approved, so nothing was sent. Ask again.")
        return data

    def _part(self, mid: str, part: str, limit: int) -> tuple[dict[str, str], bytes]:
        """One attachment of an email by its part id (stable, unlike Gmail's attachment ids)."""
        m = self._get(f"/messages/{mid}", params={"format": "full"})
        p = _find_part(m.get("payload", {}), part)
        if p is None or not p.get("filename"):
            raise ToolError(f"That email has no attachment in part {part!r}. Use gmail_read to see its parts.")
        body = p.get("body", {})
        if int(body.get("size", 0) or 0) > limit:
            raise ToolError(f"{p['filename']} is too large ({mailfiles.size_text(int(body['size']))}).")
        if body.get("data"):
            raw = body["data"]
        elif body.get("attachmentId"):
            raw = self._get(f"/messages/{mid}/attachments/{body['attachmentId']}").get("data", "")
        else:
            raw = ""
        data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        if len(data) > limit:
            raise ToolError(f"{p['filename']} is too large ({mailfiles.size_text(len(data))}).")
        return {"name": p["filename"], "type": (p.get("mimeType") or "application/octet-stream").lower()}, data

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
        for f in a.get("files", []):
            if f.get("delivery") == "drive":
                continue
            maintype, _, subtype = f["type"].partition("/")
            msg.add_attachment(self._file_bytes(f), maintype=maintype, subtype=subtype, filename=f["name"])
        if a.get("forward_id"):
            raw = self._get(f"/messages/{a['forward_id']}", params={"format": "raw"})["raw"]
            msg.add_attachment(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)), maintype="message",
                               subtype="rfc822", filename="forwarded.eml")
        return msg

    def _send(self, a: dict[str, Any]) -> Any:
        return self._with_drive(a, self._send_mail)

    def _send_mail(self, a: dict[str, Any]) -> dict[str, Any]:
        raw = self._mime(a).as_bytes()
        meta: dict[str, Any] = {"threadId": a["thread_id"]} if a.get("thread_id") else {}
        if len(raw) > UPLOAD_OVER:
            r = self._upload("/messages/send", raw, meta)
        else:
            r = self._post("/messages/send", {"raw": _b64(raw), **meta})
        return {"sent": True, "message_id": r.get("id"), "thread_id": r.get("threadId")}

    def _draft(self, a: dict[str, Any]) -> Any:
        return self._with_drive(a, self._save_draft)

    def _save_draft(self, a: dict[str, Any]) -> dict[str, Any]:
        raw = self._mime(a).as_bytes()
        if len(raw) > UPLOAD_OVER:
            r = self._upload("/drafts", raw, {})
        else:
            r = self._post("/drafts", {"message": {"raw": _b64(raw)}})
        return {"draft_saved": True, "draft_id": r.get("id"), "note": "The user can review and send it from Gmail."}

    # -- Google Drive links ----------------------------------------------------------------

    def _with_drive(self, a: dict[str, Any], deliver: Callable[[dict[str, Any]], dict[str, Any]]) -> Any:
        """Upload → share with exactly the approved list → send. If anything fails, the shares are removed and the
        uploads trashed, so nothing stays shared for an email that never went out."""
        drive = [f for f in a.get("files", []) if f.get("delivery") == "drive"]
        done: list[dict[str, Any]] = []
        try:
            for f in drive:
                data = self._file_bytes(f)
                fid, link = self._drive_upload(f["name"], f["type"], data)
                item = {"name": f["name"], "size": f["size"], "file_id": fid, "link": link, "perms": [],
                        "invited": []}
                done.append(item)
                for addr in a["share"]:
                    pid, invited = self._drive_share(fid, addr)
                    item["perms"].append(pid)
                    if invited:
                        item["invited"].append(addr)
            if done:
                a = dict(a, body=_with_links(a["body"], done))
            out = deliver(a)
        except Exception:
            for item in done:
                self._drive_undo(item)
            raise
        attached = [f for f in a.get("files", []) if f.get("delivery") != "drive"]
        if attached:
            out["attachments"] = len(attached)
        if done:
            out["drive_links"] = [{"name": d["name"], "link": d["link"], "file_id": d["file_id"]} for d in done]
            out["shared_with"] = a["share"]
            invited = sorted({x for d in done for x in d["invited"]})
            if invited:
                out["note"] = ("Google also emailed its own sharing invitation to " + ", ".join(invited) +
                               " (no Google account found for them).")
        return out

    def _drive(self, method: str, url: str, **kw: Any) -> httpx.Response:
        for attempt in (1, 2):
            headers = {"Authorization": f"Bearer {self._token()}", **kw.pop("headers", {})}
            r = self.http.request(method, url, headers=headers, **kw)
            if r.status_code == 401 and attempt == 1:
                self._access = None
                kw["headers"] = {k: v for k, v in headers.items() if k != "Authorization"}
                continue
            return r
        return r

    def _drive_ok(self, r: httpx.Response) -> dict[str, Any]:
        if r.status_code < 300:
            return _json(r) if r.content else {}
        err = _json(r).get("error")
        reasons = [e.get("reason", "") for e in (err.get("errors") or [])] if isinstance(err, dict) else []
        if "accessNotConfigured" in reasons or "SERVICE_DISABLED" in r.text:
            raise ToolError("The Google Drive API is turned off in the user's Google Cloud project. Ask them to "
                            "enable it (Google Cloud console, APIs & Services, Library, Google Drive API).")
        if r.status_code in (401, 403) and ("insufficient" in r.text.lower() or "scope" in r.text.lower()):
            raise ToolError(NO_DRIVE)
        if r.status_code == 404:
            raise ToolError("Google Drive says that file doesn't exist (or wasn't shared by aiSecurityWarden).")
        if r.status_code == 429 or r.status_code >= 500:
            raise ToolError(f"Google Drive is busy or unavailable ({r.status_code}); try again in a minute.")
        msg = err.get("message", "") if isinstance(err, dict) else ""
        raise ToolError(f"Google Drive refused the request ({r.status_code}{': ' + msg[:200] if msg else ''}).")

    def _drive_folder(self) -> str:
        if self._folder:
            return self._folder
        q = (f"name = '{DRIVE_FOLDER}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false "
             "and 'root' in parents")
        found = self._drive_ok(self._drive("GET", DRIVE + "/files", params={"q": q, "fields": "files(id)",
                                                                             "spaces": "drive"})).get("files") or []
        if found:
            self._folder = found[0]["id"]
        else:
            self._folder = self._drive_ok(self._drive("POST", DRIVE + "/files", params={"fields": "id"}, json={
                "name": DRIVE_FOLDER, "mimeType": "application/vnd.google-apps.folder",
                "appProperties": {"aisecuritywarden": "1"}}))["id"]
        return self._folder

    def _drive_upload(self, name: str, mime: str, data: bytes) -> tuple[str, str]:
        folder = self._drive_folder()
        start = self._drive("POST", DRIVE_UPLOAD + "/files", params={"uploadType": "resumable"},
                            headers={"X-Upload-Content-Type": mime, "X-Upload-Content-Length": str(len(data))},
                            json={"name": name, "parents": [folder], "appProperties": {"aisecuritywarden": "1"}})
        self._drive_ok(start)
        session = start.headers.get("Location", "")
        if not session.startswith(DRIVE_UPLOAD):
            raise ToolError("Google Drive didn't start the upload.")
        done = self._drive_ok(self._drive("PUT", session, content=data, headers={"Content-Type": mime}))
        fid = done.get("id", "")
        if not DRIVE_ID_RE.match(fid):
            raise ToolError("Google Drive's upload reply was incomplete.")
        meta = self._drive_ok(self._drive("GET", f"{DRIVE}/files/{fid}", params={"fields": "id,webViewLink"}))
        return fid, meta.get("webViewLink") or f"https://drive.google.com/file/d/{fid}/view"

    def _drive_share(self, fid: str, addr: str) -> tuple[str, bool]:
        """View-only access for one person. Only ever type "user": never "anyone" or "domain"."""
        body = {"type": "user", "role": "reader", "emailAddress": addr}
        r = self._drive("POST", f"{DRIVE}/files/{fid}/permissions",
                        params={"sendNotificationEmail": "false", "fields": "id"}, json=body)
        invited = False
        if r.status_code == 400 and "invalidSharingRequest" in r.text:
            # no Google account for this address: Google only allows sharing with its own invitation email
            r = self._drive("POST", f"{DRIVE}/files/{fid}/permissions",
                            params={"sendNotificationEmail": "true", "fields": "id"}, json=body)
            invited = True
        return self._drive_ok(r)["id"], invited

    def _drive_undo(self, item: dict[str, Any]) -> None:
        try:
            for pid in item["perms"]:
                self._drive("DELETE", f"{DRIVE}/files/{item['file_id']}/permissions/{pid}")
            self._drive("PATCH", f"{DRIVE}/files/{item['file_id']}", json={"trashed": True})
        except Exception as e:  # noqa: BLE001 - best effort; the error that matters is the original one
            print(f"sw-mcp: gmail: couldn't undo a Drive share ({type(e).__name__})", file=sys.stderr)

    def _upload(self, path: str, raw: bytes, meta: dict[str, Any]) -> dict[str, Any]:
        """A big email through Gmail's upload endpoint (a JSON body is limited to a few MB)."""
        if path == "/drafts":
            meta = {"message": meta}
        boundary = "sw-" + uuid.uuid4().hex
        while boundary.encode() in raw:
            boundary = "sw-" + uuid.uuid4().hex
        content = (f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{json.dumps(meta)}\r\n"
                   f"--{boundary}\r\nContent-Type: message/rfc822\r\n\r\n").encode() + raw + \
            f"\r\n--{boundary}--\r\n".encode()
        return self._call("POST", path, base=UPLOAD, params={"uploadType": "multipart"}, content=content,
                          extra_headers={"Content-Type": f"multipart/related; boundary={boundary}"})

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
        if isinstance(data.get("scope"), str):
            self._scopes = set(data["scope"].split())
        elif self._scopes is None:
            self._scopes = {GMAIL_SCOPE}
        self._access_exp = time.monotonic() + max(0, int(data.get("expires_in", 3600)) - 60)
        return self._access

    def _call(self, method: str, path: str, base: str = API, extra_headers: dict[str, str] | None = None,
              **kw: Any) -> dict[str, Any]:
        for attempt in (1, 2):
            r = self.http.request(method, base + path,
                                  headers={"Authorization": f"Bearer {self._token()}", **(extra_headers or {})}, **kw)
            if r.status_code == 401 and attempt == 1:
                self._access = None
                continue
            if r.status_code == 404:
                raise ToolError("Gmail says that message, thread or label doesn't exist.")
            if r.status_code == 413:
                raise ToolError("Gmail says the email is too large.")
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
        """Google sign-in in the browser (loopback + PKCE), once. The refresh token goes to aiSecurityWarden."""
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
                self.wfile.write(b"<p>aiSecurityWarden: done. You can close this tab and go back to the terminal.</p>")
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


def _with_links(body: str, items: list[dict[str, Any]]) -> str:
    lines = [f"- {d['name']} ({mailfiles.size_text(d['size'])}): {d['link']}" for d in items]
    return (body.rstrip() + "\n\n" if body.strip() else "") + (
        "Files on Google Drive, shared with you only (sign in to Google with this email address to open them; a "
        "free Google account can use any email address):\n" + "\n".join(lines) + "\n")


def _check_part(part: str) -> str:
    if not isinstance(part, str) or not PART_RE.match(part):
        raise ToolError(f"{part!r} isn't an attachment part (use the part from gmail_read, like \"1\").")
    return part


def _find_part(payload: dict[str, Any], part: str) -> dict[str, Any] | None:
    stack = [payload]
    while stack:
        p = stack.pop()
        if p.get("partId") == part:
            return p
        stack.extend(p.get("parts", []) or [])
    return None


def _unb64(text: str, i: int) -> bytes:
    t = re.sub(r"\s+", "", text)
    if t.startswith("data:") and "," in t:
        t = t.split(",", 1)[1]          # a data: URL
    try:
        return base64.b64decode(t + "=" * (-len(t) % 4), altchars=b"-_" if ("-" in t or "_" in t) else None,
                                validate=True)
    except ValueError:
        raise ToolError(f"Attachment {i}: base64 isn't valid.") from None


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
    def describe(f: dict[str, Any]) -> str:
        return (f"{f['name']} · {mailfiles.size_text(f['size'])} · {f['type']} · sha {f['sha256'][:8]}"
                + (" · from an email" if "message_id" in f else "")
                + (f" · file {f['path']}" if "path" in f else ""))
    attached = [f for f in a.get("files", []) if f.get("delivery") != "drive"]
    drive = [f for f in a.get("files", []) if f.get("delivery") == "drive"]
    if attached:
        fields.append((f"Attachments ({len(attached)})", "; ".join(describe(f) for f in attached)))
    if drive:
        fields.append((f"Drive links ({len(drive)})", "; ".join(describe(f) for f in drive)))
        fields.append(("Drive: view only for", ", ".join(a["share"])))
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
            attachments.append({"name": part["filename"], "type": mime, "size": body.get("size", 0),
                                "part": part.get("partId", "")})
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


def _has_token(args: Any) -> bool:
    """Whether this machine has an aiSecurityWarden token to read the OAuth client from: a token file, the
    environment, or SW_Tokens.json (the named token, or the only one there)."""
    if getattr(args, "token_file", None) or os.environ.get("SW_ACCESS_TOKEN_FILE") or os.environ.get("SW_ACCESS_TOKEN"):
        return True
    from ..client.tokens import TokenStore
    try:
        store = TokenStore()
        return store.pick(getattr(args, "token_name", None) or os.environ.get("SW_TOKEN_NAME"),
                          token_id=getattr(args, "token_id", None) or os.environ.get("SW_TOKEN_ID"),
                          server=getattr(args, "server", None) or os.environ.get("SW_SERVER_URL")) is not None
    except Exception:  # noqa: BLE001 - e.g. several tokens and none named: ask instead
        return False


def _oauth_client(args: Any) -> tuple[str, str]:
    """The OAuth client id and secret: from the bot's aiSecurityWarden project if a token is set up, else asked."""
    from .cli import _client, _config
    if _has_token(args):
        try:
            s = _client(args, _config(args)).fetch()
            if s.get("GMAIL_CLIENT_ID") and s.get("GMAIL_CLIENT_SECRET"):
                print("Using GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET from aiSecurityWarden.", file=sys.stderr)
                return s["GMAIL_CLIENT_ID"], s["GMAIL_CLIENT_SECRET"]
        except Exception as e:  # noqa: BLE001
            print(f"sw-mcp: couldn't read them from aiSecurityWarden ({e}); asking instead.", file=sys.stderr)
    print("Google OAuth client ID: ", end="", file=sys.stderr, flush=True)   # stdout carries only the token
    cid = input().strip()
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
        from ..client.cli import TerminalSecondFactor
        admin = SecurityWardenClient(url, _read_cred_file(path), second_factor=TerminalSecondFactor(),
                                     verify=getattr(args, "ca_bundle", None) or os.environ.get("SW_CA_BUNDLE") or True)
        admin.set_secret(args.project, "GMAIL_REFRESH_TOKEN", token)
        print(f"Signed in as {who}. Stored GMAIL_REFRESH_TOKEN in project {args.project}.", file=sys.stderr)
        return
    print(f"Signed in as {who}.\n\nAdd this to the bot's aiSecurityWarden project as the secret GMAIL_REFRESH_TOKEN "
          "(website: the project's Secrets tab). It's shown once and gives access to the mailbox: don't save it "
          "anywhere else, and clear this terminal afterwards.\n", file=sys.stderr)
    print(token)
    sys.stdout.flush()
