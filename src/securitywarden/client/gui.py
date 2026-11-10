"""swadmin — a desktop admin window for SecurityWarden.

Tkinter only (standard library), so it runs wherever the client does. It is a thin
window over :class:`SecurityWardenClient`: all encryption still happens in
``securitywarden.crypto`` on this machine, and the server sees exactly what it sees
from ``swctl``.

The admin credential and secret values are typed or pasted into the window. They are
held in memory only: never written to disk, argv, the environment or shell history.
The only thing remembered between runs is the server URL. When the server requires a
second factor for the admin credential (the default), the window asks for the code from
the authenticator app (and sets the app up the first time); the 2FA session it starts is
kept in memory too and ended on sign-out.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime
from typing import Any, Callable

import httpx

from .. import __version__, crypto
from ..approval import CHANNELS, DEFAULTS, describe, normalize_policy
from ..crypto import CryptoError
from .api import SecurityWardenClient, SecurityWardenError, action_lines
from .cli import ENV_NAME_RE

try:  # Tk is optional on some Linux installs (python3-tk)
    import tkinter as tk
    from tkinter import messagebox, simpledialog, ttk
except ImportError:  # pragma: no cover
    tk = None  # type: ignore[assignment]

CONFIG_FILE = os.path.join("~", ".config", "securitywarden", "admin-ui.json")
IDLE_LOCK_SECONDS = 15 * 60
CLIPBOARD_CLEAR_SECONDS = 60
APPROVAL_POLL_SECONDS = 4
PAD = 8

def _what(a: dict[str, Any]) -> str:
    if a["kind"] == "action":
        summary = a.get("summary")
        title = summary.get("title") if isinstance(summary, dict) else None
        return f"{title} ({a['action']})" if isinstance(title, str) else f"{a['action']} (details unavailable)"
    what = "start a session" if a["kind"] == "auth" else "read secrets"
    origin = a.get("origin")
    return f"{what} (started by {' <- '.join(origin)})" if isinstance(origin, list) and origin else what


APPROVAL_MODES = {"No approval": None, "Once per session": "session", "Every fetch": "every_fetch"}
CHANNEL_LABELS = {"admin_ui": "This admin window", "push:ntfy": "ntfy push", "push:telegram": "Telegram",
                  "push:discord": "Discord"}


# ---------------------------------------------------------------------------
# helpers (no Tk)
# ---------------------------------------------------------------------------

def split_addresses(text: str) -> list[str] | None:
    """Addresses typed one per line or separated by commas/spaces; nothing typed means 'any'."""
    parts = [p for p in re.split(r"[\s,;]+", text.strip()) if p]
    return parts or None


def token_state(t: dict[str, Any], at: float | None = None) -> str:
    if t.get("revoked_at"):
        return "revoked"
    if t.get("expires_at") and t["expires_at"] <= (time.time() if at is None else at):
        return "expired"
    return "active"


def approval_policy(mode_label: str, session_hours: str, channels: list[str], timeout: str = "120",
                    per_hour: str = "6", pending: str = "1", base: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Policy from the token dialogs. Raises ValueError with a message for the user.

    ``base`` is the token's current policy: a field the dialog leaves alone (the session length
    while "Every fetch" is chosen) keeps its value instead of falling back to the default."""
    mode = APPROVAL_MODES.get(mode_label)
    if mode is None:
        return None
    if not channels:
        raise ValueError("Choose at least one place where approval requests should go.")
    policy: dict[str, Any] = {**DEFAULTS, **(base or {}), "mode": mode,
                              "channels": [c for c in CHANNELS if c in channels]}
    if mode == "session":
        try:
            hours = float(session_hours)
        except ValueError:
            hours = -1
        if not 0 < hours <= 168:
            raise ValueError("Session length must be a number of hours (up to 168).")
        policy["session_ttl"] = max(60, int(hours * 3600))
    for key, text, label in (("timeout", timeout, "Wait for a decision"), ("max_per_hour", per_hour, "Requests per hour"),
                             ("max_pending", pending, "Pending at once")):
        t = str(text).strip()
        if key != "max_pending" and t.lower() in ("", "none", "no limit"):
            policy[key] = None          # no limit (blank in the dialog)
            continue
        try:
            policy[key] = int(t)
        except ValueError:
            raise ValueError(f"{label} must be a whole number (blank: no limit).") from None
    return normalize_policy(policy)


def approval_summary(t: dict[str, Any]) -> str:
    """The token list's Approval column, with how much of the hourly limit is used."""
    p = t.get("approval")
    if not p:
        return "none"
    n = t.get("approvals_this_hour", 0)
    if p.get("max_per_hour") is None:
        return f"{describe(p)} · {n} this hour (no hourly limit)"
    return f"{describe(p)} · {n}/{p['max_per_hour']} this hour"


def fmt_time(v: int | None) -> str:
    return datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M") if v else "—"


def load_server_url() -> str:
    try:
        with open(os.path.expanduser(CONFIG_FILE), encoding="utf-8") as f:
            return str(json.load(f).get("server", ""))
    except (OSError, ValueError, AttributeError):
        return os.environ.get("SW_SERVER_URL", "")


def save_server_url(url: str) -> None:
    path = os.path.expanduser(CONFIG_FILE)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"server": url}, f)
    except OSError:
        pass  # remembering the URL is a convenience only


# ---------------------------------------------------------------------------
# the window
# ---------------------------------------------------------------------------

class AdminApp:
    """One window: a sign-in page, then projects on the left and their secrets/tokens on the right.

    Button handlers only gather input and confirm; the work is in the plain methods
    (``create_project``, ``save_secret``, ``create_token`` ...) so it can be tested without clicking.
    """

    def __init__(self, root: "tk.Tk", connect: Callable[[str, str], SecurityWardenClient] | None = None):
        self.root = root
        self.connect = connect or (lambda url, cred: SecurityWardenClient(url, cred,
                                                                          second_factor=TkSecondFactor(self)))
        self.client: SecurityWardenClient | None = None
        self.server = ""
        self.projects: list[dict[str, Any]] = []
        self.tokens: list[dict[str, Any]] = []
        self.approvals: list[dict[str, Any]] = []
        self._idle_job: str | None = None
        self._poll_job: str | None = None

        root.title("aiSecurityWarden Admin")
        root.geometry("980x600")
        root.minsize(760, 440)
        self.body = ttk.Frame(root)
        self.body.pack(fill="both", expand=True)
        root.bind_all("<Any-KeyPress>", self._touch, add="+")
        root.bind_all("<Any-ButtonPress>", self._touch, add="+")
        self.show_login()

    # -- plumbing -----------------------------------------------------------------

    def error(self, message: str) -> None:
        messagebox.showerror("aiSecurityWarden", message, parent=self.root)

    def confirm(self, title: str, message: str) -> bool:
        return messagebox.askyesno(title, message, icon="warning", default="no", parent=self.root)

    def _call(self, fn: Callable[[], Any]) -> tuple[bool, Any]:
        """Run a client call; report a failure in a dialog instead of raising."""
        self.root.config(cursor="watch")
        self.root.update_idletasks()
        try:
            return True, fn()
        except (SecurityWardenError, CryptoError) as e:
            self.error(str(e))
        except httpx.HTTPError as e:
            self.error(f"Could not reach the server: {e}")
        finally:
            self.root.config(cursor="")
        return False, None

    def _clear_body(self) -> None:
        for w in self.body.winfo_children():
            w.destroy()

    def _touch(self, _event: Any = None) -> None:
        if self._idle_job:
            self.root.after_cancel(self._idle_job)
            self._idle_job = None
        if self.client:
            self._idle_job = self.root.after(IDLE_LOCK_SECONDS * 1000, self.disconnect)

    def copy_then_clear(self, value: str) -> None:
        """Put a secret on the clipboard and take it off again after a minute if it is still there."""
        self.root.clipboard_clear()
        self.root.clipboard_append(value)

        def clear() -> None:
            try:
                if self.root.clipboard_get() == value:
                    self.root.clipboard_clear()
                    self.root.clipboard_append("")
            except tk.TclError:
                pass

        self.root.after(CLIPBOARD_CLEAR_SECONDS * 1000, clear)

    # -- sign in ----------------------------------------------------------------------

    def show_login(self, message: str = "") -> None:
        self._clear_body()
        box = ttk.Frame(self.body, padding=24)
        box.place(relx=0.5, rely=0.45, anchor="center")
        ttk.Label(box, text="aiSecurityWarden", font=("", 16, "bold")).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(box, text=f"Admin  ·  v{__version__}").grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 16))

        ttk.Label(box, text="Server address").grid(row=2, column=0, sticky="w")
        self.url_var = tk.StringVar(value=self.server or load_server_url())
        url = ttk.Entry(box, textvariable=self.url_var, width=52)
        url.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(2, 12))

        ttk.Label(box, text="Admin credential").grid(row=4, column=0, sticky="w")
        self.cred_var = tk.StringVar()
        cred = ttk.Entry(box, textvariable=self.cred_var, width=52, show="•")
        cred.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(2, 4))
        ttk.Label(box, text="Paste it from your password manager. It is kept in memory only.",
                  foreground="#666").grid(row=6, column=0, columnspan=2, sticky="w", pady=(0, 12))

        self.login_msg = ttk.Label(box, text=message, foreground="#b00020", wraplength=420, justify="left")
        self.login_msg.grid(row=7, column=0, columnspan=2, sticky="w")
        ttk.Button(box, text="Sign in", command=self._on_sign_in).grid(row=8, column=1, sticky="e", pady=(8, 0))
        cred.bind("<Return>", lambda _e: self._on_sign_in())
        url.bind("<Return>", lambda _e: cred.focus_set())
        (cred if self.url_var.get() else url).focus_set()

    def _on_sign_in(self) -> None:
        problem = self.sign_in(self.url_var.get(), self.cred_var.get())
        if problem:
            self.login_msg.config(text=problem)

    def sign_in(self, url: str, credential: str) -> str | None:
        """Returns None on success, otherwise a message for the sign-in page."""
        url, credential = url.strip(), credential.strip()
        if not url or not credential:
            return "Enter the server address and the admin credential."
        try:
            client = self.connect(url, credential)
            if client.cred.kind != crypto.KIND_ADMIN:
                return "That is a machine token. Sign in with the admin credential."
            projects = client.list_projects()
        except (SecurityWardenError, CryptoError) as e:
            return str(e)
        except httpx.HTTPError as e:
            return f"Could not reach the server: {e}"
        self.client, self.server, self.projects = client, url, projects
        save_server_url(url)
        self.show_main()
        self._touch()
        return None

    def disconnect(self) -> None:
        if self._poll_job:
            self.root.after_cancel(self._poll_job)
            self._poll_job = None
        if self.client:
            self.client.sign_out()     # ends the 2FA session on the server too
        self.client, self.projects, self.tokens, self.approvals = None, [], [], []
        self._touch()
        self.show_login()

    def _on_two_factor(self) -> None:
        assert self.client
        ok, st = self._call(self.client.second_factor_status)
        if not ok:
            return
        if not st["enabled"]:
            messagebox.showinfo("Two-factor sign-in", "Two-factor sign-in is off for this admin credential "
                                "(the server doesn't require it).", parent=self.root)
            return
        if not messagebox.askyesno("Two-factor sign-in",
                                   f"Two-factor sign-in is on. Recovery codes left: {st['recovery_codes_left']}.\n\n"
                                   "Make new recovery codes? The old ones stop working.", parent=self.root):
            return
        code = simpledialog.askstring("New recovery codes", "Current code from your authenticator app:", parent=self.root)
        if not code:
            return
        ok, codes = self._call(lambda: self.client.new_recovery_codes(code.strip()))
        if ok:
            TkSecondFactor(self).recovery_codes(codes)

    # -- main page --------------------------------------------------------------------

    def show_main(self) -> None:
        self._clear_body()
        top = ttk.Frame(self.body, padding=(PAD, PAD, PAD, 0))
        top.pack(fill="x")
        ttk.Label(top, text=f"Signed in to {self.server}").pack(side="left")
        ttk.Button(top, text="Sign out", command=self.disconnect).pack(side="right")
        ttk.Button(top, text="Two-factor…", command=self._on_two_factor).pack(side="right", padx=(0, PAD))
        ttk.Button(top, text="Refresh", command=self.refresh).pack(side="right", padx=(0, PAD))

        panes = ttk.Panedwindow(self.body, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=PAD, pady=PAD)

        left = ttk.Labelframe(panes, text="Projects", padding=PAD)
        self.project_list = tk.Listbox(left, exportselection=False, activestyle="none", width=26)
        self.project_list.pack(fill="both", expand=True)
        self.project_list.bind("<<ListboxSelect>>", lambda _e: self.load_project())
        row = ttk.Frame(left)
        row.pack(fill="x", pady=(PAD, 0))
        ttk.Button(row, text="New project…", command=self._on_new_project).pack(side="left")
        ttk.Button(row, text="Delete…", command=self._on_delete_project).pack(side="right")
        panes.add(left, weight=0)

        self.tabs = ttk.Notebook(panes)
        panes.add(self.tabs, weight=1)

        secrets = ttk.Frame(self.tabs, padding=PAD)
        self.secret_tree = self._tree(secrets, [("name", "Name", 420)])
        row = ttk.Frame(secrets)
        row.pack(fill="x", pady=(PAD, 0))
        ttk.Button(row, text="Add secret…", command=self._on_add_secret).pack(side="left")
        ttk.Button(row, text="Change value…", command=self._on_change_secret).pack(side="left", padx=PAD)
        ttk.Button(row, text="Show value…", command=self._on_reveal_secret).pack(side="left")
        ttk.Button(row, text="Delete…", command=self._on_delete_secret).pack(side="right")
        self.tabs.add(secrets, text="Secrets")

        tokens = ttk.Frame(self.tabs, padding=PAD)
        self.token_tree = self._tree(tokens, [
            ("name", "Name", 170), ("state", "Status", 70), ("expires", "Expires", 120),
            ("used", "Last used", 120), ("ip", "Last address", 110), ("allowed", "Allowed from", 170),
            ("approval", "Approval", 200)])
        self.token_tree.tag_configure("off", foreground="#888")
        row = ttk.Frame(tokens)
        row.pack(fill="x", pady=(PAD, 0))
        ttk.Button(row, text="New token…", command=self._on_new_token).pack(side="left")
        ttk.Button(row, text="Change addresses…", command=self._on_change_ips).pack(side="left", padx=PAD)
        ttk.Button(row, text="Change approval…", command=self._on_change_approval).pack(side="left")
        ttk.Button(row, text="Reset approval limit…", command=self._on_reset_approval).pack(side="left", padx=PAD)
        ttk.Button(row, text="Revoke…", command=self._on_revoke_token).pack(side="right")
        self.tabs.add(tokens, text="Tokens")

        approvals = ttk.Frame(self.tabs, padding=PAD)
        self.approval_tree = self._tree(approvals, [
            ("token", "Token", 160), ("match", "Match code", 90), ("wants", "Wants to", 130),
            ("ip", "From", 120), ("expires", "Expires", 80), ("via", "Can be decided", 200)])
        self.approval_tree.tag_configure("off", foreground="#888")
        row = ttk.Frame(approvals)
        row.pack(fill="x", pady=(PAD, 0))
        ttk.Button(row, text="Approve…", command=lambda: self._on_decide(True)).pack(side="left")
        ttk.Button(row, text="Deny", command=lambda: self._on_decide(False)).pack(side="left", padx=PAD)
        ttk.Label(row, text="Approve only if the machine shows the same match code.",
                  foreground="#666").pack(side="left", padx=PAD)
        self.approvals_tab = approvals
        self.tabs.add(approvals, text="Approvals")

        activity = ttk.Frame(self.tabs, padding=PAD)
        self.audit_tree = self._tree(activity, [
            ("time", "Time", 120), ("ok", "Result", 60), ("action", "Action", 120),
            ("who", "Credential", 170), ("ip", "Address", 110), ("detail", "Detail", 240)])
        self.audit_tree.tag_configure("fail", foreground="#b00020")
        ttk.Label(activity, text="Most recent first, all projects.", foreground="#666").pack(anchor="w", pady=(PAD, 0))
        self.activity_tab = activity
        self.tabs.add(activity, text="Activity")
        self.tabs.bind("<<NotebookTabChanged>>", lambda _e: self._on_tab())

        self._fill_projects()
        self._poll_approvals()

    def _tree(self, parent: Any, columns: list[tuple[str, str, int]]) -> "ttk.Treeview":
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", selectmode="browse")
        for key, title, width in columns:
            last = key == columns[-1][0]
            # the last column may grow to fill the window but never shrink below its width,
            # so columns that don't fit are reached with the horizontal scrollbar, not clipped
            tree.heading(key, text=title, anchor="w")
            tree.column(key, width=width, minwidth=width if last else 40, anchor="w", stretch=last)
        ybar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        xbar = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return tree

    # -- data -------------------------------------------------------------------------

    @property
    def project(self) -> str | None:
        sel = self.project_list.curselection()
        return self.projects[sel[0]]["name"] if sel else None

    def _fill_projects(self, select: str | None = None) -> None:
        self.project_list.delete(0, "end")
        for p in self.projects:
            self.project_list.insert("end", p["name"])
        names = [p["name"] for p in self.projects]
        if names:
            i = names.index(select) if select in names else 0
            self.project_list.selection_set(i)
            self.project_list.see(i)
        self.load_project()

    def refresh(self) -> None:
        current = self.project
        ok, projects = self._call(self.client.list_projects)
        if ok:
            self.projects = projects
            self._fill_projects(current)
            self.load_audit()

    def load_project(self) -> None:
        self.secret_tree.delete(*self.secret_tree.get_children())
        self.token_tree.delete(*self.token_tree.get_children())
        self.tokens = []
        name = self.project
        if not name:
            return
        ok, secrets = self._call(lambda: self.client.get_secrets(name))
        if ok:
            for n in sorted(secrets):
                self.secret_tree.insert("", "end", iid=n, values=(n,))
            del secrets  # names are all the list needs; don't keep the values around
        ok, tokens = self._call(lambda: self.client.list_tokens(name))
        if ok:
            self.tokens = tokens
            for t in tokens:
                state = token_state(t)
                self.token_tree.insert("", "end", iid=t["id"], tags=() if state == "active" else ("off",), values=(
                    t["name"], state, fmt_time(t["expires_at"]) if t["expires_at"] else "never",
                    fmt_time(t["last_used_at"]), t["last_ip"] or "—",
                    ", ".join(t.get("allowed_ips") or []) or "any address", approval_summary(t)))

    def load_audit(self) -> None:
        self.audit_tree.delete(*self.audit_tree.get_children())
        ok, rows = self._call(lambda: self.client.audit(200))
        if not ok:
            return
        names = {t["id"]: t["name"] for t in self.tokens}
        names[self.client.cred.id] = "admin"
        for e in rows:
            self.audit_tree.insert("", "end", tags=() if e["ok"] else ("fail",), values=(
                fmt_time(e["ts"]), "ok" if e["ok"] else "REFUSED", e["action"],
                names.get(e["cred_id"], e["cred_id"] or "—"), e["ip"] or "—", e["detail"] or ""))

    def load_approvals(self, quiet: bool = False) -> bool:
        """Refresh the pending-approvals list. ``quiet`` (background polling) shows no error dialogs."""
        if not self.client:
            return False
        if quiet:
            try:
                rows = self.client.list_approvals()
            except (SecurityWardenError, CryptoError, httpx.HTTPError):
                return False
        else:
            ok, rows = self._call(self.client.list_approvals)
            if not ok:
                return False
        # encrypted summaries are decrypted here, once per request
        cache = getattr(self, "_summaries", {})
        self._summaries = {}
        for a in rows:
            if a["kind"] == "action" and not a.get("summary") and a.get("summary_enc"):
                if a["id"] not in cache:
                    try:
                        cache[a["id"]] = self.client.action_summary(a)
                    except (SecurityWardenError, CryptoError, httpx.HTTPError):
                        continue        # try again on the next refresh
                self._summaries[a["id"]] = a["summary"] = cache[a["id"]]
        self.approvals = rows
        keep = self.approval_tree.selection()
        self.approval_tree.delete(*self.approval_tree.get_children())
        for a in rows:
            self.approval_tree.insert("", "end", iid=a["id"], tags=() if a["decidable"] else ("off",), values=(
                a["token_name"], a["match"], _what(a),
                a["ip"], f"{max(0, a['expires_at'] - int(time.time()))} s",
                "here" if a["decidable"] else ", ".join(CHANNEL_LABELS.get(c, c) for c in a["channels"])))
        for iid in keep:
            if self.approval_tree.exists(iid):
                self.approval_tree.selection_set(iid)
        n = sum(1 for a in rows if a["decidable"])
        self.tabs.tab(self.approvals_tab, text=f"Approvals ({n})" if n else "Approvals")
        return True

    def _poll_approvals(self) -> None:
        self._poll_job = None
        if not self.client:
            return
        before = {a["id"] for a in self.approvals if a["decidable"]}
        if self.load_approvals(quiet=True):
            new = {a["id"] for a in self.approvals if a["decidable"]} - before
            if new:  # get the operator's attention without stealing focus
                self.root.bell()
        self._poll_job = self.root.after(APPROVAL_POLL_SECONDS * 1000, self._poll_approvals)

    def _on_tab(self) -> None:
        current = self.tabs.nametowidget(self.tabs.select())
        if current is self.activity_tab:
            self.load_audit()
        elif current is self.approvals_tab:
            self.load_approvals()

    # -- actions (no dialogs; safe to call from tests) ----------------------------------

    def create_project(self, name: str) -> bool:
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name):
            self.error("Project names may use letters, digits, dot, dash and underscore.")
            return False
        ok, _ = self._call(lambda: self.client.create_project(name))
        if ok:
            ok, self.projects = self._call(self.client.list_projects)
            self._fill_projects(name)
        return ok

    def delete_project(self, name: str) -> bool:
        ok, _ = self._call(lambda: self.client.delete_project(name))
        if ok:
            ok, self.projects = self._call(self.client.list_projects)
            self._fill_projects()
        return ok

    def save_secret(self, name: str, value: str) -> bool:
        name = name.strip()
        if not ENV_NAME_RE.match(name):
            self.error("Secret names must be valid environment variable names: letters, digits and "
                       "underscore, not starting with a digit (for example WEBULL_APP_KEY).")
            return False
        if not value:
            self.error("The value is empty.")
            return False
        project = self.project
        ok, _ = self._call(lambda: self.client.set_secret(project, name, value))
        if ok:
            self.load_project()
        return ok

    def reveal_secret(self, name: str) -> str | None:
        project = self.project
        ok, secrets = self._call(lambda: self.client.get_secrets(project))
        return secrets.get(name) if ok else None

    def delete_secret(self, name: str) -> bool:
        project = self.project
        ok, _ = self._call(lambda: self.client.delete_secret(project, name))
        if ok:
            self.load_project()
        return ok

    def create_token(self, name: str, expires_days: str, addresses: str,
                     approval: dict[str, Any] | None = None) -> str | None:
        """Returns the full token string (shown once) or None."""
        name = name.strip()
        if not name:
            self.error("Give the token a name, such as the machine that will use it.")
            return None
        days: float | None = None
        if expires_days.strip():
            try:
                days = float(expires_days)
            except ValueError:
                days = -1
            if days <= 0:
                self.error("Expiry must be a number of days, or blank for a token that never expires.")
                return None
        project, ips = self.project, split_addresses(addresses)
        ok, tok = self._call(lambda: self.client.create_token(project, name, days, ips, approval))
        if not ok:
            return None
        self.load_project()
        return str(tok)

    def set_token_ips(self, token_id: str, addresses: str) -> bool:
        ips = split_addresses(addresses)
        ok, _ = self._call(lambda: self.client.set_token_ips(token_id, ips))
        if ok:
            self.load_project()
        return ok

    def set_token_approval(self, token_id: str, approval: dict[str, Any] | None) -> bool:
        ok, _ = self._call(lambda: self.client.set_token_approval(token_id, approval))
        if ok:
            self.load_project()
        return ok

    def reset_approval_limits(self, token_id: str) -> bool:
        ok, _ = self._call(lambda: self.client.reset_approval_limits(token_id))
        if ok:
            self.load_project()
            self.load_approvals(quiet=True)
        return ok

    def decide(self, approval_id: str, approve: bool) -> bool:
        ok, _ = self._call(lambda: self.client.decide_approval(approval_id, approve))
        self.load_approvals()
        if ok:
            self.load_audit()
        return ok

    def revoke_token(self, token_id: str) -> bool:
        ok, _ = self._call(lambda: self.client.revoke_token(token_id))
        if ok:
            self.load_project()
        return ok

    # -- button handlers ----------------------------------------------------------------

    def _selected(self, tree: "ttk.Treeview", what: str) -> str | None:
        sel = tree.selection()
        if not sel:
            messagebox.showinfo("aiSecurityWarden", f"Select a {what} first.", parent=self.root)
            return None
        return sel[0]

    def _need_project(self) -> bool:
        if self.project:
            return True
        messagebox.showinfo("SecurityWarden", "Create or select a project first.", parent=self.root)
        return False

    def _on_new_project(self) -> None:
        name = simpledialog.askstring("New project", "Project name (for example hermes-webull):", parent=self.root)
        if name:
            self.create_project(name)

    def _on_delete_project(self) -> None:
        name = self.project
        if name and self.confirm("Delete project", f"Delete “{name}”?\n\nThis destroys all of its secrets and "
                                 "revokes all of its tokens. It cannot be undone."):
            self.delete_project(name)

    def _on_add_secret(self) -> None:
        if self._need_project():
            SecretDialog(self, None)

    def _on_change_secret(self) -> None:
        name = self._selected(self.secret_tree, "secret")
        if name:
            SecretDialog(self, name)

    def _on_reveal_secret(self) -> None:
        name = self._selected(self.secret_tree, "secret")
        if name:
            value = self.reveal_secret(name)
            if value is not None:
                ShowOnceDialog(self, f"Value of {name}", "This is the stored value.", value)

    def _on_delete_secret(self) -> None:
        name = self._selected(self.secret_tree, "secret")
        if name and self.confirm("Delete secret", f"Delete “{name}” from {self.project}?"):
            self.delete_secret(name)

    def _on_new_token(self) -> None:
        if self._need_project():
            TokenDialog(self)

    def _on_change_ips(self) -> None:
        tid = self._selected(self.token_tree, "token")
        if tid:
            AddressDialog(self, next(t for t in self.tokens if t["id"] == tid))

    def _on_change_approval(self) -> None:
        tid = self._selected(self.token_tree, "token")
        if tid:
            ApprovalDialog(self, next(t for t in self.tokens if t["id"] == tid))

    def _on_reset_approval(self) -> None:
        tid = self._selected(self.token_tree, "token")
        if not tid:
            return
        tok = next(t for t in self.tokens if t["id"] == tid)
        if not tok.get("approval"):
            messagebox.showinfo("SecurityWarden", "That token does not need approval.", parent=self.root)
        elif self.confirm("Reset approval limit", f"Let “{tok['name']}” ask for approval again now?\n\n"
                          "Its hourly count starts over and any request still waiting is cancelled. "
                          "Approved sessions keep working; the history stays in the activity log."):
            self.reset_approval_limits(tid)

    def _on_decide(self, approve: bool) -> None:
        aid = self._selected(self.approval_tree, "request")
        if not aid:
            return
        a = next((x for x in self.approvals if x["id"] == aid), None)
        if not a:
            return
        if not a["decidable"]:
            messagebox.showinfo("SecurityWarden", "This token's policy does not allow approval from this window.",
                                parent=self.root)
            return
        what = ""
        if a["kind"] == "action":
            what = action_lines(a["action"], self.client.action_summary(a)) + "\n\n"
        if approve and not self.confirm(
                "Approve request", f"Approve “{a['token_name']}” from {a['ip']}?\n\n{what}"
                f"Only approve if the machine shows match code {a['match']} and you expected this request."):
            return
        self.decide(aid, approve)

    def _on_revoke_token(self) -> None:
        tid = self._selected(self.token_tree, "token")
        if not tid:
            return
        tok = next(t for t in self.tokens if t["id"] == tid)
        if tok["revoked_at"]:
            messagebox.showinfo("SecurityWarden", "That token is already revoked.", parent=self.root)
        elif self.confirm("Revoke token", f"Revoke “{tok['name']}”?\n\nThe machine using it loses access "
                          "immediately. It cannot be un-revoked."):
            self.revoke_token(tid)


# ---------------------------------------------------------------------------
# dialogs
# ---------------------------------------------------------------------------

class _Dialog:
    def __init__(self, app: AdminApp, title: str):
        self.app = app
        self.win = tk.Toplevel(app.root)
        self.win.title(title)
        self.win.transient(app.root)
        self.win.resizable(False, False)
        self.frame = ttk.Frame(self.win, padding=16)
        self.frame.pack(fill="both", expand=True)
        self.win.bind("<Escape>", lambda _e: self.win.destroy())

    def _buttons(self, ok_text: str, ok: Callable[[], None], cancel_text: str = "Cancel") -> None:
        row = ttk.Frame(self.frame)
        row.pack(fill="x", pady=(16, 0))
        ttk.Button(row, text=ok_text, command=ok).pack(side="right")
        ttk.Button(row, text=cancel_text, command=self.win.destroy).pack(side="right", padx=(0, PAD))

    def _modal(self, focus: Any = None) -> None:
        self.win.update_idletasks()
        r = self.app.root
        x = r.winfo_rootx() + (r.winfo_width() - self.win.winfo_width()) // 2
        y = r.winfo_rooty() + (r.winfo_height() - self.win.winfo_height()) // 3
        self.win.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.win.grab_set()
        (focus or self.win).focus_set()


class _ApprovalFields:
    """Approval mode, session length and channels, shared by the token dialogs."""

    def __init__(self, parent: Any, policy: dict[str, Any] | None):
        self.base = policy
        p = {**DEFAULTS, **(policy or {})}
        box = ttk.Labelframe(parent, text="Human approval", padding=PAD)
        box.pack(fill="x", pady=(12, 0))
        current = next((k for k, v in APPROVAL_MODES.items() if v == (policy or {}).get("mode")), "No approval")
        self.mode = tk.StringVar(value=current)
        ttk.Combobox(box, textvariable=self.mode, values=list(APPROVAL_MODES), state="readonly",
                     width=20).grid(row=0, column=0, sticky="w")
        ttk.Label(box, text="Session length (hours)").grid(row=0, column=1, sticky="e", padx=(PAD * 2, 4))
        self.hours = tk.StringVar(value=f"{p['session_ttl'] / 3600:g}")
        ttk.Entry(box, textvariable=self.hours, width=6).grid(row=0, column=2, sticky="w")
        ttk.Label(box, text="Ask in:").grid(row=1, column=0, sticky="w", pady=(PAD, 0))
        self.channels = {c: tk.BooleanVar(value=c in p["channels"]) for c in CHANNELS}
        for i, c in enumerate(CHANNELS):
            ttk.Checkbutton(box, text=CHANNEL_LABELS[c], variable=self.channels[c]).grid(
                row=2 + i, column=0, columnspan=3, sticky="w")
        r = 2 + len(CHANNELS)
        ttk.Label(box, text="Push channels must be set up on the server first.", foreground="#666").grid(
            row=r, column=0, columnspan=3, sticky="w", pady=(4, PAD))
        self.timeout = tk.StringVar(value="" if p["timeout"] is None else str(p["timeout"]))
        self.per_hour = tk.StringVar(value="" if p["max_per_hour"] is None else str(p["max_per_hour"]))
        self.pending = tk.StringVar(value=str(p["max_pending"]))
        for i, (label, var, hint) in enumerate((("Wait for a decision (seconds)", self.timeout, "15-600, blank: no limit"),
                                                ("Requests per hour", self.per_hour, "1-120, blank: no limit"),
                                                ("Pending at once", self.pending, "1-5"))):
            ttk.Label(box, text=label).grid(row=r + 1 + i, column=0, sticky="w")
            ttk.Entry(box, textvariable=var, width=6).grid(row=r + 1 + i, column=1, sticky="w", padx=(PAD * 2, 4))
            ttk.Label(box, text=hint, foreground="#666").grid(row=r + 1 + i, column=2, sticky="w")

    def policy(self) -> dict[str, Any] | None:
        """Raises ValueError with a message for the user."""
        return approval_policy(self.mode.get(), self.hours.get(), [c for c, v in self.channels.items() if v.get()],
                               self.timeout.get(), self.per_hour.get(), self.pending.get(), base=self.base)


class SecretDialog(_Dialog):
    def __init__(self, app: AdminApp, name: str | None):
        super().__init__(app, "Change value" if name else "Add secret")
        ttk.Label(self.frame, text="Name").pack(anchor="w")
        self.name = tk.StringVar(value=name or "")
        name_entry = ttk.Entry(self.frame, textvariable=self.name, width=48,
                               state="readonly" if name else "normal")
        name_entry.pack(fill="x", pady=(2, 12))
        ttk.Label(self.frame, text="Value").pack(anchor="w")
        self.value = tk.StringVar()
        self.entry = ttk.Entry(self.frame, textvariable=self.value, width=48, show="•")
        self.entry.pack(fill="x", pady=(2, 4))
        self.show = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.frame, text="Show what I typed", variable=self.show,
                        command=lambda: self.entry.config(show="" if self.show.get() else "•")).pack(anchor="w")
        ttk.Label(self.frame, text="Encrypted on this computer before it is sent.",
                  foreground="#666").pack(anchor="w", pady=(8, 0))
        self._buttons("Save", self._save)
        self.entry.bind("<Return>", lambda _e: self._save())
        self._modal(self.entry if name else name_entry)

    def _save(self) -> None:
        if self.app.save_secret(self.name.get(), self.value.get()):
            self.win.destroy()


class TokenDialog(_Dialog):
    def __init__(self, app: AdminApp):
        super().__init__(app, f"New token for {app.project}")
        ttk.Label(self.frame, text="Name (the machine or bot that will use it)").pack(anchor="w")
        self.name = tk.StringVar()
        name = ttk.Entry(self.frame, textvariable=self.name, width=48)
        name.pack(fill="x", pady=(2, 12))
        ttk.Label(self.frame, text="Expires after (days; blank = never)").pack(anchor="w")
        self.days = tk.StringVar(value="180")
        ttk.Entry(self.frame, textvariable=self.days, width=10).pack(anchor="w", pady=(2, 12))
        ttk.Label(self.frame, text="Allowed client addresses (one per line; blank = any address)").pack(anchor="w")
        self.ips = tk.Text(self.frame, width=48, height=4)
        self.ips.pack(fill="x", pady=(2, 4))
        ttk.Label(self.frame, text="An address like 192.168.1.12 or a range like 10.0.0.0/24.",
                  foreground="#666").pack(anchor="w")
        self.approval = _ApprovalFields(self.frame, None)
        self._buttons("Create token", self._create)
        self._modal(name)

    def _create(self) -> None:
        try:
            policy = self.approval.policy()
        except ValueError as e:
            self.app.error(str(e))
            return
        token = self.app.create_token(self.name.get(), self.days.get(), self.ips.get("1.0", "end"), policy)
        if token:
            self.win.destroy()
            ShowOnceDialog(self.app, "Token created",
                           "Copy this token to the machine now. It is shown once and cannot be recovered.", token)


class AddressDialog(_Dialog):
    def __init__(self, app: AdminApp, token: dict[str, Any]):
        super().__init__(app, f"Allowed addresses for {token['name']}")
        self.token = token
        ttk.Label(self.frame, text="Allowed client addresses (one per line; blank = any address)").pack(anchor="w")
        self.ips = tk.Text(self.frame, width=48, height=5)
        self.ips.insert("1.0", "\n".join(token.get("allowed_ips") or []))
        self.ips.pack(fill="x", pady=(2, 4))
        ttk.Label(self.frame, text="Takes effect immediately; the token itself does not change.",
                  foreground="#666").pack(anchor="w")
        self._buttons("Save", self._save)
        self._modal(self.ips)

    def _save(self) -> None:
        if self.app.set_token_ips(self.token["id"], self.ips.get("1.0", "end")):
            self.win.destroy()


class ApprovalDialog(_Dialog):
    def __init__(self, app: AdminApp, token: dict[str, Any]):
        super().__init__(app, f"Approval for {token['name']}")
        self.token = token
        self.fields = _ApprovalFields(self.frame, token.get("approval"))
        ttk.Label(self.frame, text="Takes effect immediately. Pending requests and approved sessions\n"
                  "for this token are cancelled.", foreground="#666", justify="left").pack(anchor="w", pady=(8, 0))
        self._buttons("Save", self._save)
        self._modal()

    def _save(self) -> None:
        try:
            policy = self.fields.policy()
        except ValueError as e:
            self.app.error(str(e))
            return
        if self.app.set_token_approval(self.token["id"], policy):
            self.win.destroy()


class TkSecondFactor:
    """Asks for the admin credential's second factor in dialogs (see SecurityWardenClient's second_factor)."""

    def __init__(self, app: AdminApp):
        self.app = app

    def code(self, retry: bool) -> str:
        prompt = ("That code was wrong or already used. Enter the next code:" if retry else
                  "Code from your authenticator app (or a recovery code):")
        code = simpledialog.askstring("Two-factor sign-in", prompt, parent=self.app.root)
        if not code:
            raise SecurityWardenError("Sign-in cancelled: the admin credential needs a code from your authenticator app.")
        return code.strip()

    def setup(self, key_text: str, uri: str, retry: bool) -> str:
        d = SetupSecondFactorDialog(self.app, key_text, uri, retry)
        self.app.root.wait_window(d.win)
        if not d.code:
            raise SecurityWardenError("Sign-in cancelled: two-factor sign-in has to be set up for the admin credential.")
        return d.code

    def recovery_codes(self, codes: list[str]) -> None:
        d = ShowOnceDialog(self.app, "Recovery codes",
                           "Two-factor sign-in is on. Save these single-use recovery codes somewhere safe (a password "
                           "manager). Each one signs in once if you lose your phone. They won't be shown again.",
                           "\n".join(codes), height=len(codes))
        self.app.root.wait_window(d.win)


class SetupSecondFactorDialog(_Dialog):
    def __init__(self, app: AdminApp, key_text: str, uri: str, retry: bool):
        super().__init__(app, "Set up two-factor sign-in")
        self.code: str | None = None
        ttk.Label(self.frame, wraplength=460, justify="left", text=(
            "This admin credential needs two-factor sign-in. In your authenticator app (Microsoft Authenticator: "
            "+ > Other account > Enter code manually), add an account with this key:")).pack(anchor="w")
        key = tk.Text(self.frame, width=48, height=1, font=("Courier", 12))
        key.insert("1.0", key_text)
        key.config(state="disabled")
        key.pack(anchor="w", pady=(6, 6))
        ttk.Label(self.frame, wraplength=460, justify="left", foreground="#666",
                  text="Or set it up from the website, which shows a QR code to scan.").pack(anchor="w")
        if retry:
            ttk.Label(self.frame, text="That code didn't match. Check the key and try the next code.",
                      foreground="#b00020").pack(anchor="w", pady=(8, 0))
        ttk.Label(self.frame, text="Code the app shows now").pack(anchor="w", pady=(12, 0))
        self.var = tk.StringVar()
        entry = ttk.Entry(self.frame, textvariable=self.var, width=12)
        entry.pack(anchor="w")
        entry.bind("<Return>", lambda _e: self._ok())
        self._buttons("Turn on", self._ok)
        self._modal(entry)

    def _ok(self) -> None:
        self.code = self.var.get().strip() or None
        self.win.destroy()


class ShowOnceDialog(_Dialog):
    """Shows a token or secret value with a Copy button; nothing is kept after it closes."""

    def __init__(self, app: AdminApp, title: str, note: str, value: str, height: int = 3):
        super().__init__(app, title)
        ttk.Label(self.frame, text=note, wraplength=460, justify="left").pack(anchor="w", pady=(0, 8))
        box = tk.Text(self.frame, width=64, height=height, wrap="char")
        box.insert("1.0", value)
        box.config(state="disabled")
        box.pack(fill="x")
        self.status = ttk.Label(self.frame, text="", foreground="#666")
        self.status.pack(anchor="w", pady=(4, 0))

        def copy() -> None:
            app.copy_then_clear(value)
            self.status.config(text=f"Copied. The clipboard is cleared after {CLIPBOARD_CLEAR_SECONDS} seconds.")

        self._buttons("Copy to clipboard", copy, cancel_text="Close")
        self._modal()


def main(argv: list[str] | None = None) -> int:
    if tk is None:
        print("swadmin needs Tkinter (on Debian/Ubuntu: sudo apt install python3-tk)", file=sys.stderr)
        return 1
    root = tk.Tk()
    AdminApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
