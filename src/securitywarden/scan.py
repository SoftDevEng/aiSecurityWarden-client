"""sw-scan: what can your AI agent actually read?

An AI agent that runs as you can read every file you can. ``sw-scan`` looks where credentials usually sit (agent
configs, sign-in files of other tools, ``.env`` files and their forgotten copies, private keys, this terminal's
environment) and shows what it finds, grouped by what to do about it.

Trust by construction:

- **Local only.** No network code at all: this module imports nothing that can open a connection
  (``tests/test_scan.py`` checks).
- **Never shows a secret.** Output (text and ``--json``) carries only the kind of secret, a public prefix such as
  ``sk-ant-`` and the last 4 characters; generic values show nothing at all. Values are not kept after a file is
  scanned.
- **Read-only.** It never changes, moves or deletes anything.
- **Standard library only**, one file: it also runs on its own as ``python sw_scan.py`` (Windows, macOS, Linux).

What it is not: proof that you're safe. It finds credentials by where they usually live and what they usually look
like; a secret in an unusual place or format can be missed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import shutil
import sys
import textwrap
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

try:
    from . import __version__ as VERSION
except ImportError:  # run as a single file
    VERSION = "standalone"

# ---------------------------------------------------------------------------------------------------------------
# what a secret looks like
# ---------------------------------------------------------------------------------------------------------------

# categories, in report order: (key, heading, what to do)
CATEGORIES = [
    ("vault", "API keys and tokens",
     "Move them into a vault and give the agent a scoped, revocable token instead: aiSecurityWarden holds them "
     "end-to-end encrypted and can ask your phone before the agent gets them. Then rotate any key an agent could "
     "already read."),
    ("copies", "Copies and backups of the same secrets",
     "Delete them once the real one is in a vault. Deleting a .env does nothing while its .bak copies stay."),
    ("signin", "Sign-in files of other tools",
     "These are other programs' own sign-ins, which no vault can take over. Run the agent as its own user "
     "(not as you) so it can't read them, and prefer short-lived sign-ins."),
    ("sshkey", "Private keys without a passphrase",
     "Add a passphrase (ssh-keygen -p -f FILE) and use an SSH agent, or keep the key away from the agent's user."),
    ("sw", "aiSecurityWarden tokens",
     "Readable by design: the token alone gets nothing outside its project. Make sure its allowed addresses and "
     "approval are on, so a copied token is useless elsewhere."),
]
CATEGORY_KEYS = [c[0] for c in CATEGORIES]


@dataclass(frozen=True)
class Pattern:
    name: str
    weight: int
    prefix: str          # the public part shown in previews ("" shows nothing but the last 4)
    rx: re.Pattern
    category: str = "vault"


def _p(name: str, weight: int, prefix: str, rx: str, category: str = "vault") -> Pattern:
    return Pattern(name, weight, prefix, re.compile(rx), category)


PATTERNS: list[Pattern] = [
    _p("Anthropic API key", 20, "sk-ant-", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    # sk- keys that are not Anthropic's (OpenAI, and several providers that copied the format)
    _p("OpenAI-style API key", 18, "sk-", r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"),
    _p("Google API key", 15, "AIza", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    _p("AWS access key", 18, "", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _p("GitHub token", 18, "gh", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    _p("GitHub fine-grained token", 20, "github_pat_", r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    _p("Google OAuth refresh token", 20, "1//", r"(?<![\w/])1//0[A-Za-z0-9_\-]{30,}"),
    _p("Google OAuth access token", 12, "ya29.", r"\bya29\.[A-Za-z0-9_\-]{20,}"),
    _p("Slack token", 15, "xox", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"),
    _p("Telegram bot token", 12, "", r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b"),
    _p("Discord bot token", 12, "", r"\b[MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}\b"),
    _p("npm token", 10, "npm_", r"\bnpm_[A-Za-z0-9]{36}\b"),
    _p("PyPI token", 15, "pypi-", r"\bpypi-AgE[A-Za-z0-9_\-]{50,}"),
    _p("Stripe key", 18, "", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
    _p("Hugging Face token", 12, "hf_", r"\bhf_[A-Za-z0-9]{30,}\b"),
    _p("xAI API key", 15, "xai-", r"\bxai-[A-Za-z0-9]{30,}"),
    _p("Groq API key", 12, "gsk_", r"\bgsk_[A-Za-z0-9]{40,}"),
    # user:password@ in a URL (git credentials, database URLs); the preview shows only the last 4 of the password
    _p("password in a URL", 12, "", r"(?<=[a-z]://)[^\s:/@'\"]+:[^\s@/'\"]{6,}(?=@)"),
    _p("aiSecurityWarden machine token", 6, "sw1.m.",
       r"\bsw1\.m\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{10,}:[A-Za-z0-9_\-]{40,}", "sw"),
    _p("aiSecurityWarden admin credential", 20, "sw1.a.",
       r"\bsw1\.a\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{10,}:[A-Za-z0-9_\-]{40,}", "sw"),
]

# NAME=value / "name": "value" lines whose name says secret (only in files that hold settings)
GENERIC_NAME = re.compile(r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIALS?|AUTH)", re.I)
GENERIC_NOT_SECRET = re.compile(
    r"(?:_(?:FILE|PATH|DIR|URL|URI|ID|NAME|TYPE|ENDPOINT|HOST|PORT|REGION|EXPIRES?(?:_AT|_IN)?|COUNT|LIMIT|"
    r"LENGTH|MODE|ENABLED|HEADER|PREFIX|ENV|VERSION)$|PUBLIC|^SW_TOKEN_(?:NAME|ID)$|^(?:TOKEN_TYPE|KEYBOARD.*)$|"
    r"^(?:KEY|KEYS)$)", re.I)
GENERIC_LINE = re.compile(
    r"""^\s*(?:export\s+)?["']?(?P<name>[A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[:=]\s*(?P<value>.+?)\s*,?\s*$""")
PLACEHOLDER = re.compile(
    r"^(?:\$\{?.*|<.*>|\{\{.*\}\}|.*(?:changeme|change_me|your[_\-]|example|placeholder|xxxx|\*\*\*|dummy|"
    r"redacted|replace).*|true|false|null|none|yes|no|bearer|basic|\d+|https?://\S*|[/~.].*)$", re.I)

PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----\s*(?P<body>.*?)-----END", re.S)

# ---------------------------------------------------------------------------------------------------------------
# where to look
# ---------------------------------------------------------------------------------------------------------------

# Known files, relative to the home folder (forward slashes; Windows paths are matched case-insensitively there).
# (path, label, category when the file holds no recognisable key but is itself a sign-in, or None)
KNOWN_FILES = [
    (".aws/credentials", "AWS credentials", "signin"),
    (".config/gcloud/application_default_credentials.json", "Google Cloud sign-in", "signin"),
    (".config/gcloud/credentials.db", "Google Cloud sign-in", "signin"),
    (".azure/msal_token_cache.json", "Azure CLI sign-in", "signin"),
    (".azure/accessTokens.json", "Azure CLI sign-in", "signin"),
    (".kube/config", "Kubernetes config", None),
    (".git-credentials", "Git credentials", "signin"),
    (".netrc", "netrc", "signin"),
    ("_netrc", "netrc", "signin"),
    (".npmrc", "npm config", None),
    (".pypirc", "PyPI config", None),
    (".docker/config.json", "Docker registry sign-in", None),
    (".config/gh/hosts.yml", "GitHub CLI sign-in", "signin"),
    (".claude/.credentials.json", "Claude Code sign-in", "signin"),
    (".claude.json", "Claude Code config", None),
    (".codex/auth.json", "Codex sign-in", "signin"),
    (".cursor/mcp.json", "Cursor MCP config", None),
    (".config/Claude/claude_desktop_config.json", "Claude Desktop config", None),
    (".config/claude/claude_desktop_config.json", "Claude Desktop config", None),
    ("Library/Application Support/Claude/claude_desktop_config.json", "Claude Desktop config", None),
    ("AppData/Roaming/Claude/claude_desktop_config.json", "Claude Desktop config", None),
    ("AppData/Roaming/gcloud/application_default_credentials.json", "Google Cloud sign-in", "signin"),
    ("AppData/Roaming/gcloud/credentials.db", "Google Cloud sign-in", "signin"),
    ("AppData/Roaming/GitHub CLI/hosts.yml", "GitHub CLI sign-in", "signin"),
    (".hermes/.env", "Hermes settings", None),
    (".hermes/config.yaml", "Hermes settings", None),
    (".hermes/auth.json", "Hermes sign-ins", "signin"),
    (".config/securitywarden/SW_Tokens.json", "aiSecurityWarden tokens", None),
    ("AppData/Roaming/SecurityWarden/SW_Tokens.json", "aiSecurityWarden tokens", None),
]
BINARY_SIGNIN = {".db"}                      # report presence, don't read

# file names worth reading anywhere under the home folder
CANDIDATE = re.compile(
    r"(^\.env($|[.\-_])|[.\-_]env$|\.env\.|^credentials?($|\.)|token|secret|password|^_?netrc$|"
    r"\.(pem|key|ppk)$|^id_(rsa|dsa|ecdsa|ed25519)(_sk)?$|auth\.json$|mcp\.json$)", re.I)
BACKUP = re.compile(r"(\.(bak|backup|orig|old|save|prev|copy)\b|[.\-_]bak[.\-_0-9]|~$|\.sw[op]$|backup|copy)", re.I)
# never read source code or media, whatever its name says (Python's own token.py, a secrets.js helper...)
NOT_DATA = {".py", ".pyc", ".pyi", ".pyo", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java",
            ".kt", ".c", ".h", ".cc", ".cpp", ".cs", ".rb", ".php", ".swift", ".md", ".rst", ".html", ".htm",
            ".css", ".scss", ".map", ".lock", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".woff",
            ".woff2", ".ttf", ".otf", ".so", ".a", ".o", ".dll", ".exe", ".dylib", ".class", ".jar", ".whl",
            ".zip", ".gz", ".tgz", ".xz", ".bz2", ".7z", ".pdf", ".mp3", ".mp4", ".mov", ".sh", ".ps1", ".bat",
            ".d.ts", ".txt.gz", ".sqlite", ".db"}
# folders that hold installed software, caches or someone else's files, not your settings
SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", ".venv", "venv", "env", "site-packages", "dist-packages",
             "__pycache__", ".cache", ".npm", ".pnpm-store", ".yarn", ".cargo", ".rustup", ".gradle", ".m2",
             ".terraform", ".next", ".nuxt", "dist", "build", "target", ".tox", ".nox", ".mypy_cache",
             ".pytest_cache", ".ruff_cache", "snap", ".mozilla", ".thunderbird", "Trash", ".Trash",
             ".vscode-server", ".cursor-server", ".docker-desktop", "go", "miniconda3", "anaconda3", ".conda",
             ".pyenv", ".nvm", ".bun", ".deno", ".local-lib", "OneDrive", "Dropbox", "iCloud Drive"}
SKIP_PATHS = {"AppData/Local", "AppData/LocalLow", "Library/Caches", "Library/Containers", "Library/Group Containers",
              "Library/Developer", "Library/Logs", ".local/lib", ".local/pipx", ".local/share/Trash",
              ".local/share/virtualenvs", ".local/share/pnpm", ".local/share/containers", ".hermes/hermes-agent"}
MAX_DEPTH = 6
MAX_ENTRIES = 250_000
MAX_FILE_BYTES = 512_000
MAX_SECONDS = 20.0

# ---------------------------------------------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------------------------------------------


@dataclass
class Finding:
    kind: str
    category: str
    where: str
    preview: str
    weight: int
    line: int | None = None
    backup: bool = False
    copy_of: str | None = None       # the first place the same value was seen
    note: str = ""


@dataclass
class Result:
    home: str
    findings: list[Finding] = field(default_factory=list)
    files_read: int = 0
    entries_seen: int = 0
    truncated: bool = False
    seconds: float = 0.0
    client_installed: bool = False

    @property
    def distinct(self) -> int:
        return sum(1 for f in self.findings if f.copy_of is None)

    @property
    def score(self) -> int:
        # each distinct secret counts its weight; each extra copy a little; 1 - e^(-x/50) keeps the scale honest:
        # one AI API key ~ 33 (exposed), three ~ 70 (wide open)
        w = sum(f.weight if f.copy_of is None else 2 for f in self.findings)
        return min(100, round(100 * (1 - math.exp(-w / 50))))

    @property
    def verdict(self) -> str:
        return "WIDE OPEN" if self.score >= 70 else "EXPOSED" if self.score >= 30 else "PRETTY TIGHT"


def preview(value: str, prefix: str) -> str:
    """The public prefix and the last 4 characters; never more. Short values show nothing."""
    v = value.strip()
    if len(v) < 16:
        return "(hidden)"
    shown = prefix if prefix and v.startswith(prefix) else ""
    return f"{shown}…{v[-4:]}"


class Scanner:
    def __init__(self, home: str, with_env: bool = True, max_seconds: float = MAX_SECONDS) -> None:
        self.home = Path(home).expanduser()
        self.with_env = with_env
        self.deadline = time.monotonic() + max_seconds
        self.result = Result(home=str(self.home))
        # value digest -> first place it was seen; digests live only in memory, values not at all
        self._first: dict[bytes, str] = {}
        self._seen_paths: set[str] = set()

    # -- recording -------------------------------------------------------------------------------------------

    def _add(self, kind: str, category: str, where: str, value: str | None, prefix: str, weight: int,
             line: int | None = None, backup: bool = False, note: str = "") -> None:
        copy_of = None
        if value is not None:
            digest = hashlib.sha256(value.strip().encode("utf-8", "replace")).digest()
            here = f"{where}:{line}" if line else where
            first = self._first.get(digest)
            if first is not None:
                if first.rsplit(":", 1)[0] == where or first == where:
                    return                              # the same value twice in one file: once is enough
                copy_of = first
            else:
                self._first[digest] = here
        cat = "copies" if (copy_of or backup) and category == "vault" else category
        self.result.findings.append(Finding(kind, cat, where, preview(value, prefix) if value else "(file)",
                                            weight, line, backup, copy_of, note))

    # -- reading ---------------------------------------------------------------------------------------------

    def scan_text(self, text: str, where: str, settings_file: bool, backup: bool = False,
                  signin: str | None = None) -> int:
        """Record every recognisable secret in ``text``. Returns how many were found. ``signin``: the file is
        another tool's own sign-in, so its keys are filed there instead of under "move into a vault"."""
        found = 0

        def cat(c: str) -> str:
            return signin if signin and c == "vault" else c
        matched_spans: list[tuple[int, int]] = []
        line_starts = [0] + [m.end() for m in re.finditer("\n", text)]

        def line_of(pos: int) -> int:
            lo, hi = 0, len(line_starts) - 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if line_starts[mid] <= pos:
                    lo = mid
                else:
                    hi = mid - 1
            return lo + 1

        for pat in PATTERNS:
            for m in pat.rx.finditer(text):
                if any(s <= m.start() < e for s, e in matched_spans):
                    continue                            # sk-ant-… is not also an "OpenAI-style" key
                matched_spans.append(m.span())
                self._add(pat.name, cat(pat.category), where, m.group(0), pat.prefix, pat.weight,
                          line_of(m.start()), backup)
                found += 1
        for m in PRIVATE_KEY_BLOCK.finditer(text):
            if not private_key_encrypted(m.group(0)):
                self._add("private key (no passphrase)", "sshkey", where, m.group(0), "", 12,
                          line_of(m.start()), backup)
                found += 1
        if settings_file:
            for n, raw in enumerate(text.splitlines(), 1):
                m = GENERIC_LINE.match(raw)
                if not m:
                    continue
                name, value = m.group("name"), m.group("value").strip().strip("\"'").strip()
                if (not GENERIC_NAME.search(name) or GENERIC_NOT_SECRET.search(name) or len(value) < 8
                        or PLACEHOLDER.match(value) or " " in value):
                    continue
                pos = line_starts[n - 1] if n - 1 < len(line_starts) else 0
                end = pos + len(raw)
                if any(pos <= s < end for s, _ in matched_spans):
                    continue                            # already named above
                self._add(f"secret setting {name}", cat("vault"), where, value, "", 8, n, backup)
                found += 1
        return found

    def scan_file(self, path: Path, label: str = "", signin_category: str | None = None) -> None:
        key = os.path.normcase(str(path))
        if key in self._seen_paths:
            return
        self._seen_paths.add(key)
        try:
            st = path.stat()
        except OSError:
            return
        if st.st_size == 0:
            return
        where = str(path)
        backup = bool(BACKUP.search(path.name))
        if path.suffix.lower() in BINARY_SIGNIN:
            if signin_category:
                self._add(label or "sign-in file", signin_category, where, None, "", 10, backup=backup)
            return
        if st.st_size > MAX_FILE_BYTES:
            return
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return
        self.result.files_read += 1
        if path.suffix.lower() == ".ppk":
            if re.search(r"^Encryption:\s*none\s*$", text, re.M):
                self._add("PuTTY private key (no passphrase)", "sshkey", where, text, "", 12, backup=backup)
            return
        found = self.scan_text(text, where, settings_file=True, backup=backup, signin=signin_category)
        if not found and signin_category and text.strip() not in ("", "{}", "[]"):
            self._add(label or "sign-in file", signin_category, where, None, "", 10, backup=backup)

    def scan_known(self) -> None:
        for rel, label, category in KNOWN_FILES:
            p = self.home.joinpath(*rel.split("/"))
            if p.is_file() and not p.is_symlink():
                self.scan_file(p, label, category)

    def scan_ssh(self) -> None:
        d = self.home / ".ssh"
        try:
            entries = sorted(d.iterdir()) if d.is_dir() else []
        except OSError:
            return
        for p in entries:
            if p.is_file() and not p.is_symlink() and not p.name.endswith(".pub") and p.name not in (
                    "known_hosts", "known_hosts.old", "config", "authorized_keys", "authorized_keys2"):
                self.scan_file(p)

    def walk(self) -> None:
        """Every candidate file under the home folder, skipping software, caches and other people's folders."""
        stack: list[tuple[Path, int]] = [(self.home, 0)]
        while stack:
            if time.monotonic() > self.deadline or self.result.entries_seen > MAX_ENTRIES:
                self.result.truncated = True
                return
            d, depth = stack.pop()
            try:
                entries = sorted(os.scandir(d), key=lambda e: e.name)
            except OSError:
                continue
            for e in entries:
                self.result.entries_seen += 1
                try:
                    if e.is_symlink():
                        continue
                    if e.is_dir(follow_symlinks=False):
                        rel = Path(e.path).relative_to(self.home).as_posix()
                        if depth + 1 <= MAX_DEPTH and e.name not in SKIP_DIRS and rel not in SKIP_PATHS:
                            stack.append((Path(e.path), depth + 1))
                    elif e.is_file(follow_symlinks=False) and CANDIDATE.search(e.name):
                        p = Path(e.path)
                        suffixes = "".join(p.suffixes[-2:]).lower()
                        if p.suffix.lower() in NOT_DATA or suffixes in NOT_DATA:
                            continue
                        self.scan_file(p)
                except OSError:
                    continue

    def scan_env(self) -> None:
        for name in sorted(os.environ):
            value = os.environ[name]
            if not value or len(value) < 8:
                continue
            where = f"environment variable {name}"
            hit = False
            for pat in PATTERNS:
                m = pat.rx.search(value)
                if m:
                    self._add(pat.name, pat.category, where, m.group(0), pat.prefix, pat.weight)
                    hit = True
                    break
            if (not hit and GENERIC_NAME.search(name) and not GENERIC_NOT_SECRET.search(name)
                    and not PLACEHOLDER.match(value) and " " not in value and os.sep not in value):
                self._add(f"secret setting {name}", "vault", where, value, "", 8)

    def run(self) -> Result:
        start = time.monotonic()
        self.scan_known()
        self.scan_ssh()
        self.walk()
        if self.with_env:
            self.scan_env()
        self.result.client_installed = any(shutil.which(b) for b in ("swctl", "sw-mcp", "sw-sudo"))
        self.result.seconds = round(time.monotonic() - start, 2)
        return self.result


def private_key_encrypted(block: str) -> bool:
    """True when a PEM/OpenSSH private key needs a passphrase."""
    if "ENCRYPTED" in block.split("\n", 3)[0] or "Proc-Type: 4,ENCRYPTED" in block:
        return True
    m = PRIVATE_KEY_BLOCK.search(block)
    if not m or "OPENSSH" not in m.group(1):
        return False
    body = "".join(line for line in m.group("body").splitlines() if ":" not in line)
    try:
        raw = base64.b64decode(body + "=" * (-len(body) % 4))
    except (ValueError, TypeError):
        return False
    magic = b"openssh-key-v1\x00"
    if not raw.startswith(magic) or len(raw) < len(magic) + 4:
        return False
    n = int.from_bytes(raw[len(magic):len(magic) + 4], "big")
    return raw[len(magic) + 4:len(magic) + 4 + n] != b"none"


# ---------------------------------------------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------------------------------------------

def _colors(stream) -> tuple[str, ...]:  # noqa: ANN001
    on = stream.isatty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"
    return ("\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m") if on else ("",) * 6


def _shorten(path: str, home: str) -> str:
    return "~" + path[len(home):] if path.startswith(home) else path


def to_json(res: Result) -> dict:
    return {
        "tool": "sw-scan", "version": VERSION, "score": res.score, "verdict": res.verdict,
        "secrets": len(res.findings), "distinct": res.distinct, "files_read": res.files_read,
        "seconds": res.seconds, "incomplete": res.truncated,
        "categories": [{"key": k, "heading": h, "advice": a,
                        "count": sum(1 for f in res.findings if f.category == k)} for k, h, a in CATEGORIES],
        "findings": [asdict(f) for f in res.findings],
    }


def report(res: Result, out=sys.stdout, show: int = 12) -> None:  # noqa: ANN001
    GREEN, RED, YEL, DIM, BOLD, RESET = _colors(out)
    col = RED if res.score >= 70 else YEL if res.score >= 30 else GREEN
    w = out.write
    w(f"\n{BOLD}  sw-scan {VERSION}: what can your AI agent actually read?{RESET}\n")
    w(f"{DIM}  local only · nothing sent anywhere · no secret is ever shown{RESET}\n\n")
    bar = "█" * max(1, res.score // 4) + "░" * (25 - max(1, res.score // 4))
    w(f"  {BOLD}exposure {col}{res.score}/100  {res.verdict}{RESET}\n  {col}{bar}{RESET}\n")
    copies = sum(1 for f in res.findings if f.copy_of)
    w(f"  {len(res.findings)} readable secret(s), {res.distinct} distinct"
      f"{f', {copies} of them copies' if copies else ''}; {res.files_read} files read in {res.seconds}s\n")
    if res.truncated:
        w(f"  {YEL}stopped early (time or size limit): the home folder is bigger than one quick pass{RESET}\n")
    if not res.findings:
        w(f"\n  {GREEN}Nothing found in the usual places.{RESET} An agent running as you can still read whatever "
          "you can,\n  so keep it to its own user and its own keys.\n\n")
        return
    w(f"\n  An AI agent running as {BOLD}this user{RESET} can read every item below, and anything a web page or an\n"
      "  email talks it into sending can include them.\n")
    for key, heading, advice in CATEGORIES:
        items = [f for f in res.findings if f.category == key]
        if not items:
            continue
        w(f"\n  {BOLD}{heading} ({len(items)}){RESET}\n")
        # columns as wide as their longest entry in this group, so a long name doesn't push its row out of line
        kind_w = max(34, *(len(f.kind) for f in items[:show]))
        prev_w = max(16, *(len(f.preview) for f in items[:show]))
        for f in items[:show]:
            where = _shorten(f.where, res.home) + (f":{f.line}" if f.line else "")
            extra = f"  {DIM}same as {_shorten(f.copy_of, res.home)}{RESET}" if f.copy_of else ""
            w(f"   {RED}•{RESET} {f.kind:<{kind_w}} {f.preview:<{prev_w}} {DIM}{where}{RESET}{extra}\n")
        if len(items) > show:
            w(f"   {DIM}… {len(items) - show} more (--all shows every one){RESET}\n")
        wrapped = textwrap.fill(advice, 100, initial_indent="   → ", subsequent_indent="     ")
        w(f"{DIM}{wrapped}{RESET}\n")
        envs = sorted({f.where for f in items if key == "vault" and not f.where.startswith("environment ")})
        if envs:
            w(f"{DIM}     To move a file's keys: the project's Secrets tab on aisecuritywarden.com, or on a server you run\n"
              f"     yourself: swctl admin secret import PROJECT {_shorten(envs[0], res.home)}{RESET}\n")
    w(f"\n  {BOLD}What helps{RESET}\n")
    w("   1. Run the agent as its own user, never as you: then it can't read most of the above at all.\n")
    w("   2. Give it its keys from a vault, through a token you can revoke, instead of files it can read.\n")
    w("   3. Delete the copies, and rotate every key an agent could already read.\n")
    if res.client_installed:
        w(f"\n  {DIM}The aiSecurityWarden client is installed here. It protects the secrets you've moved into it;\n"
          f"  the files above are still readable until you move and delete them.{RESET}\n")
    else:
        w(f"\n  {DIM}aiSecurityWarden does step 2: end-to-end encrypted keys, a phone approval before the agent gets\n"
          f"  them, and a gate on what it sends, deletes or runs. Free plan: https://aisecuritywarden.com{RESET}\n")
    w("\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="sw-scan", description="What can your AI agent actually read? Local only; never shows a secret.")
    ap.add_argument("--home", default="~", help="the home folder to scan (default: yours)")
    ap.add_argument("--json", action="store_true", help="machine-readable output (still never shows a secret)")
    ap.add_argument("--all", action="store_true", help="list every finding, not the first 12 of each kind")
    ap.add_argument("--no-env", action="store_true", help="don't look at this terminal's environment variables")
    ap.add_argument("--fail-at", type=int, metavar="SCORE",
                    help="exit with status 1 when the score is at least SCORE (for scripts and CI)")
    ap.add_argument("--version", action="version", version=f"sw-scan {VERSION}")
    args = ap.parse_args(argv)
    try:   # a Windows console or pipe in a legacy code page can't print … or █: never crash over a character
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass
    home = os.path.expanduser(args.home)
    if not os.path.isdir(home):
        print(f"sw-scan: no such folder: {home}", file=sys.stderr)
        return 2
    # another user's home: their environment isn't this terminal's
    with_env = not args.no_env and os.path.realpath(home) == os.path.realpath(os.path.expanduser("~"))
    res = Scanner(home, with_env=with_env).run()
    if args.json:
        json.dump(to_json(res), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        report(res, show=10_000 if args.all else 12)
    return 1 if args.fail_at is not None and res.score >= args.fail_at else 0


if __name__ == "__main__":
    raise SystemExit(main())
