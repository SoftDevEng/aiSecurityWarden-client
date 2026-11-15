"""Files in email: names, types, Gmail's blocked kinds, and reading text out of an attachment.

No network and no crypto here. Used by the Gmail connector (and later Outlook) for attachments the AI sends and
attachments it reads. Everything an attachment contains is untrusted: the caller marks what it returns.
"""

from __future__ import annotations

import io
import os
import re
import subprocess
import sys
import unicodedata
import zipfile
from typing import Any
from xml.etree import ElementTree

MAX_FILES = 10                      # attachments per email
MAX_INLINE = 1_000_000              # bytes per file the AI passes as text or base64
MAX_TOTAL = 18_000_000              # all files of one email: Gmail's 25 MB limit after base64 encoding
MAX_READ_FILE = 15_000_000          # an attachment the AI asks to read
MAX_NAME = 255                      # bytes, UTF-8
PDF_TIMEOUT = 20                    # seconds to get the text out of one PDF
PDF_MAX_PAGES = 300
UNZIPPED_MAX = 50_000_000           # a .docx's text part, uncompressed

# By extension. Anything else is sent as application/octet-stream.
TYPES = {
    "txt": "text/plain", "md": "text/markdown", "markdown": "text/markdown", "csv": "text/csv",
    "tsv": "text/tab-separated-values", "json": "application/json", "xml": "application/xml",
    "html": "text/html", "htm": "text/html", "ics": "text/calendar", "log": "text/plain",
    "svg": "image/svg+xml", "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif",
    "webp": "image/webp", "heic": "image/heic", "pdf": "application/pdf", "zip": "application/zip",
    "doc": "application/msword", "xls": "application/vnd.ms-excel", "ppt": "application/vnd.ms-powerpoint",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "odt": "application/vnd.oasis.opendocument.text", "rtf": "application/rtf",
    "mp3": "audio/mpeg", "wav": "audio/wav", "mp4": "video/mp4", "mov": "video/quicktime",
}

# Gmail refuses these, also inside archives (support.google.com/mail/answer/6590).
BLOCKED = frozenset([
    "ade", "adp", "apk", "appx", "appxbundle", "bat", "cab", "chm", "cmd", "com", "cpl", "diagcab", "diagcfg",
    "diagpack", "dll", "dmg", "ex", "ex_", "exe", "hta", "img", "ins", "iso", "isp", "jar", "jnlp", "js", "jse",
    "lib", "lnk", "mde", "mjs", "msc", "msi", "msix", "msixbundle", "msp", "mst", "nsh", "pif", "ps1", "scr",
    "sct", "shb", "sys", "vb", "vbe", "vbs", "vhd", "vxd", "wsc", "wsf", "wsh", "xll",
])
ARCHIVES = frozenset(["7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "cab"])   # Gmail can't look inside some; we can't either

TEXT_TYPES = {"text/plain", "text/markdown", "text/csv", "text/tab-separated-values", "application/json",
              "application/xml", "text/calendar", "text/html", "image/svg+xml"}


class FileProblem(ValueError):
    """A file that can't be sent or read. The message is shown to the AI."""


def clean_name(name: str) -> str:
    """A safe file name: no folders, no control characters, CR/LF, quotes or ``/ \\ :``; at most 255 bytes."""
    base = re.split(r"[/\\]", str(name or ""))[-1]
    base = unicodedata.normalize("NFC", base)
    base = "".join(c for c in base if unicodedata.category(c)[0] != "C" and c not in "\"'`:<>|*?")
    base = " ".join(base.split()).strip(" .")
    if not base:
        raise FileProblem("Each attachment needs a file name (like summary.md).")
    stem, dot, ext = base.rpartition(".")
    if not dot:
        stem, ext = base, ""
    while len(base.encode("utf-8")) > MAX_NAME:
        stem = stem[:-1]
        base = f"{stem}.{ext}" if ext else stem
    return base


def extension(name: str) -> str:
    return name.rpartition(".")[2].lower() if "." in name else ""


def mime_type(name: str) -> str:
    return TYPES.get(extension(name), "application/octet-stream")


def check_sendable(name: str, data: bytes) -> None:
    """Refuse what Gmail would bounce: blocked extensions, and zips holding them or protected by a password."""
    ext = extension(name)
    if ext in BLOCKED:
        raise FileProblem(f"Gmail doesn't allow .{ext} files as attachments ({name}).")
    if ext in ARCHIVES:
        raise FileProblem(f"{name}: send archives as .zip (Gmail can't check what's inside .{ext} files).")
    if ext == "zip" or (data[:4] == b"PK\x03\x04" and ext not in ("docx", "xlsx", "pptx", "odt")):
        _check_zip(name, data)


def _check_zip(name: str, data: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                if info.flag_bits & 0x1:
                    raise FileProblem(f"Gmail doesn't allow password-protected zips ({name}).")
                inner = extension(info.filename.rstrip("/"))
                if inner in BLOCKED:
                    raise FileProblem(f"Gmail doesn't allow {name}: it holds a .{inner} file.")
                if inner == "zip" or inner in ARCHIVES:
                    raise FileProblem(f"{name} holds another archive; Gmail may refuse it. Send the files directly.")
    except zipfile.BadZipFile:
        raise FileProblem(f"{name} isn't a valid zip file.") from None


def size_text(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.0f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


# -- reading ------------------------------------------------------------------------------

def read_text(name: str, mime: str, data: bytes, html_to_text: Any) -> tuple[str | None, str]:
    """The text of an attachment, or None with the reason it has none. ``html_to_text`` turns HTML into text."""
    ext = extension(name)
    if mime in TEXT_TYPES or ext in ("txt", "md", "csv", "tsv", "json", "xml", "html", "htm", "ics", "log", "svg"):
        text = _decode(data)
        if mime == "text/html" or ext in ("html", "htm"):
            text = html_to_text(text)
        return text, "text"
    if mime == "application/pdf" or ext == "pdf":
        return _pdf_text(data)
    if ext == "docx" or mime == TYPES["docx"]:
        return _docx_text(data)
    kind = mime.split("/")[0] if "/" in mime else "binary"
    return None, (f"no text to read ({kind} file). It can still be forwarded, or attached to a reply with "
                  "message_id and part.")


def _decode(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else ("utf-8-sig",):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            pass
    return data.decode("latin-1")


_PDF_SCRIPT = """
import io, sys
sys.path.insert(0, sys.argv[2])
from pypdf import PdfReader
r = PdfReader(io.BytesIO(sys.stdin.buffer.read()))
out = []
for i, page in enumerate(r.pages):
    if i >= int(sys.argv[1]):
        out.append("[... %d more pages not read]" % (len(r.pages) - i))
        break
    out.append(page.extract_text() or "")
sys.stdout.buffer.write("\\n\\n".join(out).encode("utf-8", "replace"))
"""


def _pdf_text(data: bytes) -> tuple[str | None, str]:
    """PDF text through pypdf, in a separate Python process with a time limit: a hostile PDF can't hang sw-mcp."""
    try:
        import pypdf
    except ImportError:
        return None, "reading PDFs needs pypdf, which is missing; ask the user to reinstall aisecuritywarden"
    try:
        p = subprocess.run([sys.executable, "-I", "-c", _PDF_SCRIPT, str(PDF_MAX_PAGES),
                            os.path.dirname(os.path.dirname(os.path.abspath(pypdf.__file__)))], input=data,
                           capture_output=True, timeout=PDF_TIMEOUT, env=_child_env(), check=False)
    except subprocess.TimeoutExpired:
        return None, f"the PDF took longer than {PDF_TIMEOUT} seconds to read; it wasn't read"
    if p.returncode != 0:
        return None, "the PDF couldn't be read (damaged or encrypted)"
    text = p.stdout.decode("utf-8", "replace").strip()
    return (text, "pdf") if text else (None, "the PDF has no text layer (probably a scan)")


def _child_env() -> dict[str, str]:
    keep = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "LANG", "LC_ALL")
    return {k: v for k, v in os.environ.items() if k.upper() in keep}


_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _docx_text(data: bytes) -> tuple[str | None, str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            info = z.getinfo("word/document.xml")
            if info.file_size > UNZIPPED_MAX:
                return None, "the document is too large to read"
            with z.open(info) as f:
                xml = f.read(UNZIPPED_MAX + 1)
        if b"<!DOCTYPE" in xml[:2000] or b"<!ENTITY" in xml:
            return None, "the document couldn't be read"
        root = ElementTree.fromstring(xml)
    except (KeyError, zipfile.BadZipFile, ElementTree.ParseError):
        return None, "the document couldn't be read (not a valid .docx)"
    paras = []
    for p in root.iter(_W + "p"):
        paras.append("".join(t.text or "" for t in p.iter(_W + "t")))
    text = "\n".join(paras).strip()
    return (text, "docx") if text else (None, "the document has no text")


# -- files on this machine ----------------------------------------------------------------
#
# The agent attaches a file from disk only from the outbox (made for it, created on first use) or folders the user
# lists in SW_ATTACHMENT_FOLDERS (in the MCP settings, separated like PATH). Hidden files and folders, aiSecurityWarden's
# own files and the usual secret folders are refused even inside those, and so is any path that leads out of them.

SECRET_DIRS = (".ssh", ".gnupg", ".config", ".aws", ".azure", ".kube", ".docker", ".hermes", ".claude", ".netrc")
SECRET_NAMES = ("sw_tokens.json",)


def outbox() -> str:
    """The folder the agent saves files in to attach them (``SW_OUTBOX`` overrides it)."""
    if os.environ.get("SW_OUTBOX"):
        return os.path.abspath(os.path.expanduser(os.environ["SW_OUTBOX"]))
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
        return os.path.join(base, "aiSecurityWarden", "outbox")
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support", "aiSecurityWarden", "outbox")
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(home, ".local", "share")
    return os.path.join(base, "aisecuritywarden", "outbox")


def make_outbox() -> str:
    path = outbox()
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
    except OSError:
        pass
    return path


def attachment_roots() -> list[str]:
    """Real paths of the folders files may be attached from. Too-broad folders (a drive, the home folder) are
    ignored."""
    home = os.path.realpath(os.path.expanduser("~"))
    wanted = [outbox()] + [p for p in os.environ.get("SW_ATTACHMENT_FOLDERS", "").split(os.pathsep) if p.strip()]
    roots: list[str] = []
    for p in wanted:
        real = os.path.realpath(os.path.expanduser(p.strip()))
        if real in (home, os.path.dirname(real)) or real == os.path.abspath(os.sep) or not os.path.isdir(real):
            continue
        if _is_secret(real, home) or real in roots:
            continue
        roots.append(real)
    return roots


def _is_secret(real: str, home: str) -> bool:
    if os.path.basename(real).lower() in SECRET_NAMES or real.lower().endswith(".connectors.json"):
        return True
    for d in SECRET_DIRS:
        secret = os.path.join(home, d)
        if real == secret or real.startswith(secret + os.sep):
            return True
    cfg = os.environ.get("XDG_CONFIG_HOME")
    if cfg and (real == os.path.realpath(cfg) or real.startswith(os.path.realpath(cfg) + os.sep)):
        return True
    appdata = os.environ.get("APPDATA")
    if appdata:
        sw = os.path.realpath(os.path.join(appdata, "SecurityWarden"))
        if real == sw or real.startswith(sw + os.sep):
            return True
    return False


def check_path(path: str) -> str:
    """The real path of a file the agent may attach, or FileProblem. A bare name means a file in the outbox."""
    roots = attachment_roots()
    box = outbox()
    if not isinstance(path, str) or not path.strip() or "\x00" in path:
        raise FileProblem("Give the file's path.")
    p = path.strip()
    if sys.platform == "win32" and (p.startswith(("\\\\", "//")) or ":" in p[2:]):
        raise FileProblem("Network paths and alternate streams can't be attached.")
    p = os.path.expanduser(p)
    if not os.path.isabs(p):
        p = os.path.join(box, p)
    real = os.path.realpath(p)
    home = os.path.realpath(os.path.expanduser("~"))
    root = next((r for r in roots if real.startswith(r + os.sep)), None)
    if root is None:
        raise FileProblem(f"Only files in the aiSecurityWarden outbox ({box}) can be attached. Save the file there "
                          "first, then pass its name as path.")
    rel = os.path.relpath(real, root)
    if any(part.startswith(".") for part in rel.split(os.sep)) or _is_secret(real, home):
        raise FileProblem("Hidden files and aiSecurityWarden's own files can't be attached.")
    if not os.path.isfile(real):
        raise FileProblem(f"There's no file {rel} in {root}.")
    return real


def read_path(real: str, limit: int) -> bytes:
    """Read a checked file without following a link swapped in after the check."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(real, flags)
    except OSError:
        raise FileProblem(f"{os.path.basename(real)} can't be opened.") from None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        now = os.stat(real, follow_symlinks=False)
        if (st.st_dev, st.st_ino) != (now.st_dev, now.st_ino) or os.path.realpath(real) != real:
            raise FileProblem(f"{os.path.basename(real)} changed while it was read.")
        if st.st_size > limit:
            raise FileProblem(f"{os.path.basename(real)} is too large ({size_text(st.st_size)}).")
        data = f.read(limit + 1)
    if len(data) > limit:
        raise FileProblem(f"{os.path.basename(real)} is too large.")
    return data
