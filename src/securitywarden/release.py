"""Signed client releases: what the server hands out for ``sw-mcp update`` / ``swctl update``.

A release is a client wheel plus a ``.swrel`` file next to it::

    {"manifest": {"format": "swrel1", "package": "securitywarden", "version": "0.6.0",
                  "file": "securitywarden-0.6.0-py3-none-any.whl", "sha256": "...", "size": 123456,
                  "published": "2026-11-11T12:00:00Z", "notes": "What changed, in a line or two."},
     "key_id": "...", "signature": "..."}

The manifest is signed with an Ed25519 release key kept offline (never on the server). Clients install a release
only if the signature checks out with a key in :data:`TRUSTED_KEYS`, the wheel's SHA-256 and size match, and the
version is newer than the installed one (no downgrades). See DESIGN.md "Client updates".

    python -m securitywarden.release keygen --out release-key.pem      # once; prints the public key
    python -m securitywarden.release sign dist/securitywarden-0.6.0-py3-none-any.whl --key release-key.pem \\
        --notes "Client updates from the MCP server"
    python -m securitywarden.release verify dist/securitywarden-0.6.0-py3-none-any.whl.swrel
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone
from typing import Any

from . import crypto

FORMAT = "swrel1"
PACKAGE = "securitywarden"
EXTENSION = ".swrel"
MAX_WHEEL = 50 * 1024 * 1024
MAX_NOTES = 2000
MAX_SWREL = 16 * 1024

# Release keys this client trusts: key id -> Ed25519 public key (hex). Generated with ``keygen``; the private key
# stays offline. Add a new key here one release *before* signing with it, so clients already trust it.
TRUSTED_KEYS: dict[str, str] = {"4d9bbf4bf2978cb7": "72d3cc9abfffb0275b35aa2cc799a9ddd264f359538a2b46723f30f3e54a3053",}

_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)(?:(a|b|rc)(\d+))?(?:\.post(\d+))?(?:\.dev(\d+))?$")
_PRE_RANK = {"a": 0, "b": 1, "rc": 2}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ReleaseError(Exception):
    """A release that must not be installed (bad signature, wrong file, not newer...). The message is shown."""


def version_key(v: str) -> tuple:
    """A sort key for PEP 440 versions of the forms this project uses (1.2.3, 1.2.3rc1, 1.2.3.post1,
    1.2.3.dev4). Raises ValueError for anything else."""
    m = _VERSION_RE.match(v.strip()) if isinstance(v, str) else None
    if not m:
        raise ValueError(f"not a version: {v!r}")
    rel = [int(x) for x in m.group(1).split(".")]
    while len(rel) > 1 and rel[-1] == 0:
        rel.pop()
    pre_l, pre_n, post, dev = m.group(2), m.group(3), m.group(4), m.group(5)
    if pre_l:
        pre = (_PRE_RANK[pre_l], int(pre_n))
    elif post is None and dev is not None:
        pre = (-1, 0)                    # 1.0.dev1 comes before 1.0a1
    else:
        pre = (3, 0)                     # a final release
    return (tuple(rel), pre, -1 if post is None else int(post), float("inf") if dev is None else int(dev))


def is_newer(candidate: str, installed: str) -> bool:
    return version_key(candidate) > version_key(installed)


def wheel_name(version: str) -> str:
    return f"{PACKAGE}-{version}-py3-none-any.whl"


def check_manifest(m: Any) -> dict[str, Any]:
    """The manifest if every field is well-formed, else ReleaseError."""
    if not isinstance(m, dict) or set(m) != {"format", "package", "version", "file", "sha256", "size",
                                            "published", "notes"}:
        raise ReleaseError("the release manifest has missing or unknown fields")
    if m["format"] != FORMAT or m["package"] != PACKAGE:
        raise ReleaseError("this isn't an aiSecurityWarden client release")
    try:
        version_key(m["version"])
    except ValueError:
        raise ReleaseError("the release has a malformed version") from None
    if m["file"] != wheel_name(m["version"]):
        raise ReleaseError("the release's file name doesn't match its version")
    if not isinstance(m["sha256"], str) or not SHA256_RE.match(m["sha256"]):
        raise ReleaseError("the release has a malformed SHA-256")
    if not isinstance(m["size"], int) or isinstance(m["size"], bool) or not 0 < m["size"] <= MAX_WHEEL:
        raise ReleaseError("the release has a bad size")
    if not isinstance(m["published"], str) or len(m["published"]) > 40:
        raise ReleaseError("the release has a bad date")
    if not isinstance(m["notes"], str) or len(m["notes"]) > MAX_NOTES:
        raise ReleaseError("the release notes are too long")
    return m


def verify(doc: Any, keys: dict[str, str] | None = None) -> dict[str, Any]:
    """Check a ``.swrel`` document: well-formed and signed by a trusted release key. Returns the manifest."""
    keys = TRUSTED_KEYS if keys is None else keys
    if not isinstance(doc, dict) or set(doc) != {"manifest", "key_id", "signature"}:
        raise ReleaseError("malformed release signature file")
    m = check_manifest(doc["manifest"])
    if not keys:
        raise ReleaseError("this client has no release key built in, so it can't check updates; update it by hand")
    pub = keys.get(doc["key_id"]) if isinstance(doc["key_id"], str) else None
    if not pub:
        raise ReleaseError("the release is signed with a key this client doesn't trust")
    if not crypto.verify_release(pub, m, doc["signature"]):
        raise ReleaseError("the release signature is wrong: not installing it")
    return m


def check_wheel(m: dict[str, Any], data: bytes) -> None:
    """The downloaded wheel is exactly the one the manifest names."""
    if len(data) != m["size"] or hashlib.sha256(data).hexdigest() != m["sha256"]:
        raise ReleaseError("the downloaded file doesn't match the signed release (size or SHA-256): not installing it")


def _wheel_version(path: str) -> str:
    """The version in the wheel's own METADATA (so a renamed file can't be signed as another version)."""
    with zipfile.ZipFile(path) as z:
        meta = [n for n in z.namelist() if re.fullmatch(r"securitywarden-[^/]+\.dist-info/METADATA", n)]
        if len(meta) != 1:
            raise ReleaseError(f"{path} isn't a securitywarden wheel")
        for line in z.read(meta[0]).decode("utf-8").splitlines():
            if line.startswith("Version:"):
                return line.split(":", 1)[1].strip()
    raise ReleaseError(f"{path} has no version in its metadata")


def make_manifest(wheel: str, notes: str = "", *, published: str | None = None) -> dict[str, Any]:
    with open(wheel, "rb") as f:
        data = f.read()
    version = _wheel_version(wheel)
    if os.path.basename(wheel) != wheel_name(version):
        raise ReleaseError(f"expected the file to be called {wheel_name(version)}")
    return check_manifest({
        "format": FORMAT, "package": PACKAGE, "version": version, "file": wheel_name(version),
        "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
        "published": published or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "notes": notes.strip(),
    })


def sign(wheel: str, pem: bytes, password: bytes, notes: str = "") -> dict[str, Any]:
    m = make_manifest(wheel, notes)
    key_id, sig = crypto.sign_release(pem, password, m)
    return {"manifest": m, "key_id": key_id, "signature": sig}


# ---------------------------------------------------------------------------
# command line (on the release workstation)
# ---------------------------------------------------------------------------

def _passphrase(confirm: bool) -> bytes:
    env = os.environ.get("SW_RELEASE_KEY_PASSPHRASE")     # for a build script; never on the command line
    if env:
        return env.encode("utf-8")
    p = getpass.getpass("Release key passphrase: ")
    if confirm and getpass.getpass("Again: ") != p:
        raise SystemExit("release: the passphrases don't match")
    return p.encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m securitywarden.release", description="sign client releases")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="make a release signing key (keep it offline) and print its public key")
    k.add_argument("--out", required=True, help="where to write the encrypted private key (PEM)")
    s = sub.add_parser("sign", help="write WHEEL.swrel next to a client wheel")
    s.add_argument("wheel")
    s.add_argument("--key", required=True, help="the release key (PEM)")
    s.add_argument("--notes", default="", help="what changed, in a line or two (shown to the user)")
    s.add_argument("--notes-file", help="read the notes from a file instead")
    v = sub.add_parser("verify", help="check a .swrel file (and its wheel, if next to it) with the built-in keys")
    v.add_argument("swrel")
    v.add_argument("--public-key", help="check with this public key (hex) instead of the built-in ones")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "keygen":
            if os.path.exists(a.out):
                raise SystemExit(f"release: {a.out} exists; not overwriting a key")
            pem, pub = crypto.new_release_key(_passphrase(True))
            fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
            kid = crypto.release_key_id(pub)
            print(f"Wrote {a.out}. Keep it offline, with its passphrase in your password manager.")
            print("Add this line to TRUSTED_KEYS in src/securitywarden/release.py and release that client first:")
            print(f'    "{kid}": "{pub}",')
        elif a.cmd == "sign":
            notes = open(a.notes_file, encoding="utf-8").read() if a.notes_file else a.notes
            with open(a.key, "rb") as f:
                pem = f.read()
            doc = sign(a.wheel, pem, _passphrase(False), notes)
            out = a.wheel + EXTENSION
            with open(out, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=1)
                f.write("\n")
            verified = doc["key_id"] in TRUSTED_KEYS
            print(f"Wrote {out} (version {doc['manifest']['version']}, key {doc['key_id']})")
            if not verified:
                print("Warning: this key isn't in TRUSTED_KEYS of this client: installed clients won't accept it "
                      "until a client that trusts it is out.", file=sys.stderr)
        else:
            with open(a.swrel, encoding="utf-8") as f:
                doc = json.load(f)
            keys = None
            if a.public_key:
                keys = {crypto.release_key_id(a.public_key): a.public_key.lower()}
            m = verify(doc, keys)
            wheel = os.path.join(os.path.dirname(a.swrel), m["file"])
            if os.path.exists(wheel):
                with open(wheel, "rb") as f:
                    check_wheel(m, f.read())
                print(f"ok: {m['file']} {m['version']} (signature and file)")
            else:
                print(f"ok: {m['file']} {m['version']} (signature; wheel not found next to it)")
    except (ReleaseError, crypto.CryptoError, OSError, json.JSONDecodeError) as e:
        print(f"release: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
