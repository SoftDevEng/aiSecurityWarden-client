"""Account rules shared by the server and clients. Standard library only."""

from __future__ import annotations

import re
import unicodedata

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")
MAX_EMAIL = 254
MIN_PASSWORD = 12
MAX_PASSWORD = 1024


def normalize_email(email: str) -> str:
    """trim, NFC, lowercase. Raises ValueError for something that can't be an address."""
    e = unicodedata.normalize("NFC", (email or "").strip()).lower()
    if len(e) > MAX_EMAIL or not EMAIL_RE.match(e):
        raise ValueError("enter a valid email address")
    return e


def password_problem(password: str, email: str = "") -> str | None:
    """Why a new password can't be used, or None. Enforced by clients: the server never sees passwords."""
    pw = unicodedata.normalize("NFC", password or "")
    if len(pw) < MIN_PASSWORD:
        return f"use at least {MIN_PASSWORD} characters"
    if len(pw) > MAX_PASSWORD:
        return f"use at most {MAX_PASSWORD} characters"
    if email and pw.strip().lower() == email.strip().lower():
        return "don't use your email address as the password"
    if len(set(pw)) < 4:
        return "use more different characters"
    return None
