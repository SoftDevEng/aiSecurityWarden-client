"""Second factor: TOTP (RFC 6238), recovery codes and server-side sealing at rest (crypto.py)."""
import re
from urllib.parse import parse_qs, urlparse

import pytest

from securitywarden import crypto as c

RFC_KEY = b"12345678901234567890"          # RFC 6238 appendix B, SHA-1


@pytest.mark.parametrize("t, code", [(59, "287082"), (1111111109, "081804"), (1111111111, "050471"),
                                     (1234567890, "005924"), (2000000000, "279037")])
def test_rfc6238_vectors(t, code):
    assert c.totp_code(RFC_KEY, t) == code
    assert c.totp_check(RFC_KEY, code, t) == t // 30


def test_one_step_of_drift_either_side_and_no_more():
    t = 1_700_000_000
    code = c.totp_code(RFC_KEY, t)
    assert c.totp_check(RFC_KEY, code, t + 30) == t // 30          # phone a step behind
    assert c.totp_check(RFC_KEY, code, t - 30) == t // 30          # phone a step ahead
    assert c.totp_check(RFC_KEY, code, t + 60) is None
    assert c.totp_check(RFC_KEY, code, t - 60) is None


def test_a_used_step_is_refused():
    t = 1_700_000_000
    code = c.totp_code(RFC_KEY, t)
    step = c.totp_check(RFC_KEY, code, t)
    assert c.totp_check(RFC_KEY, code, t, after_step=step) is None          # the same code again
    assert c.totp_check(RFC_KEY, code, t + 30, after_step=step) is None
    nxt = c.totp_code(RFC_KEY, t + 30)
    assert c.totp_check(RFC_KEY, nxt, t + 30, after_step=step) == step + 1  # the next one is fine


@pytest.mark.parametrize("text", ["", "12345", "1234567", "abcdef", "12 34 5", None])
def test_malformed_codes_are_refused(text):
    assert c.totp_check(RFC_KEY, text, 59) is None


def test_codes_may_be_typed_with_a_space_or_dash():
    assert c.totp_check(RFC_KEY, "287 082", 59) == 1
    assert c.totp_check(RFC_KEY, "287-082", 59) == 1


def test_wrong_key_fails():
    assert c.totp_check(c.new_totp_key(), "287082", 59) is None


def test_key_text_and_uri_are_what_authenticator_apps_read():
    key = c.new_totp_key()
    assert len(key) == 20
    text = c.totp_key_text(key)
    assert re.fullmatch(r"([A-Z2-7]{4} ){7}[A-Z2-7]{4}", text)
    u = urlparse(c.totp_uri(key, "brian@example.com"))
    assert (u.scheme, u.netloc) == ("otpauth", "totp")
    assert u.path == "/aiSecurityWarden:brian@example.com"
    q = parse_qs(u.query)
    assert q["secret"] == [text.replace(" ", "")]
    assert q["issuer"] == ["aiSecurityWarden"]
    assert (q["algorithm"], q["digits"], q["period"]) == (["SHA1"], ["6"], ["30"])


def test_recovery_codes():
    codes = c.new_recovery_codes()
    assert len(codes) == 10 and len(set(codes)) == 10
    for code in codes:
        assert re.fullmatch(r"[a-z2-7]{5}-[a-z2-7]{5}", code)
    k = c.new_at_rest_key()
    h = c.recovery_code_hash(k, codes[0])
    assert c.recovery_code_hash(k, codes[0].upper().replace("-", " ")) == h      # typed loosely
    assert c.recovery_code_hash(c.new_at_rest_key(), codes[0]) != h              # keyed
    assert codes[0] not in h
    for bad in ("", "abc", "12345-67890", codes[0] + "x"):
        assert c.normalize_recovery_code(bad) is None
        with pytest.raises(c.CryptoError):
            c.recovery_code_hash(k, bad)


def test_at_rest_sealing_is_bound_to_its_context():
    k = c.new_at_rest_key()
    blob = c.seal_at_rest(k, b"totp key", "totp|user|abc")
    assert blob.startswith("v1.")
    assert c.open_at_rest(k, blob, "totp|user|abc") == b"totp key"
    with pytest.raises(c.CryptoError):
        c.open_at_rest(k, blob, "totp|user|xyz")                 # moved to another account
    with pytest.raises(c.CryptoError):
        c.open_at_rest(c.new_at_rest_key(), blob, "totp|user|abc")  # another server's key
