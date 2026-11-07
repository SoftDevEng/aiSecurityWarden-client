import os

import pytest

from securitywarden import crypto
from securitywarden.crypto import CryptoError


def test_credential_roundtrip():
    c = crypto.new_credential("m")
    parsed = crypto.parse_credential(str(c))
    assert parsed == c
    assert str(c).startswith("sw1.m.")


def test_credential_repr_hides_secrets():
    c = crypto.new_credential("a")
    r = repr(c)
    assert c.secret not in r and crypto.b64e(c.key) not in r


@pytest.mark.parametrize("bad", ["", "garbage", "sw1.x.aaaaaaaaaaaaaaaaaaaa.s:AAAA",
                                 "sw2.m.aaaaaaaaaaaaaaaaaaaa.s:" + "A" * 43,
                                 "sw1.m.short.s:" + "A" * 43,
                                 "sw1.m.aaaaaaaaaaaaaaaaaaaa.s:AAAA"])
def test_parse_rejects_malformed(bad):
    with pytest.raises(CryptoError):
        crypto.parse_credential(bad)


def test_secret_roundtrip_and_aad_binding():
    pk, pid = crypto.new_key(), crypto.new_id()
    mac, blob = crypto.encrypt_secret(pk, pid, "API_KEY", "s3cr3t")
    assert crypto.decrypt_secret(pk, pid, mac, blob) == ("API_KEY", "s3cr3t")
    with pytest.raises(CryptoError):  # moved to another project
        crypto.decrypt_secret(pk, crypto.new_id(), mac, blob)
    other_mac, _ = crypto.encrypt_secret(pk, pid, "OTHER", "x")
    with pytest.raises(CryptoError):  # stored under another name's id
        crypto.decrypt_secret(pk, pid, other_mac, blob)
    with pytest.raises(CryptoError):  # wrong key
        crypto.decrypt_secret(crypto.new_key(), pid, mac, blob)


def test_blob_does_not_contain_plaintext():
    pk, pid = crypto.new_key(), crypto.new_id()
    mac, blob = crypto.encrypt_secret(pk, pid, "WEBULL_APP_KEY", "plaintext-value-123")
    assert "WEBULL" not in blob and "plaintext" not in blob and "WEBULL" not in mac


def test_project_key_wrap_bound_to_token():
    pk, pid = crypto.new_key(), crypto.new_id()
    t1, t2 = crypto.new_credential("m"), crypto.new_credential("m")
    w = crypto.wrap_project_key_for_token(pk, t1, pid)
    assert crypto.unwrap_project_key_for_token(w, t1, pid) == pk
    with pytest.raises(CryptoError):
        crypto.unwrap_project_key_for_token(w, t2, pid)
    with pytest.raises(CryptoError):
        crypto.unwrap_project_key_for_token(w, t1, crypto.new_id())


def test_tampered_blob_rejected():
    pk, pid = crypto.new_key(), crypto.new_id()
    mac, blob = crypto.encrypt_secret(pk, pid, "A", "b")
    raw = bytearray(crypto.b64d(blob[3:]))
    raw[-1] ^= 1
    with pytest.raises(CryptoError):
        crypto.decrypt_secret(pk, pid, mac, "v1." + crypto.b64e(bytes(raw)))


# -- Ed25519 signatures (Discord interactions) ------------------------------------------------------

def _signed(message: bytes):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    k = Ed25519PrivateKey.generate()
    pub = k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return pub, k.sign(message).hex(), k


def test_ed25519_rejects_tampering_and_other_keys():
    msg = b"1700000000" + b'{"type":3}'
    pub, sig, _ = _signed(msg)
    other_pub, other_sig, _ = _signed(msg)
    assert not crypto.verify_ed25519(pub, msg + b" ", sig)          # body changed
    assert not crypto.verify_ed25519(pub, b"1700000001" + msg[10:], sig)   # timestamp changed
    assert not crypto.verify_ed25519(other_pub, msg, sig)          # another application's key
    assert not crypto.verify_ed25519(pub, msg, other_sig)
    assert crypto.verify_ed25519(pub, msg, sig)
    assert crypto.verify_ed25519(pub.upper(), msg, sig.upper())    # hex case doesn't matter


@pytest.mark.parametrize("pub,sig", [("", "00" * 64), ("zz" * 32, "00" * 64), ("00" * 31, "00" * 64),
                                     ("00" * 32, ""), ("00" * 32, "00" * 63), ("00" * 32, "gg" * 64),
                                     (None, "00" * 64), ("00" * 32, None)])
def test_ed25519_malformed_input_is_false_not_an_error(pub, sig):
    assert crypto.verify_ed25519(pub, b"x", sig) is False


def test_passkey_wrap_rejects_short_prf_and_swaps():
    acct = os.urandom(32)
    prf = os.urandom(32)
    blob = crypto.wrap_account_key_with_passkey(acct, prf, "u1", "c1")
    assert crypto.unwrap_account_key_with_passkey(blob, prf, "u1", "c1") == acct
    with pytest.raises(crypto.CryptoError):
        crypto.wrap_account_key_with_passkey(acct, prf[:16], "u1", "c1")
    for uid, cid, key in (("u2", "c1", prf), ("u1", "c2", prf), ("u1", "c1", os.urandom(32))):
        with pytest.raises(crypto.CryptoError):
            crypto.unwrap_account_key_with_passkey(blob, key, uid, cid)
    assert len(crypto.passkey_prf_salt()) == 32
