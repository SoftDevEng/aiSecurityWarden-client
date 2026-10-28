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
