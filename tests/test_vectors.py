"""The shared crypto test vectors (tests/vectors/crypto-v1.json) that the web front end is checked against.

If this fails after a deliberate change to crypto.py, every other implementation must change too (the
server repo's web front end): regenerate with `python -m securitywarden.vectors`, then update the copy
in the server repo and run its web tests.
"""

import json
import os

import pytest

from securitywarden import crypto, vectors

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "vectors", "crypto-v1.json")


@pytest.fixture(scope="module")
def v():
    with open(PATH, encoding="utf-8") as f:
        return json.load(f)


def test_vectors_match_crypto_py():
    with open(PATH, encoding="utf-8") as f:
        committed = f.read()
    assert vectors.render() == committed, \
        "crypto.py output changed: run `python tests/vectors/generate.py` and update web/src/lib/crypto.ts"


def test_vectors_decrypt(v):
    pw = v["project_key_wraps"]
    pid, pkey = pw["project_id"], bytes.fromhex(pw["project_key_hex"])
    assert crypto.unwrap_project_key_for_token(pw["token"]["blob"], crypto.parse_credential(pw["token"]["credential"]),
                                               pid) == pkey
    assert crypto.unwrap_project_key_for_admin(pw["admin"]["blob"], crypto.parse_credential(pw["admin"]["credential"]),
                                               pid) == pkey
    for s in v["secrets"]:
        assert crypto.decrypt_secret(bytes.fromhex(s["project_key_hex"]), s["project_id"], s["mac"], s["blob"]) == \
            (s["name"], s["value"])


def test_vectors_must_fail(v):
    mf = v["must_fail"]
    for c in mf["open"]:
        with pytest.raises(crypto.CryptoError):
            crypto.open_(bytes.fromhex(c["key_hex"]), c["blob"], c["aad"])
    for c in mf["secret"]:
        with pytest.raises(crypto.CryptoError):
            crypto.decrypt_secret(bytes.fromhex(c["project_key_hex"]), c["project_id"], c["mac"], c["blob"])
    for c in mf["project_key"]:
        cred = crypto.parse_credential(c["credential"])
        unwrap = crypto.unwrap_project_key_for_admin if cred.kind == "a" else crypto.unwrap_project_key_for_token
        with pytest.raises(crypto.CryptoError):
            unwrap(c["blob"], cred, c["project_id"])
    for text in v["credentials"]["invalid"]:
        with pytest.raises(crypto.CryptoError):
            crypto.parse_credential(text)


def test_account_vectors(v):
    a = v["accounts"]
    uid, acct = a["user_id"], bytes.fromhex(a["account_key_hex"])
    for p in a["passwords"]:
        m = crypto.master_key(p["password"], crypto.b64d(p["salt_b64"]), p["kdf"])
        assert m.hex() == p["master_hex"]
        assert crypto.b64e(crypto.account_auth_key(m)) == p["auth_key_b64"]
        assert crypto.unwrap_account_key_with_password(p["wrapped_key_password"], m, uid) == acct
    r = a["recovery"]
    rk = bytes.fromhex(r["key_hex"])
    assert crypto.format_recovery_key(rk) == r["text"]
    for t in [r["text"], *r["texts_ok"]]:
        assert crypto.parse_recovery_key(t) == rk
    for t in r["texts_bad"]:
        with pytest.raises(crypto.CryptoError):
            crypto.parse_recovery_key(t)
    assert crypto.unwrap_account_key_with_recovery(r["wrapped_key_recovery"], rk, uid) == acct
    for w in a["project_wraps"]:
        assert crypto.unwrap_project_key_for_account(w["blob"], acct, uid, w["project_id"]).hex() == w["project_key_hex"]
    for bad in a["bad_kdfs"]:
        with pytest.raises(ValueError):
            crypto.check_kdf(bad)


def test_account_vectors_must_fail(v):
    a = v["accounts"]
    acct = bytes.fromhex(a["account_key_hex"])
    for c in a["must_fail"]:
        with pytest.raises(crypto.CryptoError):
            if c["kind"] == "password":
                crypto.unwrap_account_key_with_password(c["blob"], bytes.fromhex(c["master_hex"]), c["user_id"])
            elif c["kind"] == "recovery":
                crypto.unwrap_account_key_with_recovery(c["blob"], bytes.fromhex(c["key_hex"]), c["user_id"])
            else:
                crypto.unwrap_project_key_for_account(c["blob"], acct, c["user_id"], c["project_id"])
