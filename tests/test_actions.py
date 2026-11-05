"""Action approval, client side: policies, rule decisions, summaries, digests and encrypted summaries.
The server side (requests, approvals, redemption) is tested in the server repo against this package."""

import json
import os

import pytest

from securitywarden import approval, crypto
from securitywarden.approval import (action_decision, describe_actions, normalize_action_policy,
                                     normalize_action_summary, parse_action_rule, rule_matches)
from securitywarden.crypto import CryptoError

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "vectors", "crypto-v1.json"), encoding="utf-8") as _f:
    V = json.load(_f)["actions"]


# -- policies ------------------------------------------------------------------------

def test_default_policy_asks_for_everything():
    assert normalize_action_policy(None) is None
    assert action_decision(None, "gmail.read.search", "low") == ("each", None)
    assert describe_actions(None) == "ask for every action via admin_ui (default)"


def test_policy_vectors():
    p = V["policy"]
    assert normalize_action_policy(p["input"]) == p["output"]
    for d in p["decisions"]:
        if d["mode"] is None:
            with pytest.raises(ValueError):
                action_decision(p["output"], d["action"], d["risk"])
        else:
            assert action_decision(p["output"], d["action"], d["risk"]) == (d["mode"], d["window"]), d
    assert describe_actions(p["output"]) == p["describe"]
    for bad in V["bad_policies"]:
        with pytest.raises(ValueError):
            normalize_action_policy(bad)


def test_high_risk_is_never_allowed_or_windowed():
    p = normalize_action_policy({"rules": [{"match": "*", "mode": "allow"}]})
    assert action_decision(p, "gmail.send", "high") == ("each", None)
    assert action_decision(p, "gmail.send", "medium") == ("allow", None)
    p = normalize_action_policy({"rules": [{"match": "gmail.*", "mode": "window", "window": 600}]})
    assert action_decision(p, "gmail.send", "high") == ("each", None)
    assert action_decision(p, "gmail.label", "low") == ("window", 600)
    # deny stays deny whatever the risk
    p = normalize_action_policy({"rules": [{"match": "gmail.*", "mode": "deny"}]})
    assert action_decision(p, "gmail.read.search", "low") == ("deny", None)


def test_first_matching_rule_wins_and_patterns():
    p = normalize_action_policy({"rules": [{"match": "gmail.send", "mode": "deny"},
                                           {"match": "gmail.*", "mode": "allow"}]})
    assert action_decision(p, "gmail.send", "low") == ("deny", None)
    assert action_decision(p, "gmail.label", "low") == ("allow", None)
    assert rule_matches("gmail.*", "gmail.read.search") and rule_matches("gmail.read.*", "gmail.read")
    assert not rule_matches("gmail.read.*", "gmail.readx") and not rule_matches("gmail.send", "gmail.send.now")
    assert rule_matches("*", "anything.at.all")


def test_bad_action_names_and_risks():
    for bad in ("", "gmail", "Gmail.send", "gmail..send", "gmail.send!", "1gmail.send", "a." * 7 + "b"):
        with pytest.raises(ValueError):
            action_decision(None, bad, "low")
    with pytest.raises(ValueError):
        action_decision(None, "gmail.send", "extreme")


def test_parse_action_rule():
    assert parse_action_rule("gmail.send=each") == {"match": "gmail.send", "mode": "each"}
    assert parse_action_rule(" gmail.label = window:30m") == {"match": "gmail.label", "mode": "window", "window": 1800}
    for bad in ("gmail.send", "gmail.label=window", "gmail.label=window:soon"):
        with pytest.raises(ValueError):
            parse_action_rule(bad)


# -- summaries -----------------------------------------------------------------------

def test_summary_rules():
    s = normalize_action_summary({"title": " Send an email ", "fields": [("To", "bob@example.com")]})
    assert s == {"title": "Send an email", "fields": [["To", "bob@example.com"]], "count": 1}
    for bad in ({}, {"title": ""}, {"title": "x" * 101}, {"title": "t", "fields": [["only one"]]},
                {"title": "t", "fields": [["l", "v"]] * 11}, {"title": "t", "preview": "p" * 501},
                {"title": "t", "count": 0}, {"title": "t", "count": True}, {"title": "t", "extra": 1},
                {"title": "t", "fields": [["l" * 41, "v"]]}):
        with pytest.raises(ValueError):
            normalize_action_summary(bad)
    assert approval.clip("a  b\nc", 10) == "a b c" and approval.clip("x" * 20, 10) == "x" * 9 + "…"


# -- digests and encrypted summaries -------------------------------------------------

def test_digest_vectors_and_canonical_form():
    for d in V["digests"]:
        assert crypto.action_digest(d["action"], d["args"]) == d["digest"]
    a = crypto.action_digest("gmail.send", {"to": ["b@x.example"], "subject": "Hi"})
    assert a == crypto.action_digest("gmail.send", {"subject": "Hi", "to": ["b@x.example"]})   # key order
    assert a != crypto.action_digest("gmail.send", {"to": ["c@x.example"], "subject": "Hi"})   # any change
    assert a != crypto.action_digest("gmail.forward", {"to": ["b@x.example"], "subject": "Hi"})  # the action too
    for bad in ({"amount": 1.5}, {"blob": b"bytes"}, {1: "x"}, {"s": {1, 2}}):
        with pytest.raises(CryptoError):
            crypto.action_digest("x.y", bad)


def test_summary_encryption_vectors():
    s = V["summary"]
    pkey = bytes.fromhex(s["project_key_hex"])
    assert crypto.decrypt_action_summary(pkey, s["project_id"], s["request_id"], s["blob"]) == s["summary"]
    for bad in V["summary_must_fail"]:
        with pytest.raises(CryptoError):
            crypto.decrypt_action_summary(pkey, bad["project_id"], bad["request_id"], bad["blob"])
    # round trip with a fresh nonce
    blob = crypto.encrypt_action_summary(pkey, "p" * 22, "r" * 22, {"title": "t", "fields": [], "count": 1})
    assert crypto.decrypt_action_summary(pkey, "p" * 22, "r" * 22, blob)["title"] == "t"
    with pytest.raises(CryptoError):
        crypto.decrypt_action_summary(crypto.new_key(), "p" * 22, "r" * 22, blob)


def test_comment_encryption_vectors():
    c = V["comment"]
    pkey = bytes.fromhex(c["project_key_hex"])
    assert crypto.decrypt_approval_comment(pkey, c["project_id"], c["request_id"], c["blob"]) == c["comment"]
    assert c["max"] == crypto.APPROVAL_COMMENT_MAX
    for bad in V["comment_must_fail"]:
        with pytest.raises(CryptoError):
            crypto.decrypt_approval_comment(pkey, bad["project_id"], bad["request_id"], bad["blob"])
    for bad in V["bad_comments"]:
        with pytest.raises(ValueError):
            crypto.normalize_approval_comment(bad)
    assert crypto.normalize_approval_comment("  two\r\nlines\t ok ") == "two\nlines\t ok"
    blob = crypto.encrypt_approval_comment(pkey, "p" * 22, "r" * 22, "x" * crypto.APPROVAL_COMMENT_MAX)
    assert crypto.decrypt_approval_comment(pkey, "p" * 22, "r" * 22, blob) == "x" * crypto.APPROVAL_COMMENT_MAX
    with pytest.raises(CryptoError):
        crypto.decrypt_approval_comment(crypto.new_key(), "p" * 22, "r" * 22, blob)


def test_check_action_returns_the_denial_comment():
    """The server's 403 carries the comment encrypted (website) or plain (Telegram / Discord)."""
    import time

    import httpx
    from securitywarden.client.api import ApprovalError, SecurityWardenClient

    pid, rid, pkey = crypto.new_id(), crypto.new_id(), crypto.new_key()
    answers = {
        "enc": {"detail": "approval_denied", "comment_enc": crypto.encrypt_approval_comment(pkey, pid, rid, "Use Ann")},
        "plain": {"detail": "approval_denied", "comment": "  Wait until Friday "},
        "none": {"detail": "approval_denied"},
        "junk": {"detail": "approval_denied", "comment_enc": "v1.AAAA"},
        "other": {"detail": "approval_denied", "comment_enc": crypto.encrypt_approval_comment(pkey, pid, "x" * 22, "no")},
        "expired": {"detail": "approval_expired", "comment": "ignored"},
    }
    which = {"k": ""}
    http = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(403, json=answers[which["k"]])))
    c = SecurityWardenClient("https://sw.example", crypto.new_credential(crypto.KIND_MACHINE), http=http)
    c._token, c._token_exp = "t", time.monotonic() + 600
    c._action_cfg = {"project_id": pid, "project_key": pkey, "summaries": "plain"}
    for k, (reason, comment) in {"enc": ("approval_denied", "Use Ann"), "plain": ("approval_denied", "Wait until Friday"),
                                 "none": ("approval_denied", None), "junk": ("approval_denied", None),
                                 "other": ("approval_denied", None), "expired": ("approval_expired", None)}.items():
        which["k"] = k
        with pytest.raises(ApprovalError) as e:
            c.check_action(rid, "n", "d")
        assert (e.value.reason, e.value.comment) == (reason, comment), k
