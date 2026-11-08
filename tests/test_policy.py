"""Approval policies and per-token address lists: the strict parsers shared by client and server."""

import pytest

from securitywarden.approval import DEFAULTS, describe, normalize_policy, parse_duration
from securitywarden.ipallow import ip_allowed, normalize_allowed_ips, parse_peer


def test_policy_rejects_bad_input():
    for bad in ({"mode": "always"}, {"channels": []}, {"channels": ["sms"]}, {"channels": "admin_ui"},
                {"timeout": 5}, {"timeout": 601}, {"session_ttl": 30}, {"session_ttl": 10**8},
                {"max_pending": 0}, {"max_pending": True}, {"timeout": "120"}, {"surprise": 1},
                {"max_pending": 5, "max_per_hour": 2}, [], "session"):
        with pytest.raises(ValueError):
            normalize_policy(bad)
    with pytest.raises(ValueError, match="not supported yet"):
        normalize_policy({"approvers": ["dev_x"]})


def test_policy_defaults_and_normalisation():
    assert normalize_policy(None) is None
    p = normalize_policy({"channels": ["push:ntfy", "admin_ui", "push:ntfy"]})
    assert p == {**DEFAULTS, "channels": ["push:ntfy", "admin_ui"]}
    assert describe(p) == "session 8h via push:ntfy, admin_ui" and describe(None) == "none"
    assert [parse_duration(x) for x in ("90", "90s", "30m", "8h", "2d", 45)] == [90, 90, 1800, 28800, 172800, 45]
    for bad in ("", "8 hours", "-1", "1.5h", True):
        with pytest.raises(ValueError):
            parse_duration(bad)


def test_normalize():
    assert normalize_allowed_ips(["192.168.1.12", " 10.0.0.0/8 ", "192.168.1.12/32"]) == \
        ["192.168.1.12/32", "10.0.0.0/8"]
    assert normalize_allowed_ips(["::1"]) == ["::1/128"]
    for bad in (["192.168.1.12/24"], ["jarvis.local"], [""], [], ["1.2.3"]):
        with pytest.raises(ValueError):
            normalize_allowed_ips(bad)
    with pytest.raises(ValueError):
        normalize_allowed_ips([f"10.0.0.{i}" for i in range(33)])


def test_parse_peer():
    assert parse_peer("192.168.1.12") == "192.168.1.12"
    assert parse_peer(" 192.168.1.12:51234 ") == "192.168.1.12"      # IIS/ARR appends the port
    assert parse_peer("[2001:db8::1]:443") == "2001:db8::1"
    assert parse_peer("2001:db8::1") == "2001:db8::1"
    assert parse_peer("::ffff:192.168.1.12") == "192.168.1.12"
    for bad in ("", None, "unknown", "testclient", "1.2.3.4.5", "evil, 1.2.3.4"):
        assert parse_peer(bad) is None


def test_ip_allowed():
    assert ip_allowed("192.168.1.12:5000", ["192.168.1.12/32"])
    assert ip_allowed("10.9.8.7", ["192.168.1.12/32", "10.0.0.0/8"])
    assert not ip_allowed("192.168.1.13", ["192.168.1.12/32"])
    assert not ip_allowed("unknown", ["0.0.0.0/0"])
    assert not ip_allowed("::1", ["0.0.0.0/0"])


def test_discord_is_a_push_channel():
    from securitywarden import approval
    assert "push:discord" in approval.PUSH_CHANNELS
    p = approval.normalize_policy({"channels": ["admin_ui", "push:discord"]})
    assert p["channels"] == ["admin_ui", "push:discord"]


def test_no_limit_for_wait_and_hourly_requests():
    from securitywarden.approval import (OPEN_REQUEST_MAX, normalize_action_policy, over_hourly_limit,
                                         request_timeout)
    p = normalize_policy({"timeout": None, "max_per_hour": None, "max_pending": 5})
    assert p["timeout"] is None and p["max_per_hour"] is None and p["max_pending"] == 5
    assert request_timeout(p) == OPEN_REQUEST_MAX and not over_hourly_limit(p, 10**6)
    assert request_timeout(normalize_policy({})) == 120 and over_hourly_limit(normalize_policy({}), 6)
    a = normalize_action_policy({"timeout": None, "max_per_hour": None, "max_pending": 50})
    assert request_timeout(a) == OPEN_REQUEST_MAX and not over_hourly_limit(a, 5000)
    # the flood guard can't be switched off, and other fields can't be null
    for bad in ({"max_pending": None}, {"session_ttl": None}, {"timeout": "none"}, {"max_per_hour": 0}):
        with pytest.raises(ValueError):
            normalize_policy(bad)
    with pytest.raises(ValueError):
        normalize_action_policy({"max_pending": None})


def test_swctl_and_swadmin_take_no_limit():
    from securitywarden.client import cli
    from securitywarden.client.gui import approval_policy, approval_summary
    args = cli.build_parser().parse_args(["admin", "token", "create", "proj", "--name", "bot", "--approval", "session",
                                          "--approval-timeout", "none", "--max-per-hour", "none"])
    pol = cli._policy_from_args(args)
    assert pol["timeout"] is None and pol["max_per_hour"] is None
    assert normalize_policy(pol)["max_per_hour"] is None
    pol = approval_policy("Once per session", "8", ["admin_ui"], timeout="", per_hour="", pending="2")
    assert pol["timeout"] is None and pol["max_per_hour"] is None and pol["max_pending"] == 2
    with pytest.raises(ValueError):
        approval_policy("Once per session", "8", ["admin_ui"], pending="")
    assert "no hourly limit" in approval_summary({"approval": pol, "approvals_this_hour": 3})
