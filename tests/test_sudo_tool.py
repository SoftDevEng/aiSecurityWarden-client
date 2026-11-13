"""sw-mcp's system_run tool (mcp/sudo_tool.py): offered only where sw-sudo is set up for this user; runs
sudo -n sw-sudo --json and turns its answer into the usual waiting_for_approval / check_approval flow."""

import json
import subprocess
from types import SimpleNamespace

import pytest

from securitywarden.mcp.framework import Hub
from securitywarden.mcp.sudo_tool import SudoTool

UID = 4242


class FakeSudo:
    """Stands in for subprocess.run of 'sudo -n sw-sudo --json ...'."""

    def __init__(self):
        self.calls = []
        self.answers = []

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        out = self.answers.pop(0)
        if isinstance(out, tuple):                      # (returncode, stderr): sudo itself refused
            return SimpleNamespace(returncode=out[0], stdout="", stderr=out[1])
        return SimpleNamespace(returncode=0, stdout=json.dumps(out) + "\n", stderr="")


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / "sw-sudo.json"
    p.write_text(json.dumps({"agent_uid": UID, "exe": "/usr/local/bin/sw-sudo", "server": "https://x"}))
    return str(p)


@pytest.fixture
def fake():
    return FakeSudo()


@pytest.fixture
def tool(cfg, fake, monkeypatch):
    monkeypatch.setattr("sys.platform", "linux")
    return SudoTool(config_path=cfg, runner=fake, uid=lambda: UID)


def test_not_offered_without_sw_sudo_for_this_user(cfg, fake, monkeypatch, tmp_path):
    monkeypatch.setattr("sys.platform", "linux")
    assert not SudoTool(config_path=str(tmp_path / "missing.json"), runner=fake, uid=lambda: UID).available()
    assert not SudoTool(config_path=cfg, runner=fake, uid=lambda: 1001).available()     # set up for another user
    monkeypatch.setattr("sys.platform", "win32")
    assert not SudoTool(config_path=cfg, runner=fake, uid=lambda: UID).available()


def test_bad_arguments_are_refused_without_calling_sudo(tool, fake):
    for args in ({}, {"command": "apt update"}, {"command": []}, {"command": ["apt", 1]},
                 {"command": ["apt install ffmpeg"]}, {"command": ["ls"], "extra": 1}, {"command": ["ls"], "reason": 5}):
        assert tool.run(args).is_error, args
    assert not fake.calls


def test_asks_then_runs_on_check_approval(tool, fake):
    fake.answers = [{"status": "waiting_for_approval", "request_id": "r" * 22, "match": "47", "check_after": 10},
                    {"status": "waiting_for_approval", "request_id": "r" * 22, "check_after": 15},
                    {"status": "done", "exit_code": 0, "stdout": "ffmpeg installed\n", "stderr": "", "cut": False}]
    r = tool.run({"command": ["apt", "install", "-y", "ffmpeg"], "reason": "video"})
    assert not r.is_error and "waiting_for_approval" in r.text and "47" in r.text and "r" * 22 in r.text
    assert fake.calls[0] == ["/usr/bin/sudo", "-n", "/usr/local/bin/sw-sudo", "--json", "--no-wait", "--reason",
                             "video", "--", "apt", "install", "-y", "ffmpeg"]
    assert tool.handles("r" * 22)
    assert "waiting_for_approval" in tool.check("r" * 22).text
    done = tool.check("r" * 22)
    assert not done.is_error and "exit code 0" in done.text and "UNTRUSTED DATA" in done.text
    assert "ffmpeg installed" in done.text and not tool.handles("r" * 22)
    assert fake.calls[1][-2:] == ["--status", "r" * 22]


def test_denials_refusals_and_sudo_problems_are_errors(tool, fake):
    fake.answers = [{"status": "denied", "reason": "approval_denied", "comment": "use apt-get"},
                    {"status": "refused", "reason": "bash runs other commands"},
                    (1, "sudo: a password is required")]
    r = tool.run({"command": ["apt", "install", "x"]})
    assert r.is_error and "use apt-get" in r.text
    r = tool.run({"command": ["bash"]})
    assert r.is_error and "bash runs other commands" in r.text
    r = tool.run({"command": ["ls"]})
    assert r.is_error and "sudo refused" in r.text and "password is required" in r.text


def test_a_failing_command_is_an_error_with_its_exit_code(tool, fake):
    fake.answers = [{"status": "done", "exit_code": 100, "stdout": "", "stderr": "E: Unable to locate", "cut": True}]
    r = tool.run({"command": ["apt", "install", "nope"]})
    assert r.is_error and "exit code 100" in r.text and "output was cut" in r.text


def test_the_hub_offers_it_and_routes_check_approval(tool, fake):
    hub = Hub(None, [], sudo=tool)
    names = [t["name"] for t in hub.list_tools()]
    assert "system_run" in names
    fake.answers = [{"status": "waiting_for_approval", "request_id": "q" * 22, "match": "12"},
                    {"status": "done", "exit_code": 0, "stdout": "ok", "stderr": "", "cut": False}]
    assert "waiting_for_approval" in hub.call("system_run", {"command": ["apt", "update"]}).text
    assert "exit code 0" in hub.call("check_approval", {"request_id": "q" * 22}).text


def test_the_hub_doesnt_offer_it_where_sw_sudo_isnt_set_up(fake, tmp_path, monkeypatch):
    monkeypatch.setattr("sys.platform", "linux")
    hub = Hub(None, [], sudo=SudoTool(config_path=str(tmp_path / "none.json"), runner=fake, uid=lambda: UID))
    names = [t["name"] for t in hub.list_tools()]
    assert "system_run" not in names
