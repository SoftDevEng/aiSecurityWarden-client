"""sw-sudo (securitywarden.sudo): root commands one at a time with approval. Negative tests first: who may call it,
what is refused before anything is asked, and that only the exact approved command runs, once."""

import io
import json
import os
import sys

import pytest

from securitywarden import crypto
from securitywarden import sudo
from securitywarden.client.api import ApprovalError

pytestmark = pytest.mark.skipif(sys.platform != "linux" or os.geteuid() != 0,
                                reason="sw-sudo is Linux only; these tests chown files to a fake agent user")

AGENT = 4242          # a uid with no account: files we chown to it are "the agent's"


class FakeServer:
    """What request_action / check_action would do, decided by the test."""

    def __init__(self, decision="approved", pending_checks=0):
        self.decision, self.pending_checks = decision, pending_checks
        self.requests: list[dict] = []
        self.checks = 0

    def request_action(self, action, args, summary, *, risk="high", scope=None):
        self.requests.append({"action": action, "args": args, "summary": summary, "risk": risk, "scope": scope,
                              "digest": crypto.action_digest(action, args)})
        if self.decision == "denied_by_rule":
            raise ApprovalError("action_denied")
        status = "approved" if self.decision == "allow" else "pending"
        return {"status": status, "request_id": crypto.new_id(), "nonce": crypto.new_nonce(),
                "digest": self.requests[-1]["digest"], "match": "47", "expires_in": 120, "check_after": 1}

    def check_action(self, request_id, nonce, digest):
        self.checks += 1
        if self.checks <= self.pending_checks:
            return "pending"
        if self.decision == "denied":
            raise ApprovalError("approval_denied", "use apt-get instead")
        return "approved"


@pytest.fixture
def server():
    return FakeServer()


@pytest.fixture
def ctx(server, tmp_path):
    def make(**kw):
        cfg = {**sudo.DEFAULT_CONFIG, "server": "https://sw.example", "agent_uid": AGENT, **kw.pop("config", {})}
        return sudo.Context(euid=kw.pop("euid", 0), sudo_uid=kw.pop("sudo_uid", str(AGENT)), config=cfg,
                            client_factory=lambda c: server, host="jarvis", out=io.StringIO(), err=io.StringIO(),
                            sleep=lambda s: None, state_dir=str(tmp_path / "state"), **kw)
    return make


@pytest.fixture
def rootdir():
    """A folder only root can change (tmp_path is under /tmp, which every user can write to)."""
    import shutil
    import tempfile
    d = tempfile.mkdtemp(dir="/root" if os.path.isdir("/root") else "/var/lib")
    os.chmod(d, 0o755)
    yield d
    shutil.rmtree(d)


def agent_file(tmp_path, name="fix.sh", body="#!/bin/sh\necho hi\n"):
    p = tmp_path / name
    p.write_text(body)
    os.chmod(p, 0o755)
    os.chown(p, AGENT, AGENT)
    return str(p)


# -- who may use it ------------------------------------------------------------------------------

def test_must_run_through_sudo_as_the_agent_user(ctx, server):
    for c in (ctx(euid=1000), ctx(sudo_uid=None), ctx(sudo_uid="0"), ctx(sudo_uid="1001"), ctx(sudo_uid="x")):
        assert sudo.run(["echo", "hi"], c) == sudo.EXIT_REFUSED
    assert not server.requests


# -- refused before anything is asked --------------------------------------------------------------

@pytest.mark.parametrize("argv", [
    ["bash", "-c", "id"], ["sh"], ["/bin/sh", "-c", "x"], ["python3", "-c", "1"], ["perl", "-e", "1"],
    ["env", "id"], ["sudo", "id"], ["su"], ["vi", "/etc/hosts"], ["less", "/etc/hosts"], ["xargs", "id"],
    ["find", "/", "-exec", "id", ";"], ["apt", "-o", "APT::Update::Pre-Invoke::=id", "update"],
    ["apt-get", "--option=x", "update"], ["tar", "--to-command=id", "-xf", "/dev/null"],
    ["visudo"], ["usermod", "-aG", "sudo", "hermes"], ["passwd", "hermes"], ["gpasswd", "-a", "hermes", "sudo"],
    ["cp", "/dev/null", "/etc/sudoers.d/x"], ["chmod", "777", "/etc/shadow"], ["rm", "/etc/securitywarden/sw-sudo.token"],
    ["systemctl", "edit", "ssh"], [], ["echo", "a\nb"],
])
def test_refused_commands(argv, ctx, server):
    c = ctx()
    assert sudo.run(argv, c) == sudo.EXIT_REFUSED, argv
    assert "refused" in c.err.getvalue()
    assert not server.requests


def test_a_program_or_argument_the_agent_can_change_is_refused(ctx, server, rootdir):
    script = agent_file(__import__("pathlib").Path(rootdir))
    c = ctx()
    assert sudo.run([script], c) == sudo.EXIT_REFUSED and "agent" in c.err.getvalue()
    assert sudo.run(["cat", script], ctx()) == sudo.EXIT_REFUSED                 # a file the agent controls
    folder = __import__("pathlib").Path(rootdir) / "agentdir"
    folder.mkdir()
    os.chown(folder, AGENT, AGENT)
    root_owned = folder / "tool"
    root_owned.write_text("#!/bin/true\n")
    os.chmod(root_owned, 0o755)                                                # root's file, agent's folder
    assert sudo.run([str(root_owned)], ctx()) == sudo.EXIT_REFUSED
    assert not server.requests


def test_a_renamed_copy_of_a_shell_is_still_a_shell(ctx, server, rootdir):
    shell = os.path.realpath("/bin/sh")
    if os.stat(shell).st_dev != os.stat(rootdir).st_dev:
        pytest.skip("different filesystem")
    os.link(shell, os.path.join(rootdir, "harmless"))
    c = ctx()
    assert sudo.run([os.path.join(rootdir, "harmless")], c) == sudo.EXIT_REFUSED
    assert "is a shell" in c.err.getvalue()
    assert not server.requests


def test_anything_under_tmp_is_refused(ctx, server, tmp_path):
    p = tmp_path / "tool"
    p.write_text("#!/usr/bin/true\n")
    os.chmod(p, 0o755)
    assert sudo.run([str(p)], ctx()) == sudo.EXIT_REFUSED


def test_an_owner_can_allow_a_listed_program_knowingly(ctx, server):
    c = ctx(config={"allow_programs": [os.path.realpath("/usr/bin/env")]})
    server.decision = "allow"
    assert sudo.run(["/usr/bin/env"], c) == 0


# -- what is asked, and what runs ---------------------------------------------------------------

def test_the_request_names_the_exact_command_and_program_file(ctx, server):
    server.decision = "allow"
    c = ctx()
    assert sudo.run(["echo", "hello", "a/b"], c, reason="checking the tool works") == 0
    r = server.requests[0]
    assert r["action"] == "system.run" and r["risk"] == "high"
    assert r["args"]["argv"] == ["echo", "hello", "a/b"] and r["args"]["program"] == os.path.realpath("/usr/bin/echo")
    assert set(r["args"]["file"]) == {"dev", "ino", "size", "mtime_ns"} and r["args"]["host"] == "jarvis"
    assert r["scope"] == {"program": os.path.realpath("/usr/bin/echo"), "cmd": "echo/hello/a%2Fb"}
    assert ["Agent says", "checking the tool works"] in r["summary"]["fields"]
    assert c.out.getvalue() == "hello a/b\n"


def test_runs_with_a_clean_environment_in_root_folder(ctx, server, monkeypatch):
    server.decision = "allow"
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    monkeypatch.setenv("PYTHONPATH", "/tmp")
    c = ctx()
    assert sudo.run(["/usr/bin/env"], ctx(config={"allow_programs": [os.path.realpath("/usr/bin/env")]})) == 0
    c = ctx()
    assert sudo.run(["pwd"], c) == 0 and c.out.getvalue().strip() == "/"
    env = sudo.clean_env()
    assert "LD_PRELOAD" not in env and "PYTHONPATH" not in env and env["PATH"] == sudo.SAFE_PATH


def test_waits_for_the_decision_then_runs_once(ctx):
    s = FakeServer(decision="approved", pending_checks=2)
    c = ctx()
    c.client_factory = lambda cfg: s
    assert sudo.run(["echo", "ok"], c) == 0
    assert s.checks == 3 and "match code 47" in c.err.getvalue() and c.out.getvalue() == "ok\n"


def test_denied_with_a_comment_runs_nothing(ctx):
    s = FakeServer(decision="denied")
    c = ctx()
    c.client_factory = lambda cfg: s
    assert sudo.run(["echo", "nope"], c) == sudo.EXIT_DENIED
    assert c.out.getvalue() == "" and "use apt-get instead" in c.err.getvalue()


def test_denied_by_a_rule_runs_nothing(ctx, server):
    server.decision = "denied_by_rule"
    c = ctx()
    assert sudo.run(["echo", "x"], c) == sudo.EXIT_DENIED and c.out.getvalue() == ""


def test_a_program_changed_after_approval_is_refused(ctx, rootdir):
    prog = os.path.join(rootdir, "tool")
    with open(prog, "w") as f:
        f.write("#!/usr/bin/true\n")
    os.chmod(prog, 0o755)

    class Swap(FakeServer):
        def check_action(self, *a):
            with open(prog, "a") as f:          # root (not the agent) changes it while waiting: still refused
                f.write("# changed\n")
            return "approved"
    s = Swap()
    c = ctx()
    c.client_factory = lambda cfg: s
    assert sudo.run([str(prog)], c) == sudo.EXIT_REFUSED
    assert "changed after it was approved" in c.err.getvalue()


def test_no_wait_then_status_runs_it_once_approved(ctx):
    s = FakeServer(decision="approved", pending_checks=1)
    c = ctx()
    c.client_factory = lambda cfg: s
    assert sudo.run(["echo", "later"], c, wait=False) == sudo.EXIT_PENDING
    rid = c.err.getvalue().split("--status ")[1].split()[0]
    pending = os.path.join(c.state_dir, rid + ".json")
    assert oct(os.stat(c.state_dir).st_mode & 0o777) == "0o700" and oct(os.stat(pending).st_mode & 0o777) == "0o600"
    assert sudo.status(rid, c) == sudo.EXIT_PENDING
    assert sudo.status(rid, c) == 0 and c.out.getvalue() == "later\n"
    assert not os.path.exists(pending)
    assert sudo.status(rid, c) == sudo.EXIT_REFUSED                      # used up


def test_status_refuses_odd_ids_and_other_callers(ctx):
    assert sudo.status("../../etc/passwd", ctx()) == sudo.EXIT_REFUSED
    assert sudo.status(crypto.new_id(), ctx(sudo_uid="1001")) == sudo.EXIT_REFUSED


def test_output_is_capped_and_long_commands_stopped(ctx, server):
    server.decision = "allow"
    c = ctx(config={"max_output": 10})
    assert sudo.run(["echo", "0123456789abcdef"], c) == 0
    assert c.out.getvalue() == "0123456789" and "cut at 10 bytes" in c.err.getvalue()
    c = ctx(config={"command_timeout": 1})
    assert sudo.run(["sleep", "5"], c) == sudo.EXIT_TIMEOUT


# -- set-up ----------------------------------------------------------------------------------------

def test_config_must_be_root_owned_and_not_writable_by_others(tmp_path):
    p = tmp_path / "sw-sudo.json"
    p.write_text(json.dumps({"server": "https://x", "agent_uid": AGENT}))
    os.chmod(p, 0o644)
    assert sudo.load_config(str(p))["agent_uid"] == AGENT
    os.chmod(p, 0o666)
    with pytest.raises(sudo.Refused):
        sudo.load_config(str(p))
    os.chmod(p, 0o644)
    os.chown(p, AGENT, AGENT)
    with pytest.raises(sudo.Refused):
        sudo.load_config(str(p))
    os.chown(p, 0, 0)
    p.write_text(json.dumps({"server": "https://x", "agent_uid": AGENT, "surprise": 1}))
    with pytest.raises(sudo.Refused):
        sudo.load_config(str(p))


def test_install_refuses_a_sw_sudo_the_agent_could_change(rootdir):
    agent = sudo.Agent(AGENT, frozenset())
    exe = agent_file(__import__("pathlib").Path(rootdir), "sw-sudo")
    assert sudo.check_installation(agent, exe)
    assert not [p for p in sudo.check_installation(agent, "/usr/bin/true") if "/usr/bin/true" in p]


def test_rule_scopes_match_the_suggested_rules():
    from securitywarden.approval import parse_action_rule, parse_where_text
    for r in sudo.SUGGESTED_RULES:
        rule = parse_action_rule(r)
        assert rule["match"] == "system.run"
        if "where_text" in rule:
            parse_where_text(rule["where_text"])
    scope = sudo.command_scope(["apt", "install", "-y", "ffmpeg"], "/usr/bin/apt")
    assert scope["cmd"] == "apt/install/-y/ffmpeg"
    pkey = crypto.new_key()
    sent = crypto.scope_macs(pkey, "cmd", scope["cmd"])
    assert crypto.scope_mac(pkey, "cmd", "apt/install/*") in sent           # [cmd=apt/install/*] matches
    assert crypto.scope_mac(pkey, "cmd", "apt/update") not in sent
