"""The connector toolkit: the checker, the project template, discovery by name, the guide and the
testing helpers that connector authors (often an AI) rely on."""

import importlib
import subprocess
import sys
from importlib.resources import files

import pytest

from securitywarden.mcp import Connector, Plan, Summary, tool
from securitywarden.mcp.cli import available_connectors, load_connector
from securitywarden.mcp.gmail import Gmail
from securitywarden.mcp.lint import check_connector
from securitywarden.mcp.scaffold import create_connector_project
from securitywarden.mcp.testing import FakeSecurityWarden, make_hub


def _errors(cls):
    return [m for level, m in check_connector(cls) if level == "error"]


def test_gmail_passes_its_own_checks():
    assert check_connector(Gmail) == []


def test_the_checker_finds_the_usual_mistakes():
    class Bad(Connector):
        name = "bad"
        secrets = ("lowercase_key",)
        suggested_rules = ("bad.send=allow", "bad.thing=sometimes", "other.*=each")

        @tool("Send it.", action="bad.send", risk="high",
              params={"amount": {"type": "number"}, "to": {"type": "array"}, "ghost": {"type": "string"}},
              required=["to", "missing"])
        def send(self, amount, to=None):
            return Plan({}, Summary("x"), lambda a: None)

        @tool("Read the stuff that is here.", action="bad.read.stuff", risk="high", params={})
        def read(self):
            return Plan({}, Summary("x"), lambda a: None)
    problems = check_connector(Bad)
    text = "\n".join(f"{level}: {m}" for level, m in problems)
    for expected in ("secret name 'lowercase_key'", "describe what it does", "use integer or string, not number",
                     "required 'missing' is not a parameter", "'ghost' is in params but not an argument",
                     "optional parameter 'amount' needs a default", "required parameter 'to' shouldn't have a default",
                     "suggested rule 'bad.thing=sometimes'", "warning: suggested rule 'other.*=each' matches none",
                     "covers high-risk actions", "usually risk low", "say what the list holds", "no description"):
        assert expected in text, expected

    class Unnamed(Connector):
        name = "Bad-Name"
    assert "name 'Bad-Name'" in _errors(Unnamed)[0]
    assert check_connector(int) == [("error", "not a subclass of securitywarden.mcp.Connector")]


def test_discovery_and_loading(monkeypatch):
    assert available_connectors()["gmail"] == "securitywarden.mcp.gmail:Gmail"
    assert load_connector("gmail") is Gmail
    assert load_connector("test_mcp:Notes").name == "notes"
    with pytest.raises(SystemExit):
        load_connector("nope")


def test_the_guide_ships_with_the_package():
    guide = (files("securitywarden.mcp") / "CONNECTORS.md").read_text(encoding="utf-8")
    for must in ("Plan(args, summary, run)", "untrusted(", "sw-mcp check", "securitywarden.connectors", "Checklist"):
        assert must in guide


def test_a_generated_project_is_correct_out_of_the_box(tmp_path, monkeypatch):
    root = create_connector_project("my_crm", str(tmp_path), title="My CRM")
    assert root.endswith("my-crm-connector")
    for rel in ("pyproject.toml", "AGENTS.md", "CLAUDE.md", "README.md", "src/sw_connector_my_crm/connector.py",
                "tests/test_connector.py"):
        assert (tmp_path / "my-crm-connector" / rel).is_file(), rel
    pyproject = (tmp_path / "my-crm-connector" / "pyproject.toml").read_text()
    assert 'my_crm = "sw_connector_my_crm.connector:MyCrm"' in pyproject and "__" not in pyproject
    monkeypatch.syspath_prepend(str(tmp_path / "my-crm-connector" / "src"))
    cls = importlib.import_module("sw_connector_my_crm.connector").MyCrm
    assert _errors(cls) == [] and cls.name == "my_crm" and cls.secrets == ("MY_CRM_API_KEY",)
    # its own tests pass as generated
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"],
                       cwd=root, capture_output=True, text=True,
                       env={**__import__("os").environ, "PYTHONPATH": str(tmp_path / "my-crm-connector" / "src")})
    assert r.returncode == 0, r.stdout + r.stderr
    with pytest.raises(FileExistsError):
        create_connector_project("my_crm", str(tmp_path))
    with pytest.raises(ValueError):
        create_connector_project("My-CRM", str(tmp_path))


def test_fake_securitywarden_decides_like_the_server():
    from test_mcp import Notes
    sw = FakeSecurityWarden({"notes.*": "ask", "notes.read.*": "allow"}, secrets={"NOTES_KEY": "k-123"})
    hub = make_hub(Notes, sw)
    assert "Buy milk" in hub.call("notes_read", {"id": "n1"}).text            # most specific rule wins
    r = hub.call("notes_delete", {"ids": ["n1"]})
    assert r.data["status"] == "waiting_for_approval" and sw.last()["args"] == {"ids": ["n1"]}
    sw.approve(r.data["request_id"])
    assert not hub.call("check_approval", {"request_id": r.data["request_id"]}).is_error
    sw.rules["notes.delete"] = "deny"
    assert "don't allow" in hub.call("notes_delete", {"ids": ["n2"]}).text
    sw.revoked = True
    assert "no longer accepts" in hub.call("notes_read", {"id": "n1"}).text
