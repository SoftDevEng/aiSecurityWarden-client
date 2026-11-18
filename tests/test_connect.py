"""sw-mcp connect: add the MCP entry to an agent app's settings, safely (backup, no duplicates, no guessing)."""

import json
import os

import pytest

from securitywarden import crypto
from securitywarden.client.tokens import TokenStore
from securitywarden.mcp import cli
from securitywarden.mcp import connect as cn

SERVER = "https://app.example.com"


@pytest.fixture
def token(tmp_path, monkeypatch):
    monkeypatch.setenv("SW_TOKENS_FILE", str(tmp_path / "SW_Tokens.json"))
    for k in ("SW_SERVER_URL", "SW_TOKEN_ID", "SW_TOKEN_NAME", "SW_MCP_CONFIG"):
        monkeypatch.delenv(k, raising=False)
    cred = crypto.new_credential(crypto.KIND_MACHINE)
    TokenStore().put(cred, name="Jarvis Gmail", server=SERVER)
    return cred


def _run(*argv):
    cli.main(["connect", *argv, "--command", "/opt/sw/bin/sw-mcp"])


def test_claude_desktop_entry_is_added_once_with_a_backup(token, tmp_path, capsys):
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}, "theme": "dark"}))
    _run("claude-desktop", "--file", str(cfg))
    data = json.loads(cfg.read_text())
    e = data["mcpServers"]["aisecuritywarden-jarvis-gmail"]
    assert e == {"command": "/opt/sw/bin/sw-mcp", "args": ["serve"],
                 "env": {"SW_SERVER_URL": SERVER, "SW_TOKEN_ID": token.id, "SW_TOKEN_NAME": "Jarvis Gmail"}}
    assert data["mcpServers"]["other"] == {"command": "x"} and data["theme"] == "dark"      # nothing else touched
    assert any(p.name.startswith("claude_desktop_config.json.bak-") for p in tmp_path.iterdir())
    text = cfg.read_text()
    assert str(token) not in text and token.secret not in text            # the token itself never goes in
    out = capsys.readouterr().out
    assert "Quit Claude Desktop" in out and "sw-mcp doctor" in out
    _run("claude-desktop", "--file", str(cfg))                       # again: nothing changes
    assert "nothing to change" in capsys.readouterr().out


def test_a_different_entry_needs_replace_and_bad_json_is_left_alone(token, tmp_path, capsys):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"mcpServers": {"aisecuritywarden-jarvis-gmail": {"command": "old"}}}))
    with pytest.raises(SystemExit):
        _run("claude-desktop", "--file", str(cfg))
    assert json.loads(cfg.read_text())["mcpServers"]["aisecuritywarden-jarvis-gmail"] == {"command": "old"}
    _run("claude-desktop", "--file", str(cfg), "--replace")
    assert json.loads(cfg.read_text())["mcpServers"]["aisecuritywarden-jarvis-gmail"]["args"] == ["serve"]
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json")
    with pytest.raises(SystemExit):
        _run("claude-desktop", "--file", str(bad))
    assert bad.read_text() == "{ not json"


HERMES = """model: gpt-x
mcp_servers:
  github:
    command: sw-mcp
    args:
      - serve
    enabled: false

  other-thing:
    command: foo
toolsets:
  - web
"""


def test_hermes_yaml_gets_the_entry_inside_mcp_servers_and_nothing_else_changes(token, tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(HERMES)
    _run("hermes", "--file", str(cfg))
    text = cfg.read_text()
    assert text.startswith("model: gpt-x\nmcp_servers:\n  github:")
    assert "    command: foo\n  aisecuritywarden-jarvis-gmail:\n" in text
    assert text.endswith("toolsets:\n  - web\n")
    assert f'      SW_TOKEN_ID: "{token.id}"' in text and '    args: ["serve"]' in text
    _run("hermes", "--file", str(cfg))
    assert cfg.read_text() == text                                     # idempotent
    yaml = pytest.importorskip("yaml")
    d = yaml.safe_load(text)
    assert d["mcp_servers"]["aisecuritywarden-jarvis-gmail"]["env"]["SW_SERVER_URL"] == SERVER
    assert d["mcp_servers"]["github"]["enabled"] is False and d["toolsets"] == ["web"]


def test_hermes_without_a_section_and_shapes_it_wont_guess(token, tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("model: x\n")
    _run("hermes", "--file", str(cfg))
    assert cfg.read_text().startswith("model: x\n\nmcp_servers:\n  aisecuritywarden-jarvis-gmail:\n")
    for weird in ("mcp_servers: {}\n", "mcp_servers:\n    four:\n      command: x\n"):
        f = tmp_path / "w.yaml"
        f.write_text(weird)
        with pytest.raises(SystemExit):
            _run("hermes", "--file", str(f))
        assert f.read_text() == weird
    missing = tmp_path / "new" / "config.yaml"
    _run("hermes", "--file", str(missing))
    assert missing.read_text().startswith("mcp_servers:\n  aisecuritywarden-jarvis-gmail:")


def test_claude_code_uses_its_own_command(token, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(cn.shutil, "which", lambda n: "/usr/bin/claude" if n == "claude" else None)

    class R:
        returncode, stdout, stderr = 0, "Added", ""
    monkeypatch.setattr(cn.subprocess, "run", lambda args, **kw: calls.append(args) or R())
    _run("claude-code")
    assert calls[0][:6] == ["/usr/bin/claude", "mcp", "add", "--scope", "user", "aisecuritywarden-jarvis-gmail"]
    assert f"SW_TOKEN_ID={token.id}" in calls[0] and calls[0][-3:] == ["--", "/opt/sw/bin/sw-mcp", "serve"]
    monkeypatch.setattr(cn.shutil, "which", lambda n: None)
    _run("claude-code")
    assert "isn't on the PATH" in capsys.readouterr().out


def test_no_token_or_several_says_what_to_do(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SW_TOKENS_FILE", str(tmp_path / "SW_Tokens.json"))
    for k in ("SW_SERVER_URL", "SW_TOKEN_ID", "SW_TOKEN_NAME", "SW_MCP_CONFIG"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(SystemExit):
        _run("other")
    assert "sw-mcp setup" in capsys.readouterr().err
    s = TokenStore()
    s.put(crypto.new_credential(crypto.KIND_MACHINE), name="a", server=SERVER)
    s.put(crypto.new_credential(crypto.KIND_MACHINE), name="b", server=SERVER)
    with pytest.raises(SystemExit):
        _run("other")
    _run("other", "--token-name", "b")
    assert '"SW_TOKEN_NAME": "b"' in capsys.readouterr().out


def test_dry_run_changes_nothing(token, tmp_path):
    cfg = tmp_path / "c.json"
    _run("claude-desktop", "--file", str(cfg), "--dry-run")
    assert not os.path.exists(cfg)


def test_entry_names_match_the_website():
    assert cn.entry_name("Jarvis Gmail") == "aisecuritywarden-jarvis-gmail"
    assert cn.entry_name("Ünïcode bot!!") == "aisecuritywarden-u-ni-code-bot"   # same as the website (NFKD)
    assert cn.entry_name("***") == "aisecuritywarden"
