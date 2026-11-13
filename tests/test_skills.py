"""The skills shipped for agents, the sw-mcp skill command, and the MCP server's built-in instructions."""

import io
import re
import zipfile

import pytest

from securitywarden import __version__
from securitywarden.mcp import skills
from securitywarden.mcp.server import INSTRUCTIONS


@pytest.mark.parametrize("agent", skills.AGENTS)
def test_each_skill_has_a_valid_header_and_the_rules(agent):
    t = skills.text(agent)
    fm = skills.frontmatter(t)
    assert fm["name"] == "aisecuritywarden"
    assert re.fullmatch(r"[a-z0-9-]{1,64}", fm["name"])                 # Claude's rule for skill names
    for rule in ("check_approval", "untrusted", "securitywarden_setup", "securitywarden_update",
                 "Don't run pip or pipx", "sw-mcp doctor", "SW_Tokens.json"):
        assert rule in t, rule
    assert __version__ in t and skills.MARKER in t


def test_hermes_description_fits_its_index():
    d = skills.frontmatter(skills.text("hermes"))["description"]
    assert len(d) <= skills.HERMES_DESCRIPTION_LIMIT and d.endswith(".") and d.count(".") == 1
    assert d.lower().startswith("update")                                   # the trigger first


def test_claude_description_fits():
    d = skills.frontmatter(skills.text("claude"))["description"]
    assert 0 < len(d) <= skills.CLAUDE_DESCRIPTION_LIMIT and "<" not in d and ">" not in d
    assert "update" in d and "waiting_for_approval" in d


def test_install_update_and_leave_other_skills_alone(tmp_path):
    folder = tmp_path / "skills" / "aisecuritywarden"
    path, status = skills.install("hermes", str(folder))
    assert status == "installed" and open(path).read() == skills.text("hermes")
    assert skills.install("hermes", str(folder))[1] == "unchanged"
    older = open(path).read().replace("Expired", "Old text")                  # an older version of ours
    open(path, "w").write(older)
    assert skills.install("hermes", str(folder))[1] == "updated"
    open(path, "w").write("---\nname: aisecuritywarden\n---\nmy own notes\n")    # someone else's file
    with pytest.raises(skills.SkillError, match="--force"):
        skills.install("hermes", str(folder))
    assert open(path).read().endswith("my own notes\n")
    assert skills.install("hermes", str(folder), force=True)[1] == "updated"


def test_default_folders_follow_the_agents_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "h"))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "c"))
    assert skills.default_dir("hermes") == str(tmp_path / "h" / "skills" / "aisecuritywarden")
    assert skills.default_dir("claude") == str(tmp_path / "c" / "skills" / "aisecuritywarden")
    with pytest.raises(skills.SkillError):
        skills.text("other")


def test_zip_for_the_claude_app():
    z = zipfile.ZipFile(io.BytesIO(skills.zip_bytes("claude")))
    assert z.namelist() == ["aisecuritywarden/SKILL.md"]
    assert z.read("aisecuritywarden/SKILL.md").decode() == skills.text("claude")


def test_sw_mcp_skill_command(tmp_path, monkeypatch, capsys):
    from securitywarden.mcp import cli
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    cli.main(["skill", "install", "hermes"])
    assert "Installed" in capsys.readouterr().out and (tmp_path / "skills" / "aisecuritywarden" / "SKILL.md").exists()
    cli.main(["skill", "show", "claude"])
    assert "name: aisecuritywarden" in capsys.readouterr().out
    out = tmp_path / "s.zip"
    cli.main(["skill", "zip", "claude", "-o", str(out)])
    assert zipfile.is_zipfile(out)


def test_every_agent_gets_the_core_rules_without_a_skill():
    for rule in ("check_approval", "untrusted", "securitywarden_update", "never pip or pipx",
                 "never kill or restart sw-mcp", "securitywarden_setup", "token files"):
        assert rule in INSTRUCTIONS, rule


def test_serve_refreshes_only_skills_it_installed(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "h"))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "c"))
    hermes, _ = skills.install("hermes")
    stale = open(hermes).read().replace("Expired", "Old text")             # what an older client installed
    open(hermes, "w").write(stale)
    mine = tmp_path / "c" / "skills" / "aisecuritywarden" / "SKILL.md"
    mine.parent.mkdir(parents=True)
    mine.write_text("---\\nname: aisecuritywarden\\n---\\nmy own notes\\n")
    assert skills.refresh_installed() == [hermes]
    assert open(hermes).read() == skills.text("hermes") and mine.read_text().endswith("my own notes\\n")
    assert skills.refresh_installed() == []
