"""sw-scan (securitywarden.scan) and `swctl admin secret import`. Negative tests first: no output ever carries a
secret, nothing is counted twice, code and placeholders aren't secrets, and an installed client is never claimed to
protect files it doesn't."""

import ast
import base64
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from securitywarden import scan
from securitywarden.client import cli

# fake keys, built at run time so the repository holds nothing that looks like a real key
ANT = "sk-ant-" + "api03-" + "Q" * 40 + "zz91"
OAI = "sk-" + "proj-" + "R7" * 20 + "aa42"
GHP = "ghp_" + "T" * 36 + "77"
TG = "123456789:AA" + "B" * 33
PASSWORD = "Pa55-" + "w0rdW0rd" + "q8"
ALL = [ANT, OAI, GHP, TG, PASSWORD]


def openssh_key(cipher: bytes) -> str:
    raw = b"openssh-key-v1\x00" + len(cipher).to_bytes(4, "big") + cipher + b"\x00" * 64
    body = base64.b64encode(raw).decode()
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n"


@pytest.fixture
def home(tmp_path: Path) -> Path:
    h = tmp_path / "home"
    (h / ".hermes").mkdir(parents=True)
    (h / ".hermes" / ".env").write_text(f"ANTHROPIC_API_KEY={ANT}\nOPENAI_API_KEY={OAI}\n")
    (h / ".hermes" / ".env.bak-2026-11-01").write_text(f"ANTHROPIC_API_KEY={ANT}\n")
    (h / "proj").mkdir()
    (h / "proj" / ".env").write_text(
        f'DB_PASSWORD="{PASSWORD}"\nAPI_URL=https://example.com/v1\nAPI_KEY=your_api_key_here\n'
        f"EMPTY_TOKEN=\nSECRET_FILE=/run/secrets/x\nTELEGRAM_BOT_TOKEN={TG}\nAGAIN={ANT}\n")
    (h / "proj" / "src").mkdir()
    (h / "proj" / "src" / "token.py").write_text(f'KEY = "{GHP}"\n')            # source code: never read
    (h / "proj" / "node_modules" / "x").mkdir(parents=True)
    (h / "proj" / "node_modules" / "x" / ".env").write_text(f"K={GHP}\n")       # installed software: skipped
    (h / ".git-credentials").write_text(f"https://someone:{GHP}@github.com\n")
    (h / ".claude").mkdir()
    (h / ".claude" / ".credentials.json").write_text('{"claudeAiOauth": {"accessToken": "opaque"}}')
    (h / ".ssh").mkdir()
    (h / ".ssh" / "id_ed25519").write_text(openssh_key(b"none"))
    (h / ".ssh" / "id_locked").write_text(openssh_key(b"aes256-ctr"))
    (h / ".ssh" / "id_rsa_old").write_text("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
                                           "DEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n")
    win = h / "AppData" / "Roaming" / "Claude"
    win.mkdir(parents=True)
    (win / "claude_desktop_config.json").write_text(json.dumps({"mcpServers": {"x": {"env": {"GITHUB_TOKEN": GHP}}}}))
    return h


def run(home: Path, env: bool = False) -> scan.Result:
    return scan.Scanner(str(home), with_env=env).run()


def by_kind(res: scan.Result) -> dict[str, list[scan.Finding]]:
    out: dict[str, list[scan.Finding]] = {}
    for f in res.findings:
        out.setdefault(f.kind, []).append(f)
    return out


# -- never shows a secret --------------------------------------------------------------------------------------

def test_no_output_carries_a_secret(home, monkeypatch):
    res = run(home)
    text, js = io.StringIO(), json.dumps(scan.to_json(res))
    scan.report(res, out=text, show=10_000)
    for value in ALL:
        assert value not in text.getvalue() and value not in js
        assert value[:-4][-8:] not in text.getvalue() + js       # not even a middle slice
    assert "1//" not in js and "Pa55" not in js


def test_main_json_and_text_never_print_values(home, capsys):
    for argv in (["--home", str(home), "--json"], ["--home", str(home), "--all"]):
        assert scan.main(argv) == 0
        out = capsys.readouterr().out
        for value in ALL:
            assert value not in out


def test_preview_is_prefix_and_last_four_only():
    assert scan.preview(ANT, "sk-ant-") == "sk-ant-…zz91"
    assert scan.preview("short-pw", "") == "(hidden)"
    assert scan.preview(GHP, "sk-") == "…TT77"                     # a prefix shows only when it is the key's own


# -- counts once, and says what's a copy ---------------------------------------------------------------------

def test_anthropic_key_is_not_also_an_openai_key(home):
    kinds = by_kind(run(home))
    oai = kinds.get("OpenAI-style API key", [])
    assert all(f.preview.endswith("aa42") for f in oai)           # only the real sk-proj- key
    assert not any(f.kind.startswith("secret setting ANTHROPIC") for f in run(home).findings)


def test_copies_and_backups_are_grouped(home):
    res = run(home)
    ant = [f for f in res.findings if f.kind == "Anthropic API key"]
    assert len(ant) == 3                                           # .env, its backup, and proj/.env AGAIN=
    first = [f for f in ant if f.copy_of is None]
    assert len(first) == 1 and first[0].category == "vault"
    copies = [f for f in ant if f.copy_of]
    assert all(f.category == "copies" for f in copies)
    assert any(f.backup for f in copies)
    assert res.distinct == len(res.findings) - sum(1 for f in res.findings if f.copy_of)


def test_same_value_twice_in_one_file_counts_once(tmp_path):
    h = tmp_path / "h"
    h.mkdir()
    (h / ".env").write_text(f"A_KEY={ANT}\n# old: A_KEY={ANT}\n")
    assert len([f for f in run(h).findings if f.kind == "Anthropic API key"]) == 1


# -- what is not a secret -----------------------------------------------------------------------------------

def test_code_installed_software_and_placeholders_are_ignored(home):
    res = run(home)
    wheres = {f.where for f in res.findings}
    assert not any("token.py" in w or "node_modules" in w for w in wheres)
    names = {f.kind for f in res.findings}
    for not_secret in ("API_URL", "API_KEY", "EMPTY_TOKEN", "SECRET_FILE"):
        assert f"secret setting {not_secret}" not in names
    assert "secret setting DB_PASSWORD" in names


def test_a_clean_home_scores_zero(tmp_path):
    (tmp_path / "h").mkdir()
    res = run(tmp_path / "h")
    assert res.findings == [] and res.score == 0 and res.verdict == "PRETTY TIGHT"
    out = io.StringIO()
    scan.report(res, out=out)
    assert "Nothing found" in out.getvalue()


def test_score_scale_is_not_saturated_by_one_key(tmp_path):
    h = tmp_path / "h"
    h.mkdir()
    (h / ".env").write_text(f"K={ANT}\n")
    res = run(h)
    assert 30 <= res.score < 70 and res.verdict == "EXPOSED"


# -- private keys ---------------------------------------------------------------------------------------------

def test_only_private_keys_without_a_passphrase_are_reported(home):
    keys = [f for f in run(home).findings if f.category == "sshkey"]
    assert [Path(f.where).name for f in keys] == ["id_ed25519"]


def test_private_key_encryption_detection():
    assert not scan.private_key_encrypted(openssh_key(b"none"))
    assert scan.private_key_encrypted(openssh_key(b"aes256-ctr"))
    assert scan.private_key_encrypted("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----")


# -- other tools' sign-ins and our own tokens -----------------------------------------------------------------

def test_sign_in_files_are_filed_as_sign_ins(home):
    res = run(home)
    signin = [f for f in res.findings if f.category == "signin"]
    assert any(f.where.endswith(".credentials.json") and f.preview == "(file)" for f in signin)
    git = [f for f in res.findings if f.where.endswith(".git-credentials")]
    assert git and all(f.category in ("signin", "copies") for f in git)


def test_windows_claude_config_is_read(home):
    res = run(home)
    assert any("claude_desktop_config.json" in f.where for f in res.findings)


def test_our_tokens_are_reported_honestly(tmp_path):
    h = tmp_path / "h"
    (h / ".config" / "securitywarden").mkdir(parents=True)
    tok = "sw1.m." + "AbCdEf123456" + "." + "s" * 22 + ":" + "k" * 43
    (h / ".config" / "securitywarden" / "SW_Tokens.json").write_text(json.dumps({"x": {"credential": tok}}))
    res = run(h)
    assert [f.category for f in res.findings] == ["sw"]
    out = io.StringIO()
    scan.report(res, out=out)
    assert tok not in out.getvalue()


def test_installed_client_is_never_claimed_to_protect_the_files(home, monkeypatch):
    monkeypatch.setattr(scan.shutil, "which", lambda b: "/usr/bin/" + b)
    monkeypatch.setenv("SW_SERVER_URL", "https://example.com")
    res = run(home)
    assert res.client_installed
    out = io.StringIO()
    scan.report(res, out=out)
    text = out.getvalue()
    assert "still readable" in text
    for overclaim in ("effective risk", "LOW", "sealed", "protected by"):
        assert overclaim not in text
    assert res.verdict != "PRETTY TIGHT"


# -- environment -----------------------------------------------------------------------------------------------

def test_environment_variables(home, monkeypatch):
    monkeypatch.setenv("MY_SERVICE_TOKEN", "t0k-" + "x9" * 10)
    monkeypatch.setenv("SOME_PATH_FILE", "/etc/x")
    res = run(home, env=True)
    env = [f for f in res.findings if f.where.startswith("environment variable")]
    assert any(f.where.endswith("MY_SERVICE_TOKEN") for f in env)
    assert not any(f.where.endswith("SOME_PATH_FILE") for f in env)


def test_another_users_home_skips_this_terminals_environment(home, monkeypatch, capsys):
    monkeypatch.setenv("MY_SERVICE_TOKEN", "t0k-" + "x9" * 10)
    scan.main(["--home", str(home), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert not any(f["where"].startswith("environment") for f in data["findings"])


def test_fail_at(home, tmp_path):
    assert scan.main(["--home", str(home), "--json", "--fail-at", "30"]) == 1
    (tmp_path / "empty").mkdir()
    assert scan.main(["--home", str(tmp_path / "empty"), "--json", "--fail-at", "30"]) == 0
    assert scan.main(["--home", str(tmp_path / "missing")]) == 2


# -- trust by construction -------------------------------------------------------------------------------------

def test_scan_has_no_network_code():
    tree = ast.parse(Path(scan.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert not imported & {"socket", "ssl", "http", "urllib", "httpx", "requests", "asyncio", "ftplib", "smtplib",
                           "subprocess", "xmlrpc", "webbrowser", "multiprocessing"}
    assert imported <= {"__future__", "argparse", "base64", "hashlib", "json", "math", "os", "re", "shutil", "sys",
                        "textwrap", "time", "dataclasses", "pathlib", "pwd"}


def test_scan_is_read_only(home):
    before = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in home.rglob("*") if p.is_file()}
    run(home)
    after = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in home.rglob("*") if p.is_file()}
    assert before == after


def test_runs_as_a_single_file(home, tmp_path):
    copy = tmp_path / "sw_scan.py"
    copy.write_text(Path(scan.__file__).read_text(encoding="utf-8"), encoding="utf-8")
    r = subprocess.run([sys.executable, "-I", str(copy), "--home", str(home), "--json"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["version"] == "standalone" and data["secrets"] > 0
    for value in ALL:
        assert value not in r.stdout


# -- swctl admin secret import -----------------------------------------------------------------------------------

def test_read_dotenv():
    pairs, problems = cli.read_dotenv(
        "# comment\nexport A=1\nB=\"x y\" # note\nC='z#1'\nD=plain # note\nE=\"unclosed\nbad line\nF=\nA=2\n")
    assert pairs == {"A": "2", "B": "x y", "C": "z#1", "D": "plain", "F": ""}
    assert len(problems) == 2 and all("unclosed" in p or "NAME=value" in p for p in problems)
    assert not any("unclosed" in p and "x" in p.split(":")[-1] for p in problems)


class FakeAdmin:
    def __init__(self, existing=None):
        self.secrets = dict(existing or {})

    def get_secrets(self, project):
        return dict(self.secrets)

    def set_secret(self, project, name, value):
        self.secrets[name] = value


def test_import_moves_values_without_printing_them(tmp_path, monkeypatch, capsys):
    f = tmp_path / ".env"
    f.write_text(f"ANTHROPIC_API_KEY={ANT}\nOPENAI_API_KEY={OAI}\nEMPTY=\nKEEP={PASSWORD}\n")
    admin = FakeAdmin({"KEEP": "old"})
    monkeypatch.setattr(cli, "_admin_client", lambda args: admin)
    assert cli.main(["admin", "secret", "import", "bot", str(f)]) == 0
    out = capsys.readouterr()
    assert admin.secrets == {"ANTHROPIC_API_KEY": ANT, "OPENAI_API_KEY": OAI, "KEEP": "old"}
    for value in ALL:
        assert value not in out.out + out.err
    assert "KEEP" in out.out and "EMPTY" in out.out and "delete" in out.out


def test_import_overwrite_only_and_dry_run(tmp_path, monkeypatch, capsys):
    f = tmp_path / ".env"
    f.write_text(f"A_KEY={ANT}\nB_KEY={OAI}\n")
    admin = FakeAdmin({"A_KEY": "old"})
    monkeypatch.setattr(cli, "_admin_client", lambda args: admin)
    cli.main(["admin", "secret", "import", "bot", str(f), "--dry-run"])
    assert admin.secrets == {"A_KEY": "old"}
    cli.main(["admin", "secret", "import", "bot", str(f), "--only", "A_KEY", "--overwrite"])
    assert admin.secrets == {"A_KEY": ANT}
    with pytest.raises(SystemExit):
        cli.main(["admin", "secret", "import", "bot", str(f), "--only", "NOPE"])
    capsys.readouterr()


def test_import_reads_stdin(monkeypatch, capsys):
    admin = FakeAdmin()
    monkeypatch.setattr(cli, "_admin_client", lambda args: admin)
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"A_KEY={ANT}\n"))
    assert cli.main(["admin", "secret", "import", "bot", "-"]) == 0
    assert admin.secrets == {"A_KEY": ANT}
    assert ANT not in capsys.readouterr().out


def test_a_legacy_code_page_does_not_crash(home, tmp_path):
    r = subprocess.run([sys.executable, "-I", "-m", "securitywarden.scan", "--home", str(home)],
                       capture_output=True, timeout=60, env={**os.environ, "PYTHONIOENCODING": "cp1252"})
    assert r.returncode == 0, r.stderr


def test_report_columns_line_up_even_with_a_long_name(tmp_path):
    """A long setting name (aws_secret_access_key) widens its group's column instead of pushing its row out of line."""
    h = tmp_path / "home"
    (h / ".aws").mkdir(parents=True)
    (h / ".aws" / "credentials").write_text("[default]\naws_access_key_id = AKIA" + "ABCDEFGHIJ234567"
                                            + "\naws_secret_access_key = " + "Zq8" * 13 + "x\n")
    out = io.StringIO()
    scan.report(run(h), out=out)
    rows = [ln for ln in out.getvalue().splitlines() if ln.startswith("   •") and "credentials:" in ln]
    assert len(rows) == 2
    assert len({ln.index("~/.aws/credentials") for ln in rows}) == 1        # same column


# -- what to do, in order (0.7.17) -------------------------------------------------------------------------------

def test_plan_deletes_only_backup_files_and_scores_only_go_down(home):
    res = run(home)
    steps = scan.plan(res)
    first = steps[0]
    assert first["step"].startswith("Delete 1 backup file")
    assert first["files"] == [str(home / ".hermes" / ".env.bak-2026-11-01")]      # never a live .env
    scores = [res.score] + [s["score_after"] for s in steps if s["score_after"] is not None]
    assert scores == sorted(scores, reverse=True)
    assert steps[-1]["step"].startswith("Run the agent as its own user") and steps[-1]["score_after"] == 0


def test_notes_say_what_differs_from_the_group(tmp_path):
    h = tmp_path / "home"
    (h / ".hermes" / "profiles" / "spyder").mkdir(parents=True)
    (h / ".hermes" / ".env").write_text(f"HERMES_DASHBOARD_BASIC_AUTH_PASSWORD={PASSWORD}\nANTHROPIC_API_KEY={ANT}\n")
    (h / ".hermes" / ".env.bak-1").write_text(f"ANTHROPIC_API_KEY={ANT}\n")
    (h / ".hermes" / "profiles" / "spyder" / "auth.json").write_text(json.dumps({"access_token": GHP}))
    res = run(h)
    note = {f.kind: f.note for f in res.findings if f.copy_of is None}
    assert note["secret setting HERMES_DASHBOARD_BASIC_AUTH_PASSWORD"] == scan.NOTE_KEEP
    assert note["Anthropic API key"] == scan.NOTE_ROTATE_FIRST
    [auth] = [f for f in res.findings if "auth.json" in f.where]
    assert auth.category == "signin" and auth.note == scan.NOTE_HERMES_SIGNIN       # a profile's sign-in too
    steps = scan.plan(res)
    move = next(s for s in steps if s["step"].startswith("Move"))
    assert "Move 1 key" in move["step"]                                              # not the dashboard password
    assert any(s["step"].startswith("Rotate 1 setting") and s["score_after"] is None for s in steps)
    out = io.StringIO()
    scan.report(res, out=out)
    assert scan.NOTE_KEEP in out.getvalue() and PASSWORD not in out.getvalue()


def test_aisecuritywarden_tokens_are_named_never_shown(tmp_path):
    h = tmp_path / "home"
    (h / ".config" / "securitywarden").mkdir(parents=True)
    tok = "sw1.m.abcdefgh." + "k" * 22 + ":" + "s" * 43
    (h / ".config" / "securitywarden" / "SW_Tokens.json").write_text(json.dumps({"format": "sw-tokens-2", "tokens": {
        "abcdefgh": {"name": "gmail-bot", "token": tok}, "x": {"name": "old", "replaced_by": "abcdefgh"}}}))
    res = run(h)
    assert res.sw_token_names == ["gmail-bot"]                   # live tokens only
    out = io.StringIO()
    scan.report(res, out=out)
    text = out.getvalue()
    flat = " ".join(text.split())
    assert "Stored here: 1 token(s): gmail-bot" in text and "can use them itself" in flat
    assert tok not in text and "s" * 20 not in text
    assert any("session approval" in s["step"] for s in scan.plan(res))
    assert scan.to_json(res)["aisecuritywarden_tokens"] == ["gmail-bot"]


def test_agents_running_as_the_home_owner(tmp_path):
    proc = tmp_path / "proc"
    uid = os.stat(tmp_path).st_uid

    def fake(pid, owner, argv):
        d = proc / str(pid)
        d.mkdir(parents=True)
        (d / "status").write_text(f"Name:\tx\nUid:\t{owner}\t{owner}\t{owner}\t{owner}\n")
        (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
    fake(10, uid, ["/home/u/.hermes/hermes-agent/venv/bin/python", "/home/u/.local/bin/hermes", "gateway",
                   "--token", "sk-ant-SECRET-IN-ARGS"])
    fake(11, uid + 1, ["/usr/bin/claude"])                       # someone else's: not this home's owner
    fake(12, uid, ["/usr/bin/vim", "notes.txt"])
    (proc / "self").mkdir()
    found = scan.agents_running_as(tmp_path, proc=str(proc))
    assert len(found) == 1 and found[0].startswith("Hermes Agent runs as ")
    assert "SECRET" not in " ".join(found)
    assert scan.agents_running_as(tmp_path, proc=str(tmp_path / "missing")) == []


def test_note_for_agents_when_not_a_terminal(home, capsys):
    assert scan.main(["--home", str(home)]) == 0                 # captured output isn't a terminal: an agent's tool
    out = " ".join(capsys.readouterr().out.split())
    assert "For an AI agent reading this" in out and "Never bring the aiSecurityWarden admin" in out
    term = io.StringIO()
    scan.report(run(home), out=term, for_agent=False)
    assert "For an AI agent" not in term.getvalue()
    js = scan.to_json(run(home))
    assert js["for_agents"] == scan.FOR_AGENTS and js["plan"] and "swctl admin" in js["for_agents"]


def test_live_file_is_the_real_one_even_when_a_backup_is_seen_first(tmp_path):
    h = tmp_path / "home"
    (h / ".hermes" / "profiles" / "spyder").mkdir(parents=True)
    (h / ".hermes" / ".env.bak-20261003").write_text(f"TELEGRAM_BOT_TOKEN={TG}\n")
    (h / ".hermes" / "profiles" / "spyder" / ".env").write_text(f"TELEGRAM_BOT_TOKEN={TG}\n")
    res = run(h)
    [live] = [f for f in res.findings if f.where.endswith(".env") and "spyder" in f.where]
    [bak] = [f for f in res.findings if f.backup]
    assert live.category == "vault" and live.copy_of is None and live.note == scan.NOTE_ROTATE_FIRST
    assert bak.category == "copies" and bak.copy_of == f"{live.where}:1"
    move = next(s for s in scan.plan(res) if s["step"].startswith("Move"))
    assert "Move 1 key" in move["step"] and move["files"] == [live.where]


def test_two_findings_on_one_line_are_not_copies_of_each_other(tmp_path):
    h = tmp_path / "home"
    h.mkdir()
    (h / ".git-credentials").write_text(f"https://someone:{GHP}@github.com\n")   # a token and a URL password
    res = run(h)
    assert len(res.findings) >= 1 and not any(f.note == scan.NOTE_ROTATE_FIRST for f in res.findings)
