"""The Hermes Agent secret source (securitywarden/hermes_plugin) and `swctl hermes-plugin`."""

from __future__ import annotations

import json
import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest

import hermes_stub

hermes_stub.install()

from agent.secret_sources.base import ErrorKind, FetchResult, SECRET_SOURCE_API_VERSION  # noqa: E402

from securitywarden.client import cli, hermes  # noqa: E402
from securitywarden.client.api import ApprovalError, TokenRejected  # noqa: E402
from securitywarden.hermes_plugin import AiSecurityWardenSource, register  # noqa: E402

posix_only = pytest.mark.skipif(os.name == "nt", reason="the fake swctl is a script with a #! line")


@pytest.fixture
def source():
    return AiSecurityWardenSource()


def fake_swctl(tmp_path: Path, body: str) -> str:
    """A stand-in swctl: `body` runs with `argv` (its arguments) and `os` available."""
    path = tmp_path / "swctl"
    path.write_text(f"#!{sys.executable}\nimport json, os, sys, time\nargv = sys.argv[1:]\n"
                    + textwrap.dedent(body), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


# -- the Hermes contract (the same checks as Hermes's conformance kit) ------------------------------------------

def test_identity(source):
    assert source.name == "aisecuritywarden" and source.name.replace("_", "").isalnum()
    assert source.label == "aiSecurityWarden"
    assert source.shape == "bulk"
    assert source.api_version == SECRET_SOURCE_API_VERSION


def test_disabled_by_default(source):
    assert source.is_enabled({}) is False
    assert source.is_enabled({"enabled": False}) is False
    assert source.is_enabled({"enabled": True}) is True


def test_never_raises_on_malformed_config(source, tmp_path):
    for cfg in ({}, {"enabled": True}, {"enabled": True, "env": "not-a-dict"}, {"enabled": True, "swctl": 5},
                {"enabled": True, "timeout_seconds": "bogus"}, {"enabled": True, "server_url": ["x"]}, None):
        result = source.fetch(cfg, tmp_path)
        assert isinstance(result, FetchResult)
        if not result.ok:
            assert result.error_kind is not None and not result.secrets


def test_timeout_positive_and_room_for_an_approval(source):
    assert source.fetch_timeout_seconds({}) == 180
    assert source.fetch_timeout_seconds({"timeout_seconds": "junk"}) == 180
    assert source.fetch_timeout_seconds({"timeout_seconds": -1}) == 180
    assert source.fetch_timeout_seconds({"timeout_seconds": 300}) == 300


def test_protects_its_own_settings(source):
    from agent.secret_sources.base import is_valid_env_name
    protected = source.protected_env_vars({"enabled": True})
    assert {"SW_SERVER_URL", "SW_ACCESS_TOKEN", "SW_TOKEN_NAME", "SW_ALLOW_HTTP", "SW_CA_BUNDLE"} <= protected
    assert all(is_valid_env_name(v) for v in protected)


def test_every_error_kind_has_a_hint(source):
    for kind in (ErrorKind.NOT_CONFIGURED, ErrorKind.BINARY_MISSING, ErrorKind.AUTH_FAILED, ErrorKind.AUTH_EXPIRED,
                 ErrorKind.NETWORK, ErrorKind.TIMEOUT, ErrorKind.INTERNAL):
        assert source.remediation(kind, {})


def test_register():
    got = []

    class Ctx:
        def register_secret_source(self, s):
            got.append(s)

    register(Ctx())
    assert len(got) == 1 and isinstance(got[0], AiSecurityWardenSource)


def test_plugin_needs_nothing_from_this_package():
    """The file is copied into ~/.hermes/plugins on its own, so it may import only Hermes and the stdlib."""
    import securitywarden.hermes_plugin as plugin
    text = Path(plugin.__file__).read_text(encoding="utf-8")
    assert "securitywarden" not in "".join(ln for ln in text.splitlines() if ln.startswith(("import", "from")))


# -- fetching ------------------------------------------------------------------------------------------------------

def test_missing_swctl(source, tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python"))
    r = source.fetch({"enabled": True}, tmp_path)
    assert r.error_kind is ErrorKind.BINARY_MISSING and not r.secrets
    r = source.fetch({"enabled": True, "swctl": str(tmp_path / "nope")}, tmp_path)
    assert r.error_kind is ErrorKind.BINARY_MISSING and "nope" in r.error


@posix_only
def test_argv_from_config(source, tmp_path):
    swctl = fake_swctl(tmp_path, 'print(json.dumps({"ARGS": " ".join(argv)}))')
    r = source.fetch({"enabled": True, "swctl": swctl, "server_url": "https://sw.example", "token_name": "jarvis",
                      "token_file": "~/tok"}, tmp_path)
    assert r.ok, r.error
    args = r.secrets["ARGS"]
    assert args.startswith("--server https://sw.example --token-name jarvis --token-file ")
    assert "~" not in args and args.endswith("export --format json")
    assert r.binary_path == Path(swctl)


@posix_only
def test_secrets_and_what_is_skipped(source, tmp_path):
    swctl = fake_swctl(tmp_path, '''
        print(json.dumps({"OPENAI_API_KEY": "sk-1", "MULTI": "a\\nb", "bad-name": "x", "EMPTY": ""}))
        print("swctl: waiting for a person to approve this fetch (match code 123-456, up to 120 s)...",
              file=sys.stderr)
    ''')
    r = source.fetch({"enabled": True, "swctl": swctl}, tmp_path)
    assert r.ok
    assert r.secrets == {"OPENAI_API_KEY": "sk-1", "MULTI": "a\nb"}
    assert any("EMPTY" in w for w in r.warnings)
    assert not any("bad-name" in w for w in r.warnings)       # names that aren't variables aren't repeated


@posix_only
def test_only_sw_settings_reach_swctl(source, tmp_path, monkeypatch):
    monkeypatch.setenv("SW_TOKEN_NAME", "jarvis")
    monkeypatch.setenv("SW_SERVER_URL", "https://sw.example")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    swctl = fake_swctl(tmp_path, 'print(json.dumps({"SEEN": ",".join(sorted(os.environ))}))')
    r = source.fetch({"enabled": True, "swctl": swctl}, tmp_path)
    seen = r.secrets["SEEN"].split(",")
    assert "SW_TOKEN_NAME" in seen and "SW_SERVER_URL" in seen
    assert "ANTHROPIC_API_KEY" not in seen and "GITHUB_TOKEN" not in seen


@posix_only
@pytest.mark.parametrize("code,message,kind", [
    (3, "can't reach the server: ConnectError: [Errno 111] Connection refused", ErrorKind.NETWORK),
    (4, "authentication failed (401): unauthorized (the token was revoked, expired or is wrong)",
     ErrorKind.AUTH_EXPIRED),
    (5, "the approval request was denied", ErrorKind.AUTH_FAILED),
    (5, "the approval request expired before anyone approved it", ErrorKind.AUTH_FAILED),
    (6, "no server URL (use --server or SW_SERVER_URL)", ErrorKind.NOT_CONFIGURED),
    # swctl before 0.7.13 exits 1 for everything: the text decides
    (1, "no machine token: none for this program in /x (swctl setup)", ErrorKind.NOT_CONFIGURED),
    (1, "the approval request expired before anyone approved it", ErrorKind.AUTH_FAILED),
    (1, "authentication failed (401): unauthorized", ErrorKind.AUTH_EXPIRED),
    (1, "httpx.ConnectError: [Errno -3] Temporary failure in name resolution", ErrorKind.NETWORK),
    (1, "something new", ErrorKind.INTERNAL),
])
def test_failures(source, tmp_path, code, message, kind):
    swctl = fake_swctl(tmp_path, f'print("Traceback...", file=sys.stderr)\n'
                                 f'print("swctl: " + {message!r}, file=sys.stderr)\nsys.exit({code})')
    r = source.fetch({"enabled": True, "swctl": swctl}, tmp_path)
    assert r.error_kind is kind and not r.secrets
    assert r.error == message


@posix_only
def test_not_json(source, tmp_path):
    swctl = fake_swctl(tmp_path, 'print("OPENAI_API_KEY=sk-1")')
    r = source.fetch({"enabled": True, "swctl": swctl}, tmp_path)
    assert r.error_kind is ErrorKind.INTERNAL and "sk-1" not in r.error and not r.secrets
    swctl = fake_swctl(tmp_path, 'print("[1, 2]")')
    assert source.fetch({"enabled": True, "swctl": swctl}, tmp_path).error_kind is ErrorKind.INTERNAL


@posix_only
def test_times_out_before_hermes_does(source, tmp_path):
    swctl = fake_swctl(tmp_path, 'time.sleep(10)')
    r = source.fetch({"enabled": True, "swctl": swctl, "timeout_seconds": 1}, tmp_path)
    assert r.error_kind is ErrorKind.TIMEOUT and "approval" in r.error


# -- swctl's exit codes ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("exc,code", [
    (TokenRejected("authentication failed (401): x"), cli.EXIT_TOKEN),
    (ApprovalError("approval_denied"), cli.EXIT_APPROVAL),
    (__import__("httpx").ConnectError("refused"), cli.EXIT_NETWORK),
])
def test_swctl_exit_codes(monkeypatch, capsys, exc, code):
    class Client:
        def fetch(self):
            raise exc

    monkeypatch.setattr(cli, "_machine_client", lambda args: Client())
    with pytest.raises(SystemExit) as e:
        cli.main(["--server", "https://sw.example", "export", "--format", "json"])
    assert e.value.code == code
    assert capsys.readouterr().out == ""


def test_swctl_exit_code_unconfigured(monkeypatch, tmp_path):
    for k in ("SW_SERVER_URL", "SW_ACCESS_TOKEN", "SW_ACCESS_TOKEN_FILE", "SW_TOKEN_NAME", "SW_TOKEN_ID"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SW_TOKENS_FILE", str(tmp_path / "SW_Tokens.json"))
    with pytest.raises(SystemExit) as e:
        cli.main(["export"])
    assert e.value.code == cli.EXIT_CONFIG
    with pytest.raises(SystemExit) as e:
        cli.main(["--server", "https://sw.example", "export"])
    assert e.value.code == cli.EXIT_CONFIG


# -- swctl hermes-plugin -----------------------------------------------------------------------------------------------

def test_install_copies_the_plugin(tmp_path):
    folder, changed = hermes.install(str(tmp_path), dry_run=True)
    assert changed and not os.path.exists(folder)
    folder, changed = hermes.install(str(tmp_path))
    assert changed and folder == str(tmp_path / "plugins" / "aisecuritywarden")
    assert sorted(os.listdir(folder)) == ["__init__.py", "plugin.yaml"]
    assert "name: aisecuritywarden" in (Path(folder) / "plugin.yaml").read_text(encoding="utf-8")
    assert hermes.install(str(tmp_path)) == (folder, False)
    (Path(folder) / "__init__.py").write_text("old", encoding="utf-8")
    assert hermes.install(str(tmp_path)) == (folder, True)
    assert "AiSecurityWardenSource" in (Path(folder) / "__init__.py").read_text(encoding="utf-8")


def test_install_works_without_hermes(tmp_path):
    """swctl runs where Hermes isn't importable: it must copy the plugin without importing it."""
    import subprocess
    r = subprocess.run([sys.executable, "-c", "import sys; sys.modules['agent'] = None\n"
                        "from securitywarden.client import cli; cli.main(['hermes-plugin', '--hermes-home', sys.argv[1]])",
                        str(tmp_path)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "plugins" / "aisecuritywarden" / "__init__.py").is_file()


def test_plugin_version_matches_the_client():
    from securitywarden import __version__
    text = hermes.plugin_files()["plugin.yaml"].decode()
    assert f"version: {__version__}\n" in text


@pytest.mark.skipif(os.name == "nt", reason="symlinks")
def test_install_refuses_a_link(tmp_path):
    (tmp_path / "plugins").mkdir()
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "plugins" / "aisecuritywarden").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(hermes.HermesError):
        hermes.install(str(tmp_path))
    assert os.listdir(tmp_path / "elsewhere") == []


def test_hermes_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "h"))
    assert hermes.hermes_home() == str(tmp_path / "h")
    monkeypatch.delenv("HERMES_HOME")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.setattr(sys, "platform", "win32")
    assert hermes.hermes_home() == os.path.join(str(tmp_path / "local"), "hermes")
    (tmp_path / ".hermes").mkdir()            # an older install in ~/.hermes, and nothing in LOCALAPPDATA
    assert hermes.hermes_home() == os.path.join(str(tmp_path), ".hermes")
    monkeypatch.setattr(sys, "platform", "linux")
    assert hermes.hermes_home() == os.path.join(str(tmp_path), ".hermes")


def _store(tmp_path, monkeypatch, *names):
    from securitywarden import crypto
    from securitywarden.client.tokens import TokenStore
    path = tmp_path / "SW_Tokens.json"
    monkeypatch.setenv("SW_TOKENS_FILE", str(path))
    for k in ("SW_SERVER_URL", "SW_ACCESS_TOKEN", "SW_ACCESS_TOKEN_FILE", "SW_TOKEN_NAME", "SW_TOKEN_ID"):
        monkeypatch.delenv(k, raising=False)
    store = TokenStore(str(path))
    for name in names:
        store.put(crypto.new_credential(crypto.KIND_MACHINE), name=name, server=f"https://{name}.example")
    return store


def test_command_prints_only_what_is_needed(tmp_path, monkeypatch, capsys):
    _store(tmp_path, monkeypatch, "jarvis")
    home = tmp_path / "h"
    assert cli.main(["hermes-plugin", "--hermes-home", str(home)]) == 0
    out = capsys.readouterr().out
    assert "Installed the aiSecurityWarden secret source" in out
    assert "hermes plugins enable aisecuritywarden" in out
    assert "hermes config set secrets.aisecuritywarden.enabled true" in out
    # one token stored, with its server: nothing else to set
    assert "token_name" not in out and "server_url" not in out
    assert cli.main(["hermes-plugin", "--hermes-home", str(home)]) == 0
    assert "already up to date" in capsys.readouterr().out


def test_command_with_several_tokens_asks_for_a_name(tmp_path, monkeypatch, capsys):
    _store(tmp_path, monkeypatch, "jarvis", "gmail")
    assert cli.main(["hermes-plugin", "--hermes-home", str(tmp_path / "h")]) == 0
    out = capsys.readouterr().out
    assert "secrets.aisecuritywarden.token_name <one of: gmail, jarvis>" in out
    assert cli.main(["--token-name", "jarvis", "hermes-plugin", "--hermes-home", str(tmp_path / "h")]) == 0
    assert "secrets.aisecuritywarden.token_name jarvis" in capsys.readouterr().out


def test_command_without_a_token_says_to_set_one_up(tmp_path, monkeypatch, capsys):
    _store(tmp_path, monkeypatch)
    assert cli.main(["--server", "https://sw.example", "hermes-plugin", "--hermes-home", str(tmp_path / "h")]) == 0
    out = capsys.readouterr().out
    assert "No machine token is stored" in out and "swctl --server" in out
    assert "secrets.aisecuritywarden.server_url https://sw.example" in out


def test_swctl_setting_only_when_the_plugin_would_not_find_it(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    pipx = os.path.join(str(tmp_path), ".local", "bin", "swctl")
    assert not any("aisecuritywarden.swctl" in ln for ln in hermes.next_steps(server=None, token_name=None, token_id=None,
                                                               swctl=pipx, stored=[{"name": "a", "server": "x"}]))
    lines = hermes.next_steps(server=None, token_name=None, token_id=None, swctl="/opt/sw/bin/swctl",
                              stored=[{"name": "a", "server": "x"}])
    assert any(ln.endswith("secrets.aisecuritywarden.swctl /opt/sw/bin/swctl") for ln in lines)


def test_export_uses_the_stored_tokens_server(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch, "jarvis")
    seen = {}

    class Client:
        def __init__(self, url, cred, **kw):
            seen["url"] = url

        def fetch(self):
            return {"K": "v"}

    monkeypatch.setattr(cli, "SecurityWardenClient", Client)
    assert cli.main(["export", "--format", "json"]) == 0
    assert seen["url"] == "https://jarvis.example"
    # an explicit server still wins
    assert cli.main(["--server", "https://jarvis.example/", "export"]) == 0


def test_export_with_several_tokens_and_no_name_is_a_setting_problem(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch, "jarvis", "gmail")
    with pytest.raises(SystemExit) as e:
        cli.main(["export"])
    assert e.value.code == cli.EXIT_CONFIG


@posix_only
def test_finds_swctl_in_pipx_folder(source, tmp_path, monkeypatch):
    (tmp_path / ".local" / "bin").mkdir(parents=True)
    fake = fake_swctl(tmp_path / ".local" / "bin", 'print(json.dumps({"K": "v"}))')
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python"))
    monkeypatch.setenv("HOME", str(tmp_path))
    r = source.fetch({"enabled": True}, tmp_path)
    assert r.ok and r.secrets == {"K": "v"} and r.binary_path == Path(fake)
