"""SW_Tokens.json: several machine tokens in one owner-only file, by name; setup by name; the MCP server
picking its token by name; and tools hidden when the token's rules deny them."""

import json
import os
import stat
import threading

import httpx
import pytest

from securitywarden import crypto
from securitywarden.client import SecurityWardenError
from securitywarden.client.setup import setup_into_store
from securitywarden.client.tokens import FILE_NAME, TokenStore, default_tokens_path
from securitywarden.mcp import Hub
from securitywarden.mcp.framework import SetupTarget
from securitywarden.mcp.testing import FakeSecurityWarden

from test_mcp import FakeServer, Notes
from test_setup import FakeSetupServer

URL = "https://vault.example.com"


@pytest.fixture
def setup_server():
    return FakeSetupServer()


@pytest.fixture
def http(setup_server):
    return httpx.Client(transport=httpx.MockTransport(setup_server))


def m():
    return crypto.new_credential(crypto.KIND_MACHINE)


def test_default_location(monkeypatch, tmp_path):
    monkeypatch.delenv("SW_TOKENS_FILE", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    if os.name != "nt":
        assert default_tokens_path() == str(tmp_path / "securitywarden" / FILE_NAME)
    monkeypatch.setenv("SW_TOKENS_FILE", str(tmp_path / "x.json"))
    assert default_tokens_path() == str(tmp_path / "x.json")


def test_tokens_by_name_owner_only_never_overwritten_by_accident(tmp_path):
    store = TokenStore(str(tmp_path / "sw" / FILE_NAME))
    a, b = m(), m()
    store.put("jarvis-gmail", a, server=URL, project="Gmail")
    store.put("webull-trader", b, server=URL)
    assert store.names() == ["jarvis-gmail", "webull-trader"] and store.credential("webull-trader") == b
    data = json.loads(open(store.path).read())
    assert data["format"] == "sw-tokens-1" and data["tokens"]["jarvis-gmail"]["project"] == "Gmail"
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(os.path.dirname(store.path)).st_mode) == 0o700
    with pytest.raises(SecurityWardenError, match="already holds"):
        store.put("jarvis-gmail", m())
    store.put("jarvis-gmail", b, replace=True)
    assert store.credential("jarvis-gmail") == b and store.credential("webull-trader") == b
    # one named: that one; none named and several stored: refuse to guess
    with pytest.raises(SecurityWardenError, match="several tokens"):
        store.pick(None)
    assert store.pick("webull-trader") == "webull-trader"
    store.remove("jarvis-gmail")
    assert store.pick(None) == "webull-trader"
    c = store.credential("webull-trader")
    assert c.secret not in repr(c)
    for bad in ("", " ", "x" * 101, "a\nb"):
        with pytest.raises(SecurityWardenError):
            store.put(bad, m())


def test_many_writers_at_once_lose_nothing(tmp_path):
    store = TokenStore(str(tmp_path / FILE_NAME))
    threads = [threading.Thread(target=store.put, args=(f"bot{i}", m())) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(store.names()) == 12 and not os.path.exists(store.path + ".lock")


def test_a_stale_lock_is_taken_over(tmp_path):
    store = TokenStore(str(tmp_path / FILE_NAME))
    open(store.path + ".lock", "w").close()
    os.utime(store.path + ".lock", (1, 1))
    store.put("a", m())
    assert store.names() == ["a"]


def test_setup_by_name_refuses_another_tokens_code_without_using_it(tmp_path, http, setup_server):
    store = TokenStore(str(tmp_path / FILE_NAME))
    code = setup_server.add(m(), name="webull-trader", project="Webull")
    with pytest.raises(SecurityWardenError, match="'webull-trader'.*set up for 'jarvis-gmail'"):
        setup_into_store(URL, code, store, "jarvis-gmail", http=http)
    assert store.names() == [] and len(setup_server.codes) == 1          # still usable where it belongs
    cred, name = setup_into_store(URL, code, store, "webull-trader", http=http)
    assert name == "webull-trader" and store.entry(name)["project"] == "Webull" and store.credential(name) == cred
    # no name given: stored under the token's own name
    cred2, name2 = setup_into_store(URL, setup_server.add(m(), name="jarvis-gmail"), store, None, http=http)
    assert name2 == "jarvis-gmail" and store.names() == ["jarvis-gmail", "webull-trader"]


def _hub(tmp_path, http, name=None):
    made = []

    def make(cred):
        made.append(str(cred))
        return FakeServer({"notes.read.note": "allow"})
    store = TokenStore(str(tmp_path / FILE_NAME))
    hub = Hub(None, [Notes], setup=SetupTarget(URL, None, make, http=http, store=store, token_name=name),
              log=lambda msg: None)
    return hub, store, made


def test_the_agent_sets_up_its_own_named_token(tmp_path, http, setup_server):
    hub, store, made = _hub(tmp_path, http, name="jarvis-gmail")
    store.put("webull-trader", m())                                        # another bot's, untouched
    r = hub.call("securitywarden_setup", {"code": setup_server.add(m(), name="webull-trader")})
    assert r.is_error and "webull-trader" in r.text and made == []
    cred = m()
    ok = hub.call("securitywarden_setup", {"code": setup_server.add(cred, name="jarvis-gmail")})
    assert not ok.is_error and store.credential("jarvis-gmail") == cred and cred.secret not in ok.text
    assert "Buy milk" in hub.call("notes_read", {"id": "n1"}).text
    assert sorted(store.names()) == ["jarvis-gmail", "webull-trader"]


def test_several_tokens_and_no_name(tmp_path, http, setup_server):
    hub, store, made = _hub(tmp_path, http)
    store.put("a", m())
    store.put("b", m())
    r = hub.call("notes_read", {"id": "n1"})
    assert r.is_error and "SW_TOKEN_NAME" in r.text
    # setting up still works: the token is stored under its own name and used from then on
    cred = m()
    ok = hub.call("securitywarden_setup", {"code": setup_server.add(cred, name="c")})
    assert not ok.is_error and store.credential("c") == cred and hub.setup.token_name == "c"


def test_a_stored_token_is_found_by_name(tmp_path, http):
    hub, store, made = _hub(tmp_path, http, name="b")
    store.put("a", m())
    b = m()
    store.put("b", b)
    assert "Buy milk" in hub.call("notes_read", {"id": "n1"}).text and made == [str(b)]


def test_tools_the_rules_deny_are_not_offered():
    from securitywarden.mcp.remote import RemoteConnectors
    sw = FakeSecurityWarden()
    sw.actions = {"rules": [{"match": "notes.delete", "mode": "deny"}, {"match": "notes.*", "mode": "allow"}],
                  "channels": ["admin_ui"]}
    hub = Hub(sw, [Notes], source=RemoteConnectors({}, os.devnull), log=lambda msg: None)
    names = {t["name"] for t in hub.list_tools()}
    assert "notes_delete" not in names and "notes_read" in names
    sw.actions = None                                                      # rules changed: offered again
    hub.refresh(force=True)
    assert hub.tools_changed and "notes_delete" in {t["name"] for t in hub.list_tools()}


def test_swctl_and_sw_mcp_setup_into_the_shared_file(tmp_path, monkeypatch, capsys, setup_server, http):
    import io
    import securitywarden.client.setup as setup_mod
    from securitywarden.client import cli as swctl
    from securitywarden.mcp import cli as swmcp
    real = setup_mod.redeem_setup_code_info
    monkeypatch.setattr(setup_mod, "redeem_setup_code_info", lambda url, code, **kw: real(url, code, **{**kw, "http": http}))
    for k in ("SW_ACCESS_TOKEN_FILE", "SW_ACCESS_TOKEN", "SW_SERVER_URL", "SW_MCP_CONFIG", "SW_TOKEN_NAME"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SW_TOKENS_FILE", str(tmp_path / FILE_NAME))

    a = m()
    monkeypatch.setattr("sys.stdin", io.StringIO(setup_server.add(a, name="webull-trader") + "\n"))
    swctl.main(["--server", URL, "setup", "--code-stdin"])
    assert "SW_TOKEN_NAME=webull-trader" in capsys.readouterr().err
    b = m()
    monkeypatch.setattr("sys.stdin", io.StringIO(setup_server.add(b, name="jarvis-gmail") + "\n"))
    swmcp.main(["setup", "--server", URL, "--token-name", "jarvis-gmail", "--code-stdin"])
    assert "SW_TOKEN_NAME=jarvis-gmail" in capsys.readouterr().err
    store = TokenStore()
    assert store.credential("webull-trader") == a and store.credential("jarvis-gmail") == b
    # the same name again is refused before the code is used
    monkeypatch.setattr("sys.stdin", io.StringIO(setup_server.add(m(), name="jarvis-gmail") + "\n"))
    with pytest.raises(SystemExit):
        swmcp.main(["setup", "--server", URL, "--token-name", "jarvis-gmail", "--code-stdin"])
    assert len(setup_server.codes) == 1
