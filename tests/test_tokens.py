"""SW_Tokens.json: several machine tokens in one owner-only file, by token id (names for people and as a
fallback); setup; replacing a token; old name-keyed files; the MCP server picking its token; and tools hidden when
the token's rules deny them."""

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


def test_tokens_by_id_owner_only_never_overwritten_by_accident(tmp_path):
    store = TokenStore(str(tmp_path / "sw" / FILE_NAME))
    a, b = m(), m()
    assert store.put(a, name="jarvis-gmail", server=URL, project="Gmail") == a.id
    store.put(b, name="trader", server=URL)
    assert store.names() == ["jarvis-gmail", "trader"] and store.credential(b.id) == b
    data = json.loads(open(store.path).read())
    assert data["format"] == "sw-tokens-2" and data["tokens"][a.id]["name"] == "jarvis-gmail"
    assert data["tokens"][a.id]["project"] == "Gmail" and "jarvis-gmail" not in data["tokens"]
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(os.path.dirname(store.path)).st_mode) == 0o700
    with pytest.raises(SecurityWardenError, match="already holds"):
        store.put(m(), name="jarvis-gmail", server=URL)                  # same name and server: not by accident
    # found by id, by name (with the server), or as the only one; several and nothing named: refuse to guess
    with pytest.raises(SecurityWardenError, match="several tokens"):
        store.pick(None)
    assert store.pick(token_id=b.id) == b.id and store.pick("trader", server=URL) == b.id
    store.remove(a.id)
    assert store.pick(None) == b.id
    c = store.credential(b.id)
    assert c.secret not in repr(c)
    for bad in ("", " ", "x" * 101, "a\nb"):
        with pytest.raises(SecurityWardenError):
            store.put(m(), name=bad)
    with pytest.raises(SecurityWardenError, match="isn't a token id"):
        store.pick(token_id="../../etc")
    assert all("token" not in e and e["name"] for e in store.entries())


def test_same_name_from_another_account_or_server_never_collides(tmp_path):
    store = TokenStore(str(tmp_path / FILE_NAME))
    mine, keiths, elsewhere = m(), m(), m()
    store.put(mine, name="gmail", server=URL, account="brian")
    store.put(elsewhere, name="gmail", server="https://other.example.com")
    assert store.credential(mine.id) == mine and store.credential(elsewhere.id) == elsewhere
    assert store.pick("gmail", server=URL) == mine.id
    assert store.pick("gmail", server="https://OTHER.example.com/") == elsewhere.id
    # another account on the same server: the website allows the name per account, so it's stored by id too
    store.put(keiths, name="gmail", server=URL, account="keith")         # no replace needed: not the same token
    assert store.credential(mine.id) == mine and store.credential(keiths.id) == keiths
    with pytest.raises(SecurityWardenError, match="SW_TOKEN_ID"):
        store.pick("gmail", server=URL)                                   # ambiguous by name: never guess
    assert store.pick("gmail", token_id=keiths.id, server=URL) == keiths.id


def test_replacing_a_token_keeps_old_settings_working(tmp_path):
    store = TokenStore(str(tmp_path / FILE_NAME))
    old, new, newer = m(), m(), m()
    store.put(old, name="jarvis-gmail", server=URL)
    store.put(new, name="jarvis-gmail", server=URL, replace=True)       # the old one was revoked
    raw = json.loads(open(store.path).read())["tokens"]
    assert raw[old.id] == {"name": "jarvis-gmail", "server": URL, "replaced_by": new.id,
                           "replaced_at": raw[old.id]["replaced_at"]}  # its secret is gone
    assert str(old) not in open(store.path).read()
    assert store.pick(token_id=old.id) == new.id and store.names() == ["jarvis-gmail"]
    store.put(newer, name="jarvis-gmail", server=URL, replace=True)
    assert store.pick(token_id=old.id) == newer.id == store.pick(token_id=new.id)
    assert store.entry(old.id) is None and store.credential(newer.id) == newer
    # an id that was never here falls back to the name; with no name, there's nothing
    assert store.pick("jarvis-gmail", token_id=m().id, server=URL) == newer.id
    assert store.pick(token_id=m().id) is None


def test_old_name_keyed_files_are_read_and_converted_with_a_backup(tmp_path):
    a, b = m(), m()
    path = tmp_path / FILE_NAME
    old = {"format": "sw-tokens-1", "tokens": {
        "jarvis-gmail": {"token": str(a), "server": URL, "project": "Gmail", "id": a.id, "saved_at": 5},
        "trader": {"token": str(b), "server": URL, "project": None, "id": b.id, "saved_at": 6}}}
    path.write_text(json.dumps(old))
    store = TokenStore(str(path))
    assert store.pick("jarvis-gmail", server=URL) == a.id and store.credential(b.id) == b
    assert json.loads(path.read_text())["format"] == "sw-tokens-1"     # reading changes nothing
    c = m()
    store.put(c, name="new-bot", server=URL)
    data = json.loads(path.read_text())
    assert data["format"] == "sw-tokens-2" and set(data["tokens"]) == {a.id, b.id, c.id}
    assert data["tokens"][a.id]["name"] == "jarvis-gmail" and data["tokens"][a.id]["saved_at"] == 5
    assert json.loads((tmp_path / (FILE_NAME + ".v1.bak")).read_text()) == old
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(str(path) + ".v1.bak").st_mode) == 0o600


def test_many_writers_at_once_lose_nothing(tmp_path):
    store = TokenStore(str(tmp_path / FILE_NAME))
    threads = [threading.Thread(target=store.put, args=(m(),), kwargs={"name": f"bot{i}"}) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(store.names()) == 12 and not os.path.exists(store.path + ".lock")


def test_a_stale_lock_is_taken_over(tmp_path):
    store = TokenStore(str(tmp_path / FILE_NAME))
    open(store.path + ".lock", "w").close()
    os.utime(store.path + ".lock", (1, 1))
    store.put(m(), name="a")
    assert store.names() == ["a"]


def test_setup_by_name_refuses_another_tokens_code_without_using_it(tmp_path, http, setup_server):
    store = TokenStore(str(tmp_path / FILE_NAME))
    code = setup_server.add(m(), name="webull-trader", project="Webull")
    with pytest.raises(SecurityWardenError, match="'webull-trader'.*set up for 'jarvis-gmail'"):
        setup_into_store(URL, code, store, "jarvis-gmail", http=http)
    assert store.names() == [] and len(setup_server.codes) == 1          # still usable where it belongs
    cred, name = setup_into_store(URL, code, store, "webull-trader", http=http)
    assert name == "webull-trader" and store.entry(cred.id)["project"] == "Webull" and store.credential(cred.id) == cred
    # no name given: stored under the token's own name
    cred2, name2 = setup_into_store(URL, setup_server.add(m(), name="jarvis-gmail"), store, None, http=http)
    assert name2 == "jarvis-gmail" and store.names() == ["jarvis-gmail", "webull-trader"]
    # a program set up by id refuses a second setup while its token is stored (no replace: it still works)
    with pytest.raises(SecurityWardenError, match="already holds"):
        setup_into_store(URL, setup_server.add(m(), name="jarvis-gmail"), store, "jarvis-gmail", token_id=cred2.id,
                         http=http)
    # once the old one is rejected (replace), the new token takes its place and the old id leads to it
    cred3, _ = setup_into_store(URL, setup_server.add(m(), name="jarvis-gmail"), store, "jarvis-gmail",
                                token_id=cred2.id, replace=True, http=http)
    assert store.pick(token_id=cred2.id) == cred3.id
    # the same name from another account on this server: stored beside it, never over it
    two = TokenStore(str(tmp_path / "two.json"))
    mine, _ = setup_into_store(URL, setup_server.add(m(), name="gmail", account="brian"), two, None, http=http)
    other, _ = setup_into_store(URL, setup_server.add(m(), name="gmail", account="keith"), two, None, http=http)
    assert two.credential(other.id) == other and two.credential(mine.id) == mine
    with pytest.raises(SecurityWardenError, match="SW_TOKEN_ID"):
        two.pick("gmail", server=URL)
    assert two.pick("gmail", token_id=mine.id, server=URL) == mine.id


def _hub(tmp_path, http, name=None, token_id=None):
    made = []

    def make(cred):
        made.append(str(cred))
        return FakeServer({"notes.read.note": "allow"})
    store = TokenStore(str(tmp_path / FILE_NAME))
    hub = Hub(None, [Notes], setup=SetupTarget(URL, None, make, http=http, store=store, token_name=name,
                                               token_id=token_id),
              log=lambda msg: None)
    return hub, store, made


def test_the_agent_sets_up_its_own_named_token(tmp_path, http, setup_server):
    hub, store, made = _hub(tmp_path, http, name="jarvis-gmail")
    store.put(m(), name="webull-trader", server=URL)                       # another bot's, untouched
    r = hub.call("securitywarden_setup", {"code": setup_server.add(m(), name="webull-trader")})
    assert r.is_error and "webull-trader" in r.text and made == []
    cred = m()
    ok = hub.call("securitywarden_setup", {"code": setup_server.add(cred, name="jarvis-gmail")})
    assert not ok.is_error and store.credential(cred.id) == cred and cred.secret not in ok.text
    assert "Buy milk" in hub.call("notes_read", {"id": "n1"}).text
    assert sorted(store.names()) == ["jarvis-gmail", "webull-trader"]


def test_several_tokens_and_no_name(tmp_path, http, setup_server):
    hub, store, made = _hub(tmp_path, http)
    store.put(m(), name="a", server=URL)
    store.put(m(), name="b", server=URL)
    r = hub.call("notes_read", {"id": "n1"})
    assert r.is_error and "SW_TOKEN_ID" in r.text
    # setting up still works: the token is stored under its own name and used from then on
    cred = m()
    ok = hub.call("securitywarden_setup", {"code": setup_server.add(cred, name="c")})
    assert not ok.is_error and store.credential(cred.id) == cred and hub.setup.token_name == "c"


def test_a_stored_token_is_found_by_name(tmp_path, http):
    hub, store, made = _hub(tmp_path, http, name="b")
    store.put(m(), name="a", server=URL)
    b = m()
    store.put(b, name="b", server=URL)
    assert "Buy milk" in hub.call("notes_read", {"id": "n1"}).text and made == [str(b)]


def test_a_stored_token_is_found_by_id_even_with_a_stale_name(tmp_path, http):
    b = m()
    hub, store, made = _hub(tmp_path, http, name="renamed-on-the-website", token_id=b.id)
    store.put(m(), name="a", server=URL)
    store.put(b, name="b", server=URL)
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
    for k in ("SW_ACCESS_TOKEN_FILE", "SW_ACCESS_TOKEN", "SW_SERVER_URL", "SW_MCP_CONFIG", "SW_TOKEN_NAME",
              "SW_TOKEN_ID"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SW_TOKENS_FILE", str(tmp_path / FILE_NAME))

    a = m()
    monkeypatch.setattr("sys.stdin", io.StringIO(setup_server.add(a, name="webull-trader") + "\n"))
    swctl.main(["--server", URL, "setup", "--code-stdin"])
    assert f"SW_TOKEN_ID={a.id} SW_TOKEN_NAME=webull-trader" in capsys.readouterr().err
    b = m()
    monkeypatch.setattr("sys.stdin", io.StringIO(setup_server.add(b, name="jarvis-gmail") + "\n"))
    swmcp.main(["setup", "--server", URL, "--token-name", "jarvis-gmail", "--code-stdin"])
    assert f"SW_TOKEN_ID={b.id} SW_TOKEN_NAME=jarvis-gmail" in capsys.readouterr().err
    store = TokenStore()
    assert store.credential(a.id) == a and store.credential(b.id) == b
    # the same name again is refused before the code is used
    monkeypatch.setattr("sys.stdin", io.StringIO(setup_server.add(m(), name="jarvis-gmail") + "\n"))
    with pytest.raises(SystemExit):
        swmcp.main(["setup", "--server", URL, "--token-name", "jarvis-gmail", "--code-stdin"])
    assert len(setup_server.codes) == 1


def test_gmail_login_reads_the_oauth_client_with_a_named_token(tmp_path, monkeypatch):
    import argparse
    from securitywarden.mcp import cli as swmcp
    from securitywarden.mcp import gmail
    for k in ("SW_ACCESS_TOKEN_FILE", "SW_ACCESS_TOKEN", "SW_MCP_CONFIG", "SW_TOKEN_NAME", "SW_TOKEN_ID"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SW_TOKENS_FILE", str(tmp_path / FILE_NAME))
    monkeypatch.setenv("SW_SERVER_URL", URL)
    asked = []
    monkeypatch.setattr("builtins.input", lambda *a: asked.append(1) or "typed-id")
    monkeypatch.setattr("getpass.getpass", lambda *a: "typed-secret")

    class Fetch:
        def fetch(self):
            return {"GMAIL_CLIENT_ID": "cid", "GMAIL_CLIENT_SECRET": "cs"}
    used = []
    monkeypatch.setattr(swmcp, "_client", lambda args, cfg, wait=True: used.append(1) or Fetch())
    args = argparse.Namespace(config=None, server=None, token_file=None, token_name=None, ca_bundle=None)
    assert gmail._oauth_client(args) == ("typed-id", "typed-secret") and not used    # no token yet: asks
    TokenStore().put(m(), name="keith-gmail", server=URL)
    assert gmail._oauth_client(args) == ("cid", "cs") and used and len(asked) == 1  # the only token
    TokenStore().put(m(), name="other", server=URL)
    assert gmail._oauth_client(args) == ("typed-id", "typed-secret")               # several, none named: asks
    monkeypatch.setenv("SW_TOKEN_NAME", "keith-gmail")
    assert gmail._oauth_client(args) == ("cid", "cs")


def test_two_mcp_servers_each_take_only_their_own_code(tmp_path, http, setup_server):
    """The jarvis case: an older entry with a token file of its own (its token revoked) and a new entry for
    'Jarvis Gmail' in SW_Tokens.json. Each setup tool says which token it's for, and the old one refuses the new
    token's code without using it up, telling the agent to use the other tool."""
    from securitywarden.client.setup import setup_from_code
    revoked = m()
    old_file = str(tmp_path / "gmail-token-old")
    setup_from_code(URL, setup_server.add(revoked, name="gmail-old"), old_file, http=http)

    class Rejected(FakeServer):
        def check_token(self):
            from securitywarden.client import TokenRejected
            raise TokenRejected("revoked")
    old = Hub(None, [Notes], setup=SetupTarget(URL, old_file, lambda cred: Rejected({"notes.read.note": "allow"}),
                                                  http=http), log=lambda msg: None)
    new, store, made = _hub(tmp_path, http, name="Jarvis Gmail")
    d_old = next(t for t in old.list_tools() if t["name"] == "securitywarden_setup")["description"]
    d_new = next(t for t in new.list_tools() if t["name"] == "securitywarden_setup")["description"]
    assert "gmail-token-old" in d_old and revoked.id in d_old and "'Jarvis Gmail'" in d_new

    cred = m()
    code = setup_server.add(cred, name="Jarvis Gmail")
    r = old.call("securitywarden_setup", {"code": code})
    assert r.is_error and "NOT used up" in r.text and "'Jarvis Gmail'" in r.text
    assert open(old_file).read().strip() == str(revoked) and len(setup_server.codes) == 1
    ok = new.call("securitywarden_setup", {"code": code})
    assert not ok.is_error and "'Jarvis Gmail'" in ok.text and store.credential(cred.id) == cred


def test_set_up_by_id_only_refuses_another_tokens_code(tmp_path, http, setup_server):
    mine = m()
    hub, store, made = _hub(tmp_path, http, token_id=mine.id)
    r = hub.call("securitywarden_setup", {"code": setup_server.add(m(), name="someone-else")})
    assert r.is_error and "NOT used up" in r.text and len(setup_server.codes) == 1
    ok = hub.call("securitywarden_setup", {"code": setup_server.add(mine, name="mine")})
    assert not ok.is_error and store.credential(mine.id) == mine


def test_swctl_tokens_list_and_import(tmp_path, monkeypatch, capsys):
    from securitywarden.client import cli as swctl
    monkeypatch.setenv("SW_TOKENS_FILE", str(tmp_path / FILE_NAME))
    monkeypatch.delenv("SW_SERVER_URL", raising=False)
    old = m()
    path = tmp_path / "gmail-token"
    path.write_text(str(old) + "\n")
    swctl.main(["--server", URL, "tokens", "import", "--file", str(path), "--name", "jarvis-gmail"])
    err = capsys.readouterr().err
    assert f"SW_TOKEN_ID={old.id}" in err and "SW_TOKEN_NAME=jarvis-gmail" in err and str(old) not in err
    assert TokenStore().credential(old.id) == old and path.exists()            # the old file is left for the user
    swctl.main(["--server", URL, "tokens", "import", "--file", str(path), "--name", "jarvis-gmail"])
    assert "nothing to do" in capsys.readouterr().err
    swctl.main(["tokens", "list"])
    out = capsys.readouterr().out
    assert old.id in out and "jarvis-gmail" in out and str(old) not in out and old.secret not in out
    admin = tmp_path / "admin"
    admin.write_text(str(crypto.new_credential(crypto.KIND_ADMIN)))
    with pytest.raises(SystemExit):
        swctl.main(["--server", URL, "tokens", "import", "--file", str(admin), "--name", "x"])
