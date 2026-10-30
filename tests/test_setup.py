"""One-time setup codes on the client: the crypto (against the shared vectors), storing the token so only
this user can read it, and the MCP securitywarden_setup tool's rules. The server side is tested in the
server repo against this package."""

import json
import os
import stat

import httpx
import pytest

from securitywarden import crypto
from securitywarden.client import SecurityWardenError, redeem_setup_code
from securitywarden.client.setup import setup_from_code, store_credential
from securitywarden.crypto import CryptoError
from securitywarden.mcp import Hub
from securitywarden.mcp.framework import SetupTarget

from test_mcp import FakeServer, Notes

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "vectors", "crypto-v1.json"), encoding="utf-8") as _f:
    V = json.load(_f)["setup"]


# -- crypto ----------------------------------------------------------------------------------

def test_setup_vectors():
    secret = bytes.fromhex(V["secret_hex"])
    assert crypto.format_setup_code(secret) == V["code"] and crypto.setup_id(secret) == V["id"]
    for p in V["parse"]:
        assert crypto.parse_setup_code(p["text"]).hex() == p["secret_hex"]
    for bad in V["bad_codes"]:
        with pytest.raises(CryptoError):
            crypto.parse_setup_code(bad)
    assert str(crypto.decrypt_from_setup(secret, V["blob"])) == V["credential"]
    for bad in V["must_fail"]:
        with pytest.raises(CryptoError):
            crypto.decrypt_from_setup(bytes.fromhex(bad["secret_hex"]), bad["blob"])
    with pytest.raises(CryptoError):
        crypto.encrypt_for_setup(secret, crypto.new_credential(crypto.KIND_ADMIN))
    code = crypto.format_setup_code(crypto.new_setup_secret())
    assert crypto.format_setup_code(crypto.parse_setup_code(code)) == code


# -- storing and redeeming -------------------------------------------------------------------

class FakeSetupServer:
    def __init__(self):
        self.codes = {}        # setup id -> blob

    def add(self, cred):
        secret = crypto.new_setup_secret()
        sid, blob = crypto.encrypt_for_setup(secret, cred)
        self.codes[sid] = blob
        return crypto.format_setup_code(secret)

    def __call__(self, req: httpx.Request) -> httpx.Response:
        sid = req.url.path.rsplit("/", 1)[-1]
        if req.method == "POST" and req.url.path.startswith("/v1/setup/") and sid in self.codes:
            return httpx.Response(200, json={"blob": self.codes.pop(sid)})
        return httpx.Response(404, json={"detail": "unknown, used or expired setup code"})


@pytest.fixture
def setup_server():
    return FakeSetupServer()


@pytest.fixture
def http(setup_server):
    return httpx.Client(transport=httpx.MockTransport(setup_server))


def test_store_is_owner_only_and_never_overwrites_by_accident(tmp_path):
    cred = crypto.new_credential(crypto.KIND_MACHINE)
    path = tmp_path / "new" / "dir" / "token"
    where = store_credential(str(path), cred)
    assert open(where).read().strip() == str(cred)
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(where).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    with pytest.raises(SecurityWardenError, match="already holds a token"):
        store_credential(str(path), crypto.new_credential(crypto.KIND_MACHINE))
    other = crypto.new_credential(crypto.KIND_MACHINE)
    store_credential(str(path), other, replace=True)
    assert open(where).read().strip() == str(other)
    assert [p.name for p in path.parent.iterdir()] == ["token"]          # no temporary files left


def test_setup_from_code_works_once(tmp_path, http, setup_server):
    cred = crypto.new_credential(crypto.KIND_MACHINE)
    code = setup_server.add(cred)
    got, where = setup_from_code("https://vault.example.com", code, str(tmp_path / "t"), http=http)
    assert str(got) == str(cred) and open(where).read().strip() == str(cred)
    with pytest.raises(SecurityWardenError, match="unknown, already used or expired"):
        redeem_setup_code("https://vault.example.com", code, http=http)
    # a stored token is never replaced by accident, and the code isn't used up trying
    code2 = setup_server.add(crypto.new_credential(crypto.KIND_MACHINE))
    with pytest.raises(SecurityWardenError, match="already holds a token"):
        setup_from_code("https://vault.example.com", code2, str(tmp_path / "t"), http=http)
    assert len(setup_server.codes) == 1
    with pytest.raises(SecurityWardenError, match="isn't a SecurityWarden setup code"):
        redeem_setup_code("https://vault.example.com", "hello", http=http)
    with pytest.raises(SecurityWardenError, match="plain http"):
        redeem_setup_code("http://vault.example.com", code2)


# -- the MCP setup tool ------------------------------------------------------------------------

def _hub(tmp_path, http, server=None):
    made = []

    def make(cred):
        made.append(str(cred))
        return server or FakeServer({"notes.read.note": "allow"})
    hub = Hub(None, [Notes], setup=SetupTarget("https://vault.example.com", str(tmp_path / "token"), make, http=http),
              log=lambda m: None)
    return hub, made


def test_until_set_up_tools_explain_and_setup_is_offered(tmp_path, http, setup_server):
    hub, made = _hub(tmp_path, http)
    names = [t["name"] for t in hub.list_tools()]
    assert "securitywarden_setup" in names
    r = hub.call("notes_read", {"id": "n1"})
    assert r.is_error and "setup code" in r.text and "securitywarden_setup" in r.text
    cred = crypto.new_credential(crypto.KIND_MACHINE)
    code = setup_server.add(cred)
    ok = hub.call("securitywarden_setup", {"code": code})
    assert not ok.is_error and "set up" in ok.text
    assert str(cred) not in ok.text and cred.secret not in ok.text      # the token never goes to the AI
    assert made == [str(cred)] and open(tmp_path / "token").read().strip() == str(cred)
    assert "Buy milk" in hub.call("notes_read", {"id": "n1"}).text


def test_setup_refuses_once_set_up(tmp_path, http, setup_server):
    hub, made = _hub(tmp_path, http)
    hub.call("securitywarden_setup", {"code": setup_server.add(crypto.new_credential(crypto.KIND_MACHINE))})
    first = open(tmp_path / "token").read()
    attacker = setup_server.add(crypto.new_credential(crypto.KIND_MACHINE))
    r = hub.call("securitywarden_setup", {"code": attacker})
    assert r.is_error and "already set up" in r.text
    assert open(tmp_path / "token").read() == first and len(made) == 1
    assert len(setup_server.codes) == 1                                  # the other code wasn't even used


def test_a_hub_with_a_token_offers_no_setup(tmp_path, http):
    hub = Hub(FakeServer(), [Notes], log=lambda m: None)
    assert "securitywarden_setup" not in [t["name"] for t in hub.list_tools()]
    with pytest.raises(KeyError):
        hub.call("securitywarden_setup", {"code": "SWS1-x"})


def test_bad_codes_change_nothing(tmp_path, http):
    hub, made = _hub(tmp_path, http)
    for args in ({"code": "nope"}, {"code": crypto.format_setup_code(crypto.new_setup_secret())}, {}, {"code": 1},
                 {"code": "x", "extra": 1}):
        r = hub.call("securitywarden_setup", args)
        assert r.is_error, args
    assert not (tmp_path / "token").exists() and made == []


def test_a_token_stored_from_a_terminal_is_picked_up(tmp_path, http):
    hub, made = _hub(tmp_path, http)
    cred = crypto.new_credential(crypto.KIND_MACHINE)
    store_credential(str(tmp_path / "token"), cred)
    assert "Buy milk" in hub.call("notes_read", {"id": "n1"}).text and made == [str(cred)]


def test_swctl_and_sw_mcp_setup_commands(tmp_path, monkeypatch, capsys, setup_server, http):
    import io
    import securitywarden.client.setup as setup_mod
    from securitywarden.client import cli as swctl
    from securitywarden.mcp import cli as swmcp
    real = setup_mod.redeem_setup_code
    monkeypatch.setattr(setup_mod, "redeem_setup_code", lambda url, code, **kw: real(url, code, http=http))
    for k in ("SW_ACCESS_TOKEN_FILE", "SW_ACCESS_TOKEN", "SW_SERVER_URL", "SW_MCP_CONFIG"):
        monkeypatch.delenv(k, raising=False)

    cred = crypto.new_credential(crypto.KIND_MACHINE)
    monkeypatch.setattr("sys.stdin", io.StringIO(setup_server.add(cred) + "\n"))
    path = tmp_path / "a" / "token"
    assert swctl.main(["--server", "https://vault.example.com", "--token-file", str(path), "setup", "--code-stdin"]) in (0, None)
    assert path.read_text().strip() == str(cred) and "readable by you only" in capsys.readouterr().err

    cred2 = crypto.new_credential(crypto.KIND_MACHINE)
    monkeypatch.setattr("sys.stdin", io.StringIO(setup_server.add(cred2) + "\n"))
    with pytest.raises(SystemExit):                                       # already there: refused, code kept
        swmcp.main(["setup", "--server", "https://vault.example.com", "--token-file", str(path), "--code-stdin"])
    assert len(setup_server.codes) == 1
    swmcp.main(["setup", "--server", "https://vault.example.com", "--token-file", str(path), "--code-stdin",
                "--replace", "--connector", "gmail"])
    err = capsys.readouterr().err
    assert path.read_text().strip() == str(cred2) and "serve --connector gmail" in err
