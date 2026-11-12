"""Connectors stored in aiSecurityWarden: crypto, bundles, loading from memory, live updates, rollback."""

import io
import json
import sys

import pytest

from securitywarden import crypto
from securitywarden.mcp.bundle import BundleError, bundle_bytes, load_bundle, pack, unload_bundle, validate_bundle
from securitywarden.mcp.framework import Hub
from securitywarden.mcp.remote import RemoteConnectors
from securitywarden.mcp.scaffold import create_connector_project
from securitywarden.mcp.server import StdioServer
from securitywarden.mcp.testing import FakeSecurityWarden

CODE = '''
from securitywarden.mcp import Connector, Plan, Summary, tool

class Memo(Connector):
    name = "memo"
    description = "Memos."
    suggested_rules = ("memo.read.*=allow",)

    @tool("Say which version this is.", action="memo.read.version", risk="low")
    def version(self) -> Plan:
        return Plan({}, Summary("Version"), lambda a: {"version": VERSION})

    @tool("Delete a memo.", action="memo.delete", risk="high",
          params={"memo_id": {"type": "string", "description": "id"}}, required=["memo_id"])
    def delete(self, memo_id: str) -> Plan:
        return Plan({"id": memo_id}, Summary("Delete a memo", [("Memo", memo_id)]), lambda a: {"deleted": a["id"]})
'''


def memo_bundle(version: int, extra: str = "") -> dict:
    return validate_bundle({"format": "sw-connector-1", "name": "memo", "title": "Memo",
                            "entry": "sw_t_memo.connector:Memo",
                            "files": {"sw_t_memo/__init__.py": "",
                                      "sw_t_memo/connector.py": f"VERSION = {version}\n" + CODE + extra}})


@pytest.fixture(autouse=True)
def _clean():
    yield
    unload_bundle(memo_bundle(1))


# -- crypto -----------------------------------------------------------------------------------------

def test_connector_crypto_binds_id_version_and_part():
    ck, cid, pid, pkey = crypto.new_connector_key(), crypto.new_id(), crypto.new_id(), crypto.new_key()
    b, m = crypto.encrypt_connector(ck, cid, 4, {"x": "é"}, {"name": "n", "activation": "restart"})
    assert crypto.decrypt_connector_bundle(ck, cid, 4, b) == {"x": "é"}
    assert crypto.decrypt_connector_meta(ck, cid, 4, m)["activation"] == "restart"
    for bad in (lambda: crypto.decrypt_connector_bundle(ck, cid, 3, b),            # version
                lambda: crypto.decrypt_connector_bundle(ck, crypto.new_id(), 4, b),  # another connector
                lambda: crypto.decrypt_connector_bundle(ck, cid, 4, m),            # meta as bundle
                lambda: crypto.decrypt_connector_meta(crypto.new_key(), cid, 4, m)):
        with pytest.raises(crypto.CryptoError):
            bad()
    with pytest.raises(crypto.CryptoError):
        crypto.encrypt_connector(ck, cid, 1, {}, {"activation": "sometime"})
    with pytest.raises(crypto.CryptoError):
        crypto.encrypt_connector(ck, cid, 0, {}, {"activation": "now"})
    w = crypto.wrap_connector_key_for_project(ck, pkey, pid, cid)
    assert crypto.unwrap_connector_key_for_project(w, pkey, pid, cid) == ck
    with pytest.raises(crypto.CryptoError):
        crypto.unwrap_connector_key_for_project(w, pkey, crypto.new_id(), cid)   # another project
    with pytest.raises(crypto.CryptoError):
        crypto.unwrap_connector_key_for_project(w, pkey, pid, crypto.new_id())   # another connector
    acct, uid = crypto.new_key(), crypto.new_id()
    wu = crypto.wrap_connector_key_for_account(ck, acct, uid, cid)
    assert crypto.unwrap_connector_key_for_account(wu, acct, uid, cid) == ck
    with pytest.raises(crypto.CryptoError):
        crypto.unwrap_connector_key_for_account(wu, acct, crypto.new_id(), cid)
    admin = crypto.new_credential("a")
    wa = crypto.wrap_connector_key_for_admin(ck, admin, cid)
    assert crypto.unwrap_connector_key_for_admin(wa, admin, cid) == ck


# -- bundles ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("change, why", [
    ({"format": "zip"}, "format"),
    ({"name": "Memo!"}, "name"),
    ({"entry": "sw_t_memo.connector"}, "entry"),
    ({"entry": "elsewhere:Memo"}, "not in the bundle"),
    ({"files": {"../evil.py": "x"}}, "bad file"),
    ({"files": {"sw_t_memo/native.so": "x"}}, "bad file"),
    ({"files": {"json/__init__.py": "x"}, "entry": "json:Memo"}, "may not provide"),
    ({"files": {"securitywarden/x.py": "x"}, "entry": "securitywarden.x:Memo"}, "may not provide"),
    ({"files": {"httpx.py": "x"}, "entry": "httpx:Memo"}, "may not provide"),
])
def test_bad_bundles_are_refused(change, why):
    b = dict(memo_bundle(1), **change)
    with pytest.raises(BundleError, match=why):
        validate_bundle(b)


def test_pack_a_scaffolded_connector(tmp_path, monkeypatch):
    root = create_connector_project("packtest", str(tmp_path))
    monkeypatch.syspath_prepend(f"{root}/src")
    from sw_connector_packtest.connector import Packtest
    b = pack(Packtest)
    assert b["name"] == "packtest" and b["entry"] == "sw_connector_packtest.connector:Packtest"
    assert set(b["files"]) == {"sw_connector_packtest/__init__.py", "sw_connector_packtest/connector.py"}
    assert {t["action"] for t in b["tools"]} == {"packtest.read.items", "packtest.delete"}
    assert json.loads(bundle_bytes(b)) == b
    for m in [m for m in sys.modules if m.startswith("sw_connector_packtest")]:
        del sys.modules[m]
    # it loads from memory, not from the folder
    monkeypatch.setattr(sys, "path", [p for p in sys.path if not p.startswith(root)])
    cls = load_bundle(b, "test@1")
    assert cls.name == "packtest" and cls is not Packtest
    unload_bundle(b)


def test_pack_refuses_a_connector_with_errors():
    from securitywarden.mcp import Connector, Plan, Summary, tool

    class Bad(Connector):
        name = "bad"

        @tool("x", action="bad.read.x", risk="low", params={"n": {"type": "number"}})
        def x(self, n):
            return Plan({}, Summary("x"), lambda a: None)
    with pytest.raises(BundleError, match="errors"):
        pack(Bad)


def test_load_from_memory_and_replace_with_a_new_version():
    v1 = load_bundle(memo_bundle(1), "c1@1")
    v2 = load_bundle(memo_bundle(2), "c1@2")
    assert v1 is not v2 and sys.modules["sw_t_memo.connector"].VERSION == 2
    with pytest.raises(BundleError, match="another connector"):
        load_bundle(memo_bundle(3), "c2@1")          # a different connector may not take its package
    with pytest.raises(BundleError, match="failed to load"):
        load_bundle(memo_bundle(4, "\nraise RuntimeError('boom')\n"), "c1@4")
    with pytest.raises(BundleError, match="already installed"):
        load_bundle(dict(memo_bundle(1), files={"pytest/__init__.py": ""}, entry="pytest:Memo"), "c3@1")


# -- sw-mcp picking connectors up from aiSecurityWarden -----------------------------------------------

def hub_for(sw, tmp_path, *, clock=None):
    t = [0.0]
    src = RemoteConnectors({}, str(tmp_path / "versions.json"))
    logs = []
    hub = Hub(sw, [], source=src, log=logs.append, clock=clock or (lambda: t[0]))
    return hub, t, logs


def version_of(hub):
    return json.loads(hub.call("memo_version", {}).text)["version"]


def test_go_live_now_updates_a_running_agent(tmp_path):
    sw = FakeSecurityWarden({"memo.read.*": "allow"})
    cid = sw.publish(memo_bundle(1))
    hub, t, logs = hub_for(sw, tmp_path)
    assert {x["name"] for x in hub.list_tools()} >= {"memo_version", "memo_delete"}
    assert version_of(hub) == 1
    sw.publish(memo_bundle(2), connector_id=cid)
    assert version_of(hub) == 1                       # checked again only after refresh_every
    t[0] += 31
    assert version_of(hub) == 2 and hub.tools_changed
    assert json.load(open(tmp_path / "versions.json")) == {cid: 2}


def test_on_next_restart_waits_for_a_restart(tmp_path):
    sw = FakeSecurityWarden({"memo.read.*": "allow"})
    cid = sw.publish(memo_bundle(1))
    hub, t, logs = hub_for(sw, tmp_path)
    assert version_of(hub) == 1
    sw.publish(memo_bundle(2), connector_id=cid, activation="restart")
    t[0] += 31
    assert version_of(hub) == 1 and any("when sw-mcp restarts" in m for m in logs)
    hub2, _, _ = hub_for(sw, tmp_path)                # a restart
    assert version_of(hub2) == 2


def test_an_older_version_is_never_loaded(tmp_path):
    sw = FakeSecurityWarden({"memo.read.*": "allow"})
    cid = sw.publish(memo_bundle(5), version=5)
    hub, t, logs = hub_for(sw, tmp_path)
    assert version_of(hub) == 5
    sw.publish(memo_bundle(4), connector_id=cid, version=4)       # a server rolling it back
    t[0] += 31
    assert version_of(hub) == 5 and any("never loaded" in m for m in logs)
    hub2, _, logs2 = hub_for(sw, tmp_path)            # not after a restart either
    hub2.list_tools()
    assert "memo_version" not in hub2.tools and any("never loaded" in m for m in logs2)


def test_turned_off_and_new_connectors_and_waiting_actions(tmp_path):
    sw = FakeSecurityWarden({"memo.read.*": "allow"})
    hub, t, logs = hub_for(sw, tmp_path)
    assert "memo_delete" not in hub.tools
    cid = sw.publish(memo_bundle(1))
    r = hub.call("memo_delete", {"memo_id": "m1"})    # unknown tool: looks again at once
    assert r.data["status"] == "waiting_for_approval"
    sw.publish(memo_bundle(2), connector_id=cid)
    t[0] += 31
    sw.approve(r.data["request_id"])
    done = hub.call("check_approval", {"request_id": r.data["request_id"]})
    assert done.is_error and "was updated" in done.text   # code that changed meanwhile doesn't run the old plan
    del sw.custom[cid]
    t[0] += 31
    hub.list_tools()
    assert "memo_delete" not in hub.tools and "sw_t_memo" not in sys.modules


def test_a_broken_new_version_keeps_the_old_one_running(tmp_path):
    sw = FakeSecurityWarden({"memo.read.*": "allow"})
    cid = sw.publish(memo_bundle(1))
    hub, t, logs = hub_for(sw, tmp_path)
    assert version_of(hub) == 1
    sw.publish(memo_bundle(2, "\nraise RuntimeError('boom')\n"), connector_id=cid)
    t[0] += 31
    assert version_of(hub) == 1 and any("not loaded" in m for m in logs)


def test_builtin_connectors_turned_on_in_securitywarden(tmp_path):
    from securitywarden.mcp.gmail import Gmail
    sw = FakeSecurityWarden()
    sw.builtin = ["gmail", "future_thing"]
    logs = []
    hub = Hub(sw, [], source=RemoteConnectors({"gmail": lambda: Gmail}, str(tmp_path / "v.json")), log=logs.append)
    assert "gmail_send" in {x["name"] for x in hub.list_tools()}
    assert any("update the aiSecurityWarden client" in m for m in logs)


def test_the_agent_is_told_when_tools_change(tmp_path):
    sw = FakeSecurityWarden({"memo.read.*": "allow"})
    hub, t, _ = hub_for(sw, tmp_path)
    hub.list_tools()                                  # nothing yet
    sw.publish(memo_bundle(1))
    t[0] += 31
    lines = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
             {"jsonrpc": "2.0", "method": "notifications/initialized"},
             {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "memo_version", "arguments": {}}}]
    out = io.BytesIO()
    StdioServer(hub).serve(io.BytesIO(b"".join(json.dumps(m).encode() + b"\n" for m in lines)), out)
    msgs = [json.loads(x) for x in out.getvalue().splitlines()]
    assert msgs[0]["result"]["capabilities"]["tools"]["listChanged"] is True
    assert msgs[2] == {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
    assert '"version": 1' in msgs[1]["result"]["content"][0]["text"]
