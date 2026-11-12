"""Client updates: signed releases, no downgrades, the approval-gated MCP tools and the update notice."""

import hashlib
import json
import zipfile

import pytest

from securitywarden import crypto, release
from securitywarden.client import update
from securitywarden.client.api import SecurityWardenError
from securitywarden.mcp import Hub

from test_mcp import FakeServer, Notes

PASS = b"correct horse battery"


@pytest.fixture(autouse=True)
def _nothing_newer_on_disk(monkeypatch):
    """These tests say which version is installed; the real one on disk (this dev install) doesn't count."""
    monkeypatch.setattr(update, "disk_version", lambda: None)


@pytest.fixture(scope="module")
def key():
    pem, pub = crypto.new_release_key(PASS)
    return pem, {crypto.release_key_id(pub): pub}


def _wheel(tmp_path, version):
    path = tmp_path / release.wheel_name(version)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"aisecuritywarden-{version}.dist-info/METADATA",
                   f"Metadata-Version: 2.1\nName: aisecuritywarden\nVersion: {version}\n")
        z.writestr("securitywarden/__init__.py", f'__version__ = "{version}"\n')
    return str(path)


class Offer:
    """Stands in for the server's /v1/client endpoints."""

    def __init__(self, doc=None, data=b"", min_supported=None):
        self.doc, self.data, self.min_supported = doc, data, min_supported
        self.downloads = []

    def client_release(self):
        return {"release": self.doc, "min_supported": self.min_supported}

    def download_client_release(self, file):
        self.downloads.append(file)
        return self.data


def _offer(tmp_path, key, version="0.7.0", notes="Faster approvals", **kw):
    pem, _keys = key
    w = _wheel(tmp_path, version)
    doc = release.sign(w, pem, PASS, notes)
    return Offer(doc, open(w, "rb").read(), **kw)


# -- versions --------------------------------------------------------------------------

def test_versions_sort_like_pip():
    order = ["0.6.0.dev2", "0.6.0.dev24", "0.6.0a1", "0.6.0rc1", "0.6.0", "0.6.0.post1", "0.6.1.dev1", "0.7"]
    assert sorted(order, key=release.version_key) == order
    assert release.version_key("1.0") == release.version_key("1.0.0")
    assert not release.is_newer("0.6.0", "0.6.0")
    with pytest.raises(ValueError):
        release.version_key("1.0-beta")


# -- signatures ------------------------------------------------------------------------

def test_a_signed_release_verifies_and_any_change_breaks_it(tmp_path, key):
    pem, keys = key
    doc = release.sign(_wheel(tmp_path, "0.7.0"), pem, PASS, "notes")
    assert release.verify(doc, keys)["version"] == "0.7.0"
    for field, value in (("version", "0.7.1"), ("sha256", "0" * 64), ("notes", "other")):
        bad = json.loads(json.dumps(doc))
        bad["manifest"][field] = value
        if field == "version":
            bad["manifest"]["file"] = release.wheel_name(value)
        with pytest.raises(release.ReleaseError):
            release.verify(bad, keys)


def test_untrusted_keys_and_no_keys_are_refused(tmp_path, key):
    pem, keys = key
    doc = release.sign(_wheel(tmp_path, "0.7.0"), pem, PASS)
    other_pem, other_pub = crypto.new_release_key(PASS)
    with pytest.raises(release.ReleaseError, match="doesn't trust"):
        release.verify(doc, {crypto.release_key_id(other_pub): other_pub})
    with pytest.raises(release.ReleaseError, match="no release key"):
        release.verify(doc, {})
    with pytest.raises(crypto.CryptoError):
        crypto.sign_release(pem, b"wrong passphrase!", doc["manifest"])


def test_the_file_name_must_match_the_wheels_own_version(tmp_path, key):
    w = _wheel(tmp_path, "0.7.0")
    renamed = tmp_path / release.wheel_name("0.8.0")
    renamed.write_bytes(open(w, "rb").read())
    with pytest.raises(release.ReleaseError, match="called"):
        release.make_manifest(str(renamed))


def test_manifest_fields_are_checked(tmp_path, key):
    m = release.make_manifest(_wheel(tmp_path, "0.7.0"))
    for bad in ({**m, "file": "../../evil.whl"}, {**m, "package": "other"}, {**m, "size": 0},
                {**m, "extra": 1}, {**m, "notes": "x" * 5000}):
        with pytest.raises(release.ReleaseError):
            release.check_manifest(bad)


# -- check and download ------------------------------------------------------------------

def test_check_offers_only_newer_signed_releases(tmp_path, key):
    _pem, keys = key
    offer = _offer(tmp_path, key, "0.7.0")
    info = update.check(offer, installed="0.6.0.dev24", keys=keys, problem=lambda: None)
    assert info.available and not info.required and info.latest == "0.7.0" and info.notes == "Faster approvals"
    assert "0.6.0.dev24 -> 0.7.0" in info.text()
    same = update.check(offer, installed="0.7.0", keys=keys, problem=lambda: None)
    assert not same.available and "up to date" in same.text()
    newer = update.check(offer, installed="0.8.0", keys=keys, problem=lambda: None)
    assert not newer.available                                     # never a downgrade


def test_min_supported_makes_it_required(tmp_path, key):
    _pem, keys = key
    offer = _offer(tmp_path, key, "0.7.0", min_supported="0.6.5")
    info = update.check(offer, installed="0.6.0", keys=keys, problem=lambda: None)
    assert info.required and "REQUIRED" in info.text() and "0.6.5" in info.text()


def test_a_bad_signature_is_reported_not_offered(tmp_path, key):
    _pem, keys = key
    offer = _offer(tmp_path, key)
    offer.doc["signature"] = "00" * 64
    info = update.check(offer, installed="0.6.0", keys=keys, problem=lambda: None)
    assert not info.available and "signature" in info.problem


def test_an_old_server_or_no_release_means_nothing_to_do(key):
    class Old:
        def client_release(self):
            return None
    assert not update.check(Old(), installed="0.6.0", keys=key[1]).available
    assert not update.check(Offer(None), installed="0.6.0", keys=key[1]).available


def test_download_checks_the_bytes_and_the_approved_version(tmp_path, key):
    _pem, keys = key
    offer = _offer(tmp_path, key, "0.7.0")
    info = update.check(offer, installed="0.6.0", keys=keys, problem=lambda: None)
    out = tmp_path / "updates"
    path = update.download(offer, info, keys=keys, folder=str(out), want_version="0.7.0", want_sha256=info.sha256)
    assert hashlib.sha256(open(path, "rb").read()).hexdigest() == info.sha256
    with pytest.raises(release.ReleaseError, match="changed after it was approved"):
        update.download(offer, info, keys=keys, folder=str(out), want_version="0.7.1", want_sha256=info.sha256)
    offer.data = offer.data + b"tampered"
    with pytest.raises(release.ReleaseError, match="doesn't match"):
        update.download(offer, info, keys=keys, folder=str(out))


def test_install_runs_pip_on_the_checked_wheel_in_this_environment(tmp_path):
    calls = []

    class R:
        returncode, stdout, stderr = 0, "", ""

    def run(cmd, **kw):
        calls.append(cmd)
        return R()
    msg = update.install("/tmp/aisecuritywarden-0.7.0-py3-none-any.whl", "0.7.0", run=run, windows=False)
    assert "0.7.0 is installed" in msg and "Restart" in msg
    assert calls[0][1:4] == ["-m", "pip", "install"] and calls[0][-1].endswith(".whl")

    class Fail(R):
        returncode, stderr = 1, "ERROR: no permission"
    with pytest.raises(SecurityWardenError, match="no permission"):
        update.install("/tmp/x.whl", "0.7.0", run=lambda c, **k: Fail(), windows=False)


def test_a_development_install_is_not_updated_in_place():
    # this test suite runs from `pip install -e`
    assert "development install" in (update.install_problem() or "")


# -- the MCP tools -----------------------------------------------------------------------

class FakeUpdater:
    def __init__(self, info):
        self.info, self.installed, self.checks = info, [], 0

    def check(self, client):
        self.checks += 1
        return self.info

    def download(self, client, info, *, want_version=None, want_sha256=None):
        assert (want_version, want_sha256) == (info.latest, info.sha256)
        return "/tmp/aisecuritywarden-0.7.0-py3-none-any.whl"

    def install(self, wheel, version):
        self.installed.append((wheel, version))
        return f"aiSecurityWarden {version} is installed. Restart the agent app."


def _info(**kw):
    base = dict(installed="0.6.0", latest="0.7.0", sha256="ab" * 32, file=release.wheel_name("0.7.0"),
                available=True, notes="Faster approvals")
    return update.UpdateInfo(**{**base, **kw})


def test_update_tools_only_with_an_updater():
    names = [t["name"] for t in Hub(FakeServer(), [Notes]).list_tools()]
    assert Hub.UPDATE_TOOL not in names
    names = [t["name"] for t in Hub(FakeServer(), [Notes], updater=FakeUpdater(_info())).list_tools()]
    assert Hub.CHECK_UPDATE_TOOL in names and Hub.UPDATE_TOOL in names


def test_check_update_is_read_only_and_needs_no_approval():
    server = FakeServer()
    hub = Hub(server, [Notes], updater=FakeUpdater(_info()))
    r = hub.call(Hub.CHECK_UPDATE_TOOL, {})
    assert not r.is_error and "0.6.0 -> 0.7.0" in r.text and r.data["update_available"]
    assert server.requests == {}
    assert hub.call(Hub.CHECK_UPDATE_TOOL, {"version": "9.9"}).is_error


def test_update_asks_the_owner_then_installs_exactly_the_approved_release():
    server, upd = FakeServer({"securitywarden.update": "allow"}), FakeUpdater(_info())
    hub = Hub(server, [Notes], updater=upd)
    r = hub.call(Hub.UPDATE_TOOL, {})
    assert r.data["status"] == "waiting_for_approval"            # (the stand-in server always asks for high risk)
    rid = r.data["request_id"]
    req = server.requests[rid]
    assert req["action"] == "securitywarden.update" and req["risk"] == "high"
    assert "0.7.0" in req["summary"]["title"]
    assert dict(req["summary"]["fields"])["New version"] == "0.7.0"
    assert upd.installed == []
    server.decide(rid, True)
    done = hub.call(Hub.CHECK_TOOL, {"request_id": rid})
    assert not done.is_error and "installed" in done.text
    assert upd.installed == [("/tmp/aisecuritywarden-0.7.0-py3-none-any.whl", "0.7.0")]


def test_the_agent_cant_pick_a_version_and_denied_updates_do_nothing():
    server, upd = FakeServer(), FakeUpdater(_info())
    hub = Hub(server, [Notes], updater=upd)
    assert hub.call(Hub.UPDATE_TOOL, {"version": "0.5.0"}).is_error
    rid = hub.call(Hub.UPDATE_TOOL, {}).data["request_id"]
    server.decide(rid, False)
    assert hub.call(Hub.CHECK_TOOL, {"request_id": rid}).is_error
    assert upd.installed == []


def test_nothing_to_install_or_cant_install():
    hub = Hub(FakeServer(), [Notes], updater=FakeUpdater(_info(available=False, latest="0.6.0")))
    r = hub.call(Hub.UPDATE_TOOL, {})
    assert "Nothing to install" in r.text and not hub.pending
    hub = Hub(FakeServer(), [Notes], updater=FakeUpdater(_info(problem="this is a development install")))
    r = hub.call(Hub.UPDATE_TOOL, {})
    assert r.is_error and "development install" in r.text and not hub.pending


def test_the_update_notice_is_added_once_to_a_plain_result():
    hub = Hub(FakeServer({"notes.read.note": "allow"}), [Notes], updater=FakeUpdater(_info()))
    first = hub.call("notes_read", {"id": "n1"})
    assert "client update is available (0.6.0 -> 0.7.0)" in first.text
    second = hub.call("notes_read", {"id": "n1"})
    assert "client update" not in second.text


def test_a_required_update_is_mentioned_every_time_and_a_failed_check_is_harmless():
    hub = Hub(FakeServer({"notes.read.note": "allow"}), [Notes],
              updater=FakeUpdater(_info(required=True, min_supported="0.6.5")))
    for _ in range(2):
        assert "REQUIRED" in hub.call("notes_read", {"id": "n1"}).text

    class Broken(FakeUpdater):
        def check(self, client):
            raise SecurityWardenError("GET /v1/client/latest failed (500)")
    hub = Hub(FakeServer({"notes.read.note": "allow"}), [Notes], updater=Broken(_info()))
    r = hub.call("notes_read", {"id": "n1"})
    assert not r.is_error and "client update" not in r.text


def test_waiting_results_stay_plain_json():
    hub = Hub(FakeServer(), [Notes], updater=FakeUpdater(_info()))
    r = hub.call("notes_delete", {"ids": ["n1"]})
    assert json.loads(r.text)["status"] == "waiting_for_approval"


def test_sw_mcp_update_check_from_the_command_line(tmp_path, key, capsys, monkeypatch):
    _pem, keys = key
    offer = _offer(tmp_path, key, "9.0.0")              # newer than whatever this client is
    monkeypatch.setattr(release, "TRUSTED_KEYS", keys)
    monkeypatch.setattr(update, "install_problem", lambda: None)
    assert update.run_cli(offer, check_only=True, yes=False, prog="sw-mcp") == 2
    assert "available" in capsys.readouterr().out
    installed = []
    monkeypatch.setattr(update, "install", lambda w, v: installed.append(v) or f"{v} installed")
    monkeypatch.setattr(update, "updates_dir", lambda: str(tmp_path / "u"))
    assert update.run_cli(offer, check_only=False, yes=False, prog="sw-mcp", ask=lambda q: "n") == 1
    assert update.run_cli(offer, check_only=False, yes=True, prog="sw-mcp") == 0
    assert installed == ["9.0.0"]


# -- installed while running: restart to use it ---------------------------------------------------

def test_an_update_installed_while_running_says_restart_not_available(tmp_path, key):
    _pem, keys = key
    offer = _offer(tmp_path, key, "0.7.1")
    info = update.check(offer, installed="0.7.0", keys=keys, problem=lambda: None, on_disk=lambda: "0.7.1")
    assert not info.available and info.restart_needed and not info.required
    assert info.text().startswith("aiSecurityWarden 0.7.1 is installed; restart") and "still runs 0.7.0" in info.text()
    d = info.as_dict()
    assert d["restart_needed"] and d["installed_on_disk"] == "0.7.1" and not d["update_available"]
    with pytest.raises(release.ReleaseError):
        update.download(offer, info, keys=keys, folder=str(tmp_path / "u"))
    # a still newer release is offered against what's on disk, and says a restart is pending too
    newer = _offer(tmp_path, key, "0.7.2")
    info = update.check(newer, installed="0.7.0", keys=keys, problem=lambda: None, on_disk=lambda: "0.7.1")
    assert info.available and "0.7.1 -> 0.7.2" in info.text() and "restart" in info.text()
    # an older or equal version on disk changes nothing
    info = update.check(offer, installed="0.7.0", keys=keys, problem=lambda: None, on_disk=lambda: "0.7.0")
    assert info.available and not info.restart_needed


def test_after_the_agent_installs_it_says_restart_and_doesnt_ask_again():
    server, upd = FakeServer(), FakeUpdater(_info())
    hub = Hub(server, [Notes], updater=upd)
    rid = hub.call(Hub.UPDATE_TOOL, {}).data["request_id"]
    server.decide(rid, True)
    assert "installed" in hub.call(Hub.CHECK_TOOL, {"request_id": rid}).text
    # the files on disk may not have changed yet (Windows installs once this program stops)
    r = hub.call(Hub.CHECK_UPDATE_TOOL, {})
    assert "installs when this program stops" in r.text and r.data["restart_needed"] and not r.data["update_available"]
    again = hub.call(Hub.UPDATE_TOOL, {})
    assert "already installed" in again.text and not again.is_error and len(server.requests) == 1
    assert upd.installed == [("/tmp/aisecuritywarden-0.7.0-py3-none-any.whl", "0.7.0")]
    hub2 = Hub(FakeServer({"notes.read.note": "allow"}), [Notes], updater=upd)
    hub2._update_installed = "0.7.0"
    assert "client update" not in hub2.call("notes_read", {"id": "n1"}).text     # no "update available" notice
