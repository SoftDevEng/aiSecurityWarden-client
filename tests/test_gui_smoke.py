"""swadmin's window builds and its dialogs work on this platform's Tk (macOS, Windows; Linux CI has no display
and skips). Full window tests against a real server live in the server repo (tests/test_gui.py)."""

import pytest

from securitywarden.client import SecurityWardenError, gui


@pytest.fixture(scope="module")
def root():
    tk = pytest.importorskip("tkinter")
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    r.withdraw()
    yield r
    r.destroy()


@pytest.fixture
def app(root, monkeypatch, tmp_path):
    monkeypatch.setattr(gui, "CONFIG_FILE", str(tmp_path / "admin-ui.json"))

    def refuse(url, cred):
        raise SecurityWardenError("no server in this test")

    a = gui.AdminApp(root, connect=refuse)
    yield a
    for w in root.winfo_children():
        w.destroy()


def test_the_sign_in_page_builds_and_reports_problems(app):
    assert app.sign_in("", "") == "Enter the server address and the admin credential."
    assert app.sign_in("https://vault.example.com", "sw1.a.x") == "no server in this test"


def test_the_server_address_is_remembered(app):
    gui.save_server_url("https://vault.example.com")
    assert gui.load_server_url() == "https://vault.example.com"


def test_two_factor_dialogs(app, root):
    d = gui.SetupSecondFactorDialog(app, "ABCD EFGH IJKL MNOP", "otpauth://totp/x?secret=ABCDEFGHIJKLMNOP", retry=True)
    d.var.set(" 123456 ")
    d._ok()
    assert d.code == "123456"
    s = gui.ShowOnceDialog(app, "Recovery codes", "Save these.", "aaaaa-bbbbb\nccccc-ddddd", height=2)
    root.update_idletasks()
    assert s.win.winfo_exists()
    s.win.destroy()
