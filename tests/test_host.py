"""sw-mcp names the program that runs it, so an update tells the user exactly what to restart."""

import os

import pytest
from test_mcp import FakeServer, Notes
from test_update import FakeUpdater, _info

from securitywarden.mcp import host
from securitywarden.mcp.framework import Hub


def _tree(monkeypatch, procs, services=None):
    """procs: pid -> (ppid, argv). The first parent is the first key."""
    first = next(iter(procs))
    monkeypatch.setattr(host.os, "getppid", lambda: first)
    monkeypatch.setattr(host, "_proc", lambda pid: procs.get(pid))
    monkeypatch.setattr(host, "_service", lambda pid: (services or {}).get(pid))


HERMES = ["/home/jarvis/.venv/bin/python3", "/home/jarvis/.local/bin/hermes", "dashboard", "--host",
          "100.82.80.17", "--port", "9119"]


def test_shells_and_launchers_are_skipped_up_to_the_real_program(monkeypatch):
    _tree(monkeypatch, {
        900: (800, ["/bin/sh", "-c", "sw-mcp serve --connector gmail"]),
        800: (700, ["/usr/bin/env", "sw-mcp"]),
        700: (284805, ["/home/jarvis/.local/share/pipx/venvs/aisecuritywarden/bin/python", "/home/jarvis/.local/bin/sw-mcp"]),
        284805: (1, HERMES),
    })
    h = host.agent_host()
    assert h["pid"] == 284805 and h["command"].startswith("/home/jarvis/.venv/bin/python3 /home/jarvis/.local/bin/hermes dashboard")


def test_the_advice_names_the_host_its_service_and_hermes_cache(monkeypatch):
    _tree(monkeypatch, {500: (1, HERMES)}, {500: "hermes-dashboard.service (user service)"})
    text = host.restart_advice()
    assert "PID 500" in text and "hermes dashboard --host 100.82.80.17 --port 9119" in text
    assert "systemctl --user restart hermes-dashboard.service" in text
    assert "mcp_schema_cache.json" in text
    assert "don't kill, restart or relaunch" in text and "don't write scripts" in text


def test_secrets_on_the_command_line_are_hidden(monkeypatch):
    _tree(monkeypatch, {500: (1, ["node", "app.js", "--api-key=sk-123", "--token", "abc", "--port", "1"])})
    cmd = host.agent_host()["command"]
    assert "sk-123" not in cmd and "abc" not in cmd and "--port 1" in cmd


def test_unknown_host_still_gives_the_rule(monkeypatch):
    _tree(monkeypatch, {500: (1, ["/bin/bash"])})
    assert host.agent_host() is None
    text = host.restart_advice()
    assert "gateway or dashboard" in text and "don't write scripts" in text


def test_a_broken_process_table_never_breaks_an_update(monkeypatch):
    monkeypatch.setattr(host.os, "getppid", lambda: 5)
    monkeypatch.setattr(host, "_proc", lambda pid: (_ for _ in ()).throw(PermissionError()))
    assert host.agent_host() is None


@pytest.mark.skipif(not os.path.isdir("/proc/self"), reason="Linux /proc")
def test_real_process_table_is_readable():
    ppid, argv = host._proc(os.getpid())
    assert ppid == os.getppid() and argv


def test_the_update_result_tells_the_agent_what_to_relay_and_to_stop(monkeypatch):
    _tree(monkeypatch, {500: (1, HERMES)})
    server, upd = FakeServer({"securitywarden.update": "allow"}), FakeUpdater(_info())
    hub = Hub(server, [Notes], updater=upd)
    rid = hub.call(Hub.UPDATE_TOOL, {}).data["request_id"]
    server.decide(rid, True)
    done = hub.call(Hub.CHECK_TOOL, {"request_id": rid})
    assert "0.7.0 is installed" in done.text and "hermes dashboard" in done.text and "PID 500" in done.text
    assert "don't kill, restart or relaunch" in done.text
    again = hub.call(Hub.UPDATE_TOOL, {})
    assert "Nothing to install" in again.text and "hermes dashboard" in again.text
