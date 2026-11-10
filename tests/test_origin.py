"""What started a client, as shown on its session request: names only, never paths or other arguments."""
from securitywarden.client.origin import ancestry, label


def test_labels_are_names_only():
    assert label(["/home/j/.venv/bin/python", "/home/j/.hermes/bin/hermes", "gateway", "run"]) == "hermes gateway"
    assert label(["python3", "-c", "import os; print(os.environ['SECRET'])"]) == "python3 -c"
    assert label(["/usr/bin/python3.14", "-u", "-m", "pkg.tool", "--token=abc"]) == "python3.14 -m pkg.tool"
    assert label(["/bin/bash", "-lc", "echo hi"]) == "bash -c"
    assert label(["/bin/bash", "-l"]) == "bash"
    assert label(["node", "x y z"]) == "node"
    assert label(["bash", "-c", "x"]) == "bash -c"
    assert label(["C:\\Program Files\\Claude\\Claude.exe", "--type=renderer"]) == "Claude"
    assert label(["/usr/lib/systemd/systemd", "--user"]) == "systemd"
    assert label(["node", "/opt/app/server.js", "--key", "s3cret"]) == "server.js"
    assert label(["hermes", "chat"]) == "hermes chat"
    assert label(["tool", "/etc/secret/path"]) == "tool"
    assert label([]) == ""


def test_ancestry_walks_up_from_the_parent():
    procs = {50: (40, ["python3", "-c", "code"]), 40: (30, ["bash"]), 30: (1, ["python", "/x/hermes", "gateway"]),
             1: (0, ["/sbin/init"])}
    assert ancestry(50, lookup=procs.get) == ["python3 -c", "bash", "hermes gateway"]
    assert ancestry(30, lookup=procs.get) == ["hermes gateway", "init"]
    assert ancestry(99, lookup=procs.get) == []


def test_ancestry_never_raises():
    def boom(pid):
        raise RuntimeError("no")
    assert ancestry(5, lookup=boom) == []
