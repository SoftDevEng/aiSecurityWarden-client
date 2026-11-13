"""sw-sudo: root commands for an AI agent, one exact command at a time, with human approval (Linux).

The agent runs as a limited user. It never gets the root password; instead it runs

    sudo sw-sudo -- apt install -y ffmpeg

``sudo`` runs this helper as root (one sudoers line written by ``sw-sudo install``). The helper checks who called it
and what the command is, asks aiSecurityWarden with its own machine token (``system.run``, the exact command's
digest), waits for the owner's decision under the token's action rules, re-checks the command and runs it once, with
no shell and a clean environment. The helper's token sits in a root-only file the agent can't read.

Design: project doc SecurityWarden-privileged-commands.md. Guards (refused before anything is asked):

- the caller must be the configured agent user (``SUDO_UID``, set by sudo, not by the caller);
- shells, interpreters, editors, pagers and other programs that run arbitrary commands are refused (a person
  approving ``bash -c ...`` would be handing over root), as are user and sudo management programs;
- a program, or any argument naming a file, that the agent user could change is refused (approving
  ``/home/hermes/fix.sh`` would approve whatever the file says when it runs);
- known option tricks that run commands (``apt -o``, ``find -exec``, ``tar --to-command`` ...) are refused;
- arguments naming the helper's own files, sudoers, passwd/shadow/group are refused;
- the program's identity (device, inode, size, mtime) is part of the approved digest and checked again just before
  it runs; the environment is clean, the working directory is ``/``, stdin is empty, output is capped and the
  command has a time limit.

These reduce what one approval can turn into, but approving a command still approves what that command does as
root: read it.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from . import crypto

try:
    import pwd
except ImportError:          # Windows: sw-sudo is Linux only (main() says so)
    pwd = None  # type: ignore[assignment]

ACTION = "system.run"
CONFIG_DIR = "/etc/securitywarden"
CONFIG_PATH = os.path.join(CONFIG_DIR, "sw-sudo.json")
TOKEN_PATH = os.path.join(CONFIG_DIR, "sw-sudo.token")
SUDOERS_PATH = "/etc/sudoers.d/securitywarden"
STATE_DIR = "/var/lib/securitywarden/sw-sudo"      # requests waiting for a decision (--no-wait), root only
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# exit codes (besides the command's own)
EXIT_REFUSED, EXIT_DENIED, EXIT_TIMEOUT, EXIT_PENDING = 125, 126, 124, 75

# Programs that run arbitrary commands, or hand over root some other way. Matched on the resolved program's file
# name, with any version suffix stripped (python3.12 -> python). An owner can allow one by its full path in
# allow_programs (sw-sudo.json), knowingly.
SHELL_EQUIVALENTS = frozenset("""
sh bash dash zsh ksh mksh csh tcsh fish ash busybox toybox rbash yash
python python2 python3 pypy pypy3 perl ruby irb node nodejs deno bun php lua luajit tclsh wish expect guile
gawk awk mawk nawk gdb lldb strace ltrace valgrind
env sudo su doas pkexec runuser setpriv nsenter unshare chroot sg newgrp setsid nohup nice ionice taskset
chrt stdbuf timeout xargs parallel watch flock script screen tmux byobu ssh scp sftp ssh-agent
vi vim nvim view vimdiff rvim ex ed nano pico emacs emacsclient joe micro mcedit
less more most pg man info
docker podman nerdctl ctr crictl kubectl lxc lxd systemd-run systemd-nspawn machinectl
git make cmake ninja crontab at batch
""".split())

# User, group and sudo management: one approval here can make the agent root for good.
ACCOUNT_PROGRAMS = frozenset("""
visudo sudoedit passwd chpasswd chage useradd usermod userdel adduser deluser addgroup delgroup
groupadd groupmod groupdel gpasswd vipw vigr pwck grpck newusers chsh chfn
""".split())

# Options that make an otherwise ordinary program run commands (GTFOBins). Program -> option prefixes refused.
DANGEROUS_OPTIONS: dict[str, tuple[str, ...]] = {
    "apt": ("-o", "--option", "-c", "--config-file"),
    "apt-get": ("-o", "--option", "-c", "--config-file"),
    "apt-cache": ("-o", "--option", "-c", "--config-file"),
    "dpkg": ("--admindir", "--instdir", "--root", "--force-script-chrootless"),
    "find": ("-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls"),
    "tar": ("--to-command", "--checkpoint-action", "-I", "--use-compress-program", "--info-script",
            "--new-volume-script", "-F", "--rsh-command"),
    "rsync": ("-e", "--rsh", "--rsync-path"),
    "zip": ("-T", "-TT", "--unzip-command"),
    "sed": ("-i", "--in-place"),                 # 'e' commands and in-place writes to anything
    "systemctl": ("edit",),
    "journalctl": ("--pager", "-e"),
    "mount": ("-o",),
}

# Arguments naming these (or anything under them) are refused: they'd let one approval undo the set-up.
PROTECTED_PATHS = ("/etc/sudoers", "/etc/sudoers.d", CONFIG_DIR, "/etc/passwd", "/etc/shadow", "/etc/group",
                   "/etc/gshadow", STATE_DIR, "/root/.ssh", "/etc/pam.d", "/etc/security")

DEFAULT_CONFIG: dict[str, Any] = {
    "server": None, "agent_user": None, "agent_uid": None, "token_file": TOKEN_PATH,
    "command_timeout": 600,       # seconds a command may run
    "wait": 900,                  # seconds to wait for a decision before giving up (the request stays open)
    "max_output": 1024 * 1024,    # bytes of stdout and of stderr passed back
    "allow_programs": [],         # full paths allowed despite the shell-equivalent list (owner's choice)
    "exe": None,                  # the sw-sudo the sudoers line names (for sw-mcp's system_run tool)
    "shim": None,                 # the sudo shim's folder, if installed (install --sudo-shim)
}
SHIM_DIR = "/usr/local/lib/securitywarden/bin"


class Refused(Exception):
    """A guard refused the command before anything was asked."""


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

def load_config(path: str = CONFIG_PATH) -> dict[str, Any]:
    try:
        st = os.lstat(path)
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raise Refused(f"sw-sudo isn't set up on this machine ({path} is missing); run: sudo sw-sudo install") from None
    except (OSError, ValueError) as e:
        raise Refused(f"can't read {path}: {e}") from None
    if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or not stat.S_ISREG(st.st_mode):
        raise Refused(f"{path} must be a regular file owned by root and writable only by root")
    if not isinstance(raw, dict) or set(raw) - set(DEFAULT_CONFIG):
        raise Refused(f"{path}: unknown settings")
    cfg = {**DEFAULT_CONFIG, **raw}
    if not isinstance(cfg["agent_uid"], int) or not cfg["server"]:
        raise Refused(f"{path} needs server and agent_uid; run: sudo sw-sudo install")
    return cfg


# ---------------------------------------------------------------------------
# guards
# ---------------------------------------------------------------------------

@dataclass
class Agent:
    """Who must not be able to change what runs."""
    uid: int
    gids: frozenset[int] = field(default_factory=frozenset)

    @classmethod
    def of(cls, uid: int) -> "Agent":
        try:
            pw = pwd.getpwuid(uid)
            gids = set(os.getgrouplist(pw.pw_name, pw.pw_gid))
        except KeyError:
            gids = set()
        return cls(uid, frozenset(gids))

    def can_write(self, st: os.stat_result) -> bool:
        m = st.st_mode
        if st.st_uid == self.uid:
            return True
        if m & stat.S_IWGRP and st.st_gid in self.gids:
            return True
        return bool(m & stat.S_IWOTH)       # world-writable, sticky or not (/tmp): refused


def agent_can_change(path: str, agent: Agent) -> str | None:
    """Why the agent could change what ``path`` is (the file, a symlink on the way, or any folder above it), or
    None. A sticky world-writable folder (/tmp) still lets the agent create files there: refused too."""
    p = os.path.abspath(path)
    seen = set()
    while True:
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            st = None
        if st is not None:
            if agent.can_write(st):
                return f"{p} can be changed by the agent's user"
            if stat.S_ISLNK(st.st_mode):
                target = os.path.join(os.path.dirname(p), os.readlink(p))
                if target in seen:
                    return f"{p}: symlink loop"
                seen.add(target)
                why = agent_can_change(target, agent)
                if why:
                    return why
        parent = os.path.dirname(p)
        if parent == p:
            return None
        p = parent


def resolve_program(name: str) -> str:
    if not name:
        raise Refused("no command given")
    if "/" in name:
        cand = os.path.abspath(name)
    else:
        cand = None
        for d in SAFE_PATH.split(":"):
            q = os.path.join(d, name)
            if os.path.isfile(q) and os.access(q, os.X_OK):
                cand = q
                break
        if cand is None:
            raise Refused(f"{name}: not found in {SAFE_PATH}")
    real = os.path.realpath(cand)
    if not os.path.isfile(real) or not os.access(real, os.X_OK):
        raise Refused(f"{cand} isn't an executable file")
    return real


def _base(name: str) -> str:
    b = os.path.basename(name)
    stripped = b.rstrip("0123456789.")
    return stripped or b


def file_identity(path: str) -> dict[str, int]:
    st = os.stat(path)
    return {"dev": st.st_dev, "ino": st.st_ino, "size": st.st_size, "mtime_ns": st.st_mtime_ns}


def _shell_identities() -> set[tuple[int, int]]:
    """Known shells by file identity, so a renamed copy or a hard link of bash is still a shell."""
    names = set()
    try:
        with open("/etc/shells", encoding="utf-8") as f:
            names.update(line.strip() for line in f if line.strip().startswith("/"))
    except OSError:
        pass
    for d in SAFE_PATH.split(":"):
        for n in ("sh", "bash", "dash", "zsh", "ksh", "busybox", "python3", "perl"):
            names.add(os.path.join(d, n))
    out = set()
    for n in names:
        try:
            st = os.stat(n)
            out.add((st.st_dev, st.st_ino))
        except OSError:
            pass
    return out


def check_command(argv: list[str], agent: Agent, allow_programs: list[str] | tuple[str, ...] = ()) -> str:
    """Raise Refused, or return the resolved program path."""
    if not argv:
        raise Refused("no command given (sudo sw-sudo -- COMMAND ARGS...)")
    if any("\x00" in a or "\n" in a or "\r" in a for a in argv):
        raise Refused("arguments may not contain line breaks or NUL")
    if len(argv) > 64 or sum(len(a) for a in argv) > 4000:
        raise Refused("command too long (64 arguments, 4000 characters)")
    real = resolve_program(argv[0])
    allowed = real in set(allow_programs)
    names = {_base(argv[0]), _base(real), os.path.basename(real)}
    if not allowed:
        if names & ACCOUNT_PROGRAMS:
            raise Refused(f"{os.path.basename(real)} manages users, groups or sudo: one approval could make the agent "
                          "root for good. Do this yourself on the machine.")
        if names & SHELL_EQUIVALENTS:
            raise Refused(f"{os.path.basename(real)} runs other commands (approving it would hand over root). Ask for "
                          "the exact command instead")
        st = os.stat(real)
        if (st.st_dev, st.st_ino) in _shell_identities():
            raise Refused(f"{real} is a shell (a copy or link of one)")
    why = agent_can_change(real, agent)
    if why:
        raise Refused(f"the program can be changed by the agent ({why})")
    prog = _base(real)
    bad = DANGEROUS_OPTIONS.get(prog, ())
    for a in argv[1:]:
        for opt in bad:
            if a == opt or (opt.startswith("--") and a.startswith(opt + "=")) or \
                    (len(opt) == 2 and opt.startswith("-") and a.startswith(opt) and not a.startswith("--")):
                raise Refused(f"{prog} {opt} can run other commands or write anywhere; not allowed through sw-sudo")
        for cand in _paths_in(a):
            ap = os.path.abspath(cand)
            for prot in PROTECTED_PATHS:
                if ap == prot or ap.startswith(prot.rstrip("/") + "/"):
                    raise Refused(f"{ap} is protected (sudo, accounts or sw-sudo's own files)")
            if os.path.lexists(ap):
                why = agent_can_change(ap, agent)
                if why:
                    raise Refused(f"an argument names a file the agent can change ({why})")
    return real


def _paths_in(arg: str) -> list[str]:
    """Things in an argument that look like file paths: the argument, or the value of --opt=/path."""
    out = []
    if arg.startswith("/") or arg.startswith("./") or arg.startswith("../") or arg.startswith("~"):
        out.append(os.path.expanduser(arg))
    if arg.startswith("-") and "=" in arg:
        v = arg.split("=", 1)[1]
        if v.startswith("/"):
            out.append(v)
    return out


# ---------------------------------------------------------------------------
# what is asked
# ---------------------------------------------------------------------------

def command_scope(argv: list[str], real: str) -> dict[str, str]:
    """For rules by argument: ``program`` (/usr/bin/apt, rules like [program=/usr/bin/*]) and ``cmd``: the program
    name and arguments joined by "/" (slashes inside an argument encoded), so ``[cmd=apt/install/*]`` matches any
    ``apt install ...`` and ``[cmd=apt/update]`` exactly ``apt update``."""
    enc = [a.replace("%", "%25").replace("/", "%2F") for a in argv[1:]]
    cmd = "/".join([os.path.basename(real)] + enc)
    return {"program": real, "cmd": cmd[:300]}


def request_args(argv: list[str], real: str, host: str, user: str) -> dict[str, Any]:
    """Exactly what is approved: the digest covers all of it, including the program file's identity."""
    return {"argv": argv, "program": real, "file": file_identity(real), "host": host, "user": user, "cwd": "/",
            "env": "clean"}


def summary_for(argv: list[str], real: str, host: str, user: str, reason: str | None) -> dict[str, Any]:
    line = shlex.join(argv)
    fields = [["Command", line[:300]], ["Program", real], ["Machine", host], ["Asked by", user]]
    if reason:
        fields.append(["Agent says", reason[:200]])
    return {"title": f"Run as root on {host}: {line[:120]}", "fields": fields}


# ---------------------------------------------------------------------------
# running
# ---------------------------------------------------------------------------

def clean_env() -> dict[str, str]:
    return {"PATH": SAFE_PATH, "HOME": "/root", "USER": "root", "LOGNAME": "root", "SHELL": "/bin/false",
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "dumb", "PAGER": "cat", "SYSTEMD_PAGER": "",
            "SYSTEMD_PAGERSECURE": "1", "GIT_PAGER": "cat", "DEBIAN_FRONTEND": "noninteractive",
            "NEEDRESTART_MODE": "a"}


def run_command(argv: list[str], real: str, timeout: int, max_output: int) -> tuple[int, bytes, bytes, bool]:
    """(exit code, stdout, stderr, cut off). No shell; argv[0] replaced by the resolved path."""
    try:
        p = subprocess.run([real, *argv[1:]], cwd="/", env=clean_env(), stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, close_fds=True)
    except subprocess.TimeoutExpired as e:
        out, err = (e.stdout or b""), (e.stderr or b"")
        return EXIT_TIMEOUT, out[:max_output], err[:max_output] + f"\nsw-sudo: stopped after {timeout} s\n".encode(), True
    cut = len(p.stdout) > max_output or len(p.stderr) > max_output
    return p.returncode, p.stdout[:max_output], p.stderr[:max_output], cut


@dataclass
class Context:
    """Everything the run depends on, so tests can supply their own."""
    euid: int
    sudo_uid: str | None
    config: dict[str, Any]
    client_factory: Callable[[dict[str, Any]], Any]
    host: str = field(default_factory=socket.gethostname)
    out: Any = sys.stdout
    err: Any = sys.stderr
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    state_dir: str = STATE_DIR
    json_out: bool = False       # --json: one JSON object on stdout instead of text (for sw-mcp's system_run)


def _emit(ctx: Context, status: str, code: int, **data: Any) -> int:
    """In --json mode: the outcome as one JSON line on stdout. Returns the exit code either way."""
    if ctx.json_out:
        print(json.dumps({"status": status, **data}), file=ctx.out)
    return code


def _client(cfg: dict[str, Any]) -> Any:
    from .client.api import SecurityWardenClient
    with open(cfg["token_file"], encoding="utf-8") as f:
        cred = crypto.parse_credential(f.read())
    return SecurityWardenClient(cfg["server"], cred, wait_for_approval=True)


def _caller(ctx: Context) -> tuple[Agent, str]:
    if ctx.euid != 0:
        raise Refused("run it through sudo: sudo sw-sudo -- COMMAND ARGS...")
    if ctx.sudo_uid is None or not ctx.sudo_uid.isdigit():
        raise Refused("only the agent's user may use sw-sudo, through sudo")
    uid = int(ctx.sudo_uid)
    if uid != ctx.config["agent_uid"]:
        raise Refused("only the configured agent user may use sw-sudo")
    try:
        name = pwd.getpwuid(uid).pw_name
    except KeyError:
        name = str(uid)
    return Agent.of(uid), name


def _write_out(ctx: Context, code: int, out: bytes, err: bytes, cut: bool) -> int:
    ctx.out.buffer.write(out) if hasattr(ctx.out, "buffer") else ctx.out.write(out.decode(errors="replace"))
    ctx.err.buffer.write(err) if hasattr(ctx.err, "buffer") else ctx.err.write(err.decode(errors="replace"))
    if cut:
        print(f"sw-sudo: output cut at {ctx.config['max_output']} bytes", file=ctx.err)
    return code


def _pending_path(ctx: Context, rid: str) -> str:
    if not crypto.ID_RE.match(rid or ""):
        raise Refused("not a request id")
    return os.path.join(ctx.state_dir, rid + ".json")


def _save_pending(ctx: Context, rid: str, data: dict[str, Any]) -> None:
    os.makedirs(ctx.state_dir, mode=0o700, exist_ok=True)
    os.chmod(ctx.state_dir, 0o700)
    fd = os.open(_pending_path(ctx, rid), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)


def run(argv: list[str], ctx: Context, *, wait: bool = True, reason: str | None = None) -> int:
    from .client.api import ApprovalError
    try:
        agent, user = _caller(ctx)
        real = check_command(argv, agent, ctx.config.get("allow_programs") or ())
    except Refused as e:
        print(f"sw-sudo: refused: {e}", file=ctx.err)
        return _emit(ctx, "refused", EXIT_REFUSED, reason=str(e))
    args = request_args(argv, real, ctx.host, user)
    client = ctx.client_factory(ctx.config)
    try:
        req = client.request_action(ACTION, args, summary_for(argv, real, ctx.host, user, reason), risk="high",
                                    scope=command_scope(argv, real))
    except ApprovalError as e:
        print(f"sw-sudo: denied by the token's rules ({e})", file=ctx.err)
        return _emit(ctx, "denied", EXIT_DENIED, reason="the owner's rules deny this command")
    if req["status"] == "pending":
        _save_pending(ctx, req["request_id"], {"argv": argv, "real": real, "args": args, "nonce": req["nonce"],
                                               "digest": req["digest"]})
        if not wait:
            print(f"sw-sudo: waiting for approval (match code {req['match']}). Check later with: "
                  f"sudo sw-sudo --status {req['request_id']}", file=ctx.err)
            return _emit(ctx, "waiting_for_approval", EXIT_PENDING, request_id=req["request_id"], match=req["match"],
                         check_after=int(req.get("check_after") or 15))
        print(f"sw-sudo: waiting for approval (match code {req['match']})", file=ctx.err)
        status = _wait(client, req, ctx)
        if status != "approved":
            return status
        _drop_pending(ctx, req["request_id"])
    return _execute(argv, real, args, req["digest"], ctx)


def _drop_pending(ctx: Context, rid: str) -> None:
    try:
        os.remove(_pending_path(ctx, rid))
    except OSError:
        pass


def _wait(client: Any, req: dict[str, Any], ctx: Context) -> Any:
    from .client.api import ApprovalError
    end = ctx.clock() + ctx.config["wait"]
    while True:
        ctx.sleep(max(2.0, min(float(req.get("check_after") or 5), 15.0)))
        try:
            if client.check_action(req["request_id"], req["nonce"], req["digest"]) == "approved":
                return "approved"
        except ApprovalError as e:
            _drop_pending(ctx, req["request_id"])
            return _denied(e, ctx)
        if ctx.clock() > end:
            print(f"sw-sudo: no decision yet; still open. Check later with: sudo sw-sudo --status "
                  f"{req['request_id']}", file=ctx.err)
            return _emit(ctx, "waiting_for_approval", EXIT_PENDING, request_id=req["request_id"],
                         match=req.get("match"), check_after=15)


def _denied(e: Exception, ctx: Context) -> int:
    comment = getattr(e, "comment", None)
    print(f"sw-sudo: not approved ({e})" + (f": {comment}" if comment else ""), file=ctx.err)
    return _emit(ctx, "denied", EXIT_DENIED, reason=str(getattr(e, "reason", e)), comment=comment)


def _execute(argv: list[str], real: str, args: dict[str, Any], digest: str, ctx: Context) -> int:
    """Re-check everything just before running: the program must be the same file and still pass the guards."""
    try:
        agent, user = _caller(ctx)
        again = check_command(argv, agent, ctx.config.get("allow_programs") or ())
        now_args = request_args(argv, again, ctx.host, user)
    except (Refused, OSError) as e:
        print(f"sw-sudo: refused after approval: {e}", file=ctx.err)
        return _emit(ctx, "refused", EXIT_REFUSED, reason=f"after approval: {e}")
    if again != real or crypto.action_digest(ACTION, now_args) != digest:
        print("sw-sudo: refused: the command or the program file changed after it was approved", file=ctx.err)
        return _emit(ctx, "refused", EXIT_REFUSED, reason="the command or the program file changed after it was approved")
    code, out, err, cut = run_command(argv, real, int(ctx.config["command_timeout"]), int(ctx.config["max_output"]))
    if ctx.json_out:
        return _emit(ctx, "done", code, exit_code=code, stdout=out.decode("utf-8", "replace"),
                     stderr=err.decode("utf-8", "replace"), cut=cut)
    return _write_out(ctx, code, out, err, cut)


def status(rid: str, ctx: Context) -> int:
    """For a request left waiting (--no-wait, or the wait ran out): run it if it was approved since."""
    from .client.api import ApprovalError
    try:
        _caller(ctx)
        path = _pending_path(ctx, rid)
        with open(path, encoding="utf-8") as f:
            p = json.load(f)
    except (Refused, OSError, ValueError) as e:
        print(f"sw-sudo: {e}", file=ctx.err)
        return _emit(ctx, "unknown", EXIT_REFUSED, reason="no request waiting with that id (finished, or never asked)")
    client = ctx.client_factory(ctx.config)
    try:
        st = client.check_action(rid, p["nonce"], p["digest"])
    except ApprovalError as e:
        os.remove(path)
        return _denied(e, ctx)
    if st != "approved":
        print("sw-sudo: still waiting for approval", file=ctx.err)
        return _emit(ctx, "waiting_for_approval", EXIT_PENDING, request_id=rid, check_after=15)
    os.remove(path)
    return _execute(p["argv"], p["real"], p["args"], p["digest"], ctx)


# ---------------------------------------------------------------------------
# set-up
# ---------------------------------------------------------------------------

SUGGESTED_RULES = (
    "system.run[cmd=apt/update]=allow",
    "system.run[cmd=apt-get/update]=allow",
    "system.run[cmd=systemctl/status/*]=allow",
    "system.run[cmd=systemctl/restart/*]=each",
    "system.run[cmd=apt/install/*]=each",
    "system.run=each",
)


def self_path() -> str:
    found = sys.argv[0] if os.path.isabs(sys.argv[0]) else (shutil.which(sys.argv[0]) or sys.argv[0])
    return os.path.realpath(found)


def check_installation(agent: Agent, exe: str) -> list[str]:
    """Problems that would let the agent change what runs as root: this program, its Python, its packages."""
    import securitywarden
    problems = []
    for p in {exe, os.path.realpath(sys.executable), os.path.dirname(os.path.realpath(securitywarden.__file__)),
              os.path.dirname(os.path.realpath(crypto.__file__))}:
        why = agent_can_change(p, agent)
        if why:
            problems.append(why)
    return sorted(set(problems))


def shim_script(exe: str) -> str:
    """A ``sudo`` for the agent's PATH: plain ``sudo CMD`` becomes ``sudo sw-sudo -- CMD`` (an approval request).
    A convenience, not a boundary: the real sudo refuses the agent anything but sw-sudo anyway."""
    q = shlex.quote(exe)
    return f"""#!/bin/sh
# aiSecurityWarden: "sudo COMMAND" from the AI agent becomes "sudo sw-sudo -- COMMAND", which asks the owner to
# approve that exact command. Installed by: sw-sudo install --sudo-shim. The agent has no other sudo rights.
if [ "$1" = "--" ]; then shift; fi
case "$1" in
  "") echo "usage: sudo COMMAND ARGS...  (each command waits for the owner's approval through aiSecurityWarden)" >&2
      exit {EXIT_REFUSED} ;;
  sw-sudo|{q}) shift; exec /usr/bin/sudo {q} "$@" ;;
  -*) echo "sudo: $1 isn't available to this agent (no other users, shells or editors as root)." >&2
      echo "For a root command, use: sudo COMMAND ARGS...  or  sudo sw-sudo --reason 'why' -- COMMAND ARGS..." >&2
      exit {EXIT_REFUSED} ;;
esac
exec /usr/bin/sudo {q} -- "$@"
"""


def install_shim(exe: str, folder: str = SHIM_DIR) -> str:
    os.makedirs(folder, mode=0o755, exist_ok=True)
    for d in (folder, os.path.dirname(folder)):
        os.chown(d, 0, 0)
        os.chmod(d, 0o755)
    path = os.path.join(folder, "sudo")
    _write_root_file(path, shim_script(exe), 0o755)
    return path


def install(agent_user: str, server: str, *, read_code: Callable[[], str] = lambda: getpass.getpass(
        "One-time setup code from the website (Tokens → the sw-sudo token → Set up): "),
            exe: str | None = None, run_visudo: Callable[[str], bool] | None = None,
            out: Any = sys.stdout, sudo_shim: bool = False) -> int:
    from .client.setup import setup_from_code
    if os.geteuid() != 0:
        print("sw-sudo install must run as root (sudo sw-sudo install ...)", file=sys.stderr)
        return EXIT_REFUSED
    try:
        pw = pwd.getpwnam(agent_user)
    except KeyError:
        print(f"no user {agent_user!r} on this machine", file=sys.stderr)
        return EXIT_REFUSED
    if pw.pw_uid == 0:
        print("the agent user must not be root: run the agent as its own limited user", file=sys.stderr)
        return EXIT_REFUSED
    agent = Agent.of(pw.pw_uid)
    exe = exe or self_path()
    problems = check_installation(agent, exe)
    if problems:
        print("sw-sudo: refused: the agent's user could change sw-sudo itself, which then runs as root:\n  "
              + "\n  ".join(problems) + "\nInstall aiSecurityWarden for root, e.g. sudo pipx install --global "
              "aisecuritywarden (or a root-owned venv in /opt), and run that sw-sudo.", file=sys.stderr)
        return EXIT_REFUSED
    os.makedirs(CONFIG_DIR, mode=0o755, exist_ok=True)
    try:
        cred, path = setup_from_code(server, read_code().strip(), TOKEN_PATH, replace=os.path.exists(TOKEN_PATH))
    except Exception as e:  # noqa: BLE001 (shown, not logged)
        print(f"sw-sudo: the setup code didn't work: {e}", file=sys.stderr)
        return EXIT_REFUSED
    os.chown(path, 0, 0)
    os.chmod(path, 0o600)
    cfg = {**DEFAULT_CONFIG, "server": server, "agent_user": agent_user, "agent_uid": pw.pw_uid, "token_file": path,
           "exe": exe, "shim": SHIM_DIR if sudo_shim else None}
    _write_root_file(CONFIG_PATH, json.dumps(cfg, indent=1) + "\n", 0o644)
    line = f"# aiSecurityWarden: the agent asks for root one command at a time (sw-sudo)\n" \
           f"{agent_user} ALL=(root) NOPASSWD: {exe}\n"
    tmp = SUDOERS_PATH + ".tmp"
    _write_root_file(tmp, line, 0o440)
    ok = (run_visudo or (lambda p: subprocess.run(["visudo", "-cf", p], capture_output=True).returncode == 0))(tmp)
    if not ok:
        os.remove(tmp)
        print("sw-sudo: visudo refused the sudoers line; nothing changed in sudoers", file=sys.stderr)
        return EXIT_REFUSED
    os.replace(tmp, SUDOERS_PATH)
    shim_note = ""
    if sudo_shim:
        shim = install_shim(exe)
        why = agent_can_change(shim, agent)
        if why:
            print(f"sw-sudo: the sudo shim can be changed by the agent ({why}); remove it", file=sys.stderr)
        shim_note = (f"\n\nsudo shim: {shim}. Put {SHIM_DIR} first in the agent's PATH, in its service settings,\n"
                     f"e.g. for a systemd service: Environment=PATH={SHIM_DIR}:/usr/local/bin:/usr/bin:/bin\n"
                     f"Then a plain 'sudo COMMAND' from the agent asks for approval too.")
    print(f"Set up. {agent_user} can now run: sudo sw-sudo -- COMMAND ARGS...\n"
          f"Token {cred.id} stored in {path} (root only).\n\n"
          "On the website, for this token: turn session approval off (it reads no secrets; every command is\n"
          "approved by its action rules) and add rules like these (first match wins):\n  "
          + "\n  ".join(SUGGESTED_RULES)
          + f"\n\nCheck that {agent_user} has no other sudo rights (sudo -l -U {agent_user}).\n"
          "The agent's aiSecurityWarden MCP connection (sw-mcp) now offers it a system_run tool for root commands;\n"
          "restart the agent so it sees it." + shim_note, file=out)
    return 0


def _write_root_file(path: str, text: str, mode: int) -> None:
    fd = os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chown(path + ".new", 0, 0)
    os.chmod(path + ".new", mode)
    os.replace(path + ".new", path)


def uninstall() -> int:
    if os.geteuid() != 0:
        print("sw-sudo uninstall must run as root", file=sys.stderr)
        return EXIT_REFUSED
    for p in (SUDOERS_PATH, CONFIG_PATH, TOKEN_PATH, os.path.join(SHIM_DIR, "sudo")):
        try:
            os.remove(p)
            print(f"removed {p}")
        except FileNotFoundError:
            pass
    print("Revoke the sw-sudo token on the website too.")
    return 0


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if sys.platform != "linux":
        print("sw-sudo is for Linux (Windows: sw-elevate, planned)", file=sys.stderr)
        return EXIT_REFUSED
    if argv[:1] == ["install"]:
        p = argparse.ArgumentParser(prog="sw-sudo install", description="Set sw-sudo up (as root).")
        p.add_argument("--agent-user", required=True, help="the limited user the AI agent runs as")
        p.add_argument("--server", default="https://app.aisecuritywarden.com")
        p.add_argument("--sudo-shim", action="store_true",
                       help=f"also install a 'sudo' in {SHIM_DIR} that turns plain 'sudo COMMAND' into sw-sudo")
        a = p.parse_args(argv[1:])
        return install(a.agent_user, a.server, sudo_shim=a.sudo_shim)
    if argv[:1] == ["uninstall"]:
        return uninstall()
    p = argparse.ArgumentParser(
        prog="sw-sudo", usage="sudo sw-sudo [--no-wait] [--reason TEXT] -- COMMAND ARGS...\n"
                              "       sudo sw-sudo --status REQUEST_ID\n       sudo sw-sudo check -- COMMAND ARGS...\n"
                              "       sudo sw-sudo install --agent-user USER [--server URL] [--sudo-shim]",
        description="Run one command as root after a person approves it in aiSecurityWarden.")
    p.add_argument("--no-wait", action="store_true", help="ask and return at once (exit 75 while waiting)")
    p.add_argument("--reason", help="a short note shown to the person deciding (why the agent needs it)")
    p.add_argument("--status", metavar="REQUEST_ID", help="run a request left waiting, if it was approved since")
    p.add_argument("--json", action="store_true", help="print one JSON object with the outcome (for sw-mcp)")
    p.add_argument("command", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    cmd = a.command[1:] if a.command[:1] == ["--"] else a.command
    try:
        cfg = load_config()
    except Refused as e:
        print(f"sw-sudo: {e}", file=sys.stderr)
        return EXIT_REFUSED
    ctx = Context(euid=os.geteuid(), sudo_uid=os.environ.get("SUDO_UID"), config=cfg, client_factory=_client,
                  json_out=a.json)
    if a.status:
        return status(a.status, ctx)
    if cmd[:1] == ["check"]:
        cmd = cmd[1:][1:] if cmd[1:2] == ["--"] else cmd[1:]
        try:
            agent, user = _caller(ctx)
            real = check_command(cmd, agent, cfg.get("allow_programs") or ())
        except Refused as e:
            print(f"sw-sudo: would be refused: {e}", file=sys.stderr)
            return EXIT_REFUSED
        print(json.dumps({"program": real, "scope": command_scope(cmd, real),
                          "summary": summary_for(cmd, real, ctx.host, user, a.reason)}, indent=1))
        return 0
    return run(cmd, ctx, wait=not a.no_wait, reason=a.reason)


if __name__ == "__main__":
    raise SystemExit(main())
