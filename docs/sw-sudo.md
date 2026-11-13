# sw-sudo: root commands for an AI agent, one at a time, with approval (Linux)

Run your agent (e.g. Hermes) as its own **limited user**. When it needs root, it asks for **one exact command**:

```bash
sudo sw-sudo -- apt install -y ffmpeg
sudo sw-sudo --reason "the user asked for video conversion" -- apt install -y ffmpeg
```

You see the command, the machine and what started it on your phone or the website, and approve or deny (with a
comment if you like). The agent never gets the root password and can't read the helper's token.

## How it works

`sudo` runs `sw-sudo` as root (one sudoers line, written by `sw-sudo install`; the agent has no other sudo rights).
`sw-sudo` then:

1. checks the caller is the configured agent user (`SUDO_UID`, set by sudo);
2. checks the command against its guards (below) and refuses before anything is asked if it fails one;
3. asks aiSecurityWarden with **its own machine token** (`/etc/securitywarden/sw-sudo.token`, root only) for the
   action `system.run`, with a digest of exactly what will run: the arguments, the resolved program path and the
   program file's identity (device, inode, size, modification time), the machine and the user;
4. waits for the decision under the token's **action rules** (allow / time window / ask every time / deny);
5. checks everything again, refuses if the program file changed since, and runs the command **once**: no shell,
   a clean environment (fixed `PATH`, no `LD_*`, `PYTHON*` ...), working folder `/`, nothing on stdin, a time limit
   (10 minutes) and an output cap (1 MB each for stdout and stderr). The command's exit code is returned.

Exit codes of sw-sudo itself: **125** refused by a guard, **126** denied, **124** the command timed out, **75**
still waiting (with `--no-wait`, or when the wait ran out; `sudo sw-sudo --status <id>` later runs it if approved).

## Guards

Refused before anything is asked:

- **Shells, interpreters and command runners**: `bash`, `sh`, `python`, `perl`, `node`, `env`, `sudo`, `su`,
  `xargs`, `vi`, `less`, `man`, `docker`, `git`, `make`, `systemd-run`, `ssh`, `screen` ... and any copy or hard
  link of a shell. Approving one would hand over root.
- **User, group and sudo management**: `visudo`, `passwd`, `useradd`, `usermod`, `gpasswd`, `adduser` ... Do these
  yourself on the machine.
- **Files the agent can change**: the program, or any argument that names an existing file, if the agent's user
  could change it or any folder above it (including anything under `/tmp`). Approving `/home/hermes/fix.sh` would
  approve whatever the file says when it runs.
- **Options that run commands**: `apt -o`, `apt-get --option`, `find -exec`, `tar --to-command`, `rsync -e`,
  `zip -T`, `systemctl edit`, `sed -i`, `mount -o` ...
- **Protected files**: arguments under `/etc/sudoers*`, `/etc/securitywarden`, `/etc/passwd`, `/etc/shadow`,
  `/etc/group`, `/etc/pam.d`, `/root/.ssh`.

You can allow a specific program anyway by its full path in `allow_programs` in `/etc/securitywarden/sw-sudo.json`
(root only), knowingly.

**Honest limit**: the guards narrow what one approval can turn into, but approving a command still approves what
that command does as root. Read it before you tap Approve.

## Set-up

1. Install aiSecurityWarden **for root**, so the agent's user can't change the program that runs as root:
   `sudo pipx install --global aisecuritywarden` (or a root-owned venv in `/opt`). `sw-sudo install` refuses a copy
   the agent's user could change.
2. On the website: a project for it (e.g. "jarvis root"), with no secrets, and a machine token in it named
   `sw-sudo`. Set the token's **session approval to No** (it reads no secrets; every command is approved by its
   action rules) and **allowed addresses** to this machine. Add action rules, for example (first match wins):

   ```
   system.run[cmd=apt/update]=allow
   system.run[cmd=apt-get/update]=allow
   system.run[cmd=systemctl/status/*]=allow
   system.run[cmd=systemctl/restart/*]=each
   system.run[cmd=apt/install/*]=each
   system.run=each
   ```

   `cmd` is the program name and its arguments joined by `/` (a `/` inside an argument is written `%2F`), so
   `[cmd=apt/install/*]` matches any `apt install ...` and `[cmd=apt/update]` exactly `apt update`. `program` is
   the resolved path, e.g. `[program=/usr/bin/apt]`. Without a matching rule a command asks.
3. On the machine, as root: `sudo sw-sudo install --agent-user hermes` (add `--server URL` for your own server)
   and type the token's one-time setup code. It stores the token (root only), writes
   `/etc/securitywarden/sw-sudo.json` and the sudoers line (checked with `visudo -c` first).
4. Make sure the agent's user has no other sudo rights: `sudo -l -U hermes`.
5. Tell the agent to use `sudo sw-sudo -- ...` instead of `sudo ...` (a line in its instructions or skill).

`sudo sw-sudo check -- COMMAND` shows what would be asked (or why it would be refused) without asking.
`sudo sw-sudo uninstall` removes the sudoers line, the settings and the token file; revoke the token on the website.

Windows (`sw-elevate`, a service over a named pipe) is planned.
