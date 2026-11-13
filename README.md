# aiSecurityWarden client

<!-- mcp-name: io.github.SoftDevEng/aisecuritywarden -->

The open-source client for **[aiSecurityWarden](https://aisecuritywarden.com)**, a secrets service with **scoped,
revocable machine tokens**, **end-to-end encryption** and **human approval** for AI agents. Built so AI agents
(like [Hermes Agent](https://hermes-agent.nousresearch.com)) and other unattended services can fetch API keys at
startup without ever storing those keys on disk.

All encryption and decryption happens here, in the client. The server only ever receives ciphertext,
proofs it keeps only as Argon2id hashes, and wrapped keys, so you can check what leaves your machine by
reading this code.

Get an account and see how it works at **[aisecuritywarden.com](https://aisecuritywarden.com)**.

This repository contains:

- the Python client library (`securitywarden.client.SecurityWardenClient`);
- `swctl`, the command-line tool (machines: `swctl export` / `swctl run`; admins: `swctl admin ...`);
- `swadmin`, a small desktop admin window;
- the cryptography (`src/securitywarden/crypto.py`), the approval-policy and address-list parsers, and the
  shared test vectors other implementations are checked against;
- the protocol and design document: [docs/DESIGN.md](https://github.com/SoftDevEng/aiSecurityWarden-client/blob/main/docs/DESIGN.md).

The aiSecurityWarden server is a separate product.

> **Status: alpha.** The design is deliberately small and reviewable, but it has not had an independent
> security audit. Read the [threat model](#threat-model).

## How it works

```
 Admin workstation                 aiSecurityWarden server                Agent box (e.g. jarvis)
 ─────────────────                 ─────────────────────                ───────────────────────
 swctl admin ...                   stores only:                         sw1.m.<id>.<secret>:<key>
  • creates project key  ───────▶   • ciphertext                        (chmod 600 file)
  • encrypts secrets                • Argon2 hashes                            │
  • wraps project key               • wrapped keys          ◀── id+secret ─────┤  1. auth → 5-min JWT
    per machine token               • audit log             ─── ciphertext ──▶ │  2. fetch
                                                                               │  3. decrypt locally with <key>
                                                                               ▼
                                                                    KEY=VALUE → agent env → tools
```

A machine token has three parts:

| Part     | Sent to server? | Purpose |
|----------|-----------------|---------|
| `id`     | yes             | identifies the token |
| `secret` | yes (over TLS)  | proves possession; server keeps only an Argon2id hash |
| `key`    | **never**       | unwraps the project key, which decrypts the secrets |

So the server can authenticate a token and hand out ciphertext, but it **cannot
read any secret**. A full copy of the server's database is useless without a token key.

## Threat model

**Protects against**
- Secrets at rest on agent machines: only a token sits on disk, not your API keys.
  Backups, copied dotfiles and logs leak a token you can revoke in one command.
- Server compromise: the database holds only AES-256-GCM ciphertext, Argon2 hashes and
  wrapped keys. Ciphertext is bound to its project, token and name (AAD), so a
  malicious server can't swap blobs around either.
- Over-broad access: each token is read-only and scoped to one project.
- Stale credentials: tokens can expire; revocation takes effect on the next request
  (access JWTs are re-checked against the database every time).
- Brute force: Argon2id hashing, per-IP and per-token failure rate limiting, and the
  same timing for unknown token ids.

**Does not protect against**
- An attacker who already controls the agent machine while it's running. They can read the
  token file, or read the decrypted secrets from the process memory or environment.
  No secrets manager can prevent that.
- Losing the admin credential. Project keys are wrapped under it; without it the
  secrets can't be recovered (by design). Keep it in your password manager.
- A server operator who swaps in malicious *client* code. Install `swctl` from a source you trust.

## Install

```bash
pipx install aisecuritywarden     # or: pip install aisecuritywarden (in a virtual environment)
```

It installs the commands `swctl`, `sw-mcp` and `swadmin`. In Python code (connectors) the package is imported as
`securitywarden`, e.g. `from securitywarden.mcp import Connector`.

**Coming from 0.6 (installed as `securitywarden`)?** Reinstall once under the new name; your tokens and settings
stay where they are:

```bash
pip uninstall securitywarden && pip install aisecuritywarden     # same environment as before
```

Needs Python 3.10+, on Linux, Windows or macOS (all three are tested in CI). `swadmin` also needs Tkinter:
it ships with the python.org installers for Windows and macOS; on Debian/Ubuntu, `sudo apt install python3-tk`.

### macOS

1. Install Python from [python.org](https://www.python.org/downloads/macos/) (3.10 or newer). Its installer
   includes a current Tk, so `swadmin` works. Avoid Apple's built-in `/usr/bin/python3`: its Tk is old and
   draws windows badly. With Homebrew's Python, also run `brew install python-tk`.
2. Install the client in its own virtual environment:

   ```bash
   python3 -m venv ~/.venvs/securitywarden
   ~/.venvs/securitywarden/bin/pip install aisecuritywarden
   ~/.venvs/securitywarden/bin/swadmin          # the admin window; swctl and sw-mcp are next to it
   ```

3. Files live where they do on Linux: `~/.config/securitywarden/` (tokens, the admin credential file if you use
   one, swctl's cached 2FA session), each readable by you only.

The website works in Safari too (CI runs it in WebKit, Safari's engine).

### Updating

```bash
sw-mcp update --check     # or: swctl update --check
sw-mcp update             # installs the newest signed release; never an older one
```

Or ask your agent: "check for aiSecurityWarden updates" / "update aiSecurityWarden". The agent's
`securitywarden_update` tool asks you to approve the exact version first. Restart the agent app afterwards. When a
newer client is out, the agent is told once (and every time if the server requires it). Updates are signed with
an offline release key and checked against the key built into the client; see DESIGN.md "Client updates".

From source:

```bash
git clone https://github.com/SoftDevEng/aiSecurityWarden-client && cd aiSecurityWarden-client
pip install -e ".[dev]" && pytest
```

## Quick start

You need the address of an aiSecurityWarden server and, to administer it, its admin credential.

### 1. Admin (from your workstation)

```bash
mkdir -p ~/.config/securitywarden
echo 'sw1.a....' > ~/.config/securitywarden/admin.cred && chmod 600 ~/.config/securitywarden/admin.cred
export SW_SERVER_URL=https://vault.example.com

swctl admin project create hermes-webull
swctl admin secret set hermes-webull WEBULL_APP_KEY       # prompts; value never in argv/history
swctl admin secret set hermes-webull WEBULL_APP_SECRET
swctl admin token create hermes-webull --name jarvis --expires-days 180
```

### 2. Machine

```bash
export SW_SERVER_URL=https://vault.example.com SW_TOKEN_ID=<token id> SW_TOKEN_NAME=jarvis
swctl setup                       # paste the one-time setup code the website (or --setup-code) shows

swctl export                      # KEY=VALUE lines
swctl export --format json
swctl run -- python my_bot.py     # run a command with secrets in its environment
```

### Hermes Agent integration

Hermes supports custom vaults through a **command helper** that prints `KEY=VALUE`
lines at launch. That's exactly what `swctl export` does. See
[examples/hermes/](https://github.com/SoftDevEng/aiSecurityWarden-client/tree/main/examples/hermes) for a wrapper script and config.

### AI agent tools with approval (`sw-mcp`)

`sw-mcp` gives an agent tools for an application, such as Gmail, as an MCP server. Every action goes through
the token's rules in aiSecurityWarden: reading may be allowed outright, while sending an email waits until you
approve exactly that email (on the website, in swadmin, Telegram or ntfy). The agent is told it's waiting and
checks back. See [docs/mcp-gmail.md](https://github.com/SoftDevEng/aiSecurityWarden-client/blob/main/docs/mcp-gmail.md) for the Gmail set-up with Hermes, and
[DESIGN.md](https://github.com/SoftDevEng/aiSecurityWarden-client/blob/main/docs/DESIGN.md#mcp-connectors) for writing a connector for another application.

```bash
sw-mcp tools --connector gmail          # the tools, their actions, risks and suggested rules
sw-mcp serve --connector gmail          # what Hermes runs (stdio)
sw-mcp call gmail_search query=is:unread limit=5   # try one tool by hand; waits for approval if needed
sw-mcp setup --token-file ~/.config/securitywarden/gmail-token   # store the token from a one-time setup code
```

Other applications get a **connector**: one Python class whose tools each declare an action and a risk. An AI can
write one: `sw-mcp new-connector NAME` creates the project (with instructions for the AI in `AGENTS.md`),
`sw-mcp guide` prints the rules, and `sw-mcp check` plus the generated tests confirm it's right. Installed
connector packages are found by name (`--connector NAME`). See [docs/connectors.md](https://github.com/SoftDevEng/aiSecurityWarden-client/blob/main/docs/connectors.md).

Connectors can also come from aiSecurityWarden itself: turn a built-in one (Gmail) on for a project on the website,
or upload your own (`sw-mcp pack NAME`, then **Connectors > Upload**; encrypted in the browser, account-wide,
versioned with a backup of the version replaced). `sw-mcp serve` then loads whatever the token's project uses,
with no `--connector` needed, and picks up new versions as you choose: at once, or on the next restart.

## Admin commands

| Command | |
|---|---|
| `swctl admin project create|list|delete NAME` | manage projects |
| `swctl admin secret set|get|delete PROJECT NAME` | values read from a prompt or stdin |
| `swctl admin secret list PROJECT` | names only |
| `swctl admin token create PROJECT --name N [--expires-days D] [--allow-ip ADDR]...` | prints the token once; `--allow-ip` (address or CIDR, repeatable) pins where it may connect from |
| `swctl admin token set-ips ID --allow-ip ADDR... \| --any` | replace or remove a token's allowed addresses |
| `swctl admin token list [PROJECT]` | status, expiry, last used, last IP, allowed addresses, approval |
| `swctl admin token create ... --approval session\|every_fetch [--session-ttl 8h] [--channel C]...` | require a person to approve the token's use (see below) |
| `swctl admin token set-approval ID --approval none\|session\|every_fetch [...]` | change or remove it; ends pending requests and approved sessions |
| `swctl admin token reset-approval-limits ID` | let a token that hit its hourly limit ask again now (also in swadmin: **Reset approval limit…**) |
| `swctl admin approvals list` / `approve ID [--match NN]` / `deny ID` | decide pending requests |
| `swctl admin token revoke ID` | immediate |
| `swctl admin audit [--limit N]` | auth, fetch and admin events |

### Human approval

A machine token can require a person to approve it before it gets any secrets: once per
session (`--approval session`, the session lasts `--session-ttl`, default 8 h) or for
every fetch (`--approval every_fetch`). Requests go to the channels you choose:

- `admin_ui`: the Approvals tab in `swadmin` (or `swctl admin approvals`);
- `push:telegram` and `push:ntfy`: a phone notification with Approve / Deny buttons.
  These work behind an IIS/firewall allowlist, because the server polls Telegram / ntfy
  for the answer instead of the phone calling in. They are set up on the server, per project
  (the project's **Approval setup** tab in the web admin).

```bash
swctl admin token set-approval <token-id> --approval session --session-ttl 8h \
      --channel admin_ui --channel push:telegram
```

The machine prints a two-digit **match code** while it waits (`swctl: waiting for a person
to approve this session (match code 47, up to 120 s)...`); approve only if the prompt shows
the same code. An approval works once, only for the process and address that asked, and
ends when the token is revoked or its policy changes. Details: [docs/DESIGN.md](https://github.com/SoftDevEng/aiSecurityWarden-client/blob/main/docs/DESIGN.md#human-approval).

### Admin window (`swadmin`)

If you would rather not use a terminal, `swadmin` opens a small desktop window that does
the same things as `swctl admin`: projects, secrets, tokens (create, revoke, allowed
addresses, approval policy), pending approval requests and the activity log. The Approvals
tab checks for new requests every few seconds while you are signed in. It is installed with the client and needs only Tkinter,
which ships with Python on Windows and macOS (`sudo apt install python3-tk` on Debian/Ubuntu).

- The admin credential and secret values are pasted into the window and held in memory
  only: nothing reaches argv, the environment or shell history. Only the server address is
  remembered between runs.
- Encryption still happens on your machine, in the same code `swctl` uses.
- New tokens and revealed values are shown once with a Copy button; the clipboard is
  cleared after a minute. The window signs out after 15 minutes without input.

## Cryptography

All of it lives in [`src/securitywarden/crypto.py`](https://github.com/SoftDevEng/aiSecurityWarden-client/blob/main/src/securitywarden/crypto.py): AES-256-GCM (random
96-bit nonces) with associated data binding every ciphertext to its context, HKDF-SHA256 for key separation,
HMAC-SHA256 for secret-name lookup ids (names are encrypted too) and PBKDF2-SHA256 for account passwords,
all from the `cryptography` library. There's no custom crypto. The server stores Argon2id hashes of the
proofs clients send. Test vectors: [`tests/vectors/crypto-v1.json`](https://github.com/SoftDevEng/aiSecurityWarden-client/blob/main/tests/vectors/crypto-v1.json)
(regenerate with `python -m securitywarden.vectors`). Full design: [docs/DESIGN.md](https://github.com/SoftDevEng/aiSecurityWarden-client/blob/main/docs/DESIGN.md).

## License

Apache-2.0. See [LICENSE](https://github.com/SoftDevEng/aiSecurityWarden-client/blob/main/LICENSE). Security reports: see [SECURITY.md](https://github.com/SoftDevEng/aiSecurityWarden-client/blob/main/SECURITY.md).
