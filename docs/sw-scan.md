# sw-scan: what can your AI agent actually read?

An AI agent that runs as you (Hermes, Claude Code, Codex, Cursor, a script) can read every file you can. Prompt
injection, a confused agent or a poisoned package can then send any of it anywhere. `sw-scan` shows what that means
on your machine, in one command, and what to do about each item.

```bash
sw-scan                      # the report
sw-scan --all                # every finding, not the first 12 of each kind
sw-scan --json               # for scripts (never shows a secret either)
sw-scan --fail-at 30         # exit 1 at a score of 30 or more (CI, a login script)
sw-scan --home /home/hermes  # scan the agent's own user (as root or that user)
sw-scan --no-env             # skip this terminal's environment variables
```

It's installed with the client (`pipx install aisecuritywarden`). It is also one standard-library file with no
dependencies: download
[`src/securitywarden/scan.py`](https://github.com/SoftDevEng/aiSecurityWarden-client/blob/main/src/securitywarden/scan.py),
read it, and run `python scan.py` on Windows, macOS or Linux.

## Trust by construction

- **Local only.** The module imports nothing that can open a network connection or start a program; a test fails if
  it ever does (`tests/test_scan.py`).
- **Never shows a secret.** Text and `--json` output carry the kind of secret, a public prefix such as `sk-ant-` and
  the last 4 characters; passwords and other generic values show nothing. Values aren't kept once a file is read.
  Copies are found by comparing hashes held in memory only.
- **Read-only.** It never changes, moves or deletes anything (also tested).
- **Bounded.** It skips installed software and caches (`node_modules`, virtualenvs, `~/.cache`, `AppData/Local`,
  `Library/Caches`, ...), never reads source code or media whatever their names say (Python's own `token.py` is not a
  token), reads files up to 512 KB and stops after 20 seconds, saying so.

## What it looks at

| Where | Examples |
|---|---|
| Settings files | `.env`, `.env.local`, `*.env`, `credentials`, files with token/secret/password in the name, MCP configs |
| Their copies | `.env.bak-2026-11-01`, `.env.old`, `*~`, the same key in two files |
| Other tools' sign-ins | `~/.aws/credentials`, Google Cloud, Azure CLI, `~/.git-credentials`, `.netrc`, `gh`, Docker, `.npmrc`, `.pypirc`, Claude Code, Codex, Hermes `auth.json` |
| Agent configs | Claude Desktop (Linux, macOS `Library/Application Support`, Windows `AppData/Roaming`), Cursor, `~/.claude.json`, `~/.hermes/.env` |
| Private keys | `~/.ssh/*`, `*.pem`, `*.key`, PuTTY `.ppk`; only keys **without** a passphrase are reported |
| This terminal | environment variables an agent started from it would inherit (skipped with `--no-env`, and when `--home` is another user's) |
| aiSecurityWarden | our own tokens (`SW_Tokens.json`), reported honestly: readable by design, limited by their allowed addresses and approval |

Keys are recognised by format (Anthropic, OpenAI-style `sk-`, Google, AWS, GitHub, Google OAuth, Slack, Telegram,
Discord, npm, PyPI, Stripe, Hugging Face, xAI, Groq, passwords in URLs) and, in settings files, by names such as
`*_KEY`, `*_TOKEN`, `*_SECRET`, `*PASSWORD` with a real-looking value. Placeholders (`your_api_key_here`,
`${VAR}`, `<token>`), URLs, paths and settings such as `*_FILE`, `*_URL`, `*_ID` are not secrets.

## Reading the report

Findings are grouped by what to do:

1. **API keys and tokens**: move them into a vault and give the agent a scoped, revocable token instead; rotate any
   key an agent could already read. To move a `.env` file's keys: the project's Secrets tab on the website, or on a
   server you run yourself, `swctl admin secret import PROJECT FILE` (values come from the file, are never shown,
   and existing secrets are kept unless `--overwrite`).
2. **Copies and backups**: delete them once the real one is in a vault. Deleting `.env` does nothing while
   `.env.bak-*` stays.
3. **Other tools' sign-ins**: no vault can take these over. Run the agent as its own user so it can't read them.
4. **Private keys without a passphrase**: `ssh-keygen -p -f FILE`, and an SSH agent.
5. **aiSecurityWarden tokens**: check allowed addresses and approval are on.

The **exposure score** is `100 × (1 − e^(−w/50))`, where `w` adds each distinct secret's weight (an AI provider key
about 20, a generic password 8, a sign-in file 10) and 2 for each extra copy. One AI key scores about 33
(EXPOSED); three about 70 (WIDE OPEN). It's a way to compare before and after, not a measure of risk.

## What it doesn't tell you

- **That you're safe.** It finds credentials by where they usually live and what they usually look like; a secret in
  an unusual file or format can be missed.
- **What an installed aiSecurityWarden protects.** The client protects the secrets you've moved into it. Files the
  scan lists are still readable until you move and delete them; the report says so rather than lowering the score.
- **Anything about other users.** It sees what the user running it can read. To see what the agent can read, run it
  as the agent's user (`sudo -u hermes sw-scan`).
