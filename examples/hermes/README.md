# Using aiSecurityWarden with Hermes Agent

aiSecurityWarden ships a Hermes **secret source** plugin. At start-up Hermes asks it for secrets; it runs
`swctl export` and hands Hermes every secret the machine token's project holds. Hermes puts them in its environment
and keeps them out of the agent's terminal and `execute_code` sandboxes.

The machine token never enters Hermes: it stays in swctl, which runs as a separate process and is given only its
own `SW_*` settings, not the rest of Hermes's environment. The plugin works on Linux, macOS and Windows.

## 1. Create a project, secrets and a token

On the website (app.aisecuritywarden.com, or your own server), or from an admin workstation:

```bash
swctl admin project create hermes-bot
swctl admin secret set hermes-bot MYAPP_API_KEY       # prompts; the value is never on the command line
swctl admin secret set hermes-bot MYAPP_API_SECRET
swctl admin token create hermes-bot --name jarvis --expires-days 180 --setup-code \
      --allow-ip 192.0.2.12        # the agent box; the token is refused from anywhere else
```

Use one project and one token per bot or profile, so each token reads only that bot's keys.

## 2. Install the client and store the token (agent box)

```bash
pipx install aisecuritywarden
swctl --server https://app.aisecuritywarden.com setup      # paste the one-time setup code
```

## 3. Install the plugin

In the Hermes desktop app: **Capabilities → Plugins → Install from Git**, with

```
https://github.com/SoftDevEng/aiSecurityWarden-hermes
```

or from a terminal:

```bash
hermes plugins install SoftDevEng/aiSecurityWarden-hermes --enable
```

Hermes then updates it with **Update all** (or `hermes plugins update aisecuritywarden`). Keep the client current
too (`pipx upgrade aisecuritywarden`): the plugin runs its swctl.

Without Git access, `swctl hermes-plugin` copies the same plugin from the installed client (run it again after each
client update), and prints the settings this computer needs. If the client is installed in Hermes's own Python,
Hermes also finds the plugin there (an entry point).

## 4. Turn it on

```bash
hermes plugins enable aisecuritywarden          # or the plugin's On switch in the desktop app
hermes config set secrets.aisecuritywarden.enabled true
```

That's all when one token is stored on the computer: the plugin uses it, with the server `swctl setup` recorded for
it. `swctl hermes-plugin` prints exactly the lines this computer needs, adding `token_name` when several tokens are
stored and `swctl` when Hermes might not find it on its own.

Then restart Hermes (the gateway and the dashboard, if they run).

### Settings (`secrets.aisecuritywarden` in config.yaml)

| Key | Default | |
|---|---|---|
| `enabled` | `false` | Load the secrets at start-up |
| `token_name` / `token_id` | `SW_TOKEN_NAME` / `SW_TOKEN_ID`, else the only stored token | Which stored token, when there are several |
| `server_url` | `SW_SERVER_URL`, else the token's own server | Needed only for a token kept outside `SW_Tokens.json` |
| `swctl` | PATH, next to Hermes's Python, then `~/.local/bin` | Full path of swctl |
| `token_file` | `SW_ACCESS_TOKEN_FILE` | A token kept in a file of its own instead |
| `ca_bundle` | `SW_CA_BUNDLE` | Your own CA, for a private server |
| `timeout_seconds` | `180` | Longest wait, including a phone approval |
| `override_existing` | `false` | Replace values already in `.env` or the shell |

With several tokens on one computer, name the one whose project holds Hermes's keys: every secret in that project
goes into Hermes's environment, so don't point it at a connector's token (for example the one sw-mcp uses for Gmail).

A secret in the vault can't change these settings: Hermes never lets any source overwrite `SW_SERVER_URL`,
`SW_ACCESS_TOKEN`, `SW_TOKEN_NAME`, `SW_ALLOW_HTTP` or the other `SW_*` variables swctl reads.

### Passing secrets to an MCP server

```yaml
mcp_servers:
  myapp:
    command: /home/<you>/.venvs/myapp/bin/python
    args: ["/home/<you>/.hermes/mcp/myapp_mcp.py"]
    env:
      MYAPP_API_KEY: "${MYAPP_API_KEY}"
      MYAPP_API_SECRET: "${MYAPP_API_SECRET}"
```

## Requiring approval at start-up

```bash
swctl admin token set-approval <token-id> --approval session --session-ttl 8h --channel push:telegram
```

When Hermes starts, the fetch waits until you press Approve (the server waits up to 120 s by default). The plugin
gives it 180 s; raise `timeout_seconds` if your policy waits longer. Each Hermes process that starts (the gateway,
the dashboard) asks for its own approval.

## When it fails

Hermes says so at start-up, with the reason and what to do, for example:

```
aiSecurityWarden: authentication failed (401): ... (the token was revoked, expired or is wrong)
aiSecurityWarden: → The server refused the machine token (revoked, expired or wrong): make a new one on the website and run `swctl setup` again.
```

Hermes starts without those secrets; it never reuses old values after a refused token or a denied approval.
`swctl export` exits with 3 (can't reach the server), 4 (token refused), 5 (approval denied or expired) or
6 (no server or no token on this computer), which is how the plugin tells these apart.

## Rotating and revoking

```bash
swctl admin secret set hermes-bot MYAPP_API_KEY      # new value; picked up on the next Hermes restart
swctl admin token revoke <token-id>                  # jarvis loses access immediately
swctl admin audit                                    # every fetch, with its address
```

## Older Hermes: the command helper

Hermes versions without secret-source plugins can run swctl through the
[command helper](https://hermes-agent.nousresearch.com/docs/user-guide/secrets/command) instead (Linux and macOS
only). `securitywarden-helper.sh` in this folder is a wrapper for it:

```yaml
secrets:
  command:
    enabled: true
    command: "/usr/local/bin/securitywarden-helper"
    helper_timeout_seconds: 150  # the default is 3 s; leave room for TLS, and for an approval if the token needs one
    override_existing: true
```

Use one or the other, not both: with the plugin on, turn the helper off (`hermes config set secrets.command.enabled false`).
