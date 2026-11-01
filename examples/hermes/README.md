# Using SecurityWarden with Hermes Agent

Hermes can load secrets from any CLI vault through its
[command helper](https://hermes-agent.nousresearch.com/docs/user-guide/secrets/command):
a shell command that prints `KEY=VALUE` lines at launch. `swctl export` prints exactly
that.

## 1. Create a project, secrets and a token (admin workstation)

```bash
swctl admin project create hermes-bot
swctl admin secret set hermes-bot EXAMPLE_API_KEY
swctl admin secret set hermes-bot EXAMPLE_API_SECRET
swctl admin token create hermes-bot --name jarvis-bot --expires-days 180 \
      --allow-ip 192.0.2.12        # the agent box; the token is refused from anywhere else
```

Use one project and one token per bot/profile. Each token can then only read that bot's keys.

## 2. Install on the agent box

```bash
pipx install securitywarden          # or: python3 -m venv ~/.venvs/sw && ~/.venvs/sw/bin/pip install securitywarden
umask 077 && mkdir -p ~/.config/securitywarden
echo 'sw1.m....' > ~/.config/securitywarden/token
sudo install -m 755 securitywarden-helper.sh /usr/local/bin/securitywarden-helper
# edit SW_SERVER_URL / SWCTL in the script, then test:
securitywarden-helper | cut -c1-20     # show only the start of each line
```

## 3. Hermes profile `config.yaml`

```yaml
secrets:
  command:
    enabled: true
    command: "/usr/local/bin/securitywarden-helper"
    helper_timeout_seconds: 10   # default is 3s; leave room for TLS + Argon2 on the server
                                 # with an approval policy: more than its timeout, e.g. 150
    override_existing: true      # let SecurityWarden be the rotation authority over .env

mcp_servers:
  example:
    command: /home/<you>/.venvs/example/bin/python
    args: ["/home/<you>/.hermes/mcp/example_mcp.py"]
    env:
      EXAMPLE_API_KEY: "${EXAMPLE_API_KEY}"
      EXAMPLE_API_SECRET: "${EXAMPLE_API_SECRET}"
```

For Gmail, use `sw-mcp` instead: it fetches its own secrets and asks for approval before each action
([docs/mcp-gmail.md](../../docs/mcp-gmail.md)).

Hermes strips managed credentials from terminal and `execute_code` sandboxes, so the
agent itself can't print them. Only the MCP server you pass them to receives them.

## Requiring approval at start-up

```bash
swctl admin token set-approval <token-id> --approval session --session-ttl 8h --channel push:telegram
```

When Hermes starts the profile, the helper waits until you press Approve (the match code
is in the helper's stderr and in the prompt). Raise `helper_timeout_seconds` above the
policy's timeout (default 120 s), e.g. to 150, or start-up fails while the request is
pending. With `session` mode the helper is approved once per start; every restart asks again.

## Rotating and revoking

```bash
swctl admin secret set hermes-bot EXAMPLE_API_KEY       # new value; picked up on next Hermes restart
swctl admin token revoke <token-id>                      # jarvis loses access immediately
swctl admin audit                                        # see every fetch, with IP
```
