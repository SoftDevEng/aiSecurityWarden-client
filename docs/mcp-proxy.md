# Approval proxy: any MCP server behind aiSecurityWarden

`sw-mcp` can sit between your AI agent and an MCP server someone else made (GitHub's, for example). The agent sees
that server's tools, and every call goes through aiSecurityWarden first: your rules decide, or you approve on the
website or your phone (approve, deny, or deny with a comment). The server's credential stays in aiSecurityWarden;
the agent never holds it.

A **mapping file** (`.swproxy`) says how to reach the server and which tools are which actions. GitHub's is built
in. You can upload your own on the website's **Connectors** page.

## GitHub in five steps

1. Install GitHub's MCP server on the agent's machine, so `github-mcp-server` is on the PATH
   (see github.com/github/github-mcp-server, Releases).
2. On GitHub, make a **fine-grained personal access token** limited to the repositories the agent should touch,
   with only the permissions it needs.
3. On the aiSecurityWarden website, add it to the project as the secret **`GITHUB_PAT`**.
4. **Connectors**: turn on **GitHub** for the project, and pick it for the agent's token (project → Tokens →
   Manage). Then **AI agent actions** → **Use the suggested GitHub rules** and adjust them.
5. Restart the agent (or wait a minute: `sw-mcp` picks up connectors by itself). The first time, `sw-mcp` asks you
   to **approve GitHub's tool list** (a "GitHub: allow N new or changed tools" request). Approve it and the tools
   appear.

To use GitHub's hosted endpoint instead of the local program, set `SW_PROXY_TRANSPORT=github=http` in the MCP
server's environment (the token then never leaves `sw-mcp`'s memory; see below).

## Rules by repository

Rules can name a scope in square brackets:

    github.read.*=allow
    github.pr.merge[repo=SoftDevEng/sandbox]=allow
    github.file.write[branch=SoftDevEng/sandbox/test/*]=window:30m
    github.issue.create[repo=SoftDevEng/*]=window:30m
    github.*=each

- `repo` is `owner/name`, `owner` is the account, `branch` is `owner/name/branch`.
- A `*` can only be a whole last part (`SoftDevEng/*`), and it covers everything below it.
- aiSecurityWarden's server never sees the names: the website hashes them with your project key, and `sw-mcp`
  hashes the request's values the same way.
- High-risk actions (merging, writing files, creating repositories) still ask every time. Rules can never skip
  that.

## Tool changes

`sw-mcp` keeps a fingerprint of every tool: its name, its description, what it accepts and its hints. When the
server adds a tool or changes one, the agent doesn't see it until you approve the change. That stops a server from
quietly telling the agent to do new things. Tools you didn't approve stay hidden; tools that didn't change keep
working.

Tools the mapping file doesn't name are offered as `github.unmapped.<tool>`, so a rule like `github.read.*=allow`
never covers them, whatever the server says about them.

## Keep the credential away from the agent: run sw-mcp as its own user

With a **local** server (stdio), the credential is in that program's environment. On Linux, any program running
as the **same user** can read it from `/proc`, and that includes the agent's own terminal tool. `sw-mcp` checks
this, and when the agent and `sw-mcp` run as the same user it writes a warning to the activity log.

The fix is to run `sw-mcp` as a separate user that the agent can't become:

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin swmcp
sudo -u swmcp python3 -m venv /home/swmcp/venv
sudo -u swmcp /home/swmcp/venv/bin/pip install securitywarden-<version>-py3-none-any.whl
# move the token so only swmcp can read it
sudo install -o swmcp -g swmcp -m 600 ~/.config/securitywarden/token /home/swmcp/token
# let the agent's user start sw-mcp as swmcp, and nothing else:
echo "$USER ALL=(swmcp) NOPASSWD: /home/swmcp/venv/bin/sw-mcp" | sudo tee /etc/sudoers.d/sw-mcp
sudo chmod 440 /etc/sudoers.d/sw-mcp
```

Then, in the agent's MCP settings, start it through sudo:

```yaml
command: /usr/bin/sudo
args: ["-u", "swmcp", "/home/swmcp/venv/bin/sw-mcp", "serve", "--server", "https://app.aisecuritywarden.com",
       "--token-file", "/home/swmcp/token"]
```

`github-mcp-server` must be on swmcp's PATH (or name its full path in a custom mapping file). Remove the old token
file from the agent's home once it works.

Alternatively, use the server's HTTP endpoint (`SW_PROXY_TRANSPORT=<name>=http`). The credential then only exists
in `sw-mcp`'s memory, and Ubuntu doesn't let one process read another's memory unless it started it. That is
weaker than a separate user, but much better than an environment variable.

## Writing a mapping file

```json
{"format": "sw-proxy/1", "name": "acme", "title": "Acme", "secrets": ["ACME_TOKEN"],
 "upstream": {"http": {"url": "https://mcp.acme.example/mcp",
                       "headers": {"Authorization": "Bearer ${secret:ACME_TOKEN}"}}},
 "tools": {"list_orders": {"action": "acme.read.orders", "risk": "low"},
           "refund": {"action": "acme.order.refund", "risk": "high", "scope": {"customer": "{customer_id}"},
                      "summary": {"title": "Refund order {order_id}", "fields": [["Amount", "{amount}"]]}}},
 "suggested_rules": ["acme.read.*=allow", "acme.*=each"]}
```

- `${secret:NAME}` is only allowed in the upstream's `env` (stdio) or `headers` (http), never in the command, its
  arguments or the URL. Every NAME must be listed in `secrets`.
- A **stdio** upstream runs a program on the agent's machine. Uploading a mapping file is trusting that program,
  just as uploading a custom connector is trusting its code.
- `summary` templates and `scope` read the tool's top-level arguments by name (`{owner}`).
- Upstream results and error messages reach the agent marked as untrusted data.
