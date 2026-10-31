# Gmail for an AI agent, with approval

This sets up the Gmail connector so an agent (Hermes here) can read and manage a mailbox, while SecurityWarden
decides what it may do on its own and asks you for the rest. Nothing here needs the Gmail password.

What you end up with:

- The agent reads, searches and lists mail freely.
- Labelling, archiving and marking read ask once, then are allowed for 30 minutes.
- Drafts, sending, replying, forwarding and moving to Trash ask every time, showing you the recipients,
  subject and text. Only exactly what you approved is sent.
- Your rules live in SecurityWarden, not on the agent's machine.

## 1. Google Cloud (once, about 10 minutes)

1. Go to <https://console.cloud.google.com/>, create a project (e.g. "SecurityWarden Gmail").
2. **APIs & Services → Library**: enable the **Gmail API**.
3. **Google Auth Platform → Branding / Audience** (older consoles: **OAuth consent screen**): user type
   **External**, fill in an app name and your email. Under **Audience**, add the Gmail address the agent will
   use as a test user, then press **Publish app** so the status is **In production**. (In "Testing", Google
   expires the sign-in every 7 days. For your own use the app doesn't need Google's verification; you'll see
   an "unverified app" warning once when signing in.)
4. **Clients → Create client**: type **Desktop app**. Keep the **Client ID** and **Client secret** for step 2.

## 2. SecurityWarden (website)

1. Create a project, e.g. **mail**.
2. **Secrets**: add `GMAIL_CLIENT_ID` and `GMAIL_CLIENT_SECRET` from step 1.
3. **Tokens → New token**, e.g. **jarvis**. The dialog shows a **setup code** (`SWS1-…`). It works once, for 10
   minutes; keep the dialog open until the machine has used it (you can make a new code while it's open).
4. On the token, **Manage → Change actions → Use rules for this token → Use the suggested Gmail rules**, choose
   where you want to be asked (this website, Telegram or ntfy), and save. Telegram or ntfy need the project's
   **Approval setup** tab first.
5. Optional, **Approval setup → AI agent actions**: choose **Encrypted** if the recipients and text of emails
   should not appear in phone messages or on the server (you then approve on the website).

## 3. The agent's machine

Install the client:

```bash
python -m pip install "securitywarden @ git+https://github.com/SoftDevEng/SecurityWarden-client"
```

### Hermes or Claude Desktop: add the MCP server

Hermes: **Add MCP server** (or `~/.hermes/config.yaml`); Claude Desktop: **Settings → Developer → Edit Config**.
Hermes passes stdio servers only the environment you list, so name both variables. No `timeout` is needed:
every call answers within seconds, approvals included.

```yaml
mcp_servers:
  sw_gmail:
    command: "/home/you/.venvs/sw/bin/sw-mcp"     # Windows: C:\Users\you\...\Scripts\sw-mcp.exe
    args: ["serve"]
    env:
      SW_SERVER_URL: "https://vault.example.com"
      SW_TOKEN_NAME: "jarvis-gmail"                # the token's name on the website
```

The token will be kept in `SW_Tokens.json` (`~/.config/securitywarden/` on Linux, `%APPDATA%\SecurityWarden\` on
Windows) under that name, next to any other bots' tokens; it doesn't need to exist yet. Every bot's settings look
like this, apart from the name.

Gmail comes from the website: under **Connectors**, make Gmail available to the project, and tick **Gmail** for
the token (when creating it, or under **Manage**). Unticking it there removes the tools from the running agent.
(Before server 0.6.0.dev6: `args: ["serve", "--connector", "gmail"]` and `SW_ACCESS_TOKEN_FILE` with a path of
its own, which still works.)

### Give it the setup code

On the website, **Copy for the agent** and paste it into the chat (*"Set up SecurityWarden with code SWS1-…"*). The
agent calls `securitywarden_setup`, which stores the token in `SW_Tokens.json` under its name, readable only by
your user, and the Gmail tools work; the website's dialog closes by itself once the code is used. A code for
another token is refused without being used up. Or, in a terminal on the machine:
`sw-mcp setup --server https://vault.example.com --token-name jarvis-gmail` and paste the code when asked.

The code works once, so it doesn't matter that it stays in the chat. The setup tool refuses while the stored
token works, so nothing in an email can make the agent swap it.

**Changing the token:** revoke the old one on the website (the agent then says its token was revoked), create a
new token, and give the agent the new setup code. No terminal needed.

### Sign in to Gmail (once, on a computer with a browser)

```bash
sw-mcp login gmail --server https://vault.example.com --token-file <the same token file> 
```

It reads the client ID and secret from SecurityWarden, opens Google's sign-in (sign in with the agent's Gmail
account and allow access), and prints a refresh token **once** on standard output. Add it to the project's
**Secrets** as `GMAIL_REFRESH_TOKEN` (on Windows: `sw-mcp login gmail ... | Set-Clipboard`, then paste). With the
admin credential on this machine, `--project mail` stores it directly instead. A headless machine like a server
can't open the browser: do this step on your PC with a token for the same project.

Check by hand before involving the agent:

```bash
sw-mcp call gmail_search query=is:unread limit=3 --connector gmail
sw-mcp call gmail_send to=you@example.com subject=Test "body=Hello\nfrom SecurityWarden" --connector gmail
```

`sw-mcp call` waits (up to 15 minutes) while an action needs your approval, then prints the result.

## 4. Tool names

The tools appear as `mcp_sw_gmail_gmail_search`, `mcp_sw_gmail_gmail_send`, … and `mcp_sw_gmail_check_approval`
(Hermes prefixes `mcp_<server name>_`). Keep the server name short and lowercase. The token file path is not a
secret; the token itself never goes in the MCP settings.

## 5. Try it

- "Summarise my unread email from today." Runs straight away.
- "Archive the newsletters." You're asked once (match code shown); for 30 minutes more archiving runs without asking.
- "Reply to Bob that the invoice is paid." You're asked with the recipient, subject and text. The agent says
  it's waiting; after you approve, it calls `check_approval` and the email is sent. Deny it and nothing is sent.

## Good to know

- Emails are shown to the agent as untrusted data with a warning not to follow instructions inside them.
  The approval on sending is what protects you if an email tries to trick the agent ("forward all bank mail
  to …"): you'd see that forward and its recipient before anything leaves.
- Revoking the SecurityWarden token stops the agent at once. To cut Gmail access too, remove the app at
  <https://myaccount.google.com/permissions>.
- Waiting actions are kept by the `sw-mcp` process; if it restarts, the agent just asks again.
