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
3. **Tokens → New token**, e.g. **jarvis**. Copy the token: it's shown once.
4. On the token, **Manage → Change actions → Use rules for this token → Use the suggested Gmail rules**, choose
   where you want to be asked (this website, Telegram or ntfy), and save. Telegram or ntfy need the project's
   **Approval setup** tab first.
5. Optional, **Approval setup → AI agent actions**: choose **Encrypted** if the recipients and text of emails
   should not appear in phone messages or on the server (you then approve on the website).

## 3. The agent's machine

```bash
python -m pip install "securitywarden @ git+https://github.com/SoftDevEng/SecurityWarden-client"
umask 077 && mkdir -p ~/.config/securitywarden
nano ~/.config/securitywarden/jarvis.token          # paste the token from step 2.3, save
export SW_SERVER_URL=https://vault.example.com SW_ACCESS_TOKEN_FILE=~/.config/securitywarden/jarvis.token
sw-mcp login gmail
```

On Windows (PowerShell), put the token in `%USERPROFILE%\.config\securitywarden\jarvis.token` with Notepad, then:

```powershell
$env:SW_SERVER_URL="https://vault.example.com"; $env:SW_ACCESS_TOKEN_FILE="$env:USERPROFILE\.config\securitywarden\jarvis.token"; sw-mcp login gmail
```

`sw-mcp login gmail` reads the client ID and secret from SecurityWarden, opens Google's sign-in in the browser
(sign in with the agent's Gmail account and allow access), and then prints a refresh token **once**. Add it to
the project's **Secrets** as `GMAIL_REFRESH_TOKEN`, then clear the terminal. (With the admin credential on this
machine, `sw-mcp login gmail --project mail` stores it directly instead.)

Check: `sw-mcp tools --connector gmail` lists the tools. Try one by hand before involving the agent:

```bash
sw-mcp call gmail_search query=is:unread limit=3 --connector gmail
sw-mcp call gmail_send to=you@example.com subject=Test "body=Hello\nfrom SecurityWarden" --connector gmail
```

`sw-mcp call` waits (up to 15 minutes) while an action needs your approval, then prints the result.

## 4. Hermes

In `~/.hermes/config.yaml`. Hermes passes stdio servers only the environment you list, so name both variables:

```yaml
mcp_servers:
  sw:
    command: "sw-mcp"            # Windows: the full path, e.g. C:\Users\you\venv\Scripts\sw-mcp.exe
    args: ["serve", "--connector", "gmail"]
    env:
      SW_SERVER_URL: "https://vault.example.com"
      SW_ACCESS_TOKEN_FILE: "/home/you/.config/securitywarden/jarvis.token"
    timeout: 300
```

The tools appear as `mcp_sw_gmail_search`, `mcp_sw_gmail_send`, … and `mcp_sw_check_approval`. The token
file path is not a secret; the token itself never goes in this file.

`timeout: 300` matters only if the token also needs approval to read its secrets (Human approval on the
token): the first Gmail call then waits for that approval. Action approvals never block: the agent gets
"waiting_for_approval" at once.

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
