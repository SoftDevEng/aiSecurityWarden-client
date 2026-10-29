# Design

## Goals

1. Unattended machines (AI agents, bots, CI) get secrets at startup **without the
   secrets living on their disk**.
2. Each machine's access is **scoped** (one project, read-only), **expiring** and
   **revocable** right away.
3. The server is **untrusted for confidentiality**: a full database dump reveals no secret.
4. It stays **small enough to review**: one crypto module, one SQLite file, no custom primitives.

Non-goals for v0.1: multi-user RBAC, a web UI, HSM/KMS integration, secret versioning.

## Credentials

```
sw1.<kind>.<id>.<secret>:<key>
```

- `kind`: `m` for a machine token, `a` for the admin credential.
- `id`: 16 random bytes, base64url. Public.
- `secret`: 32 random bytes, base64url. Sent to `/v1/auth` over TLS; the server stores Argon2id(secret).
- `key`: 32 random bytes, base64url. **Never sent.** `wrap_key = HKDF-SHA256(key, info="securitywarden/v1/wrap")`.

The `id`/`secret` split mirrors OAuth client credentials. The `key` part is what makes
this end-to-end encrypted, the same idea as the encryption key embedded in a Bitwarden
Secrets Manager access token.

## Key hierarchy

```
admin key ──wrap──▶ project_key ◀──wrap── machine token key (one wrapped copy per token)
                        │
                        ├─ HKDF "secret-enc" ─▶ AES-256-GCM key for secret blobs
                        └─ HKDF "name-mac"   ─▶ HMAC-SHA256 key for secret lookup ids
```

- Project keys are generated **client-side** by the admin client.
- The server stores `projects.wrapped_key` (under the admin key) and
  `credentials.wrapped_key` (under each machine token's key).
- Issuing a token: the admin client unwraps the project key with the admin key and
  re-wraps it under the new token's key. The server never sees the project key unwrapped.

## Ciphertext format and AAD

`v1.` + base64url(nonce‖ciphertext‖tag), AES-256-GCM, 96-bit random nonce.

| Object | AAD |
|---|---|
| project key for a token | `sw1\|pkey\|<project_id>\|<token_id>` |
| project key for the admin | `sw1\|pkey-admin\|<project_id>` |
| secret blob | `sw1\|secret\|<project_id>\|<name_mac>` |
| action summary | `sw1\|action\|<project_id>\|<request_id>` |

The AAD stops a malicious server from substituting ciphertext across projects, tokens
or secret names. Secret blobs contain `{"n": name, "v": value}`. The client also checks
that `HMAC(name) == name_mac` after decrypting.

## Authentication

1. `POST /v1/auth {id, secret, nonce?}` → Argon2id verify (a dummy hash for unknown ids keeps the
   timing the same) → HS256 JWT (`sub`, `knd`, `pid`, `exp` = 5 min). A token with a session
   approval policy gets `202` instead; see [Human approval](#human-approval).
2. Every authenticated request re-loads the credential row, so **revocation and expiry apply
   immediately** even to JWTs already issued.
3. Failed auths are rate-limited per IP and per id (in-memory sliding window).
4. The JWT signing key is random, stored in the `meta` table. It only protects session
   integrity, not secret confidentiality.

## Client address restrictions

A machine token can carry a list of allowed client addresses (`credentials.allowed_ips`,
up to 32 exact addresses or CIDR ranges; empty means any address). The list lives on the
server's credential row, not in the token string, so the `sw1` credential format is
unchanged and the list can be edited without reissuing the token
(`PUT /v1/admin/tokens/{id}/allowed-ips`).

- It is enforced at `/v1/auth` **after** the secret verifies (so a caller without the
  secret cannot probe the policy) and again on every authenticated request, alongside the
  revocation check. A refusal is `403`, is audited, and counts toward the failure limit.
- A stolen token is therefore useless from any other address. It does not stop
  unauthenticated requests reaching the server; a network allowlist in front still does that.
- The client address is the TCP peer, or with `SW_TRUST_PROXY=1` the **last**
  `X-Forwarded-For` entry (the one the trusted proxy appended), with any `:port` removed.
  Earlier entries are client-supplied and ignored. An address that cannot be parsed never
  matches an allowlist.
- `allowed_ips` on token creation is an additive, optional request field. The client checks
  that the server echoed it back and revokes the token if not, so an older server cannot
  silently issue an unrestricted token.

## Human approval

An admin can require a person to approve a machine token's use. Like `allowed_ips`, the
policy lives on the server's token row (`credentials.approval`, JSON; NULL = no approval)
and can be changed without reissuing the token (`PUT /v1/admin/tokens/{id}/approval`).
The admin credential itself cannot be given a policy.

```json
{"mode": "session", "session_ttl": 28800, "channels": ["admin_ui", "push:telegram"],
 "timeout": 120, "max_pending": 1, "max_per_hour": 6}
```

Parsed strictly (`approval.py`, shared by client and server): unknown keys, unknown
channels and out-of-range numbers are rejected. `session_ttl` 60 s to 7 days, and also
capped by the server's `SW_MAX_SESSION_TTL` (default 24 h); `timeout` 15 to 600 s;
`max_pending` 1 to 5; `max_per_hour` 1 to 120. `approvers` (device signatures) is reserved
and refused until implemented.

**What it stops:** a stolen token file used from an allowed address (another process on
the agent box), an agent with shell access running `swctl export` on its own, an attacker
with a token and a LAN foothold. **What it does not stop:** a compromised server issuing
sessions to itself. That needs the signed-device and approval-to-decrypt tiers (below).

### Session mode

1. `POST /v1/auth {id, secret, nonce}`. Address and expiry checks run first, so a refused
   address never creates a request. A client that sends no nonce (pre-0.4) gets `428`.
2. The server returns `202 {status: "pending", approval_id, match, expires_in, poll_interval}`
   and stores a pending row bound to the token id, client address and SHA-256 of the nonce.
   `match` is a two-digit code shown by the client and in every prompt.
3. Each channel in the policy is notified. A prompt contains the token id and label,
   the project name, what is asked for, the client address, the time and the match code.
   Never a secret, secret name, the token or its key part (the server has none of them).
4. A person approves or denies. The decision is recorded once (`pending` → `approved` /
   `denied` only while unexpired); later decisions get `409`.
5. The client polls `POST /v1/auth/approvals/{id} {id, secret, nonce}`: `202` while pending,
   `403 approval_denied | approval_expired | approval_cancelled` otherwise. Once approved,
   the first poll from the **same address with the same nonce** gets a JWT whose lifetime
   is `min(session_ttl, SW_MAX_SESSION_TTL)` and that carries `apr` = the approval id; the
   row becomes `redeemed`. A different address or nonce is refused (`approval_mismatch`,
   audited, counts toward the failure limit); a second redemption gets `approval_used`.

Every request with an `apr` JWT re-checks that the approval is still `redeemed`
(invariant 4). Revoking the token, changing or removing its policy, or deleting its
project sets its pending, approved and redeemed approvals to `cancelled`, which ends those
sessions at once. A JWT without `apr` for a token whose policy is `session` (issued before
the policy was set) is refused.

### Every-fetch mode

`/v1/auth` issues an ordinary JWT. Each `GET /v1/secrets` (header `X-SW-Nonce`) returns
`202` with a new approval of kind `fetch`; the client polls
`POST /v1/secrets/approvals/{id} {nonce}` and gets the secrets payload once, on approval.
The same address/nonce/single-use rules apply. Without the header (pre-0.4 client) the
server returns `428`. Prompts identify the project by name, never the secret names.

### Channels

| Channel | How the approver is authenticated |
|---|---|
| `admin_ui` | Signed in with the admin credential: `GET /v1/admin/approvals`, `POST /v1/admin/approvals/{id}/decision {decision}`. Used by `swadmin` (Approvals tab) and `swctl admin approvals`. Refused (`403`) when `admin_ui` is not in the token's policy. |
| `push:ntfy` | One-time capability in the Approve/Deny buttons. |
| `push:telegram` | One-time capability in the inline buttons, accepted only from the configured chat (and `allowed_user_ids`, required for groups). |

A **capability** is 128 random bits, one per request and channel. The server stores only
its SHA-256, so a database copy cannot decide anything. It decides only while the request
is pending, only while its channel is still in the policy, and is useless after the first
decision. Unknown capabilities count toward the per-address failure limit.

Decisions come back without the phone connecting to the server, which keeps working behind
an address allowlist:

- **Telegram:** the server long-polls `getUpdates` (no webhook) for button presses. It keeps
  each prompt's message id (`approval_messages`), and once the request is settled, by any
  channel or by expiry, revocation, a policy change or a limit reset, it edits the message
  to show the outcome (e.g. "Approved in the admin window.") and removes the buttons. A
  background pass does this within about 3 s and also marks overdue requests expired.
- **ntfy relay:** buttons POST `approve <cap>` / `deny <cap>` to `ntfy.reply_topic`; the
  server polls that topic while requests are pending.
- **ntfy direct** (no reply topic): buttons POST to `<public_url>/v1/approvals/<cap>/approve`.
  `GET /v1/approvals/<cap>` shows a page with the two buttons and decides nothing, so link
  previews are harmless. This needs the phone to reach the server.

Anyone who can read the notification can approve. For ntfy without an access token the
topic name is the only protection, so the server refuses topics shorter than 20 characters
in that case. Push settings (bot token, topics, access tokens) are server configuration, never
accepted on a command line (invariant 5). They are set in the web admin (`GET`/`PUT
/v1/admin/notify`, admin only) and kept in `meta.notify_config`, or read from a JSON file
(`SW_NOTIFY_CONFIG`); the database wins. They are not end-to-end encrypted: the server must
read them to send. Responses never include the bot token or ntfy access tokens (only their last
four characters); a null secret on save keeps the stored one. Saving reconfigures the pollers
without a restart. `POST /v1/admin/notify/test` sends a prompt whose buttons match nothing;
`POST /v1/admin/notify/telegram/lookup` lists chats that messaged the bot (from pending updates
read without an offset, or, while this server already polls that bot, from chats its poller saw,
kept in memory only). See the server's deployment guide. Failed sends are audited by channel and HTTP status only, so a
Telegram URL (which contains the bot token) never reaches a log.

#### Per-project approval setup

Each project can have its own Telegram and ntfy settings (`projects.notify_config`), set in the project's
**Approval setup** tab: `GET`/`PUT {prefix}/projects/{id}/notify`, `POST …/notify/copy`, `…/notify/test` and
`…/notify/telegram/lookup`, where `{prefix}` is `/v1/admin` (operator) or `/v1/user` (account). Same rules
as the server-wide settings: secrets are never sent back (last four characters only), null keeps a saved one,
"" removes an optional one. `GET {prefix}/projects` never includes the settings.

- **Which settings a request uses:** its token's project's own settings. The operator's projects without
  their own use the server-wide settings above, so existing installs keep working unchanged.
- **The operator's switch for accounts:** `users.push_allowed`, set with `POST /v1/admin/users/{id}/push
  {allowed}`, off by default. While it is off (or the account is disabled or deleted) the account's projects
  use no push channels and their pollers stop; their settings are kept.
- **Telegram:** a bot token, chat id and allowed user ids, at the server's Telegram API address
  (`SW_TELEGRAM_API_URL`; an account can't choose another). **One bot may serve any number of projects and
  owners**, each with its own chat.
- **ntfy:** either **generated** (`{"generated": true}`: the server makes two random topics on
  `SW_USER_NTFY_URL`, default `https://ntfy.sh`, kept until `regenerate`) or an own server and topics. Always
  relay mode (a reply topic; no direct mode), https only. For accounts an own server must resolve to public
  addresses only, so an account can't make the server send requests into its own network
  (`SW_USER_NOTIFY_PRIVATE_HOSTS=1` allows private hosts on a LAN install; checked when saving).
- **Copy:** `POST …/notify/copy {from_project, channels}` copies another project's settings (the operator can
  also copy the server-wide ones with `"server"`), bot token included, without the browser holding it. Each
  project keeps its own copy.
- **Pollers:** one per Telegram bot (by its numeric id) and one per ntfy reply topic, shared by every project
  and owner that uses it (Telegram serves a bot's updates to one reader only). The server-wide notifier polls
  its own bot and topic. Poll positions are kept per poller (`meta` `notify:tg:<bot id>:…`,
  `notify:ntfy:<url>/<topic>:…`; the server-wide ones keep `notify:…`). Pollers are started and stopped
  whenever settings, permissions or accounts change.
- **A press only counts through the request's own project.** A poller reports what came in (bot, chat and
  user, or reply topic); the server decides only if that matches the settings of the request's project:
  the same bot and chat (and an allowed user, when listed), or the same reply topic. Anything else is
  refused ("Not a SecurityWarden request for this chat.") and audited, even with a genuine capability. So a
  bot shared between projects or owners can't be used to approve another project's requests from another
  chat.
- **Policies:** a token may name `push:telegram` / `push:ntfy` only while its project has that channel (and,
  for an account, the operator allows push); `400` otherwise. If a channel goes away later, requests still
  appear on the website (`admin_ui`) when the policy names it.

### Abuse limits and audit

`max_pending` outstanding requests per token and `max_per_hour` requests per token (`429`
beyond either) prevent prompt flooding. Every request counts toward the hourly limit,
whatever its outcome. An admin can let a token ask again at once with
`POST /v1/admin/tokens/{id}/approval/reset`: it records `credentials.approval_reset_at`
(requests from before it stop counting) and cancels the token's pending requests. Approved
sessions are kept and no history is deleted. The token list reports `approvals_this_hour`. Audited: request created or refused, notification
sent or failed (channel only), approved, denied, expired, redeemed, refused redemption
(wrong address / nonce / reuse), policy changed (with the number of approvals cancelled),
limits reset (with the number of pending requests cancelled).

### Compatibility

Credential and blob formats are unchanged, so the `sw1` / `v1.` prefixes stay. The new
fields and endpoints are additive: a token with no policy behaves exactly as in 0.3.0, and
older clients get `428` (not a hang or a silent bypass) for a token that needs approval.
`approval` on token creation is checked the same way as `allowed_ips`: if an older server
does not echo it back, the client revokes the token.

### Not yet implemented

- **Device tier:** an enrolled phone key (Ed25519) signs
  `sw1-approve|<approval_id>|<token_id>|<client_ip>|<nonce>|<match>|<decision>|<expires_at>`;
  the server only verifies, so it cannot approve on its own behalf. TOTP as a second factor
  on `admin_ui`.
- **Approval needed to decrypt:** the approver device holds a second key share and releases
  it (encrypted to an ephemeral client key) on approval, so a stolen token plus a
  compromised server still cannot decrypt. Changes the wire format; bumps `sw1` / `v1.`.
- Locking a token after N consecutive denials.

## Action approval

Human approval of the **secrets** stops a stolen token. It doesn't stop an AI agent that has its secrets
from doing something it shouldn't: sending an email it was tricked into sending by another email
(prompt injection), deleting the wrong messages, placing an order. Action approval puts a person in
front of each **action** the agent's tools take. It is generic: the server knows actions by name,
never what Gmail or any other application is.

Honest limit: it protects against the agent, not against someone who controls the agent's machine
(the application's own credentials have to be on that machine to call it).

### Actions

An action has a **name** (`<app>.<verb>[.<more>]`, lowercase letters, digits and `_`, 2 to 6 parts:
`gmail.send`, `gmail.read.search`, `webull.order.place`), a **risk** declared by the connector (`low`,
`medium`, `high`), a **summary** for the person deciding, and a **digest** of exactly what will be done:

    digest = SHA-256( "sw1|action-digest|" ‖ canonical JSON {"action": name, "args": args} )

Canonical JSON: keys sorted, no whitespace, UTF-8 (not `\u`-escaped), no floats. Large content (a body,
an attachment) goes into `args` as its own SHA-256. An approval is bound to the digest: if the agent
changes one recipient or one word after asking, it is a different action and needs a new approval.

The **summary** is `{"title", "fields": [[label, value], ...], "preview"?, "count"}` (title ≤ 100
characters, ≤ 10 fields, preview ≤ 500, `count` > 1 for a batch such as "archive 40 messages").
The client always sends it encrypted under the project key
(`HKDF(project_key, "securitywarden/v1/action-summary")`, AAD above) as `summary_enc`, which the web
pages and `swctl` decrypt. It also sends it in plaintext as `summary` unless the project keeps summaries
encrypted: then the server, the activity log and phone messages never see the content (phone messages
say only "jarvis wants to: gmail.send — open SecurityWarden to review", without buttons).

### Policy (per token, set by an admin; the agent can't change it)

    {"channels": ["admin_ui", "push:telegram"], "timeout": 3600, "max_pending": 5, "max_per_hour": 60,
     "rules": [{"match": "gmail.read.*", "mode": "allow"},
               {"match": "gmail.label",  "mode": "window", "window": 1800},
               {"match": "gmail.send",   "mode": "each"},
               {"match": "*",            "mode": "each"}]}

Rules are tried in order and the first match decides; nothing matched means `each`. `match` is an
exact name, `prefix.*` (the prefix itself and everything under it) or `*`.

| Mode | Meaning |
|---|---|
| `allow` | no person asked; still logged |
| `each` | a person approves this one action |
| `window` | a person approves once; the same action name is then allowed for `window` seconds (60 to 86400) |
| `deny` | refused |

A `high`-risk action is never `allow` or `window`: such rules are tightened to `each`. Risk only ever
tightens; a rule is the most an agent can get. No policy (NULL) means: ask for every action, on the
website (`admin_ui`), timeout 1 hour. Limits: `timeout` 60 s to 24 h (the agent checks back, it doesn't
block), `max_pending` 1 to 50, `max_per_hour` 1 to 1000. Changing a token's action policy, revoking it
or resetting its limits ends pending action requests and open windows.

### Protocol (machine token)

- `GET /v1/actions/config` → `{"project_id", "wrapped_key", "summaries": "plain" | "encrypted"}`: the
  token-wrapped project key, so the client can encrypt summaries without fetching secrets.
- `POST /v1/actions` with `{"id", "action", "risk", "digest", "nonce", "summary_enc", "summary"?}`
  (`id` chosen by the client, so it can be in the summary's AAD; `nonce` 128 random bits):
  - `200 {"status": "approved"}`: allowed (by `allow`, or an open window). Already used: do it now.
  - `202 {"status": "pending", "request_id", "match", "expires_in", "check_after"}`: a person has been
    asked, by the token's action-policy channels, with the match code.
  - `403 action_denied`: the policy says `deny`. `429`: limits.
- `POST /v1/actions/{id}` with `{"nonce", "digest"}` (same token and client address as the request):
  `202` still pending; `200 {"status": "approved"}` once, when approved (it is used up by this call);
  `403 approval_denied | approval_expired | approval_cancelled | approval_used | approval_mismatch |
  action_mismatch` otherwise.

Pending action requests use the same machinery as session and fetch approvals: match codes, one-time
capabilities in the Telegram / ntfy buttons (per project approval setup), the Approvals pages, the
prompts that update to "Approved in Telegram.", per-owner tenancy and the activity log (action name,
risk, decision and channel; the summary only when the project allows plaintext summaries).

### The agent's side

The MCP framework (`securitywarden.mcp`) does this for every connector: before a tool marked as an
action runs, it computes the digest and summary and asks. Pending: the tool returns
`{"status": "waiting_for_approval", "request_id", "match", "check_after"}` to the AI at once; the AI
calls `check_approval(request_id)` later, which performs the stored action, with exactly the stored
arguments, once it is approved.

## MCP connectors

`sw-mcp serve` is a Model Context Protocol server (stdio, JSON-RPC 2.0, one message per line; written on the
standard library rather than the MCP SDK so the client keeps two dependencies). It serves the tools of the
enabled connectors plus `check_approval`. A connector is one class per application:

- `name` (the action prefix), `secrets` (names it reads from the token's project), `suggested_rules`;
- tools declared with `@tool(description, action=..., risk=..., params=..., required=...)`. A tool doesn't do
  anything: it **prepares** a `Plan(args, summary, run)`. `args` (JSON values, no floats) decides everything
  `run` does; `run(args)` gets nothing else. Preparing may look things up (e.g. the sender of the email being
  replied to) so that `args` and the summary are complete; nothing it reads goes back to the AI.

For each call the framework:

1. checks the arguments against the tool's schema;
2. prepares the plan and computes `action_digest(action, args)`;
3. if the same action with the same digest is already waiting, checks that request instead of asking again;
4. asks the server (`POST /v1/actions`): allowed → `run(args)` now; pending → stores the plan in memory and
   answers `waiting_for_approval` (it names only the action, never the summary, which may hold outside text);
   denied or refused → says so, nothing runs;
5. `check_approval(request_id)` → `POST /v1/actions/{id}`; approved → `run` with a copy of the stored
   `args`, once. A plan lives only in this process (lost on restart: the AI simply asks again).

Results are text. Anything that came from outside (an email, a web page) is returned as `untrusted(...)`,
which the framework renders inside `<untrusted-content boundary="<random>">` with a note that it is data,
not instructions; the random boundary can't be closed from inside the content. Logs (stderr) carry tool
names, action names and request ids, never arguments or content. Secrets are fetched with the machine token
when first needed and kept in memory; they never appear in results or logs.

Rules are in SecurityWarden, so a compromised or confused agent can't loosen them; the connector's declared
risk can only tighten them (high-risk actions always ask). The honest limit stays: whoever controls the
agent's machine holds the token and the application's credentials.

### Gmail (`securitywarden.mcp.gmail`)

OAuth only (a Google Cloud "Desktop app" client; scope `gmail.modify`). Secrets: `GMAIL_CLIENT_ID`,
`GMAIL_CLIENT_SECRET`, `GMAIL_REFRESH_TOKEN`. `sw-mcp login gmail` runs Google's sign-in once (loopback
redirect on 127.0.0.1, PKCE S256, a random state) and stores the refresh token in the project with the admin
credential (`--project`) or shows it once to paste into the website.

| Tool | Action | Risk | Suggested rule |
|---|---|---|---|
| `gmail_search`, `gmail_read`, `gmail_read_thread`, `gmail_labels` | `gmail.read.*` | low | allow |
| `gmail_label`, `gmail_archive`, `gmail_mark_read` | `gmail.label`, `.archive`, `.mark_read` | low | window 30 min |
| `gmail_draft` | `gmail.draft` | medium | each |
| `gmail_send`, `gmail_reply`, `gmail_forward`, `gmail_trash` | `gmail.send`, `.reply`, `.forward`, `.trash` | high | each (always) |

Sending digests the full recipients, subject and body; a reply also the thread and the headers it answers;
a forward the original message id (Gmail messages don't change). Addresses and subjects are checked
(no line breaks: no header injection), at most 50 recipients and 100 messages per batch.

## Web front end

`web/` is a Svelte 5 + TypeScript single-page app, built by Vite into
`src/securitywarden/server/webui/` and served by the same FastAPI app (any non-`/v1` GET
path returns the page; the app routes in the browser).

- **Crypto in the browser.** `web/src/lib/crypto.ts` is a port of `crypto.py` using only
  WebCrypto (AES-256-GCM, HKDF-SHA256, HMAC-SHA256). The secret payload is serialised exactly
  like Python's `json.dumps` default (`ensure_ascii`: every character outside printable ASCII,
  including DEL, as `\uXXXX`), so both produce identical bytes.
- **Shared test vectors.** `tests/vectors/generate.py` writes `tests/vectors/crypto-v1.json`
  from `crypto.py` and `approval.py` with seeded nonces: credentials, HKDF, wrap keys, name
  MACs, blobs, project-key wraps, secrets with awkward values, and cases that must fail
  (wrong key, wrong context, tampering, blobs moved between names, projects or tokens).
  `tests/test_vectors.py` fails if Python's output changes; `web/tests/*.test.ts` checks the
  TypeScript produces and rejects exactly the same.
- **What the browser holds:** the admin credential and unwrapped project keys, in memory
  only (never `localStorage`, cookies or the URL). Sign-out, reload, closing the tab and 15
  minutes of inactivity drop them. The API is called with the same bearer JWT as the
  Python client; there is no cookie, so no CSRF surface.
- **Headers on every response:** `Content-Security-Policy: default-src 'none'; script-src
  'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri
  'none'; form-action 'self'; frame-ancestors 'none'`, plus `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`,
  `Cache-Control: no-store`. The build is configured to need nothing more (no inline script
  or style, no `data:` URIs); fonts (Atkinson Hyperlegible, OFL) are self-hosted.
- **Dependencies:** Svelte is the only code library in the bundle; everything else is build
  and test tooling. Versions are pinned exactly and installed with `npm ci` and
  `ignore-scripts=true`.
- **Limit:** the page is code delivered by the server. A compromised server could deliver
  code that captures keys. swadmin and swctl don't have this exposure. Planned: published
  bundle hashes per release.

## Accounts

People can create an account with an email address and a password. The server operator (the holder of the
`sw1.a.` admin credential) approves each new account before it can be used. Accounts are end-to-end encrypted
like everything else: the server never receives a password, a key derived from it, the account key, the
recovery key, a project key or any secret.

### Keys

All of this runs in the browser (`web/src/lib/crypto.ts`) and identically in `crypto.py`:

```
email      = trim, Unicode NFC, lowercase
password   = Unicode NFC, UTF-8 (12+ characters; checked by the client: the server never sees it)
salt       = 16 random bytes per account (stored by the server)
master     = PBKDF2-HMAC-SHA256(password, salt, iterations, 32 bytes)   iterations >= 600,000
auth_key   = HKDF(master, "securitywarden/v1/account-auth")   -> sent to the server to sign in
pw_wrap    = HKDF(master, "securitywarden/v1/account-wrap")   -> never leaves the browser

account_key = 32 random bytes (generated at sign-up, never changes)
wrapped_key_password = AES-GCM(pw_wrap, account_key, AAD "sw1|account-key|password|<user id>")

recovery_key  = 32 random bytes, shown once as "SWR1-" + base32 in groups of four
recovery_auth = HKDF(recovery_key, "securitywarden/v1/recovery-auth") -> sent only to recover
recovery_wrap = HKDF(recovery_key, "securitywarden/v1/recovery-wrap")
wrapped_key_recovery = AES-GCM(recovery_wrap, account_key, AAD "sw1|account-key|recovery|<user id>")

project key of an account's project:
  AES-GCM(HKDF(account_key, "securitywarden/v1/account-pkey"), project_key, AAD "sw1|pkey-user|<user id>|<project id>")
```

The server stores the salt, the KDF parameters (`{"alg": "pbkdf2-sha256", "iterations": N}`, versioned so
Argon2id can be added per account), Argon2id hashes of `auth_key` and `recovery_auth`, and the two wrapped
copies of the account key. `auth_key` only proves knowledge of the password; it can't decrypt anything, and
`pw_wrap` can't be computed from it. Secrets, project keys and machine tokens work exactly as for the
operator; only the key a project key is wrapped under differs.

If the database is stolen, an attacker can try passwords against `wrapped_key_password` (PBKDF2 at 600,000
iterations per guess) or against the Argon2id hash. A long password is what stops that. Argon2id in the
browser is a planned upgrade.

### Flows

- **Prelogin** `POST /v1/account/prelogin {email}` returns the KDF parameters and salt. For an unknown email it
  returns the default parameters and a salt derived from a server secret (`HMAC(meta.prelogin_key, email)`),
  so the answer doesn't reveal whether an account exists.
- **Sign-up** `POST /v1/account/signup` with the client-generated user id, email, KDF parameters, salt,
  `auth_key`, `recovery_auth` and both wrapped keys. The account starts **pending**. The answer is the same
  "request received" whether or not the email is already registered. Limited per address (5 per hour) and in
  total pending accounts.
- **Operator approval** `GET /v1/admin/users`, `POST /v1/admin/users/{id}/approve|disable|enable`,
  `DELETE /v1/admin/users/{id}`. Disabling ends the account's sessions at once. Deleting removes its projects
  and secrets, revokes its machine tokens and ends its sessions.
- **Sign-in** `POST /v1/account/signin {email, auth_key}`. Wrong email and wrong password get the same `401`
  (an unknown email is checked against a dummy hash, so timing is the same). Only after a correct password
  does the answer say the account is pending or disabled (`403`). Success returns a session token, the user
  id and `wrapped_key_password`. Failures are limited per address and per email.
- **Recovery** `POST /v1/account/recover/start {email, recovery_auth}` returns `wrapped_key_recovery` and a
  10-minute recovery ticket; `POST /v1/account/recover/finish` with the ticket and a new salt, KDF parameters,
  `auth_key` and `wrapped_key_password` sets the new password and ends every session. Without the password or
  the recovery key an account's data can't be recovered by anyone, including the operator.
- **Password change** `POST /v1/account/password` (signed in, with the current `auth_key`): new salt and
  wrapped key; the account key and everything under it stay the same. Other sessions end.

### Sessions

`Authorization: Bearer sws1.<random>`: an opaque 256-bit token; the server stores only its SHA-256. Every
request re-reads the session and the account (invariant 4): sign-out, sign-out everywhere, disabling and
password changes take effect immediately. Sessions end after 15 minutes without a request
(`SW_SESSION_IDLE`) and after 12 hours in any case (`SW_SESSION_MAX`). There are no cookies, so there is
no CSRF surface; the browser keeps the token and the account key in memory only, so reloading the page
signs out (the keys can't survive a reload without being stored, which they never are).

Each session has a `stage`. Today a successful sign-in is `full`. A second factor will add a stage that only
allows the second-factor step, without changing anything else.

### What each side can reach

- `/v1/user/...` mirrors the operator's `/v1/admin/...` project, secret, token, approval and activity
  endpoints, scoped to the signed-in account: another account's project, token or approval is `404`.
- The operator's `/v1/admin/...` project, token and approval endpoints cover the operator's own projects
  only. The operator can't decide an account's approval requests or list its tokens. The operator sees
  accounts (email, status, dates), the activity log and server settings, never secrets.
- Projects have an owner (`projects.owner_id`; empty for the operator); names are unique per owner.
- Accounts' tokens can be approved on the website (`admin_ui`), and through Telegram or ntfy set up in the
  project's Approval setup tab when the operator allows it ([Per-project approval setup](#per-project-approval-setup)).

## What the server stores

| Table | Contents |
|---|---|
| `projects` | id, owner (account id, or empty for the operator), name, project key wrapped under the owner's key, the project's Telegram/ntfy settings (readable by the server, like the server-wide ones), whether action summaries stay encrypted |
| `credentials` | id, kind, label, Argon2id(secret), project, owner, token-wrapped project key, expiry, revoked, last used/IP, allowed client addresses, approval policy, action policy, approval-limit reset time |
| `users` | id, email, status, KDF parameters, salt, Argon2id(sign-in key), Argon2id(recovery proof), account key wrapped under the password-derived key and under the recovery key, dates, last sign-in IP, push allowed |
| `sessions` | SHA-256(session token), account, kind (session or recovery ticket), stage, created, last seen, expiry, IP |
| `approvals` | id, token, kind (`auth`, `fetch`, `action`), client address, SHA-256(nonce), match code, times, status, decided via; for actions also the name, risk, digest, encrypted summary and (only if the project allows) the plaintext summary |
| `action_windows` | token, action name, until: open "approve similar for N minutes" windows |
| `approval_caps` | SHA-256(capability), approval, channel |
| `approval_messages` | Telegram message id and the prompt text sent, so it can be updated when settled |
| `secrets` | project, HMAC(name), AES-GCM blob |
| `audit` | timestamp, credential, account, action, result, IP, detail |
| `meta` | JWT signing key, prelogin salt key, Telegram/ntfy poll positions, notification settings |

Project names, token labels and account emails are plaintext metadata. Pick names accordingly.

## Known limitations / roadmap

- One admin credential per database. Admin key rotation (re-wrap all project keys) is planned.
- The rate limiter is per process. Behind several workers, use one worker or a front-end limiter.
- No secret versioning or history yet.
- MCP connectors: Gmail first; the Webull trading server is next on the framework. Plans waiting for approval
  live in the MCP server's memory only.
- Possible future additions: a native Hermes secret-source plugin (`ctx.register_secret_source()`),
  multi-user accounts for the web front end, and Postgres support.
