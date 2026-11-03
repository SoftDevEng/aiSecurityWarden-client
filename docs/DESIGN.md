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
| machine token under a setup code | `sw1\|setup\|<setup_id>` |
| connector key for the operator / an account / a project | `sw1\|ckey-admin\|<cid>`, `sw1\|ckey-user\|<user_id>\|<cid>`, `sw1\|ckey-project\|<project_id>\|<cid>` |
| a connector version's code / description | `sw1\|connector-bundle\|<cid>\|<version>`, `sw1\|connector-meta\|<cid>\|<version>` |

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

**No call waits for a person.** `sw-mcp` makes its client with `wait_for_approval=False`: when the token
itself needs a person's OK (session or every-fetch approval), the client raises `ApprovalPending` instead of
polling, and the tool answers `waiting_for_approval` with `action` `securitywarden.session` /
`securitywarden.fetch` at once. `check_approval` with that request id resumes the same call (the client keeps
the nonce and proof and checks the same approval; it never asks twice). So every tool call returns within
seconds and the agent's own tool timeout never needs raising.

**First-time setup.** If the configured token file doesn't exist yet, the tools answer "not set up: ask the user
for a setup code", and the extra tool `securitywarden_setup(code)` is offered. It redeems the code at the
configured server only (never one the agent names), stores the token (see "Setup codes") and switches the
tools on. The token never appears in a tool result.

**Changing the token = revoking it.** While the stored token works, `securitywarden_setup` refuses, so content
that tricks the agent into calling it can't swap the token. Once the server rejects the token itself (HTTP 401
on sign-in: revoked, expired or deleted; the client raises `TokenRejected`), every tool answers "the token was
revoked: ask the user for a new setup code", and `securitywarden_setup` checks with the server
(`check_token()`) and then replaces the file. Network errors, rate limits, address lists and pending approvals
never count as rejected. Only someone signed in to the token's SecurityWarden account can revoke it.

Rules are in SecurityWarden, so a compromised or confused agent can't loosen them; the connector's declared
risk can only tighten them (high-risk actions always ask). The honest limit stays: whoever controls the
agent's machine holds the token and the application's credentials.

**Finding connectors.** The ones turned on for the token's project in SecurityWarden (see "Connector
distribution"), plus any named in the MCP settings: by name from the entry-point group `securitywarden.connectors` (installed packages
declare `name = "module:Class"`; Gmail is registered the same way), or directly as `module:Class`. A connector's
actions must start with its `name`. `sw-mcp check` lints connectors (names, schemas against method signatures, no
floats, suggested rules); `securitywarden.mcp.testing` gives connector tests a fake SecurityWarden; the guide for
authors (and their AI) ships as `securitywarden/mcp/CONNECTORS.md` (`sw-mcp guide`).

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

## Connector distribution

Connectors are chosen **per token** on the website instead of being installed on each machine: a project makes
connectors available (and holds their keys, see below), and each of its tokens picks from those; a token with
none only fetches secrets. `sw-mcp` loads whatever its token has, so an agent's MCP settings need no
`--connector` at all. Taking a connector away from a project takes it away from the project's tokens too.

**Fewer tools, fewer mistakes.** Every tool's description goes to the model on every turn, so `sw-mcp` doesn't
offer tools whose action the token's rules `deny` (the server sends the effective rules with the connector list;
a denied call would be refused anyway). Changing the rules changes the list within one refresh.

**Built-in connectors** (`securitywarden/mcp/catalog.py`: Gmail today) ship with the client. The server lists
them from the client package it runs with; making one available to a project stores `builtin:<name>`. Machines whose
client doesn't have that connector yet log "update the SecurityWarden client" and carry on. They never count
against an account's limits.

**Custom connectors** are stored by the server, encrypted, account-wide (one upload serves every project of the
account), latest version only.

- *Bundle.* `sw-mcp pack NAME` writes `NAME.swconnector`: canonical JSON `{"format": "sw-connector-1", name,
  title, description, entry: "package.module:Class", files: {path: text}, tools, secrets, suggested_rules}`.
  Only `.py`, `.json`, `.txt` and `.md` files under plain package folders; the code may use the standard library
  and what the client installs (httpx, cryptography). A bundle may not provide `securitywarden`, its
  dependencies, `site`/`sitecustomize` or any standard-library name. `pack` refuses connectors that fail
  `sw-mcp check`.
- *Keys.* Each connector has its own random 256-bit key, wrapped for its owner (admin key:
  `seal(admin wrap key, ...)`; account: `HKDF(account key, "securitywarden/v1/account-ckey")`) and, for each
  project that uses it, under `HKDF(project key, "securitywarden/v1/project-ckey")`. A project's machines can
  only read the connectors turned on for that project.
- *Versions.* Each upload is sealed under `HKDF(ckey, "securitywarden/v1/connector-bundle")` (the code) and
  `"…/connector-meta"` (name, title, size, SHA-256 of the canonical bundle, tools, secrets, suggested rules,
  `activation`), each with the version number in its AAD and inside the payload. The server accepts only
  version = stored + 1 and keeps the version it replaces (one backup) for download. Restoring a backup uploads
  it again as the next version.
- *Activation* (chosen per upload, inside the encrypted meta so the server can't change it): `now`: running
  `sw-mcp` processes load the new version at their next tool call (they look at most every 30 s, and at once
  for a tool they don't know), drop actions of the replaced connector still waiting for approval, and send
  `notifications/tools/list_changed`; `restart`: running processes keep the version they have, new ones load
  the new one.
- *Rollback.* Each machine records the highest version it has loaded of every connector
  (`connector-versions/<token name>.json` next to SW_Tokens.json, or `<token file>.connectors.json`) and refuses
  a lower one, also after restarts. The server can still withhold
  an update or a connector (it can always deny service), but can't make a machine run older code or code from
  another connector or account.
- *Loading.* From memory (a meta-path finder serves the bundle's packages only; nothing is written to disk). A
  version that fails to load is logged and the previous one keeps running.
- *Approval.* Uploading while signed in is the approval: the code runs because the account owner put it
  there. Machines record each download in the activity log (`connector.fetch`). Agents can't upload.
- *Limits* (`count` connectors, `bytes` of stored ciphertext each) are set by the operator: a server default
  (2 and 256 KB until plans exist) and per-account overrides. The operator's own connectors aren't limited
  (up to 10 MB each). Lowering a limit never deletes anything; it only blocks new uploads.

Endpoints (owner `{prefix}` = `/v1/admin` or `/v1/user`; every lookup checks the owner, another owner's object
is a 404):

| | |
|---|---|
| `GET {prefix}/connectors` | built-ins (with the projects using them), custom connectors (encrypted meta, owner-wrapped key, size, backup info, projects), limits |
| `POST {prefix}/connectors` | `{id, blob, meta, wrapped_key}`, version 1 |
| `PUT {prefix}/connectors/{cid}` | `{version, blob, meta}`: the next version; the current one becomes the backup |
| `GET {prefix}/connectors/{cid}/download?which=current\|previous` | `{version, blob, meta}` |
| `DELETE {prefix}/connectors/{cid}` | the connector, its backup and every project's use of it |
| `PUT/DELETE {prefix}/projects/{pid}/connectors/{cid}` | make available to a project (`{wrapped_key}`: under the project key) / take away (also from its tokens) |
| `PUT/DELETE {prefix}/projects/{pid}/builtin-connectors/{name}` | the same for a built-in |
| `PUT {prefix}/tokens/{tid}/connectors` | `{connectors: [ids and builtin:<name>]}`: the token's choice, from its project's |
| `GET /v1/connectors` (machine) | `{token, builtin: [names], custom: [{id, version, meta, wrapped_key}], actions}` chosen for the token, with its effective action rules |
| `GET /v1/connectors/{cid}` (machine) | `{id, version, blob}` if chosen for the token; audited |
| `GET/PUT /v1/admin/settings/connector-limits`, `PUT /v1/admin/users/{uid}/connector-limits` | the operator's limits |

## Setup codes

A machine token is long, works until revoked, and has to end up in a file only the machine's user can read.
A **setup code** carries it there instead: `SWS1-` + 32 base32 characters (160 random bits), made where the token
is created (website, `swctl admin token create --setup-code`), working once, for 1–60 minutes (10 by default).

- Creating: `setup_id = b64url(HKDF(code_secret, "securitywarden/v1/setup-id", 16 bytes))`; the token string is
  sealed under `HKDF(code_secret, "securitywarden/v1/setup-key")` with AAD `sw1|setup|<setup_id>`;
  `POST /v1/{admin,user}/tokens/{id}/setup-codes {id, blob, expires_in}` (owner checked, token active, at most
  5 open codes per token).
- Redeeming: `POST /v1/setup/{setup_id}`, no credential: returns `{blob}` once and deletes the row in the same
  step. Unknown, used and expired codes all answer 404 and count as failures for the address (rate limit);
  the token's allowed addresses apply. Revoking the token deletes its codes.
- The client decrypts, checks it is a machine token, and writes it with `store_credential`: a temporary file
  created mode 600 in a 700 folder (POSIX), or with inherited permissions removed and only the current user
  granted (Windows, `icacls`), then renamed into place. An existing token is never replaced without
  `--replace`, and the code isn't used up when that would fail.
- The server sees neither the code nor the token, only the derived id and the ciphertext. Once used, a code is
  worthless, so it may sit in a chat with the agent or an email. If setup says a code was already used and
  nobody here used it, someone else collected the token: revoke it.

- `POST /v1/setup/{setup_id}?name=<token name>`: a machine set up for a named token sends its name; a code for a
  token with another name answers 409 `setup_code_for_another_token: <its name>` and is **not** used up. The
  answer carries the token's `name` and `project` (names aren't secret).
- A used code is kept a day, marked used (its ciphertext emptied), so the page that made it can see it was
  collected: `GET {prefix}/tokens/{tid}/setup-codes/{setup_id}` → `waiting` | `used` (time, address) | `expired`.
  The website closes its setup dialog when it reads `used`, and says from which address.

Ways to redeem: the agent's `securitywarden_setup` tool, `sw-mcp setup`, `swctl setup`. The website's
**Copy for the agent** copies *"Set up SecurityWarden with code SWS1-…"*, ready to paste into the chat (never with
a server address: the agent only uses the server in its own settings).

### SW_Tokens.json (tokens on a machine, by name)

Every machine token on a machine lives in one file only its user can read, keyed by the token's name on the
website, so every bot's MCP settings look alike except for `SW_TOKEN_NAME`:

    {"format": "sw-tokens-1",
     "tokens": {"jarvis-gmail": {"token": "sw1.m....", "id": "...", "server": "https://...", "project": "Gmail",
                                 "saved_at": 1793400000}}}

- Location: `SW_TOKENS_FILE`, else `%APPDATA%\SecurityWarden\SW_Tokens.json` (Windows) or
  `$XDG_CONFIG_HOME/securitywarden/SW_Tokens.json` (default `~/.config/securitywarden`).
- Which token: `SW_TOKEN_NAME` (or `--token-name`, or `token_name` in the sw-mcp config); without one, the only
  token in the file. With several and no name, programs refuse to guess.
- The server allows one **active** token per name and owner (a revoked token's name is free again), so a name
  identifies one token. Replacing a revoked token touches only its own entry.
- Writes take a lock file (`O_EXCL`; a lock older than 30 s is a leftover and taken over) and replace the file in
  one step, so bots setting up at the same time don't lose each other's entries.
- `SW_ACCESS_TOKEN_FILE` (a file per token) and `SW_ACCESS_TOKEN` keep working and take precedence.
- Every process of that user can read every token in the file, as it could read separate files before; one
  user per machine trust boundary, as before.
- Connector rollback state: `connector-versions/<token name>.json` in the same folder.

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

Each session has a `stage`: `full` after a complete sign-in, or `code` / `setup` while the second factor
is still to come ([Second factor](#second-factor-2fa)). Only `full` sessions reach the account's data.

### What each side can reach

- `/v1/user/...` mirrors the operator's `/v1/admin/...` project, secret, token, approval and activity
  endpoints, scoped to the signed-in account: another account's project, token or approval is `404`.
- The operator's `/v1/admin/...` project, token and approval endpoints cover the operator's own projects
  only. The operator can't decide an account's approval requests or list its tokens. The operator sees
  accounts (email, status, dates), the activity log and server settings, never secrets.
- Projects have an owner (`projects.owner_id`; empty for the operator); names are unique per owner.
- Accounts' tokens can be approved on the website (`admin_ui`), and through Telegram or ntfy set up in the
  project's Approval setup tab when the operator allows it ([Per-project approval setup](#per-project-approval-setup)).

## Second factor (2FA)

Codes from an authenticator app (TOTP, RFC 6238: HMAC-SHA1, 6 digits, 30-second steps), so any common app
works: Microsoft Authenticator, Google Authenticator, Authy, 1Password, Bitwarden. Plus 10 single-use
**recovery codes** (`xxxxx-xxxxx`, 50 bits each) for a lost phone.

**What it protects, and what it doesn't.** 2FA protects *signing in*: someone with a stolen password (or a
stolen admin credential) can't sign in without the phone. It doesn't change the encryption. The server has to
know each TOTP key to check codes, so TOTP keys are **not** end-to-end encrypted: they are sealed under the
server's **at-rest key** (`seal_at_rest`, AES-256-GCM, AAD `sw1|at-rest|totp|user|<id>` or
`totp|cred|<id>`), which is kept outside the database (`SW_SERVER_KEY`, base64url 32 bytes, or the key file
next to the database, `<db>.key`, created on first use, owner-only). A copy of the database without that key
reveals no TOTP key. Recovery codes are stored only as HMAC-SHA256 under a key derived from the at-rest key,
so a database copy alone can't be used to test guesses either. Losing the at-rest key locks out everyone who
uses 2FA until they're reset (by the operator, or `securitywarden-server reset-2fa` for the operator itself),
so back it up, separately from the database.

**Checking a code.** Within one step either side of the server's clock; a step at or before the last one used
is refused, so a code can't be used twice (per account / credential). Wrong codes count toward the same
sign-in rate limit as wrong passwords. A recovery code works once, then it's gone.

### Accounts (optional, or required by the operator)

1. `POST /v1/account/signin` with the password proof. Without 2FA: as before (`full` session, wrapped
   account key). With 2FA on: `{"second_factor": "code", "session"}`, a `code`-stage session (5 minutes) and
   **no** wrapped account key. When the operator requires 2FA and the account hasn't set it up:
   `{"second_factor": "setup", "session"}` (a `setup`-stage session, 15 minutes).
2. `POST /v1/account/signin/code {code}` (code-stage session): a TOTP code or a recovery code. The session
   becomes `full` and the answer is what step 1 returns without 2FA (wrapped account key included).
3. Setting up: `POST /v1/account/2fa/setup` → `{key, uri}` (a new key, pending until confirmed; the browser
   shows `uri` as a QR code and `key` to type in). `POST /v1/account/2fa/confirm {code}` turns it on and
   returns the recovery codes once; other sessions end. From a `setup`-stage session it also completes the
   sign-in (same answer as step 2). Replacing the app on an account with 2FA on needs a current code in
   `setup`.
4. `POST /v1/account/2fa/disable {auth_key, code}` (password proof and a code; refused while the operator
   requires 2FA). `POST /v1/account/2fa/recovery-codes {code}` replaces the recovery codes.
5. Operator: `PUT /v1/admin/settings/security {"require_2fa"}` (turning it on ends the sessions of accounts
   without 2FA); `POST /v1/admin/users/<id>/2fa/reset` turns an account's 2FA off and ends its sessions.

The account recovery key (new password) does not bypass 2FA.

### The admin credential (required by default)

The operator's admin credential needs a code unless the server runs with `SW_OPERATOR_2FA=0`.

1. `POST /v1/auth {id, secret, nonce, code?, mfa_session?}`. Without a code or a live 2FA session: `403
   second_factor_required`, or `403 second_factor_setup` if no app is set up yet. With a valid code (TOTP or
   recovery): `200` with the JWT plus `mfa_session` (`swm1.<random>`; the server keeps its SHA-256), a 2FA
   session that ends after 15 minutes idle and 12 hours in any case (the account session limits). Later
   `/v1/auth` calls send `mfa_session` instead of a code, so the 5-minute JWTs renew without asking again.
   A wrong code: `401 wrong code`.
2. Admin JWTs carry the 2FA session (`mfs`); every request checks it is still live (invariant 4), so ending
   it ends access at once.
3. First sign-in: `POST /v1/auth/2fa/setup {id, secret}` → `{key, uri}`; `POST /v1/auth/2fa/confirm {id,
   secret, code}` → the JWT, `mfa_session` and the recovery codes (once). Refused once 2FA is on.
4. `POST /v1/auth/2fa/signout {mfa_session}` ends it. `GET /v1/admin/2fa`, `POST /v1/admin/2fa/recovery-codes
   {code}`.
5. Locked out (lost phone and recovery codes): `securitywarden-server reset-2fa` on the server itself.

Clients: `SecurityWardenClient(..., second_factor=...)` asks the person (swctl: terminal prompts, and the
2FA session cached next to the admin credential file, owner-only; swadmin: dialogs, memory only). Machine
tokens are unaffected: they have human approval instead.

## What the server stores

| Table | Contents |
|---|---|
| `projects` | id, owner (account id, or empty for the operator), name, project key wrapped under the owner's key, the project's Telegram/ntfy settings (readable by the server, like the server-wide ones), whether action summaries stay encrypted |
| `credentials` | id, kind, label, Argon2id(secret), project, owner, token-wrapped project key, expiry, revoked, last used/IP, allowed client addresses, approval policy, action policy, approval-limit reset time; admin credential: 2FA (TOTP key sealed at rest, last step used, keyed hashes of recovery codes) |
| `users` | id, email, status, KDF parameters, salt, Argon2id(sign-in key), Argon2id(recovery proof), account key wrapped under the password-derived key and under the recovery key, dates, last sign-in IP, push allowed, own connector limits, 2FA (as for the admin credential) |
| `sessions` | SHA-256(session token), account, kind (session or recovery ticket), stage, created, last seen, expiry, IP |
| `cred_sessions` | SHA-256(2FA session token), admin credential, created, last seen, expiry, IP |
| `approvals` | id, token, kind (`auth`, `fetch`, `action`), client address, SHA-256(nonce), match code, times, status, decided via; for actions also the name, risk, digest, encrypted summary and (only if the project allows) the plaintext summary |
| `action_windows` | token, action name, until: open "approve similar for N minutes" windows |
| `connectors` | id, owner, version, the code and its description (both encrypted under the connector's key), the key wrapped for the owner, size, dates, and the replaced version (encrypted) as a backup |
| `project_connectors` | project, connector id or `builtin:<name>`, the connector key wrapped under the project key |
| `setup_codes` | setup id (HKDF of the code, not the code), token, the token encrypted under the code, created, expiry, when and from where it was used (ciphertext emptied then; the row is deleted a day later, or when expired or revoked) |
| `token_connectors` | token, connector id or `builtin:<name>`: the connectors chosen for the token |
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
