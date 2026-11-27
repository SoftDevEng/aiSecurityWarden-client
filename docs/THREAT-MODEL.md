# aiSecurityWarden threat model

**Version 1, 2026-11-26** (client 0.7.16, server 0.6.0.dev34). This is a living document, kept with the open-source
client so anyone can check it against the code. It covers the whole system, including the server, which is closed
source. **Status: reviewed by its authors only; no independent audit yet** (planned before 1.0). Found something this
document gets wrong, or a way around a mitigation? See [Reporting](#reporting).

How to read it: [what we protect](#1-what-we-protect), [the parts and where trust changes](#2-the-parts-and-the-trust-boundaries),
[who we defend against](#3-who-we-defend-against), then [threats and mitigations](#4-threats-and-mitigations) per
boundary, [what we don't protect against](#5-what-we-dont-protect-against), the
[OWASP mappings](#6-mapping-to-the-owasp-top-10-lists), [assumptions](#7-assumptions-and-deployment-requirements) and
[open items](#8-open-items). The protocol details behind every mitigation are in [DESIGN.md](DESIGN.md).

## The short version

aiSecurityWarden does three things for an AI agent: it keeps the agent's API keys **end-to-end encrypted** so the
server can't read them, it lets the owner **approve the agent's access** to those keys, and it puts the owner's
**rules and approvals in front of the agent's actions** (sending email, merging code, running a root command).

It is built on one principle, learned by watching real agents work around restrictions:

> **A machine that runs an AI agent can't keep a secret from that agent.** Code running as the agent's user can read
> whatever that user can. So the security is the **gate**, which lives off the agent's machine: on the server, in
> the owner's rules, and on the owner's phone. Every use of a token can be approved and is logged, and every action
> through a connector is checked against rules the agent can't change.

Approval protects the **moment of access**. Once a secret has been handed to an agent's process, what that process
does with it is limited by the vendor credential itself (scope, expiry, IP limits), not by us.

## 1. What we protect

| # | Asset | Where it lives | Main property |
|---|---|---|---|
| A1 | Secret values and names | Encrypted on the server; decrypted only in the owner's browser/client and in the agent's client after approval | Confidentiality from the server and from anyone without a key |
| A2 | Key material: account key, project keys, a machine token's key part, the admin credential | Owner's device memory; the token's key part in the agent machine's token file | Never sent to the server |
| A3 | Approval decisions | Server, bound to one request, address and nonce | Only the owner can decide; one decision per request |
| A4 | Action integrity: what the owner approved is what runs | Action digest on both sides | A changed action is refused |
| A5 | The owner's rules and settings | Server | The agent can't loosen them |
| A6 | Tool descriptions the agent sees through the approval proxy | Pins on the server | No change reaches the agent unapproved |
| A7 | The app credentials connectors use (Gmail OAuth, GitHub token) | Stored as encrypted secrets; held in `sw-mcp`'s memory while it runs | The agent's model never receives them |
| A8 | The client code that runs on machines | PyPI, signed releases, the operator's release folder | Only released code installs; no downgrades |
| A9 | Account access | Server sessions | Password + optional 2FA/passkey; immediate revocation |
| A10 | Availability of approvals and secrets | Server, phone channels | Agents keep working; nothing is decided by timeout |
| A11 | Activity history | Server audit table; the revocation log beside backups | Complete, and not undone by a restore |

## 2. The parts and the trust boundaries

```
 Owner's devices                          aiSecurityWarden server                 Third parties
 ┌────────────────────────┐   TLS   ┌───────────────────────────────┐        ┌───────────────────────┐
 │ browser (web app)      │◀──────▶│ FastAPI app, SQLite database   │◀──────▶│ Telegram / Discord /  │
 │ swadmin, swctl admin   │   B1    │ at-rest key (outside the DB)   │   B4   │ ntfy (approval        │
 │ phone: approval buttons│         │ pollers for phone channels     │        │ messages)             │
 └────────────────────────┘         └───────────────────────────────┘        └───────────────────────┘
            ▲  B5: approval taps                     ▲ TLS, B2
            │  (through Telegram/Discord/ntfy)       │
                                     Agent machine   │
                     ┌───────────────────────────────┴──────────────────────────────┐
                     │ token file (SW_Tokens.json)  swctl  sw-mcp (connectors, proxy) │──▶ app APIs (Gmail,
                     │ Hermes plugin  sw-sudo (root helper, its own token)            │    GitHub, ...) B6
                     │ the AI agent (its model at a provider, its tools, its code)  B3│──▶ model provider
                     └────────────────────────────────────────────────────────────────┘
```

| Boundary | Between | What crosses it |
|---|---|---|
| B1 | Owner's device and the server | Ciphertext, wrapped keys, password *proofs* (never the password), approval decisions, rules |
| B2 | Agent machine and the server | Token id + secret part (never the key part), approval requests with match codes, action digests and (optionally encrypted) summaries, ciphertext |
| B3 | The agent and the aiSecurityWarden tools on its machine | MCP tool calls in; results out, with outside content marked untrusted |
| B4 | Server and phone-channel providers | Approval prompts (summaries only if the project allows), one-time capabilities in buttons |
| B5 | Owner's phone and the server (through B4) | Button presses, deny comments |
| B6 | Connectors and the apps they call | App API calls with the app credential, only after the gate allows them |

The most important boundary is B3. The agent is **not trusted**: it may be confused, prompt-injected, or running
code nobody reviewed. Everything that matters is decided across B2 by the server and across B5 by the owner.

## 3. Who we defend against

| # | Adversary | Capabilities we assume | Goal |
|---|---|---|---|
| T1 | **A prompt-injected or confused agent** (the main one) | Controls the agent's tool calls; may run code as the agent's user if it has a terminal/code tool | Exfiltrate data, send/delete/merge, escalate to root |
| T2 | **Malicious code as the agent's user** (a poisoned package, the agent's own scripts) | Reads every file and environment the user can; can run the client | Steal keys and tokens; use them from elsewhere |
| T3 | **Someone with a copied token** (backup, dotfile sync, log, chat) | The full token string, from another machine | Read the project's secrets |
| T4 | **A thief of the server database or a backup** | Every row, but not the at-rest key kept outside the database | Read secrets, tokens, 2FA keys, settings |
| T5 | **A compromised server or malicious operator** | Runs any server code, sees all traffic it terminates | Read secrets, approve on the owner's behalf, push code |
| T6 | **Network attacker** | On-path between parties; can't break TLS | Read or alter traffic; replay |
| T7 | **Someone with the owner's password, phone or unlocked device** | One factor, or a device left open | Sign in, approve requests |
| T8 | **A malicious or compromised MCP server, connector or its author** | Controls tool descriptions and results | Rug pull / tool poisoning; inject instructions |
| T9 | **A supply-chain attacker on our releases** | Could publish a package or tamper with a download | Run code on every customer machine |
| T10 | **Another account on the same server** | A normal account | Reach another owner's projects, tokens, approvals or phone channels |
| T11 | **An approval flooder** | A token, or an agent in a loop | Wear the owner down into tapping Approve |

## 4. Threats and mitigations

Each threat is tagged with its STRIDE class (**S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure,
**D**enial of service, **E**levation of privilege). "Residual" is what is left after the mitigation.

### 4.1 Secrets and keys (B1, B2; T3, T4, T5, T6)

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| S-1 (I) | The server, its operator or a database thief reads secrets | Secrets are encrypted on the owner's device (AES-256-GCM); project keys are generated client-side and stored only wrapped; secret **names** are stored as keyed HMACs. Account keys come from the password via PBKDF2-SHA256 (600,000 iterations) and HKDF; the server stores only Argon2id hashes of sign-in and recovery *proofs* | Offline password guessing against a stolen database is bounded by password strength (Argon2id in the browser is planned). Project names, token labels and emails are plaintext metadata |
| S-2 (T) | A malicious server swaps ciphertext between projects, tokens or names | Every ciphertext's AAD binds it to its context (`sw1\|secret\|<project>\|<name mac>`, ...); the client re-checks the name MAC after decrypting | None known |
| S-3 (I) | A token copied off a machine (backup, log) is used elsewhere | **Allowed client addresses** per token, enforced after the secret checks and on every request; **approval** per session or per fetch; an alert when a revoked/expired token or a wrong address is used with the correct secret; one-click revoke, effective on the next request | A token without allowed addresses or approval is usable from anywhere until revoked: the website warns about both |
| S-4 (I) | The token key part reaches the server | The `key` half of `sw1.m.<id>.<secret>:<key>` is never sent; it unwraps the token's copy of the project key locally | — |
| S-5 (I) | The token leaks in transit to the machine | **Setup codes**: one-time, 160-bit, 1–60 minutes, carrying the token encrypted; the server sees neither code nor token. A code used by someone else shows up ("already used") | A code is a bearer credential while it's valid |
| S-6 (S) | Brute force of token secrets or passwords | Argon2id, per-address and per-id rate limits, equal timing for unknown ids and emails, the same answer for unknown and wrong | The limiter is per server process |
| S-7 (E) | Secret names that hijack programs (`LD_PRELOAD`, `PATH`, `PYTHONPATH`, `NODE_OPTIONS`, proxies) injected through the vault | The Hermes plugin and `swctl run` refuse such names unless the owner lists them (`allow_names`, `--allow-name`) | Whoever can write to a project controls the environment it delivers; keep projects to their owner |

### 4.2 Approval of secret access (B2, B5; T1, T2, T3, T7, T11)

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| P-1 (S) | Someone else's request is approved by mistake | A two-digit **match code** shown on the machine and in every prompt; "started by" on session requests (the programs that launched the client, e.g. `python3 -c <- bash <- hermes` vs `hermes gateway <- systemd`) | "Started by" is reported by the machine, so it's a clue, not proof |
| P-2 (S, T) | An approval is replayed, or redeemed from another machine | Approvals are bound to the token, the client address and a nonce; redeemed once; a mismatch is refused and audited | — |
| P-3 (S) | A database copy is used to approve | Button capabilities are stored only as SHA-256; one per request and channel; useless after the first decision | — |
| P-4 (S) | Someone approves through a phone channel they don't own | Telegram: only the configured chat and user ids; Discord: Ed25519-signed interactions from the configured application; ntfy: random topics (≥ 20 chars) or an access token; a press counts only through the request's own project's bot and chat, even when a bot is shared | Anyone who can read the notification can approve: phone channels are a convenience, not a security tier |
| P-5 (E) | The agent controls the approval channel (it chats through the same bot) | Setup says to use a bot only for approvals; the server detects sharing (Telegram 409s, foreign Discord interactions) and warns | Detection, not prevention |
| P-6 (S) | An unlocked phone or laptop approves | Optional **passkey to approve** on the website; phone channels can be turned off per token | — |
| P-7 (D) | Approval fatigue: an agent floods prompts until the owner taps Approve | `max_pending` (never unlimited) and `max_per_hour` per token; requests expire instead of defaulting to yes | The owner can still tap carelessly |
| P-8 (D) | A program starts without its secrets because nobody answered | "Started without secrets?" alert when a start-up request expires unanswered | — |

### 4.3 Actions through connectors and the proxy (B3, B6; T1, T8)

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| A-1 (E) | A prompt-injected agent sends, forwards, deletes, merges or pushes | Every connector tool call goes through the token's **rules** (allow / window / ask each time / deny), kept on the server where the agent can't change them; anything without a rule asks; suggested rules ask for every high-risk action; deny can carry a comment | An owner can loosen rules: the website flags each line that lets a high-risk action run unasked. Allowed actions run without a person |
| A-2 (T) | The approved action is changed before it runs (one recipient, one word) | The approval is bound to a SHA-256 **digest** of the exact action and arguments (attachments by hash); a different digest is a new request | — |
| A-3 (I) | The agent's model reads app credentials | Connectors hold app credentials (OAuth tokens, GitHub tokens) inside `sw-mcp`; tool results never include them | Code running as the same user can read `sw-mcp`'s memory or environment (see 4.5) |
| A-4 (T) | **Rug pull / tool poisoning**: a proxied MCP server changes what its tools say or do | **Tool pins**: each tool's description, schema and annotations are fingerprinted; a changed list is offered to the agent only after the owner approves it, an approval no rule can skip, and which neither the machine nor the server can make alone | A server that behaves differently behind an unchanged description isn't detected by pins; the action gate still applies |
| A-5 (T) | Instructions hidden in emails, web pages and tool results | Outside content is returned wrapped as untrusted, with a per-response boundary; the agent's instructions say not to follow it | Marking reduces, it does not prevent, injection: the gate in A-1 is what limits the damage |
| A-6 (I) | Action details leak to the server or phone providers | Summaries are always sent encrypted under the project key; a project can keep them encrypted only (phone messages then show just the action name) | With plaintext summaries on, the server and phone providers see them |
| A-7 (E) | Mapped tools are bypassed through unmapped ones | Unmapped tools become `<name>.unmapped.*`, high risk if the upstream calls them destructive, never covered by rules for mapped actions | — |
| A-8 (I) | A stdio upstream's environment (with its secrets) is read by the agent running as the same user | `sw-mcp` warns and reports `proxy_same_user`; docs recommend a separate user | Same-user limit (4.5) |

### 4.4 Root and administrator commands (T1, T2)

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| R-1 (E) | An agent with root changes anything, reads every token | Run the agent as a **limited user**; root only through **sw-sudo**: one exact command per approval, with the machine and the agent's reason; the helper's token is readable by root only; one checked sudoers line | Requires the owner to set it up; Windows (`sw-elevate`) is planned |
| R-2 (E) | An approved command turns into a root shell | Refused before asking: shells, interpreters and command runners, user and sudo management, programs or files the agent could change (including `/tmp`), options that run commands (`apt -o`, `find -exec`), sudo/password/aiSecurityWarden files. Runs once, without a shell, with a clean environment, a time limit and capped output; refused if the program file changed after approval | Approving a command approves what it does as root: the owner must read it |

### 4.5 The agent's own machine (T1, T2) — the hard limit

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| M-1 (I) | Code running as the agent's user reads the token file, `sw-mcp`'s memory, `/proc/*/environ`, or the secrets a start-up script exported | Out of our control on that machine. What still holds: the token works only from its allowed addresses, reads and actions still go through approval and rules, everything is logged, and revocation is instant. `sw-scan` shows what the agent can read; the docs say to run the agent as its own user | **Secrets already delivered into an agent's environment are known to that agent.** Give it narrow, expiring vendor credentials |
| M-2 (E) | The agent starts its own `sw-mcp` or `swctl` with any entry on the machine | The server still decides: session approval ("started by" shows it), the token's rules, the token's connectors | To keep an agent to its listed tools, turn off its code/terminal tool or separate users |
| M-3 (T) | Custom connector code is malicious | Uploading while signed in is the approval; connectors load only for projects that turned them on; machines refuse older versions (no rollback); the author writes no approval logic and can't exceed the rules | A connector runs with `sw-mcp`'s privileges: only install connectors you trust |

### 4.6 Accounts, the web app and the server (B1; T4, T5, T6, T7, T10)

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| W-1 (S) | Stolen password | Optional (or operator-required) TOTP 2FA, single-use recovery codes, passkeys; codes single-use and rate-limited; an account with 2FA gets its wrapped key only after the code | — |
| W-2 (I) | 2FA secrets or phone-channel bot tokens leak from the database | Sealed under the **at-rest key**, kept outside the database (`SW_SERVER_KEY` or a key file); recovery codes stored as keyed hashes; backups never include the at-rest key | Someone with both the database and the key file has them |
| W-3 (E) | One account reaches another's data | Every project, token, approval and setting lookup checks the owner (another owner's object is a 404); tested across every endpoint; team admins reach only user management and never other admins or themselves | — |
| W-4 (I, T) | A malicious or compromised server delivers web-app code that captures keys | Strict CSP (`script-src 'self'`, no inline script, nothing from other origins except Google's token endpoints for Connect Gmail); nothing sensitive in storage beyond the tab's session token. **The desktop client (`swadmin`, `swctl`) does the same encryption from open-source code**, without trusting code the server delivers | A browser user trusts the server's page code. Published bundle hashes are planned |
| W-5 (S) | A compromised server approves requests on its own | Out of reach today: the server records decisions | Planned: signed approvals from an enrolled device and "approval needed to decrypt" (a second key share released by the approver), so a server alone can't approve or decrypt |
| W-6 (R) | Disputes about who did what | Audit log of sign-ins, approvals, denials, actions (name, risk, decision, channel), setup codes, connector fetches; a restore can't undo revocations (sealed revocation log, replayed after every restore) | The operator controls the server's log |
| W-7 (I) | Session theft | Opaque session tokens stored as hashes; 15-minute idle and 12-hour limits; no cookies (no CSRF surface); sign-out everywhere; unlocking after a reload needs the password again | — |
| W-8 (D) | Denial of service | Rate limits, IIS address allowlist in front of the app, maintenance mode during restores | A server outage stops new approvals and secret fetches (by design: fail closed) |

### 4.7 Releases and supply chain (T9)

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| U-1 (T) | A malicious update reaches machines through our server | Client updates install only if **signed with the offline release key** (Ed25519, key built into the client), match the signed size and SHA-256, and are newer (no downgrades); from an agent, the exact version needs the owner's approval | A compromise of the offline release key |
| U-2 (T) | A malicious package on PyPI | PyPI publishing through trusted publishing (no long-lived upload token) from tagged releases; the release must match `__version__` | A compromise of the GitHub repository or account |
| U-3 (T) | A malicious Hermes plugin update | The Hermes catalog pins our plugin to an exact commit, reviewed by Nous before it changes; the plugin only runs the installed `swctl` and makes no network calls itself | — |

## 5. What we don't protect against

Said plainly, so nobody relies on something we don't do:

- **An attacker who controls the agent's machine while it runs**, as the agent's user or as root. They can read the
  token file, the decrypted secrets in memory or the environment, and connector credentials in `sw-mcp`. We limit what
  they can do *through us* (addresses, approval, rules, logging, revocation); nothing on that machine is hidden from
  them.
- **What an agent does with a secret it was given.** Approval protects the moment of access, not later use.
- **A server that refuses service.** It can always withhold secrets, updates or connectors (fail closed).
- **A compromised server today**, for approvals: it can record an approval nobody gave. It still can't decrypt
  secrets or install unsigned code. (Signed device approvals are planned.)
- **Browser users against a malicious server's page code.** Use the desktop client if that matters to you.
- **Carelessness the gate can't see**: approving without reading, loosening rules to `allow`, sharing a phone bot with
  the agent, running the agent as root.
- **Prompt injection itself.** No one can reliably prevent it; we bound its effect.
- **Lost keys.** Without the password (or a passkey) and the recovery key, an account's data can't be recovered by
  anyone, including us. The same for the operator's admin credential.

## 6. Mapping to the OWASP Top 10 lists

### OWASP Top 10 for LLM Applications (2025)

| Risk | Where aiSecurityWarden helps | Where it doesn't |
|---|---|---|
| LLM01 Prompt Injection | Bounds the effect: rules and approvals on every action (A-1), the exact action approved (A-2), untrusted marking (A-5) | Doesn't stop the model being misled |
| LLM02 Sensitive Information Disclosure | Keys out of `.env` files and out of the model's view (A-3); encrypted summaries (A-6); `sw-scan` | Secrets delivered into an agent's environment (M-1) |
| LLM03 Supply Chain | Signed updates, trusted publishing, pinned plugin (4.7); tool pins (A-4) | Other packages on the agent's machine |
| LLM05 Improper Output Handling | Tool results marked untrusted; proxy results capped and sanitised to text | — |
| LLM06 Excessive Agency | The core of the product: least privilege per token, rules, approvals, sw-sudo | Rules an owner sets to `allow` |
| LLM10 Unbounded Consumption | Per-token request limits (P-7) | Model usage itself |

LLM04, LLM07, LLM08 and LLM09 are about the model and its data, outside our scope.

### OWASP Top 10 for Agentic Applications (2026)

| Risk | Where aiSecurityWarden helps |
|---|---|
| ASI01 Agent Goal Hijack | A hijacked goal still has to pass the rules and the owner (A-1, A-2) |
| ASI02 Tool Misuse & Exploitation | Per-action rules, digests, deny-by-rule, unmapped tools treated as high risk (A-1, A-2, A-7) |
| ASI03 Identity & Privilege Abuse | Scoped, revocable, address-bound tokens; approval; no root except per-command sw-sudo (4.1, 4.2, 4.4) |
| ASI04 Agentic Supply Chain | Tool pins against rug pulls, signed updates, connector rollback protection (A-4, M-3, 4.7) |
| ASI05 Unexpected Code Execution | sw-sudo's guards; dangerous environment names refused (R-2, S-7). Code the agent runs as its own user is the M-1 limit |
| ASI06 Memory & Context Poisoning | Untrusted marking of outside content (A-5) |
| ASI07 Insecure Inter-Agent Communication | Not addressed directly |
| ASI08 Cascading Failures | Fail closed: no secret or action without the server; limits per token |
| ASI09 Human-Agent Trust Exploitation | Match codes, "started by", the exact action shown, flood limits, passkey approval (P-1, P-6, P-7) |
| ASI10 Rogue Agents | The gate doesn't depend on the agent's cooperation; activity log; instant revoke |

## 7. Assumptions and deployment requirements

The mitigations above assume:

- **TLS** in front of the server, and an address allowlist, VPN or tailnet restricting who can reach it (the hosted
  service runs behind IIS with an allowlist). `SW_TRUST_PROXY=1` only behind a proxy that sets `X-Forwarded-For`.
- **The at-rest key kept outside the database** and backed up separately from it.
- **The owner's devices are not compromised** while they unlock keys or approve.
- **Phone-channel bots used only for approvals**, never shared with the agent.
- **Agents run as limited users**, ideally a separate user from `sw-mcp`; root only through sw-sudo.
- **Narrow vendor credentials**: scoped, read-only where possible, expiring, IP-limited where the vendor allows.

The recommended set-up is in the [help guide](https://aisecuritywarden.com/help.html#practice).

## 8. Open items

Known gaps we intend to close, roughly in order:

1. **Independent security review** before 1.0.
2. **Signed device approvals** (an enrolled phone key signs each decision; the server only verifies) and **approval
   needed to decrypt** (a second key share released on approval), so a compromised server can't approve or decrypt.
3. **Exact-value redaction** in the Hermes plugin: remove the secrets we delivered from anything sent to the model.
4. **Tool-list pins extended to MCP skills**, now that servers can ship skills that change at any time.
5. **Published web bundle hashes** per release.
6. **Argon2id in the browser** for account keys; **admin key rotation**; token storage in the OS keyring.
7. **sw-elevate** for Windows administrator commands; a separate-user service for `sw-mcp`.
8. A shared rate limiter across server workers.

## Reporting

Please don't open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/SoftDevEng/aiSecurityWarden-client/security/advisories/new) for
this repository (see [SECURITY.md](../SECURITY.md)), or the contact form at https://aisecuritywarden.com/#contact
("Security report"). Never include real secrets or tokens. Reports that break a guarantee in section 4, or show that
section 5 understates a limit, are the most useful.

## Changes

- **Version 1 (2026-11-26):** first published version.
