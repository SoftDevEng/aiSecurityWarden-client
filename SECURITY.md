# Security Policy

SecurityWarden is alpha software that hasn't been independently audited.

## Reporting a vulnerability

Please **don't** open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/SoftDevEng/aiSecurityWarden-client/security/advisories/new)
for this repository. Expect an acknowledgement within a few days.

Helpful details: affected version, a description, reproduction steps, and the impact
(e.g. which guarantee in the [threat model](README.md#threat-model) it breaks).

## Scope

In scope: anything that lets the server, a network attacker, or a holder of one token
read secrets they shouldn't, forge credentials, bypass revocation or expiry, or tamper
with ciphertext without being detected.

Out of scope: attacks that need code execution on a machine that legitimately holds a
token (see the threat model).
