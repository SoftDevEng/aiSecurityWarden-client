# CLAUDE.md — SecurityWarden client

The open-source (Apache-2.0) client for SecurityWarden: scoped machine tokens and end-to-end encryption.
Primary consumer: Hermes Agent via its command-helper secret source (`swctl export`).
Must run on Linux and Windows. The server is a separate, private repository (`aiSecurityWarden-server`),
which depends on this package for its crypto and parsers.

## Layout

- `src/securitywarden/crypto.py`: **all** crypto and the credential format. Keep it the only place crypto lives
  (including approval capabilities, nonces, their lookup hashes and match codes, and account key derivation).
- `src/securitywarden/approval.py`, `ipallow.py`: strict parsers for approval policies and per-token address
  lists, shared with the server. `account.py`: email and password rules shared with the server and web front end.
- `src/securitywarden/client/`: `SecurityWardenClient` (`api.py`), the `swctl` CLI (`cli.py`) and the `swadmin`
  Tkinter window (`gui.py`; no crypto of its own, never persists credentials).
- `src/securitywarden/vectors.py`: builds the crypto test vectors (`tests/vectors/crypto-v1.json`) every other
  implementation is checked against (the server repo's browser crypto keeps a copy).
- `docs/DESIGN.md` is the source of truth for the protocol. Update it with any protocol change.

## Commands

```bash
pip install -e ".[dev]" && pytest -q
python -m securitywarden.vectors      # after any change to crypto.py, approval.py or account.py;
                                      # then update the copy in the server repo (tests/vectors/) and its web crypto
```

Tests that need a running server (end-to-end, swctl, swadmin, approvals) live in the server repo, which installs
this package; run them there before releasing a change here.

## Invariants (do not break)

1. The client never sends a credential's `key` part, a project key, an account key, a password or a password-
   derived key, or plaintext secret names/values to the server.
2. Every ciphertext is AES-256-GCM with AAD binding it to its context (see DESIGN.md). Don't add encryption
   without AAD.
3. No custom crypto primitives. Only `cryptography` (AES-GCM, HKDF, HMAC, PBKDF2).
4. Secret values are never accepted on the command line (argv). Use a prompt or stdin.
5. `Credential.__repr__` must never include `secret` or `key`. Don't log credentials, JWTs or session tokens.
6. The client refuses plain `http://` to non-local hosts unless `SW_ALLOW_HTTP=1`.
7. Any wire/format change bumps the `sw1` / `v1.` version prefixes instead of silently changing them.
8. `tests/vectors/crypto-v1.json` changes only by regenerating it; other implementations must then match.

## Conventions

- Python ≥ 3.10, standard library first; keep dependencies minimal (`cryptography`, `httpx`).
- Tests for every security property you add (negative tests matter most).
- Releases are tagged `vX.Y.Z[.devN]`; the server pins a tag.
