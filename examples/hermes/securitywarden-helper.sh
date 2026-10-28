#!/bin/sh
# Hermes Agent command helper for SecurityWarden.
#
# Hermes runs this via /bin/sh -c at launch and parses stdout as KEY=VALUE lines.
# It must be non-interactive and finish within helper_timeout_seconds.
#
# Install:
#   sudo install -m 755 securitywarden-helper.sh /usr/local/bin/securitywarden-helper
#   umask 077; mkdir -p ~/.config/securitywarden
#   echo 'sw1.m....' > ~/.config/securitywarden/token     # from: swctl admin token create ...
#
# Everything is set explicitly here because the helper's environment is not
# guaranteed to include your shell profile or Hermes' .env.

set -eu

: "${SW_SERVER_URL:=https://securitywarden.example.com}"
: "${SW_ACCESS_TOKEN_FILE:=$HOME/.config/securitywarden/token}"
export SW_SERVER_URL SW_ACCESS_TOKEN_FILE

# Use the absolute path to swctl from the venv/pipx install you trust.
SWCTL="${SWCTL:-$HOME/.local/bin/swctl}"

exec "$SWCTL" export --format dotenv
