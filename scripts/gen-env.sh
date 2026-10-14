#!/usr/bin/env sh
# Create .env from .env.example with every "change-me" replaced by a distinct random secret.
# Refuses to overwrite an existing .env.
set -eu
cd "$(dirname "$0")/.."
[ -e .env ] && { echo ".env already exists — not overwriting" >&2; exit 1; }
umask 077
while IFS= read -r line; do
  case "$line" in
    *=change-me) printf '%s=%s\n' "${line%%=*}" "$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)" ;;
    *) printf '%s\n' "$line" ;;
  esac
done < .env.example > .env
chmod 600 .env
echo "wrote .env (0600)"
