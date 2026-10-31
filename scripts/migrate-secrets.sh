#!/usr/bin/env bash
# One-time migration: move secrets from agent-guard/.env into macOS Keychain,
# then delete the plaintext file. Run once, from anywhere:
#   ./scripts/migrate-secrets.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$ROOT/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "No .env file found at $ENV_FILE - nothing to migrate."
  exit 0
fi

migrate() {
  local name="$1" keychain_name="$2"
  local value
  value="$(grep -E "^${name}=" "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"'"'"'' || true)"
  if [[ -n "${value:-}" ]]; then
    security add-generic-password -U -s "agentguard.${keychain_name}" -a "${USER}" -w "$value" >/dev/null
    echo "Stored ${name} -> Keychain (agentguard.${keychain_name})"
  else
    echo "Skipped ${name} (empty or absent)"
  fi
}

migrate "NEAR_PRIVATE_KEY" "deployer-private-key"
migrate "OUTLAYER_API_KEY" "outlayer-api-key"
migrate "CLAUDE_API_KEY" "claude-api-key"

rm -f "$ENV_FILE"
echo "Deleted plaintext $ENV_FILE"
echo "Verify: security find-generic-password -s agentguard.deployer-private-key -w >/dev/null && echo OK"
