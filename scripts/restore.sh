#!/bin/bash
# restore.sh - Restore backup using vaultcrypt
# Usage: restore.sh <vault_directory> [output_directory]

set -euo pipefail

# --- Configuration ---
# Path to vaultcrypt binary
VAULTCRYPT_BIN="${VAULTCRYPT_BIN:-$HOME/bin/vaultcrypt}"
# Keychain configuration
KEYCHAIN_SERVICE="vaultcrypt"
KEYCHAIN_ACCOUNT="$USER"

# --- Helper Functions ---

fail() {
    echo "Error: $*" >&2
    exit 1
}

# --- Main Script ---

if [ $# -lt 1 ]; then
    echo "Usage: $(basename "$0") <vault_directory> [output_directory]"
    echo "If output_directory is omitted, restores to the current directory (.)."
    exit 1
fi

VAULT_DIR="$1"
OUTPUT_DIR="${2:-.}"

# Ensure absolute paths
VAULT_DIR=$(cd "$VAULT_DIR" &>/dev/null && pwd || fail "Vault directory not found: $VAULT_DIR")
[ -d "$VAULT_DIR" ] || fail "Not a directory: $VAULT_DIR"

# Create output directory if it doesn't exist and get its absolute path
OUTPUT_DIR=$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" &>/dev/null && pwd || fail "Could not create or access output directory: $OUTPUT_DIR")

# Check prerequisites
[ -x "$VAULTCRYPT_BIN" ] || fail "vaultcrypt binary not found at $VAULTCRYPT_BIN"

# Check if keychain item exists (optional check for UX)
if [[ "$(uname -s)" == "Darwin" ]]; then
    security find-generic-password -a "$KEYCHAIN_ACCOUNT" -s "$KEYCHAIN_SERVICE" -w >/dev/null 2>&1 || \
        echo "Warning: Keychain item not found (Service: $KEYCHAIN_SERVICE, Account: $KEYCHAIN_ACCOUNT). You will be prompted for a passphrase."
fi

echo "Restoring vault from: $VAULT_DIR"
echo "Restoring to: $OUTPUT_DIR"

# Perform restore
VAULTCRYPT_ARGS=()
if [[ "$(uname -s)" == "Darwin" ]]; then
    VAULTCRYPT_ARGS+=(--passphrase-keychain-service "$KEYCHAIN_SERVICE")
    VAULTCRYPT_ARGS+=(--passphrase-keychain-account "$KEYCHAIN_ACCOUNT")
fi
"$VAULTCRYPT_BIN" restoredir -i "$VAULT_DIR" -o "$OUTPUT_DIR" \
    "${VAULTCRYPT_ARGS[@]}"

echo "------------------------------------------------"
echo "SUCCESS: Restore completed"
echo "------------------------------------------------"
