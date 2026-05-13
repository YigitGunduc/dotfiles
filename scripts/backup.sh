#!/bin/bash
# backup.sh - Snapshot backup using vaultcrypt with iCloud materialization
# Usage: backup <source_directory>

set -euo pipefail

# --- Configuration ---
# Target destination on Google Drive
DEST_ROOT="/Users/anakin/Library/CloudStorage/GoogleDrive-ygunduc@gmail.com/My Drive/Backups"
# Path to vaultcrypt binary
VAULTCRYPT_BIN="/Users/anakin/bin/vaultcrypt"
# Keychain configuration
KEYCHAIN_SERVICE="vaultcrypt"
KEYCHAIN_ACCOUNT="$USER"
# Local staging area to avoid slow cloud filesystem writes during encryption
LOCAL_STAGE_ROOT="$HOME/Library/Caches/vaultcrypt-backups"
# Max time to wait for iCloud materialization (1 hour)
MAX_WAIT=3600
WAIT_INTERVAL=10

# --- Helper Functions ---

fail() {
    echo "Error: $*" >&2
    exit 1
}

count_offline_files() {
    # On macOS, iCloud files that are not local have the 'offline' flag (UF_OFFLINE)
    find "$1" -type f -flags offline 2>/dev/null | wc -l | tr -d ' '
}

materialize() {
    local dir="$1"
    if command -v brctl >/dev/null 2>&1; then
        echo "Triggering iCloud download for: $dir"
        brctl download "$dir" >/dev/null 2>&1 || true
    else
        # Fallback: reading files also triggers download on macOS
        echo "brctl not found, triggering downloads via access..."
        find "$dir" -type f -exec head -c 1 {} + >/dev/null 2>&1 || true
    fi
}

# --- Main Script ---

# 1. Argument Parsing (Flags)
IS_CAFFEINATED=false
if [[ "${1-}" == "--caffeinated" ]]; then
    IS_CAFFEINATED=true
    shift
fi

FAST_MODE=""
DRY_RUN=""
ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fast|-f) FAST_MODE="--fast"; shift ;;
        --dry-run) DRY_RUN="--dry-run"; shift ;;
        *) ARGS+=("$1"); shift ;;
    esac
done

# 2. Prevent sleep during the process (Caffeinate Wrapper)
if [[ "$IS_CAFFEINATED" == "false" ]]; then
    if [ ${#ARGS[@]} -lt 1 ]; then
        echo "Usage: $(basename "$0") [--fast] [--dry-run] <directory>"
        exit 1
    fi
    SOURCE_NAME=$(basename "${ARGS[0]}")
    echo "Caffeinating for backup of $SOURCE_NAME..."
    
    PASS_ARGS=("--caffeinated")
    [ -n "$FAST_MODE" ] && PASS_ARGS+=("--fast")
    [ -n "$DRY_RUN" ] && PASS_ARGS+=("--dry-run")
    PASS_ARGS+=("${ARGS[@]}")
    
    exec caffeinate -is "$0" "${PASS_ARGS[@]}"
fi

# 3. Validate input
if [ ${#ARGS[@]} -lt 1 ]; then
    echo "Usage: $(basename "$0") [--fast] [--dry-run] <directory>"
    exit 1
fi

# Ensure we have an absolute path for the source
SOURCE_DIR=$(cd "${ARGS[0]}" &>/dev/null && pwd || fail "Source directory not found: ${ARGS[0]}")
[ -d "$SOURCE_DIR" ] || fail "Not a directory: $SOURCE_DIR"

# 4. Check prerequisites
[ -x "$VAULTCRYPT_BIN" ] || fail "vaultcrypt binary not found at $VAULTCRYPT_BIN"
command -v rclone >/dev/null 2>&1 || fail "rclone not found in PATH"

# Check if keychain item exists
security find-generic-password -a "$KEYCHAIN_ACCOUNT" -s "$KEYCHAIN_SERVICE" -w >/dev/null 2>&1 || \
    fail "Keychain item not found (Service: $KEYCHAIN_SERVICE, Account: $KEYCHAIN_ACCOUNT). Please add it first."

# 5. Handle iCloud / Offline files (Skip if dry-run)
if [ -z "$DRY_RUN" ]; then
    materialize "$SOURCE_DIR"
    echo "Checking for offline files..."
    ELAPSED=0
    while true; do
        OFFLINE_COUNT=$( (find "$SOURCE_DIR" -type f -flags offline 2>/dev/null || true) | wc -l | tr -d ' ' )
        if [ "$OFFLINE_COUNT" -eq 0 ]; then
            echo "All files are local. Proceeding."
            break
        fi
        if [ "$ELAPSED" -ge "$MAX_WAIT" ]; then
            fail "Timed out waiting for $OFFLINE_COUNT iCloud files to download."
        fi
        echo "Waiting for $OFFLINE_COUNT offline files to materialize... (${ELAPSED}s elapsed)"
        sleep "$WAIT_INTERVAL"
        ELAPSED=$((ELAPSED + WAIT_INTERVAL))
    done
else
    echo "[DRY-RUN] Skipping iCloud materialization check."
fi

# 6. Prepare naming and staging
DIR_NAME=$(basename "$SOURCE_DIR")
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")
VAULT_SNAPSHOT_NAME="${DIR_NAME}-${TIMESTAMP}.vault"

LATEST_STAGE="${LOCAL_STAGE_ROOT}/${DIR_NAME}.latest"
SNAPSHOT_STAGE="${LOCAL_STAGE_ROOT}/${VAULT_SNAPSHOT_NAME}"
FINAL_DEST="${DEST_ROOT}/${VAULT_SNAPSHOT_NAME}"

echo "Preparing backup: $VAULT_SNAPSHOT_NAME"
[ -n "$DRY_RUN" ] || mkdir -p "$LATEST_STAGE"
[ -n "$DRY_RUN" ] || mkdir -p "$DEST_ROOT"

# 7. Perform incremental encryption to local .latest stage
echo "Syncing to local stage (Incremental)..."
"$VAULTCRYPT_BIN" syncdir -i "$SOURCE_DIR" -o "$LATEST_STAGE" \
    $FAST_MODE $DRY_RUN \
    --passphrase-keychain-service "$KEYCHAIN_SERVICE" \
    --passphrase-keychain-account "$KEYCHAIN_ACCOUNT"

# 8. Create instant APFS clone for the cloud upload
if [ -z "$DRY_RUN" ]; then
    echo "Cloning snapshot (APFS)..."
    rm -rf "$SNAPSHOT_STAGE" # Ensure clean state
    cp -Rc "$LATEST_STAGE" "$SNAPSHOT_STAGE"
    
    # 9. Sync to Google Drive
    echo "Syncing to Google Drive..."
    rclone sync "$SNAPSHOT_STAGE" "$FINAL_DEST" \
        --progress \
        --metadata \
        --exclude ".DS_Store" \
        --exclude ".localized"

    # 10. Cleanup snapshot (but keep .latest for next time)
    echo "Cleaning up local snapshot..."
    rm -rf "$SNAPSHOT_STAGE"
else
    echo "[DRY-RUN] Would clone $LATEST_STAGE to $SNAPSHOT_STAGE and sync to $FINAL_DEST"
fi

echo "------------------------------------------------"
echo "SUCCESS: Backup completed"
echo "------------------------------------------------"
