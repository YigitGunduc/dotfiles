#!/bin/bash

set -euo pipefail

# --- CONFIGURATION ---
SOURCE_DIR="$HOME/Documents"
REMOTE_NAME="gdrive"
REMOTE_PATH="/Backups/iCloud_Mirror"
LOG_FILE="$HOME/Library/Logs/icloud_backup.log"
MAX_WAIT=300
WAIT_INTERVAL=5
INNER_FLAG="--run-under-caffeinate"
SCRIPT_PATH="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"

setup_logging() {
    local log_dir
    log_dir="$(dirname "$LOG_FILE")"

    if mkdir -p "$log_dir" 2>/dev/null && touch "$LOG_FILE" 2>/dev/null; then
        exec > >(tee -ia "$LOG_FILE") 2>&1
    else
        echo "Warning: cannot write log file at $LOG_FILE; continuing without file logging." >&2
    fi
}

count_offline_files() {
    local count=0

    while IFS= read -r _; do
        count=$((count + 1))
    done < <(find "$SOURCE_DIR" -type f -flags offline -print 2>/dev/null || true)

    echo "$count"
}

check_prereqs() {
    if ! command -v rclone >/dev/null 2>&1; then
        echo "Aborting: rclone is not installed or not in PATH."
        exit 1
    fi

    if ! rclone listremotes 2>/dev/null | grep -Fxq "${REMOTE_NAME}:"; then
        echo "Aborting: rclone remote '$REMOTE_NAME' is not configured."
        echo "Run 'rclone config' and create a remote named '$REMOTE_NAME'."
        exit 1
    fi

    if [ ! -d "$SOURCE_DIR" ]; then
        echo "Aborting: source directory does not exist: $SOURCE_DIR"
        exit 1
    fi
}

check_power() {
    local power_source
    power_source="$(pmset -g batt | head -n 1)"

    if [[ "$power_source" == *"Battery Power"* ]]; then
        echo "Aborting: Mac is on Battery Power."
        exit 0
    fi
}

materialize_source() {
    echo "Materializing files in $SOURCE_DIR..."

    if command -v brctl >/dev/null 2>&1; then
        brctl download "$SOURCE_DIR" >/dev/null 2>&1 || true
    else
        echo "Warning: brctl is not available; skipping explicit iCloud download request."
    fi
}

wait_for_local_files() {
    local elapsed=0
    local still_downloading

    while [ "$elapsed" -lt "$MAX_WAIT" ]; do
        still_downloading="$(count_offline_files)"

        if [ "$still_downloading" -eq 0 ]; then
            echo "All files local. Proceeding."
            return 0
        fi

        echo "Waiting for $still_downloading offline files... (${elapsed}s elapsed)"
        sleep "$WAIT_INTERVAL"
        elapsed=$((elapsed + WAIT_INTERVAL))
    done

    still_downloading="$(count_offline_files)"
    echo "Aborting: $still_downloading files are still offline after ${MAX_WAIT}s."
    exit 1
}

run_sync() {
    echo "Starting rclone sync..."
    rclone sync "$SOURCE_DIR" "$REMOTE_NAME:$REMOTE_PATH" \
        --progress \
        --metadata \
        --drive-chunk-size 64M \
        --exclude ".DS_Store" \
        --exclude ".localized" \
        --exclude "node_modules/**"
}

main() {
    setup_logging

    check_prereqs
    check_power

    if [ "${1-}" != "$INNER_FLAG" ]; then
        exec caffeinate -is bash "$SCRIPT_PATH" "$INNER_FLAG"
    fi

    echo "--- Backup Started: $(date) ---"

    materialize_source
    wait_for_local_files
    run_sync

    echo "--- Backup Successful: $(date) ---"
}

main "${1-}"
