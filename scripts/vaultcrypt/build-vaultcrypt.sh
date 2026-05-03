#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$script_dir"

tmp_header="vaultcrypt_embedded_source.h.tmp"

if ! command -v xxd >/dev/null 2>&1; then
  echo "build-vaultcrypt.sh: xxd is required" >&2
  exit 1
fi

if ! command -v cc >/dev/null 2>&1; then
  echo "build-vaultcrypt.sh: cc is required" >&2
  exit 1
fi

xxd -i vaultcrypt.c > "$tmp_header"
mv "$tmp_header" vaultcrypt_embedded_source.h

cc -Wall -Wextra -pedantic -std=c11 vaultcrypt.c -o vaultcrypt
