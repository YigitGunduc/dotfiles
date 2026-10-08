#!/usr/bin/env bash
# doctor.sh - check that the dotfiles install is healthy.
# Installed as ~/bin/dotfiles-doctor. Exits 1 if anything is broken.

set -uo pipefail

# Resolve our own symlink (~/bin/dotfiles-doctor -> repo/scripts/doctor.sh).
self="${BASH_SOURCE[0]}"
while [ -L "$self" ]; do
  link="$(readlink "$self")"
  case "$link" in
    /*) self="$link" ;;
    *) self="$(dirname "$self")/$link" ;;
  esac
done
DOTFILES_DIR="$(cd "$(dirname "$self")/.." && pwd)"

# shellcheck source=lib/manifest.sh
source "$DOTFILES_DIR/scripts/lib/manifest.sh"

FAILS=0
WARNS=0

if [ -t 1 ]; then
  C_OK=$'\e[32m' C_WARN=$'\e[33m' C_FAIL=$'\e[31m' C_DIM=$'\e[2m' C_OFF=$'\e[0m'
else
  C_OK="" C_WARN="" C_FAIL="" C_DIM="" C_OFF=""
fi

ok()   { printf '  %sok%s    %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '  %swarn%s  %s\n' "$C_WARN" "$C_OFF" "$*"; WARNS=$((WARNS + 1)); }
fail() { printf '  %sFAIL%s  %s\n' "$C_FAIL" "$C_OFF" "$*"; FAILS=$((FAILS + 1)); }
info() { printf '  %sinfo  %s%s\n' "$C_DIM" "$*" "$C_OFF"; }
section() { printf '\n%s\n' "$*"; }

has() { command -v "$1" >/dev/null 2>&1; }

check_link() {
  local source="$DOTFILES_DIR/$1"
  local target="$HOME/$2"

  if [ -L "$target" ] && [ "$(readlink "$target")" = "$source" ]; then
    ok "~/$2"
  elif [ -L "$target" ]; then
    fail "~/$2 points to $(readlink "$target"), expected $source"
  elif [ -e "$target" ]; then
    fail "~/$2 is a regular file, not a link to the repo"
  else
    fail "~/$2 is missing"
  fi
}

check_links() {
  local entry
  for entry in "$@"; do
    check_link "${entry%%|*}" "${entry#*|}"
  done
}

if [ -f "$HOME/$PROFILE_FILE" ]; then
  PROFILE="$(cat "$HOME/$PROFILE_FILE")"
else
  PROFILE="$(default_profile)"
fi

printf 'dotfiles doctor: %s (profile: %s)\n' "$DOTFILES_DIR" "$PROFILE"
[ -f "$HOME/$PROFILE_FILE" ] || warn "no install recorded yet; run $DOTFILES_DIR/install.sh"

section "Shell and config"
if [ -f "$HOME/.bash_profile" ] && [ ! -L "$HOME/.bash_profile" ] &&
   grep -qF "$DOTFILES_DIR/.bash_profile" "$HOME/.bash_profile"; then
  ok "~/.bash_profile loads the repo profile"
else
  fail "~/.bash_profile is not the install stub; re-run install.sh"
fi
check_links "${COMMON_LINKS[@]}"
[ "$PROFILE" = "full" ] && check_links "${FULL_LINKS[@]}"
if [ -e "$HOME/.vimrc" ]; then
  warn "~/.vimrc exists and overrides ~/.vim/vimrc"
fi
if [ -f "$HOME/.bashrc.local" ]; then
  info "~/.bashrc.local is loaded"
fi

section "Built tools"
for name in "${C_TOOLS[@]}"; do
  bin="$HOME/bin/$name"
  if [ ! -x "$bin" ]; then
    if has cc; then
      fail "$name not built; re-run install.sh"
    else
      warn "$name not built (no C compiler)"
    fi
  elif [ "$DOTFILES_DIR/scripts/$name.c" -nt "$bin" ]; then
    warn "$name is older than its source; re-run install.sh"
  else
    ok "$name"
  fi
done

section "Optional commands"
for name in "${OPTIONAL_COMMANDS[@]}"; do
  has "$name" && ok "$name" || info "$name not installed"
done
{ has fd || has fdfind; } && ok "fd" || info "fd not installed"
{ has bat || has batcat; } && ok "bat" || info "bat not installed"

if [ "$PROFILE" = "full" ]; then
  section "Full profile"
  if [ "$(uname -s)" = "Darwin" ]; then
    brew_bin="$(command -v brew || true)"
    if [ -z "$brew_bin" ]; then
      fail "Homebrew not installed (https://brew.sh)"
    elif "$brew_bin" bundle check --file "$DOTFILES_DIR/Brewfile" >/dev/null 2>&1; then
      ok "Brewfile packages installed"
    else
      warn "Brewfile packages missing; run: brew bundle --file $DOTFILES_DIR/Brewfile"
    fi
  fi

  if [ -x "$HOME/bin/vaultcrypt" ]; then
    ok "vaultcrypt"
  else
    fail "vaultcrypt missing from ~/bin (needed by backup/restore; it lives in its own repo)"
  fi
  has rclone && ok "rclone" || fail "rclone missing (needed by backup)"

  if [ "$(uname -s)" = "Darwin" ] && has security; then
    if security find-generic-password -a "$USER" -s vaultcrypt >/dev/null 2>&1; then
      ok "Keychain item for vaultcrypt"
    else
      warn "no Keychain item (service vaultcrypt, account $USER); backup will refuse to run"
    fi
  fi

  if [ -x "$HOME/bin/auther" ] && [ -x "$HOME/.local/share/dotfiles/venvs/auther/bin/python3" ]; then
    ok "auther"
  else
    fail "auther not installed; re-run install.sh"
  fi

  if [ -d "$HOME/.secrets" ]; then
    perms="$(stat -f '%Lp' "$HOME/.secrets" 2>/dev/null || stat -c '%a' "$HOME/.secrets" 2>/dev/null)"
    if [ "$perms" = "700" ]; then
      ok "~/.secrets (700)"
    else
      warn "~/.secrets is mode $perms; run: chmod 700 ~/.secrets"
    fi
  else
    info "no ~/.secrets; create it with: mkdir -m 700 ~/.secrets  (api_keys.sh there is auto-loaded)"
  fi
fi

section "Housekeeping"
managed=" ${C_TOOLS[*]} auther vaultcrypt "
for entry in "${COMMON_LINKS[@]}" "${FULL_LINKS[@]}"; do
  target="${entry#*|}"
  case "$target" in bin/*) managed="$managed${target#bin/} " ;; esac
done
unmanaged=""
for file in "$HOME"/bin/*; do
  [ -e "$file" ] || continue
  name="$(basename "$file")"
  case "$managed" in *" $name "*) ;; *) unmanaged="$unmanaged $name" ;; esac
done
if [ -n "$unmanaged" ]; then
  info "not managed by dotfiles in ~/bin:$unmanaged"
fi
if [ -d "$HOME/$BACKUP_ROOT" ]; then
  info "install backups: $(ls -1 "$HOME/$BACKUP_ROOT" | wc -l | tr -d ' ') in ~/$BACKUP_ROOT (safe to delete once reviewed)"
fi
if has git && [ -n "$(git -C "$DOTFILES_DIR" status --porcelain 2>/dev/null)" ]; then
  info "dotfiles repo has uncommitted changes"
fi

printf '\n'
if [ "$FAILS" -gt 0 ]; then
  printf '%s%d problem(s), %d warning(s).%s\n' "$C_FAIL" "$FAILS" "$WARNS" "$C_OFF"
  exit 1
fi
printf '%sAll good%s (%d warning(s)).\n' "$C_OK" "$C_OFF" "$WARNS"
