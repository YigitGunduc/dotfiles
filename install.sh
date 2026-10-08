#!/usr/bin/env bash

set -euo pipefail

DOTFILES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_HOME="${HOME}"
DRY_RUN=0
SKIP_BREW=0
SKIP_PACKAGES=0
PROFILE=""
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

# shellcheck source=scripts/lib/manifest.sh
source "$DOTFILES_DIR/scripts/lib/manifest.sh"

BACKUP_DIR="$TARGET_HOME/$BACKUP_ROOT/$TIMESTAMP"

usage() {
  cat <<'EOF'
install.sh - install dotfiles symlinks and local tools

Usage:
  ./install.sh                 # minimal on Linux, full on macOS
  ./install.sh --minimal       # shell/git/vim config + C tools; no packages, Python or sudo
  ./install.sh --full          # also packages, backup/restore, vaultcrypt, auther
  ./install.sh --dry-run
  ./install.sh --skip-brew     # full profile without Homebrew packages
  ./install.sh --skip-packages # full profile without apt packages (Linux)
  HOME=/some/other/home ./install.sh

Afterwards, run `dotfiles-doctor` any time to check the install.
EOF
}

log() {
  printf '%s\n' "$*"
}

section() {
  log ""
  log "== $* =="
}

run_cmd() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[dry-run] '
    printf '%q ' "$@"
    printf '\n'
  else
    "$@"
  fi
}

ensure_dir() {
  if [ ! -d "$1" ]; then
    log "Creating directory: $1"
    run_cmd mkdir -p "$1"
  fi
}

ensure_homebrew_packages() {
  local brew_bin

  if [ "$SKIP_BREW" -eq 1 ]; then
    log "Skipping Homebrew packages."
    return
  fi

  for brew_bin in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    if [ -x "$brew_bin" ]; then
      break
    fi
  done

  if [ ! -x "${brew_bin:-}" ]; then
    log "Homebrew not found. Install it from https://brew.sh, then re-run ./install.sh"
    return
  fi

  if "$brew_bin" bundle check --file "$DOTFILES_DIR/Brewfile" >/dev/null 2>&1; then
    log "Homebrew packages already installed."
    return
  fi

  log "Installing Homebrew packages from: $DOTFILES_DIR/Brewfile"
  run_cmd "$brew_bin" bundle --file "$DOTFILES_DIR/Brewfile"
}

ensure_linux_packages() {
  local package_manager missing=() package

  [ "$SKIP_PACKAGES" -eq 1 ] && { log "Skipping Linux packages."; return; }
  [ "$(uname -s)" = "Linux" ] || return

  if command -v apt-get >/dev/null 2>&1; then
    package_manager=apt-get
  else
    log "apt-get not found; skipping optional Linux packages."
    return
  fi

  # Keep the feature set aligned with Brewfile. fdfind/batcat are Ubuntu names.
  # Use the compiler pieces directly: build-essential also pulls dpkg-dev,
  # which requires bzip2 on some minimal Ubuntu/Pi images.
  for package in gcc make libc6-dev python3 python3-venv vim fzf ripgrep fd-find bat colordiff zoxide rclone; do
    if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed'; then
      continue
    fi
    if apt-cache show "$package" >/dev/null 2>&1; then
      missing+=("$package")
    else
      log "Linux package unavailable in apt sources; keeping feature optional: $package"
    fi
  done
  [ "${#missing[@]}" -gt 0 ] || { log "Linux packages already installed."; return; }

  log "Installing Linux packages: ${missing[*]}"
  if [ "$(id -u)" -eq 0 ]; then
    run_cmd "$package_manager" update
    run_cmd "$package_manager" install -y "${missing[@]}"
  elif command -v sudo >/dev/null 2>&1; then
    run_cmd sudo "$package_manager" update
    run_cmd sudo "$package_manager" install -y "${missing[@]}"
  else
    log "No sudo/root access; skipping Linux packages: ${missing[*]}"
  fi
}

# Move an existing file aside into ~/.dotfiles-backup/<timestamp>/, keeping
# its path relative to $HOME, so backups never land on PATH.
backup_path() {
  local path=$1
  local rel="${path#"$TARGET_HOME"/}"
  local backup="$BACKUP_DIR/$rel"

  ensure_dir "$(dirname "$backup")"
  log "Backing up existing file: $path -> $backup"
  run_cmd mv "$path" "$backup"
}

link_path() {
  local source=$1
  local target=$2

  ensure_dir "$(dirname "$target")"

  if [ -L "$target" ]; then
    if [ "$(readlink "$target")" = "$source" ]; then
      log "Symlink already correct: $target"
      return
    fi
    backup_path "$target"
  elif [ -e "$target" ]; then
    backup_path "$target"
  fi

  log "Linking: $target -> $source"
  run_cmd ln -s "$source" "$target"
  if [[ "$target" == *"/bin/"* ]]; then
    run_cmd chmod +x "$source"
  fi
}

link_manifest() {
  local entry
  for entry in "$@"; do
    link_path "$DOTFILES_DIR/${entry%%|*}" "$TARGET_HOME/${entry#*|}"
  done
}

# ~/.bash_profile is a small real file rather than a symlink, so installers
# that append PATH lines (bun, IDEs, ...) edit this machine's file, not the repo.
install_bash_profile_stub() {
  local target="$TARGET_HOME/.bash_profile"
  local source_line=". \"$DOTFILES_DIR/.bash_profile\""

  if [ -f "$target" ] && [ ! -L "$target" ] && grep -qF "$source_line" "$target"; then
    log "Bash profile stub already in place: $target"
    return
  fi

  if [ -L "$target" ] || [ -e "$target" ]; then
    backup_path "$target"
  fi

  log "Writing bash profile stub: $target"
  if [ "$DRY_RUN" -eq 1 ]; then
    return
  fi
  cat >"$target" <<EOF
# Machine-local login profile, written by $DOTFILES_DIR/install.sh.
# Shared settings live in the dotfiles repo; tool installers may append below.
$source_line
EOF
}

build_c_tool() {
  local name=$1
  local source="$DOTFILES_DIR/scripts/$name.c"
  local target="$TARGET_HOME/bin/$name"
  local tmp_target flags

  if [ ! -f "$source" ]; then
    printf 'Missing C source: %s\n' "$source" >&2
    exit 1
  fi

  if [ -x "$target" ] && [ "$target" -nt "$source" ]; then
    log "Up to date: $target"
    return
  fi

  # Word splitting is intended: flags is a list of compiler arguments.
  flags="$(c_tool_flags "$name")"
  log "Compiling: $target <- $source"
  if [ "$DRY_RUN" -eq 1 ]; then
    # shellcheck disable=SC2086
    run_cmd cc -O2 -Wall -Wextra -pedantic -std=c11 "$source" $flags -o "$target"
    return
  fi

  tmp_target="${target}.tmp.$$"
  # shellcheck disable=SC2086
  cc -O2 -Wall -Wextra -pedantic -std=c11 "$source" $flags -o "$tmp_target"
  chmod +x "$tmp_target"
  mv "$tmp_target" "$target"
}

build_c_tools() {
  local name

  if ! command -v cc >/dev/null 2>&1; then
    if [ "$PROFILE" = "minimal" ]; then
      log "No C compiler (cc) found; skipping ${C_TOOLS[*]}. The shell works without them."
      return
    fi
    if [ "$(uname -s)" = "Darwin" ]; then
      printf 'Missing compiler: cc. Run `xcode-select --install`, then re-run ./install.sh\n' >&2
    else
      printf 'Missing compiler: cc. Install gcc, or use ./install.sh --minimal\n' >&2
    fi
    exit 1
  fi

  for name in "${C_TOOLS[@]}"; do
    build_c_tool "$name"
  done
}

install_built_binary() {
  local build_script=$1
  local built_binary=$2
  local target=$3
  local tmp_target

  ensure_dir "$(dirname "$target")"

  if [ ! -f "$build_script" ]; then
    printf 'Missing build script: %s\n' "$build_script" >&2
    exit 1
  fi

  log "Building and installing: $target via $build_script"
  if [ "$DRY_RUN" -eq 1 ]; then
    run_cmd "$build_script"
    run_cmd cp "$built_binary" "$target"
    run_cmd chmod +x "$target"
    return
  fi

  "$build_script"

  if [ ! -f "$built_binary" ]; then
    printf 'Missing built binary after build: %s\n' "$built_binary" >&2
    exit 1
  fi

  tmp_target="${target}.tmp.$$"
  cp "$built_binary" "$tmp_target"
  chmod +x "$tmp_target"
  mv "$tmp_target" "$target"
}

file_hash() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    sha256sum "$1" | cut -d' ' -f1
  fi
}

install_python_app() {
  local app_name=$1
  local script_path=$2
  local requirements_path=$3
  local launcher_path=$4
  local venv_dir="$TARGET_HOME/.local/share/dotfiles/venvs/$app_name"
  local venv_python="$venv_dir/bin/python3"
  local stamp="$venv_dir/.requirements.sha256"
  local tmp_launcher wanted_hash

  if ! command -v python3 >/dev/null 2>&1; then
    log "python3 not found; skipping $app_name."
    return
  fi

  if [ ! -f "$script_path" ]; then
    printf 'Missing Python script: %s\n' "$script_path" >&2
    exit 1
  fi

  if [ ! -f "$requirements_path" ]; then
    printf 'Missing requirements file: %s\n' "$requirements_path" >&2
    exit 1
  fi

  ensure_dir "$(dirname "$launcher_path")"
  wanted_hash="$(file_hash "$requirements_path")"

  if [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$wanted_hash" ] &&
     "$venv_python" -c '' >/dev/null 2>&1; then
    log "Python app up to date: $app_name"
  elif [ "$DRY_RUN" -eq 1 ]; then
    log "Provisioning Python app: $app_name"
    run_cmd python3 -m venv "$venv_dir"
    run_cmd "$venv_python" -m pip install --quiet --upgrade pip
    run_cmd "$venv_python" -m pip install --quiet -r "$requirements_path"
  else
    # Build a fresh venv in place, keeping the old one to restore on failure,
    # so a broken python3 never leaves a half-upgraded venv behind.
    log "Provisioning Python app: $app_name"
    rm -rf "$venv_dir.old"
    [ -d "$venv_dir" ] && mv "$venv_dir" "$venv_dir.old"
    if python3 -m venv "$venv_dir" &&
       "$venv_python" -m pip install --quiet --upgrade pip &&
       "$venv_python" -m pip install --quiet -r "$requirements_path"; then
      printf '%s\n' "$wanted_hash" >"$stamp"
      rm -rf "$venv_dir.old"
    else
      rm -rf "$venv_dir"
      if [ -d "$venv_dir.old" ]; then
        mv "$venv_dir.old" "$venv_dir"
        log "WARNING: could not rebuild $app_name with $(python3 --version 2>&1); kept the previous install."
      else
        log "WARNING: could not install $app_name with $(python3 --version 2>&1); skipping."
        return
      fi
    fi
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    log "Writing launcher: $launcher_path"
    return
  fi

  chmod +x "$script_path"
  tmp_launcher="${launcher_path}.tmp.$$"
  cat >"$tmp_launcher" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec "$venv_python" "$script_path" "\$@"
EOF
  chmod +x "$tmp_launcher"
  mv "$tmp_launcher" "$launcher_path"
}

# Older installs left *.bak.<timestamp> copies next to their targets in ~/bin.
move_legacy_bin_backups() {
  local file found=0

  for file in "$TARGET_HOME"/bin/*.bak.*; do
    [ -e "$file" ] || [ -L "$file" ] || continue
    found=1
    backup_path "$file"
  done
  [ "$found" -eq 1 ] || log "No old backups in ~/bin."
}

write_profile_marker() {
  local marker="$TARGET_HOME/$PROFILE_FILE"

  ensure_dir "$(dirname "$marker")"
  if [ "$DRY_RUN" -eq 0 ]; then
    printf '%s\n' "$PROFILE" >"$marker"
  fi
}

for arg in "$@"; do
  case "$arg" in
    --minimal)
      PROFILE=minimal
      ;;
    --full)
      PROFILE=full
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
    --skip-brew)
      SKIP_BREW=1
      ;;
    --skip-packages)
      SKIP_PACKAGES=1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n\n' "$arg" >&2
      usage >&2
      exit 1
      ;;
  esac
done

PROFILE="${PROFILE:-$(default_profile)}"

section "Install ($PROFILE profile)"
log "Dotfiles source: $DOTFILES_DIR"
log "Target home:     $TARGET_HOME"

if [ "$PROFILE" = "full" ]; then
  section "Packages"
  if [ "$(uname -s)" = "Darwin" ]; then
    ensure_homebrew_packages
  else
    ensure_linux_packages
  fi
fi

section "Directories"
ensure_dir "$TARGET_HOME/bin"

section "Links"
install_bash_profile_stub
if [ -L "$TARGET_HOME/.vimrc" ] || [ -e "$TARGET_HOME/.vimrc" ]; then
  # ~/.vimrc would take precedence over ~/.vim/vimrc.
  backup_path "$TARGET_HOME/.vimrc"
fi
link_manifest "${COMMON_LINKS[@]}"
if [ "$PROFILE" = "full" ]; then
  link_manifest "${FULL_LINKS[@]}"
fi

section "Builds"
build_c_tools
if [ "$PROFILE" = "full" ]; then
  VAULTCRYPT_DIR="$DOTFILES_DIR/scripts/vaultcrypt"
  if [ -x "$VAULTCRYPT_DIR/build-vaultcrypt.sh" ]; then
    install_built_binary "$VAULTCRYPT_DIR/build-vaultcrypt.sh" "$VAULTCRYPT_DIR/vaultcrypt" "$TARGET_HOME/bin/vaultcrypt"
  else
    log "Skipping vaultcrypt: it lives in its own repo; install it to ~/bin/vaultcrypt from there."
  fi
  install_python_app \
    "auther" \
    "$DOTFILES_DIR/scripts/auther/auther.py" \
    "$DOTFILES_DIR/scripts/auther/requirements.txt" \
    "$TARGET_HOME/bin/auther"
fi

section "Cleanup"
move_legacy_bin_backups
write_profile_marker

section "Doctor"
if [ "$DRY_RUN" -eq 1 ]; then
  log "[dry-run] Would run: $DOTFILES_DIR/scripts/doctor.sh"
else
  HOME="$TARGET_HOME" "$DOTFILES_DIR/scripts/doctor.sh" || true
fi

section "Done"
log "Install complete ($PROFILE profile)."
log "Open a new shell or run: source ~/.bash_profile"
