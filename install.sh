#!/usr/bin/env bash

set -euo pipefail

DOTFILES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_HOME="${HOME}"
DRY_RUN=0
SKIP_BREW=0
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

usage() {
  cat <<'EOF'
install.sh - install dotfiles symlinks and local tools

Usage:
  ./install.sh
  ./install.sh --dry-run
  ./install.sh --skip-brew
  HOME=/some/other/home ./install.sh
EOF
}

log() {
  printf '%s\n' "$*"
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
    log "Homebrew not found. Skipping Brewfile packages."
    return
  fi

  if "$brew_bin" bundle check --file "$DOTFILES_DIR/Brewfile" >/dev/null 2>&1; then
    log "Homebrew packages already installed."
    return
  fi

  log "Installing Homebrew packages from: $DOTFILES_DIR/Brewfile"
  run_cmd "$brew_bin" bundle --file "$DOTFILES_DIR/Brewfile"
}

backup_path() {
  local path=$1
  local backup="${path}.bak.${TIMESTAMP}"
  log "Backing up existing file: $path -> $backup"
  run_cmd mv "$path" "$backup"
}

link_path() {
  local source=$1
  local target=$2
  local parent

  parent="$(dirname "$target")"
  ensure_dir "$parent"

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
}

build_c_tool() {
  local source=$1
  local target=$2
  local parent tmp_target
  shift 2

  parent="$(dirname "$target")"
  ensure_dir "$parent"

  if [ ! -f "$source" ]; then
    printf 'Missing C source: %s\n' "$source" >&2
    exit 1
  fi

  if ! command -v cc >/dev/null 2>&1; then
    printf 'Missing compiler: cc\n' >&2
    exit 1
  fi

  if [ -L "$target" ] || [ -d "$target" ]; then
    backup_path "$target"
  fi

  log "Compiling: $target <- $source"
  if [ "$DRY_RUN" -eq 1 ]; then
    run_cmd cc -O2 -Wall -Wextra -pedantic -std=c11 "$source" "$@" -o "$target"
    return
  fi

  tmp_target="${target}.tmp.$$"
  cc -O2 -Wall -Wextra -pedantic -std=c11 "$source" "$@" -o "$tmp_target"
  chmod +x "$tmp_target"
  mv "$tmp_target" "$target"
}

ensure_python3() {
  if ! command -v python3 >/dev/null 2>&1; then
    printf 'Missing runtime: python3\n' >&2
    exit 1
  fi
}

install_python_app() {
  local app_name=$1
  local script_path=$2
  local requirements_path=$3
  local launcher_path=$4
  local venv_dir="$TARGET_HOME/.local/share/dotfiles/venvs/$app_name"
  local venv_python="$venv_dir/bin/python3"
  local venv_pip="$venv_dir/bin/pip"
  local parent tmp_launcher

  ensure_python3

  if [ ! -f "$script_path" ]; then
    printf 'Missing Python script: %s\n' "$script_path" >&2
    exit 1
  fi

  if [ ! -f "$requirements_path" ]; then
    printf 'Missing requirements file: %s\n' "$requirements_path" >&2
    exit 1
  fi

  ensure_dir "$venv_dir"
  parent="$(dirname "$launcher_path")"
  ensure_dir "$parent"

  log "Provisioning Python app: $app_name"
  if [ "$DRY_RUN" -eq 1 ]; then
    run_cmd python3 -m venv "$venv_dir"
    run_cmd "$venv_python" -m pip install --upgrade pip
    run_cmd "$venv_pip" install -r "$requirements_path"
    log "Writing launcher: $launcher_path"
    return
  fi

  python3 -m venv "$venv_dir"
  "$venv_python" -m pip install --upgrade pip
  "$venv_pip" install -r "$requirements_path"

  chmod +x "$script_path"

  if [ -L "$launcher_path" ] || [ -d "$launcher_path" ]; then
    backup_path "$launcher_path"
  elif [ -e "$launcher_path" ]; then
    backup_path "$launcher_path"
  fi

  tmp_launcher="${launcher_path}.tmp.$$"
  cat >"$tmp_launcher" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec "$venv_python" "$script_path" "\$@"
EOF
  chmod +x "$tmp_launcher"
  mv "$tmp_launcher" "$launcher_path"
}

for arg in "$@"; do
  case "$arg" in
    --dry-run)
      DRY_RUN=1
      ;;
    --skip-brew)
      SKIP_BREW=1
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

log "Dotfiles source: $DOTFILES_DIR"
log "Target home:     $TARGET_HOME"

ensure_homebrew_packages

ensure_dir "$TARGET_HOME/bin"

MINIFETCH_SOURCE="$DOTFILES_DIR/scripts/minifetch.c"

link_path "$DOTFILES_DIR/.bashrc" "$TARGET_HOME/.bashrc"
link_path "$DOTFILES_DIR/.bash_profile" "$TARGET_HOME/.bash_profile"
link_path "$DOTFILES_DIR/.gitconfig" "$TARGET_HOME/.gitconfig"
if [ -L "$TARGET_HOME/.vimrc" ] || [ -e "$TARGET_HOME/.vimrc" ]; then
  backup_path "$TARGET_HOME/.vimrc"
fi
link_path "$DOTFILES_DIR/.vim/vimrc" "$TARGET_HOME/.vim/vimrc"
link_path "$DOTFILES_DIR/.vim/colors/gruvbox.vim" "$TARGET_HOME/.vim/colors/gruvbox.vim"
if [ "$(uname -s)" = "Darwin" ]; then
  build_c_tool "$MINIFETCH_SOURCE" "$TARGET_HOME/bin/minifetch" \
    -framework ApplicationServices \
    -framework CoreFoundation \
    -framework IOKit
  build_c_tool "$DOTFILES_DIR/scripts/vaultcrypt.c" "$TARGET_HOME/bin/vaultcrypt"
else
  build_c_tool "$MINIFETCH_SOURCE" "$TARGET_HOME/bin/minifetch"
  log "Skipping vaultcrypt: requires macOS CommonCrypto."
fi
build_c_tool "$DOTFILES_DIR/scripts/gitprompt.c" "$TARGET_HOME/bin/gitprompt"
build_c_tool "$DOTFILES_DIR/scripts/ftree.c" "$TARGET_HOME/bin/ftree"
build_c_tool "$DOTFILES_DIR/scripts/shamir.c" "$TARGET_HOME/bin/shamir"
install_python_app \
  "auther" \
  "$DOTFILES_DIR/scripts/auther.py" \
  "$DOTFILES_DIR/scripts/auther-requirements.txt" \
  "$TARGET_HOME/bin/auther"
link_path "$DOTFILES_DIR/scripts/vim" "$TARGET_HOME/bin/vim"

log ""
log "Install complete."
log "Open a new shell or run: source ~/.bash_profile"
