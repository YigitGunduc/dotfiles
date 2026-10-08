# Login shell setup: PATH and environment only. Interactive settings live in
# .bashrc; machine-specific lines belong in ~/.bash_profile (the local stub
# written by install.sh), not in this file.

path_prepend() {
    [ -d "$1" ] || return 0
    case ":$PATH:" in
        *":$1:"*) ;;
        *) PATH="$1:$PATH" ;;
    esac
}

case "$(uname -s 2>/dev/null)" in
    Darwin)
        for brew_bin in /opt/homebrew/bin/brew /usr/local/bin/brew; do
            if [ -x "$brew_bin" ]; then
                eval "$("$brew_bin" shellenv)"
                break
            fi
        done
        unset brew_bin
        [ -d /Applications/Docker.app/Contents/Resources/bin ] &&
            PATH="$PATH:/Applications/Docker.app/Contents/Resources/bin"
        export BASH_SILENCE_DEPRECATION_WARNING=1
        ;;
esac

# Optional user-installed tools.
export BUN_INSTALL="$HOME/.bun"
path_prepend "$BUN_INSTALL/bin"
path_prepend "$HOME/.antigravity/antigravity/bin"

# Personal bins go last so they win over Homebrew and system versions.
path_prepend "$HOME/.local/bin"
path_prepend "$HOME/bin"
export PATH
unset -f path_prepend

if [ -f "$HOME/.bashrc" ]; then
    . "$HOME/.bashrc"
fi
