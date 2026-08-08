export PATH="$HOME/bin:$PATH"
export PATH="$HOME/.local/bin:$PATH"

case "$(uname -s 2>/dev/null)" in
    Darwin)
        export PATH="$PATH:/Applications/Docker.app/Contents/Resources/bin/"
        for brew_bin in /opt/homebrew/bin/brew /usr/local/bin/brew; do
            if [ -x "$brew_bin" ]; then
                eval "$("$brew_bin" shellenv)"
                break
            fi
        done
        export BASH_SILENCE_DEPRECATION_WARNING=1
        export PATH="$HOME/.antigravity/antigravity/bin:$PATH"
        ;;
    Linux)
        # Keep optional user-installed tools available on small servers too.
        export PATH="$HOME/.antigravity/antigravity/bin:$PATH"
        ;;
esac

if [ -f "$HOME/.bashrc" ]; then
    source "$HOME/.bashrc"
fi

# bun
export BUN_INSTALL="$HOME/.bun"
export PATH="$BUN_INSTALL/bin:$PATH"
