export PATH="$HOME/bin:$PATH"
export PATH="$HOME/.local/bin:$PATH"
export PATH="$PATH:/Applications/Docker.app/Contents/Resources/bin/"

for brew_bin in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    if [ -x "$brew_bin" ]; then
        eval "$("$brew_bin" shellenv)"
        break
    fi
done

export BASH_SILENCE_DEPRECATION_WARNING=1

# Added by Antigravity
export PATH="$HOME/.antigravity/antigravity/bin:$PATH"

if [ -f "$HOME/.bashrc" ]; then
    source "$HOME/.bashrc"
fi
