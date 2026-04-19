# Dotfiles

Minimal personal dotfiles for Bash and Vim, with a few small native CLI tools.

## Install

Install the dotfiles and compile local tools:

```bash
cd ~/.dotfiles
./install.sh
source ~/.bash_profile
```

`install.sh` also installs Homebrew packages from [Brewfile](/Users/anakin/.dotfiles/Brewfile) when Homebrew is available. If you only want the symlinks and local binaries:

```bash
./install.sh --skip-brew
```

Dry run:

```bash
./install.sh --dry-run
```

## What Gets Installed

`install.sh` does three things:

- Installs Homebrew packages from [Brewfile](/Users/anakin/.dotfiles/Brewfile) when Homebrew is available
- Symlinks:
  - `.bashrc`
  - `.bash_profile`
  - `.gitconfig`
  - `.vim/vimrc`
  - `.vim/colors/gruvbox.vim`
- Installs to `~/bin`:
  - `minifetch`
  - `gitprompt`
  - `ftree`
  - `vaultcrypt`
  - `vim`

If a target already exists, it gets backed up to `*.bak.<timestamp>`.

## Dependencies

Current Homebrew packages from [Brewfile](/Users/anakin/.dotfiles/Brewfile):

- `bat`: syntax-highlighted file viewer, also used for `fzf` previews
- `bash-completion`: lightweight programmable completion for Bash commands
- `colordiff`: colorized `diff`
- `fd`: fast file finder, used as the `fzf` file source
- `fzf`: fuzzy finder for terminal selection
- `ripgrep`: fast file content search via `rg`
- `zoxide`: smarter directory jumping with `z` and `zi`

System/runtime assumptions:

- Bash
- Vim with `+clipboard`
- `cc` to compile local C tools
- Homebrew at `/opt/homebrew/bin/brew` or `/usr/local/bin/brew`
- macOS `open` and Docker Desktop path are assumed in `.bash_profile`

## Sensitive Files

For encrypted local secrets, this repo ships `vaultcrypt`, a contained native
binary built from a single C file with no Homebrew dependency.

Properties:

- macOS only
- no Brew dependency
- single source file: [scripts/vaultcrypt.c](/Users/anakin/.dotfiles/scripts/vaultcrypt.c)
- file format is documented in the source header for recovery
- algorithms are fixed:
  - `PBKDF2-HMAC-SHA256`
  - `AES-256-CTR`
  - `HMAC-SHA256` over `header || ciphertext`

Examples:

```bash
vaultcrypt enc -i wallet-seed.txt
vaultcrypt dec -i wallet-seed.txt.vlt -o -
vaultcrypt info -i wallet-seed.txt.vlt
vaultcrypt info --json -i wallet-seed.txt.vlt
vaultcrypt selftest
```

Practical rules:

- Do not commit plaintext seed phrases to this repo
- Keep the passphrase separate from the ciphertext
- Test decryption immediately after creating a backup
- Use `-o -` or `--stdout` explicitly if you want decrypted plaintext on stdout
- Use `--recovery-json PATH` if you want a separate machine-readable recovery note

Recovery note:
- the ciphertext stores the salt, IV, and PBKDF2 iteration count
- if you lose the tool, the source comment at the top of `vaultcrypt.c` describes the exact format and key split needed to decrypt with another implementation

## Shell

Shell behavior comes from [.bashrc](/Users/anakin/.dotfiles/.bashrc) and [.bash_profile](/Users/anakin/.dotfiles/.bash_profile).

### Startup

`.bash_profile`:

- prepends `~/bin`
- prepends `~/.local/bin`
- appends Docker Desktop CLI path
- runs `brew shellenv` before loading `.bashrc`
- supports both `/opt/homebrew/bin/brew` and `/usr/local/bin/brew`
- suppresses Bash deprecation warnings
- prepends Antigravity path if present
- loads `.bashrc`

`.bashrc`:

- exits immediately for non-interactive shells
- loads Homebrew Bash completion when available
- enables:
  - `histappend`
  - `checkwinsize`
  - `cmdhist`
  - `extglob`
- sets:
  - `HISTSIZE=50000`
  - `HISTFILESIZE=100000`
  - `HISTCONTROL=ignoreboth:erasedups`
  - `HISTTIMEFORMAT="%d-%m-%Y %H:%M:%S "`
  - `EDITOR=vim`
- runs `minifetch` on top-level interactive shells if installed
- initializes `zoxide` at the end

### Prompt

The prompt shows:

- username
- hostname
- shortened current path
- current git branch and dirty marker via `gitprompt`

Notes:

- path is compressed by `short_path()`
- git state is computed by the compiled `gitprompt` helper, not inline shell `git` calls

### Aliases

Current shell aliases:

- `..='cd ..'`
- `...='cd ../../../'`
- `icloud='cd ~/Library/Mobile\ Documents/com~apple~CloudDocs/'`
- `l='ls -lah'`
- `la='ls -lAh'`
- `ll='ls -lh'`
- `v='vim'`
- `h='history'`
- `c='clear'`
- `o='open .'`

Diff and grep:

- `diff='colordiff -u'` if `colordiff` exists, otherwise `diff='diff -u'`
- `grep='grep --color=auto'`
- `egrep='grep -E --color=auto'`
- `fgrep='grep -F --color=auto'`

Linux-only package aliases:

- `apt='sudo apt'`
- `apt-get='sudo apt'`
- `update='apt update'`
- `upgrade='apt upgrade'`
- `install='apt install'`
- `remove='apt remove'`

### Shell Functions

- `short_path()`: compresses `$PWD` for the prompt
- `mkcd <dir>`: creates a directory and enters it
- `up [N]`: moves up `N` directories
- `prompt_update()`: rebuilds `PS1` and queries `gitprompt`

### File and Content Search

Configured behavior:

- `fd` is the default file source for `fzf`
- `bat` is used for `fzf` file previews
- `ripgrep` is separate and used directly via `rg`

Examples:

- find files by name:
  ```bash
  fd minifetch
  ```
- fuzzy-pick files:
  ```bash
  fd | fzf
  ```
- search file contents:
  ```bash
  rg "pattern"
  ```
- fuzzy-pick from content matches:
  ```bash
  rg "pattern" | fzf
  ```

### FZF

Configured in `.bashrc`:

- `FZF_DEFAULT_COMMAND='fd --type f --hidden --follow --exclude .git'`
- `FZF_CTRL_T_COMMAND="$FZF_DEFAULT_COMMAND"`
- `FZF_CTRL_T_OPTS='--preview "bat --style=numbers --color=always --line-range=:200 {}"'` when `bat` exists

Also sources Homebrew `fzf` Bash integration when available:

- `/opt/homebrew/opt/fzf/shell/completion.bash`
- `/opt/homebrew/opt/fzf/shell/key-bindings.bash`
- fallback to `/usr/local/opt/fzf/...`

Practical usage:

- `Ctrl-T`: fuzzy-pick a file path into the current command line
- `Ctrl-R`: fuzzy-search shell history from the upstream `fzf` script

### Zoxide

Configured with:

```bash
eval "$(zoxide init bash)"
```

Usage:

- `z foo`: jump to a frequently used directory matching `foo`
- `zi`: interactive directory picker

## Vim

Behavior comes from [.vim/vimrc](/Users/anakin/.dotfiles/.vim/vimrc).

### Goals

- modern defaults
- minimal config
- built-in features only
- system clipboard by default
- vendored `gruvbox` colorscheme for consistent installs

### Core Features

- UTF-8 encoding
- syntax highlighting
- filetype plugins and indent
- `gruvbox` if available, otherwise Vim continues silently
- line numbers and relative numbers
- cursor line
- sign column always on
- split right / split below
- mouse enabled
- persistent undo
- case-smart searching
- search highlighting
- autoindent and smartindent

### Clipboard

Clipboard is the first priority in the current Vim setup.

Configured with:

```vim
set clipboard=unnamed,unnamedplus
```

That means normal Vim copy/paste uses the system clipboard when supported:

- `y`
- `yy`
- `p`
- `P`

This machine’s Vim supports `+clipboard`.

### Vim Leader

Leader is:

```vim
let mapleader=" "
```

So the leader key is `Space`.

### Vim Keybindings

Current custom mappings:

- `Ctrl-h`: move to left split
- `Ctrl-j`: move to lower split
- `Ctrl-k`: move to upper split
- `Ctrl-l`: move to right split
- `Space w`: save current file
- `Space Space`: clear search highlighting
- `Space e`: open netrw explorer with `:Lex 20`
- `Space y f`: copy current file path to clipboard
- `Space y d`: copy current file directory to clipboard

### Vim Autocommands

- trim trailing whitespace on save, except Markdown
- restore last cursor position on reopen
- Python uses 4 spaces
- JS/TS/TSX/JSX/HTML/CSS use 2 spaces

## Git

Git behavior comes from [.gitconfig](/Users/anakin/.dotfiles/.gitconfig).

Defaults:

- `pull.rebase = true`
- `fetch.prune = true`
- `init.defaultBranch = master`

Aliases:

- `git st`: `git status -sb`
- `git co`: `git checkout`
- `git br`: `git branch`
- `git lg`: `git log --graph --decorate --oneline --all`

## Local Tools

### `minifetch`

Source: [scripts/minifetch.c](/Users/anakin/.dotfiles/scripts/minifetch.c)

Purpose:

- prints a compact system summary with ASCII art

Fields shown:

- OS
- Host
- Kernel
- Uptime
- Shell
- Terminal
- Resolution
- CPU
- GPU
- Memory
- Battery
- Local IP
- Disk

Usage:

```bash
minifetch
minifetch --no-color
```

### `gitprompt`

Source: [scripts/gitprompt.c](/Users/anakin/.dotfiles/scripts/gitprompt.c)

Purpose:

- fast git prompt helper for Bash
- prints current branch and `*` for dirty state

Example output:

```text
 (main*)
```

### `ftree`

Source: [scripts/ftree.c](/Users/anakin/.dotfiles/scripts/ftree.c)

Purpose:

- small tree-style directory viewer

Examples:

```bash
ftree
ftree -a -L 2 ~/Developer
ftree -I .git,node_modules --sort size -s
```

## Local Overrides

If present, `.bashrc` loads:

```bash
~/.bashrc.local
```

Use that for machine-specific overrides without changing the repo.
