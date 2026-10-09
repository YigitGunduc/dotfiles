# Dotfiles

Personal Bash, Git and Vim setup with a few small native CLI tools.

## Quick start

```bash
git clone git@github.com:YigitGunduc/dotfiles.git ~/.dotfiles
~/.dotfiles/install.sh
exec bash -l
```

Re-running `install.sh` is safe and fast: links that are already correct are
left alone, and tools are only rebuilt when their source changed.

## Profiles

The installer picks a profile from the OS. Override it with `--minimal` or `--full`.

| | **minimal** (Linux default) | **full** (macOS default) |
|---|---|---|
| Bash, Git, Vim, tmux config | ✓ | ✓ |
| `minifetch`, `gitprompt`, `ftree`, `shamir` (built with `cc`) | ✓ if `cc` exists | ✓ (requires `cc`) |
| Packages ([Brewfile](Brewfile) / apt) | – | ✓ |
| `backup`, `restore`, `.vaultcrypt.conf` | – | ✓ |
| `auther` (Python venv) | – | ✓ |
| Needs sudo, network, Python | no | for packages and auther |

The minimal profile needs nothing beyond Bash; `fzf`, `rg`, `fd`, `bat`,
`zoxide` and `colordiff` are used automatically when they happen to be installed.
Without a C compiler it skips the tools and the prompt simply has no git branch.

Other options: `--dry-run`, `--skip-brew`, `--skip-packages` (Linux full),
and `HOME=/other/home ./install.sh`.

On a new Mac, install the compiler with `xcode-select --install` and Homebrew
from <https://brew.sh> first.

## Doctor

```bash
dotfiles-doctor
```

Runs at the end of every install and checks links, built tools (including
stale builds), optional commands and, for the full profile, Homebrew packages,
vaultcrypt, rclone, the Keychain item, auther and `~/.secrets`. It also lists
files in `~/bin` that the dotfiles don't manage. Exits non-zero if something is broken.

## Layout

- `~/.bash_profile` is a small **local** file written by the installer that
  sources [.bash_profile](.bash_profile). Tool installers (bun, IDEs, …) that
  append PATH lines edit that local file, not this repo.
- [.bash_profile](.bash_profile): PATH and environment only.
- [.bashrc](.bashrc): interactive settings, prompt, aliases.
- `~/.bashrc.local`: machine-specific interactive settings
  (see [.bashrc.local.example](.bashrc.local.example)).
- `~/.secrets/api_keys.sh`: sourced by `.bashrc` if present (keep it `chmod 700`).
- [scripts/lib/manifest.sh](scripts/lib/manifest.sh): what each profile links and builds.
- When install replaces an existing file, it is moved to
  `~/.dotfiles-backup/<timestamp>/`.

## Shell

- Prompt: `[user@host:/s/h/o/rt/path] (branch*)`. Path, branch and virtualenv
  are inserted as plain text, so odd folder or branch names can't run code.
- History: 50k entries, shared across sessions, timestamps, no duplicates.
- `minifetch` runs in top-level interactive shells; `zoxide` replaces `cd` when installed.
- `fzf` uses `fd` for files and `bat` for previews (`Ctrl-T`, `Ctrl-R`).
- `vim` with no arguments opens an `fzf` file picker when `fzf` is installed.

Functions: `mkcd <dir>`, `up [N]`, `icloud` (macOS), `drive` (Google Drive, macOS).

Aliases: `..`, `...`, `l`, `la`, `ll`, `v`, `h`, `c`, `o` (open current dir),
colored `grep`/`diff`. On Linux only: `apt`/`install`/`update`/`upgrade`/`remove`
run through `sudo apt`.

## Vim

[.vim/vimrc](.vim/vimrc): built-in features only, vendored gruvbox, system
clipboard, persistent undo, relative numbers, 2-space indent (4 for Python),
trailing whitespace trimmed on save (except Markdown).

Leader is `Space`:

| Keys | Action |
|---|---|
| `Ctrl-h/j/k/l` | move between splits |
| `Space w` | save |
| `Space Space` | clear search highlight |
| `Space e` | file explorer (`:Lex 20`) |
| `Space y f` / `Space y d` | copy file path / directory |

## tmux

[.tmux.conf](.tmux.conf): plugin-free, prefix `Ctrl-a`, mouse on,
windows numbered from 1 (renumbered on close), 100k scrollback, true color and a gruvbox status bar.
tmux itself is installed by the full profile; minimal only links the config.

| Keys | Action |
|---|---|
| `Ctrl-h/j/k/l` | move between panes (passed through to vim and fzf) |
| `prefix \|` / `prefix -` | split side by side / stacked, in the current directory |
| `prefix H/J/K/L` | resize pane (repeatable) |
| `prefix Ctrl-l` | clear the screen (plain `Ctrl-l` moves panes) |
| `prefix Ctrl-a` | send a literal `Ctrl-a` (start of line in bash) |
| `prefix [` then `v`, `y` | copy mode: select, copy to the system clipboard |
| `prefix r` | reload the config |

## Git

[.gitconfig](.gitconfig): `pull.rebase`, `fetch.prune`, aliases `st`, `co`, `br`, `lg`.
Repos under `~/Developer/msu/` use [.gitconfig.msu](.gitconfig.msu).

## Tools

| Tool | Source | What it does |
|---|---|---|
| `minifetch` | [scripts/minifetch.c](scripts/minifetch.c) | system summary with ASCII art (`--no-color`, `--field NAME`) |
| `gitprompt` | [scripts/gitprompt.c](scripts/gitprompt.c) | branch and dirty marker for the prompt, read straight from `.git` |
| `ftree` | [scripts/ftree.c](scripts/ftree.c) | tree viewer: `ftree -a -L 2`, `ftree -I .git,node_modules --sort size -s` |
| `shamir` | [scripts/shamir.c](scripts/shamir.c) | Shamir secret sharing: `shamir split -t 2 -n 3 < secret`, `shamir combine` |
| `auther` | [scripts/auther/auther.py](scripts/auther/auther.py) | TOTP codes from the Keychain: `auther`, `auther add`, `auther copy <name>` |
| `backup` | [scripts/backup.sh](scripts/backup.sh) | encrypted snapshot of a folder with vaultcrypt, uploaded with rclone |
| `restore` | [scripts/restore.sh](scripts/restore.sh) | decrypt a vaultcrypt backup |
| `dotfiles-doctor` | [scripts/doctor.sh](scripts/doctor.sh) | check the install |

`backup` and `restore` need `vaultcrypt`, which now lives in its own repo;
install it to `~/bin/vaultcrypt` from there. Note that
[.vaultcrypt.conf](.vaultcrypt.conf) excludes archives (`*.zip`, `*.tar`, …),
keys (`*.pem`, `*.key`) and build/log folders from backups.

Notes and plans live in [docs/](docs/).
