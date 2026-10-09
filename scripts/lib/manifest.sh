# What each install profile manages. Sourced by install.sh and doctor.sh.
# Links are "repo-relative source|home-relative target".

COMMON_LINKS=(
  ".bashrc|.bashrc"
  ".gitconfig|.gitconfig"
  ".gitconfig.msu|.gitconfig.msu"
  ".tmux.conf|.tmux.conf"
  ".vim/vimrc|.vim/vimrc"
  ".vim/colors/gruvbox.vim|.vim/colors/gruvbox.vim"
  "scripts/vim|bin/vim"
  "scripts/doctor.sh|bin/dotfiles-doctor"
)

FULL_LINKS=(
  ".vaultcrypt.conf|.vaultcrypt.conf"
  "scripts/backup.sh|bin/backup"
  "scripts/restore.sh|bin/restore"
)

# Built from scripts/<name>.c into ~/bin/<name>. Plain libc, no packages needed.
C_TOOLS=(minifetch gitprompt ftree shamir)

# Commands .bashrc uses when present. Missing ones only lose a convenience.
OPTIONAL_COMMANDS=(tmux fzf rg zoxide colordiff)

PROFILE_FILE=".local/share/dotfiles/profile"
BACKUP_ROOT=".dotfiles-backup"

default_profile() {
  if [ "$(uname -s)" = "Darwin" ]; then
    echo full
  else
    echo minimal
  fi
}

c_tool_flags() {
  if [ "$1" = "minifetch" ] && [ "$(uname -s)" = "Darwin" ]; then
    echo "-framework ApplicationServices -framework CoreFoundation -framework IOKit"
  fi
}
