# Interactive shell config.


########################################
# Exit if not interactive
########################################
case $- in *i*) ;; *) return ;; esac


########################################
# Shell Behavior & History
########################################
shopt -s histappend checkwinsize cmdhist extglob
HISTSIZE=50000
HISTFILESIZE=100000
HISTCONTROL=ignoreboth:erasedups
HISTTIMEFORMAT="%d-%m-%Y %H:%M:%S "
PROMPT_COMMAND='history -a; history -n'


########################################
# Platform detection
########################################
case "$(uname -s)" in
  Darwin) IS_MAC=1 ;;
  Linux)  IS_LINUX=1 ;;
  *)      IS_OTHER=1 ;;
esac


########################################
# Environment
########################################
export EDITOR=vim

if [[ $IS_MAC ]]; then
  export CLICOLOR=1
  alias ls='ls -G'
else
  alias ls='ls --color=auto'
fi


########################################
# Tooling
########################################
for completion_script in \
  "${HOMEBREW_PREFIX:-}/etc/profile.d/bash_completion.sh" \
  /opt/homebrew/etc/profile.d/bash_completion.sh \
  /usr/local/etc/profile.d/bash_completion.sh
do
  if [ -r "$completion_script" ]; then
    source "$completion_script"
    break
  fi
done

if command -v fd >/dev/null 2>&1; then
  export FZF_DEFAULT_COMMAND='fd --type f --hidden --follow --exclude .git'
  export FZF_CTRL_T_COMMAND="$FZF_DEFAULT_COMMAND"
fi

if command -v bat >/dev/null 2>&1; then
  export FZF_CTRL_T_OPTS='--preview "bat --style=numbers --color=always --line-range=:200 {}"'
fi

if command -v fzf >/dev/null 2>&1; then
  for fzf_script in \
    /opt/homebrew/opt/fzf/shell/completion.bash \
    /usr/local/opt/fzf/shell/completion.bash
  do
    if [ -f "$fzf_script" ]; then
      source "$fzf_script"
      break
    fi
  done

  for fzf_script in \
    /opt/homebrew/opt/fzf/shell/key-bindings.bash \
    /usr/local/opt/fzf/shell/key-bindings.bash
  do
    if [ -f "$fzf_script" ]; then
      source "$fzf_script"
      break
    fi
  done
fi

########################################
# Utility Functions
########################################

# Compact current directory path (/h/u/D/projects)
short_path() {
  local IFS='/'; local -a parts; local out="/"
  read -r -a parts <<< "$PWD"
  for ((i=1; i<${#parts[@]}; i++)); do
    local seg="${parts[i]}"
    if (( i == ${#parts[@]} - 1 )); then out+="$seg"
    else out+="${seg:0:1}/"; fi
  done
  printf '%s' "${out%/}"
}

# make + cd into dir
mkcd() { mkdir -p -- "$1" && cd -- "$1" || return; }

# go up N dirs
up() {
  local n="${1:-1}" path=""
  while (( n-- > 0 )); do path+="../"; done
  cd "$path" || return
}

prompt_update() {
  local prompt_path

  prompt_path="$(short_path)"
  if command -v gitprompt >/dev/null 2>&1; then
    PROMPT_GIT="$(gitprompt)"
  else
    PROMPT_GIT=""
  fi

  if [[ "$color_prompt" == "yes" ]]; then
    PS1="[\[\e[92m\]\u\[\e[m\]\[\e[94m\]\h\[\e[m\]:\[\e[93m\]${prompt_path}\[\e[m\]]\[\e[91m\]${PROMPT_GIT}\[\e[m\] \\$ "
  else
    PS1="[\u@\h:${prompt_path}]${PROMPT_GIT} \\$ "
  fi
}

########################################
# Prompt
########################################
if command -v tput >/dev/null && tput setaf 1 >/dev/null 2>&1; then
  color_prompt=yes
fi

PROMPT_COMMAND='history -a; history -n; prompt_update'


########################################
# Aliases
########################################
# Navigation
alias ..='cd ..'
alias ...='cd ../../../'
alias icloud='cd ~/Library/Mobile\ Documents/com~apple~CloudDocs/'

# Listing
alias l='ls -lah'
alias la='ls -lAh'
alias ll='ls -lh'

# Diff & Grep
if command -v colordiff >/dev/null; then
  alias diff='colordiff -u'
else
  alias diff='diff -u'
fi
alias grep='grep --color=auto'
alias egrep='grep -E --color=auto'
alias fgrep='grep -F --color=auto'

# Package shortcuts (Linux only)
if [[ $IS_LINUX ]]; then
  alias apt='sudo apt'
  alias apt-get='sudo apt'
  alias update='apt update'
  alias upgrade='apt upgrade'
  alias install='apt install'
  alias remove='apt remove'
fi

# Misc
alias v='vim'
alias h='history'
alias c='clear'
alias o='open .'           # keep native macOS open

if [ -f "$HOME/.bashrc.local" ]; then
  source "$HOME/.bashrc.local"
fi


########################################
# Startup
########################################
if [[ -t 1 && "${TERM:-}" != "dumb" && "${SHLVL:-1}" -eq 1 ]] && command -v minifetch >/dev/null 2>&1; then
  minifetch
fi

if command -v zoxide >/dev/null 2>&1; then
  eval "$(zoxide init bash)"
fi
