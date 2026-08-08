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
case "$(uname -s 2>/dev/null)" in
  Darwin) IS_MAC=1; IS_LINUX=0; IS_OTHER=0 ;;
  Linux)  IS_MAC=0; IS_LINUX=1; IS_OTHER=0 ;;
  *)      IS_MAC=0; IS_LINUX=0; IS_OTHER=1 ;;
esac


########################################
# Environment
########################################
export EDITOR=vim

if [[ $IS_MAC -eq 1 ]]; then
  export CLICOLOR=1
  alias ls='ls -G'
else
  alias ls='ls --color=auto'
fi

# Load personal API keys if the file exists
if [ -f "$HOME/.secrets/api_keys.sh" ]; then
    source "$HOME/.secrets/api_keys.sh"
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

if command -v fd >/dev/null 2>&1 || command -v fdfind >/dev/null 2>&1; then
  FZF_FILE_COMMAND="fd"
  command -v fd >/dev/null 2>&1 || FZF_FILE_COMMAND="fdfind"
  export FZF_DEFAULT_COMMAND="$FZF_FILE_COMMAND --type f --hidden --follow --exclude .git"
  export FZF_CTRL_T_COMMAND="$FZF_DEFAULT_COMMAND"
fi

if command -v bat >/dev/null 2>&1 || command -v batcat >/dev/null 2>&1; then
  BAT_COMMAND="bat"
  command -v bat >/dev/null 2>&1 || BAT_COMMAND="batcat"
  export FZF_CTRL_T_OPTS="--preview '$BAT_COMMAND --style=numbers --color=always --line-range=:200 {}'"
fi

if command -v fzf >/dev/null 2>&1; then
  for fzf_script in \
    /opt/homebrew/opt/fzf/shell/completion.bash \
    /usr/local/opt/fzf/shell/completion.bash \
    /usr/share/doc/fzf/examples/completion.bash
  do
    if [ -f "$fzf_script" ]; then
      source "$fzf_script"
      break
    fi
  done

  for fzf_script in \
    /opt/homebrew/opt/fzf/shell/key-bindings.bash \
    /usr/local/opt/fzf/shell/key-bindings.bash \
    /usr/share/doc/fzf/examples/key-bindings.bash
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

# jump to iCloud Drive
icloud() {
  [[ $IS_MAC -eq 1 ]] || { printf 'iCloud is only available on macOS\\n' >&2; return 1; }
  cd "$HOME/Library/Mobile Documents/com~apple~CloudDocs" || return
}

# jump to Google Drive "My Drive" for the first configured account
drive() {
  local dir
  for dir in "$HOME"/Library/CloudStorage/GoogleDrive-*/"My Drive"; do
    [ -d "$dir" ] || continue
    cd "$dir" || return
    return
  done
  printf 'Google Drive path not found\n' >&2
  return 1
}

prompt_update() {
  local prompt_path
  local env_prompt=""
  local host_separator="@"

  if [[ $IS_MAC -eq 1 ]]; then
    host_separator=""
  fi

  prompt_path="$(short_path)"
  if command -v gitprompt >/dev/null 2>&1; then
    PROMPT_GIT="$(gitprompt)"
  else
    PROMPT_GIT=""
  fi

  if [[ -n "${VIRTUAL_ENV_PROMPT:-}" ]]; then
    env_prompt="${VIRTUAL_ENV_PROMPT} "
  elif [[ -n "${VIRTUAL_ENV:-}" ]]; then
    env_prompt="($(basename "${VIRTUAL_ENV}")) "
  elif [[ -n "${CONDA_DEFAULT_ENV:-}" ]]; then
    env_prompt="(${CONDA_DEFAULT_ENV}) "
  fi

  if [[ "$color_prompt" == "yes" ]]; then
    PS1="\[\e[96m\]${env_prompt}\[\e[m\][\[\e[92m\]\u\[\e[m\]${host_separator}\[\e[94m\]\h\[\e[m\]:\[\e[93m\]${prompt_path}\[\e[m\]]\[\e[91m\]${PROMPT_GIT}\[\e[m\] \\$ "
  else
    PS1="${env_prompt}[\u@\h:${prompt_path}]${PROMPT_GIT} \\$ "
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
if [[ $IS_MAC -eq 1 ]]; then
  alias o='open .'
elif command -v xdg-open >/dev/null 2>&1; then
  alias o='xdg-open .'
fi

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
  eval "$(zoxide init --cmd cd bash)"
fi


export PYTHONDONTWRITEBYTECODE=1
