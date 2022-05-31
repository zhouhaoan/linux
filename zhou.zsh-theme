
local username="%n"
local path_prefix="%{$fg[yellow]%}["
local path_string="%{$fg[white]%}%~"
local path_postfix="%{$fg[yellow]%}]"
local prompt_string=" %{%F{14}%}❯%{%F{11}%}❯%{%F{10}%}❯% "
local error_prompt_string=" %{%F{9}%}❯%{%F{9}%}❯%{%F{9}%}❯% %{%F{15}%}"


local local_time="%T"
local newline=$'\n'
local line_mode=$'\n'

local host_name="%{%F{11}%}${username}%{$reset_color%}"
local time_string="%{$fg[cyan]%}${local_time}%{$reset_color%}"


# set the git_prompt_info text
ZSH_THEME_GIT_PROMPT_PREFIX="%{%F{10}%}("
ZSH_THEME_GIT_PROMPT_SUFFIX="%{%F{10}%})%{$reset_color%}"
ZSH_THEME_GIT_PROMPT_DIRTY="♻"
ZSH_THEME_GIT_PROMPT_CLEAN=""

RPROMPT+='$(git_prompt_info)$(git_prompt_status)%{$reset_color%} '
PROMPT='${host_name}⌚${time_string} ${path_prefix}${path_string}${path_postfix}${newline}\
%(?:${prompt_string}:${error_prompt_string}) '
# PROMPT+=' %{%F{15}%}'
PROMPT+='%{$reset_color%}'


ZSH_THEME_GIT_PROMPT_ADDED="%{$fg[cyan]%} ✈"
ZSH_THEME_GIT_PROMPT_MODIFIED="%{$fg[yellow]%} ✭"
ZSH_THEME_GIT_PROMPT_DELETED="%{$fg[red]%} ✗"
ZSH_THEME_GIT_PROMPT_RENAMED="%{$fg[blue]%} ➦"
ZSH_THEME_GIT_PROMPT_UNMERGED="%{$fg[magenta]%} ✂"
ZSH_THEME_GIT_PROMPT_UNTRACKED="%{$fg[magenta]%} ✦"
