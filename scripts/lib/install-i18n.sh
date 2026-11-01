# shellcheck shell=bash
# CDNCA 安装器界面语言（中文 / English），四个安装器共用。
#
# 唯一源文件：install-control.sh、install-node.sh、install-auth.sh、install-site.sh 在
# “BEGIN/END install-i18n” 标记之间逐字嵌入本文件，修改后运行
#   node scripts/sync-install-preflight.mjs
# 语言选择顺序：--lang zh|en（或 --lang=…）> 环境变量 CDNCA_INSTALL_LANG >
# LC_ALL / LC_MESSAGES / LANG（zh* 为中文，其余英文）。未显式指定且在终端交互时，
# install_lang_prompt 第一屏让用户选择。
# 文案写法：msg '中文' 'English'，原样输出对应语言（不追加换行）。未调用
# install_lang_init 时按中文输出，单独抽取函数的测试不受影响。
# 只影响屏幕提示；参数、默认值、安装步骤与日志里的英文技术串都不变。

INSTALL_LANG=${INSTALL_LANG:-}
INSTALL_LANG_AUTO=false
INSTALL_ARGS=()

install_lang_normalise() {
  case "$1" in
    zh | zh[-_]* | cn) printf 'zh' ;;
    en | en[-_]*) printf 'en' ;;
    *) return 1 ;;
  esac
}

# install_lang_init "$@"：确定语言，并把去掉 --lang 后的参数放进 INSTALL_ARGS。
install_lang_init() {
  local arg chosen='' expect=false
  INSTALL_ARGS=()
  for arg in "$@"; do
    if "$expect"; then chosen=$arg expect=false; continue; fi
    case "$arg" in
      --lang) expect=true ;;
      --lang=*) chosen=${arg#--lang=} ;;
      *) INSTALL_ARGS+=("$arg") ;;
    esac
  done
  if "$expect"; then
    printf '%s\n' 'error: missing value for --lang (zh or en)' >&2
    exit 2
  fi
  [ -n "$chosen" ] || chosen=${CDNCA_INSTALL_LANG:-}
  if [ -n "$chosen" ]; then
    INSTALL_LANG=$(install_lang_normalise "$chosen") || {
      printf '%s\n' 'error: --lang / CDNCA_INSTALL_LANG must be zh or en' >&2
      exit 2
    }
    INSTALL_LANG_AUTO=false
    return 0
  fi
  case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in
    zh*) INSTALL_LANG=zh ;;
    *) INSTALL_LANG=en ;;
  esac
  INSTALL_LANG_AUTO=true
}

# 交互安装第一屏：语言是自动判断的、stdin 与 stderr 都是终端时询问一次，回车用自动结果。
install_lang_prompt() {
  "$INSTALL_LANG_AUTO" && [ -t 0 ] && [ -t 2 ] || return 0
  local answer default=1
  [ "$INSTALL_LANG" = en ] && default=2
  printf 'Language / 语言:  1) 中文   2) English  [%s]: ' "$default" >&2
  IFS= read -r answer || answer=''
  case "${answer:-$default}" in
    1 | zh*) INSTALL_LANG=zh ;;
    2 | en*) INSTALL_LANG=en ;;
  esac
  INSTALL_LANG_AUTO=false
}

msg() {
  if [ "${INSTALL_LANG:-zh}" = en ]; then printf '%s' "$2"; else printf '%s' "$1"; fi
}
