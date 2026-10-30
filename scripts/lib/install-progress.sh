# shellcheck shell=bash
# CDNCA 安装进度展示（主控与节点共用）。
#
# 唯一源文件：scripts/install-control.sh 与 scripts/install-node.sh 在
# “BEGIN/END install-progress” 标记之间逐字嵌入本文件，修改后运行
#   node scripts/sync-install-preflight.mjs
# 只做展示：不改变任何安装步骤、参数、默认值或顺序。未调用 progress_init 时
# 所有函数都原样直通（progress_run 直接执行命令），单独抽取函数的测试不受影响。
#
# 安装器在嵌入块之前定义 PROGRESS_LABEL（行前缀）、PROGRESS_ROLE（日志名）与
# PROGRESS_STAGES，每项为 “名称|最短秒|最长秒|标记”，标记 interactive 表示该
# 阶段含人工输入，不参与剩余时间校准。main 里依次调用无参的 progress_init、
# progress_stage（每次进入下一阶段）与 progress_done，不改变原有步骤。
# 输出写 stderr；stderr 是终端（且 TERM 不是 dumb）时用 \r 单行刷新，
# 否则（curl | bash 管道、SSH 无终端、CI、重定向到文件）每次一整行。
# NO_COLOR 非空时不输出颜色。完整原始输出写入 PROGRESS_LOG_DIR 下的安装日志。

PROGRESS_LOG_DIR=${PROGRESS_LOG_DIR:-/var/log}
PROGRESS_LOG=''
PROGRESS_PREFIX=''
PROGRESS_TTY=false
PROGRESS_COLOR=false
PROGRESS_INLINE=false
PROGRESS_CURRENT=0
PROGRESS_PASSED=0
PROGRESS_START=0
PROGRESS_STAGE_START=0
PROGRESS_ACTUAL=0
PROGRESS_NOMINAL=0
PROGRESS_WAIT_LABEL=''
PROGRESS_WAIT_START=0
PROGRESS_WAIT_NEXT=0
PROGRESS_HEARTBEAT=''
# 安装器知道版本后设置（失败行与安装日志带上版本）。
PROGRESS_VERSION=''

progress_clock() { printf '%d:%02d' $(($1 / 60)) $(($1 % 60)); }

# 时间区间，不给假精确数：60 秒以内按秒，否则按分钟取整。
progress_span() {
  local low=$1 high=$2 low_minutes high_minutes
  if [ "$high" -lt 60 ]; then
    if [ "$low" -eq "$high" ]; then printf '约 %d 秒' "$high"; else printf '约 %d–%d 秒' "$low" "$high"; fi
    return
  fi
  low_minutes=$((low / 60)) high_minutes=$(((high + 59) / 60))
  [ "$low_minutes" -gt 0 ] || [ "$low" -lt 15 ] || low_minutes=1
  if [ "$low_minutes" -eq 0 ]; then printf '约 %d 分钟内' "$high_minutes"
  elif [ "$low_minutes" -ge "$high_minutes" ]; then printf '约 %d 分钟' "$high_minutes"
  else printf '约 %d–%d 分钟' "$low_minutes" "$high_minutes"; fi
}

progress_bar() {
  local filled=$(($1 * 24 / 100)) bar
  bar=$(printf '%*s' "$filled" '' | tr ' ' '#')$(printf '%*s' $((24 - filled)) '' | tr ' ' '-')
  printf '[%s] %3d%%' "$bar" "$1"
}

# 一整行：先清掉 \r 单行，再写 stderr 与安装日志。第二个参数是颜色（ANSI SGR）。
progress_clear_inline() {
  if "$PROGRESS_INLINE"; then printf '\r\033[K' >&2; PROGRESS_INLINE=false; fi
}

progress_line() {
  progress_clear_inline
  if "$PROGRESS_COLOR" && [ -n "${2:-}" ]; then
    printf '%s \033[%sm%s\033[0m\n' "$PROGRESS_PREFIX" "$2" "$1" >&2
  else
    printf '%s %s\n' "$PROGRESS_PREFIX" "$1" >&2
  fi
  [ -z "$PROGRESS_LOG" ] || printf '%s %s\n' "$(date '+%F %T')" "$1" >>"$PROGRESS_LOG" 2>/dev/null || true
}

# 终端上原地刷新；非终端时由调用方节流后走 progress_line。
progress_inline() {
  printf '\r\033[K%s %s' "$PROGRESS_PREFIX" "$1" >&2
  PROGRESS_INLINE=true
}

progress_init() {
  local entry low high total_low=0 total_high=0
  PROGRESS_PREFIX=$PROGRESS_LABEL PROGRESS_TTY=false PROGRESS_COLOR=false
  if [ -t 2 ] && [ "${TERM:-}" != dumb ]; then
    PROGRESS_TTY=true
    [ -n "${NO_COLOR:-}" ] || PROGRESS_COLOR=true
  fi
  PROGRESS_LOG="${PROGRESS_LOG_DIR}/cdnca-install-${PROGRESS_ROLE}-$(date +%Y%m%d-%H%M%S).log"
  (umask 077; : >>"$PROGRESS_LOG") 2>/dev/null || PROGRESS_LOG=''
  PROGRESS_START=$SECONDS
  for entry in "${PROGRESS_STAGES[@]}"; do
    IFS='|' read -r _ low high _ <<<"$entry"
    total_low=$((total_low + low)) total_high=$((total_high + high))
  done
  progress_line "共 ${#PROGRESS_STAGES[@]} 个步骤，预计$(progress_span "$total_low" "$total_high")${PROGRESS_LOG:+；完整输出写入 ${PROGRESS_LOG}}"
}

progress_close_stage() {
  [ "$PROGRESS_CURRENT" -gt 0 ] || return 0
  local spent=$((SECONDS - PROGRESS_STAGE_START)) name low high flag
  IFS='|' read -r name low high flag <<<"${PROGRESS_STAGES[$((PROGRESS_CURRENT - 1))]}"
  if [ "$flag" != interactive ]; then
    PROGRESS_ACTUAL=$((PROGRESS_ACTUAL + spent)) PROGRESS_NOMINAL=$((PROGRESS_NOMINAL + (low + high) / 2))
  fi
  progress_line "✓ [${PROGRESS_CURRENT}/${#PROGRESS_STAGES[@]}] ${name} 完成（用时 $(progress_clock "$spent")）" 32
  PROGRESS_PASSED=$PROGRESS_CURRENT PROGRESS_CURRENT=0
}

# 进入下一阶段：标题 + 整体进度条。百分比按阶段权重（区间中值）；剩余时间 =
# 本阶段及以后各阶段区间之和，已完成的非交互阶段实际比权重慢时按比例放大。
progress_stage() {
  [ -n "$PROGRESS_PREFIX" ] || return 0
  local stage index name low high flag done_mid=0 total_mid=0 rest_low=0 rest_high=0 factor=100
  progress_close_stage
  stage=$((PROGRESS_PASSED + 1))
  PROGRESS_CURRENT=$stage PROGRESS_STAGE_START=$SECONDS
  for index in "${!PROGRESS_STAGES[@]}"; do
    IFS='|' read -r _ low high _ <<<"${PROGRESS_STAGES[$index]}"
    total_mid=$((total_mid + (low + high) / 2))
    if [ $((index + 1)) -lt "$stage" ]; then
      done_mid=$((done_mid + (low + high) / 2))
    else
      rest_low=$((rest_low + low)) rest_high=$((rest_high + high))
    fi
  done
  if [ "$PROGRESS_NOMINAL" -gt 0 ] && [ "$PROGRESS_ACTUAL" -gt "$PROGRESS_NOMINAL" ]; then
    factor=$((PROGRESS_ACTUAL * 100 / PROGRESS_NOMINAL))
  fi
  IFS='|' read -r name low high flag <<<"${PROGRESS_STAGES[$((stage - 1))]}"
  progress_line "[${stage}/${#PROGRESS_STAGES[@]}] ${name}（$(progress_span "$low" "$high")）……" 1
  progress_line "$(progress_bar $((done_mid * 100 / total_mid)))  已用 $(progress_clock $((SECONDS - PROGRESS_START)))  预计剩余$(progress_span $((rest_low * factor / 100)) $((rest_high * factor / 100)))"
}

progress_done() {
  [ -n "$PROGRESS_PREFIX" ] || return 0
  progress_close_stage
  progress_line "$(progress_bar 100)  全部 ${#PROGRESS_STAGES[@]} 个步骤完成，总用时 $(progress_clock $((SECONDS - PROGRESS_START)))${PROGRESS_LOG:+。安装日志：${PROGRESS_LOG}}" 32
}

# 由安装器的 EXIT 清理调用：中途失败时标出失败阶段、版本与日志位置。原因与下一步
# 就是上方安装器自己的 error 行，这里不另编文案。始终返回 0。
progress_on_exit() {
  local status=$1 name
  progress_stop_heartbeat
  if [ "$status" -ne 0 ] && [ "$PROGRESS_CURRENT" -gt 0 ]; then
    IFS='|' read -r name _ <<<"${PROGRESS_STAGES[$((PROGRESS_CURRENT - 1))]}"
    progress_line "✗ [${PROGRESS_CURRENT}/${#PROGRESS_STAGES[@]}] ${name} 失败（${PROGRESS_VERSION:+版本 ${PROGRESS_VERSION}，}本步骤已用 $(progress_clock $((SECONDS - PROGRESS_STAGE_START)))，退出码 ${status}）。原因与处理办法见上方 error 行${PROGRESS_LOG:+；完整输出：${PROGRESS_LOG}}" 31
    PROGRESS_CURRENT=0
  fi
  return 0
}

# 失败分支里调用（fail "... $(progress_keep_output FILE 标签)"）：FILE 在安装器的临时目录里，
# 退出时连同临时秘密一起删除，所以先把它并入安装日志（root 0600，退出后仍在），
# 输出可查看的位置；安装日志不可写时把 FILE 最后 30 行打到 stderr，不给出不存在的路径。
# 只用于不含秘密的子命令输出。始终返回 0，不改变调用方的失败退出码。
progress_keep_output() {
  local file=$1 label=$2
  if [ -n "$PROGRESS_LOG" ] && [ -f "$PROGRESS_LOG" ] &&
    { printf '>>> %s（失败输出）\n' "$label"; cat -- "$file" 2>/dev/null; } >>"$PROGRESS_LOG" 2>/dev/null; then
    printf "inspect '>>> %s' in %s before retrying" "$label" "$PROGRESS_LOG"
    return 0
  fi
  printf '%s %s 的输出无法写入安装日志，最后 30 行：\n' "${PROGRESS_LABEL:-}" "$label" >&2
  tail -n 30 -- "$file" 2>/dev/null | sed 's/^/    /' >&2 || true
  printf 'its output is printed above'
  return 0
}

# 轮询等待里每轮调用一次（放在 sleep 前）：同一标签从第一次调用起计时，
# 终端每轮刷新，非终端每 10 秒一行，带已等待时间与超时上限（秒）。
progress_tick() {
  [ -n "$PROGRESS_PREFIX" ] || return 0
  local label=$1 limit=$2 waited text
  if [ "$label" != "$PROGRESS_WAIT_LABEL" ] || [ $((SECONDS - PROGRESS_WAIT_START)) -gt $((limit + 30)) ]; then
    PROGRESS_WAIT_LABEL=$label PROGRESS_WAIT_START=$SECONDS PROGRESS_WAIT_NEXT=10
  fi
  waited=$((SECONDS - PROGRESS_WAIT_START))
  text="  等待${label}……已等 $(progress_clock "$waited")，最长 $(progress_clock "$limit")"
  if "$PROGRESS_TTY"; then progress_inline "$text"
  elif [ "$waited" -ge "$PROGRESS_WAIT_NEXT" ]; then PROGRESS_WAIT_NEXT=$((PROGRESS_WAIT_NEXT + 10)); progress_line "$text"; fi
}

# apt 输出里的 “N/M：包名”；看不出时输出为空。
progress_apt_detail() {
  awk '/ newly installed/ { for (i = 2; i <= NF; i++) if ($i == "newly") total = $(i - 1) + 0; done = 0; got = 0; name = "" }
    /^Get:[0-9]+ / { got++ }
    /^Unpacking / { name = $2 }
    /^Setting up / { done++; name = $3 }
    END {
      if (total <= 0) exit
      if (name != "") printf "  正在安装 %d/%d：%s", done, total, name
      else if (got > 0) printf "  正在下载软件包 %d/%d", got, total
    }' "$1" 2>/dev/null || true
}

# 后台心跳：终端每秒、非终端每 15 秒一行；安装器进程（$$）退出后自停。
progress_heartbeat() {
  local label=$1 output=$2 started=$SECONDS next=15 elapsed text
  while sleep 1 && kill -0 "$$" 2>/dev/null; do
    elapsed=$((SECONDS - started))
    text="  仍在${label}……已用 $(progress_clock "$elapsed")$(progress_apt_detail "$output")"
    if "$PROGRESS_TTY"; then progress_inline "$text"
    elif [ "$elapsed" -ge "$next" ]; then next=$((next + 15)); progress_line "$text"; fi
  done
}

progress_stop_heartbeat() {
  [ -n "$PROGRESS_HEARTBEAT" ] || return 0
  kill "$PROGRESS_HEARTBEAT" 2>/dev/null || true
  wait "$PROGRESS_HEARTBEAT" 2>/dev/null || true
  PROGRESS_HEARTBEAT=''
  if "$PROGRESS_TTY"; then printf '\r\033[K' >&2; fi
}

# 运行一个输出很多或很久没输出的外部命令：命令在前台执行（Ctrl-C 照常中断），
# 原始输出进安装日志（或 PROGRESS_RUN_OUTPUT 指定的文件，结束后再并入安装
# 日志），屏幕上只显示心跳。失败时把输出最后 30 行打到 stderr，返回原退出码。
progress_run() {
  local label=$1 output=${PROGRESS_RUN_OUTPUT:-$PROGRESS_LOG} status=0 from=1
  shift
  if [ -z "$PROGRESS_PREFIX" ] || [ -z "$output" ]; then
    if [ -n "${PROGRESS_RUN_OUTPUT:-}" ]; then "$@" >"$PROGRESS_RUN_OUTPUT" 2>&1; else "$@"; fi
    return
  fi
  if [ "$output" = "$PROGRESS_LOG" ]; then
    printf '>>> %s\n' "$label" >>"$PROGRESS_LOG"
    from=$(($(wc -l <"$PROGRESS_LOG") + 1))
  else
    : >"$output"
  fi
  progress_heartbeat "$label" "$output" &
  PROGRESS_HEARTBEAT=$!
  "$@" >>"$output" 2>&1 </dev/null || status=$?
  progress_stop_heartbeat
  if [ "$output" != "$PROGRESS_LOG" ]; then
    [ -z "$PROGRESS_LOG" ] || cat "$output" >>"$PROGRESS_LOG" 2>/dev/null || true
  elif [ "$status" -ne 0 ]; then
    printf '%s %s失败（退出码 %s），输出最后 30 行：\n' "$PROGRESS_PREFIX" "$label" "$status" >&2
    tail -n "+$from" "$PROGRESS_LOG" | tail -n 30 | sed 's/^/    /' >&2
  fi
  return "$status"
}

# 运行一次 curl 下载（参数原样传入），把 curl 自带进度表改写成：终端单行
# “百分比 已下/总量 速度”，非终端只为 1MB 以上的文件每 10% 一行。curl 的报错行照常输出。
progress_download() {
  local label=$1
  shift
  [ -n "$PROGRESS_PREFIX" ] || { "$@"; return; }
  { "$@" 2>&1 1>&3 3>&- | awk -v prefix="$PROGRESS_PREFIX" -v label="$label" -v tty="$PROGRESS_TTY" '
    BEGIN { RS = "[\r\n]"; last = -10 }
    NF == 12 && $1 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
      pct = $3 + 0
      text = sprintf("   下载 %s：%d%%（%s/%s，%s/s）", label, pct, $4, $2, $12)
      if (tty == "true") { printf "\r\033[K%s%s", prefix, text; inline = 1; next }
      if ($2 !~ /[MG]$/) next
      if (pct < last) last = -10
      if (pct >= last + 10 || (pct == 100 && last != 100)) { print prefix text; last = pct - pct % 10; if (pct == 100) last = 100 }
      next
    }
    /^ *% *Total/ || /^ *Dload/ || NF == 0 { next }
    { if (inline) { printf "\r\033[K"; inline = 0 } print }
    END { if (inline) printf "\n" }' >&2; } 3>&1
}
