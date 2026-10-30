# shellcheck shell=bash
# 系统自动更新（AUDIT-1029 ①-11），主控与节点安装器共用。
# 生产机默认停用 apt-daily.timer、apt-daily-upgrade.timer 与 unattended-upgrades.service：
# 无人值守升级会在业务运行时替换 PostgreSQL/Redis/nginx 等依赖并重启它们，安装期间还占着 dpkg 锁。
# 软件包本身保留，管理员仍可手动 apt-get update && apt-get upgrade（或 unattended-upgrade -v 手动跑一次）。
# --keep-unattended-upgrades：保留系统默认，只在安装期间暂停两个定时器、退出时由 cleanup 恢复。
# 调用方提供 log/fail/progress_line/progress_tick，并在 EXIT 时启动 PAUSED_APT_TIMERS 里的定时器。
KEEP_UNATTENDED_UPGRADES=false
PAUSED_APT_TIMERS=()

# apt-get update 不理会 DPkg::Lock::Timeout 就去拿 lists 锁：先停定时器，再等正在跑的自动更新结束
# （不打断正在写 dpkg 的进程），最后按开关停用或只暂停。
quiesce_package_automation() {
  local timer unit deadline=$((SECONDS + 900)) waiting='' disabled=''
  [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 || return 0
  for timer in apt-daily.timer apt-daily-upgrade.timer; do
    if systemctl is-active --quiet "$timer"; then
      systemctl stop "$timer" && PAUSED_APT_TIMERS+=("$timer")
    fi
  done
  while systemctl is-active --quiet apt-daily.service apt-daily-upgrade.service ||
    pgrep -f '/usr/bin/unattended-upgrade( |$)' >/dev/null; do
    [ "$SECONDS" -lt "$deadline" ] || fail 'package automation (apt-daily/unattended-upgrades) is still running after 15 minutes'
    [ -n "$waiting" ] || { log 'waiting for the running automatic package update to finish'; waiting=1; }
    progress_tick '系统自动更新（apt-daily/unattended-upgrades）结束' 900
    sleep 5
  done
  if [ "$KEEP_UNATTENDED_UPGRADES" = true ]; then
    [ "${#PAUSED_APT_TIMERS[@]}" -eq 0 ] ||
      progress_line "已按 --keep-unattended-upgrades 保留系统自动更新：安装期间暂停 ${PAUSED_APT_TIMERS[*]}，结束后恢复"
  else
    # 只处理存在且启用（或正在运行）的单元；未安装、已停用或被 mask 的不动。
    for unit in apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service; do
      systemctl is-enabled --quiet "$unit" 2>/dev/null || systemctl is-active --quiet "$unit" || continue
      systemctl disable --now "$unit" >/dev/null 2>&1 || fail "cannot disable ${unit}; rerun with --keep-unattended-upgrades to keep the system default"
      disabled="$disabled $unit"
    done
    # 已停用的定时器退出时不再恢复。
    PAUSED_APT_TIMERS=()
    [ -z "$disabled" ] ||
      progress_line "已停用系统自动更新（${disabled# }）：生产机默认关闭，避免无人值守升级在运行中替换并重启依赖服务；软件包保留，可手动 apt-get update && apt-get upgrade；恢复系统默认：systemctl enable --now${disabled}"
  fi
  # dnf waits on the rpm lock itself; only pause the cache timer for the install.
  if command -v dnf >/dev/null 2>&1 && systemctl is-active --quiet dnf-makecache.timer; then
    systemctl stop dnf-makecache.timer && PAUSED_APT_TIMERS+=(dnf-makecache.timer)
  fi
}
