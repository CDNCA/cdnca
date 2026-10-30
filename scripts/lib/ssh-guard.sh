# cdnca SSH 防爆破（"SSH 防爆破只装 fail2ban"，FINAL C13）：给本机装 fail2ban 的 sshd 监狱。
# 唯一源文件：由 scripts/sync-install-preflight.mjs 逐字嵌入各安装器的 “BEGIN/END ssh-guard” 标记之间，
# tests/install-ssh-guard.test.mjs 校验嵌入内容与本文件一致。
#
# 安装器参数（各安装器自行解析后设置变量）：
#   --ssh-guard-ignoreip "IP/CIDR ..."  不封禁的地址（运维出口与本平台各机器），写入 ignoreip；默认只有回环
#   --no-ssh-guard                      不装 fail2ban（SSH_GUARD_ENABLED=false）
# 不写死任何真实地址；已有其他 fail2ban 配置不动，只管理 jail.d/cdnca-sshd.local。
SSH_GUARD_ENABLED=${SSH_GUARD_ENABLED:-true}
SSH_GUARD_IGNOREIP=${SSH_GUARD_IGNOREIP:-}
SSH_GUARD_ROOT=${SSH_GUARD_ROOT:-}
SSH_GUARD_JAIL=${SSH_GUARD_ROOT}/etc/fail2ban/jail.d/cdnca-sshd.local

ssh_guard_log() { printf '[cdnca-ssh-guard] %s\n' "$*" >&2; }

# 地址列表：空格或逗号分隔的 IPv4/IPv6 地址或 CIDR；非法项返回 1。
ssh_guard_validate_ignoreip() {
  local item
  for item in ${1//,/ }; do
    [[ "$item" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/([0-9]|[12][0-9]|3[0-2]))?$ ]] ||
      [[ "$item" =~ ^[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(/([0-9]{1,2}|1[01][0-9]|12[0-8]))?$ ]] || return 1
  done
}

ssh_guard_render() {
  local extra=${SSH_GUARD_IGNOREIP//,/ }
  printf '%s\n' '# cdnca：SSH 密码爆破防护，由安装器管理（scripts/lib/ssh-guard.sh），重跑安装器会覆盖。' \
    '[DEFAULT]' "ignoreip = 127.0.0.1/8 ::1${extra:+ $extra}" 'bantime = 1h' 'findtime = 10m' 'maxretry = 5' \
    'banaction = nftables-multiport' 'banaction_allports = nftables-allports' '' \
    '[sshd]' 'enabled = true' 'port = ssh' 'backend = systemd'
}

ssh_guard_install_package() {
  command -v fail2ban-client >/dev/null 2>&1 && return 0
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends fail2ban python3-systemd >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf -y -q install epel-release >/dev/null 2>&1 || true
    dnf -y -q install fail2ban-server >/dev/null 2>&1 || dnf -y -q install fail2ban >/dev/null
  else
    return 1
  fi
}

# 安装并启用；失败只告警不中断安装（防爆破不是业务前置）。
ssh_guard_setup() {
  [ "$SSH_GUARD_ENABLED" = true ] || { ssh_guard_log '已按 --no-ssh-guard 跳过 fail2ban'; return 0; }
  ssh_guard_validate_ignoreip "$SSH_GUARD_IGNOREIP" || { ssh_guard_log "--ssh-guard-ignoreip 含非法地址：$SSH_GUARD_IGNOREIP"; return 1; }
  [ -n "$SSH_GUARD_IGNOREIP" ] ||
    ssh_guard_log '提示：未给 --ssh-guard-ignoreip，只放行回环；建议加上运维出口与本平台各机器地址，避免误封'
  if ! ssh_guard_install_package; then
    ssh_guard_log '警告：无法安装 fail2ban（无 apt-get/dnf 或安装失败），SSH 防爆破未启用'
    return 0
  fi
  install -d -m 0755 "${SSH_GUARD_JAIL%/*}"
  ssh_guard_render >"${SSH_GUARD_JAIL}.new"
  mv -f -- "${SSH_GUARD_JAIL}.new" "$SSH_GUARD_JAIL"
  if ! fail2ban-client -t >/dev/null 2>&1; then
    ssh_guard_log "警告：fail2ban 配置检查失败，SSH 防爆破未启用（见 $SSH_GUARD_JAIL）"
    return 0
  fi
  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || { ssh_guard_log '警告：fail2ban 启动失败，SSH 防爆破未启用'; return 0; }
  ssh_guard_log "fail2ban sshd 已启用（5 次失败/10 分钟封 1 小时；ignoreip：127.0.0.1/8 ::1${SSH_GUARD_IGNOREIP:+ ${SSH_GUARD_IGNOREIP//,/ }}）"
}
