# shellcheck shell=bash
# CDNCA 安装前检测（主控与节点共用）。
#
# 这是唯一的源文件：scripts/install-control.sh 与 scripts/install-node.sh 以
# “BEGIN/END install-preflight” 标记之间逐字嵌入本文件（两个安装器都通过
# curl | bash 单文件下发，不能在运行时 source 外部文件）。修改后运行
#   node scripts/sync-install-preflight.mjs
# 重新嵌入；tests/install-preflight.test.mjs 校验嵌入内容与本文件一致。
#
# 支持矩阵与阈值依据：docs/install/os-support-matrix.md。
# 只读检测：不安装软件、不改系统配置。测试通过 PREFLIGHT_ROOT（替换
# /etc、/proc、/sys 读取位置）与 PATH 中的假命令模拟主机。

PREFLIGHT_ROOT=${PREFLIGHT_ROOT:-}
PREFLIGHT_ROLE=${PREFLIGHT_ROLE:-}
PREFLIGHT_ASSUME_YES=${PREFLIGHT_ASSUME_YES:-false}
PREFLIGHT_OS_ID=''
PREFLIGHT_OS_VERSION=''
PREFLIGHT_STATUS=()
PREFLIGHT_ITEM=()
PREFLIGHT_DETAIL=()
PREFLIGHT_HINT=()

preflight_record() {
  PREFLIGHT_STATUS+=("$1")
  PREFLIGHT_ITEM+=("$2")
  PREFLIGHT_DETAIL+=("$3")
  PREFLIGHT_HINT+=("${4:-}")
}

preflight_os_release_value() {
  local key=$1 file="${PREFLIGHT_ROOT}/etc/os-release"
  [ -r "$file" ] || return 0
  awk -F= -v key="$key" '$1 == key { value = substr($0, length(key) + 2); gsub(/^"|"$/, "", value); gsub(/^\047|\047$/, "", value); print value; exit }' "$file"
}

# 分级：official（正式支持）/ compatible（兼容支持）/ unsupported:<原因>。
# 结论与依据见 docs/install/os-support-matrix.md，两处必须同步修改。
preflight_os_tier() {
  local role=$1 id=$2 version=$3 major
  major=${version%%.*}
  case "$id" in
    rocky|almalinux|rhel|centos)
      case "$id:$major" in
        centos:7|centos:8) printf 'unsupported:CentOS %s 已停止维护；systemd、内核与 Python 版本低于当前安装器的要求\n' "$major"; return ;;
        rocky:8|rocky:9|rocky:10|almalinux:8|almalinux:9|almalinux:10|rhel:8|rhel:9|rhel:10) printf 'compatible\n'; return ;;
      esac ;;
    ubuntu)
      case "$version" in
        24.04) printf 'official\n'; return ;;
        22.04|20.04) printf 'compatible\n'; return ;;
        18.04)
          # Node: setpriv package + a pidfd kernel (HWE 5.4). Control waits for the
          # musl ClamAV build (build-portable-clamav-musl.sh): glibc 2.27 < 2.28.
          if [ "$role" = control ]; then
            printf 'unsupported:主控暂不支持 Ubuntu 18.04：glibc 2.27 低于官方 ClamAV 1.4 构建要求的 2.28，基于 musl 的 ClamAV 构建尚未发布；节点可以安装\n'
          else
            printf 'compatible\n'
          fi
          return ;;
        16.04) printf 'unsupported:Ubuntu 16.04 的 Python 3.5 低于安装器要求的 3.6\n'; return ;;
      esac ;;
    debian)
      case "$major" in
        10|11|12|13) printf 'compatible\n'; return ;;
        9) printf 'unsupported:Debian 9 的 Python 3.5 低于安装器要求的 3.6\n'; return ;;
      esac ;;
  esac
  printf 'unsupported:未适配的发行版 %s %s\n' "${id:-unknown}" "${version:-unknown}"
}

preflight_check_os() {
  local role=$1 name tier
  PREFLIGHT_OS_ID=$(preflight_os_release_value ID)
  PREFLIGHT_OS_VERSION=$(preflight_os_release_value VERSION_ID)
  name=$(preflight_os_release_value PRETTY_NAME)
  if [ -z "$PREFLIGHT_OS_ID" ]; then
    preflight_record fail 操作系统 '无法读取 /etc/os-release' '请在受支持的 Linux 发行版上安装（见支持矩阵）'
    return
  fi
  tier=$(preflight_os_tier "$role" "$PREFLIGHT_OS_ID" "$PREFLIGHT_OS_VERSION")
  case "$tier" in
    official) preflight_record pass 操作系统 "${name:-$PREFLIGHT_OS_ID $PREFLIGHT_OS_VERSION}（正式支持）" ;;
    compatible) preflight_record warn 操作系统 "${name:-$PREFLIGHT_OS_ID $PREFLIGHT_OS_VERSION}（兼容支持：已在容器内验证依赖安装，整机安装未逐版本实测）" \
      '生产环境建议使用 Ubuntu 24.04；继续安装请确认' ;;
    *) preflight_record fail 操作系统 "${name:-$PREFLIGHT_OS_ID $PREFLIGHT_OS_VERSION}：${tier#unsupported:}" \
      '请改用 Ubuntu 24.04（推荐）、Ubuntu 22.04/20.04、Debian 10–13 或 Rocky/AlmaLinux/RHEL 8/9/10' ;;
  esac
}

preflight_check_arch() {
  local role=$1 machine flags
  machine=$(uname -m)
  if [ "$machine" != x86_64 ]; then
    preflight_record fail CPU架构 "$machine" '目前只提供 x86_64（amd64）安装包，请使用 x86_64 服务器'
    return
  fi
  flags=$(awk -F: '/^flags/ { print $2; exit }' "${PREFLIGHT_ROOT}/proc/cpuinfo" 2>/dev/null || true)
  if [ "$role" = control ] && [ -n "$flags" ] && ! printf '%s\n' "$flags" | grep -qw sse4_2; then
    preflight_record fail CPU架构 'x86_64，但 CPU 不支持 SSE4.2' 'ClickHouse 需要 SSE4.2，请更换 CPU 型号或在虚拟化平台开启 CPU 直通（host-passthrough）'
    return
  fi
  preflight_record pass CPU架构 x86_64
}

# pidfd_open(getpid(), 0): ENOSYS means the kernel (or an emulator) lacks pidfd.
# Any interpreter the host already has; none at all is reported as unknown.
preflight_pidfd_probe() {
  if command -v perl >/dev/null 2>&1; then
    perl -e 'require POSIX; my $fd = syscall(434, $$, 0); exit(($fd < 0 && $! == POSIX::ENOSYS()) ? 1 : 0)' 2>/dev/null && return 0
    return 1
  fi
  local python
  for python in python3 python; do
    command -v "$python" >/dev/null 2>&1 || continue
    "$python" -c 'import ctypes, errno, os, sys
libc = ctypes.CDLL(None, use_errno=True)
fd = libc.syscall(434, os.getpid(), 0)
sys.exit(1 if fd < 0 and ctypes.get_errno() == errno.ENOSYS else 0)' 2>/dev/null && return 0
    return 1
  done
  return 2
}

preflight_check_kernel() {
  local role=$1 release major minor probe=0
  release=$(uname -r)
  major=${release%%.*}
  minor=${release#*.}; minor=${minor%%.*}
  case "$major$minor" in *[!0-9]*|'') preflight_record warn 内核 "无法识别内核版本 $release"; return ;; esac
  if [ "$role" = node ]; then
    # The Agent signals OpenResty only through pidfd (Linux 5.3+, or a vendor
    # backport): there is no PID-reuse-prone fallback.
    if [ "$major" -lt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -lt 3 ]; }; then
      preflight_pidfd_probe || probe=$?
      case "$probe" in
        0) preflight_record warn 内核 "$release（低于 5.3，但内核提供了 pidfd_open）" '未在该内核上逐版本实测；建议升级到 5.10 以上' ;;
        2) preflight_record fail 内核 "$release（低于 5.3），无法确认 pidfd 支持" '请安装 perl 后重试，或升级内核到 5.3 以上（CentOS 7 可用 ELRepo kernel-lt/kernel-ml，Ubuntu 用 HWE 内核）' ;;
        *) preflight_record fail 内核 "$release 不支持 pidfd_open（节点重载 OpenResty 依赖它）" '请升级内核到 5.3 以上（CentOS 7 可用 ELRepo kernel-lt/kernel-ml，Ubuntu 16.04/18.04 用 HWE 内核，Debian 9/10 用 backports 内核）' ;;
      esac
      [ "$probe" = 0 ] || return 0
    elif [ "$major" -eq 5 ] && [ "$minor" -lt 10 ]; then
      preflight_record warn 内核 "$release（5.3–5.9 可用，未逐版本实测）" '建议使用 5.10 以上内核'
    fi
    if [ ! -r "${PREFLIGHT_ROOT}/sys/fs/cgroup/cgroup.controllers" ]; then
      preflight_record warn cgroup "未启用 cgroup v2（legacy/hybrid）" 'Agent 可在 cgroup v1 下运行；IPAddressDeny 等依赖 cgroup v2 的服务限制不会生效'
    fi
    if [ "$major" -gt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -ge 10 ]; }; then
      preflight_record pass 内核 "$release"
    fi
    return 0
  fi
  if [ "$major" -lt 4 ] || { [ "$major" -eq 4 ] && [ "$minor" -lt 18 ]; }; then
    preflight_record warn 内核 "$release（低于 4.18，未验证）"
    return
  fi
  preflight_record pass 内核 "$release"
}

preflight_check_cpu() {
  local role=$1 cores
  cores=$(grep -c '^processor' "${PREFLIGHT_ROOT}/proc/cpuinfo" 2>/dev/null || true)
  [ -n "$cores" ] && [ "$cores" -gt 0 ] 2>/dev/null || cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf 0)
  # 推荐配置：主控至少 4 核 16G，节点 4 核 8G 起；低于推荐只告警。
  if [ "$cores" -lt 1 ]; then
    preflight_record warn CPU核数 '无法识别 CPU 核数'
  elif [ "$role" = control ] && [ "$cores" -lt 4 ]; then
    preflight_record warn CPU核数 "$cores 核（主控推荐至少 4 核）" 'PostgreSQL、ClickHouse、ClamAV 与管理端同机运行，核数少时访问日志与统计会明显变慢'
  elif [ "$role" = node ] && [ "$cores" -lt 4 ]; then
    preflight_record warn CPU核数 "$cores 核（节点推荐至少 4 核）" 'OpenResty、WAF 与 TLS 握手按核扩展，核数少时高并发与 CC 防护能力下降'
  else
    preflight_record pass CPU核数 "$cores 核"
  fi
}

preflight_meminfo_mib() {
  awk -v key="$1:" '$1 == key { printf "%d", $2 / 1024; found = 1; exit } END { if (!found) printf "0" }' "${PREFLIGHT_ROOT}/proc/meminfo" 2>/dev/null || printf 0
}

# 阈值依据见支持矩阵“最低配置”一节。云主机标称内存会少报一部分（内核保留），
# 因此按标称值的约 90% 判断：2G 机器 MemTotal 通常约 1.9G。
preflight_check_memory() {
  local role=$1 total swap fail_mib warn_mib swap_note
  total=$(preflight_meminfo_mib MemTotal)
  swap=$(preflight_meminfo_mib SwapTotal)
  # 低于 fail 不能安装；低于 warn（推荐：主控 16G、节点 8G，按标称约 90%）告警。
  if [ "$role" = control ]; then fail_mib=3500 warn_mib=14700; else fail_mib=900 warn_mib=7300; fi
  if [ "$total" -le 0 ]; then
    preflight_record warn 内存 '无法读取 /proc/meminfo'
  elif [ "$total" -lt "$fail_mib" ]; then
    if [ "$role" = node ] && [ $((total + swap)) -ge 2800 ]; then
      preflight_record warn 内存 "${total} MiB + Swap ${swap} MiB（节点建议 2G 以上）" '内存不足 2G 时需保留至少 2G Swap'
    else
      preflight_record fail 内存 "${total} MiB（$(if [ "$role" = control ]; then printf '主控最低 4G'; else printf '节点最低 1G，且需 2G Swap'; fi)）" \
        "$(if [ "$role" = control ]; then printf '请升级到 4G 以上内存（推荐 16G）'; else printf '请升级到 2G 以上内存，或 1G 内存加 2G Swap（推荐 8G）'; fi)"
    fi
  elif [ "$total" -lt "$warn_mib" ]; then
    swap_note=''; [ "$swap" -le 0 ] || swap_note=" + Swap ${swap} MiB"
    preflight_record warn 内存 "${total} MiB${swap_note}（$(if [ "$role" = control ]; then printf '主控推荐 16G 以上'; else printf '节点推荐 8G 以上'; fi)）" \
      "$(if [ "$role" = control ]; then printf '可以安装，但访问日志多时 ClickHouse 与 ClamAV 可能内存紧张；规模大建议 8 核 32G'; else printf '可以安装；大缓存或高并发建议 4 核 16G，内存不足 2G 时需加 2G Swap'; fi)"
  else
    preflight_record pass 内存 "${total} MiB"
  fi
}

# 取路径本身或最近的已存在上级目录，避免 /data 等尚未创建的目录导致 df 失败。
preflight_existing_parent() {
  local path=$1
  while [ ! -e "$path" ] && [ "$path" != / ]; do path=$(dirname "$path"); done
  printf '%s\n' "$path"
}

preflight_check_disk() {
  local role=$1 path existing line mount avail_mib fail_mib warn_mib seen=' '
  local -a paths
  if [ "$role" = control ]; then
    paths=(/ /var/lib /data /usr/local)
    fail_mib=10240 warn_mib=40960
  else
    paths=(/ /opt /var/lib /usr)
    fail_mib=2048 warn_mib=10240
  fi
  for path in "${paths[@]}"; do
    existing=$(preflight_existing_parent "$path")
    line=$(df -Pm "$existing" 2>/dev/null | awk 'NR == 2 { print $6 " " $4 }') || line=''
    [ -n "$line" ] || { preflight_record warn 磁盘空间 "无法读取 $path 所在分区的可用空间"; continue; }
    mount=${line% *}; avail_mib=${line##* }
    case "$seen" in *" $mount "*) continue ;; esac
    seen="$seen$mount "
    if [ "$avail_mib" -lt "$fail_mib" ]; then
      preflight_record fail 磁盘空间 "$path（分区 $mount）可用 $((avail_mib / 1024)) GiB，低于 $((fail_mib / 1024)) GiB" "请清理或扩容 $mount 分区"
    elif [ "$avail_mib" -lt "$warn_mib" ]; then
      preflight_record warn 磁盘空间 "$path（分区 $mount）可用 $((avail_mib / 1024)) GiB，建议 $((warn_mib / 1024)) GiB 以上" \
        "$(if [ "$role" = control ]; then printf '日志、分析数据和对象存储会持续增长，建议使用 100G 以上 SSD'; else printf '缓存会占用磁盘，按缓存规模预留空间'; fi)"
    else
      preflight_record pass 磁盘空间 "$path（分区 $mount）可用 $((avail_mib / 1024)) GiB"
    fi
  done
}

preflight_systemd_minimum() {
  case "$PREFLIGHT_OS_ID:${PREFLIGHT_OS_VERSION%%.*}" in
    ubuntu:24) printf 255 ;;
    ubuntu:22) printf 249 ;;
    ubuntu:20) printf 245 ;;
    ubuntu:18) printf 237 ;;
    debian:10) printf 241 ;;
    debian:11) printf 247 ;;
    rocky:8|almalinux:8|rhel:8) printf 239 ;;
    debian:12|rocky:9|almalinux:9|rhel:9) printf 252 ;;
    debian:13|rocky:10|almalinux:10|rhel:10) printf 257 ;;
    *) printf 249 ;;
  esac
}

# Hardening directives our units use; on a systemd that lacks one, systemd
# itself ignores it (see scripts/lib/systemd-compat.sh for functional ones).
PREFLIGHT_SANDBOX_DIRECTIVES=(Service.ProtectSystem Service.ReadWritePaths Service.ProtectKernelTunables Service.ProtectKernelModules
  Service.ProtectControlGroups Service.ProtectKernelLogs Service.ProtectClock Service.ProtectHostname Service.RestrictNamespaces
  Service.RestrictRealtime Service.RestrictSUIDSGID Service.LockPersonality Service.MemoryDenyWriteExecute Service.ProtectProc
  Service.IPAddressDeny Service.KeyringMode)

preflight_check_systemd() {
  local version minimum directive missing='' groups=''
  if [ ! -d "${PREFLIGHT_ROOT}/run/systemd/system" ] || ! command -v systemctl >/dev/null 2>&1; then
    preflight_record fail systemd '本机未以 systemd 作为 init 运行（容器或 OpenVZ/LXC 精简环境常见）' '请在以 systemd 启动的完整虚拟机或物理机上安装'
    return
  fi
  version=$(systemctl --version 2>/dev/null | awk 'NR == 1 { print $2 }')
  version=${version%%[!0-9]*}
  minimum=$(preflight_systemd_minimum)
  if [ -z "$version" ]; then
    preflight_record fail systemd '无法识别 systemd 版本'
  elif [ "$version" -lt 219 ]; then
    preflight_record fail systemd "版本 $version，低于 219" '请升级系统'
  elif [ "$version" -lt "$minimum" ]; then
    # Older systemd: units get a compatibility drop-in (systemd-compat.sh) and
    # unknown hardening directives are ignored by systemd itself.
    if command -v systemd_compat_knows >/dev/null 2>&1; then
      for directive in "${PREFLIGHT_SANDBOX_DIRECTIVES[@]}"; do
        systemd_compat_knows "$directive" || missing="$missing ${directive#Service.}"
      done
      for directive in @system-service @chown @setuid; do
        systemd_compat_knows "$directive" || groups="$groups $directive"
      done
    fi
    preflight_record warn systemd "版本 $version（低于 $minimum）：沙箱加固降级${missing:+，不支持:$missing}${groups:+；系统调用过滤分组缺失:$groups，将不启用系统调用过滤}" \
      '服务可以运行，但上述隔离措施不会生效；建议使用 systemd 249 以上的系统'
  else
    preflight_record pass systemd "版本 $version"
  fi
}

preflight_check_root() {
  if [ "$(id -u)" -eq 0 ]; then
    preflight_record pass root权限 '以 root 运行'
  else
    preflight_record fail root权限 "当前用户 $(id -un 2>/dev/null || id -u)" '请使用 root 运行，或在命令前加 sudo'
  fi
}

# 从 /proc/net/tcp{,6} 读取监听端口（状态 0A），不依赖 ss/netstat。
preflight_listening_ports() {
  local file
  for file in "${PREFLIGHT_ROOT}/proc/net/tcp" "${PREFLIGHT_ROOT}/proc/net/tcp6"; do
    [ -r "$file" ] || continue
    awk 'NR > 1 && $4 == "0A" { split($2, parts, ":"); print parts[2] }' "$file"
  done | while read -r hex; do printf '%d\n' "0x$hex"; done | sort -un
}

# 参数：端口:用途 ...
preflight_check_ports() {
  local listening entry port label busy=''
  listening=" $(preflight_listening_ports | tr '\n' ' ') "
  for entry in "$@"; do
    port=${entry%%:*}; label=${entry#*:}
    case "$listening" in *" $port "*) busy="$busy${busy:+、}$port（$label）" ;; esac
  done
  if [ -n "$busy" ]; then
    preflight_record fail 端口占用 "已被占用：$busy" '用 ss -ltnp 查看占用进程；请在干净的系统上安装，或停止占用这些端口的服务'
  else
    preflight_record pass 端口占用 "所需端口均空闲（$(printf '%s\n' "$@" | cut -d: -f1 | paste -sd, -)）"
  fi
}

# 参数：必须已存在的命令 -- 安装器会自动补装的命令。a|b 表示任一即可。
preflight_check_commands() {
  local command alternative found missing='' auto='' mode=required
  for command in "$@"; do
    if [ "$command" = -- ]; then mode=auto; continue; fi
    found=false
    for alternative in ${command//|/ }; do
      if command -v "$alternative" >/dev/null 2>&1; then found=true; break; fi
    done
    [ "$found" = false ] || continue
    command=${command//|/ 或 }
    if [ "$mode" = required ]; then missing="$missing $command"; else auto="$auto $command"; fi
  done
  if [ -n "$missing" ]; then
    preflight_record fail 必需命令 "缺少:$missing" '请先用系统包管理器安装这些基础工具'
  elif [ -n "$auto" ]; then
    preflight_record pass 必需命令 "基础命令齐全；将自动安装:$auto"
  else
    preflight_record pass 必需命令 '全部已安装'
  fi
}

preflight_date_epoch() {
  date -u -d "$1" +%s 2>/dev/null || true
}

# 参数：显示名 URL [备用URL]。不使用 curl -k：证书不受系统信任（curl 退出码
# 60/51/58，自签证书由安装器后续用固定指纹校验）记为“可连接”，但读不到时间。
preflight_check_remote() {
  local label=$1 url='' headers='' local_epoch remote_date remote_epoch skew untrusted=false candidate rc
  shift
  if ! command -v curl >/dev/null 2>&1; then
    preflight_record warn "连通性（$label）" '未安装 curl，跳过检测'
    return
  fi
  for candidate in "$@"; do
    [ -n "$candidate" ] || continue
    rc=0
    headers=$(curl -sS -I -o /dev/null -D - --connect-timeout 8 --max-time 15 "$candidate" 2>/dev/null) || rc=$?
    if [ "$rc" -eq 0 ]; then url=$candidate; break; fi
    case "$rc" in 51|58|60) url=$candidate; untrusted=true; headers=''; break ;; esac
    headers=''
  done
  if [ -z "$url" ]; then
    preflight_record fail "连通性（$label）" "无法连接 $*" '请检查 DNS、出站防火墙与代理设置，确认本机能访问该 HTTPS 地址'
    return
  fi
  if [ "$untrusted" = true ]; then
    preflight_record pass "连通性（$label）" "$url 可连接（证书不受系统信任，安装时用固定指纹校验）"
    preflight_record warn 时间偏差 "证书不受系统信任，无法在检测阶段读取 $label 的服务器时间" '请确认已开启 NTP 时间同步（timedatectl set-ntp true）'
    return
  fi
  preflight_record pass "连通性（$label）" "$url 可连接"
  remote_date=$(printf '%s\n' "$headers" | tr -d '\r' | awk 'tolower($1) == "date:" { sub(/^[^:]*: */, ""); print; exit }')
  remote_epoch=$(preflight_date_epoch "$remote_date")
  local_epoch=$(date -u +%s)
  if [ -z "$remote_epoch" ]; then
    preflight_record warn 时间偏差 "无法从 $label 读取服务器时间" '请确认已开启 NTP 时间同步（timedatectl set-ntp true）'
    return
  fi
  skew=$((local_epoch - remote_epoch)); [ "$skew" -ge 0 ] || skew=$((-skew))
  if [ "$skew" -gt 300 ]; then
    preflight_record fail 时间偏差 "本机与 $label 相差 ${skew} 秒（超过 300 秒，激活与签名校验会被拒绝）" '请开启 NTP 同步：timedatectl set-ntp true，或安装 chrony 后重试'
  elif [ "$skew" -gt 60 ]; then
    preflight_record warn 时间偏差 "本机与 $label 相差 ${skew} 秒" '建议开启 NTP 同步：timedatectl set-ntp true'
  else
    preflight_record pass 时间偏差 "${skew} 秒"
  fi
}

# 参数：显示名 主机 端口。只做 TCP 建连，失败记为警告（可能是分离部署）。
preflight_check_tcp() {
  local label=$1 host=$2 port=$3
  if timeout 6 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$host" "$port" 2>/dev/null; then
    preflight_record pass "连通性（$label）" "$host:$port 可连接"
  else
    preflight_record warn "连通性（$label）" "$host:$port 无法连接" "请确认主控已放行 TCP $port，且本机出站未被拦截"
  fi
}

preflight_check_selinux() {
  if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = Enforcing ]; then
    preflight_record warn SELinux '处于 Enforcing 模式（未在 Enforcing 下做整机实测）' \
      '安装器会对安装目录执行 restorecon；若服务无法启动，用 ausearch -m avc -ts recent 查看拒绝记录'
  fi
}

# 参数：需要放行的 TCP 端口列表。只检测并提示，不修改防火墙。
preflight_check_firewall() {
  local ports="$*" commands=''
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    commands=$(for port in $ports; do printf 'ufw allow %s/tcp; ' "$port"; done)
    preflight_record warn 防火墙 "ufw 已启用，安装器不会修改规则" "请放行：$commands"
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    commands=$(for port in $ports; do printf 'firewall-cmd --permanent --add-port=%s/tcp; ' "$port"; done)
    preflight_record warn 防火墙 "firewalld 正在运行，安装器不会修改规则" "请放行：${commands}firewall-cmd --reload"
  elif command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP'; then
    commands=$(for port in $ports; do printf 'iptables -I INPUT -p tcp --dport %s -j ACCEPT; ' "$port"; done)
    preflight_record warn 防火墙 'iptables INPUT 默认策略为 DROP' "请放行：$commands"
  else
    preflight_record pass 防火墙 "未检测到启用的主机防火墙；云安全组需放行 TCP ${ports// /, }"
  fi
}

# 主控与节点不能装在同一台机器上（端口与 OpenResty/nginx 冲突）。
preflight_check_coexistence() {
  local role=$1 path
  if [ "$role" = node ]; then
    for path in /etc/cdnca-control /usr/local/cdnca-control /data/cdnca-native-root; do
      if [ -e "${PREFLIGHT_ROOT}$path" ]; then
        preflight_record fail 主控共存 "本机已安装主控（$path）" '节点不能与主控装在同一台机器上，请使用另一台服务器'
        return
      fi
    done
  else
    for path in /etc/cdnca-edge-agent /opt/cdnca-node /usr/lib/cdnca-edge-agent; do
      if [ -e "${PREFLIGHT_ROOT}$path" ]; then
        preflight_record fail 节点共存 "本机已安装节点（$path）" '主控不能与节点装在同一台机器上，请使用另一台服务器'
        return
      fi
    done
  fi
}

preflight_tag() {
  case "$1" in pass) printf '通过' ;; warn) printf '警告' ;; *) printf '不通过' ;; esac
}

# 返回 0 继续安装；有“不通过”或用户拒绝时返回 1。
preflight_report() {
  local prefix=$1 index fails=0 warns=0 answer
  printf '%s 安装前检测\n' "$prefix" >&2
  for index in "${!PREFLIGHT_STATUS[@]}"; do
    printf '%s   [%s] %s：%s\n' "$prefix" "$(preflight_tag "${PREFLIGHT_STATUS[$index]}")" "${PREFLIGHT_ITEM[$index]}" "${PREFLIGHT_DETAIL[$index]}" >&2
    if [ "${PREFLIGHT_STATUS[$index]}" != pass ] && [ -n "${PREFLIGHT_HINT[$index]}" ]; then
      printf '%s          建议：%s\n' "$prefix" "${PREFLIGHT_HINT[$index]}" >&2
    fi
    case "${PREFLIGHT_STATUS[$index]}" in fail) fails=$((fails + 1)) ;; warn) warns=$((warns + 1)) ;; esac
  done
  if [ "$fails" -gt 0 ]; then
    printf '%s 检测结果：%d 项不通过、%d 项警告。请按上面的建议处理后重新执行安装命令；本机未做任何修改。\n' "$prefix" "$fails" "$warns" >&2
    return 1
  fi
  if [ "$warns" -eq 0 ]; then
    printf '%s 检测结果：全部通过。\n' "$prefix" >&2
    return 0
  fi
  if [ "$PREFLIGHT_ASSUME_YES" = true ]; then
    printf '%s 检测结果：%d 项警告，已指定 --yes，继续安装。\n' "$prefix" "$warns" >&2
    return 0
  fi
  if { : </dev/tty; } 2>/dev/null && [ -t 2 ]; then
    printf '%s 检测结果：%d 项警告。确认继续安装？[y/N] ' "$prefix" "$warns" >&2
    IFS= read -r answer </dev/tty || answer=''
    case "$answer" in
      y|Y|yes|YES) return 0 ;;
      *) printf '%s 已取消安装；本机未做任何修改。如需跳过确认，请在命令末尾加 --yes。\n' "$prefix" >&2; return 1 ;;
    esac
  fi
  printf '%s 检测结果：%d 项警告；非交互运行，继续安装（加 --yes 可省略本提示）。\n' "$prefix" "$warns" >&2
  return 0
}
