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
# 界面语言见 install-i18n；未嵌入它的安装器与单独加载时按中文。
declare -F msg >/dev/null || msg() { if [ "${INSTALL_LANG:-zh}" = en ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }

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
        centos:7|centos:8) printf "unsupported:$(msg 'CentOS %s 已停止维护；systemd、内核与 Python 版本低于当前安装器的要求' 'CentOS %s is end-of-life; its systemd, kernel and Python are older than this installer requires')\n" "$major"; return ;;
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
            printf 'unsupported:%s\n' "$(msg '主控暂不支持 Ubuntu 18.04：glibc 2.27 低于官方 ClamAV 1.4 构建要求的 2.28，基于 musl 的 ClamAV 构建尚未发布；节点可以安装' 'the control plane does not support Ubuntu 18.04 yet: glibc 2.27 is older than the 2.28 the official ClamAV 1.4 build needs and the musl ClamAV build is not released; nodes can be installed')"
          else
            printf 'compatible\n'
          fi
          return ;;
        16.04) printf 'unsupported:%s\n' "$(msg 'Ubuntu 16.04 的 Python 3.5 低于安装器要求的 3.6' 'Python 3.5 on Ubuntu 16.04 is older than the required 3.6')"; return ;;
      esac ;;
    debian)
      case "$major" in
        10|11|12|13) printf 'compatible\n'; return ;;
        9) printf 'unsupported:%s\n' "$(msg 'Debian 9 的 Python 3.5 低于安装器要求的 3.6' 'Python 3.5 on Debian 9 is older than the required 3.6')"; return ;;
      esac ;;
  esac
  printf "unsupported:$(msg '未适配的发行版 %s %s' 'unsupported distribution %s %s')\n" "${id:-unknown}" "${version:-unknown}"
}

preflight_check_os() {
  local role=$1 name tier
  PREFLIGHT_OS_ID=$(preflight_os_release_value ID)
  PREFLIGHT_OS_VERSION=$(preflight_os_release_value VERSION_ID)
  name=$(preflight_os_release_value PRETTY_NAME)
  if [ -z "$PREFLIGHT_OS_ID" ]; then
    preflight_record fail 操作系统 "$(msg '无法读取 /etc/os-release' 'cannot read /etc/os-release')" "$(msg '请在受支持的 Linux 发行版上安装（见支持矩阵）' 'install on a supported Linux distribution (see the support matrix)')"
    return
  fi
  tier=$(preflight_os_tier "$role" "$PREFLIGHT_OS_ID" "$PREFLIGHT_OS_VERSION")
  case "$tier" in
    official) preflight_record pass 操作系统 "${name:-$PREFLIGHT_OS_ID $PREFLIGHT_OS_VERSION}$(msg '（正式支持）' ' (officially supported)')" ;;
    compatible) preflight_record warn 操作系统 "${name:-$PREFLIGHT_OS_ID $PREFLIGHT_OS_VERSION}$(msg '（兼容支持：已在容器内验证依赖安装，整机安装未逐版本实测）' ' (compatible: dependency installation verified in containers, full installs not tested on every release)')" \
      "$(msg '生产环境建议使用 Ubuntu 24.04；继续安装请确认' 'Ubuntu 24.04 is recommended for production; confirm to continue')" ;;
    *) preflight_record fail 操作系统 "${name:-$PREFLIGHT_OS_ID $PREFLIGHT_OS_VERSION}$(msg '：' ': ')${tier#unsupported:}" \
      "$(msg '请改用 Ubuntu 24.04（推荐）、Ubuntu 22.04/20.04、Debian 10–13 或 Rocky/AlmaLinux/RHEL 8/9/10' 'use Ubuntu 24.04 (recommended), Ubuntu 22.04/20.04, Debian 10–13 or Rocky/AlmaLinux/RHEL 8/9/10')" ;;
  esac
}

preflight_check_arch() {
  local role=$1 machine flags
  machine=$(uname -m)
  if [ "$machine" != x86_64 ]; then
    preflight_record fail CPU架构 "$machine" "$(msg '目前只提供 x86_64（amd64）安装包，请使用 x86_64 服务器' 'only x86_64 (amd64) packages are provided; use an x86_64 server')"
    return
  fi
  flags=$(awk -F: '/^flags/ { print $2; exit }' "${PREFLIGHT_ROOT}/proc/cpuinfo" 2>/dev/null || true)
  if [ "$role" = control ] && [ -n "$flags" ] && ! printf '%s\n' "$flags" | grep -qw sse4_2; then
    preflight_record fail CPU架构 "$(msg 'x86_64，但 CPU 不支持 SSE4.2' 'x86_64, but the CPU lacks SSE4.2')" "$(msg 'ClickHouse 需要 SSE4.2，请更换 CPU 型号或在虚拟化平台开启 CPU 直通（host-passthrough）' 'ClickHouse needs SSE4.2; change the CPU model or enable CPU passthrough (host-passthrough) in the hypervisor')"
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
  case "$major$minor" in *[!0-9]*|'') preflight_record warn 内核 "$(msg "无法识别内核版本 $release" "cannot parse kernel version $release")"; return ;; esac
  if [ "$role" = node ]; then
    # The Agent signals OpenResty only through pidfd (Linux 5.3+, or a vendor
    # backport): there is no PID-reuse-prone fallback.
    if [ "$major" -lt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -lt 3 ]; }; then
      preflight_pidfd_probe || probe=$?
      case "$probe" in
        0) preflight_record warn 内核 "$release$(msg '（低于 5.3，但内核提供了 pidfd_open）' ' (older than 5.3 but provides pidfd_open)')" "$(msg '未在该内核上逐版本实测；建议升级到 5.10 以上' 'not tested on this kernel; 5.10 or newer is recommended')" ;;
        2) preflight_record fail 内核 "$release$(msg '（低于 5.3），无法确认 pidfd 支持' ' (older than 5.3); cannot confirm pidfd support')" "$(msg '请安装 perl 后重试，或升级内核到 5.3 以上（CentOS 7 可用 ELRepo kernel-lt/kernel-ml，Ubuntu 用 HWE 内核）' 'install perl and retry, or upgrade the kernel to 5.3+ (ELRepo kernel-lt/kernel-ml on CentOS 7, HWE kernel on Ubuntu)')" ;;
        *) preflight_record fail 内核 "$release$(msg ' 不支持 pidfd_open（节点重载 OpenResty 依赖它）' ' lacks pidfd_open (needed to reload OpenResty on nodes)')" "$(msg '请升级内核到 5.3 以上（CentOS 7 可用 ELRepo kernel-lt/kernel-ml，Ubuntu 16.04/18.04 用 HWE 内核，Debian 9/10 用 backports 内核）' 'upgrade the kernel to 5.3+ (ELRepo kernel-lt/kernel-ml on CentOS 7, HWE kernel on Ubuntu 16.04/18.04, backports kernel on Debian 9/10)')" ;;
      esac
      [ "$probe" = 0 ] || return 0
    elif [ "$major" -eq 5 ] && [ "$minor" -lt 10 ]; then
      preflight_record warn 内核 "$release$(msg '（5.3–5.9 可用，未逐版本实测）' ' (5.3–5.9 works, not tested on every release)')" "$(msg '建议使用 5.10 以上内核' 'a 5.10+ kernel is recommended')"
    fi
    if [ ! -r "${PREFLIGHT_ROOT}/sys/fs/cgroup/cgroup.controllers" ]; then
      preflight_record warn cgroup "$(msg '未启用 cgroup v2（legacy/hybrid）' 'cgroup v2 is not enabled (legacy/hybrid)')" "$(msg 'Agent 可在 cgroup v1 下运行；IPAddressDeny 等依赖 cgroup v2 的服务限制不会生效' 'the Agent runs on cgroup v1, but service limits that need cgroup v2 (IPAddressDeny etc.) will not apply')"
    fi
    if [ "$major" -gt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -ge 10 ]; }; then
      preflight_record pass 内核 "$release"
    fi
    return 0
  fi
  if [ "$major" -lt 4 ] || { [ "$major" -eq 4 ] && [ "$minor" -lt 18 ]; }; then
    preflight_record warn 内核 "$release$(msg '（低于 4.18，未验证）' ' (older than 4.18, not verified)')"
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
    preflight_record warn CPU核数 "$(msg '无法识别 CPU 核数' 'cannot detect the CPU count')"
  elif [ "$role" = control ] && [ "$cores" -lt 4 ]; then
    preflight_record warn CPU核数 "$cores $(msg '核（主控推荐至少 4 核）' 'cores (4+ recommended for the control plane)')" "$(msg 'PostgreSQL、ClickHouse、ClamAV 与管理端同机运行，核数少时访问日志与统计会明显变慢' 'PostgreSQL, ClickHouse, ClamAV and the console share this host; with few cores access logs and statistics slow down noticeably')"
  elif [ "$role" = node ] && [ "$cores" -lt 4 ]; then
    preflight_record warn CPU核数 "$cores $(msg '核（节点推荐至少 4 核）' 'cores (4+ recommended for nodes)')" "$(msg 'OpenResty、WAF 与 TLS 握手按核扩展，核数少时高并发与 CC 防护能力下降' 'OpenResty, WAF and TLS handshakes scale per core; few cores reduce concurrency and CC protection')"
  else
    preflight_record pass CPU核数 "$cores $(msg '核' 'cores')"
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
    preflight_record warn 内存 "$(msg '无法读取 /proc/meminfo' 'cannot read /proc/meminfo')"
  elif [ "$total" -lt "$fail_mib" ]; then
    if [ "$role" = node ] && [ $((total + swap)) -ge 2800 ]; then
      preflight_record warn 内存 "${total} MiB + Swap ${swap} MiB$(msg '（节点建议 2G 以上）' ' (2G+ recommended for nodes)')" "$(msg '内存不足 2G 时需保留至少 2G Swap' 'keep at least 2G of swap when memory is below 2G')"
    else
      preflight_record fail 内存 "${total} MiB（$(if [ "$role" = control ]; then msg '主控最低 4G' 'control plane minimum 4G'; else msg '节点最低 1G，且需 2G Swap' 'node minimum 1G plus 2G swap'; fi)）" \
        "$(if [ "$role" = control ]; then msg '请升级到 4G 以上内存（推荐 16G）' 'upgrade to 4G+ memory (16G recommended)'; else msg '请升级到 2G 以上内存，或 1G 内存加 2G Swap（推荐 8G）' 'upgrade to 2G+ memory, or 1G plus 2G swap (8G recommended)'; fi)"
    fi
  elif [ "$total" -lt "$warn_mib" ]; then
    swap_note=''; [ "$swap" -le 0 ] || swap_note=" + Swap ${swap} MiB"
    preflight_record warn 内存 "${total} MiB${swap_note}$(msg '（' ' (')$(if [ "$role" = control ]; then msg '主控推荐 16G 以上' '16G+ recommended for the control plane'; else msg '节点推荐 8G 以上' '8G+ recommended for nodes'; fi)$(msg '）' ')')" \
      "$(if [ "$role" = control ]; then msg '可以安装，但访问日志多时 ClickHouse 与 ClamAV 可能内存紧张；规模大建议 8 核 32G' 'installable, but ClickHouse and ClamAV may run short with heavy access logs; 8 cores / 32G for large deployments'; else msg '可以安装；大缓存或高并发建议 4 核 16G，内存不足 2G 时需加 2G Swap' 'installable; 4 cores / 16G for large caches or high concurrency, add 2G swap below 2G memory'; fi)"
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
    [ -n "$line" ] || { preflight_record warn 磁盘空间 "$(msg "无法读取 $path 所在分区的可用空间" "cannot read free space of the partition holding $path")"; continue; }
    mount=${line% *}; avail_mib=${line##* }
    case "$seen" in *" $mount "*) continue ;; esac
    seen="$seen$mount "
    if [ "$avail_mib" -lt "$fail_mib" ]; then
      preflight_record fail 磁盘空间 "$(msg "$path（分区 $mount）可用 $((avail_mib / 1024)) GiB，低于 $((fail_mib / 1024)) GiB" "$path (partition $mount) has $((avail_mib / 1024)) GiB free, below $((fail_mib / 1024)) GiB")" "$(msg "请清理或扩容 $mount 分区" "free up or grow the $mount partition")"
    elif [ "$avail_mib" -lt "$warn_mib" ]; then
      preflight_record warn 磁盘空间 "$(msg "$path（分区 $mount）可用 $((avail_mib / 1024)) GiB，建议 $((warn_mib / 1024)) GiB 以上" "$path (partition $mount) has $((avail_mib / 1024)) GiB free; $((warn_mib / 1024)) GiB+ recommended")" \
        "$(if [ "$role" = control ]; then msg '日志、分析数据和对象存储会持续增长，建议使用 100G 以上 SSD' 'logs, analytics and object storage keep growing; a 100G+ SSD is recommended'; else msg '缓存会占用磁盘，按缓存规模预留空间' 'the cache uses disk; reserve space for its size'; fi)"
    else
      preflight_record pass 磁盘空间 "$(msg "$path（分区 $mount）可用 $((avail_mib / 1024)) GiB" "$path (partition $mount) has $((avail_mib / 1024)) GiB free")"
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
    preflight_record fail systemd "$(msg '本机未以 systemd 作为 init 运行（容器或 OpenVZ/LXC 精简环境常见）' 'this host does not run systemd as init (common in containers or minimal OpenVZ/LXC)')" "$(msg '请在以 systemd 启动的完整虚拟机或物理机上安装' 'install on a full VM or bare-metal host booted with systemd')"
    return
  fi
  version=$(systemctl --version 2>/dev/null | awk 'NR == 1 { print $2 }')
  version=${version%%[!0-9]*}
  minimum=$(preflight_systemd_minimum)
  if [ -z "$version" ]; then
    preflight_record fail systemd "$(msg '无法识别 systemd 版本' 'cannot detect the systemd version')"
  elif [ "$version" -lt 219 ]; then
    preflight_record fail systemd "$(msg "版本 $version，低于 219" "version $version is older than 219")" "$(msg '请升级系统' 'upgrade the system')"
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
    preflight_record warn systemd "$(msg "版本 $version（低于 $minimum）：沙箱加固降级${missing:+，不支持:$missing}${groups:+；系统调用过滤分组缺失:$groups，将不启用系统调用过滤}" "version $version (older than $minimum): reduced sandboxing${missing:+, unsupported:$missing}${groups:+; missing syscall filter groups:$groups, syscall filtering disabled}")" \
      "$(msg '服务可以运行，但上述隔离措施不会生效；建议使用 systemd 249 以上的系统' 'services run, but the isolation above does not apply; systemd 249+ is recommended')"
  else
    preflight_record pass systemd "$(msg "版本 $version" "version $version")"
  fi
}

preflight_check_root() {
  if [ "$(id -u)" -eq 0 ]; then
    preflight_record pass root权限 "$(msg '以 root 运行' 'running as root')"
  else
    preflight_record fail root权限 "$(msg '当前用户' 'current user') $(id -un 2>/dev/null || id -u)" "$(msg '请使用 root 运行，或在命令前加 sudo' 'run as root or prefix the command with sudo')"
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
    case "$listening" in *" $port "*) busy="$busy${busy:+$(msg '、' ', ')}$port$(msg '（' ' (')$(preflight_label "$label")$(msg '）' ')')" ;; esac
  done
  if [ -n "$busy" ]; then
    preflight_record fail 端口占用 "$(msg '已被占用：' 'in use: ')$busy" "$(msg '用 ss -ltnp 查看占用进程；请在干净的系统上安装，或停止占用这些端口的服务' 'find the owners with ss -ltnp; install on a clean system or stop those services')"
  else
    preflight_record pass 端口占用 "$(msg '所需端口均空闲（' 'required ports are free (')$(printf '%s\n' "$@" | cut -d: -f1 | paste -sd, -)$(msg '）' ')')"
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
    command=${command//|/ $(msg 或 or) }
    if [ "$mode" = required ]; then missing="$missing $command"; else auto="$auto $command"; fi
  done
  if [ -n "$missing" ]; then
    preflight_record fail 必需命令 "$(msg '缺少:' 'missing:')$missing" "$(msg '请先用系统包管理器安装这些基础工具' 'install these base tools with the system package manager first')"
  elif [ -n "$auto" ]; then
    preflight_record pass 必需命令 "$(msg '基础命令齐全；将自动安装:' 'base commands present; will install automatically:')$auto"
  else
    preflight_record pass 必需命令 "$(msg '全部已安装' 'all installed')"
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
    preflight_record warn "连通性（$label）" "$(msg '未安装 curl，跳过检测' 'curl is not installed; check skipped')"
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
    preflight_record fail "连通性（$label）" "$(msg '无法连接' 'cannot connect to') $*" "$(msg '请检查 DNS、出站防火墙与代理设置，确认本机能访问该 HTTPS 地址' 'check DNS, outbound firewall and proxy settings so this host can reach that HTTPS address')"
    return
  fi
  if [ "$untrusted" = true ]; then
    preflight_record pass "连通性（$label）" "$url $(msg '可连接（证书不受系统信任，安装时用固定指纹校验）' 'reachable (certificate not trusted by the system; the install pins its fingerprint)')"
    preflight_record warn 时间偏差 "$(msg "证书不受系统信任，无法在检测阶段读取 $label 的服务器时间" "untrusted certificate: cannot read the server time of $label during the checks")" "$(msg '请确认已开启 NTP 时间同步（timedatectl set-ntp true）' 'make sure NTP time sync is on (timedatectl set-ntp true)')"
    return
  fi
  preflight_record pass "连通性（$label）" "$url $(msg '可连接' 'reachable')"
  remote_date=$(printf '%s\n' "$headers" | tr -d '\r' | awk 'tolower($1) == "date:" { sub(/^[^:]*: */, ""); print; exit }')
  remote_epoch=$(preflight_date_epoch "$remote_date")
  local_epoch=$(date -u +%s)
  if [ -z "$remote_epoch" ]; then
    preflight_record warn 时间偏差 "$(msg "无法从 $label 读取服务器时间" "cannot read the server time from $label")" "$(msg '请确认已开启 NTP 时间同步（timedatectl set-ntp true）' 'make sure NTP time sync is on (timedatectl set-ntp true)')"
    return
  fi
  skew=$((local_epoch - remote_epoch)); [ "$skew" -ge 0 ] || skew=$((-skew))
  if [ "$skew" -gt 300 ]; then
    preflight_record fail 时间偏差 "$(msg "本机与 $label 相差 ${skew} 秒（超过 300 秒，激活与签名校验会被拒绝）" "clock differs from $label by ${skew} s (over 300 s; activation and signature checks will be refused)")" "$(msg '请开启 NTP 同步：timedatectl set-ntp true，或安装 chrony 后重试' 'enable NTP: timedatectl set-ntp true, or install chrony and retry')"
  elif [ "$skew" -gt 60 ]; then
    preflight_record warn 时间偏差 "$(msg "本机与 $label 相差 ${skew} 秒" "clock differs from $label by ${skew} s")" "$(msg '建议开启 NTP 同步：timedatectl set-ntp true' 'enabling NTP is recommended: timedatectl set-ntp true')"
  else
    preflight_record pass 时间偏差 "${skew} $(msg 秒 s)"
  fi
}

# 参数：显示名 主机 端口。只做 TCP 建连，失败记为警告（可能是分离部署）。
preflight_check_tcp() {
  local label=$1 host=$2 port=$3
  if timeout 6 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$host" "$port" 2>/dev/null; then
    preflight_record pass "连通性（$label）" "$host:$port $(msg '可连接' 'reachable')"
  else
    preflight_record warn "连通性（$label）" "$host:$port $(msg '无法连接' 'unreachable')" "$(msg "请确认主控已放行 TCP $port，且本机出站未被拦截" "make sure the control plane allows TCP $port and outbound traffic from here is not blocked")"
  fi
}

preflight_check_selinux() {
  if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = Enforcing ]; then
    preflight_record warn SELinux "$(msg '处于 Enforcing 模式（未在 Enforcing 下做整机实测）' 'Enforcing mode (full installs not tested under Enforcing)')" \
      "$(msg '安装器会对安装目录执行 restorecon；若服务无法启动，用 ausearch -m avc -ts recent 查看拒绝记录' 'the installer runs restorecon on its directories; if a service fails to start, check denials with ausearch -m avc -ts recent')"
  fi
}

# 参数：需要放行的 TCP 端口列表。只检测并提示，不修改防火墙。
preflight_check_firewall() {
  local ports="$*" commands=''
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    commands=$(for port in $ports; do printf 'ufw allow %s/tcp; ' "$port"; done)
    preflight_record warn 防火墙 "$(msg 'ufw 已启用，安装器不会修改规则' 'ufw is active; the installer does not change its rules')" "$(msg '请放行：' 'allow: ')$commands"
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    commands=$(for port in $ports; do printf 'firewall-cmd --permanent --add-port=%s/tcp; ' "$port"; done)
    preflight_record warn 防火墙 "$(msg 'firewalld 正在运行，安装器不会修改规则' 'firewalld is running; the installer does not change its rules')" "$(msg '请放行：' 'allow: ')${commands}firewall-cmd --reload"
  elif command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP'; then
    commands=$(for port in $ports; do printf 'iptables -I INPUT -p tcp --dport %s -j ACCEPT; ' "$port"; done)
    preflight_record warn 防火墙 "$(msg 'iptables INPUT 默认策略为 DROP' 'iptables INPUT policy is DROP')" "$(msg '请放行：' 'allow: ')$commands"
  else
    preflight_record pass 防火墙 "$(msg "未检测到启用的主机防火墙；云安全组需放行 TCP ${ports// /, }" "no active host firewall; allow TCP ${ports// /, } in the cloud security group")"
  fi
}

# 主控与节点不能装在同一台机器上（端口与 OpenResty/nginx 冲突）。
preflight_check_coexistence() {
  local role=$1 path
  if [ "$role" = node ]; then
    for path in /etc/cdnca-control /usr/local/cdnca-control /data/cdnca-native-root; do
      if [ -e "${PREFLIGHT_ROOT}$path" ]; then
        preflight_record fail 主控共存 "$(msg "本机已安装主控（$path）" "a control plane is installed here ($path)")" "$(msg '节点不能与主控装在同一台机器上，请使用另一台服务器' 'a node cannot share a host with the control plane; use another server')"
        return
      fi
    done
  else
    for path in /etc/cdnca-edge-agent /opt/cdnca-node /usr/lib/cdnca-edge-agent; do
      if [ -e "${PREFLIGHT_ROOT}$path" ]; then
        preflight_record fail 节点共存 "$(msg "本机已安装节点（$path）" "a node is installed here ($path)")" "$(msg '主控不能与节点装在同一台机器上，请使用另一台服务器' 'the control plane cannot share a host with a node; use another server')"
        return
      fi
    done
  fi
}

# 检测项与端口用途在记录里保持中文（测试与调用方按中文匹配），报告时按界面语言显示。
preflight_label() {
  [ "${INSTALL_LANG:-zh}" = en ] || { printf '%s' "$1"; return 0; }
  case "$1" in
    连通性（*）) local inner=${1#连通性（}; printf 'Connectivity (%s)' "$(preflight_label "${inner%）}")" ;;
    '管理端网页（本机回环）') printf 'management web (loopback)' ;;
    *）) printf '%s' "$1" | sed 's/）$//' ;;
    操作系统) printf 'Operating system' ;; CPU架构) printf 'CPU architecture' ;; CPU核数) printf 'CPU cores' ;;
    内核) printf 'Kernel' ;; 内存) printf 'Memory' ;; 磁盘空间) printf 'Disk space' ;; root权限) printf 'Root' ;;
    端口占用) printf 'Ports' ;; 必需命令) printf 'Required commands' ;; 时间偏差) printf 'Clock skew' ;;
    防火墙) printf 'Firewall' ;; 主控共存) printf 'Control plane on this host' ;; 节点共存) printf 'Node on this host' ;;
    主控) printf 'control plane' ;; 授权端) printf 'licensing server' ;; 端口规划) printf 'Port plan' ;; 端口调整) printf 'Port changes' ;;
    管理端域名) printf 'Management domain' ;; 管理端网页) printf 'Management web' ;; 管理端HTTPS) printf 'management HTTPS' ;;
    节点升级下载) printf 'node upgrade downloads' ;;
    宝塔环境) printf 'BaoTa environment' ;; 宝塔站点证书) printf 'BaoTa site certificate' ;; 宝塔防火墙) printf 'BaoTa firewall' ;;
    宝塔手工步骤) printf 'BaoTa manual steps' ;; 宝塔nginx) printf 'BaoTa nginx' ;; 宝塔Apache) printf 'BaoTa Apache' ;;
    宝塔OpenLiteSpeed) printf 'BaoTa OpenLiteSpeed' ;;
    证书签发与依赖安装) printf 'certificate issuance and package installation' ;; 节点注册) printf 'node enrollment' ;;
    节点通道) printf 'node channel' ;; NATS监控) printf 'NATS monitoring' ;; Gateway健康检查) printf 'Gateway health check' ;;
    内部gRPC) printf 'internal gRPC' ;; 升级源) printf 'upgrade source' ;; 对象存储) printf 'object storage' ;;
    ClickHouse-复制) printf 'ClickHouse-replication' ;; 网关内部gRPC) printf 'Gateway internal gRPC' ;;
    网关NATS) printf 'Gateway NATS' ;; 网关Redis) printf 'Gateway Redis' ;; 网站HTTP) printf 'website HTTP' ;;
    网站HTTPS) printf 'website HTTPS' ;; 本机健康检查) printf 'local health check' ;; 本机证书服务) printf 'local certificate service' ;;
    *) printf '%s' "$1" ;;
  esac
}

preflight_tag() {
  case "$1" in pass) msg '通过' 'PASS' ;; warn) msg '警告' 'WARN' ;; *) msg '不通过' 'FAIL' ;; esac
}

# 返回 0 继续安装；有“不通过”或用户拒绝时返回 1。
preflight_report() {
  local prefix=$1 index fails=0 warns=0 answer
  printf '%s %s\n' "$prefix" "$(msg '安装前检测' 'Pre-installation checks')" >&2
  for index in "${!PREFLIGHT_STATUS[@]}"; do
    printf "%s   [%s] %s$(msg '：' ': ')%s\n" "$prefix" "$(preflight_tag "${PREFLIGHT_STATUS[$index]}")" "$(preflight_label "${PREFLIGHT_ITEM[$index]}")" "${PREFLIGHT_DETAIL[$index]}" >&2
    if [ "${PREFLIGHT_STATUS[$index]}" != pass ] && [ -n "${PREFLIGHT_HINT[$index]}" ]; then
      printf "%s          $(msg '建议：' 'Hint: ')%s\n" "$prefix" "${PREFLIGHT_HINT[$index]}" >&2
    fi
    case "${PREFLIGHT_STATUS[$index]}" in fail) fails=$((fails + 1)) ;; warn) warns=$((warns + 1)) ;; esac
  done
  if [ "$fails" -gt 0 ]; then
    printf "%s $(msg '检测结果：%d 项不通过、%d 项警告。请按上面的建议处理后重新执行安装命令；本机未做任何修改。' 'Result: %d failed, %d warnings. Fix them as suggested above and run the install command again; nothing on this host was changed.')\n" "$prefix" "$fails" "$warns" >&2
    return 1
  fi
  if [ "$warns" -eq 0 ]; then
    printf '%s %s\n' "$prefix" "$(msg '检测结果：全部通过。' 'Result: all checks passed.')" >&2
    return 0
  fi
  if [ "$PREFLIGHT_ASSUME_YES" = true ]; then
    printf "%s $(msg '检测结果：%d 项警告，已指定 --yes，继续安装。' 'Result: %d warnings; --yes given, continuing.')\n" "$prefix" "$warns" >&2
    return 0
  fi
  if { : </dev/tty; } 2>/dev/null && [ -t 2 ]; then
    printf "%s $(msg '检测结果：%d 项警告。确认继续安装？[y/N] ' 'Result: %d warnings. Continue the installation? [y/N] ')" "$prefix" "$warns" >&2
    IFS= read -r answer </dev/tty || answer=''
    case "$answer" in
      y|Y|yes|YES) return 0 ;;
      *) printf '%s %s\n' "$prefix" "$(msg '已取消安装；本机未做任何修改。如需跳过确认，请在命令末尾加 --yes。' 'Installation cancelled; nothing was changed. Add --yes to the command to skip this question.')" >&2; return 1 ;;
    esac
  fi
  printf "%s $(msg '检测结果：%d 项警告；非交互运行，继续安装（加 --yes 可省略本提示）。' 'Result: %d warnings; non-interactive run, continuing (--yes hides this note).')\n" "$prefix" "$warns" >&2
  return 0
}
