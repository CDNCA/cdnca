#!/usr/bin/env bash
# CDNCA edge-agent installer.
# The enrollment token is read from an owner-only file, used once, and removed
# before the long-lived agent service is started.
set -Eeuo pipefail
umask 077

# Legacy native layout path; a fresh install refuses it and never creates it.
readonly LEGACY_INSTALL_ROOT="/usr/local/cdnca-edge-agent"
# The Agent is installed through the signed packaging transaction so the root
# packaging helper can upgrade it in place (versions/<v> + current).
readonly PACKAGE_RELEASE_ROOT="/usr/lib/cdnca-edge-agent"
readonly AGENT_BINARY="${PACKAGE_RELEASE_ROOT}/current/edge-agent"
readonly PACKAGING_LIBEXEC="/usr/libexec/cdnca-edge-agent"
readonly HELPER_BINARY="/usr/libexec/cdnca-edge-agent-helper"
readonly HELPER_SOCKET="/run/cdnca-edge-agent/helper.sock"
readonly HELPER_RECEIPT_PIN="/etc/cdnca-edge-agent/helper-receipt-public.json"
readonly SYSTEMD_PACKAGE_DIR="/usr/lib/systemd/system"
readonly CONFIG_DIR="/etc/cdnca-edge-agent"
readonly IDENTITY_DIR="${CONFIG_DIR}/identity"
readonly TRUST_DIR="${CONFIG_DIR}/trust"
readonly TLS_DIR="${CONFIG_DIR}/tls"
readonly STATE_ROOT="/var/lib/cdnca-edge"
# Inside the Agent unit these resolve through the fixed state bind to
# /var/lib/cdnca-edge-agent-backups/active-state; the host path stays empty.
readonly JOURNAL_DIR="/var/lib/cdnca-edge-agent/gateway-journal"
readonly CERT_RUNTIME_DIR="/var/lib/cdnca-edge-agent/certificates"
readonly NODE_MONITORING_DIR="/var/lib/cdnca-node-monitoring"
readonly CONFIG_FILE="${CONFIG_DIR}/config.json"
readonly SERVICE_NAME="cdnca-edge-agent"
readonly NATIVE_ROOT="/opt/cdnca-node"
# Install record (PJ-E06): written right after the blank host gate, one line
# per completed step; --resume continues only the half install it describes.
readonly INSTALL_STATE_DIR="/var/lib/cdnca-node-install"
readonly INSTALL_STATE_FILE="${INSTALL_STATE_DIR}/state"
readonly INSTALL_STATE_SCHEMA="schema=cdnca.node-install-state/v1"
RESUME=false
# Static Ed25519 tool (tools/ed25519-tool); same pin as install-control.sh. All
# Ed25519 verification here and in packaging lib.sh uses it, not host OpenSSL.
readonly CDNCA_ED25519_TOOL_SHA256="82d8412f72b021d894ed14db2daded74b14f4930a167e307b22131ea067d7d17"
readonly ED25519_TOOL_INSTALLED="/usr/libexec/cdnca-ed25519"
ED25519_TOOL=""
ED25519_TOOL_INSTALLED_NOW=false

CONTROL_PLANE=""
CONTROL_PLANE_ORIGIN=""
ENROLLMENT_TOKEN=""
ENROLLMENT_TOKEN_STDIN=false
REGISTRATION_KEY=""
REGISTRATION_KEY_STDIN=false
MACHINE_ID_FILE="/etc/machine-id"
PRODUCT_UUID_FILE="/sys/class/dmi/id/product_uuid"
NODE_NAME=""
MASTER_HOST=""
MASTER_PORT=""
GATEWAY_ADDRESS=""
GATEWAY_ENROLLMENT_ADDRESS=""
GATEWAY_SERVER_NAME=""
# grpc (direct) or ws (WebSocket tunnel through a CDN, ADR 0013 §4.2).
GATEWAY_TRANSPORT=""
GATEWAY_TUNNEL_HOST=""
# Extra endpoints tried after the first (ADR 0013 §4.5): address|server_name|transport[|tunnel_host] separated by spaces.
GATEWAY_ENDPOINTS=""
GATEWAY_ENROLLMENT_PORT="19443"
GATEWAY_PORT="19444"
GATEWAY_ROOT_CA_FILE=""
GATEWAY_ROOT_CA_URL=""
GATEWAY_ROOT_CA_FALLBACK_URL=""
CONTROL_PLANE_CA_FILE=""
CONTROL_PLANE_CA_URL=""
CONTROL_PLANE_CA_FALLBACK_URL=""
CONTROL_PLANE_CA_SHA256=""
ARTIFACT_TRUST_FILE=""
ARTIFACT_TRUST_URL=""
ARTIFACT_TRUST_FALLBACK_URL=""
AGENT_URL=""
AGENT_FALLBACK_URL=""
AGENT_SHA256_URL=""
AGENT_SHA256_FALLBACK_URL=""
UPGRADE_TRUST_SHA256=""
UPGRADE_TRUST_URL=""
UPGRADE_TRUST_FALLBACK_URL=""
UPGRADE_INSTALLATION_ID=""
UPGRADE_DOWNLOAD_HOST=""
UPGRADE_DOWNLOAD_PORT=""
UPGRADE_DOWNLOAD_ADDRESSES=""
SKIP_FIREWALL=false
SKIP_SYSCTL_TUNING=false
# Probe only (default): run the external probes the controller asks for and
# answer the probe path; never joins the node market.
EXTERNAL_PROBE=true
# XDP kernel filter: detected at install and at every Agent start
# (native, then generic, else nftables). --disable-xdp keeps nftables only.
DISABLE_XDP=false
SYSCTL_ROOT=${CDNCA_SYSCTL_ROOT-/proc/sys}
SYSCTL_CONF=${CDNCA_SYSCTL_CONF-/etc/sysctl.d/90-cdnca-edge.conf}
ASSUME_YES=false
# PJ-E05: seconds to wait, after the Agent is stable, for its first Gateway session.
GATEWAY_SESSION_WAIT_SECONDS=${GATEWAY_SESSION_WAIT_SECONDS:-120}
AGENT_STARTED_AT=''
# Set when the Agent is kept running although the install did not complete.
INSTALL_KEEP=false
# Node public IP sent with the self-registration (control-api uses it when the
# request does not arrive from a public address). Order: --public-ip, a public
# address on a network interface, external echo services (agreeing answers),
# then a prompt on the terminal.
PUBLIC_IP=''
PUBLIC_IP_SOURCES=${CDNCA_PUBLIC_IP_SOURCES-'https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip https://4.ipw.cn'}

log() { printf '[cdnca-edge] %s\n' "$*"; }
warn() { printf '[cdnca-edge] warning: %s\n' "$*" >&2; }
fail() { printf '[cdnca-edge] error: %s\n' "$*" >&2; exit 1; }
# 安装进度阶段（名称|最短秒|最长秒|标记），与 main 里的 progress_stage 一一对应。
PROGRESS_LABEL='[cdnca-edge]'
PROGRESS_ROLE=node
PROGRESS_STAGES=(
  '环境预检并连接管理端|5|90|interactive'
  '安装基础工具|10|150|'
  '获取管理端证书与信任材料|5|60|'
  '下载并校验节点安装包|20|240|'
  '安装节点运行时|20|120|'
  '注册节点并写入配置|5|60|'
  '配置防火墙与内核参数|5|60|'
  '启动服务并自检|15|100|'
)

usage() {
  cat <<'EOF'
CDNCA edge-agent installer (x86_64; Ubuntu 24.04 official; Ubuntu 22.04,
Debian 12/13 and Rocky/AlmaLinux/RHEL 9/10 compatible)

Usage: printf '%s\n' KEY | install-node.sh --control-plane URL --registration-key-stdin [options]

Required:
  --control-plane URL          Management URL used for downloads and defaults
  --registration-key-stdin     Read the reusable node registration key (one
                               line) from standard input, never from process
                               arguments; the host registers itself as a
                               pending (待初始化) node and is initialized later
  --enrollment-token-stdin     Read the one-time token from standard input
  --token TOKEN                One-time token from the copied short command
  --enrollment-token TOKEN     Same as --token (visible in process arguments)

Without --upgrade-trust-sha256 the trust pin, gateway endpoints and download
fallback are read from URL/downloads/node-install-defaults over HTTPS.

Connection options:
  --master-host HOST           Management host (used when gateway is omitted)
  --master-port PORT           Management HTTPS port (metadata only)
  --gateway-address HOST:PORT  Gateway mTLS endpoint (default HOST:19444)
  --gateway-enrollment-address HOST:PORT
                               One-time enrollment endpoint (default HOST:19443)
  --gateway-server-name HOST  TLS SNI name (default gateway host)
  --gateway-transport grpc|ws  Direct gRPC (default) or WebSocket tunnel (Gateway behind a CDN)
  --gateway-tunnel-host HOST   Outer SNI/Host of the ws entrance (CDN name; default address host)
  --gateway-root-ca-file FILE  Existing Gateway CA bundle
  --gateway-root-ca-url URL    Download Gateway CA to the protected config dir
  --gateway-root-ca-fallback-url URL
                               Fallback Gateway CA URL
  --control-plane-ca-file FILE Existing CA for the management HTTPS endpoint
  --control-plane-ca-url URL   Management CA URL used for self-signed bootstrap
  --control-plane-ca-fallback-url URL
                               Fallback management CA URL
  --control-plane-ca-sha256 HEX64
                               Required pin when bootstrapping a self-signed HTTPS endpoint
  --artifact-trust-file FILE   Existing edge artifact trust document
  --artifact-trust-url URL     Download edge artifact trust document
  --artifact-trust-fallback-url URL
                               Fallback artifact trust URL
  --agent-url URL              Primary edge-agent archive URL
  --agent-fallback-url URL     Fallback edge-agent archive URL
  --agent-sha256-url URL       Primary SHA256SUMS URL for the archive
  --agent-sha256-fallback-url URL
                               Fallback SHA256SUMS URL for the archive
  --upgrade-trust-sha256 HEX64 Required pin of the management upgrade trust document
  --upgrade-trust-url URL      Upgrade trust document URL
  --upgrade-trust-fallback-url URL
                               Fallback upgrade trust document URL
  --node-name NAME             Node display name (default hostname)
  --public-ip IP               Public IP of this node (default: detected from the
                               network interfaces, then external echo services;
                               asked on the terminal when neither works)
  --skip-firewall              Do not touch the host firewall
  --no-external-probe          Do not take part in external node probing (default:
                               probe only; never joins the node market)
  --skip-sysctl-tuning         Keep kernel parameters as they are (default: raise
                               the edge baseline, never lower a larger value)
  --disable-xdp                Do not attach the XDP kernel filter (default: use
                               native XDP, else generic XDP, else nftables only)
  --ssh-guard-ignoreip "A B"   fail2ban sshd: addresses/CIDRs never banned (operator egress, platform hosts)
  --no-ssh-guard               Do not install the fail2ban SSH brute-force guard
  --keep-unattended-upgrades   Keep the system's automatic updates (default: disable
                               apt-daily, apt-daily-upgrade and unattended-upgrades;
                               packages stay installed for manual upgrades)
  --resume                     Continue a half-finished install of this host (same
                               command plus --resume); completed steps are skipped
  -y, --yes                    Continue without confirmation when preflight only warns
  -h, --help                   Show this help
EOF
}

need_value() { [ "$#" -ge 2 ] && [ -n "${2:-}" ] || fail "missing value for $1"; }
valid_url() { [[ "$1" =~ ^https://[^/?#@[:space:]]+(/[^[:space:]]*)?$ ]]; }
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
valid_sha256() { [[ "$1" =~ ^[[:xdigit:]]{64}$ ]]; }

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --control-plane) need_value "$@"; CONTROL_PLANE=$2; shift 2 ;;
      --enrollment-token|--token) need_value "$@"; ENROLLMENT_TOKEN=$2; shift 2 ;;
      --enrollment-token-stdin) ENROLLMENT_TOKEN_STDIN=true; shift ;;
      --registration-key-stdin) REGISTRATION_KEY_STDIN=true; shift ;;
      --node-name) need_value "$@"; NODE_NAME=$2; shift 2 ;;
      --public-ip) need_value "$@"; PUBLIC_IP=$2; shift 2 ;;
      --master-host) need_value "$@"; MASTER_HOST=$2; shift 2 ;;
      --master-port) need_value "$@"; MASTER_PORT=$2; shift 2 ;;
      --gateway-address) need_value "$@"; GATEWAY_ADDRESS=$2; shift 2 ;;
      --gateway-enrollment-address) need_value "$@"; GATEWAY_ENROLLMENT_ADDRESS=$2; shift 2 ;;
      --gateway-server-name) need_value "$@"; GATEWAY_SERVER_NAME=$2; shift 2 ;;
      --gateway-transport) need_value "$@"; GATEWAY_TRANSPORT=$2; shift 2 ;;
      --gateway-tunnel-host) need_value "$@"; GATEWAY_TUNNEL_HOST=$2; shift 2 ;;
      --gateway-port) need_value "$@"; GATEWAY_PORT=$2; shift 2 ;;
      --gateway-root-ca-file) need_value "$@"; GATEWAY_ROOT_CA_FILE=$2; shift 2 ;;
      --gateway-root-ca-url) need_value "$@"; GATEWAY_ROOT_CA_URL=$2; shift 2 ;;
      --gateway-root-ca-fallback-url) need_value "$@"; GATEWAY_ROOT_CA_FALLBACK_URL=$2; shift 2 ;;
      --control-plane-ca-file) need_value "$@"; CONTROL_PLANE_CA_FILE=$2; shift 2 ;;
      --control-plane-ca-url) need_value "$@"; CONTROL_PLANE_CA_URL=$2; shift 2 ;;
      --control-plane-ca-fallback-url) need_value "$@"; CONTROL_PLANE_CA_FALLBACK_URL=$2; shift 2 ;;
      --control-plane-ca-sha256) need_value "$@"; CONTROL_PLANE_CA_SHA256=$2; shift 2 ;;
      --artifact-trust-file) need_value "$@"; ARTIFACT_TRUST_FILE=$2; shift 2 ;;
      --artifact-trust-url) need_value "$@"; ARTIFACT_TRUST_URL=$2; shift 2 ;;
      --artifact-trust-fallback-url) need_value "$@"; ARTIFACT_TRUST_FALLBACK_URL=$2; shift 2 ;;
      --agent-url) need_value "$@"; AGENT_URL=$2; shift 2 ;;
      --agent-fallback-url) need_value "$@"; AGENT_FALLBACK_URL=$2; shift 2 ;;
      --agent-sha256-url) need_value "$@"; AGENT_SHA256_URL=$2; shift 2 ;;
      --agent-sha256-fallback-url) need_value "$@"; AGENT_SHA256_FALLBACK_URL=$2; shift 2 ;;
      --upgrade-trust-sha256) need_value "$@"; UPGRADE_TRUST_SHA256=$2; shift 2 ;;
      --upgrade-trust-url) need_value "$@"; UPGRADE_TRUST_URL=$2; shift 2 ;;
      --upgrade-trust-fallback-url) need_value "$@"; UPGRADE_TRUST_FALLBACK_URL=$2; shift 2 ;;
      --skip-firewall) SKIP_FIREWALL=true; shift ;;
      --skip-sysctl-tuning) SKIP_SYSCTL_TUNING=true; shift ;;
      --no-external-probe) EXTERNAL_PROBE=false; shift ;;
      --disable-xdp) DISABLE_XDP=true; shift ;;
      --ssh-guard-ignoreip) need_value "$@"; SSH_GUARD_IGNOREIP=$2; shift 2 ;;
      --no-ssh-guard) SSH_GUARD_ENABLED=false; shift ;;
      --keep-unattended-upgrades) KEEP_UNATTENDED_UPGRADES=true; shift ;;
      --resume) RESUME=true; shift ;;
      -y|--yes) ASSUME_YES=true; shift ;;
      -h|--help) usage; exit 0 ;;
      *) fail "unknown option: $1 (run --help for supported options)" ;;
    esac
  done
}

read_enrollment_token() {
  if "$REGISTRATION_KEY_STDIN"; then
    { [ -z "$ENROLLMENT_TOKEN" ] && ! "$ENROLLMENT_TOKEN_STDIN"; } || fail 'choose either --registration-key-stdin or an enrollment token'
    local extra=""
    IFS= read -r REGISTRATION_KEY || [ -n "$REGISTRATION_KEY" ] || fail 'registration key input is empty'
    if IFS= read -r extra || [ -n "$extra" ]; then fail 'registration key input must contain one line'; fi
    [[ "$REGISTRATION_KEY" =~ ^nrk1\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$ ]] ||
      fail '节点注册凭据格式无效，请从管理端「节点安装命令」重新复制命令'
    return 0
  fi
  if "$ENROLLMENT_TOKEN_STDIN"; then
    [ -z "$ENROLLMENT_TOKEN" ] || fail 'choose only one enrollment token input'
    local extra=""
    IFS= read -r ENROLLMENT_TOKEN || [ -n "$ENROLLMENT_TOKEN" ] || fail 'enrollment token input is empty'
    if IFS= read -r extra || [ -n "$extra" ]; then fail 'enrollment token input must contain one line'; fi
  fi
  [[ "$ENROLLMENT_TOKEN" =~ ^[A-Za-z0-9._-]+$ ]] && [ "${#ENROLLMENT_TOKEN}" -le 512 ] || fail 'enrollment token input is invalid'
}

# The management console publishes node-install-defaults for the short copied
# command (`... | bash -s -- --control-plane <console> --token <token>`). It is
# read over the same verified HTTPS origin that served this script, only fills
# values the command did not pass, and accepts strictly validated keys.
load_console_defaults() {
  [ -z "$UPGRADE_TRUST_SHA256" ] || return 0
  valid_url "$CONTROL_PLANE" || return 0
  local body key value
  # curl_download adds --control-plane-ca-file for the console origin (a
  # console on a private-CA or temporary self-signed certificate); the origin
  # is otherwise only set later by normalise_defaults.
  CONTROL_PLANE_ORIGIN=${CONTROL_PLANE_ORIGIN:-$(printf '%s' "${CONTROL_PLANE%/}" | sed -E 's#^(https?://[^/]+).*#\1#')}
  body=$(curl_download "${CONTROL_PLANE%/}/downloads/node-install-defaults" \
    -fsSL --connect-timeout 10 --max-time 30 --max-filesize 4096) ||
    fail 'cannot read node install defaults from the management console; copy a new install command from the management console'
  while IFS='=' read -r key value; do
    case "$key" in
      upgrade_trust_sha256) valid_sha256 "$value" || fail 'console node install defaults are invalid'
        UPGRADE_TRUST_SHA256=$value ;;
      gateway_enrollment_address|gateway_address)
        [[ "$value" =~ ^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):[0-9]{1,5}$ ]] || fail 'console node install defaults are invalid'
        if [ "$key" = gateway_address ]; then GATEWAY_ADDRESS=${GATEWAY_ADDRESS:-$value}
        else GATEWAY_ENROLLMENT_ADDRESS=${GATEWAY_ENROLLMENT_ADDRESS:-$value}; fi ;;
      gateway_server_name) [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$ ]] || fail 'console node install defaults are invalid'
        GATEWAY_SERVER_NAME=${GATEWAY_SERVER_NAME:-$value} ;;
      gateway_transport) [[ "$value" =~ ^(grpc|ws)$ ]] || fail 'console node install defaults are invalid'
        GATEWAY_TRANSPORT=${GATEWAY_TRANSPORT:-$value} ;;
      gateway_tunnel_host) [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || fail 'console node install defaults are invalid'
        GATEWAY_TUNNEL_HOST=${GATEWAY_TUNNEL_HOST:-$value} ;;
      gateway_endpoints) [[ "$value" =~ ^[A-Za-z0-9.:\[\]|\ -]{0,2048}$ ]] || fail 'console node install defaults are invalid'
        GATEWAY_ENDPOINTS=${GATEWAY_ENDPOINTS:-$value} ;;
      download_fallback_origin) [[ "$value" =~ ^https://[^/?#@[:space:]]+$ ]] || fail 'console node install defaults are invalid'
        # Signed artifacts may come from the authorization server when the
        # console download fails; signatures and checksums are still verified.
        AGENT_FALLBACK_URL=${AGENT_FALLBACK_URL:-$value/downloads/edge-agent/latest/cdnca-edge-agent.tar.gz}
        AGENT_SHA256_FALLBACK_URL=${AGENT_SHA256_FALLBACK_URL:-$value/downloads/edge-agent/latest/SHA256SUMS}
        ARTIFACT_TRUST_FALLBACK_URL=${ARTIFACT_TRUST_FALLBACK_URL:-$value/downloads/edge-agent/artifacts.json}
        UPGRADE_TRUST_FALLBACK_URL=${UPGRADE_TRUST_FALLBACK_URL:-$value/downloads/edge-agent/upgrade-trust.json} ;;
      ''|'#'*) ;;
      *) fail 'console node install defaults are invalid' ;;
    esac
  done <<<"$body"
  [ -n "$UPGRADE_TRUST_SHA256" ] || fail 'console node install defaults do not carry the upgrade trust pin'
}

require_commands() {
  local command
  # nft: the node DDoS protection table and the XDP filter's fallback need
  # nftables; a minimal image without it would run unprotected (PJ-E04).
  for command in curl jq openssl sha256sum systemctl file python3 flock timeout getent groupadd useradd passwd id ip \
    perl setpriv od systemd-sysusers systemd-tmpfiles nft; do
    command -v "$command" >/dev/null 2>&1 || return 1
  done
  # The packaging transaction hashes state trees with Digest::SHA.
  perl -MDigest::SHA -e 1 >/dev/null 2>&1
}

install_dependencies() {
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive progress_run '更新软件源' apt-get update -qq
    DEBIAN_FRONTEND=noninteractive progress_run '安装基础工具' apt-get install -y -qq curl jq openssl ca-certificates coreutils file python3 util-linux passwd libc-bin iproute2 perl systemd nftables
    # Ubuntu 18.04 ships setpriv as its own package; later util-linux includes it.
    command -v setpriv >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive progress_run '安装 setpriv' apt-get install -y -qq setpriv
  elif command -v dnf >/dev/null 2>&1; then
    # Minimal EL images ship curl-minimal/coreutils-single; requesting curl or
    # coreutils would conflict, and both already provide the needed commands.
    progress_run '安装基础工具' dnf -y -q install jq openssl ca-certificates file python3 util-linux passwd shadow-utils hostname iproute \
      perl-interpreter perl-Digest-SHA systemd procps-ng nftables
  elif command -v yum >/dev/null 2>&1; then
    progress_run '安装基础工具' yum -y -q install jq openssl ca-certificates file python3 util-linux passwd shadow-utils hostname iproute \
      perl-interpreter perl-Digest-SHA systemd procps-ng nftables
  else
    fail 'no supported package manager (apt-get, dnf or yum) was found'
  fi
  # Without nft the node has no DDoS protection: stop here rather than
  # install a node that silently runs without it.
  command -v nft >/dev/null 2>&1 ||
    fail 'nftables (the nft command) could not be installed; the node DDoS protection needs it. Install nftables and run the installer again'
}

normalise_defaults() {
  valid_url "$CONTROL_PLANE" || fail '--control-plane must be an HTTPS URL'
  [ -n "$ENROLLMENT_TOKEN" ] || [ -n "$REGISTRATION_KEY" ] || fail '--registration-key-stdin or --enrollment-token is required'
  [ "$EUID" -eq 0 ] || fail 'run this installer as root'
  CONTROL_PLANE=${CONTROL_PLANE%/}
  CONTROL_PLANE_ORIGIN=$(printf '%s' "$CONTROL_PLANE" | sed -E 's#^(https?://[^/]+).*#\1#')
  [ -n "$CONTROL_PLANE_ORIGIN" ] || fail '--control-plane must include a valid origin'
  NODE_NAME=${NODE_NAME:-$(hostname -s)}
  # PJ-E07: an IPv6 literal authority is [address][:port]; the host keeps no
  # brackets and gets them back wherever a port follows.
  local authority url_host url_port='' gateway_host
  authority=$(printf '%s' "$CONTROL_PLANE" | sed -E 's#^[A-Za-z]+://([^/]+).*#\1#')
  if [[ "$authority" =~ ^\[([0-9A-Fa-f:.]+)\](:([0-9]+))?$ ]]; then
    url_host=${BASH_REMATCH[1]} url_port=${BASH_REMATCH[3]}
  elif [[ "$authority" =~ ^([^:]+)(:([0-9]+))?$ ]]; then
    url_host=${BASH_REMATCH[1]} url_port=${BASH_REMATCH[3]}
  else
    fail "--control-plane host is invalid; an IPv6 address must be bracketed, e.g. https://[${authority}]"
  fi
  MASTER_HOST=${MASTER_HOST:-$url_host}
  MASTER_HOST=${MASTER_HOST#[}; MASTER_HOST=${MASTER_HOST%]}
  MASTER_PORT=${MASTER_PORT:-$url_port}
  MASTER_PORT=${MASTER_PORT:-443}
  gateway_host=$MASTER_HOST
  [[ "$gateway_host" != *:* ]] || gateway_host="[${gateway_host}]"
  valid_port "$MASTER_PORT" || fail '--master-port must be between 1 and 65535'
  valid_port "$GATEWAY_ENROLLMENT_PORT" || fail '--gateway-enrollment-port must be between 1 and 65535'
  valid_port "$GATEWAY_PORT" || fail '--gateway-port must be between 1 and 65535'
  GATEWAY_ENROLLMENT_ADDRESS=${GATEWAY_ENROLLMENT_ADDRESS:-${gateway_host}:${GATEWAY_ENROLLMENT_PORT}}
  GATEWAY_ADDRESS=${GATEWAY_ADDRESS:-${gateway_host}:${GATEWAY_PORT}}
  GATEWAY_SERVER_NAME=${GATEWAY_SERVER_NAME:-${MASTER_HOST}}
  GATEWAY_TRANSPORT=${GATEWAY_TRANSPORT:-grpc}
  [[ "$GATEWAY_TRANSPORT" =~ ^(grpc|ws)$ ]] || fail '--gateway-transport must be grpc or ws'
  [ -z "$GATEWAY_TUNNEL_HOST" ] || [ "$GATEWAY_TRANSPORT" = ws ] || fail '--gateway-tunnel-host requires --gateway-transport ws'
  ARTIFACT_TRUST_FILE=${ARTIFACT_TRUST_FILE:-${TRUST_DIR}/artifacts.json}
  CONTROL_PLANE_CA_URL=${CONTROL_PLANE_CA_URL:-${CONTROL_PLANE}/downloads/gateway-ca.pem}
  CONTROL_PLANE_CA_FALLBACK_URL=${CONTROL_PLANE_CA_FALLBACK_URL:-${CONTROL_PLANE_CA_URL}}
  AGENT_URL=${AGENT_URL:-${CONTROL_PLANE%/}/downloads/edge-agent/latest/cdnca-edge-agent.tar.gz}
  AGENT_FALLBACK_URL=${AGENT_FALLBACK_URL:-${CONTROL_PLANE%/}/downloads/edge-agent/latest/cdnca-edge-agent.tar.gz}
  AGENT_SHA256_URL=${AGENT_SHA256_URL:-${CONTROL_PLANE%/}/downloads/edge-agent/latest/SHA256SUMS}
  AGENT_SHA256_FALLBACK_URL=${AGENT_SHA256_FALLBACK_URL:-${AGENT_FALLBACK_URL%/*}/SHA256SUMS}
  GATEWAY_ROOT_CA_URL=${GATEWAY_ROOT_CA_URL:-${CONTROL_PLANE%/}/downloads/gateway-ca.pem}
  GATEWAY_ROOT_CA_FALLBACK_URL=${GATEWAY_ROOT_CA_FALLBACK_URL:-${GATEWAY_ROOT_CA_URL}}
  ARTIFACT_TRUST_URL=${ARTIFACT_TRUST_URL:-${CONTROL_PLANE%/}/downloads/edge-agent/artifacts.json}
  ARTIFACT_TRUST_FALLBACK_URL=${ARTIFACT_TRUST_FALLBACK_URL:-${ARTIFACT_TRUST_URL}}
  valid_url "$AGENT_URL" || fail '--agent-url must be an HTTPS URL'
  valid_url "$AGENT_FALLBACK_URL" || fail '--agent-fallback-url must be an HTTPS URL'
  valid_url "$AGENT_SHA256_URL" || fail '--agent-sha256-url must be an HTTPS URL'
  valid_url "$AGENT_SHA256_FALLBACK_URL" || fail '--agent-sha256-fallback-url must be an HTTPS URL'
  valid_url "$GATEWAY_ROOT_CA_URL" || fail '--gateway-root-ca-url must be an HTTPS URL'
  valid_url "$GATEWAY_ROOT_CA_FALLBACK_URL" || fail '--gateway-root-ca-fallback-url must be an HTTPS URL'
  valid_url "$CONTROL_PLANE_CA_URL" || fail '--control-plane-ca-url must be an HTTPS URL'
  valid_url "$CONTROL_PLANE_CA_FALLBACK_URL" || fail '--control-plane-ca-fallback-url must be an HTTPS URL'
  if [ -n "$CONTROL_PLANE_CA_SHA256" ]; then
    valid_sha256 "$CONTROL_PLANE_CA_SHA256" || fail '--control-plane-ca-sha256 must be exactly 64 hexadecimal characters'
    CONTROL_PLANE_CA_SHA256=$(printf '%s' "$CONTROL_PLANE_CA_SHA256" | tr '[:upper:]' '[:lower:]')
  fi
  if [ -n "$CONTROL_PLANE_CA_FILE" ]; then
    [ -f "$CONTROL_PLANE_CA_FILE" ] || fail "control-plane CA file does not exist: $CONTROL_PLANE_CA_FILE"
  fi
  valid_url "$ARTIFACT_TRUST_URL" || fail '--artifact-trust-url must be an HTTPS URL'
  # Without this pin the node could never verify upgrade executions; refuse to
  # install an unupgradable node rather than silently skipping upgrade trust.
  [ -n "$UPGRADE_TRUST_SHA256" ] || fail '--upgrade-trust-sha256 is required; copy a new install command from the management console'
  valid_sha256 "$UPGRADE_TRUST_SHA256" || fail '--upgrade-trust-sha256 must be exactly 64 hexadecimal characters'
  UPGRADE_TRUST_SHA256=$(printf '%s' "$UPGRADE_TRUST_SHA256" | tr '[:upper:]' '[:lower:]')
  UPGRADE_TRUST_URL=${UPGRADE_TRUST_URL:-${CONTROL_PLANE%/}/downloads/edge-agent/upgrade-trust.json}
  UPGRADE_TRUST_FALLBACK_URL=${UPGRADE_TRUST_FALLBACK_URL:-${UPGRADE_TRUST_URL}}
  valid_url "$UPGRADE_TRUST_URL" || fail '--upgrade-trust-url must be an HTTPS URL'
  valid_url "$UPGRADE_TRUST_FALLBACK_URL" || fail '--upgrade-trust-fallback-url must be an HTTPS URL'
  valid_url "$ARTIFACT_TRUST_FALLBACK_URL" || fail '--artifact-trust-fallback-url must be an HTTPS URL'
  [[ "$NODE_NAME" != *$'\n'* && "$NODE_NAME" != *$'\r'* && ${#NODE_NAME} -le 200 ]] || fail '--node-name contains invalid characters'
}

TEMP_DIR=''
NATIVE_STAGE_PARENT=''
NATIVE_STAGE=''
NATIVE_RELEASE=''
NATIVE_MANIFEST_SHA=''
NATIVE_VERSION=''
OPENRESTY_VERSION=''
NATIVE_SECURITY_ASSETS=''
ENROLLMENT_ATTEMPTED=false
AGENT_UNIT_INSTALLED=false
PACKAGING_INSTALLED=false
HELPER_UNITS_INSTALLED=false
CREATED_LINKS=()
CREATED_TARGETS=()
# >>> BEGIN package-automation (generated from scripts/lib/package-automation.sh; do not edit here)
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
# <<< END package-automation
cleanup() {
  local status=$? index unit
  [ -z "${PROGRESS_PREFIX:-}" ] || progress_on_exit "$status"
  if [ "$status" -ne 0 ] && ! "$INSTALL_KEEP"; then
    # First-install rollback never replaces or removes pre-existing state.
    # An attempted enrollment may have committed remotely: retain its identity
    # and recovery journal, and never claim that the token is reusable.
    if "$AGENT_UNIT_INSTALLED" || "$PACKAGING_INSTALLED"; then
      systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
      systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
    if "$HELPER_UNITS_INSTALLED"; then
      systemctl stop cdnca-edge-agent-helper.socket cdnca-edge-agent-helper.service >/dev/null 2>&1 || true
      systemctl disable cdnca-edge-agent-helper.socket >/dev/null 2>&1 || true
      rm -f -- "${SYSTEMD_PACKAGE_DIR}/cdnca-edge-agent-helper.socket" "${SYSTEMD_PACKAGE_DIR}/cdnca-edge-agent-helper.service"
    fi
    for unit in "${SERVICE_NAME}.service" cdnca-edge-agent-helper.service cdnca-edge-agent-helper.socket; do
      rm -f -- "/etc/systemd/system/${unit}.d/zz-cdnca-systemd-compat.conf"
      rmdir -- "/etc/systemd/system/${unit}.d" 2>/dev/null || true
    done
    if "$AGENT_UNIT_INSTALLED" || "$PACKAGING_INSTALLED" || "$HELPER_UNITS_INSTALLED"; then
      systemctl daemon-reload || true
    fi
    # The tool is removed only if this run created it and no packaging install
    # (whose retained files call it) has started.
    if "$ED25519_TOOL_INSTALLED_NOW" && ! "$PACKAGING_INSTALLED" && ed25519_tool_matches "$ED25519_TOOL_INSTALLED"; then
      rm -f -- "$ED25519_TOOL_INSTALLED"
    fi
    for index in "${!CREATED_LINKS[@]}"; do
      if [ -L "${CREATED_LINKS[$index]}" ] && [ "$(readlink "${CREATED_LINKS[$index]}")" = "${CREATED_TARGETS[$index]}" ]; then
        rm -f -- "${CREATED_LINKS[$index]}"
      fi
    done
    if [ -n "$NATIVE_RELEASE" ]; then warn "first installation rolled back; verified release retained at ${NATIVE_RELEASE}"; fi
    if "$PACKAGING_INSTALLED"; then warn "the signed Agent package remains under ${PACKAGE_RELEASE_ROOT} and ${PACKAGING_LIBEXEC}; its service is stopped and disabled"; fi
    if "$ENROLLMENT_ATTEMPTED"; then warn 'enrollment was attempted; identity/recovery state is retained and the one-time token may already be consumed'; fi
    if [ -f "$INSTALL_STATE_FILE" ]; then warn '安装未完成：修复上面的错误后，在原安装命令末尾加 --resume 续装（已完成的步骤会跳过）'; fi
  fi
  if [ -n "$NATIVE_STAGE_PARENT" ] && [ -d "$NATIVE_STAGE_PARENT" ]; then rm -rf -- "$NATIVE_STAGE_PARENT"; fi
  if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then rm -rf -- "$TEMP_DIR"; fi
  [ "${#PAUSED_APT_TIMERS[@]}" -eq 0 ] || systemctl start "${PAUSED_APT_TIMERS[@]}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# >>> BEGIN install-preflight (generated from scripts/lib/install-preflight.sh; do not edit here)
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
# <<< END install-preflight
# >>> BEGIN ssh-guard (generated from scripts/lib/ssh-guard.sh; do not edit here)
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
# <<< END ssh-guard

# >>> BEGIN install-progress (generated from scripts/lib/install-progress.sh; do not edit here)
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
# <<< END install-progress
# >>> BEGIN systemd-compat (generated from scripts/lib/systemd-compat.sh; do not edit here)
# shellcheck shell=bash
# systemd 兼容渲染（主控与节点共用）。
#
# 唯一源文件：由 scripts/sync-install-preflight.mjs 逐字嵌入 install-control.sh
# 与 install-node.sh 的 “BEGIN/END systemd-compat” 标记之间。
#
# 原则：单元文件本身不改（节点单元受签名清单逐字节校验，主控单元受升级器
# 校验），只在本机 systemd 不认识其中的指令时，生成
#   /etc/systemd/system/<unit>.d/zz-cdnca-systemd-compat.conf
# 把“功能性”指令换成旧版本能理解的等价写法；纯加固指令旧版本本来就会忽略，
# 这里只记录下来供安装前检测提示“沙箱加固降级”。新版 systemd 上不产生任何
# 文件，行为与原来完全一致。依据：docs/install/os-support-matrix.md 第 2 节。
#
# 本机支持哪些指令，直接从 systemd 二进制里的 gperf 表（"Section.Key"）和
# 系统调用分组名（"@group"）判断，不按发行版或版本号猜（RHEL 有大量回移植）。

SYSTEMD_COMPAT_ROOT=${SYSTEMD_COMPAT_ROOT:-}
SYSTEMD_COMPAT_DEGRADED=()

systemd_compat_binaries() {
  {
    local candidate binary
    # The directive tables live in PID 1 or in the private libraries it links
    # (libsystemd-core-NNN.so on EL9, libsystemd-shared-NNN.so on Debian/Ubuntu).
    for binary in "${SYSTEMD_COMPAT_ROOT}"/lib/systemd/systemd "${SYSTEMD_COMPAT_ROOT}"/usr/lib/systemd/systemd; do
      [ -f "$binary" ] && [ ! -L "$binary" ] || continue
      printf '%s\n' "$binary"
      [ -z "$SYSTEMD_COMPAT_ROOT" ] || continue
      ldd "$binary" 2>/dev/null | awk '$3 ~ /\/libsystemd-[a-z]+-[0-9.]+\.so$/ { print $3 }'
    done
    for candidate in "${SYSTEMD_COMPAT_ROOT}"/lib/systemd/libsystemd-*.so "${SYSTEMD_COMPAT_ROOT}"/usr/lib/systemd/libsystemd-*.so \
      "${SYSTEMD_COMPAT_ROOT}"/usr/lib64/systemd/libsystemd-*.so "${SYSTEMD_COMPAT_ROOT}"/usr/lib/x86_64-linux-gnu/systemd/libsystemd-*.so \
      "${SYSTEMD_COMPAT_ROOT}"/lib/x86_64-linux-gnu/systemd/libsystemd-*.so; do
      [ -f "$candidate" ] && [ ! -L "$candidate" ] && printf '%s\n' "$candidate"
    done
  } 2>/dev/null | sort -u
}

# 参数：Section.Key 或 @group。在 systemd 二进制的字符串表中按整词查找。
systemd_compat_knows() {
  local binaries
  binaries=$(systemd_compat_binaries)
  [ -n "$binaries" ] || return 1
  # shellcheck disable=SC2086 # one path per line, no spaces in systemd paths
  LC_ALL=C grep -aqwF -- "$1" $binaries
}

systemd_compat_version() {
  systemctl --version 2>/dev/null | awk 'NR == 1 { sub(/[^0-9].*/, "", $2); print $2 }'
}

# 打印单元需要的兼容 drop-in 内容（无需兼容时为空），并把被忽略的加固指令
# 追加到 SYSTEMD_COMPAT_DEGRADED。参数：单元文件路径。
systemd_compat_render() {
  local unit=$1 section='' line key value token version reset_filter=false exec_start='' bind=''
  local -a service=()
  version=$(systemd_compat_version)
  version=${version:-0}
  # Ubuntu 24.04 (255) is the baseline the units were written for.
  [ "$version" -lt 255 ] || return 0
  # Never downgrade on a probe that cannot see the directive tables: a key that
  # every systemd has must be found first.
  systemd_compat_knows Service.ExecStart && systemd_compat_knows Unit.Description || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      \[*\]) section=${line#[}; section=${section%]}; continue ;;
      ''|'#'*|';'*) continue ;;
      *=*) key=${line%%=*}; value=${line#*=} ;;
      *) continue ;;
    esac
    [ "$section" = Service ] && [ "$key" = ExecStart ] && exec_start=$value
    if [ "$section" = Service ] && [ "$key" = SystemCallFilter ]; then
      for token in $value; do
        token=${token#\~}
        case "$token" in
          @*) systemd_compat_knows "$token" || reset_filter=true ;;
        esac
      done
    fi
    if [ "$section" = Service ] && [ "$key" = Type ] && [ "$value" = exec ] && [ "$version" -lt 240 ]; then
      service+=('Type=simple')
    fi
    if [ "$section" = Service ] && [ "$key" = ProtectSystem ] && [ "$value" = strict ] && [ "$version" -lt 232 ]; then
      # “strict”在 232 之前是无效值，整行会被忽略；full 至少保护 /usr /boot /etc。
      service+=('ProtectSystem=full')
      SYSTEMD_COMPAT_DEGRADED+=("ProtectSystem=strict→full")
    fi
    systemd_compat_knows "$section.$key" && continue
    case "$section.$key" in
      Unit.StartLimitIntervalSec) service+=("StartLimitInterval=$value") ;;
      Unit.StartLimitBurst) service+=("StartLimitBurst=$value") ;;
      Service.BindPaths) bind=$value ;;
      Service.ReadWritePaths) service+=("ReadWriteDirectories=$value") ;;
      Service.ReadOnlyPaths) service+=("ReadOnlyDirectories=$value") ;;
      *) SYSTEMD_COMPAT_DEGRADED+=("$key") ;;
    esac
  done <"$unit"
  if [ "$reset_filter" = true ]; then
    # 旧版本不认识其中的分组时，部分生效的白名单可能拦截必需的系统调用；
    # 整体清空（加固降级）比服务被内核杀掉安全。
    service+=('SystemCallFilter=')
    SYSTEMD_COMPAT_DEGRADED+=("SystemCallFilter")
  fi
  if [ -n "$bind" ]; then
    # BindPaths（233+）之前：在同一服务进程的私有挂载命名空间（PrivateTmp/
    # ProtectSystem 已创建）内先绑定，再 exec 原程序，效果等同于 BindPaths。
    local source=${bind%%:*} rest=${bind#*:} target
    target=${rest%%:*}
    [ -n "$exec_start" ] && [ -n "$source" ] && [ -n "$target" ] || return 1
    # "$$" is a literal dollar for systemd; the shell then sees "$1".
    service+=('ExecStart=' "ExecStart=/bin/sh -c 'mount --bind \"\$\$1\" \"\$\$2\" && shift 2 && exec \"\$\$@\"' sh $source $target $exec_start")
  fi
  [ "${#service[@]}" -gt 0 ] || return 0
  printf '# Generated by the CDNCA installer for systemd %s; see docs/install/os-support-matrix.md.\n' "$version"
  printf '[Service]\n'
  printf '%s\n' "${service[@]}"
}

# 生成并安装 drop-in（只在需要时）。参数：单元文件路径 单元名。
systemd_compat_apply() {
  local unit=$1 name=$2 content directory
  content=$(systemd_compat_render "$unit") || return 1
  [ -n "$content" ] || return 0
  directory="${SYSTEMD_COMPAT_ROOT}/etc/systemd/system/${name}.d"
  install -d -m 0755 "$directory"
  printf '%s\n' "$content" >"${directory}/zz-cdnca-systemd-compat.conf"
  chmod 0644 "${directory}/zz-cdnca-systemd-compat.conf"
}
# <<< END systemd-compat

# Read-only host checks before any download, account or service change.
run_preflight() {
  preflight_check_root
  preflight_check_os node
  preflight_check_arch node
  preflight_check_kernel node
  preflight_check_cpu node
  preflight_check_memory node
  preflight_check_disk node
  preflight_check_systemd
  preflight_check_coexistence node
  if "$RESUME"; then
    preflight_record pass 端口占用 '续装：跳过（端口可能由上次安装启动的服务占用）'
  else
    preflight_check_ports 80:网站HTTP 443:网站HTTPS 18080:本机健康检查 18443:本机证书服务
  fi
  preflight_check_commands bash awk sed grep df uname id 'apt-get|dnf' -- curl jq openssl sha256sum systemctl file python3 \
    flock timeout getent groupadd useradd passwd ip perl setpriv od systemd-sysusers systemd-tmpfiles
  if valid_url "$CONTROL_PLANE"; then
    preflight_check_remote 主控 "${CONTROL_PLANE%/}/downloads/node-install-defaults"
  else
    preflight_record fail 主控 '--control-plane 不是 HTTPS 地址' '请从管理端「节点安装命令」重新复制完整命令'
  fi
  preflight_check_selinux
  preflight_check_firewall 80 443
  PREFLIGHT_ASSUME_YES=$ASSUME_YES
  preflight_report '[cdnca-edge]' || exit 1
}

# After console defaults: nodes must reach the Gateway enrollment port. A split
# Gateway may be filtered from here only temporarily, so this only warns.
check_gateway_reachable() {
  local address=$GATEWAY_ENROLLMENT_ADDRESS host port
  host=${address%:*}; port=${address##*:}; host=${host#[}; host=${host%]}
  timeout 6 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$host" "$port" 2>/dev/null ||
    warn "无法连接节点注册端口 ${address}；请确认主控已放行 TCP ${port}（以及节点通道 ${GATEWAY_ADDRESS}），否则注册会失败"
}

assert_blank_host() {
  [ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || fail 'native node first install requires Linux x86_64'
  case "$(preflight_os_tier node "$(preflight_os_release_value ID)" "$(preflight_os_release_value VERSION_ID)")" in
    official|compatible) ;;
    *) fail 'native node first install requires Ubuntu 24.04/22.04/20.04/18.04, Debian 10-13 or Rocky/AlmaLinux/RHEL 8/9/10' ;;
  esac
  if [ ! -d /run/systemd/system ] || ! command -v systemctl >/dev/null || ! command -v flock >/dev/null; then
    fail 'systemd and flock are required'
  fi
  local lock=/run/lock/cdnca-native-node-install.lock path unit
  if [ ! -e "$lock" ] && [ ! -L "$lock" ]; then (set -o noclobber; : >"$lock") || fail 'cannot create node install lock'; fi
  [ ! -L "$lock" ] && [ -f "$lock" ] && [ "$(stat -c '%u:%h:%a' "$lock")" = '0:1:600' ] || fail 'unsafe node install lock'
  exec 9>>"$lock"
  flock -n 9 || fail 'another node installation is running'
  if "$RESUME"; then install_state_check_resumable; fi
  for path in "$INSTALL_STATE_DIR" "$NATIVE_ROOT" "$LEGACY_INSTALL_ROOT" "$CONFIG_DIR" "$STATE_ROOT" "$NODE_MONITORING_DIR" /var/lib/cdnca-edge-agent \
    /var/lib/site-runtime /var/log/cdnca-edge-agent /usr/local/openresty /usr/local/share/cdnca /opt/cdnca/l4geo /usr/sbin/nginx \
    "$PACKAGE_RELEASE_ROOT" "$PACKAGING_LIBEXEC" "$HELPER_BINARY" /var/lib/cdnca-edge-agent-backups \
    /var/lib/cdnca-edge-agent-packaging /var/lib/cdnca-edge-agent-helper; do
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then continue; fi
    if "$RESUME"; then resume_owned_path "$path" || fail "resume refused: ${path} was not left by this installer"; continue; fi
    install_state_unfinished_hint
    fail "first install refused: existing path ${path}"
  done
  # cdnca-openresty-native.service: a leftover would start a second OpenResty
  # on the ports the dynamic routing runtime binds.
  for unit in "$SERVICE_NAME.service" cdnca-openresty-native.service cdnca-openresty.service openresty.service nginx.service \
    cdnca-edge-agent-helper.service cdnca-edge-agent-helper.socket; do
    [ "$(systemctl show "$unit" --property=LoadState --value)" != not-found ] || continue
    # Resume: only the Agent and helper units the packaging/helper steps installed.
    if "$RESUME" && [[ "$unit" = "$SERVICE_NAME.service" || "$unit" = cdnca-edge-agent-helper.* ]]; then continue; fi
    install_state_unfinished_hint
    fail "first install refused: existing service ${unit}"
  done
  for path in /opt /usr/local /usr/local/share /etc/systemd/system /opt/cdnca; do
    if [ -L "$path" ] || { [ -e "$path" ] && [ ! -d "$path" ]; }; then fail 'unsafe installation parent'; fi
  done
}

# Install record (PJ-E06). The file is created right after a passed blank host
# gate, so only a half install of this installer can carry one.
install_state_begin() {
  mkdir -m 0700 "$INSTALL_STATE_DIR"
  (set -o noclobber; printf '%s\n' "$INSTALL_STATE_SCHEMA" >"$INSTALL_STATE_FILE")
  chmod 0600 "$INSTALL_STATE_FILE"
}
# No record (a step run outside main) records nothing; --resume then refuses.
install_state_add() { [ ! -f "$INSTALL_STATE_FILE" ] || printf '%s\n' "$1" >>"$INSTALL_STATE_FILE"; }
install_state_has() { grep -Fxq -- "$1" "$INSTALL_STATE_FILE" 2>/dev/null; }
install_state_value() { sed -n "s/^$1=//p" "$INSTALL_STATE_FILE" 2>/dev/null | tail -n 1; }

install_state_unfinished_hint() {
  [ -f "$INSTALL_STATE_FILE" ] && ! install_state_has step=done || return 0
  warn "上次节点安装未完成（${INSTALL_STATE_FILE}）：修复失败原因后，在原安装命令末尾加 --resume 续装，已完成的步骤会跳过"
}

install_state_check_resumable() {
  [ -f "$INSTALL_STATE_FILE" ] || fail "无法续装：本机没有安装记录 ${INSTALL_STATE_FILE}，--resume 只用于本安装器上次未完成的安装"
  [ ! -L "$INSTALL_STATE_DIR" ] && [ ! -L "$INSTALL_STATE_FILE" ] && [ "$(stat -c '%u:%h:%a' "$INSTALL_STATE_FILE")" = '0:1:600' ] &&
    [ "$(head -n 1 "$INSTALL_STATE_FILE")" = "$INSTALL_STATE_SCHEMA" ] || fail "unsafe or unknown install record ${INSTALL_STATE_FILE}"
  ! install_state_has step=done || fail '本机节点已安装完成，无需续装；如需重装，请先在管理端删除该节点并清理本机'
  log "续装上次未完成的节点安装（${INSTALL_STATE_FILE}）"
}

# resume_owned_path: a path the previous run of this installer may have left.
# Links must still point where activation put them; never a foreign runtime.
resume_owned_path() {
  case "$1" in
    "$LEGACY_INSTALL_ROOT"|/var/lib/site-runtime|/usr/sbin/nginx) return 1 ;;
    /usr/local/openresty) [ -L "$1" ] && [ "$(readlink "$1")" = "${NATIVE_ROOT}/current/runtime/openresty" ] ;;
    /usr/local/share/cdnca) [ -L "$1" ] && [ "$(readlink "$1")" = "${NATIVE_ROOT}/current/lua/share/cdnca" ] ;;
    /opt/cdnca/l4geo) [ -L "$1" ] && [ "$(readlink "$1")" = "${NATIVE_ROOT}/current/lua/l4geo" ] ;;
    "$HELPER_BINARY") [ -f "$1" ] && [ ! -L "$1" ] ;;
    *) [ -d "$1" ] && [ ! -L "$1" ] ;;
  esac
}

is_control_plane_url() {
  local url=$1
  case "$url" in
    "${CONTROL_PLANE_ORIGIN}"|"${CONTROL_PLANE_ORIGIN}"/*) return 0 ;;
    *) return 1 ;;
  esac
}

curl_download() {
  local url=$1
  shift
  local -a trust_args=()
  if [ -n "$CONTROL_PLANE_CA_FILE" ] && is_control_plane_url "$url"; then
    trust_args+=(--cacert "$CONTROL_PLANE_CA_FILE")
    # A customer may configure a publicly trusted certificate for the control
    # plane instead of the installer-generated root.  The pinned CA is still
    # used first, but must not replace the system trust store permanently.
    if curl --proto '=https' --proto-redir '=https' "${trust_args[@]}" "$@" "$url"; then
      return 0
    fi
  fi
  curl --proto '=https' --proto-redir '=https' "$@" "$url"
}

verify_ca_file() {
  local file=$1 expected actual
  [ -s "$file" ] || return 1
  openssl x509 -in "$file" -noout >/dev/null 2>&1 || return 1
  openssl x509 -in "$file" -noout -checkend 0 >/dev/null 2>&1 || return 1
  openssl x509 -in "$file" -noout -text 2>/dev/null | grep -Fq 'CA:TRUE' || return 1
  if [ -n "$CONTROL_PLANE_CA_SHA256" ]; then
    expected=$CONTROL_PLANE_CA_SHA256
    actual=$(sha256sum "$file" | awk '{print tolower($1)}')
    [ "$actual" = "$expected" ] || return 1
  fi
}

prepare_control_plane_ca() {
  [ "${CONTROL_PLANE%%:*}" = 'https' ] || return 0
  [ -n "$TEMP_DIR" ] || TEMP_DIR=$(mktemp -d -t cdnca-edge-install.XXXXXX)
  if [ -n "$CONTROL_PLANE_CA_FILE" ]; then
    verify_ca_file "$CONTROL_PLANE_CA_FILE" || fail 'control-plane CA file is invalid or does not match --control-plane-ca-sha256'
    return 0
  fi

  local candidate="${TEMP_DIR}/control-plane-ca.pem"
  # A publicly trusted management certificate needs no bootstrap exception.
  # For the generated self-signed certificate, the one-time insecure fetch is
  # allowed only when the copied command supplied an exact CA digest.
  if ! curl --proto '=https' --proto-redir '=https' -fL --connect-timeout 10 --max-time 60 --max-filesize 65536 --retry 1 --output "$candidate" "$CONTROL_PLANE_CA_URL" ||
    ! verify_ca_file "$candidate"; then
    if [ "$CONTROL_PLANE_CA_FALLBACK_URL" != "$CONTROL_PLANE_CA_URL" ] &&
      curl --proto '=https' --proto-redir '=https' -fL --connect-timeout 10 --max-time 60 --max-filesize 65536 --retry 1 --output "$candidate" "$CONTROL_PLANE_CA_FALLBACK_URL" &&
      verify_ca_file "$candidate"; then
      CONTROL_PLANE_CA_FILE=$candidate
      return 0
    fi
    [ -n "$CONTROL_PLANE_CA_SHA256" ] || fail 'management HTTPS uses an untrusted certificate; rerun with --control-plane-ca-sha256 from the management page'
    rm -f -- "$candidate"
    curl --proto '=https' --proto-redir '=https' --insecure -fL --connect-timeout 10 --max-time 60 --max-filesize 65536 --retry 1 --output "$candidate" "$CONTROL_PLANE_CA_URL" ||
      if [ "$CONTROL_PLANE_CA_FALLBACK_URL" != "$CONTROL_PLANE_CA_URL" ]; then
        curl --proto '=https' --proto-redir '=https' --insecure -fL --connect-timeout 10 --max-time 60 --max-filesize 65536 --retry 1 --output "$candidate" "$CONTROL_PLANE_CA_FALLBACK_URL"
      else
        return 1
      fi
    verify_ca_file "$candidate" || fail 'management CA bootstrap failed: downloaded certificate does not match the pinned SHA-256'
  fi
  CONTROL_PLANE_CA_FILE=$candidate
}

download_verified() {
  local primary=$1 fallback=$2 sums_primary=$3 sums_fallback=$4 output=$5 expected_name=$6
  local candidate sums expected actual index
  local -a artifact_urls=("$primary")
  local -a checksum_urls=("$sums_primary")
  if [ "$fallback" != "$primary" ]; then
    artifact_urls+=("$fallback")
    checksum_urls+=("$sums_fallback")
  fi
  for index in "${!artifact_urls[@]}"; do
    candidate="${TEMP_DIR}/download-candidate"
    sums="${TEMP_DIR}/download-checksums"
    rm -f -- "$candidate" "$sums"
    progress_download 节点安装包 curl_download "${artifact_urls[$index]}" -fL --connect-timeout 10 --max-time 300 --max-filesize 536870912 --retry 1 --output "$candidate" || continue
    if file "$candidate" | grep -Eqi 'HTML|text, Unicode|ASCII text'; then
      continue
    fi
    curl_download "${checksum_urls[$index]}" -fL --connect-timeout 10 --max-time 60 --max-filesize 65536 --retry 1 --output "$sums" || continue
    expected=$(awk -v name="$expected_name" '$2 == name || $2 == "./" name || $2 == "edge-agent.tar.gz" || $2 == "./edge-agent.tar.gz" || $2 == "cdnca-edge-agent.tar.gz" || $2 == "./cdnca-edge-agent.tar.gz" {print $1; exit}' "$sums")
    [[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || continue
    actual=$(sha256sum "$candidate" | awk '{print $1}')
    [ "$actual" = "$expected" ] || continue
    cp -- "$candidate" "$output"
    return 0
  done
  return 1
}

download_json_verified() {
  local primary=$1 fallback=$2 output=$3 expression=$4 candidate index
  local -a urls=("$primary")
  [ "$fallback" != "$primary" ] && urls+=("$fallback")
  for index in "${!urls[@]}"; do
    candidate="${TEMP_DIR}/json-candidate"
    rm -f -- "$candidate"
    curl_download "${urls[$index]}" -fL --connect-timeout 10 --max-time 60 --max-filesize 65536 --retry 1 --output "$candidate" || continue
    jq -e "$expression" "$candidate" >/dev/null 2>&1 || continue
    cp -- "$candidate" "$output"
    return 0
  done
  return 1
}

download_certificate_verified() {
  local primary=$1 fallback=$2 output=$3 candidate index
  local -a urls=("$primary")
  [ "$fallback" != "$primary" ] && urls+=("$fallback")
  for index in "${!urls[@]}"; do
    candidate="${TEMP_DIR}/certificate-candidate"
    rm -f -- "$candidate"
    curl_download "${urls[$index]}" -fL --connect-timeout 10 --max-time 60 --max-filesize 65536 --retry 1 --output "$candidate" || continue
    openssl x509 -in "$candidate" -noout >/dev/null 2>&1 || continue
    cp -- "$candidate" "$output"
    return 0
  done
  return 1
}

# A tool is usable only when its bytes match this installer's pin.
ed25519_tool_matches() {
  [ -f "$1" ] && [ ! -L "$1" ] && [ -x "$1" ] && [ "$(sha256sum "$1" | awk '{print $1}')" = "$CDNCA_ED25519_TOOL_SHA256" ]
}

resolve_ed25519_tool() {
  local candidate
  [ -z "$ED25519_TOOL" ] || return 0
  # Management side: the verified copy at the management path; node side: the
  # installed copy or the one fetched and pinned by fetch_ed25519_tool.
  for candidate in "${CDNCA_ED25519_TOOL_PATH:-}" "$ED25519_TOOL_INSTALLED" /usr/local/libexec/cdnca/cdnca-ed25519; do
    if [ -n "$candidate" ] && ed25519_tool_matches "$candidate"; then ED25519_TOOL=$candidate; return 0; fi
  done
  return 1
}

fetch_ed25519_tool() {
  local candidate url
  resolve_ed25519_tool && return 0
  [ -n "$TEMP_DIR" ] || TEMP_DIR=$(mktemp -d -t cdnca-edge-install.XXXXXX)
  candidate="${TEMP_DIR}/cdnca-ed25519"
  for url in "${AGENT_URL%/latest/*}/cdnca-ed25519" "${AGENT_FALLBACK_URL%/latest/*}/cdnca-ed25519"; do
    rm -f -- "$candidate"
    curl_download "$url" -fsSL --connect-timeout 10 --max-time 120 --max-filesize 16777216 --retry 1 --output "$candidate" || continue
    chmod 0500 "$candidate"
    if ed25519_tool_matches "$candidate"; then ED25519_TOOL=$candidate; return 0; fi
  done
  fail 'cannot download the Ed25519 tool matching this installer; copy a new install command from the management console'
}

# After activation: the fixed root-only copy that packaging lib.sh calls.
install_ed25519_tool() {
  if [ -e "$ED25519_TOOL_INSTALLED" ] || [ -L "$ED25519_TOOL_INSTALLED" ]; then
    [ "$(stat -c '%u:%a:%h' "$ED25519_TOOL_INSTALLED")" = 0:555:1 ] && ed25519_tool_matches "$ED25519_TOOL_INSTALLED" ||
      fail "existing ${ED25519_TOOL_INSTALLED} differs from the pinned Ed25519 tool; refusing to replace it"
  else
    ED25519_TOOL_INSTALLED_NOW=true
    install -m 0555 "$ED25519_TOOL" "$ED25519_TOOL_INSTALLED"
  fi
  ED25519_TOOL=$ED25519_TOOL_INSTALLED
  [ "$("$ED25519_TOOL" --version)" = 'cdnca-ed25519 1' ] || fail 'the Ed25519 tool does not run on this host'
}

verify_native_package() {
  # The verifier is shipped with this installer, never trusted from the archive.
  # Validate the complete signed inventory before creating the destination.
  resolve_ed25519_tool || fail 'the pinned Ed25519 tool is not available'
  python3 - "$1" "$2" "$3" "$ED25519_TOOL" <<'PY_NATIVE_NODE'
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path

DOMAIN = b'cdnca.native-node.release/v1\n'
MAX_ARCHIVE, MAX_TOTAL, MAX_FILE = 512 << 20, 1 << 30, 256 << 20
MAX_MANIFEST, MAX_MEMBERS = 4 << 20, 32768
METADATA = {'release.manifest.json', 'release.manifest.sig'}
EXECUTABLES = {'bin/edge-agent', 'bin/cdnca-edge-agent-helper', 'runtime/openresty/nginx/sbin/nginx',
               'runtime/openresty/bin/openresty', 'runtime/lib/ld-musl-x86_64.so.1', 'runtime/bin/h3probe'}
# The signed packaging toolset and its manifest v2 inputs let the root helper
# upgrade this node in place. Scripts are executable; everything else is data.
PACKAGING_SCRIPTS = {f'packaging/scripts/{name}.sh' for name in
                     ('install', 'lib', 'preflight', 'rollback', 'uninstall', 'upgrade')}
PACKAGING_DATA = {
    'packaging/systemd/cdnca-edge-agent.service', 'packaging/systemd/cdnca-edge-agent-root.service',
    'packaging/systemd/cdnca-edge-agent-helper.service', 'packaging/systemd/cdnca-edge-agent-helper.socket',
    'packaging/sysusers/cdnca-edge-agent.conf', 'packaging/tmpfiles/cdnca-edge-agent.conf',
    'packaging/tmpfiles/cdnca-edge-agent-root.conf', 'packaging/logrotate/cdnca-edge-agent',
    'packaging/config/agent.env', 'packaging/config/config.example.json', 'packaging/README.md',
    'upgrade/manifest', 'upgrade/manifest.sig', 'upgrade/package-signing.pem', 'evidence/edge-agent.spdx.json',
}
REQUIRED_DATA = {
    'runtime/openresty/lualib/resty/ipmatcher.lua',
    'lua/share/cdnca/range/guard.lua', 'lua/share/cdnca/security/cdnca_waf.lua', 'lua/share/cdnca/security/cdnca_rule_interp.lua', 'lua/share/cdnca/security/cdnca_banlist.lua', 'lua/share/cdnca/dynroute/cdnca_site.lua', 'lua/share/cdnca/dynroute/cdnca_site_admin.lua', 'lua/share/cdnca/dynroute/cdnca_tls.lua', 'lua/share/cdnca/dynroute/cdnca_origin.lua', 'lua/share/cdnca/dynroute/cdnca_originauth.lua', 'lua/share/cdnca/dynroute/cdnca_origintls.lua', 'lua/share/cdnca/dynroute/cdnca_cache.lua', 'lua/share/cdnca/dynroute/cdnca_filters.lua', 'lua/share/cdnca/dynroute/cdnca_limits.lua',
    'lua/share/cdnca/security/cc.lua', 'lua/share/cdnca/security/cc_adaptive.lua',
    'lua/share/cdnca/security/url_auth.lua', 'lua/share/cdnca/challenge/engine.lua',
    'lua/share/cdnca/challenge/crypto.lua', 'lua/share/cdnca/challenge/ip.lua',
    'lua/l4geo/engine.lua', 'lua/l4geo/cdnca_l4_geo.lua',
    'lua/share/cdnca/security/cdnca_iplib.lua', 'lua/l4geo/cdnca_iplib.lua',
    'lua/share/cdnca/httppolicy/engine.lua', 'lua/share/cdnca/firewallaction/engine.lua', 'lua/share/cdnca/siteaccess/engine.lua', 'lua/share/cdnca/errorpage/handler.lua', 'lua/share/cdnca/originauth/engine.lua', 'lua/share/cdnca/originauth/crypto.lua', 'lua/share/cdnca/dynroute/cdnca_dynroute.lua', 'lua/share/cdnca/sched302/cdnca_sched302.lua', 'lua/share/cdnca/dynroute/cdnca_telemetry.lua', 'lua/share/cdnca/dynroute/cdnca_webp.lua', 'lua/share/cdnca/dynroute/cdnca_webp_codec.lua', 'lua/share/cdnca/dynroute/cdnca_security.lua', 'lua/share/cdnca/dynroute/cdnca_managed_waf.lua', 'lua/share/cdnca/dynroute/cdnca_rule_plan.lua', 'lua/share/cdnca/dynroute/cdnca_bot.lua',
}

def require(condition, reason):
    if not condition:
        raise ValueError(reason)

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result

def document(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                      parse_constant=lambda _: require(False, 'nonfinite JSON number'))

def fields(value, expected):
    require(type(value) is dict and set(value) == set(expected.split()), 'unexpected schema fields')

def matches(pattern, value):
    return type(value) is str and re.fullmatch(pattern, value) is not None

def safe_path(value):
    require(matches(r'[A-Za-z0-9_+./-]{1,240}', value) and
            all(part not in ('', '.', '..') for part in value.split('/')), 'unsafe member path')
    require(value in METADATA or value in ('bin/edge-agent', 'bin/cdnca-edge-agent-helper', 'runtime/bin/h3probe') or
            value in PACKAGING_SCRIPTS or value in PACKAGING_DATA or
            any(value.startswith(prefix) for prefix in (
                'runtime/openresty/', 'runtime/lib/', 'runtime/usr/lib/',
                'lua/share/cdnca/', 'lua/l4geo/', 'evidence/')), 'unapproved member path')

def open_input(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if not (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            info.st_uid == os.geteuid() and info.st_mode & 0o022 == 0 and 0 < info.st_size <= limit):
        os.close(fd)
        raise ValueError('unsafe input file')
    return os.fdopen(fd, 'rb')

def ed25519_tool(arguments):
    result = subprocess.run([TOOL, *arguments], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=15, check=False, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    require(result.returncode == 0, 'signature verification failed')
    return result.stdout

archive, trust_path, destination, TOOL = sys.argv[1:]
created = False
try:
    require(not os.path.lexists(destination), 'destination already exists')
    parent = Path(destination).parent
    require(parent.is_dir() and not parent.is_symlink(), 'unsafe destination parent')
    with open_input(trust_path, 65536) as source:
        trust = document(source.read())
    fields(trust, 'version keys')
    require(type(trust['version']) is int and trust['version'] == 1 and
            type(trust['keys']) is list and 0 < len(trust['keys']) <= 32, 'invalid trust document')
    keys = {}
    for key in trust['keys']:
        fields(key, 'key_id public_key_pem')
        require(matches(r'[A-Za-z0-9._-]{1,128}', key['key_id']) and
                key['key_id'] not in keys and type(key['public_key_pem']) is str and
                len(key['public_key_pem']) <= 4096, 'invalid trust key')
        keys[key['key_id']] = key['public_key_pem']

    with tempfile.TemporaryDirectory(prefix='.native-verify-', dir=parent) as scratch:
        with open_input(archive, MAX_ARCHIVE) as compressed, tempfile.TemporaryFile(dir=scratch) as raw:
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            total = 0
            for chunk in iter(lambda: compressed.read(65536), b''):
                require(not decoder.eof, 'trailing gzip data')
                while chunk:
                    block = decoder.decompress(chunk, 1 << 20)
                    chunk = decoder.unconsumed_tail
                    total += len(block)
                    require(total <= MAX_TOTAL, 'expanded package too large')
                    raw.write(block)
                    require(not decoder.unused_data, 'trailing gzip data')
            require(decoder.eof and total % 512 == 0, 'truncated package')
            raw.seek(0)
            members, metadata = {}, {}
            while True:
                header = raw.read(512)
                require(len(header) == 512, 'missing tar end')
                if header == bytes(512):
                    require(raw.read(512) == bytes(512), 'invalid tar end')
                    for padding in iter(lambda: raw.read(65536), b''):
                        require(not any(padding), 'trailing tar data')
                    break
                info = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
                safe_path(info.name)
                require(info.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not info.linkname,
                        'nonregular tar member')
                require(info.name not in members and len(members) < MAX_MEMBERS, 'duplicate or excessive members')
                require(info.mode in (0o444, 0o555) and 0 <= info.size <= MAX_FILE, 'unsafe member metadata')
                if info.name in METADATA:
                    require(info.mode == 0o444 and info.size <= MAX_MANIFEST, 'invalid manifest member')
                start, digest, head, body = raw.tell(), hashlib.sha256(), b'', bytearray()
                remaining = info.size
                while remaining:
                    block = raw.read(min(65536, remaining))
                    require(block, 'truncated member')
                    digest.update(block)
                    head = (head + block)[:64]
                    if info.name in METADATA:
                        body.extend(block)
                    remaining -= len(block)
                padding = (512 - info.size % 512) % 512
                require(raw.read(padding) == bytes(padding), 'invalid member padding')
                members[info.name] = (start, info.size, info.mode, digest.hexdigest(), head)
                if info.name in METADATA:
                    metadata[info.name] = bytes(body)

            require(set(metadata) == METADATA, 'missing manifest or signature')
            manifest_bytes = metadata['release.manifest.json']
            manifest = document(manifest_bytes)
            fields(manifest, 'schema key_id version source platform runtime files')
            require(manifest['schema'] == DOMAIN.decode().strip() and manifest['key_id'] in keys,
                    'unknown schema or signing key')
            require(matches(r'(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})', manifest['version']),
                    'invalid stable version')
            fields(manifest['source'], 'commit tree')
            require(all(matches(r'[0-9a-f]{40}', value) for value in manifest['source'].values()), 'invalid source identity')
            fields(manifest['platform'], 'os arch')
            require(manifest['platform'] == {'os': 'linux', 'arch': 'amd64'}, 'unsupported platform')
            runtime = manifest['runtime']
            fields(runtime, 'openresty_version nginx_version source_sha256 patch_manifest_sha256 release_eligible')
            require(runtime['release_eligible'] is True and
                    matches(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', runtime['openresty_version']) and
                    matches(r'[0-9]+\.[0-9]+\.[0-9]+', runtime['nginx_version']) and
                    matches(r'[0-9a-f]{64}', runtime['source_sha256']) and
                    matches(r'[0-9a-f]{64}', runtime['patch_manifest_sha256']), 'runtime not release eligible')

            signature = metadata['release.manifest.sig']
            signature = base64.b64decode(signature[:-1] if signature.endswith(b'\n') else signature, validate=True)
            require(len(signature) == 64, 'invalid signature encoding')
            keyfile, sigfile, messagefile = (Path(scratch) / name for name in ('key.pem', 'signature', 'message'))
            keyfile.write_text(keys[manifest['key_id']], encoding='ascii')
            sigfile.write_bytes(signature)
            messagefile.write_bytes(DOMAIN + manifest_bytes)
            # check-public accepts only a single-block 44-byte Ed25519 SPKI.
            ed25519_tool(['check-public', str(keyfile)])
            ed25519_tool(['verify', str(keyfile), str(messagefile), str(sigfile)])

            require(type(manifest['files']) is list and 0 < len(manifest['files']) <= MAX_MEMBERS - 2, 'invalid file inventory')
            listed = set()
            for entry in manifest['files']:
                fields(entry, 'path size mode sha256')
                path = entry['path']
                safe_path(path)
                require(path not in METADATA and path not in listed and path in members, 'invalid file inventory')
                listed.add(path)
                require(type(entry['size']) is int and 0 <= entry['size'] <= MAX_FILE and
                        entry['mode'] in ('0444', '0555') and matches(r'[0-9a-f]{64}', entry['sha256']), 'invalid file metadata')
                _, size, mode, digest, head = members[path]
                require((size, mode, digest) == (entry['size'], int(entry['mode'], 8), entry['sha256']), 'file verification failed')
                if path in EXECUTABLES or head.startswith(b'\x7fELF'):
                    require(len(head) >= 64 and head[:7] == b'\x7fELF\x02\x01\x01' and
                            int.from_bytes(head[16:18], 'little') in (2, 3) and
                            int.from_bytes(head[18:20], 'little') == 62, 'invalid ELF platform')
                if path in EXECUTABLES or path in PACKAGING_SCRIPTS:
                    require(mode == 0o555, 'required executable mode')
                if path in REQUIRED_DATA or path in PACKAGING_DATA:
                    require(mode == 0o444, 'required data mode')
            require(listed == set(members) - METADATA and
                    EXECUTABLES | REQUIRED_DATA | PACKAGING_SCRIPTS | PACKAGING_DATA <= listed, 'incomplete package')
            require(members['upgrade/manifest.sig'][1] == 64, 'upgrade manifest signature size')
            require(members['runtime/openresty/bin/openresty'][1:4] ==
                    members['runtime/openresty/nginx/sbin/nginx'][1:4], 'OpenResty aliases differ')
            require(not any('/'.join(path.split('/')[:index]) in listed for path in listed
                            for index in range(1, len(path.split('/')))), 'file and directory collision')

            os.mkdir(destination, 0o700)
            created = True
            for path, (offset, size, mode, digest, _) in members.items():
                output = Path(destination) / path
                output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as target:
                    raw.seek(offset)
                    remaining, actual = size, hashlib.sha256()
                    while remaining:
                        block = raw.read(min(65536, remaining))
                        require(block, 'staged member truncated')
                        target.write(block)
                        actual.update(block)
                        remaining -= len(block)
                    require(actual.hexdigest() == digest, 'staged member changed')
                    target.flush()
                    os.fchmod(target.fileno(), mode)
                    os.fsync(target.fileno())
            # umask does not affect the signed file modes; directories are readable
            # by the dedicated runtime service once the private stage is published.
            for directory, _, _ in os.walk(destination, topdown=False):
                os.chmod(directory, 0o755)
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
    # The WAF/CC assets' digests come from the verified signed inventory: the
    # installer writes them into security_runtime (the Agent re-hashes them).
    signed = {entry['path']: entry['sha256'] for entry in manifest['files']}
    print(json.dumps({'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
                      'version': manifest['version'], 'openresty_version': runtime['openresty_version'],
                      'nginx_version': runtime['nginx_version'], 'source': manifest['source'],
                      'security_assets': {name: signed[f'lua/share/cdnca/security/{file}.lua'] for name, file in
                                          (('waf', 'cdnca_waf'), ('cc', 'cc'), ('adaptive', 'cc_adaptive'))}}))
except Exception:
    if created:
        shutil.rmtree(destination)
    print('native package rejected: signature, inventory, platform or safe extraction check failed', file=sys.stderr)
    sys.exit(1)
PY_NATIVE_NODE
}

download_agent() {
  [ -n "$TEMP_DIR" ] || TEMP_DIR=$(mktemp -d -t cdnca-edge-install.XXXXXX)
  local archive="${TEMP_DIR}/edge-agent.tar.gz"
  log 'downloading signed native node release'
  download_verified "$AGENT_URL" "$AGENT_FALLBACK_URL" "$AGENT_SHA256_URL" "$AGENT_SHA256_FALLBACK_URL" \
    "$archive" 'cdnca-edge-agent.tar.gz' || fail 'unable to download a valid native node release'
  # Stage on the final filesystem without exposing a current or global alias.
  NATIVE_STAGE_PARENT=$(mktemp -d /opt/.cdnca-native-node-stage.XXXXXX)
  NATIVE_STAGE="${NATIVE_STAGE_PARENT}/release"
  verify_native_package "$archive" "$ARTIFACT_TRUST_FILE" "$NATIVE_STAGE" >"${TEMP_DIR}/native-facts.json" ||
    fail 'native node signature or package validation failed; enrollment was not attempted'
  NATIVE_MANIFEST_SHA=$(jq -er .manifest_sha256 "${TEMP_DIR}/native-facts.json")
  NATIVE_VERSION=$(jq -er .version "${TEMP_DIR}/native-facts.json")
  PROGRESS_VERSION=$NATIVE_VERSION
  progress_line "安装版本 ${NATIVE_VERSION}"
  OPENRESTY_VERSION=$(jq -er .openresty_version "${TEMP_DIR}/native-facts.json")
  NATIVE_SECURITY_ASSETS=$(jq -ec '.security_assets | select((keys == ["adaptive", "cc", "waf"]) and
    all(.[]; type == "string" and test("^[0-9a-f]{64}$")))' "${TEMP_DIR}/native-facts.json") ||
    fail 'signed native package does not inventory the WAF/CC assets'
}

# Node signer trust (签名密钥泄露吊销·节点侧): the control plane publishes the
# offline-signed cdnca.edge-signer-trust/v1 document next to artifacts.json.
# Nothing in it is used before its offline root signature verifies (Codex
# 10-26 P2) against the pin the installing control plane put in the upgrade
# trust document (signer_trust_root), which the copied command pins by SHA-256;
# the check runs the pinned Ed25519 tool. A document that does not verify, or
# a control plane without the pin, stops the install before artifacts.json or
# the installation-ban gate read anything from it. Missing document = nothing
# revoked.
SIGNER_TRUST_ROOT=''
SIGNER_TRUST_DOCUMENT=''
fetch_signer_trust() {
  local url="${ARTIFACT_TRUST_URL%/*}/signer-trust.json" signed="${TEMP_DIR}/signer-trust.json"
  local document="${TEMP_DIR}/signer-trust.document.json"
  rm -f -- "$signed" "$document"
  SIGNER_TRUST_DOCUMENT=''
  if ! curl_download "$url" -fL --connect-timeout 10 --max-time 60 --max-filesize 300000 --retry 1 --output "$signed" 2>/dev/null; then
    rm -f -- "$signed"
    return 0
  fi
  [ -n "$SIGNER_TRUST_ROOT" ] || fail "the control plane publishes a node signer trust document but its install did not pin the offline root (--signer-revocation-offline-root-*); the document cannot be verified, so the install stops. Reinstall the control plane with the three --signer-revocation-offline-root-* flags (docs/runbooks/release-1.0.35.md 3.3), then copy a new node install command"
  resolve_ed25519_tool || fail 'the pinned Ed25519 tool is not available'
  verify_signer_trust "$signed" "$SIGNER_TRUST_ROOT" "$ED25519_TOOL" >"$document" ||
    fail "the node signer trust document at ${url} does not verify against the pinned offline root ($(jq -r '.key_id + " generation " + (.generation | tostring)' <<<"$SIGNER_TRUST_ROOT")); artifacts.json was not changed. Check that the license service publishes a document signed by this offline root, or that nothing between this host and the control plane alters it"
  rm -f -- "$signed"
  SIGNER_TRUST_DOCUMENT=$document
}

# verify_signer_trust SIGNED PIN TOOL: prints the verified document. The
# signature covers the canonical envelope, which binds the SHA-256 of the
# canonical document bytes (libs/entitlement/edgesignertrust Sign/Verify); the
# wire bytes are {"document":<canonical document>,"envelope":<canonical
# envelope>,"signature":"…"}, so the digest is taken over exactly those bytes.
verify_signer_trust() {
  python3 - "$1" "$2" "$3" <<'PY_SIGNER_TRUST'
import base64, hashlib, json, re, subprocess, sys, tempfile
from pathlib import Path

SPKI = bytes.fromhex('302a300506032b6570032100')
KEY_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}')

def require(condition):
    if not condition:
        raise ValueError

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result

def strict(data):
    return json.loads(data.decode('utf-8'), object_pairs_hook=unique, parse_constant=lambda _: require(False))

def b64url(value, size):
    require(type(value) is str and re.fullmatch(r'[A-Za-z0-9_-]+', value))
    decoded = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    require(len(decoded) == size and base64.urlsafe_b64encode(decoded).rstrip(b'=').decode('ascii') == value)
    return decoded

def canonical_time(value):
    return type(value) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value)

try:
    raw = Path(sys.argv[1]).read_bytes()
    require(0 < len(raw) <= (256 << 10) + 4096)
    pin, tool = json.loads(sys.argv[2]), sys.argv[3]
    signed = strict(raw)
    require(type(signed) is dict and list(signed) == ['document', 'envelope', 'signature'])
    envelope = signed['envelope']
    require(type(envelope) is dict and list(envelope) == ['schema', 'algorithm', 'authority_kind', 'authority_key_id',
                                                          'authority_key_generation', 'document_sha256'])
    require(envelope['schema'] == 'cdnca.edge-signer-trust-envelope/v1' and envelope['algorithm'] == 'Ed25519' and
            envelope['authority_kind'] == 'offline_root')
    require(type(envelope['authority_key_id']) is str and envelope['authority_key_id'] == pin['key_id'] and
            type(envelope['authority_key_generation']) is int and envelope['authority_key_generation'] == pin['generation'])
    digest, signature = b64url(envelope['document_sha256'], 32), b64url(signed['signature'], 64)
    envelope_bytes = json.dumps(envelope, separators=(',', ':')).encode('ascii')
    prefix = b'{"document":'
    suffix = b',"envelope":' + envelope_bytes + b',"signature":"' + signed['signature'].encode('ascii') + b'"}'
    require(raw.startswith(prefix) and raw.endswith(suffix) and len(raw) > len(prefix) + len(suffix))
    document_bytes = raw[len(prefix):len(raw) - len(suffix)]
    require(hashlib.sha256(document_bytes).digest() == digest)
    with tempfile.TemporaryDirectory() as scratch:
        key, message, sig = (Path(scratch) / name for name in ('key.pem', 'message', 'signature'))
        key.write_text('-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(SPKI + b64url(pin['public_key'], 32)).decode('ascii') +
                       '\n-----END PUBLIC KEY-----\n', encoding='ascii')
        message.write_bytes(envelope_bytes)
        sig.write_bytes(signature)
        for arguments in (['check-public', str(key)], ['verify', str(key), str(message), str(sig)]):
            result = subprocess.run([tool, *arguments], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
                                    check=False, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
            require(result.returncode == 0)
    document = strict(document_bytes)
    require(type(document) is dict and list(document) == ['schema', 'revision', 'issued_at', 'trusted_keys', 'revoked_keys'])
    require(document['schema'] == 'cdnca.edge-signer-trust/v1' and type(document['revision']) is int and
            0 < document['revision'] <= 1 << 53 and canonical_time(document['issued_at']))
    trusted, revoked = document['trusted_keys'], document['revoked_keys']
    require(type(trusted) is list and len(trusted) <= 64 and type(revoked) is list and len(revoked) <= 256)
    for entry in trusted:
        require(type(entry) is dict and list(entry) in (['key_id', 'public_key_pem'], ['key_id', 'public_key_pem', 'usage']))
        require(type(entry['key_id']) is str and KEY_ID.fullmatch(entry['key_id']) and type(entry['public_key_pem']) is str and
                entry.get('usage', 'installation-ban') == 'installation-ban')
    for entry in revoked:
        require(type(entry) is dict and list(entry) in (['key_id', 'revoked_at', 'reason'],
                                                        ['key_id', 'public_key_sha256', 'revoked_at', 'reason']))
        require(type(entry['key_id']) is str and KEY_ID.fullmatch(entry['key_id']) and canonical_time(entry['revoked_at']) and
                (type(entry.get('public_key_sha256', '0' * 64)) is str and re.fullmatch(r'[0-9a-f]{64}', entry.get('public_key_sha256', '0' * 64))))
    sys.stdout.write(json.dumps(document, separators=(',', ':')))
except Exception:
    print('node signer trust document rejected: offline root signature, envelope or document check failed', file=sys.stderr)
    sys.exit(1)
PY_SIGNER_TRUST
}

# artifacts.json is served unsigned and the control plane rewrites it at run
# time (edgesignertrust.PublishDownloads: drops revoked keys, adds usage=""
# trusted keys), so it cannot be pinned by digest. Instead every key in it must
# be one the installing control plane pinned (upgrade trust artifact_trust,
# authenticated by the copied SHA-256) or an artifact key of the signer trust
# document verified against the offline root. Matching is by key ID and
# SHA-256 of the PKIX public key. Revocation and rotation keep working; a key
# added by anything else stops the install before the package is verified.
ARTIFACT_TRUST_PIN=''
require_pinned_artifact_trust() {
  local unknown
  [ -n "$ARTIFACT_TRUST_PIN" ] && [ -f "$ARTIFACT_TRUST_PIN" ] || fail 'node upgrade trust carries no artifact key pin'
  unknown=$(python3 - "$1" "$ARTIFACT_TRUST_PIN" "$SIGNER_TRUST_DOCUMENT" <<'PY_ARTIFACT_PIN'
import base64, hashlib, json, re, sys
from pathlib import Path

def identity(entry):
    match = re.fullmatch(r'-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)-----END PUBLIC KEY-----\n?', entry['public_key_pem'])
    return entry['key_id'], hashlib.sha256(base64.b64decode(match[1].replace('\n', ''), validate=True)).hexdigest()

try:
    allowed = {identity(entry) for entry in json.loads(Path(sys.argv[2]).read_text())['keys']}
    if sys.argv[3]:
        allowed |= {identity(entry) for entry in json.loads(Path(sys.argv[3]).read_text())['trusted_keys']
                    if entry.get('usage', '') == ''}
    unknown = [entry['key_id'] for entry in json.loads(Path(sys.argv[1]).read_text())['keys'] if identity(entry) not in allowed]
except Exception:
    unknown = ['<unreadable>']
if unknown:
    print(' '.join(key_id if type(key_id) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', key_id) else '<invalid>'
                   for key_id in unknown))
    sys.exit(1)
PY_ARTIFACT_PIN
  ) || fail "artifacts.json carries artifact keys (${unknown}) that neither the pinned upgrade trust nor the offline-root-verified signer trust document authorizes; the install stops before the package is verified. Check that nothing between this host and the control plane alters it, then copy a new install command from the management console"
}

# Drops every artifact key the verified document revokes (by key ID or SHA-256
# of the PKIX public key) before the node package is verified. Only removal:
# the document does not add artifact trust here.
apply_signer_revocations() {
  local trust=$1 document=$SIGNER_TRUST_DOCUMENT
  local revoked_ids revoked_prints entry key_id fingerprint keep='[]' removed=''
  [ -n "$document" ] || return 0
  revoked_ids=$(jq -c '[.revoked_keys[].key_id]' "$document")
  revoked_prints=$(jq -c '[.revoked_keys[] | .public_key_sha256 // empty]' "$document")
  while IFS= read -r entry; do
    key_id=$(jq -r .key_id <<<"$entry")
    fingerprint=$(jq -r .public_key_pem <<<"$entry" | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
    if jq -e --arg id "$key_id" --arg fp "$fingerprint" --argjson ids "$revoked_ids" --argjson fps "$revoked_prints" \
      '($ids | index($id)) != null or ($fps | index($fp)) != null' <<<'null' >/dev/null; then
      removed="${removed} ${key_id}"
      continue
    fi
    keep=$(jq -c --argjson entry "$entry" '. + [$entry]' <<<"$keep")
  done < <(jq -c '.keys[]' "$trust")
  [ -n "$removed" ] || return 0
  [ "$(jq 'length' <<<"$keep")" -gt 0 ] || fail 'every artifact trust key is revoked; refresh the control plane trust first'
  log "artifact keys revoked by the node signer trust document:${removed}"
  chmod 0600 "$trust"
  jq -n --argjson keys "$keep" '{version:1,keys:$keys}' >"${trust}.revoked"
  mv -f -- "${trust}.revoked" "$trust"
  chmod 0400 "$trust"
}

install_trust_material() {
  [ -n "$TEMP_DIR" ] || TEMP_DIR=$(mktemp -d -t cdnca-edge-install.XXXXXX)
  local trust="${TEMP_DIR}/artifacts.json" gateway_ca="${TEMP_DIR}/gateway-ca.pem"
  if [ -f "$ARTIFACT_TRUST_FILE" ] && [ ! -L "$ARTIFACT_TRUST_FILE" ]; then
    install -m 0400 "$ARTIFACT_TRUST_FILE" "$trust"
  elif [ "$ARTIFACT_TRUST_FILE" = "${TRUST_DIR}/artifacts.json" ]; then
    log 'downloading edge artifact trust document'
    download_json_verified "$ARTIFACT_TRUST_URL" "$ARTIFACT_TRUST_FALLBACK_URL" "$trust" \
      '.version == 1 and (.keys | type == "array" and length > 0)' || fail 'unable to download a valid edge artifact trust document'
  else
    fail 'external artifact trust document is missing or unsafe'
  fi
  ARTIFACT_TRUST_FILE=$trust
  chmod 0400 "$ARTIFACT_TRUST_FILE"
  jq -e '.version == 1 and (.keys | type == "array" and length > 0)' "$ARTIFACT_TRUST_FILE" >/dev/null || fail 'artifact trust document is invalid'
  fetch_signer_trust
  require_pinned_artifact_trust "$ARTIFACT_TRUST_FILE"
  apply_signer_revocations "$ARTIFACT_TRUST_FILE"
  if [ -n "$GATEWAY_ROOT_CA_FILE" ]; then
    [ -f "$GATEWAY_ROOT_CA_FILE" ] && [ ! -L "$GATEWAY_ROOT_CA_FILE" ] || fail 'Gateway CA file is missing or unsafe'
    install -m 0400 "$GATEWAY_ROOT_CA_FILE" "$gateway_ca"
  else
    log 'downloading Gateway CA certificate'
    download_certificate_verified "$GATEWAY_ROOT_CA_URL" "$GATEWAY_ROOT_CA_FALLBACK_URL" "$gateway_ca" || fail 'unable to download a valid Gateway CA; pass --gateway-root-ca-file or --gateway-root-ca-url'
  fi
  GATEWAY_ROOT_CA_FILE=$gateway_ca
  chmod 0400 "$GATEWAY_ROOT_CA_FILE"
  openssl x509 -in "$GATEWAY_ROOT_CA_FILE" -noout >/dev/null 2>&1 || fail 'Gateway CA file is not a PEM certificate'
  openssl x509 -in "$GATEWAY_ROOT_CA_FILE" -noout -checkend 0 >/dev/null 2>&1 || fail 'Gateway CA is expired'
  openssl x509 -in "$GATEWAY_ROOT_CA_FILE" -noout -text 2>/dev/null | grep -Fq 'CA:TRUE' || fail 'Gateway CA lacks CA constraints'
}

download_pinned() {
  local primary=$1 fallback=$2 expected=$3 output=$4 candidate index
  local -a urls=("$primary")
  [ "$fallback" != "$primary" ] && urls+=("$fallback")
  for index in "${!urls[@]}"; do
    candidate="${TEMP_DIR}/pinned-candidate"
    rm -f -- "$candidate"
    curl_download "${urls[$index]}" -fL --connect-timeout 10 --max-time 60 --max-filesize 65536 --retry 1 --output "$candidate" || continue
    [ "$(sha256sum "$candidate" | awk '{print tolower($1)}')" = "$expected" ] || continue
    cp -- "$candidate" "$output"
    return 0
  done
  return 1
}

# Validate cdnca.edge-upgrade-trust/v1 exactly and split it into the Agent's
# execution trust stores and the artifact key pin (require_pinned_artifact_trust). The document is authenticated by the copied pin; the
# download root is the single system anchor that verifies the live endpoint.
split_upgrade_trust() {
  python3 - "$1" "$2" <<'PY_UPGRADE_TRUST'
import base64, ipaddress, json, re, sys, uuid
from pathlib import Path

SPKI = bytes.fromhex('302a300506032b6570032100')

def require(condition):
    if not condition:
        raise ValueError

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result

def store(value):
    require(type(value) is dict and set(value) == {'version', 'keys'} and value['version'] == 1 and
            type(value['version']) is int and type(value['keys']) is list and 0 < len(value['keys']) <= 8)
    seen = set()
    for key in value['keys']:
        require(type(key) is dict and set(key) == {'key_id', 'public_key_pem'})
        require(type(key['key_id']) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', key['key_id']) and key['key_id'] not in seen)
        seen.add(key['key_id'])
        match = re.fullmatch(r'-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/]{59}=)\n-----END PUBLIC KEY-----\n', key['public_key_pem'] if type(key['public_key_pem']) is str else '')
        require(match)
        der = base64.b64decode(match[1], validate=True)
        require(len(der) == 44 and der[:12] == SPKI)
    return value

# artifact_trust: the artifacts.json keys of this control plane at install time
# (package keys plus its publisher key), any PKIX public key type.
def artifact_pin(value):
    require(type(value) is dict and set(value) == {'version', 'keys'} and type(value['version']) is int and
            value['version'] == 1 and type(value['keys']) is list and 0 < len(value['keys']) <= 64)
    seen = set()
    for key in value['keys']:
        require(type(key) is dict and set(key) == {'key_id', 'public_key_pem'})
        require(type(key['key_id']) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', key['key_id']) and key['key_id'] not in seen)
        seen.add(key['key_id'])
        match = re.fullmatch(r'-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)-----END PUBLIC KEY-----\n?', key['public_key_pem'] if type(key['public_key_pem']) is str else '')
        require(match)
        base64.b64decode(match[1].replace('\n', ''), validate=True)
    return value

def host(value, addresses):
    require(type(value) is str and value == value.lower() and 'xn--' not in value and len(value) <= 253)
    try:
        literal = ipaddress.ip_address(value)
    except ValueError:
        literal = None
    if literal is not None:
        # IP literal control plane: the host pins exactly its own address.
        require(str(literal) == value and addresses == [value])
        return value
    labels = value.split('.')
    require(len(labels) >= 2 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels))
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError

try:
    raw = Path(sys.argv[1]).read_bytes()
    document = json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=lambda _: require(False))
    base = {'schema', 'installation_id', 'control_execution', 'edge_execution', 'download', 'artifact_trust'}
    require(type(document) is dict and set(document) in (base, base | {'signer_trust_root'}))
    # The signer revocation offline root pin of this control plane (verifies
    # signer-trust.json, fetch_signer_trust); absent when it was installed without one.
    root = document.get('signer_trust_root')
    if root is not None:
        require(type(root) is dict and set(root) == {'key_id', 'generation', 'public_key'} and
                type(root['key_id']) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', root['key_id']) and
                type(root['generation']) is int and 0 < root['generation'] < 1 << 63 and
                type(root['public_key']) is str and re.fullmatch(r'[A-Za-z0-9_-]{43}', root['public_key']) and
                len(base64.urlsafe_b64decode(root['public_key'] + '=')) == 32)
    require(document['schema'] == 'cdnca.edge-upgrade-trust/v1')
    installation = document['installation_id']
    require(type(installation) is str and installation != str(uuid.UUID(int=0)) and str(uuid.UUID(installation)) == installation)
    control, edge = store(document['control_execution']), store(document['edge_execution'])
    artifacts = artifact_pin(document['artifact_trust'])
    control_keys = {key['public_key_pem'] for key in control['keys']}
    require(not control_keys & {key['public_key_pem'] for key in edge['keys']})
    download = document['download']
    require(type(download) is dict and set(download) == {'host', 'port', 'addresses', 'root_ca'})
    # "system": a public WebPKI certificate; otherwise exactly one PEM
    # certificate (the control plane's private root CA).
    root_ca = download['root_ca']
    require(root_ca == 'system' or (type(root_ca) is str and len(root_ca) <= 16384 and
        re.fullmatch(r'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n', root_ca)))
    require(type(download['port']) is int and 1 <= download['port'] <= 65535)
    addresses = download['addresses']
    require(type(addresses) is list and 0 < len(addresses) <= 16)
    seen = set()
    for address in addresses:
        require(type(address) is str and '%' not in address)
        parsed = ipaddress.ip_address(address)
        require(str(parsed) == address and not parsed.is_unspecified and not parsed.is_multicast)
        canonical = parsed.ipv4_mapped or parsed if parsed.version == 6 else parsed
        require(canonical not in seen)
        seen.add(canonical)
    download_host = host(download['host'], addresses)
    output = Path(sys.argv[2])
    for name, value in (('control-execution.json', control), ('edge-execution.json', edge), ('artifact-trust.json', artifacts)):
        (output / name).write_text(json.dumps(value, separators=(',', ':')), encoding='ascii')
    if root_ca != 'system':
        (output / 'download-ca.pem').write_text(root_ca, encoding='ascii')
    print(json.dumps({'installation_id': installation, 'host': download_host,
                      'port': download['port'], 'addresses': addresses, 'private_root': root_ca != 'system',
                      'signer_trust_root': root}))
except Exception:
    print('upgrade trust document rejected: schema, key, installation or download policy check failed', file=sys.stderr)
    sys.exit(1)
PY_UPGRADE_TRUST
}

# Pin the one system root that verifies the live download endpoint through the
# published addresses (the Agent limits this file to 64 KiB, so the full bundle
# cannot be copied). A future change of issuing root requires reinstalling.
select_download_root() {
  local host=$1 port=$2 addresses=$3 output=$4 bundle=/etc/ssl/certs/ca-certificates.crt
  # RHEL family keeps the system bundle under /etc/pki (ca-certificates package).
  [ -f "$bundle" ] || bundle=/etc/pki/tls/certs/ca-bundle.crt
  python3 - "$host" "$port" "$addresses" "$output" "$bundle" <<'PY_DOWNLOAD_ROOT'
import json, os, re, subprocess, sys, tempfile
from pathlib import Path

host, port, addresses, output, bundle = sys.argv[1], sys.argv[2], json.loads(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5])
PEM = re.compile(rb'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n')

def run(arguments, data=None):
    environment = dict(os.environ, SSL_CERT_DIR='/nonexistent', SSL_CERT_FILE='/nonexistent')
    try:
        return subprocess.run(arguments, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20, check=False,
                              env=environment)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(arguments, 124, b'', b'')

try:
    roots = PEM.findall(bundle.read_bytes())
    if not roots:
        raise ValueError
    # Only the candidate root may verify: -no-CApath is 1.1.0+, -no-CAstore 3.0+;
    # SSL_CERT_DIR/FILE (below) also empty the default store on OpenSSL 1.0.2.
    version = re.match(rb'OpenSSL ([0-9]+)\.([0-9]+)', run(['openssl', 'version']).stdout)
    version = tuple(int(part) for part in version.groups()) if version else (0, 0)
    ISOLATED = (['-no-CApath'] if version >= (1, 1) else []) + (['-no-CAstore'] if version >= (3, 0) else [])
    with tempfile.TemporaryDirectory() as scratch:
        scratch = Path(scratch)
        for address in addresses:
            target = f'[{address}]:{port}' if ':' in address else f'{address}:{port}'
            shown = run(['openssl', 's_client', '-connect', target, '-servername', host, '-showcerts'], b'')
            chain = PEM.findall(shown.stdout)
            if not chain:
                continue
            (scratch / 'leaf.pem').write_bytes(chain[0])
            (scratch / 'untrusted.pem').write_bytes(b''.join(chain[1:]) or chain[0])
            for root in roots:
                (scratch / 'root.pem').write_bytes(root)
                verified = run(['openssl', 'verify', *ISOLATED, '-CAfile', str(scratch / 'root.pem'),
                                '-untrusted', str(scratch / 'untrusted.pem'), '-purpose', 'sslserver',
                                '-verify_hostname', host, str(scratch / 'leaf.pem')])
                if verified.returncode == 0:
                    output.write_bytes(root)
                    sys.exit(0)
    raise ValueError
except SystemExit:
    raise
except Exception:
    print('upgrade download endpoint is not verified by a system root certificate', file=sys.stderr)
    sys.exit(1)
PY_DOWNLOAD_ROOT
}

install_upgrade_trust() {
  [ -n "$TEMP_DIR" ] || TEMP_DIR=$(mktemp -d -t cdnca-edge-install.XXXXXX)
  local document="${TEMP_DIR}/upgrade-trust.json" facts
  mkdir -m 0700 "${TEMP_DIR}/upgrade-trust"
  log 'downloading pinned node upgrade trust'
  download_pinned "$UPGRADE_TRUST_URL" "$UPGRADE_TRUST_FALLBACK_URL" "$UPGRADE_TRUST_SHA256" "$document" ||
    fail 'node upgrade trust is unavailable or does not match --upgrade-trust-sha256; copy a new install command from the management console'
  facts=$(split_upgrade_trust "$document" "${TEMP_DIR}/upgrade-trust") || fail 'node upgrade trust document is invalid'
  UPGRADE_INSTALLATION_ID=$(jq -er .installation_id <<<"$facts")
  UPGRADE_DOWNLOAD_HOST=$(jq -er .host <<<"$facts")
  UPGRADE_DOWNLOAD_PORT=$(jq -er .port <<<"$facts")
  UPGRADE_DOWNLOAD_ADDRESSES=$(jq -c .addresses <<<"$facts")
  SIGNER_TRUST_ROOT=$(jq -c '.signer_trust_root // empty' <<<"$facts")
  ARTIFACT_TRUST_PIN="${TEMP_DIR}/upgrade-trust/artifact-trust.json"
  if [ "$(jq -r .private_root <<<"$facts")" = true ]; then
    # The pinned document carries the control plane's private root CA.
    openssl x509 -in "${TEMP_DIR}/upgrade-trust/download-ca.pem" -noout -checkend 0 >/dev/null 2>&1 &&
      openssl x509 -in "${TEMP_DIR}/upgrade-trust/download-ca.pem" -noout -text 2>/dev/null | grep -Fq 'CA:TRUE' ||
      fail 'node upgrade download root CA is invalid or expired'
  else
    select_download_root "$UPGRADE_DOWNLOAD_HOST" "$UPGRADE_DOWNLOAD_PORT" "$UPGRADE_DOWNLOAD_ADDRESSES" \
      "${TEMP_DIR}/upgrade-trust/download-ca.pem" || fail "node upgrade download endpoint ${UPGRADE_DOWNLOAD_HOST} cannot be verified"
  fi
  chmod 0400 "${TEMP_DIR}/upgrade-trust/"*
}

preflight_native_runtime() {
  local loader="${NATIVE_STAGE}/runtime/lib/ld-musl-x86_64.so.1"
  local nginx="${NATIVE_STAGE}/runtime/openresty/nginx/sbin/nginx"
  local libs="${NATIVE_STAGE}/runtime/openresty/luajit/lib:${NATIVE_STAGE}/runtime/openresty/openssl3/lib:${NATIVE_STAGE}/runtime/openresty/pcre2/lib:${NATIVE_STAGE}/runtime/lib:${NATIVE_STAGE}/runtime/usr/lib"
  local probe="${TEMP_DIR}/runtime-preflight" output flag source probe_uid probe_gid probe_group
  # Debian/Ubuntu name GID 65534 nogroup; RHEL 9/10 name it nobody.
  probe_uid=$(id -u nobody 2>/dev/null) || fail 'native syntax probe requires nobody with UID/GID 65534'
  probe_gid=$(id -g nobody 2>/dev/null) || fail 'native syntax probe requires nobody with UID/GID 65534'
  probe_group=$(getent group 65534) || fail 'native syntax probe requires nobody with UID/GID 65534'
  [[ "$probe_uid" = 65534 && "$probe_gid" = 65534 && ( "$probe_group" = nogroup:* || "$probe_group" = nobody:* ) ]] &&
    [ "$(printf '%s\n' "$probe_group" | cut -d: -f3)" = 65534 ] ||
    fail 'native syntax probe requires nobody with UID/GID 65534'
  probe_group=${probe_group%%:*}
  mkdir -m 0700 "$probe" "$probe/logs"
  output=$(timeout 20 "$loader" --library-path "$libs" "$nginx" -V 2>&1) || fail 'native runtime version preflight failed; enrollment was not attempted'
  printf '%s\n' "$output" | grep -Fxq "nginx version: openresty/${OPENRESTY_VERSION}" || fail 'native runtime version differs from signed manifest'
  for flag in --with-stream_realip_module --with-http_v2_module --with-http_v3_module --with-http_ssl_module --with-stream --with-stream_ssl_module --with-stream_ssl_preread_module; do
    printf '%s\n' "$output" | grep -Eq -- "(^|[[:space:]])${flag}([[:space:]]|$)" || fail "native runtime required module missing: ${flag}"
  done
  # This disposable syntax probe is not a managed site configuration. No
  # current link, listener, or persistent empty configuration is fabricated.
  cat >"${probe}/nginx.conf" <<EOF
user nobody ${probe_group};
worker_processes 1;
pid ${probe}/nginx.pid;
error_log stderr;
events { worker_connections 64; }
http {
  lua_package_path '${NATIVE_STAGE}/runtime/openresty/lualib/?.lua;${NATIVE_STAGE}/runtime/openresty/lualib/?/init.lua;;';
  lua_package_cpath '${NATIVE_STAGE}/runtime/openresty/lualib/?.so;;';
}
stream { }
EOF
  timeout 30 "$loader" --library-path "$libs" "$nginx" -t -p "${probe}/" -c "${probe}/nginx.conf" >"${probe}/result" 2>&1 ||
    fail "native runtime configuration preflight failed; enrollment was not attempted; $(progress_keep_output "${probe}/result" 'openresty -t')"
  # The Agent declares HTTP_3 only after the same self-test (openresty.http3_probe).
  timeout 20 "${NATIVE_STAGE}/runtime/bin/h3probe" version >"${probe}/h3probe-version.json" 2>&1 &&
    jq -e '.schema == "cdnca.h3probe/v1" and (.go | type == "string" and length > 0) and (.quic_go | type == "string" and length > 0)' \
      "${probe}/h3probe-version.json" >/dev/null ||
    fail "packaged HTTP/3 probe (runtime/bin/h3probe) failed its self-test; $(progress_keep_output "${probe}/h3probe-version.json" 'h3probe version')"
  timeout 20 "${NATIVE_STAGE}/bin/edge-agent" --version >"${probe}/agent-version.json" 2>&1 ||
    fail "native Agent version preflight failed; $(progress_keep_output "${probe}/agent-version.json" 'edge-agent --version')"
  source=$(jq -er .source.commit "${TEMP_DIR}/native-facts.json")
  jq -e --arg version "$NATIVE_VERSION" --arg source "$source" \
    '.event == "version" and .agent_version == $version and
     (.build_id == $source or
      .build_id == ("cdnca-" + $version + "-" + ($source | .[0:7])) or
      .build_id == ("cdnca-" + $version + "-" + ($source | .[0:12])))' "${probe}/agent-version.json" >/dev/null ||
    fail 'native Agent version or source differs from signed manifest'
}

activate_native_package() {
  local recorded
  NATIVE_RELEASE="${NATIVE_ROOT}/releases/${NATIVE_MANIFEST_SHA}"
  if "$RESUME"; then
    # Continue only the package the half install started with; its retained
    # release must equal what this run downloaded and verified again.
    recorded=$(install_state_value manifest_sha256)
    [ -z "$recorded" ] || [ "$recorded" = "$NATIVE_MANIFEST_SHA" ] ||
      fail "本次下载的节点安装包（${NATIVE_MANIFEST_SHA}）与上次未完成安装的（${recorded}）不同：管理端已发布新版本，无法续装；请先清理本机后全新安装"
    [ -n "$recorded" ] || install_state_add "manifest_sha256=${NATIVE_MANIFEST_SHA}"
    mkdir -p "${NATIVE_ROOT}/releases"
    chmod 0755 "$NATIVE_ROOT" "${NATIVE_ROOT}/releases"
    rm -f -- "${NATIVE_ROOT}/.current-install"
  else
    install_state_add "manifest_sha256=${NATIVE_MANIFEST_SHA}"
    # Reserve a blank installation. A first installation has no previous release.
    mkdir -m 0755 "$NATIVE_ROOT"
    mkdir -m 0755 "${NATIVE_ROOT}/releases"
  fi
  if "$RESUME" && [ -d "$NATIVE_RELEASE" ] && [ ! -L "$NATIVE_RELEASE" ]; then
    diff -r -q -- "$NATIVE_STAGE" "$NATIVE_RELEASE" >/dev/null ||
      fail "retained release ${NATIVE_RELEASE} differs from this run's verified package; refusing to resume"
    rm -rf -- "$NATIVE_STAGE"
  else
    mv -- "$NATIVE_STAGE" "$NATIVE_RELEASE"
  fi
  mkdir -p /usr/local/share /opt/cdnca
  # The Agent itself is published by the packaging transaction, not linked here.
  CREATED_LINKS+=("${NATIVE_ROOT}/current" /usr/local/openresty /usr/local/share/cdnca /opt/cdnca/l4geo)
  CREATED_TARGETS+=("releases/${NATIVE_MANIFEST_SHA}" "${NATIVE_ROOT}/current/runtime/openresty" \
    "${NATIVE_ROOT}/current/lua/share/cdnca" "${NATIVE_ROOT}/current/lua/l4geo")
  local index
  ln -s "${CREATED_TARGETS[0]}" "${NATIVE_ROOT}/.current-install"
  mv -T -- "${NATIVE_ROOT}/.current-install" "${NATIVE_ROOT}/current"
  for index in 1 2 3; do
    if "$RESUME" && [ -L "${CREATED_LINKS[$index]}" ] && [ "$(readlink "${CREATED_LINKS[$index]}")" = "${CREATED_TARGETS[$index]}" ]; then continue; fi
    ln -sT "${CREATED_TARGETS[$index]}" "${CREATED_LINKS[$index]}"
  done
  if "$RESUME"; then
    mkdir -p "$CONFIG_DIR" "$TRUST_DIR" "$TLS_DIR"
    chmod 0700 "$CONFIG_DIR" "$TRUST_DIR" "$TLS_DIR"
  else
    mkdir -m 0700 "$CONFIG_DIR"
    mkdir -m 0700 "$TRUST_DIR" "$TLS_DIR"
  fi
  install -m 0400 "$ARTIFACT_TRUST_FILE" "${TRUST_DIR}/artifacts.json"
  install -m 0400 "$GATEWAY_ROOT_CA_FILE" "${TLS_DIR}/gateway-ca.pem"
  if [ -n "$CONTROL_PLANE_CA_FILE" ]; then install -m 0400 "$CONTROL_PLANE_CA_FILE" "${TLS_DIR}/control-plane-ca.pem"; fi
  install -m 0400 "${TEMP_DIR}/upgrade-trust/control-execution.json" "${TRUST_DIR}/control-execution.json"
  install -m 0400 "${TEMP_DIR}/upgrade-trust/edge-execution.json" "${TRUST_DIR}/edge-execution.json"
  install -m 0400 "${TEMP_DIR}/upgrade-trust/download-ca.pem" "${TLS_DIR}/upgrade-download-ca.pem"
  ARTIFACT_TRUST_FILE="${TRUST_DIR}/artifacts.json"
  GATEWAY_ROOT_CA_FILE="${TLS_DIR}/gateway-ca.pem"
}

# Files moved out of mktemp directories keep their tmp label under SELinux and
# systemd could not execute them. No-op where SELinux is absent or disabled.
relabel_selinux() {
  command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled || return 0
  command -v restorecon >/dev/null 2>&1 || { warn 'SELinux is enabled but restorecon is missing; service files keep their labels'; return 0; }
  restorecon -RF "$NATIVE_ROOT" "$PACKAGE_RELEASE_ROOT" "$PACKAGING_LIBEXEC" "$HELPER_BINARY" "$CONFIG_DIR" \
    "$SYSTEMD_PACKAGE_DIR" /etc/systemd/system /usr/local/openresty /usr/local/share/cdnca /opt/cdnca 2>/dev/null ||
    warn 'restorecon reported errors; check SELinux labels if services fail to start'
}

# Install the Agent through the signed packaging transaction as a root runtime
# identity: versions/<version> + current, the fixed state bind layout, the
# pinned manifest key and the root unit. The manifest v2, its signature, SBOM
# and key are members of the native package, so they were authenticated by the
# native signature before this point and are re-verified by install.sh.
install_agent_packaging() {
  local release=$NATIVE_RELEASE
  PACKAGING_INSTALLED=true
  if "$RESUME" && install_state_has step=packaged &&
    [ "$(readlink "${PACKAGE_RELEASE_ROOT}/current" 2>/dev/null)" = "versions/${NATIVE_VERSION}" ]; then
    log "续装：签名 Agent ${NATIVE_VERSION} 已安装，跳过"
    return 0
  fi
  "${release}/packaging/scripts/install.sh" --runtime-identity root \
    --artifact "${release}/bin/edge-agent" \
    --sbom "${release}/evidence/edge-agent.spdx.json" \
    --manifest "${release}/upgrade/manifest" \
    --signature "${release}/upgrade/manifest.sig" \
    --public-key "${release}/upgrade/package-signing.pem" >/dev/null ||
    fail 'signed Agent packaging install failed; enrollment was not attempted'
  [ "$(readlink "${PACKAGE_RELEASE_ROOT}/current")" = "versions/${NATIVE_VERSION}" ] ||
    fail 'packaging install did not select the signed Agent version'
  install_state_add step=packaged
}

# Start the root packaging helper and prove, before enrollment, that the root
# Agent can use it: one `current` round trip over the fixed socket must return
# an active receipt for this exact release, signed by the helper's own pinned
# receipt key. Only then is that key converted into the Agent's trust store.
start_packaging_helper() {
  local unit
  [ "$(sed -n 's/^version=//p' "${NATIVE_RELEASE}/upgrade/manifest")" = "$NATIVE_VERSION" ] ||
    fail 'signed upgrade manifest version differs from the native package'
  HELPER_UNITS_INSTALLED=true
  install -m 0555 "${NATIVE_RELEASE}/bin/cdnca-edge-agent-helper" "$HELPER_BINARY"
  for unit in cdnca-edge-agent-helper.service cdnca-edge-agent-helper.socket; do
    install -m 0644 "${NATIVE_RELEASE}/packaging/systemd/${unit}" "${SYSTEMD_PACKAGE_DIR}/${unit}"
    systemd_compat_apply "${SYSTEMD_PACKAGE_DIR}/${unit}" "$unit" || fail "cannot render systemd compatibility for ${unit}"
  done
  # StateDirectory= (systemd 235+) creates the helper state roots; older
  # systemd ignores it, so create them with the same owner and mode.
  systemd_compat_knows Service.StateDirectory ||
    install -d -o root -g root -m 0700 /var/lib/cdnca-edge-agent-helper /var/lib/cdnca-edge-agent-backups
  systemctl daemon-reload
  "$HELPER_BINARY" key-init || fail 'packaging helper receipt key initialization failed'
  systemctl enable --now cdnca-edge-agent-helper.socket >/dev/null
  # Resume: the receipt trust is derived again from the live helper.
  if "$RESUME"; then rm -f -- "${TRUST_DIR}/installer-receipt.json"; fi
  probe_packaging_helper "$HELPER_SOCKET" "$HELPER_RECEIPT_PIN" "$NATIVE_VERSION" \
    "${TRUST_DIR}/installer-receipt.json" ||
    fail 'packaging helper is unreachable or returned unverifiable facts; node upgrades cannot be enabled'
}

probe_packaging_helper() {
  python3 - "$@" "$ED25519_TOOL" <<'PY_PACKAGING_HELPER'
import base64, json, os, re, socket, stat, subprocess, sys, tempfile

SPKI = bytes.fromhex('302a300506032b6570032100')
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')

def require(condition):
    if not condition:
        raise ValueError

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result

def b64raw(value, size):
    require(type(value) is str and re.fullmatch(r'[A-Za-z0-9+/]+', value) is not None)
    decoded = base64.b64decode(value + '=' * (-len(value) % 4), validate=True)
    require(len(decoded) == size)
    return decoded

socket_path, pin_path, expected_version, output, tool = sys.argv[1:]
try:
    info = os.lstat(pin_path)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o440 and
            info.st_nlink == 1 and 0 < info.st_size <= 4096)
    pin = json.loads(open(pin_path, 'rb').read().decode('ascii'), object_pairs_hook=unique)
    require(type(pin) is dict and list(pin) == ['schema_version', 'key_id', 'public_key'] and
            pin['schema_version'] == 1 and type(pin['schema_version']) is int and
            type(pin['key_id']) is str and IDENTIFIER.fullmatch(pin['key_id']))
    public_key = b64raw(pin['public_key'], 32)

    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    connection.settimeout(10)
    connection.connect(socket_path)
    connection.send(b'{"protocol_version":1,"operation":"current"}')
    connection.shutdown(socket.SHUT_WR)
    raw = connection.recv(32768)
    connection.close()
    response = json.loads(raw.decode('ascii'), object_pairs_hook=unique)
    require(type(response) is dict and list(response) == ['protocol_version', 'ok', 'receipt'] and
            response['protocol_version'] == 1 and response['ok'] is True)
    receipt = response['receipt']
    fields = ['schema_version', 'installer_transaction_id', 'release_sequence', 'artifact_sha256',
              'current_version', 'previous_version', 'status', 'issued_at', 'signature']
    if 'previous_version' not in receipt:
        fields.remove('previous_version')
    require(type(receipt) is dict and list(receipt) == fields and receipt['schema_version'] == 1 and
            receipt['status'] == 'active' and receipt['current_version'] == expected_version)
    signature = receipt['signature']
    require(type(signature) is dict and list(signature) == ['key_id', 'value'] and signature['key_id'] == pin['key_id'])
    signed = dict(receipt)
    del signed['signature']
    signed['key_id'] = signature['key_id']
    message = json.dumps(signed, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    # The helper response is canonical Go JSON; re-encoding must be byte exact.
    require(json.dumps(response, separators=(',', ':'), ensure_ascii=True).encode('ascii') == raw)
    der = SPKI + public_key
    pem = '-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(der).decode('ascii') + '\n-----END PUBLIC KEY-----\n'
    with tempfile.TemporaryDirectory() as scratch:
        for name, data in (('key.pem', pem.encode('ascii')), ('message', message),
                           ('signature', b64raw(signature['value'], 64))):
            with open(os.path.join(scratch, name), 'wb') as handle:
                handle.write(data)
        verified = subprocess.run([tool, 'verify', os.path.join(scratch, 'key.pem'), os.path.join(scratch, 'message'),
                                   os.path.join(scratch, 'signature')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  timeout=15, check=False, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        require(verified.returncode == 0)
    trust = json.dumps({'version': 1, 'keys': [{'key_id': pin['key_id'], 'public_key_pem': pem}]},
                       separators=(',', ':')).encode('ascii')
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(trust)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(output, 0o400)
except Exception:
    print('packaging helper probe rejected: socket, pin, receipt or signature check failed', file=sys.stderr)
    sys.exit(1)
PY_PACKAGING_HELPER
}

prepare_native_worker_account() {
  local record group_record name _account_field runtime_uid primary_gid account_home account_shell group_name runtime_gid members status all_accounts all_groups
  record=$(getent passwd cdnca-runtime) || { [ "$?" -eq 2 ] || fail 'native worker account rejected: account lookup failed'; }
  group_record=$(getent group cdnca-runtime) || { [ "$?" -eq 2 ] || fail 'native worker account rejected: group lookup failed'; }
  [ ! -e /nonexistent ] && [ ! -L /nonexistent ] || fail 'native worker account rejected: home must not exist'
  if [ -z "$record" ] && [ -z "$group_record" ]; then
    groupadd --system cdnca-runtime || fail 'native worker account rejected: system group creation failed'
    useradd --system --gid cdnca-runtime --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin cdnca-runtime ||
      fail 'native worker account rejected: account creation failed; retain and inspect the reserved group'
    record=$(getent passwd cdnca-runtime) || fail 'native worker account rejected: created account cannot be resolved'
    group_record=$(getent group cdnca-runtime) || fail 'native worker account rejected: created group cannot be resolved'
  fi
  # Never modify an existing account to make it pass. In particular, do not
  # repurpose a login account or share another service's numeric UID/GID.
  [[ -n "$record" && -n "$group_record" && "$record" != *$'\n'* && "$group_record" != *$'\n'* ]] || fail 'native worker account rejected: incomplete or duplicate identity'
  IFS=: read -r name _account_field runtime_uid primary_gid _account_field account_home account_shell <<<"$record"
  IFS=: read -r group_name _account_field runtime_gid members <<<"$group_record"
  [[ "$name" = cdnca-runtime && "$group_name" = cdnca-runtime && "$runtime_uid" =~ ^[1-9][0-9]{0,2}$ && "$runtime_gid" =~ ^[1-9][0-9]{0,2}$ && "$primary_gid" = "$runtime_gid" ]] ||
    fail 'native worker account rejected: a private non-root system UID/GID is required'
  [[ "$account_home" = /nonexistent && ( "$account_shell" = /usr/sbin/nologin || "$account_shell" = /sbin/nologin ) ]] ||
    fail 'native worker account rejected: login shell or home is not allowed'
  [[ -z "$members" || "$members" = cdnca-runtime ]] || fail 'native worker account rejected: shared group members'
  [[ "$(id -u cdnca-runtime)" = "$runtime_uid" && "$(id -g cdnca-runtime)" = "$runtime_gid" && "$(id -G cdnca-runtime)" = "$runtime_gid" ]] ||
    fail 'native worker account rejected: mismatched identity or supplementary groups'
  status=$(passwd -S cdnca-runtime) || fail 'native worker account rejected: password lock status unavailable'
  read -r name status _account_field <<<"$status"
  # shadow-utils reports a locked password as L (Debian/Ubuntu) or LK (RHEL 9/10).
  [[ "$name" = cdnca-runtime && ( "$status" = L || "$status" = LK ) ]] || fail 'native worker account rejected: password must be locked'
  all_accounts=$(getent passwd) || fail 'native worker account rejected: account enumeration failed'
  all_groups=$(getent group) || fail 'native worker account rejected: group enumeration failed'
  printf '%s\n' "$all_accounts" | awk -F: -v uid="$runtime_uid" -v gid="$runtime_gid" '
    $3 == uid || $4 == gid {count++; if ($1 != "cdnca-runtime") bad=1} END {exit bad || count != 1}' ||
    fail 'native worker account rejected: another account shares the UID or primary GID'
  printf '%s\n' "$all_groups" | awk -F: -v gid="$runtime_gid" '
    $3 == gid {count++; if ($1 != "cdnca-runtime") bad=1} END {exit bad || count != 1}' ||
    fail 'native worker account rejected: another group shares the GID'
  if command -v sudo >/dev/null 2>&1; then
    local sudo_output sudo_host sudo_status=0
    sudo_host=$(hostname -s) || fail 'native worker account rejected: hostname lookup failed'
    [[ -n "$sudo_host" && "$sudo_host" != *$'\n'* ]] || fail 'native worker account rejected: invalid hostname'
    # A successful root -l query can report no privileges. Require that exact
    # denial, not merely a status code; unknown output and query failures stop.
    sudo_output=$(LC_ALL=C timeout --kill-after=2s 10s sudo -n -l -U cdnca-runtime 2>&1 |
      python3 -c 'import sys
expected = ("User cdnca-runtime is not allowed to run sudo on %s.\n" % sys.argv[1]).encode()
print("denied" if sys.stdin.buffer.read(len(expected) + 1) == expected else "unknown")' "$sudo_host") || sudo_status=$?
    [[ ( "$sudo_status" = 0 || "$sudo_status" = 1 ) && "$sudo_output" = denied ]] ||
      fail 'native worker account rejected: sudo privileges are present or could not be ruled out'
  fi
}

# Self-registration: the same command works on every host.
# The machine fingerprint is stable across reinstalls, so the control plane
# reuses this host's pending node instead of creating a duplicate. The key is
# sent in an owner-only request file, never in argv.
machine_fingerprint() {
  local machine product
  machine=$(tr -d '[:space:]' <"$MACHINE_ID_FILE" 2>/dev/null) || machine=''
  [ -n "$machine" ] || fail "cannot read ${MACHINE_ID_FILE}; a machine ID is required to register the node"
  product=$(tr -d '[:space:]' <"$PRODUCT_UUID_FILE" 2>/dev/null | tr '[:upper:]' '[:lower:]') || product=''
  printf 'cdnca-node-registration-v1\0%s\0%s' "$machine" "$product" | sha256sum | cut -d' ' -f1
}

# public_ip_or_empty prints the canonical form of $1 when it is a public
# unicast address (not private, shared, loopback, link-local, documentation,
# multicast or reserved), otherwise nothing.
public_ip_or_empty() {
  python3 - "$1" <<'PY' 2>/dev/null || true
import ipaddress, sys
try:
    ip = ipaddress.ip_address(sys.argv[1].strip())
except ValueError:
    sys.exit(0)
if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
    ip = ip.ipv4_mapped
if ip.is_global and not ip.is_multicast:
    print(ip)
PY
}

# interface_public_ip prints the first public address configured on a
# network interface (IPv4 first), if any.
interface_public_ip() {
  local family address
  for family in -4 -6; do
    while read -r address; do
      address=$(public_ip_or_empty "${address%%/*}")
      if [ -n "$address" ]; then printf '%s' "$address"; return 0; fi
    done < <(ip "$family" -o addr show scope global 2>/dev/null | awk '{print $4}')
  done
  return 1
}

# external_public_ip asks every echo service and prints the address at least
# two of them agree on; with a single answer, that answer.
external_public_ip() {
  local source answer best='' count=0 answers=''
  for source in $PUBLIC_IP_SOURCES; do
    answer=$(curl -fsS --proto '=https' --connect-timeout 3 --max-time 5 --max-filesize 256 "$source" 2>/dev/null | head -n 1 | tr -d '[:space:]') ||
      answer=''
    answer=$(public_ip_or_empty "$answer")
    [ -z "$answer" ] || answers+="${answer}"$'\n'
  done
  [ -n "$answers" ] || return 1
  read -r count best < <(printf '%s' "$answers" | sort | uniq -c | sort -rn | head -n 1)
  if [ "$count" -lt 2 ] && [ "$(printf '%s' "$answers" | grep -c .)" -gt 1 ]; then
    warn "external IP services disagree ($(printf '%s' "$answers" | tr '\n' ' ')); not using them"
    return 1
  fi
  [ "$count" -ge 2 ] || warn "only one external IP service answered (${best})"
  printf '%s' "$best"
}

# detect_public_ip fills PUBLIC_IP: --public-ip, a public interface address,
# agreeing external services, then the terminal. Without any of them the
# registration still runs: the control plane records the source address.
detect_public_ip() {
  local typed given=$PUBLIC_IP
  if [ -n "$given" ]; then
    # Validated here, after dependencies are installed (python3).
    PUBLIC_IP=$(public_ip_or_empty "$given")
    [ -n "$PUBLIC_IP" ] || fail "--public-ip ${given} is not a public IPv4 or IPv6 address"
    return 0
  fi
  PUBLIC_IP=$(interface_public_ip) || PUBLIC_IP=$(external_public_ip) || PUBLIC_IP=''
  if [ -z "$PUBLIC_IP" ] && [ "$ASSUME_YES" != true ] && { : </dev/tty; } 2>/dev/null && [ -t 2 ]; then
    while [ -z "$PUBLIC_IP" ]; do
      printf '[cdnca-edge] 未能自动检测本机公网 IP，请输入（直接回车跳过，由管理端按来源地址记录）: ' >&2
      IFS= read -r typed </dev/tty || typed=''
      [ -n "$typed" ] || break
      PUBLIC_IP=$(public_ip_or_empty "$typed")
      [ -n "$PUBLIC_IP" ] || printf '[cdnca-edge] %s 不是公网 IP，请重新输入\n' "$typed" >&2
    done
  fi
  if [ -n "$PUBLIC_IP" ]; then log "本机公网 IP：${PUBLIC_IP}"; else warn '未检测到本机公网 IP，管理端将按注册请求的来源地址记录'; fi
}

register_node() {
  local request="${TEMP_DIR}/registration-request.json" response="${TEMP_DIR}/registration-response.json"
  local status code fingerprint public_ip
  fingerprint=$(machine_fingerprint)
  detect_public_ip
  public_ip=$PUBLIC_IP
  log "registering this host with ${CONTROL_PLANE_ORIGIN:-$CONTROL_PLANE}"
  while :; do
    jq -n --arg credential "$REGISTRATION_KEY" --arg fingerprint "$fingerprint" \
      --arg hostname "${NODE_NAME:-$(hostname -s 2>/dev/null || true)}" \
      --arg os "$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-}")" \
      --arg kernel "$(uname -r)" --arg arch "$(uname -m)" --arg public_ip "$public_ip" \
      '{credential: $credential, machine_fingerprint: $fingerprint, hostname: $hostname,
        os_name: $os, kernel_version: $kernel, architecture: $arch}
       + (if $public_ip == "" then {} else {public_ip: $public_ip} end)' >"$request"
    chmod 0600 "$request"
    status=$(curl_download "${CONTROL_PLANE%/}/v1/node-registrations" -sS --connect-timeout 10 --max-time 30 \
      --max-filesize 65536 -o "$response" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
      --data-binary "@${request}") || status=000
    rm -f -- "$request"
    code=$(jq -r '.error.code // empty' "$response" 2>/dev/null || true)
    # A control plane older than public_ip rejects the unknown field; send
    # the registration again without it (it records the source address).
    if [ "$status" = 400 ] && [ "$code" = invalid_request ] && [ -n "$public_ip" ]; then
      warn '管理端版本较旧，不接收 public_ip 字段，改为按来源地址登记'
      public_ip=''
      continue
    fi
    break
  done
  unset REGISTRATION_KEY
  if [ "$status" = 200 ] || [ "$status" = 201 ]; then
    ENROLLMENT_TOKEN=$(jq -er '.enrollment_token.token | select(type == "string" and test("^[A-Za-z0-9._-]{16,512}$"))' "$response") ||
      fail '主控返回的注册响应无效，请稍后重试'
    log "节点已注册（$(jq -r '"ID " + .node.display_id + "，名称 " + .node.name' "$response")），安装完成后请到管理端「节点列表 → 待初始化」点击「初始化」"
    rm -f -- "$response"
    return 0
  fi
  rm -f -- "$response"
  case "$code" in
    invalid_registration_credential) fail '节点注册凭据无效或已被重置，请从管理端「节点安装命令」重新复制最新命令' ;;
    node_already_registered) fail '本机已注册到管理端（已完成注册或已初始化）；如需重新安装，请先在管理端删除该节点' ;;
    node_registration_rate_limited) fail '注册请求过于频繁，请 1 分钟后重试' ;;
    node_registration_limit) fail '待初始化节点过多，请先在管理端处理「待初始化」列表' ;;
    node_registration_unavailable) fail '管理端未启用节点注册，请检查主控配置' ;;
    validation_error) fail '注册信息无效（请检查 /etc/machine-id）' ;;
    *) fail "节点注册失败（HTTP ${status}${code:+，${code}}），请检查与管理端 ${CONTROL_PLANE} 的 HTTPS 连通性后重试" ;;
  esac
}

# fz-x13: the previous run's Gateway enrollment may have committed on the
# controller (certificate issued) while this host never wrote its identity.
# Registering again would be refused, so fetch the issued identity with the
# registration credential and let the Agent assemble it from the pending
# keys. Returns 1 to fall back to register + enroll. Called as an if/elif
# condition (errexit is off): every step checks its own status.
recover_registered_identity() {
  local request="${TEMP_DIR}/identity-request.json" response="${TEMP_DIR}/identity-response.json"
  local csr fingerprint status code
  mkdir -p "$CONFIG_DIR" && chmod 0700 "$CONFIG_DIR" || return 1
  if [ -f "${IDENTITY_DIR}.enrolling/identity.json" ] && [ ! -e "${IDENTITY_DIR}.enrolling/pending.json" ]; then
    # Files written, directory rename interrupted: no controller call needed.
    : >"$response" && chmod 0600 "$response" || return 1
  else
    csr=$("$AGENT_BINARY" enroll --print-pending-csr-sha256 --identity-dir "$IDENTITY_DIR" --machine-id-file /etc/machine-id) &&
      [[ "$csr" =~ ^[0-9a-f]{64}$ ]] || { warn '续装：本机上次的身份申请记录不完整，按原流程注册'; return 1; }
    fingerprint=$(machine_fingerprint)
    jq -n --arg credential "$REGISTRATION_KEY" --arg fingerprint "$fingerprint" --arg csr "$csr" \
      '{credential: $credential, machine_fingerprint: $fingerprint, csr_sha256: $csr}' >"$request" && chmod 0600 "$request" || return 1
    log "续装：向 ${CONTROL_PLANE_ORIGIN:-$CONTROL_PLANE} 查询本机已签发的身份"
    status=$(curl_download "${CONTROL_PLANE%/}/v1/node-registrations/identity" -sS --connect-timeout 10 --max-time 30 \
      --max-filesize 1048576 -o "$response" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
      --data-binary "@${request}") || status=000
    rm -f -- "$request"
    if [ "$status" != 200 ]; then
      code=$(jq -r '.error.code // empty' "$response" 2>/dev/null || true)
      rm -f -- "$response"
      case "$code" in
        invalid_registration_credential) fail '节点注册凭据无效或已被重置，请从管理端「节点安装命令」重新复制最新命令' ;;
        node_registration_rate_limited) fail '注册请求过于频繁，请 1 分钟后重试' ;;
      esac
      # 404: nothing was issued for this pending request (or an older
      # controller without the endpoint); registering again is safe.
      if [ "$status" = 404 ]; then log '续装：主控没有本机已签发的身份，按原流程注册'; else
        warn "续装：查询已签发身份失败（HTTP ${status}${code:+，${code}}），按原流程注册"
      fi
      return 1
    fi
    chmod 0600 "$response" || return 1
  fi
  if ! "$AGENT_BINARY" enroll --recover-from-response "$response" --identity-dir "$IDENTITY_DIR" \
    --machine-id-file /etc/machine-id >"${TEMP_DIR}/enrollment-result.json"; then
    rm -f -- "$response"
    fail '续装：主控返回的身份与本机保存的密钥不匹配，请到管理端删除该节点后重装'
  fi
  rm -f -- "$response"
  [ -f "${IDENTITY_DIR}/identity.json" ] || fail 'identity recovery returned without an identity file'
  unset REGISTRATION_KEY
  log '续装：已从主控取回本机已签发的身份，跳过注册'
}

enroll() {
  local token_file="${TEMP_DIR}/enrollment-token"
  printf '%s' "$ENROLLMENT_TOKEN" >"$token_file"
  chmod 0600 "$token_file"
  unset ENROLLMENT_TOKEN
  # Keep the parent private so enrollment.Run can create the identity
  # directory itself and atomically commit it after the Gateway response.
  mkdir -p "$CONFIG_DIR"
  chmod 0700 "$CONFIG_DIR"
  log "enrolling this host with ${GATEWAY_ENROLLMENT_ADDRESS}"
  ENROLLMENT_ATTEMPTED=true
  "$AGENT_BINARY" enroll \
    --gateway-address "$GATEWAY_ENROLLMENT_ADDRESS" \
    --gateway-server-name "$GATEWAY_SERVER_NAME" \
    --gateway-root-ca-file "$GATEWAY_ROOT_CA_FILE" \
    --gateway-transport "$GATEWAY_TRANSPORT" ${GATEWAY_TUNNEL_HOST:+--gateway-tunnel-host "$GATEWAY_TUNNEL_HOST"} \
    --identity-dir "$IDENTITY_DIR" \
    --machine-id-file /etc/machine-id \
    --token-file "$token_file" >/"${TEMP_DIR}/enrollment-result.json"
  rm -f -- "$token_file"
  [ -f "${IDENTITY_DIR}/identity.json" ] || fail 'enrollment returned without an identity file'
}

# GATEWAY_ENDPOINTS -> JSON array for gateway.endpoints.
gateway_endpoints_json() {
  local entry address server transport tunnel json='[]'
  for entry in $GATEWAY_ENDPOINTS; do
    IFS='|' read -r address server transport tunnel <<<"$entry"
    [[ "$address" =~ ^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):[0-9]{1,5}$ ]] && [[ "$server" =~ ^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$ ]] &&
      [[ "${transport:-grpc}" =~ ^(grpc|ws)$ ]] || fail "invalid gateway endpoint: $entry"
    json=$(jq -c --arg a "$address" --arg s "$server" --arg t "${transport:-grpc}" --arg h "$tunnel" \
      '. + [{address: $a, server_name: $s, transport: $t} + (if $h == "" then {} else {tunnel_host: $h} end)]' <<<"$json")
  done
  printf '%s' "$json"
}

write_config() {
  if "$RESUME" && [ -d "$NODE_MONITORING_DIR" ] && [ ! -L "$NODE_MONITORING_DIR" ]; then :; else
    mkdir -m 0700 "$NODE_MONITORING_DIR" || fail 'node monitoring state appeared after first-install preflight; refusing to reuse it'
  fi
  # The journal and certificate roots live behind the Agent unit's state bind;
  # creating them here would populate the bind mountpoint, so the Agent does.
  mkdir -p "$CONFIG_DIR" "$STATE_ROOT"
  chmod 0700 "$CONFIG_DIR" "$STATE_ROOT"
  # Upgrade is enabled only with every runtime prerequisite in place: the
  # helper was reached and its receipt key converted (start_packaging_helper),
  # and the pinned execution trust and download root were installed.
  local trust_file
  for trust_file in "${TRUST_DIR}/control-execution.json" "${TRUST_DIR}/edge-execution.json" \
    "${TRUST_DIR}/installer-receipt.json" "${TLS_DIR}/upgrade-download-ca.pem"; do
    [ -n "$(find "$trust_file" -maxdepth 0 -type f -perm 0400 2>/dev/null)" ] ||
      fail "node upgrade cannot be enabled: ${trust_file} is missing or not an owner read-only file"
  done
  # OWASP CRS engine extension (waf_engine): the node package does not contain
  # it. It arrives as an item of the node artifact set (license catalog ->
  # control plane -> node); the Agent verifies it with the platform release
  # keys of artifact_trust_file (the trust that verified this node package),
  # installs it below root (inside deployment_root, readable by the native
  # OpenResty unit) and gates the module in when a release has a site running
  # OWASP CRS rule sets. disabled=true: the module item is refused, CRS sites
  # run the self-developed detection only and the deployment status reports
  # edge_waf_crs_engine degraded. timeout is no longer used.
  # Telemetry (access/security logs to the gateway) is on: without it the
  # dynamic routing skeleton writes no node-level logs and nothing is
  # reported. The spool is the Agent default, under its state bind; the other
  # telemetry limits keep their defaults.
  jq -n \
    --arg identity "$IDENTITY_DIR" --arg trust "$ARTIFACT_TRUST_FILE" \
    --arg deployment "$STATE_ROOT" --arg journal "$JOURNAL_DIR" \
    --arg certificateRuntime "$CERT_RUNTIME_DIR" \
    --arg nodeMonitoring "$NODE_MONITORING_DIR" \
    --arg gateway "$GATEWAY_ADDRESS" --arg enrollment "$GATEWAY_ENROLLMENT_ADDRESS" --arg serverName "$GATEWAY_SERVER_NAME" \
    --arg transport "$GATEWAY_TRANSPORT" --arg tunnelHost "$GATEWAY_TUNNEL_HOST" \
    --argjson endpoints "$(gateway_endpoints_json)" \
    --arg ca "$GATEWAY_ROOT_CA_FILE" --arg openrestyVersion "$OPENRESTY_VERSION" \
    --arg upgradeInstallation "$UPGRADE_INSTALLATION_ID" --arg upgradeHost "$UPGRADE_DOWNLOAD_HOST" \
    --argjson upgradePort "$UPGRADE_DOWNLOAD_PORT" --argjson upgradeAddresses "$UPGRADE_DOWNLOAD_ADDRESSES" \
    --arg upgradeControlTrust "${TRUST_DIR}/control-execution.json" --arg upgradeEdgeTrust "${TRUST_DIR}/edge-execution.json" \
    --arg upgradeCA "${TLS_DIR}/upgrade-download-ca.pem" --arg upgradeReceiptTrust "${TRUST_DIR}/installer-receipt.json" \
    --argjson externalProbe "$EXTERNAL_PROBE" --argjson disableXDP "$DISABLE_XDP" \
    --arg securityRoot "${NATIVE_RELEASE}/lua/share/cdnca/security" --argjson securityAssets "$NATIVE_SECURITY_ASSETS" \
    '{
      version: 2, identity_dir: $identity,
      artifact_trust_file: $trust, deployment_root: $deployment, journal_dir: $journal,
      gateway: ({address: $gateway, enrollment_address: $enrollment, server_name: $serverName, root_ca_file: $ca, transport: $transport}
        + (if $tunnelHost == "" then {} else {tunnel_host: $tunnelHost} end)
        + (if ($endpoints | length) == 0 then {} else {endpoints: $endpoints} end)),
      openresty: {binary: "/usr/local/openresty/bin/openresty", config_file: "nginx.conf", health_url: "http://127.0.0.1:18080/healthz", version: $openrestyVersion, systemd_service: "cdnca-openresty-native.service", http3_probe: "/opt/cdnca-node/current/runtime/bin/h3probe"},
      certificate_runtime: {state_root: $certificateRuntime, listen_address: "127.0.0.1", listen_port: 18443},
      node_monitoring: {enabled: true, state_dir: $nodeMonitoring, default_port: 80},
      market_probe: {enabled: $externalProbe, join_market: false},
      dynamic_routing: {enabled: true, worker_group: "cdnca-runtime"},
      security_runtime: {enabled: true, mode: "native",
        waf: {path: ($securityRoot + "/cdnca_waf.lua"), sha256: $securityAssets.waf},
        cc: {path: ($securityRoot + "/cc.lua"), sha256: $securityAssets.cc},
        adaptive: {path: ($securityRoot + "/cc_adaptive.lua"), sha256: $securityAssets.adaptive}},
      telemetry: {enabled: true, spool_root: "/var/lib/cdnca-edge-agent/event-spool"},
      upgrade: {enabled: true, installation_id: $upgradeInstallation, root: "/var/lib/cdnca-edge-agent/upgrades",
        control_execution_trust_file: $upgradeControlTrust, edge_execution_trust_file: $upgradeEdgeTrust,
        installer_receipt_trust_file: $upgradeReceiptTrust, download_host: $upgradeHost, download_addresses: $upgradeAddresses,
        download_port: $upgradePort, download_root_ca_file: $upgradeCA, timeout: "10m",
        max_artifact_bytes: 285229182, disk_reserve_bytes: 536870912},
      limits: {max_command_bytes: 1048576, max_status_bytes: 262144, max_artifact_bytes: 134217728, max_decompressed_bytes: 134217728, max_artifact_chunk_bytes: 1048576, max_active_deployments: 128, command_queue_size: 32, max_files: 4096, max_file_bytes: 16777216, max_total_bytes: 134217728, retain_releases: 5},
      timeouts: {handshake: "10s", artifact_fetch: "2m", initial_backoff: "250ms", maximum_backoff: "30s", precheck: "15s", reload: "15s", health: "30s", health_interval: "500ms", health_request: "2s"},
      waf_engine: {disabled: false, root: ($deployment + "/extensions/waf-crs"), timeout: "2m"},
      xdp: {disabled: $disableXDP}
    }' >"$CONFIG_FILE"
  chmod 0600 "$CONFIG_FILE"
  "$AGENT_BINARY" --config "$CONFIG_FILE" --check-config >/dev/null || fail 'edge-agent rejected the generated v2 configuration'
}

# detect_xdp reports the XDP mode this machine supports (the Agent detects it
# again at every start and reports it to the control plane; the node page
# shows it). Never fails the install: without XDP the node runs nftables.
detect_xdp() {
  local result
  if [ "$DISABLE_XDP" = true ]; then
    log 'XDP kernel filter disabled (--disable-xdp): DDoS protection runs on nftables'
    return 0
  fi
  if ! result=$("$AGENT_BINARY" xdp-probe 2>/dev/null) || [ -z "$result" ]; then
    warn 'XDP detection did not run; the Agent detects it again when it starts'
    return 0
  fi
  case "$(printf '%s' "$result" | jq -r '.mode // empty')" in
    native) log "XDP kernel filter: native (driver) mode on $(printf '%s' "$result" | jq -r '.interfaces | join(", ")')" ;;
    generic) log "XDP kernel filter: generic mode on $(printf '%s' "$result" | jq -r '.interfaces | join(", ")') (the NIC driver has no native XDP)" ;;
    *) log "XDP kernel filter not supported here ($(printf '%s' "$result" | jq -r '[.reason, .detail] | map(select(. != null and . != "")) | join(": ")')); DDoS protection runs on nftables" ;;
  esac
}

setup_service() {
  local unit stable restarts
  # An Agent unit in /etc would shadow the packaged one and run a binary the
  # helper never upgrades; only the packaged root unit may define the service.
  [ ! -e "/etc/systemd/system/${SERVICE_NAME}.service" ] && [ ! -L "/etc/systemd/system/${SERVICE_NAME}.service" ] ||
    fail 'service appeared after first-install preflight; refusing to overwrite it'
  cmp -s "${SYSTEMD_PACKAGE_DIR}/${SERVICE_NAME}.service" "${NATIVE_RELEASE}/packaging/systemd/cdnca-edge-agent-root.service" ||
    fail 'the packaged root Agent unit is missing or differs from the signed release'
  AGENT_UNIT_INSTALLED=true
  mkdir -p /var/log/cdnca-edge-agent
  chmod 0700 /var/log/cdnca-edge-agent
  systemd_compat_apply "${SYSTEMD_PACKAGE_DIR}/${SERVICE_NAME}.service" "${SERVICE_NAME}.service" ||
    fail 'cannot render systemd compatibility for the node units'
  systemctl daemon-reload
  # No OpenResty unit: the Agent's dynamic routing runtime starts and owns the
  # OpenResty master (again after a reboot, when the Agent starts).
  systemctl enable "$SERVICE_NAME" >/dev/null
  AGENT_STARTED_AT=$(date '+%Y-%m-%d %H:%M:%S')
  systemctl restart "$SERVICE_NAME"
  # Require a stable active Agent (no automatic restart) rather than a single
  # sample: a crash loop would otherwise pass between restarts.
  stable=0
  for _ in $(seq 1 45); do
    if systemctl is-active --quiet "$SERVICE_NAME"; then stable=$((stable + 1)); else stable=0; fi
    restarts=$(systemctl show "$SERVICE_NAME" --property=NRestarts --value 2>/dev/null || true)
    [ -z "$restarts" ] || [ "$restarts" = 0 ] || break
    [ "$stable" -lt 5 ] || return 0
    progress_tick ' edge-agent 稳定运行' 90
    sleep 2
  done
  journalctl -u "$SERVICE_NAME" -n 50 --no-pager >&2 || true
  fail 'edge-agent did not become stably active'
}

# PJ-E05: an active unit is not a working node. Require that this Agent start
# held a Gateway session: the Agent sends its network inventory only after the
# GatewayHello passed (gatewayclient runSession), and a session that ended logs
# established=true. The loopback health port (OpenResty, started with the first
# release) must answer when it listens. Without a session the service is kept
# running (it keeps reconnecting) and the operator is told what to check.
verify_agent_connected() {
  local journal='' tries attempt port=${GATEWAY_ADDRESS##*:} last_error
  tries=$((GATEWAY_SESSION_WAIT_SECONDS / 3)); [ "$tries" -ge 1 ] || tries=1
  for ((attempt = 0; attempt < tries; attempt++)); do
    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
      journalctl -u "$SERVICE_NAME" -n 50 --no-pager >&2 || true
      fail 'edge-agent 启动后又退出，见上面的服务日志'
    fi
    journal=$(journalctl -u "$SERVICE_NAME" --since "$AGENT_STARTED_AT" -o cat --no-pager 2>/dev/null || true)
    if grep -Eq 'node network inventory report|gateway session ended; reconnecting established=true' <<<"$journal"; then
      log "已与主控网关 ${GATEWAY_ADDRESS} 建立会话"
      if timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/18080' 2>/dev/null; then
        curl -fsS --max-time 3 -o /dev/null http://127.0.0.1:18080/healthz || {
          INSTALL_KEEP=true
          fail '本机健康检查失败：http://127.0.0.1:18080/healthz 无响应；查看 journalctl -u cdnca-edge-agent 中的 OpenResty 报错'
        }
        log '本机健康检查通过（127.0.0.1:18080/healthz）'
      else
        log '健康端口 127.0.0.1:18080 尚未监听：主控下发首个配置后由 Agent 启动 OpenResty'
      fi
      return 0
    fi
    progress_tick ' 连接主控网关' "$GATEWAY_SESSION_WAIT_SECONDS"
    sleep 3
  done
  last_error=$(grep -F 'established=false' <<<"$journal" | tail -n 1 | sed -nE 's/.*error=(.*)$/\1/p')
  INSTALL_KEEP=true
  fail "服务已起但未连上主控网关 ${GATEWAY_ADDRESS}（等待 ${GATEWAY_SESSION_WAIT_SECONDS} 秒）${last_error:+；最近一次错误：${last_error}}。
  请检查：1) 主控防火墙/安全组已放行 TCP ${port}，本机能连通（timeout 5 bash -c 'exec 3<>/dev/tcp/${GATEWAY_ADDRESS%:*}/${port}'，IPv6 去掉方括号）；
  2) 本机时间准确（timedatectl）；3) 主控网关服务正常、证书名为 ${GATEWAY_SERVER_NAME}；4) 日志：journalctl -u ${SERVICE_NAME} -n 100。
  服务保持运行并会自动重连；修好后在原安装命令末尾加 --resume 重新自检"
}

# Edge kernel baseline. Each entry is
# name:direction:value; "min" raises a smaller value, "max" lowers a larger
# one. ip_local_port_range is deliberately left alone: widening it downwards
# would let ephemeral ports collide with tenant L4 listener ports. A value the operator already set beyond the baseline is kept, and a
# key the kernel does not expose (container, older kernel) is skipped. Only
# the values this run changed are persisted in one sysctl.d drop-in so a reboot keeps them.
# tcp_mtu_probing 1: when the path to the control
# plane / gateway drops ICMP "fragmentation needed" (PMTU black hole, e.g. a
# tunnel or VPC hop with a smaller MTU), full-size segments of a large config
# sync vanish and the stream stalls; probing shrinks the MSS once a black hole
# is detected and leaves normal paths untouched.
SYSCTL_BASELINE='net.core.somaxconn:min:65535
net.ipv4.tcp_max_syn_backlog:min:65535
net.core.netdev_max_backlog:min:16384
net.ipv4.tcp_fin_timeout:max:15
net.ipv4.tcp_max_tw_buckets:min:262144
net.ipv4.tcp_syncookies:min:1
net.core.rmem_max:min:33554432
net.core.wmem_max:min:33554432
fs.file-max:min:2097152
fs.nr_open:min:2097152
vm.max_map_count:min:262144
net.ipv4.tcp_mtu_probing:min:1'

tune_sysctl() {
  local entry name direction value path current persisted='' changed=0
  [ "$SKIP_SYSCTL_TUNING" = true ] && { log 'kernel parameter tuning skipped (--skip-sysctl-tuning)'; return 0; }
  while IFS= read -r entry; do
    name=${entry%%:*}; entry=${entry#*:}; direction=${entry%%:*}; value=${entry#*:}
    path=${SYSCTL_ROOT}/${name//.//}
    [ -r "$path" ] && [ -w "$path" ] || continue
    current=$(tr -d '[:space:]' <"$path")
    case "$direction" in
      min) [[ "$current" =~ ^[0-9]+$ ]] || continue; [ "$current" -lt "$value" ] || continue ;;
      max) [[ "$current" =~ ^[0-9]+$ ]] || continue; [ "$current" -gt "$value" ] || continue ;;
      *) continue ;;
    esac
    if printf '%s\n' "$value" >"$path" 2>/dev/null; then
      log "kernel parameter ${name}: ${current} -> ${value}"
      persisted+="${name} = ${value}"$'\n'; changed=$((changed + 1))
    else
      warn "kernel parameter ${name} could not be set to ${value}"
    fi
  done <<<"$SYSCTL_BASELINE"
  [ -n "$persisted" ] || { log 'kernel parameters already meet the edge baseline'; return 0; }
  mkdir -p "$(dirname -- "$SYSCTL_CONF")"
  printf '# Written by the cdnca edge node installer; edit or delete to change.\n%s' "$persisted" >"${SYSCTL_CONF}.tmp" &&
    chmod 0644 "${SYSCTL_CONF}.tmp" && mv -f "${SYSCTL_CONF}.tmp" "$SYSCTL_CONF" ||
    warn "could not persist kernel parameters to ${SYSCTL_CONF}"
  log "kernel parameter baseline applied (${changed} changed); persisted in ${SYSCTL_CONF}"
}

configure_firewall() {
  [ "$SKIP_FIREWALL" = true ] && return 0
  warn 'firewall was not changed; allow the configured Gateway/OpenResty ports in the host policy'
}

main() {
  # Used by the signed management bundle before consuming its activation code.
  # Verification/extraction only: no enrollment, global links or service writes.
  if [ "${1:-}" = --verify-native-package ]; then
    [ "$#" -eq 4 ] || fail 'verification requires archive, independent trust and a new destination'
    verify_native_package "$2" "$3" "$4"
    return
  fi
  parse_args "$@"
  read_enrollment_token
  progress_init
  progress_stage
  run_preflight
  load_console_defaults
  normalise_defaults
  check_gateway_reachable
  assert_blank_host
  "$RESUME" || install_state_begin
  progress_stage
  quiesce_package_automation
  # A freshly booted host runs unattended-upgrades, which holds the dpkg lock
  # for minutes; APT_CONFIG is read in addition to the system configuration.
  [ -n "$TEMP_DIR" ] || TEMP_DIR=$(mktemp -d -t cdnca-edge-install.XXXXXX)
  printf 'DPkg::Lock::Timeout "900";\n' >"$TEMP_DIR/apt-lock.conf"
  export APT_CONFIG="$TEMP_DIR/apt-lock.conf"
  if ! require_commands; then install_dependencies; fi
  require_commands || fail 'required commands are still missing after dependency installation'
  ssh_guard_setup
  progress_stage
  prepare_control_plane_ca
  fetch_ed25519_tool
  # The pinned upgrade trust carries the offline root pin install_trust_material verifies signer-trust.json with.
  install_upgrade_trust
  install_trust_material
  progress_stage
  download_agent
  progress_stage
  preflight_native_runtime
  prepare_native_worker_account
  activate_native_package
  install_ed25519_tool
  install_agent_packaging
  relabel_selinux
  start_packaging_helper
  progress_stage
  # Register only after every local preflight passed, so a host that cannot
  # be installed never appears in the pending list.
  if "$RESUME" && [ -f "${IDENTITY_DIR}/identity.json" ]; then
    log '续装：本机已向网关注册（身份文件已存在），跳过注册'
  elif "$RESUME" && [ -d "${IDENTITY_DIR}.enrolling" ] && [ -n "$REGISTRATION_KEY" ] && recover_registered_identity; then
    :
  else
    # A one-time token is consumed by the enrollment it started; the
    # controller cannot hand that identity back without a reusable credential.
    if "$RESUME" && [ -d "${IDENTITY_DIR}.enrolling" ] && [ -z "$REGISTRATION_KEY" ]; then
      warn '续装：上次的身份申请未完成，用一次性安装令牌安装的节点无法从主控取回已签发的身份；若下面注册失败，请到管理端删除该节点后重装'
    fi
    if [ -n "$REGISTRATION_KEY" ]; then register_node; fi
    enroll
  fi
  write_config
  progress_stage
  detect_xdp
  configure_firewall
  tune_sysctl
  progress_stage
  setup_service
  verify_agent_connected
  install_state_add step=done
  log "edge-agent installed and enrolled; identity is ${IDENTITY_DIR}/identity.json"
  progress_done
}

main "$@"
