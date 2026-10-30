#!/usr/bin/env bash
# CDNCA control-plane installer.
# cdncaCE community edition: no activation. The installer records the
# installation (control-api install-community); the community entitlement is
# built into control-api. Online upgrades are off (upgrade by replacing the package).
set -Eeuo pipefail
umask 077

readonly INSTALL_ROOT="/usr/local/cdnca-control"
readonly NATIVE_ROOT="/data/cdnca-native-root/cdnca"
readonly CONFIG_DIR="/etc/cdnca-control"
readonly KEY_DIR="${CONFIG_DIR}/keys"
readonly DATA_DIR="/var/lib/cdnca-control"
readonly RESPONSE_DIR="${DATA_DIR}/activation"
readonly SERVICE_NAME="cdnca-control-api"
readonly GATEWAY_SERVICE_NAME="cdnca-agent-gateway"
readonly NATS_SERVICE_NAME="cdnca-control-nats"
readonly WEB_SERVICE_NAME="cdnca-control-web"
readonly PKI_DIR="${KEY_DIR}/pki"
readonly NATS_DATA_DIR="${DATA_DIR}/nats"
readonly DOWNLOAD_DIR="${DATA_DIR}/downloads"
readonly WEB_ROOT="${NATIVE_ROOT}/current/static/web"
readonly NGINX_RUNTIME_DIR="${DATA_DIR}/nginx-runtime"
readonly GATEWAY_ENV_FILE="${CONFIG_DIR}/gateway.env"
readonly NGINX_CONF="${CONFIG_DIR}/nginx.conf"
readonly NATS_SERVER_BIN="/usr/local/bin/nats-server"
readonly NATS_CLI_BIN="/usr/local/bin/nats"
readonly UPGRADE_KEY_DIR="${KEY_DIR}/upgrade"
readonly UPGRADE_CONTROL_KEY_ID="control-execution-v1"
readonly UPGRADE_EDGE_KEY_ID="edge-execution-v1"
UPGRADE_TRUST_SHA256=""
# Static Ed25519 tool (tools/ed25519-tool, reproducible go1.27.3 build). Every
# Ed25519 key, signature and verification of this installer goes through it,
# never through the host OpenSSL; docs/install/ed25519-tool-security.md.
readonly CDNCA_ED25519_TOOL_SHA256="82d8412f72b021d894ed14db2daded74b14f4930a167e307b22131ea067d7d17"
readonly ED25519_TOOL="/usr/local/libexec/cdnca/cdnca-ed25519"

LICENSING_SERVER=""
LICENSING_SERVER_FALLBACK=""
MASTER_HOST=""
MASTER_PORT=""
CONTROL_DOMAIN=""
GATEWAY_HOST=""
# Gateway enrollment,agent ports (ADR 0013 §3.5): empty = two random free ports in 20000-29999.
GATEWAY_PORTS=""
GATEWAY_ENROLLMENT_PORT=""
GATEWAY_AGENT_PORT=""
INSTALLATION_ID=""
INSTALLATION_NAME=""
ADMIN_EMAIL="admin@local"
CERTIFICATE_EMAIL=""
ADMIN_USERNAME=""
ADMIN_PASSWORD=""
ADMIN_PASSWORD_FILE=""
DATABASE_URL=""
DATABASE_PASSWORD=""
REDIS_URL=""
NATS_URL=""
NATS_SERVER_VERSION="2.12.15-cdnca.1"
NATS_CLI_VERSION="0.2.4"
NATS_CLI_URL=""
NATS_CLI_SHA256_URL=""
NATS_LOCAL=true
REDIS_LOCAL=true
CONTROL_NATIVE_URL=""
CONTROL_NATIVE_FALLBACK_URL=""
CONTROL_NATIVE_SHA256_URL=""
CONTROL_NATIVE_SHA256_FALLBACK_URL=""
CONTROL_NATIVE_TRUST_URL=""
CONTROL_NATIVE_TRUST_FALLBACK_URL=""
CONTROL_NATIVE_FILE=""
CONTROL_NATIVE_TRUST_FILE=""
CONTROL_BINARY=""
CONTROL_ORIGIN=""
NATIVE_SUPPORT=""
TRUSTED_KEYS_URL=""
TRUSTED_KEYS_FALLBACK_URL=""
SIGNER_REVOCATION_OFFLINE_ROOT_KEY_ID=""
SIGNER_REVOCATION_OFFLINE_ROOT_GENERATION=""
SIGNER_REVOCATION_OFFLINE_ROOT_PUBLIC_KEY=""
EDGE_AGENT_URL=""
EDGE_AGENT_FALLBACK_URL=""
EDGE_AGENT_SHA256_URL=""
EDGE_AGENT_SHA256_FALLBACK_URL=""
EDGE_ARTIFACT_TRUST_URL=""
EDGE_ARTIFACT_TRUST_FALLBACK_URL=""
CONTROL_VERSION=""
PUBLIC_CERT_FILE=""
PUBLIC_KEY_FILE=""
API_KEY_PEPPER_BASE64=""
DNS_CREDENTIAL_KEY_BASE64=""
ACCESS_TOKEN_SECRET=""
IMPERSONATION_HMAC_KEY_BASE64=""
OPENRESTY_SECURITY_SECRET_KEY_BASE64=""
OBSERVABILITY_LOG_CURSOR_KEY_BASE64=""
ANNOUNCEMENT_CURSOR_KEY_BASE64=""
JOB_QUERY_CURSOR_KEY_BASE64=""
CNAME_ALLOCATION_HMAC_KEY_BASE64=""
PUBLIC_CERT_PATH=""
PUBLIC_KEY_PATH=""
NATS_TELEMETRY_URL=""
SKIP_DEPENDENCIES=false
SKIP_FIREWALL=false
# all = control plane + local Gateway; control = the same plus ControlInternal/
# Redis/NATS opened to bound standalone Gateways (ADR 0013 §3.1/§3.3; the local
# Gateway stays because the native upgrade runner and backup freeze manage
# cdnca-agent-gateway.service); gateway = only a standalone Gateway bound
# with a one-time token.
INSTALL_MODE=all
# Remote Gateway access (control mode, GW-09). Loopback consumers keep
# 127.0.0.1:4222/6379; Gateways use these TLS listeners, reachable only from
# bound Gateway addresses (nftables set fed by control-api's allow list).
readonly CONTROL_INTERNAL_REMOTE_PORT=9446
readonly NATS_GATEWAY_WS_PORT=4223
readonly REDIS_GATEWAY_TLS_PORT=6380
readonly GATEWAY_ACCESS_FILE="${DATA_DIR}/gateway-access/allowed-ips"
REDIS_DEFAULT_PASSWORD=""
REDIS_GATEWAY_PASSWORD=""
ASSUME_YES=false
# 安装环境：auto 探测宝塔（/www/server/panel 或 bt 命令），bt 与宝塔共存，
# plain 独占本机。宝塔模式不动宝塔的 nginx/MySQL/面板端口：管理端网页只监听
# 127.0.0.1:WEB_PORT，由宝塔站点反向代理；被占的依赖端口换成空闲替代端口。
INSTALL_ENV=auto
BT_ROOT=""
BT_VERSION=""
BT_PANEL_PORT=""
BT_PROXY=false
BT_PORT_CHANGES=()
WEB_PORT=""
WEB_LISTEN=""
# 宝塔模式节点升级下载直连端口：我方 nginx 用主控自带 CA 签发的证书直接提供升级制品，
# 节点已信任该 CA，不依赖宝塔站点证书是否受信。普通模式为空（升级下载走 MASTER_PORT）。
NODE_DOWNLOAD_PORT=""
WEB_REAL_IP=""
PG_PORT=5432
REDIS_PORT=6379
CH_HTTP_PORT=8123
CH_TCP_PORT=9000
CH_MYSQL_PORT=9004
CH_POSTGRESQL_PORT=9005
CH_INTERSERVER_PORT=9009

log() { printf '[cdnca-control] %s\n' "$*"; }
warn() { printf '[cdnca-control] warning: %s\n' "$*" >&2; }
fail() { printf '[cdnca-control] error: %s\n' "$*" >&2; exit 1; }
# 安装进度阶段（名称|最短秒|最长秒|标记），与 main 里的 progress_stage 一一对应。
PROGRESS_LABEL='[cdnca-control]'
PROGRESS_ROLE=control
PROGRESS_STAGES=(
  '环境预检并填写管理端地址|10|120|interactive'
  '安装基础工具|20|180|'
  '确认激活凭据与管理员账号|0|90|interactive'
  '下载并校验安装包|30|300|'
  '安装依赖（PostgreSQL、ClickHouse、Redis、ClamAV、RustFS）|180|600|'
  '生成主控身份与证书|20|150|'
  '下载节点安装包与组件|20|180|'
  '初始化数据库与消息服务|30|180|'
  '初始化社区版|5|60|'
  '初始化管理端数据|20|120|'
  '启动服务并自检|30|180|'
  '整理安装结果|2|15|'
)

usage() {
  cat <<'EOF'
CDNCA 管理端整包安装器（x86_64；Ubuntu 24.04 正式支持，Ubuntu 22.04、Debian 12/13、Rocky/AlmaLinux/RHEL 9/10 兼容支持；全新单主控）

用法: install-control.sh [选项]
  --release-server URL            社区版发布站 HTTPS 地址（下载整包、节点包、运行时归档；也可全部用本地文件）
  --release-server-fallback URL    发布站备用 HTTPS 地址
  --master-host HOST               管理端公网域名或 IP；未传入时交互填写
  --master-port PORT               管理端 HTTPS 端口；默认 443
  --domain HOST                    管理端域名；默认使用 --master-host
  --mode all|control|gateway       all（默认）主控+本机网关；control 同 all 并对独立网关开放内部端口；gateway 只装网关
  --gateway-host HOST              节点连接用的 Gateway 地址；默认同管理端地址，仅分离部署时需要
  --gateway-ports 注册,通道         Gateway 两个端口，1024–65535；不填则在 20000–29999 随机选两个空闲端口，安装完成时告知
  --env auto|bt|plain              安装环境；auto（默认）检测到宝塔面板（/www/server/panel 或 bt 命令）即按宝塔环境安装
                                   宝塔环境：不动宝塔的 nginx/MySQL/面板，管理端网页只监听 127.0.0.1，由宝塔站点反向代理；
                                   PostgreSQL/Redis/ClickHouse 默认端口被占时自动换端口
  --web-port PORT                  仅宝塔环境：管理端网页的本机回环端口，默认 18443（被占顺延）
  --bt-proxy                       仅宝塔环境：安装完成后自动把反向代理写入宝塔站点（先备份，nginx -t 失败即恢复）
  --server-cert FILE / --server-key FILE  仅 --mode gateway：网关套 CDN 且 CDN 回源校验源站证书时用的公网证书链与私钥（只用于 WebSocket 隧道外层 TLS）；不给则用主控根 CA 签发的证书
  --installation-name NAME         安装实例名称
  --admin-username USER            首个管理员用户名；未传入时交互填写
  --admin-email EMAIL              首个管理员邮箱
  --certificate-email EMAIL        证书申请联系邮箱；未传入时交互填写
  --admin-password-file FILE       从 root 私有文件读取管理员密码
  --public-cert-file FILE          公网 HTTPS 证书（与私钥配对）
  --public-key-file FILE           公网 HTTPS 证书私钥
  --control-version VERSION        必须与签名整包及编译版本一致
  --native-package-url URL         签名完整安装包地址
  --native-package-fallback-url URL
  --native-sha256-url URL          安装包 SHA256SUMS 地址
  --native-sha256-fallback-url URL
  --native-trust-url URL           独立发布公钥清单地址
  --native-trust-fallback-url URL
  --native-package-file FILE       使用 SSH 私下上传的整包（不读取公开下载）
  --native-trust-file FILE         配对的独立、root 所有的发布公钥文件
  --trusted-keys-url URL           授权签名公钥清单地址
  --trusted-keys-fallback-url URL
  --signer-revocation-offline-root-key-id ID
                                   签名密钥泄露吊销：离线根公钥 ID（三项齐全才启用主控吊销判定）
  --signer-revocation-offline-root-generation N
  --signer-revocation-offline-root-public-key BASE64URL
                                   离线根 Ed25519 公钥（32 字节，无填充 base64url）
  --edge-agent-url URL             同一发布版本的签名节点包地址
  --edge-agent-fallback-url URL
  --edge-agent-sha256-url URL
  --edge-agent-sha256-fallback-url URL
  --edge-artifact-trust-url URL    节点发布公钥清单地址
  --edge-artifact-trust-fallback-url URL
  --database-url URL              已准备的 PostgreSQL 数据库；默认本机
  --redis-url URL                 已准备的 Redis；默认本机
  --nats-url URL                  本机固定 nats://127.0.0.1:4222
  --telemetry-nats-url URL        必须与本机 NATS 相同
  --skip-dependencies             不安装依赖，但仍必须通过完整依赖预检
  --skip-firewall                 不修改防火墙（默认也只提示需开放端口）
  --keep-unattended-upgrades      保留系统自动更新（默认停用 apt-daily/apt-daily-upgrade/unattended-upgrades，软件包保留可手动升级）
  --ssh-guard-ignoreip "A B"     fail2ban 不封禁的地址/CIDR（运维出口与本平台各机器，空格或逗号分隔）
  --no-ssh-guard                  不安装 fail2ban SSH 防爆破
  -y, --yes                       安装前检测只有“警告”时不再询问，直接继续
  -h, --help                      显示帮助
清理半途失败的全新安装：install-control.sh --cleanup-failed [--yes]
  只删除本次安装创建的目录、systemd 单元、cdnca 数据库/角色与 ClickHouse 库/用户、RustFS 账户与证书，并停止、停用本次安装
  启动的 PostgreSQL/Redis/ClickHouse 服务以释放端口；依赖没装完时还卸载本次装上的依赖软件包并删其数据目录。列出清单并要求
  输入 CLEANUP 确认，只在安装记录 /var/lib/cdnca-control-install/state 存在且未完成时可用；安装前已有的软件包、服务与路径、
  证书与日志保留。清理后用原命令重装。
迁移主控到本机（全新系统）：install-control.sh migrate-from root@旧主控 [--ssh-port 22] [--wait-nodes 10m]
已安装的主控开启独立网关接入（在主控机上执行，可重复执行，失败自动恢复）：install-control.sh enable-gateway-access [--domain 主控域名]
旧的独立 API、Gateway、Web 和节点脚本地址参数已停止使用，以防混版。
EOF
}
need_value() { [ "$#" -ge 2 ] && [ -n "${2:-}" ] || fail "missing value for $1"; }
valid_url() { case "$1" in https://*|http://*) return 0 ;; *) return 1 ;; esac; }
valid_https_url() { case "$1" in https://*) return 0 ;; *) return 1 ;; esac; }
valid_nats_url() { case "$1" in nats://*|tls://*) return 0 ;; *) return 1 ;; esac; }
valid_redis_url() { case "$1" in redis://*|rediss://*) return 0 ;; *) return 1 ;; esac; }
valid_host() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$ ]]; }
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
no_newlines() { [[ "$1" != *$'\n'* && "$1" != *$'\r'* ]]; }

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --release-server|--licensing-server) need_value "$@"; LICENSING_SERVER=$2; shift 2 ;;
      --release-server-fallback|--licensing-server-fallback) need_value "$@"; LICENSING_SERVER_FALLBACK=$2; shift 2 ;;
      --master-host) need_value "$@"; MASTER_HOST=$2; shift 2 ;;
      --master-port) need_value "$@"; MASTER_PORT=$2; shift 2 ;;
      --domain) need_value "$@"; CONTROL_DOMAIN=$2; shift 2 ;;
      --mode) need_value "$@"; INSTALL_MODE=$2; shift 2 ;;
      --gateway-host) need_value "$@"; GATEWAY_HOST=$2; shift 2 ;;
      --gateway-ports) need_value "$@"; GATEWAY_PORTS=$2; shift 2 ;;
      --env) need_value "$@"; INSTALL_ENV=$2; shift 2 ;;
      --web-port) need_value "$@"; WEB_PORT=$2; shift 2 ;;
      --bt-proxy) BT_PROXY=true; shift ;;
      --native-package-url) need_value "$@"; CONTROL_NATIVE_URL=$2; shift 2 ;;
      --native-package-fallback-url) need_value "$@"; CONTROL_NATIVE_FALLBACK_URL=$2; shift 2 ;;
      --native-sha256-url) need_value "$@"; CONTROL_NATIVE_SHA256_URL=$2; shift 2 ;;
      --native-sha256-fallback-url) need_value "$@"; CONTROL_NATIVE_SHA256_FALLBACK_URL=$2; shift 2 ;;
      --native-trust-url) need_value "$@"; CONTROL_NATIVE_TRUST_URL=$2; shift 2 ;;
      --native-trust-fallback-url) need_value "$@"; CONTROL_NATIVE_TRUST_FALLBACK_URL=$2; shift 2 ;;
      --native-package-file) need_value "$@"; CONTROL_NATIVE_FILE=$2; shift 2 ;;
      --native-trust-file) need_value "$@"; CONTROL_NATIVE_TRUST_FILE=$2; shift 2 ;;
      --trusted-keys-url) need_value "$@"; TRUSTED_KEYS_URL=$2; shift 2 ;;
      --trusted-keys-fallback-url) need_value "$@"; TRUSTED_KEYS_FALLBACK_URL=$2; shift 2 ;;
      --signer-revocation-offline-root-key-id) need_value "$@"; SIGNER_REVOCATION_OFFLINE_ROOT_KEY_ID=$2; shift 2 ;;
      --signer-revocation-offline-root-generation) need_value "$@"; SIGNER_REVOCATION_OFFLINE_ROOT_GENERATION=$2; shift 2 ;;
      --signer-revocation-offline-root-public-key) need_value "$@"; SIGNER_REVOCATION_OFFLINE_ROOT_PUBLIC_KEY=$2; shift 2 ;;
      --edge-agent-url) need_value "$@"; EDGE_AGENT_URL=$2; shift 2 ;;
      --edge-agent-fallback-url) need_value "$@"; EDGE_AGENT_FALLBACK_URL=$2; shift 2 ;;
      --edge-agent-sha256-url) need_value "$@"; EDGE_AGENT_SHA256_URL=$2; shift 2 ;;
      --edge-agent-sha256-fallback-url) need_value "$@"; EDGE_AGENT_SHA256_FALLBACK_URL=$2; shift 2 ;;
      --edge-artifact-trust-url) need_value "$@"; EDGE_ARTIFACT_TRUST_URL=$2; shift 2 ;;
      --edge-artifact-trust-fallback-url) need_value "$@"; EDGE_ARTIFACT_TRUST_FALLBACK_URL=$2; shift 2 ;;
      --control-version) need_value "$@"; CONTROL_VERSION=$2; shift 2 ;;
      --public-cert-file) need_value "$@"; PUBLIC_CERT_FILE=$2; shift 2 ;;
      --public-key-file) need_value "$@"; PUBLIC_KEY_FILE=$2; shift 2 ;;
      --database-url) need_value "$@"; DATABASE_URL=$2; shift 2 ;;
      --redis-url) need_value "$@"; REDIS_URL=$2; REDIS_LOCAL=false; shift 2 ;;
      --nats-url) need_value "$@"; NATS_URL=$2; shift 2 ;;
      --telemetry-nats-url) need_value "$@"; NATS_TELEMETRY_URL=$2; shift 2 ;;
      --installation-name) need_value "$@"; INSTALLATION_NAME=$2; shift 2 ;;
      --admin-username) need_value "$@"; ADMIN_USERNAME=$2; shift 2 ;;
      --admin-email) need_value "$@"; ADMIN_EMAIL=$2; shift 2 ;;
      --certificate-email) need_value "$@"; CERTIFICATE_EMAIL=$2; shift 2 ;;
      --admin-password-file) need_value "$@"; ADMIN_PASSWORD_FILE=$2; shift 2 ;;
      --skip-dependencies) SKIP_DEPENDENCIES=true; shift ;;
      --skip-firewall) SKIP_FIREWALL=true; shift ;;
      --keep-unattended-upgrades) KEEP_UNATTENDED_UPGRADES=true; shift ;;
      --ssh-guard-ignoreip) need_value "$@"; SSH_GUARD_IGNOREIP=$2; shift 2 ;;
      --no-ssh-guard) SSH_GUARD_ENABLED=false; shift ;;
      -y|--yes) ASSUME_YES=true; shift ;;
      -h|--help) usage; exit 0 ;;
      *) fail "unsupported option: $1; use the signed full-package options shown in --help" ;;
    esac
  done
}
require_commands() {
  local command
  for command in curl jq openssl sha256sum xxd uuidgen systemctl file tar unzip awk grep sed stat base64 python3 git flock ss timeout; do
    command -v "$command" >/dev/null 2>&1 || return 1
  done
}
assert_fresh_installation() {
  local path
  if [ -e "$CONTROL_INSTALL_STATE_DIR" ] || [ -L "$CONTROL_INSTALL_STATE_DIR" ]; then
    control_install_failed_hint
    fail 'a previous control installation on this host did not finish; run install-control.sh --cleanup-failed first'
  fi
  for path in "$CONFIG_DIR" "$DATA_DIR" "$INSTALL_ROOT" "$NATIVE_ROOT" /etc/cdnca-upgrade \
    /var/lib/cdnca-upgrade /run/cdnca-upgrade /var/lib/cdnca-native-upgrade-maintenance; do
    [ ! -e "$path" ] && [ ! -L "$path" ] ||
      fail 'existing control installation state found; use the upgrade or recovery procedure, do not rerun the fresh installer'
  done
}


# 安装记录（AUDIT-1029 ①-12）。主控安装不能续装：签名辅助脚本（基线、ClickHouse、RustFS、
# 运行时密钥）只允许全新安装，身份密钥、数据库口令与运行时密钥每次重新生成。
# 所以半途失败的主控用 --cleanup-failed 清掉“本次安装创建的东西”后重装。记录在空机门禁通过后
# 立即建立，写下当时已存在的候选路径（preexisting=，清理时不动）与之后创建的库（created=）。
readonly CONTROL_INSTALL_STATE_DIR=/var/lib/cdnca-control-install
readonly CONTROL_INSTALL_STATE_FILE="${CONTROL_INSTALL_STATE_DIR}/state"
readonly CONTROL_INSTALL_STATE_SCHEMA=schema=cdnca.control-install-state/v1
readonly CONTROL_INSTALL_UNITS=(cdnca-control-backup.timer cdnca-control-backup.path cdnca-gateway-access.path
  cdnca-control-backup.service cdnca-control-frozen-console.service cdnca-native-control-upgrade-runner.service
  cdnca-control-web.service cdnca-agent-gateway.service cdnca-control-api.service cdnca-control-nats.service
  cdnca-objectstore.service cdnca-gateway-access.service cdnca-gateway-access-reload.service
  cdnca-community-identity-refresh.timer cdnca-community-identity-refresh.service)
readonly CONTROL_INSTALL_ACCOUNT=cdnca-objectstore
readonly CONTROL_INSTALL_REDIS_CONFIGS=(/etc/redis/redis.conf /etc/redis.conf /etc/valkey/valkey.conf)
# 本安装器可能装上并启动的依赖服务（Debian/EL 各单元名，见 install-ubuntu-dependencies.sh）。记录时
# 未加载（not-found）的写 service-absent=；已加载但未运行且未启用的写 service-inactive=（多为上次 --cleanup-failed
# 停用的，本次安装会重新启用）；其余已加载的写 preexisting=service:；systemctl 不可用则不写（清理时列为人工处理）。
readonly CONTROL_INSTALL_DEPENDENCY_UNITS=(postgresql.service postgresql@17-main.service postgresql-17.service
  redis-server.service redis.service valkey.service clickhouse-server.service)

# 本安装器（及其签名辅助脚本）会创建的、只属于主控的路径（社区版身份与签名公钥在 CONFIG_DIR 下：
# community/、entitlement-trusted-keys.json）。系统依赖包（PostgreSQL、ClickHouse、Redis、nginx、ClamAV）
# 及其配置见 control_install_dependency_paths/control_install_dependency_data_paths；Let's Encrypt 证书、
# 安装日志、fail2ban 规则不在此列。
control_install_owned_paths() {
  local unit config
  printf '%s\n' "$CONFIG_DIR" "$DATA_DIR" "$INSTALL_ROOT" "$NATIVE_ROOT" "$(dirname "$NATIVE_ROOT")" /etc/cdnca-upgrade /var/lib/cdnca-upgrade \
    /run/cdnca-upgrade /var/lib/cdnca-native-upgrade-maintenance /var/lib/cdnca-control-backup /etc/cdnca-analytics \
    /etc/cdnca-objectstore /var/lib/cdnca-objectstore /var/lib/cdnca-objectstore-logs /var/lib/cdnca-objectstore-credentials \
    /usr/local/lib/cdnca-runtime /usr/local/libexec/cdnca "$NATS_SERVER_BIN" "$NATS_CLI_BIN" \
    /etc/cdnca-native-dependencies/runtime.env /etc/clickhouse-server/users.d/cdnca-private-default.xml \
    /usr/local/share/ca-certificates/cdnca-objectstore.crt /etc/ssl/certs/cdnca-objectstore.pem \
    /etc/pki/ca-trust/source/anchors/cdnca-objectstore.crt /etc/letsencrypt/renewal-hooks/deploy/cdnca-control-web.sh \
    /etc/tmpfiles.d/cdnca-native-control-upgrade-runner.conf
  for config in "${CONTROL_INSTALL_REDIS_CONFIGS[@]}"; do printf '%s/cdnca-gateway\n' "$(dirname "$config")"; done
  for unit in "${CONTROL_INSTALL_UNITS[@]}"; do printf '/etc/systemd/system/%s\n/etc/systemd/system/%s.d\n' "$unit" "$unit"; done
}

# 依赖 helper（install-ubuntu-dependencies.sh）在装包前写的文件：ClamAV socket drop-in、软件源与密钥、ClickHouse
# 回环配置。依赖没装完就失败时，重跑走 helper 全新分支并拒绝它们（existing_state_requires_review）；依赖已装完时
# helper 已装分支要用它们。所以清理只在依赖未装完（记录无 step=dependencies_ready）时删本次写的（安装前已有的写
# preexisting=，不动）。
control_install_dependency_paths() {
  printf '%s\n' /etc/systemd/system/clamav-daemon.socket.d/zz-cdnca-mode.conf /etc/clickhouse-server/config.d/cdnca-loopback.xml \
    /usr/share/keyrings/cdnca-pgdg.asc /usr/share/keyrings/cdnca-clickhouse.asc \
    /etc/apt/sources.list.d/cdnca-pgdg.sources /etc/apt/sources.list.d/cdnca-clickhouse.list \
    /etc/pki/rpm-gpg/CDNCA-PGDG-RPM-GPG-KEY-RHEL /etc/pki/rpm-gpg/CDNCA-CLICKHOUSE-RPM-GPG-KEY \
    /etc/pki/rpm-gpg/CDNCA-RPM-GPG-KEY-EPEL-8 /etc/pki/rpm-gpg/CDNCA-RPM-GPG-KEY-EPEL-9 /etc/pki/rpm-gpg/CDNCA-RPM-GPG-KEY-EPEL-10 \
    /etc/yum.repos.d/cdnca-pgdg17.repo /etc/yum.repos.d/cdnca-clickhouse.repo /etc/yum.repos.d/cdnca-epel.repo
}
# 依赖 helper 跑完并通过就绪检查后，记录写 step=dependencies_ready（configure_runtime_dependencies）。
control_dependency_packages_installed() { control_install_state_has step=dependencies_ready; }

# 依赖 helper 与 ssh_guard_setup 装上的软件包的数据/配置目录（helper 全新分支的 DEPS_PROTECTED_PATHS、
# DEPS_NGINX_GUARDS 与便携 PostgreSQL/ClamAV 路径）。残留时重跑被拒（existing_state_requires_review /
# incompatible_package_profile / existing_nginx_requires_review）。清理在卸载本次装上的软件包（记录时未安装，
# package-absent=）时一并删掉本次产生的这些目录；记录时已存在的写 preexisting=，不动。fail2ban 在记录前由
# ssh_guard_setup 装上，按 main 预先取的 path-absent=/package-absent= 判定。
control_install_dependency_data_paths() {
  printf '%s\n' /var/lib/postgresql /etc/postgresql /etc/postgresql-common /var/lib/pgsql /var/lib/clickhouse /etc/clickhouse-server \
    /etc/clamav /var/lib/clamav /etc/clamd.d /etc/redis /var/lib/redis /etc/valkey /var/lib/valkey \
    /etc/nginx /etc/systemd/system/nginx.service /etc/systemd/system/nginx.service.d \
    /opt/cdnca-postgresql-17 /var/lib/cdnca-postgresql /etc/systemd/system/postgresql-17.service \
    /opt/cdnca-clamav-1.4 /var/lib/cdnca-clamav /etc/systemd/system/clamav-daemon.service /etc/systemd/system/clamav-freshclam.service \
    /etc/fail2ban
}
# Debian 与 EL 的依赖包名（含 fail2ban）；不存在的包名查询无害。
readonly CONTROL_INSTALL_DEPENDENCY_PACKAGES=(redis-server redis-tools postgresql-17 postgresql-client-17 postgresql-common
  postgresql-client-common clickhouse-server clickhouse-client clickhouse-common-static clamav clamav-base clamav-daemon
  clamav-freshclam nginx nginx-common fail2ban redis valkey postgresql17-server postgresql17 postgresql17-libs clamd
  clamav-lib clamav-filesystem fail2ban-server)
# 0：软件包在本机（含半装、只剩配置文件）；1：未安装；2：无法判定（无 dpkg-query/rpm）。
control_package_present() {
  local status
  if command -v dpkg-query >/dev/null 2>&1; then
    status=$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null) || return 1
    [ -n "$status" ] && [ "$status" != not-installed ]
  elif command -v rpm >/dev/null 2>&1; then
    rpm -q --quiet "$1" 2>/dev/null
  else
    return 2
  fi
}
# 安装前未安装的依赖包（package-absent=）与不存在的 /etc/fail2ban（path-absent=）；在 ssh_guard_setup（装 fail2ban）
# 之前由 main 取一次，记录时写入。无法判定软件包时不写软件包（清理时不卸载任何包）。
control_install_absent_packages() {
  local name status
  [ -e /etc/fail2ban ] || [ -L /etc/fail2ban ] || printf 'path-absent=/etc/fail2ban\n'
  for name in "${CONTROL_INSTALL_DEPENDENCY_PACKAGES[@]}"; do
    status=0
    control_package_present "$name" || status=$?
    [ "$status" -ne 2 ] || return 0
    [ "$status" -eq 0 ] || printf 'package-absent=%s\n' "$name"
  done
}
CONTROL_INSTALL_ABSENT_PACKAGES=unset
control_install_state_prepare() { CONTROL_INSTALL_ABSENT_PACKAGES=$(control_install_absent_packages); }

control_install_state_begin() {
  local path
  mkdir -m 0700 "$CONTROL_INSTALL_STATE_DIR"
  (set -o noclobber; printf '%s\n' "$CONTROL_INSTALL_STATE_SCHEMA" >"$CONTROL_INSTALL_STATE_FILE")
  chmod 0600 "$CONTROL_INSTALL_STATE_FILE"
  [ "$CONTROL_INSTALL_ABSENT_PACKAGES" != unset ] || CONTROL_INSTALL_ABSENT_PACKAGES=$(control_install_absent_packages)
  while IFS= read -r path; do
    [ -z "$path" ] || control_install_state_add "$path"
  done <<<"$CONTROL_INSTALL_ABSENT_PACKAGES"
  while IFS= read -r path; do
    control_install_state_has "path-absent=$path" && continue
    if [ -e "$path" ] || [ -L "$path" ]; then control_install_state_add "preexisting=$path"; fi
  done < <(control_install_owned_paths; control_install_dependency_paths; control_install_dependency_data_paths)
  if getent passwd "$CONTROL_INSTALL_ACCOUNT" >/dev/null 2>&1 || getent group "$CONTROL_INSTALL_ACCOUNT" >/dev/null 2>&1; then
    control_install_state_add "preexisting=account:$CONTROL_INSTALL_ACCOUNT"
  fi
  if command -v nft >/dev/null 2>&1 && nft list table inet cdnca_gateway_access >/dev/null 2>&1; then
    control_install_state_add preexisting=nft:cdnca_gateway_access
  fi
  local unit load
  for unit in "${CONTROL_INSTALL_DEPENDENCY_UNITS[@]}"; do
    load=$(systemctl show -p LoadState --value "$unit" 2>/dev/null) || continue
    case "$load" in
      not-found) control_install_state_add "service-absent=$unit" ;;
      '') ;;
      *)
        if ! systemctl is-active --quiet "$unit" && ! systemctl is-enabled --quiet "$unit" 2>/dev/null; then
          control_install_state_add "service-inactive=$unit"
        else
          control_install_state_add "preexisting=service:$unit"
        fi ;;
    esac
  done
}
control_install_state_add() { [ ! -f "$CONTROL_INSTALL_STATE_FILE" ] || printf '%s\n' "$1" >>"$CONTROL_INSTALL_STATE_FILE"; }
control_install_state_done() { control_install_state_add step=done; }
control_install_state_has() { grep -Fxq -- "$1" "$CONTROL_INSTALL_STATE_FILE" 2>/dev/null; }

control_install_failed_hint() {
  [ -f "$CONTROL_INSTALL_STATE_FILE" ] && ! control_install_state_has step=done || return 0
  warn "安装未完成（记录 ${CONTROL_INSTALL_STATE_FILE}）：主控安装不支持续装。修复失败原因后，先执行 install-control.sh --cleanup-failed 清理本次安装创建的目录、服务与数据库（会列出清单并要求确认），再重新执行原安装命令"
}

CLEANUP_PATHS=()
CLEANUP_DEPENDENCY_PATHS=()
CLEANUP_DEPENDENCY_DATA=()
CLEANUP_PACKAGES=()
CLEANUP_HASH_LINKS=()
CLEANUP_UNITS=()
CLEANUP_REDIS_INCLUDES=()
CLEANUP_PG=''
CLEANUP_CH=''
CLEANUP_ACCOUNT=false
CLEANUP_NFT=false
CLEANUP_SERVICES=()
CLEANUP_SERVICES_MANUAL=()

# 只读：按安装记录算出要删的东西。记录里 preexisting= 的路径与账户不动；系统依赖不动。
cleanup_failed_plan() {
  local path unit config include value
  while IFS= read -r path; do
    control_install_state_has "preexisting=$path" && continue
    [ -e "$path" ] || [ -L "$path" ] || continue
    CLEANUP_PATHS+=("$path")
  done < <(control_install_owned_paths)
  # 依赖没装完（记录无 step=dependencies_ready）：重跑走 helper 全新分支，本次装上的依赖软件包（记录时未安装，
  # package-absent=）、它们的数据/配置目录与 helper 装包前写的文件都会被拒，一并卸载、删除；本机恢复到安装前，
  # 重装时重新安装。依赖已装完：全部保留，重装走 helper 已装分支（它要求软件源、回环配置与 drop-in 原样存在）。
  if ! control_dependency_packages_installed; then
    for value in "${CONTROL_INSTALL_DEPENDENCY_PACKAGES[@]}"; do
      control_install_state_has "package-absent=$value" || continue
      control_package_present "$value" || continue
      CLEANUP_PACKAGES+=("$value")
    done
    while IFS= read -r path; do
      control_install_state_has "preexisting=$path" && continue
      [ -e "$path" ] || [ -L "$path" ] || continue
      CLEANUP_DEPENDENCY_PATHS+=("$path")
    done < <(control_install_dependency_paths)
    while IFS= read -r path; do
      control_install_state_has "preexisting=$path" && continue
      [ -e "$path" ] || [ -L "$path" ] || continue
      CLEANUP_DEPENDENCY_DATA+=("$path")
    done < <(control_install_dependency_data_paths)
  fi
  # RustFS CA 的 openssl 哈希链接（/etc/ssl/certs/<hash>.N → cdnca-objectstore.pem/.crt）随证书一起删。
  if ! control_install_state_has preexisting=/etc/ssl/certs/cdnca-objectstore.pem; then
    for path in /etc/ssl/certs/*; do
      [ -L "$path" ] && [[ "$(basename "$path")" =~ ^[0-9a-f]{8}\.[0-9]+$ ]] || continue
      case "$(basename "$(readlink "$path")")" in cdnca-objectstore.pem|cdnca-objectstore.crt) CLEANUP_HASH_LINKS+=("$path") ;; esac
    done
  fi
  for unit in "${CONTROL_INSTALL_UNITS[@]}"; do
    control_install_state_has "preexisting=/etc/systemd/system/$unit" && continue
    [ -e "/etc/systemd/system/$unit" ] || [ -L "/etc/systemd/system/$unit" ] || continue
    CLEANUP_UNITS+=("$unit")
  done
  for config in "${CONTROL_INSTALL_REDIS_CONFIGS[@]}"; do
    include="$(dirname "$config")/cdnca-gateway/redis-gateway.conf"
    control_install_state_has "preexisting=$(dirname "$include")" && continue
    [ -f "$config" ] && grep -Fxq "include $include" "$config" && CLEANUP_REDIS_INCLUDES+=("$config")
  done
  value=$(sed -n 's/^created=postgresql://p' "$CONTROL_INSTALL_STATE_FILE" | tail -n 1)
  [[ "$value" =~ ^[0-9]{1,5}$ ]] && CLEANUP_PG=$value
  value=$(sed -n 's/^created=clickhouse://p' "$CONTROL_INSTALL_STATE_FILE" | tail -n 1)
  [[ "$value" =~ ^[0-9]{1,5}$ ]] && CLEANUP_CH=$value
  if ! control_install_state_has "preexisting=account:$CONTROL_INSTALL_ACCOUNT" &&
    { getent passwd "$CONTROL_INSTALL_ACCOUNT" >/dev/null 2>&1 || getent group "$CONTROL_INSTALL_ACCOUNT" >/dev/null 2>&1; }; then
    CLEANUP_ACCOUNT=true
  fi
  if ! control_install_state_has preexisting=nft:cdnca_gateway_access && command -v nft >/dev/null 2>&1 &&
    nft list table inet cdnca_gateway_access >/dev/null 2>&1; then
    CLEANUP_NFT=true
  fi
  # 依赖服务：只停用记录时未加载或未运行未启用、现在运行或启用的（本次安装装上或启用）；按真实单元名（Id）去重，
  # 别名（Debian 的 redis.service → redis-server.service）不单独操作。记录里没有结论的列为人工处理。
  local load id
  for unit in "${CONTROL_INSTALL_DEPENDENCY_UNITS[@]}"; do
    control_install_state_has "preexisting=service:$unit" && continue
    load=$(systemctl show -p LoadState --value "$unit" 2>/dev/null) || load=''
    [ "$load" = loaded ] || continue
    systemctl is-active --quiet "$unit" || systemctl is-enabled --quiet "$unit" 2>/dev/null || continue
    if ! control_install_state_has "service-absent=$unit" && ! control_install_state_has "service-inactive=$unit"; then
      [[ " ${CLEANUP_SERVICES_MANUAL[*]-} " == *" $unit "* ]] || CLEANUP_SERVICES_MANUAL+=("$unit")
      continue
    fi
    id=$(systemctl show -p Id --value "$unit" 2>/dev/null) || id=''
    [[ "$id" =~ ^[A-Za-z0-9@._-]+\.service$ ]] || id=$unit
    [[ " ${CLEANUP_SERVICES[*]-} " == *" $id "* ]] || CLEANUP_SERVICES+=("$id")
  done
  return 0
}

cleanup_failed_report() {
  local item
  printf '[cdnca-control] 将删除本次未完成安装创建的以下内容（安装记录 %s）：\n' "$CONTROL_INSTALL_STATE_FILE" >&2
  for item in "${CLEANUP_UNITS[@]}"; do printf '  systemd 单元（停止、停用、删除）：%s\n' "$item" >&2; done
  for item in "${CLEANUP_PATHS[@]}"; do printf '  路径：%s\n' "$item" >&2; done
  for item in ${CLEANUP_DEPENDENCY_PATHS[@]+"${CLEANUP_DEPENDENCY_PATHS[@]}"}; do
    printf '  依赖安装写下的文件（依赖未装完，重装时会被拒）：%s\n' "$item" >&2
  done
  for item in ${CLEANUP_HASH_LINKS[@]+"${CLEANUP_HASH_LINKS[@]}"}; do printf '  RustFS 证书哈希链接：%s\n' "$item" >&2; done
  for item in ${CLEANUP_PACKAGES[@]+"${CLEANUP_PACKAGES[@]}"}; do
    printf '  依赖软件包（本次安装装上、依赖未装完；卸载并清除配置，重装时重新安装）：%s\n' "$item" >&2
  done
  for item in ${CLEANUP_DEPENDENCY_DATA[@]+"${CLEANUP_DEPENDENCY_DATA[@]}"}; do
    printf '  依赖数据/配置目录（本次安装产生、依赖未装完，重装时会被拒）：%s\n' "$item" >&2
  done
  for item in "${CLEANUP_REDIS_INCLUDES[@]}"; do printf '  Redis 配置中本安装追加的 include 行：%s\n' "$item" >&2; done
  [ -z "$CLEANUP_PG" ] || printf '  PostgreSQL（端口 %s）：数据库 cdnca 与角色 cdnca、cdnca_control_app、cdnca_plugin_webhook_runtime、cdnca_control_runtime、cdnca_retention_cleanup\n' "$CLEANUP_PG" >&2
  [ -z "$CLEANUP_CH" ] || printf '  ClickHouse（端口 %s）：数据库 cdnca_analytics 与用户 cdnca_analytics_query、cdnca_analytics_ingest、cdnca_analytics_rollup\n' "$CLEANUP_CH" >&2
  ! "$CLEANUP_ACCOUNT" || printf '  系统账户：%s\n' "$CONTROL_INSTALL_ACCOUNT" >&2
  ! "$CLEANUP_NFT" || printf '  nftables 表：inet cdnca_gateway_access\n' >&2
  for item in ${CLEANUP_SERVICES[@]+"${CLEANUP_SERVICES[@]}"}; do
    printf '  依赖服务（本次安装装上并启动；停止并停用以释放端口，软件包与数据目录保留）：%s\n' "$item" >&2
  done
  printf '  安装记录：%s\n' "$CONTROL_INSTALL_STATE_DIR" >&2
  printf '[cdnca-control] 保留：安装前已存在的软件包、服务与路径；依赖已装完时的 PostgreSQL/ClickHouse/Redis/ClamAV/nginx/fail2ban 软件包及其数据目录（重装直接复用）；Let'"'"'s Encrypt 证书、/var/log 下的安装日志。\n' >&2
  for item in ${CLEANUP_SERVICES_MANUAL[@]+"${CLEANUP_SERVICES_MANUAL[@]}"}; do
    printf '[cdnca-control] 无法判定是否由本次安装启动，不动，请人工处理（若占用安装所需端口，重装前自行停止）：%s\n' "$item" >&2
  done
}

cleanup_failed_confirm() {
  local answer
  if [ "$ASSUME_YES" = true ]; then
    printf '[cdnca-control] 已指定 --yes，开始清理。\n' >&2
    return 0
  fi
  { : </dev/tty; } 2>/dev/null || fail 'cleanup needs confirmation: run it on a terminal, or add --yes after reviewing the list above'
  printf '[cdnca-control] 此操作不可撤销。确认删除请输入 CLEANUP：' >&2
  IFS= read -r answer </dev/tty || answer=''
  [ "$answer" = CLEANUP ] || fail 'cleanup cancelled; nothing was changed'
}

cleanup_failed_databases() {
  local -a runner=()
  if [ -n "$CLEANUP_PG" ]; then
    command -v psql >/dev/null 2>&1 || [ ! -x /usr/pgsql-17/bin/psql ] || PATH="$PATH:/usr/pgsql-17/bin"
    if command -v runuser >/dev/null 2>&1; then runner=(runuser -u postgres -- psql -p "$CLEANUP_PG")
    else runner=(sudo -u postgres psql -p "$CLEANUP_PG"); fi
    "${runner[@]}" -X -q -v ON_ERROR_STOP=1 --dbname postgres >/dev/null <<'SQL' || fail 'cannot drop the cdnca PostgreSQL database and roles; is PostgreSQL running?'
DROP DATABASE IF EXISTS cdnca WITH (FORCE);
DROP ROLE IF EXISTS cdnca_control_app;
DROP ROLE IF EXISTS cdnca_plugin_webhook_runtime;
DROP ROLE IF EXISTS cdnca_control_runtime;
DROP ROLE IF EXISTS cdnca_retention_cleanup;
DROP ROLE IF EXISTS cdnca;
SQL
    log 'dropped the cdnca PostgreSQL database and roles'
  fi
  if [ -n "$CLEANUP_CH" ]; then
    local sql='DROP DATABASE IF EXISTS cdnca_analytics SYNC; DROP USER IF EXISTS cdnca_analytics_query, cdnca_analytics_ingest, cdnca_analytics_rollup;'
    local -a client=(clickhouse-client --host 127.0.0.1 --port "$CLEANUP_CH" --multiquery)
    # 初始化做完后 default 用户只认安装生成的私有口令（admin.xml）；更早失败时仍是无口令。
    { [ -f /etc/cdnca-analytics/admin.xml ] && "${client[@]}" --config-file /etc/cdnca-analytics/admin.xml <<<"$sql" >/dev/null 2>&1; } ||
      "${client[@]}" <<<"$sql" >/dev/null ||
      fail 'cannot drop the cdnca_analytics ClickHouse database and users; is ClickHouse running?'
    log 'dropped the cdnca_analytics ClickHouse database and users'
  fi
}

# 依赖没装完时卸载本次装上的依赖包（软件包卸载会先停它们的服务）。失败即停：安装记录保留，可修复后重跑清理。
cleanup_failed_packages() {
  [ "${#CLEANUP_PACKAGES[@]}" -gt 0 ] || return 0
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "${CLEANUP_PACKAGES[@]}" >/dev/null ||
      fail 'cannot purge the dependency packages this install added; fix apt/dpkg and rerun --cleanup-failed'
  elif command -v dnf >/dev/null 2>&1; then
    dnf -y -q remove "${CLEANUP_PACKAGES[@]}" >/dev/null ||
      fail 'cannot remove the dependency packages this install added; fix dnf and rerun --cleanup-failed'
  else
    fail 'no apt-get or dnf to remove the dependency packages this install added'
  fi
  log "removed dependency packages added by this install: ${CLEANUP_PACKAGES[*]}"
}

cleanup_failed_main() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -y|--yes) ASSUME_YES=true; shift ;;
      -h|--help) usage; exit 0 ;;
      *) fail "unsupported --cleanup-failed option: $1" ;;
    esac
  done
  [ "$EUID" -eq 0 ] || fail 'run this installer as root'
  [ -f "$CONTROL_INSTALL_STATE_FILE" ] ||
    fail "no install record ${CONTROL_INSTALL_STATE_FILE}: --cleanup-failed only removes a failed fresh installation made by this installer"
  [ ! -L "$CONTROL_INSTALL_STATE_DIR" ] && [ ! -L "$CONTROL_INSTALL_STATE_FILE" ] &&
    [ "$(stat -c '%u:%h:%a' "$CONTROL_INSTALL_STATE_FILE")" = 0:1:600 ] &&
    [ "$(head -n 1 "$CONTROL_INSTALL_STATE_FILE")" = "$CONTROL_INSTALL_STATE_SCHEMA" ] ||
    fail "unsafe or unknown install record ${CONTROL_INSTALL_STATE_FILE}"
  ! control_install_state_has step=done ||
    fail 'this control installation completed; --cleanup-failed never removes a working control plane (use backup/migrate or a system reinstall)'
  acquire_control_install_lock
  cleanup_failed_run
}

cleanup_failed_run() {
  local unit path config include
  cleanup_failed_plan
  cleanup_failed_report
  cleanup_failed_confirm
  if [ "${#CLEANUP_UNITS[@]}" -gt 0 ]; then
    systemctl disable --now "${CLEANUP_UNITS[@]}" >/dev/null 2>&1 || true
  fi
  # 删库在删 /etc/cdnca-analytics（ClickHouse 管理口令）之前。
  cleanup_failed_databases
  # 删库之后再停本次安装启动的依赖服务，释放端口让原样重装通过预检。
  for unit in ${CLEANUP_SERVICES[@]+"${CLEANUP_SERVICES[@]}"}; do
    systemctl stop "$unit" >/dev/null 2>&1 || true
    systemctl disable "$unit" >/dev/null 2>&1 || true
    ! systemctl is-active --quiet "$unit" || warn "依赖服务 $unit 未能停止，请人工停止后再重装"
  done
  for config in "${CLEANUP_REDIS_INCLUDES[@]}"; do
    include="$(dirname "$config")/cdnca-gateway/redis-gateway.conf"
    grep -Fxv "include $include" "$config" >"$config.cdnca-cleanup" || true
    cat "$config.cdnca-cleanup" >"$config"
    rm -f -- "$config.cdnca-cleanup"
  done
  cleanup_failed_packages
  ! "$CLEANUP_NFT" || nft delete table inet cdnca_gateway_access >/dev/null 2>&1 || true
  for path in ${CLEANUP_HASH_LINKS[@]+"${CLEANUP_HASH_LINKS[@]}"}; do rm -f -- "$path"; done
  for path in "${CLEANUP_PATHS[@]}"; do rm -rf -- "$path"; done
  for path in ${CLEANUP_DEPENDENCY_DATA[@]+"${CLEANUP_DEPENDENCY_DATA[@]}"}; do
    case "$path" in /etc/systemd/system/*.service) systemctl disable --now "$(basename "$path")" >/dev/null 2>&1 || true ;; esac
    rm -rf -- "$path"
  done
  # 便携 PostgreSQL/ClamAV 的工具链接（/usr/bin/psql 等）只在指向已删的便携目录时去掉。
  for path in /usr/bin/psql /usr/bin/pg_dump /usr/bin/pg_restore /usr/bin/pg_dumpall /usr/bin/pg_isready \
    /usr/sbin/clamd /usr/bin/freshclam /usr/bin/clamdscan /usr/bin/clamscan; do
    [ -L "$path" ] && [ ! -e "$path" ] || continue
    case "$(readlink "$path")" in /opt/cdnca-postgresql-17/*|/opt/cdnca-clamav-1.4/*) rm -f -- "$path" ;; esac
  done
  for path in ${CLEANUP_DEPENDENCY_PATHS[@]+"${CLEANUP_DEPENDENCY_PATHS[@]}"}; do
    rm -f -- "$path"
    # helper 新建的空父目录（clamav-daemon.socket.d、clickhouse-server/config.d）一并去掉；非空的不动。
    rmdir -- "$(dirname "$path")" 2>/dev/null || true
    [ "$(basename "$(dirname "$path")")" != config.d ] || rmdir -- "$(dirname "$(dirname "$path")")" 2>/dev/null || true
  done
  if "$CLEANUP_ACCOUNT"; then
    userdel "$CONTROL_INSTALL_ACCOUNT" >/dev/null 2>&1 || true
    ! getent group "$CONTROL_INSTALL_ACCOUNT" >/dev/null 2>&1 || groupdel "$CONTROL_INSTALL_ACCOUNT" >/dev/null 2>&1 || true
  fi
  command -v update-ca-certificates >/dev/null 2>&1 && update-ca-certificates >/dev/null 2>&1 ||
    { command -v update-ca-trust >/dev/null 2>&1 && update-ca-trust extract >/dev/null 2>&1; } || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  for unit in "${CLEANUP_UNITS[@]}"; do systemctl reset-failed "$unit" >/dev/null 2>&1 || true; done
  # 依赖服务在本机安装记录中保留；重启 Redis 让去掉的 include 生效。
  [ "${#CLEANUP_REDIS_INCLUDES[@]}" -eq 0 ] ||
    systemctl try-restart redis-server redis valkey >/dev/null 2>&1 || true
  rm -rf -- "$CONTROL_INSTALL_STATE_DIR"
  log 'failed installation cleaned up; rerun the original install command'
}

acquire_control_install_lock() {
  local lock=/run/lock/cdnca-native-control-install.lock
  if [ ! -e "$lock" ] && [ ! -L "$lock" ]; then
    (set -o noclobber; : >"$lock") || fail 'cannot reserve installation lock'
  fi
  [ -f "$lock" ] && [ ! -L "$lock" ] && [ "$(stat -c '%u:%a:%h' "$lock")" = 0:600:1 ] ||
    fail 'unsafe installation lock'
  exec 8<>"$lock"
  flock -n 8 || fail 'another control installation is running'
}

install_dependencies() {
  [ "$(uname -s):$(uname -m)" = Linux:x86_64 ] || fail 'fresh native installation requires Linux x86_64'
  # The tier table is shared with the preflight report (os-support-matrix.md).
  case "$(preflight_os_tier control "$(preflight_os_release_value ID)" "$(preflight_os_release_value VERSION_ID)")" in
    official|compatible) ;;
    *) fail 'fresh native installation requires Ubuntu 24.04/22.04/20.04, Debian 10-13 or Rocky/AlmaLinux/RHEL 8/9/10 (see docs/install/os-support-matrix.md)' ;;
  esac
  # Only bootstrap tools here. The signed helper owns the complete fixed runtime.
  if [ "$(control_os_family)" = rhel ]; then
    # Minimal EL images ship curl-minimal/coreutils-single; asking for curl or
    # coreutils conflicts, and both already provide every command used here.
    progress_run '安装基础工具' dnf -y -q install jq openssl ca-certificates vim-common util-linux file tar unzip python3 git iproute procps-ng
    return
  fi
  DEBIAN_FRONTEND=noninteractive progress_run '更新软件源' apt-get update -qq
  DEBIAN_FRONTEND=noninteractive progress_run '安装基础工具' apt-get install -y -qq --no-install-recommends \
    curl jq openssl ca-certificates coreutils xxd uuid-runtime file tar unzip python3 git util-linux iproute2
}

# debian (apt) or rhel (dnf); everything else is refused by the preflight tiers.
control_os_family() {
  case "$(preflight_os_release_value ID)" in
    rocky|almalinux|rhel|centos) printf 'rhel' ;;
    *) printf 'debian' ;;
  esac
}

# EL unit names of the same dependencies; ordering on an absent unit is a no-op,
# so the Debian unit text is unchanged.
control_dependency_units() {
  if [ "$(control_os_family)" = rhel ]; then printf ' postgresql-17.service redis.service valkey.service'; fi
}

# EPEL clamd@scan runs as clamscan and shares its socket with virusgroup; the
# Debian clamav-daemon socket belongs to the clamav group.
control_clamav_group() {
  if [ "$(control_os_family)" = rhel ]; then printf 'virusgroup'; else printf 'clamav'; fi
}
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

# Read-only host checks before any prompt or mutation. MASTER_PORT defaults to
# 443 here; a different interactive answer is rechecked by normalise_defaults.
run_preflight() {
  local port=${MASTER_PORT:-443} entry
  local -a ports=()
  select_gateway_ports
  resolve_install_env
  plan_install_ports
  while IFS= read -r entry; do ports+=("$entry"); done < <(control_preflight_ports)
  preflight_check_root
  preflight_check_os control
  preflight_check_arch control
  preflight_check_kernel control
  preflight_check_cpu control
  preflight_check_memory control
  preflight_check_disk control
  preflight_check_systemd
  preflight_check_coexistence control
  preflight_check_ports "${ports[@]}"
  preflight_check_commands bash awk sed grep df uname id 'apt-get|dnf' -- curl jq openssl sha256sum xxd uuidgen file tar unzip python3 git flock ss timeout
  if [ -n "$LICENSING_SERVER" ]; then
    preflight_check_remote 授权端 "${LICENSING_SERVER%/}/" "${LICENSING_SERVER_FALLBACK:+${LICENSING_SERVER_FALLBACK%/}/}"
  else
    preflight_record fail 授权端 '未提供 --licensing-server' '请从授权门户复制完整的安装命令'
  fi
  preflight_check_selinux
  if [ "$INSTALL_ENV" = bt ]; then
    bt_preflight_records
  else
    preflight_check_firewall "$port" "$GATEWAY_ENROLLMENT_PORT" "$GATEWAY_AGENT_PORT"
  fi
  PREFLIGHT_ASSUME_YES=$ASSUME_YES
  preflight_report '[cdnca-control]' || exit 1
}

# Ports owned by native runtime services on the control host.
readonly NATIVE_RESERVED_PORTS=' 80 4222 4223 5432 6379 6380 8080 8082 8123 8222 9000 9004 9005 9009 9091 9445 9446 19000 '

# ss when present (after dependencies), else /proc/net/tcp* (preflight).
gateway_port_listening() {
  if command -v ss >/dev/null 2>&1; then
    [ -n "$(ss -H -ltn "sport = :$1" 2>/dev/null)" ]
  else
    preflight_listening_ports | grep -qx -- "$1"
  fi
}

gateway_port_usable() {
  local port=$1 master=${MASTER_PORT:-443}
  case "$NATIVE_RESERVED_PORTS" in *" $port "*) return 1 ;; esac
  [ "$port" != "$((10#$master))" ] && ! gateway_port_listening "$port"
}

# Pick or validate the two Gateway ports (ADR 0013 §3.5). Idempotent: a later
# call (normalise_defaults after an interactive MASTER_PORT) re-checks the
# same choice without re-rolling random ports.
select_gateway_ports() {
  local enrollment agent attempt suggestion
  if [ -z "$GATEWAY_PORTS" ] && [ -n "$GATEWAY_ENROLLMENT_PORT" ] && [ -n "$GATEWAY_AGENT_PORT" ]; then
    GATEWAY_PORTS="$GATEWAY_ENROLLMENT_PORT,$GATEWAY_AGENT_PORT"
  fi
  if [ -z "$GATEWAY_PORTS" ]; then
    for attempt in $(seq 1 200); do
      enrollment=$((20000 + RANDOM % 10000)); agent=$((20000 + RANDOM % 10000))
      [ "$enrollment" != "$agent" ] && gateway_port_usable "$enrollment" && gateway_port_usable "$agent" || continue
      GATEWAY_ENROLLMENT_PORT=$enrollment GATEWAY_AGENT_PORT=$agent GATEWAY_PORTS="$enrollment,$agent"
      return 0
    done
    fail 'no two free Gateway ports were found in 20000-29999; pass --gateway-ports <enrollment>,<agent>'
  fi
  [[ "$GATEWAY_PORTS" =~ ^([0-9]{1,5}),([0-9]{1,5})$ ]] || fail '--gateway-ports must be <enrollment>,<agent>, e.g. 21443,21444'
  enrollment=$((10#${BASH_REMATCH[1]})); agent=$((10#${BASH_REMATCH[2]}))
  suggestion=$(gateway_port_suggestion)
  for attempt in "$enrollment" "$agent"; do
    # A dedicated Gateway host (--mode gateway) may also use 443 (ADR 0013 §3.1).
    [ "$attempt" -ge 1024 ] && [ "$attempt" -le 65535 ] || { [ "${INSTALL_MODE:-all}" = gateway ] && [ "$attempt" = 443 ]; } ||
      fail "Gateway port $attempt must be between 1024 and 65535; for example --gateway-ports $suggestion"
    case "$NATIVE_RESERVED_PORTS" in *" $attempt "*) fail "Gateway port $attempt is reserved by a native runtime service; for example --gateway-ports $suggestion" ;; esac
    [ "$attempt" != "$((10#${MASTER_PORT:-443}))" ] || fail "Gateway port $attempt equals the management HTTPS port; for example --gateway-ports $suggestion"
  done
  [ "$enrollment" != "$agent" ] || fail "the two Gateway ports must differ; for example --gateway-ports $suggestion"
  for attempt in "$enrollment" "$agent"; do
    ! gateway_port_listening "$attempt" || fail "Gateway port $attempt is already in use; for example --gateway-ports $suggestion"
  done
  GATEWAY_ENROLLMENT_PORT=$enrollment GATEWAY_AGENT_PORT=$agent GATEWAY_PORTS="$enrollment,$agent"
}

# A free pair in 20000-29999 for error messages; does not change the choice.
gateway_port_suggestion() {
  local port
  for port in $(seq 20000 2 29998); do
    if gateway_port_usable "$port" && gateway_port_usable "$((port + 1))"; then printf '%s,%s' "$port" "$((port + 1))"; return 0; fi
  done
  printf '21443,21444'
}

# 宝塔面板：/www/server/panel（版本在 class/common.py 的 g.version，面板端口在
# data/port.pl）或 bt 命令。BT_ROOT 只给测试替换根目录。
bt_detect() {
  local panel="${BT_ROOT}/www/server/panel" port=''
  BT_VERSION='' BT_PANEL_PORT=''
  if [ -d "$panel" ]; then
    [ ! -r "$panel/class/common.py" ] || BT_VERSION=$(sed -n "s/^[[:space:]]*g\.version[[:space:]]*=[[:space:]]*['\"]\([0-9][0-9.]*\)['\"].*/\1/p" "$panel/class/common.py" | head -n 1)
    [ ! -r "$panel/data/port.pl" ] || port=$(tr -dc '0-9' <"$panel/data/port.pl")
    ! valid_port "$port" || BT_PANEL_PORT=$port
    return 0
  fi
  command -v bt >/dev/null 2>&1
}

resolve_install_env() {
  case "$INSTALL_ENV" in
    auto) if bt_detect; then INSTALL_ENV=bt; else INSTALL_ENV=plain; fi ;;
    bt|plain) bt_detect || true ;;
    *) fail '--env must be auto, bt or plain' ;;
  esac
  [ "$INSTALL_ENV" = bt ] || { [ -z "$WEB_PORT" ] && [ "${BT_PROXY:-false}" = false ]; } ||
    fail '--web-port and --bt-proxy are only used with the BaoTa environment (--env bt)'
}

# 宝塔模式的替代端口：不在本机监听、不是主控固定端口、不是网关端口、本次未分配过。
bt_port_free() {
  local port=$1
  case "$NATIVE_RESERVED_PORTS" in *" $port "*) return 1 ;; esac
  case " ${GATEWAY_ENROLLMENT_PORT:-} ${GATEWAY_AGENT_PORT:-} ${BT_TAKEN:-} " in *" $port "*) return 1 ;; esac
  ! preflight_listening_ports | grep -qx -- "$port"
}

bt_pick_port() {
  local port
  for port in $(seq "$1" "$(($1 + 100))"); do
    if bt_port_free "$port"; then printf '%s' "$port"; return 0; fi
  done
  fail "no free port found in $1-$(($1 + 100)) for $2"
}

# 普通模式：管理端网页直接监听公网 MASTER_PORT，依赖用默认端口（占用由预检判不通过）。
# 宝塔模式：网页只监听 127.0.0.1:WEB_PORT；PostgreSQL/Redis/ClickHouse 默认端口被占时换端口。
plan_install_ports() {
  local spec variable default preferred label port
  BT_PORT_CHANGES=() BT_TAKEN=''
  if [ "$INSTALL_ENV" != bt ]; then
    WEB_PORT=${MASTER_PORT:-443} WEB_LISTEN=${MASTER_PORT:-443} WEB_REAL_IP='' NODE_DOWNLOAD_PORT=''
    return 0
  fi
  if [ -n "$WEB_PORT" ]; then
    [[ "$WEB_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$WEB_PORT" -ge 1024 ] && [ "$WEB_PORT" -le 65535 ] || fail '--web-port must be between 1024 and 65535'
    WEB_PORT=$((10#$WEB_PORT))
    case "$NATIVE_RESERVED_PORTS ${GATEWAY_ENROLLMENT_PORT:-} ${GATEWAY_AGENT_PORT:-} " in
      *" $WEB_PORT "*) fail "--web-port $WEB_PORT conflicts with a port used by the control plane" ;;
    esac
    ! preflight_listening_ports | grep -qx -- "$WEB_PORT" || fail "--web-port $WEB_PORT is already in use"
  else
    WEB_PORT=$(bt_pick_port 18443 'the management web')
    [ "$WEB_PORT" = 18443 ] || BT_PORT_CHANGES+=("管理端网页 18443 已被占用，改用 $WEB_PORT")
  fi
  BT_TAKEN=$WEB_PORT
  # 默认 19445：避开节点安装器与 agent 的网关默认端口 19443/19444（常见的 --gateway-ports 19443,19444）；
  # bt_port_free 另外避开本次实际网关端口、已监听端口与已分配端口，冲突即顺延。
  NODE_DOWNLOAD_PORT=$(bt_pick_port 19445 'node upgrade downloads')
  [ "$NODE_DOWNLOAD_PORT" = 19445 ] || BT_PORT_CHANGES+=("节点升级下载 19445 已被占用或与网关端口冲突，改用 $NODE_DOWNLOAD_PORT")
  BT_TAKEN="$BT_TAKEN $NODE_DOWNLOAD_PORT"
  WEB_LISTEN="127.0.0.1:$WEB_PORT"
  # 宝塔站点从回环转发，X-Real-IP 是浏览器地址；只信任回环来的这个头。
  WEB_REAL_IP=$'\n        set_real_ip_from 127.0.0.1;\n        real_ip_header X-Real-IP;'
  [ "${SKIP_DEPENDENCIES:-false}" = false ] || return 0
  for spec in PG_PORT:5432:15432:PostgreSQL REDIS_PORT:6379:16379:Redis CH_HTTP_PORT:8123:18123:ClickHouse-HTTP \
    CH_TCP_PORT:9000:19100:ClickHouse CH_MYSQL_PORT:9004:19104:ClickHouse-MySQL \
    CH_POSTGRESQL_PORT:9005:19105:ClickHouse-PostgreSQL CH_INTERSERVER_PORT:9009:19109:ClickHouse-复制; do
    IFS=: read -r variable default preferred label <<<"$spec"
    port=$default
    if preflight_listening_ports | grep -qx -- "$default"; then
      port=$(bt_pick_port "$preferred" "$label")
      BT_PORT_CHANGES+=("$label $default 已被占用，改用 $port")
    fi
    BT_TAKEN="$BT_TAKEN $port"
    printf -v "$variable" '%s' "$port"
  done
}

# 宝塔模式把实际依赖端口写进端口档案，签名依赖 helper、ClickHouse/控制面 helper、
# 备份恢复与迁移都按它取端口；普通模式不写（全部默认端口）。
DEPENDENCY_PORTS_FILE=/etc/cdnca-native-dependencies/runtime.env
write_dependency_ports() {
  [ "$INSTALL_ENV" = bt ] || return 0
  install -d -m 0755 "$(dirname "$DEPENDENCY_PORTS_FILE")"
  printf 'ENV=bt\nWEB_PORT=%s\nNODE_DOWNLOAD_PORT=%s\nPG_PORT=%s\nREDIS_PORT=%s\nCH_HTTP_PORT=%s\nCH_TCP_PORT=%s\nCH_MYSQL_PORT=%s\nCH_POSTGRESQL_PORT=%s\nCH_INTERSERVER_PORT=%s\n' \
    "$WEB_PORT" "$NODE_DOWNLOAD_PORT" "$PG_PORT" "$REDIS_PORT" "$CH_HTTP_PORT" "$CH_TCP_PORT" "$CH_MYSQL_PORT" "$CH_POSTGRESQL_PORT" "$CH_INTERSERVER_PORT" >"$DEPENDENCY_PORTS_FILE.tmp"
  chmod 0644 "$DEPENDENCY_PORTS_FILE.tmp"
  mv -f "$DEPENDENCY_PORTS_FILE.tmp" "$DEPENDENCY_PORTS_FILE"
}

# 预检要求空闲的端口（端口:用途），与 plan_install_ports 的结果一致。
control_preflight_ports() {
  if [ "$INSTALL_ENV" = bt ]; then
    printf '%s\n' "$WEB_PORT:管理端网页（本机回环）" "$NODE_DOWNLOAD_PORT:节点升级下载"
  else
    printf '%s\n' "${MASTER_PORT:-443}:管理端HTTPS" 80:证书签发与依赖安装
  fi
  printf '%s\n' "$GATEWAY_ENROLLMENT_PORT:节点注册" "$GATEWAY_AGENT_PORT:节点通道" 4222:NATS 8222:NATS监控 \
    8080:control-api 8082:Gateway健康检查 9091:内部gRPC 9445:升级源 19000:对象存储
  [ "${SKIP_DEPENDENCIES:-false}" = true ] || printf '%s\n' "$PG_PORT:PostgreSQL" "$REDIS_PORT:Redis" "$CH_HTTP_PORT:ClickHouse-HTTP" \
    "$CH_TCP_PORT:ClickHouse" "$CH_MYSQL_PORT:ClickHouse-MySQL" "$CH_POSTGRESQL_PORT:ClickHouse-PostgreSQL" "$CH_INTERSERVER_PORT:ClickHouse-复制"
  [ "${INSTALL_MODE:-all}" != control ] || printf '%s\n' "$CONTROL_INTERNAL_REMOTE_PORT:网关内部gRPC" "$NATS_GATEWAY_WS_PORT:网关NATS" "$REDIS_GATEWAY_TLS_PORT:网关Redis"
}

# 宝塔站点证书（/www/server/panel/vhost/cert/<站点>/fullchain.pem）是否受系统信任。浏览器与节点
# 安装命令经该站点访问；节点升级下载走直连端口，不受影响。站点多在安装后才建，所以只警告。
bt_check_site_certificate() {
  local site=$1 cert="${BT_ROOT}/www/server/panel/vhost/cert/$1/fullchain.pem" bundle=${BT_CA_BUNDLE:-} hint
  hint="浏览器访问管理端与节点安装命令都经这个站点，需要受信证书：请在宝塔站点「SSL」申请 Let's Encrypt 证书或部署受信证书（含完整中间证书）；节点升级下载走直连端口 ${NODE_DOWNLOAD_PORT}（主控自带 CA），不受站点证书影响"
  if [ -z "$bundle" ]; then
    for bundle in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt; do [ ! -r "$bundle" ] || break; done
  fi
  if [ ! -s "$cert" ]; then
    preflight_record warn 宝塔站点证书 "站点 ${site} 还没有证书（站点未建或未开启 SSL）" "$hint"
  elif ! command -v openssl >/dev/null 2>&1 || [ ! -r "$bundle" ]; then
    preflight_record warn 宝塔站点证书 "无法检查站点 ${site} 的证书（缺少 openssl 或系统 CA 证书库）" "$hint"
  elif openssl verify -CAfile "$bundle" -untrusted "$cert" -purpose sslserver -verify_hostname "$site" "$cert" >/dev/null 2>&1; then
    preflight_record pass 宝塔站点证书 "站点 ${site} 的证书受系统信任"
  else
    preflight_record warn 宝塔站点证书 "站点 ${site} 的证书不受系统信任（自签、证书链不完整、已过期或域名不符）" "$hint"
  fi
}

# 宝塔环境的中文预检清单：版本与面板端口、宝塔 nginx、端口调整、手工步骤、防火墙。
bt_preflight_records() {
  [ "$INSTALL_ENV" = bt ] || return 0
  local site=${CONTROL_DOMAIN:-${MASTER_HOST:-<管理端域名>}} change open plan server
  if [ -d "${BT_ROOT}/www/server/panel" ]; then
    preflight_record pass 宝塔环境 "检测到宝塔面板 ${BT_VERSION:-（版本未知）}，面板端口 ${BT_PANEL_PORT:-未知}（不改动宝塔的 nginx、MySQL 与面板）"
  else
    preflight_record warn 宝塔环境 '未找到宝塔面板目录 /www/server/panel，按 --env bt 继续' '确认本机确实装了宝塔；否则改用 --env plain'
  fi
  server=$(bt_web_server)
  if [ "$server" = nginx ]; then
    preflight_record pass 宝塔nginx '已安装，用于站点反向代理；管理端网页另起独立实例（独立配置、只监听回环，不改宝塔的 nginx 配置）'
  elif [ "${BT_PROXY:-false}" = true ]; then
    preflight_record fail 宝塔nginx '未找到 /www/server/nginx/sbin/nginx，--bt-proxy 只支持宝塔 nginx' '在宝塔「软件商店」安装 Nginx，或去掉 --bt-proxy 手工配置反向代理'
  elif [ "$server" = apache ]; then
    preflight_record warn 宝塔Apache '宝塔使用 Apache，安装器不会自动写入反向代理' \
      "在站点「配置文件」的 <VirtualHost *:443> 内加入下面的片段（安装结束会保存到 ${CONFIG_DIR}/bt-proxy-apache.conf）：
$(bt_proxy_apache_config)"
  elif [ "$server" = openlitespeed ]; then
    preflight_record warn 宝塔OpenLiteSpeed '宝塔使用 OpenLiteSpeed，安装器不会自动写入反向代理' \
      "在站点「配置文件」（/www/server/panel/vhost/openlitespeed/${site}.conf）加入下面的片段后重启 OpenLiteSpeed（安装结束会保存到 ${CONFIG_DIR}/bt-proxy-openlitespeed.conf）：
$(bt_proxy_openlitespeed_config)"
  else
    preflight_record warn 宝塔nginx '未找到宝塔 nginx、Apache 或 OpenLiteSpeed' '请先在宝塔「软件商店」安装 Nginx（推荐），再按安装结束时打印的步骤配置反向代理'
  fi
  if [[ "$site" =~ ^[0-9.]+$ || "$site" == *:* ]]; then
    preflight_record fail 管理端域名 "宝塔模式需要域名（当前为 $site）" '宝塔站点按域名反向代理；请用已解析到本机的域名作为 --master-host'
  elif [ "$site" != '<管理端域名>' ]; then
    bt_check_site_certificate "$site"
  fi
  for change in ${BT_PORT_CHANGES[@]+"${BT_PORT_CHANGES[@]}"}; do preflight_record pass 端口调整 "$change"; done
  plan="管理端网页 127.0.0.1:${WEB_PORT}、节点升级下载 ${NODE_DOWNLOAD_PORT}"
  [ "${SKIP_DEPENDENCIES:-false}" = true ] ||
    plan="$plan、PostgreSQL ${PG_PORT}、Redis ${REDIS_PORT}、ClickHouse-HTTP ${CH_HTTP_PORT}、ClickHouse ${CH_TCP_PORT}、ClickHouse-MySQL ${CH_MYSQL_PORT}、ClickHouse-PostgreSQL ${CH_POSTGRESQL_PORT}、ClickHouse-复制 ${CH_INTERSERVER_PORT}"
  preflight_record pass 端口规划 "$plan（写入 ${DEPENDENCY_PORTS_FILE:-/etc/cdnca-native-dependencies/runtime.env}）"
  preflight_record pass 管理端网页 "本机 127.0.0.1:${WEB_PORT}（只监听回环，由宝塔站点反向代理）"
  preflight_record pass 节点升级下载 "直连端口 ${NODE_DOWNLOAD_PORT}（我方 nginx，主控自带 CA 签发的证书，节点已信任；不经宝塔站点）"
  preflight_record warn 宝塔手工步骤 '安装完成后需要在宝塔里为管理端配置站点' \
    "① 在宝塔「网站」添加站点 ${site}（纯静态、不建数据库），在站点「SSL」申请 Let's Encrypt 证书并开启强制 HTTPS；② $(
      [ "${BT_PROXY:-false}" = true ] && printf '安装器会自动写入反向代理（已指定 --bt-proxy）' ||
        printf '在站点「反向代理」里反向代理到 https://127.0.0.1:%s，发送域名 $host（或加 --bt-proxy 由安装器自动写入）' "$WEB_PORT"
    )；③ 安装结束时会打印可复制的反向代理配置，并保存到 /etc/cdnca-control/bt-proxy.conf"
  open="${MASTER_PORT:-443}、${GATEWAY_ENROLLMENT_PORT}、${GATEWAY_AGENT_PORT}"
  [ "${INSTALL_MODE:-all}" != control ] || open="$open、$CONTROL_INTERNAL_REMOTE_PORT、$NATS_GATEWAY_WS_PORT、$REDIS_GATEWAY_TLS_PORT"
  open="$open、${NODE_DOWNLOAD_PORT}（节点升级下载）"
  preflight_record warn 宝塔防火墙 "需在宝塔「安全」放行 TCP ${open}" \
    "云服务器安全组同样放行；回环端口 ${WEB_PORT}、${PG_PORT}、${REDIS_PORT} 不要对外放行"
}

# 宝塔站点的反向代理配置（与宝塔自带反向代理同为 location ^~ /；/.well-known 证书验证仍由宝塔处理）。
bt_proxy_config() {
  cat <<EOF
  # CDNCA 管理端（install-control.sh 生成）：宝塔站点 ${CONTROL_DOMAIN} 反向代理到本机管理端网页
  location ^~ / {
    proxy_pass https://127.0.0.1:${WEB_PORT};
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$http_connection;
    proxy_ssl_server_name on;
    proxy_ssl_name ${CONTROL_DOMAIN};
    proxy_read_timeout 300s;
    client_max_body_size 0;
  }
EOF
}

# 宝塔站点的 Web 服务：nginx 优先，其次 Apache、OpenLiteSpeed（宝塔的安装路径）；都没有为空。
bt_web_server() {
  if [ -x "${BT_ROOT}/www/server/nginx/sbin/nginx" ]; then printf nginx
  elif [ -x "${BT_ROOT}/www/server/apache/bin/httpd" ]; then printf apache
  elif [ -x "${BT_ROOT}/usr/local/lsws/bin/lswsctrl" ]; then printf openlitespeed
  fi
}

# 宝塔 Apache 站点片段（只打印，不自动写入）：校验回环证书（本机根 CA，SAN 含管理端域名，
# ProxyPreserveHost 让 Apache 按 Host 校验）；X-Real-IP 用连接地址覆盖，与 nginx 片段一致。
# upgrade=websocket 需要 Apache 2.4.47+；/.well-known/ 留给宝塔续签证书。
bt_proxy_apache_config() {
  cat <<EOF
    # CDNCA 管理端（install-control.sh 生成）：宝塔 Apache 站点 ${CONTROL_DOMAIN} 反向代理到本机管理端网页
    SSLProxyEngine On
    SSLProxyVerify require
    SSLProxyCheckPeerName On
    SSLProxyCACertificateFile ${DOWNLOAD_DIR}/gateway-ca.pem
    ProxyPreserveHost On
    ProxyTimeout 300
    RequestHeader set X-Real-IP "expr=%{REMOTE_ADDR}"
    RequestHeader set X-Forwarded-Proto "https"
    ProxyPass /.well-known/ !
    ProxyPass / https://127.0.0.1:${WEB_PORT}/ upgrade=websocket
    ProxyPassReverse / https://127.0.0.1:${WEB_PORT}/
EOF
}

# 宝塔 OpenLiteSpeed 站点片段（只打印，不自动写入）：proxy 外部应用 + context /。
# OpenLiteSpeed 只附加 X-Forwarded-For，不设 X-Real-IP，管理端日志里的来源 IP 会是 127.0.0.1；
# 需要真实来源 IP 时请在宝塔改用 Nginx。
bt_proxy_openlitespeed_config() {
  cat <<EOF
  # CDNCA 管理端（install-control.sh 生成）：宝塔 OpenLiteSpeed 站点 ${CONTROL_DOMAIN} 反向代理到本机管理端网页
  extprocessor cdnca-control {
    type                    proxy
    address                 https://127.0.0.1:${WEB_PORT}
    maxConns                100
    initTimeout             60
    retryTimeout            0
    respBuffer              0
  }

  context / {
    type                    proxy
    handler                 cdnca-control
    addDefaultCharset       off
  }
EOF
}

# --bt-proxy：写入宝塔站点的 proxy 目录（站点配置已 include 它）。先备份，nginx -t
# 不通过或 reload 失败即恢复原状；任何前提不满足都不改文件，返回 1 由调用方提示手工步骤。
bt_install_proxy() {
  local site=${BT_SITE:-$CONTROL_DOMAIN} vhost dir file backup nginx output created_dir=false had_file=false
  vhost="${BT_ROOT}/www/server/panel/vhost/nginx/${site}.conf"
  dir="${BT_ROOT}/www/server/panel/vhost/nginx/proxy/${site}"
  file="$dir/cdnca-control.conf" backup="$dir/cdnca-control.conf.bak"
  nginx="${BT_ROOT}/www/server/nginx/sbin/nginx"
  if [ ! -f "$vhost" ]; then
    warn "宝塔里没有站点 ${site}（${vhost#"$BT_ROOT"} 不存在）；请先在宝塔「网站」添加该站点"
    return 1
  fi
  if ! grep -Fq "/www/server/panel/vhost/nginx/proxy/${site}/" "$vhost"; then
    warn "站点配置没有引用 proxy 目录（include /www/server/panel/vhost/nginx/proxy/${site}/*.conf），可能被手工改过；未改动任何文件"
    return 1
  fi
  [ -x "$nginx" ] || { warn '未找到宝塔 nginx（/www/server/nginx/sbin/nginx）；未改动任何文件'; return 1; }
  [ -d "$dir" ] || { install -d -m 0755 "$dir"; created_dir=true; }
  if [ -e "$file" ]; then cp -p "$file" "$backup"; had_file=true; fi
  bt_proxy_config >"$file.tmp" && chmod 0644 "$file.tmp" && mv -f "$file.tmp" "$file"
  bt_restore_proxy() {
    if [ "$had_file" = true ]; then mv -f "$backup" "$file"; else rm -f "$file"; fi
    [ "$created_dir" = false ] || rmdir "$dir" 2>/dev/null || true
  }
  if ! output=$("$nginx" -t 2>&1); then
    bt_restore_proxy
    warn "宝塔 nginx 配置检查未通过，已恢复原配置：$(printf '%s\n' "$output" | tail -n 3 | tr '\n' ' ')"
    return 1
  fi
  if ! output=$("$nginx" -s reload 2>&1); then
    bt_restore_proxy
    "$nginx" -s reload >/dev/null 2>&1 || true
    warn "宝塔 nginx 重新加载失败，已恢复原配置：$(printf '%s\n' "$output" | tail -n 3 | tr '\n' ' ')"
    return 1
  fi
  log "已写入宝塔站点 ${site} 的反向代理：${file#"$BT_ROOT"}"
  [ "$had_file" = false ] || log "原文件备份为 ${backup#"$BT_ROOT"}"
}

# 安装结束：宝塔模式保存可复制的反向代理配置，按 --bt-proxy 自动写入或打印手工步骤。
bt_report() {
  [ "$INSTALL_ENV" = bt ] || return 0
  bt_proxy_config >"${CONFIG_DIR}/bt-proxy.conf"
  chmod 0644 "${CONFIG_DIR}/bt-proxy.conf"
  local server label file
  server=$(bt_web_server)
  if [ "$server" = apache ] || [ "$server" = openlitespeed ]; then
    if [ "$server" = apache ]; then label=Apache file="${CONFIG_DIR}/bt-proxy-apache.conf"; bt_proxy_apache_config >"$file"
    else label=OpenLiteSpeed file="${CONFIG_DIR}/bt-proxy-openlitespeed.conf"; bt_proxy_openlitespeed_config >"$file"; fi
    chmod 0644 "$file"
    cat >&2 <<EOF

宝塔环境（${label}）：管理端网页只监听 127.0.0.1:${WEB_PORT}，安装器不会改动 ${label} 配置，请在宝塔里完成：
  1. 「网站」添加站点 ${CONTROL_DOMAIN}（纯静态，不建数据库），在站点「SSL」申请证书并开启强制 HTTPS。
  2. 站点「配置文件」加入下面的片段（已保存到 ${file}），保存后宝塔会重载 ${label}：
$(sed 's/^/     /' "$file")
  3. 宝塔「安全」放行 TCP ${MASTER_PORT}、${GATEWAY_ENROLLMENT_PORT}、${GATEWAY_AGENT_PORT}、${NODE_DOWNLOAD_PORT}（节点升级下载直连）；云安全组同样放行。
EOF
    return 0
  fi
  if [ "$BT_PROXY" = true ] && bt_install_proxy; then
    log "宝塔反向代理已就绪；确认站点 ${CONTROL_DOMAIN} 已开启 SSL 后即可访问 https://${CONTROL_DOMAIN}/dashboard/"
    return 0
  fi
  cat >&2 <<EOF

宝塔环境：管理端网页只监听 127.0.0.1:${WEB_PORT}，请在宝塔里完成以下步骤：
  1. 「网站」添加站点 ${CONTROL_DOMAIN}（纯静态，不建数据库），在站点「SSL」申请证书并开启强制 HTTPS。
  2. 站点「反向代理」→ 添加：目标 URL https://127.0.0.1:${WEB_PORT}，发送域名 \$host；
     或在站点「配置文件」的 server 块中加入下面的配置（已保存到 ${CONFIG_DIR}/bt-proxy.conf）：
$(bt_proxy_config | sed 's/^/     /')
  3. 宝塔「安全」放行 TCP ${MASTER_PORT}、${GATEWAY_ENROLLMENT_PORT}、${GATEWAY_AGENT_PORT}、${NODE_DOWNLOAD_PORT}（节点升级下载直连）；云安全组同样放行。
  建好站点后也可直接复制：install -D -m 0644 ${CONFIG_DIR}/bt-proxy.conf /www/server/panel/vhost/nginx/proxy/${CONTROL_DOMAIN}/cdnca-control.conf
    && /www/server/nginx/sbin/nginx -t && /www/server/nginx/sbin/nginx -s reload
EOF
}

prompt_public_endpoints() {
  if [ -z "$MASTER_HOST" ]; then
    [ -t 0 ] || fail '--master-host is required for a non-interactive installation'
    printf '管理端公网域名或 IP: ' >&2
    IFS= read -r MASTER_HOST
  fi
  MASTER_HOST=$(printf '%s' "$MASTER_HOST" | tr '[:upper:]' '[:lower:]')
  valid_host "$MASTER_HOST" || fail 'invalid public control-plane host'
  if [ -z "$MASTER_PORT" ]; then
    if [ -t 0 ]; then
      printf '管理端 HTTPS 端口 [443]: ' >&2
      IFS= read -r MASTER_PORT
    fi
    MASTER_PORT=${MASTER_PORT:-443}
  fi
  valid_port "$MASTER_PORT" || fail '--master-port must be between 1 and 65535'
  # Nodes reach this same host on the two Gateway ports (enrollment and
  # agent channel). Only a split deployment needs a different name: --gateway-host.
  GATEWAY_HOST=${GATEWAY_HOST:-$MASTER_HOST}
  GATEWAY_HOST=$(printf '%s' "$GATEWAY_HOST" | tr '[:upper:]' '[:lower:]')
  valid_host "$GATEWAY_HOST" || fail 'invalid public Gateway host'
  CONTROL_DOMAIN=$(printf '%s' "${CONTROL_DOMAIN:-$MASTER_HOST}" | tr '[:upper:]' '[:lower:]')
  valid_host "$CONTROL_DOMAIN" || fail 'invalid public control-plane domain'
  if [ -z "$PUBLIC_CERT_FILE" ] && control_domain_is_ip; then
    warn '管理端使用 IP 访问：Let'"'"'s Encrypt 不为 IP 签发证书，将使用本机私有 CA 证书，浏览器会提示“不安全”。如需正式 HTTPS，请改用已解析到本机的域名重新安装，或传入 --public-cert-file/--public-key-file。'
  fi
}

control_domain_is_ip() { [[ "$CONTROL_DOMAIN" =~ ^[0-9.]+$ || "$CONTROL_DOMAIN" == *:* ]]; }

normalise_defaults() {
  local value architecture listeners
  [ -n "$LICENSING_SERVER" ] || fail '--release-server is required'
  LICENSING_SERVER=${LICENSING_SERVER%/}
  LICENSING_SERVER_FALLBACK=${LICENSING_SERVER_FALLBACK:-$LICENSING_SERVER}
  LICENSING_SERVER_FALLBACK=${LICENSING_SERVER_FALLBACK%/}
  [ -n "$MASTER_HOST" ] || fail 'public control-plane host was not provided'
  MASTER_PORT=${MASTER_PORT:-443}
  CONTROL_DOMAIN=${CONTROL_DOMAIN:-$MASTER_HOST}
  GATEWAY_HOST=${GATEWAY_HOST:-$MASTER_HOST}
  if ! valid_host "$MASTER_HOST" || ! valid_host "$CONTROL_DOMAIN" || ! valid_host "$GATEWAY_HOST"; then
    fail 'invalid public host'
  fi
  valid_port "$MASTER_PORT" || fail 'invalid public HTTPS port'
  MASTER_PORT=$((10#$MASTER_PORT))
  case "$MASTER_PORT" in
    4222|4223|5432|6379|6380|8080|8082|8123|8222|9000|9004|9005|9009|9091|9445|9446|19000)
      fail 'public HTTPS port is reserved by a native runtime service' ;;
  esac
  if [[ "$GATEWAY_PORTS" =~ ^([0-9]{1,5}),([0-9]{1,5})$ ]]; then
    [ "$MASTER_PORT" != "$((10#${BASH_REMATCH[1]}))" ] && [ "$MASTER_PORT" != "$((10#${BASH_REMATCH[2]}))" ] ||
      fail 'public HTTPS port is reserved by the Gateway; choose another --master-port or --gateway-ports'
  fi
  # 宝塔环境的公网 443 属于宝塔 nginx，我方网页只监听回环 WEB_PORT。
  if [ "$INSTALL_ENV" != bt ]; then
    listeners=$(ss -H -ltn "sport = :$MASTER_PORT") || fail 'cannot inspect the public HTTPS port'
    [ -z "$listeners" ] || fail 'public HTTPS port is already occupied; existing listeners were not changed'
  fi
  select_gateway_ports
  plan_install_ports
  CONTROL_ORIGIN="https://$CONTROL_DOMAIN"
  case "$CONTROL_DOMAIN" in *:*) CONTROL_ORIGIN="https://[$CONTROL_DOMAIN]" ;; esac
  [ "$MASTER_PORT" = 443 ] || CONTROL_ORIGIN="$CONTROL_ORIGIN:$MASTER_PORT"
  INSTALLATION_ID=${INSTALLATION_ID:-$(uuidgen | tr '[:upper:]' '[:lower:]')}
  # Names are unique per license; a reinstall on the same host must not collide
  # with the previous installation's record, so the default carries this ID.
  INSTALLATION_NAME=${INSTALLATION_NAME:-control-$MASTER_HOST-${INSTALLATION_ID:0:8}}
  NATS_URL=${NATS_URL:-nats://127.0.0.1:4222}
  NATS_TELEMETRY_URL=${NATS_TELEMETRY_URL:-$NATS_URL}
  [ "$NATS_URL" = nats://127.0.0.1:4222 ] && [ "$NATS_TELEMETRY_URL" = "$NATS_URL" ] ||
    fail 'the fresh native profile requires the same fixed local NATS for control and telemetry'
  NATS_LOCAL=true
  CONTROL_NATIVE_URL=${CONTROL_NATIVE_URL:-$LICENSING_SERVER/downloads/control-native/latest/cdnca-control-native.tar}
  CONTROL_NATIVE_FALLBACK_URL=${CONTROL_NATIVE_FALLBACK_URL:-$LICENSING_SERVER_FALLBACK/downloads/control-native/latest/cdnca-control-native.tar}
  CONTROL_NATIVE_SHA256_URL=${CONTROL_NATIVE_SHA256_URL:-$LICENSING_SERVER/downloads/control-native/latest/SHA256SUMS}
  CONTROL_NATIVE_SHA256_FALLBACK_URL=${CONTROL_NATIVE_SHA256_FALLBACK_URL:-$LICENSING_SERVER_FALLBACK/downloads/control-native/latest/SHA256SUMS}
  CONTROL_NATIVE_TRUST_URL=${CONTROL_NATIVE_TRUST_URL:-$LICENSING_SERVER/downloads/control-native/artifacts.json}
  CONTROL_NATIVE_TRUST_FALLBACK_URL=${CONTROL_NATIVE_TRUST_FALLBACK_URL:-$LICENSING_SERVER_FALLBACK/downloads/control-native/artifacts.json}
  TRUSTED_KEYS_URL=${TRUSTED_KEYS_URL:-$LICENSING_SERVER/public/v1/signing-keyset}
  TRUSTED_KEYS_FALLBACK_URL=${TRUSTED_KEYS_FALLBACK_URL:-$LICENSING_SERVER_FALLBACK/public/v1/signing-keyset}
  EDGE_AGENT_URL=${EDGE_AGENT_URL:-$LICENSING_SERVER/downloads/edge-agent/latest/cdnca-edge-agent.tar.gz}
  EDGE_AGENT_FALLBACK_URL=${EDGE_AGENT_FALLBACK_URL:-$LICENSING_SERVER_FALLBACK/downloads/edge-agent/latest/cdnca-edge-agent.tar.gz}
  EDGE_AGENT_SHA256_URL=${EDGE_AGENT_SHA256_URL:-$LICENSING_SERVER/downloads/edge-agent/latest/SHA256SUMS}
  EDGE_AGENT_SHA256_FALLBACK_URL=${EDGE_AGENT_SHA256_FALLBACK_URL:-$LICENSING_SERVER_FALLBACK/downloads/edge-agent/latest/SHA256SUMS}
  EDGE_ARTIFACT_TRUST_URL=${EDGE_ARTIFACT_TRUST_URL:-$LICENSING_SERVER/downloads/edge-agent/artifacts.json}
  EDGE_ARTIFACT_TRUST_FALLBACK_URL=${EDGE_ARTIFACT_TRUST_FALLBACK_URL:-$LICENSING_SERVER_FALLBACK/downloads/edge-agent/artifacts.json}
  # Portable runtimes (hosts without a matching distribution package); the
  # signed dependency helper pins each archive by SHA-256.
  RUNTIME_ARCHIVE_URL=${RUNTIME_ARCHIVE_URL:-$LICENSING_SERVER/downloads/control-native/runtime}
  RUNTIME_ARCHIVE_FALLBACK_URL=${RUNTIME_ARCHIVE_FALLBACK_URL:-$LICENSING_SERVER_FALLBACK/downloads/control-native/runtime}
  architecture=$(host_architecture)
  [ "$architecture" = amd64 ] || fail 'the native profile only supports amd64'
  NATS_CLI_URL="https://github.com/nats-io/natscli/releases/download/v$NATS_CLI_VERSION/nats-$NATS_CLI_VERSION-linux-$architecture.zip"
  NATS_CLI_SHA256_URL="https://github.com/nats-io/natscli/releases/download/v$NATS_CLI_VERSION/SHA256SUMS"
  for value in "$LICENSING_SERVER" "$LICENSING_SERVER_FALLBACK" "$CONTROL_NATIVE_URL" "$CONTROL_NATIVE_FALLBACK_URL" \
    "$CONTROL_NATIVE_SHA256_URL" "$CONTROL_NATIVE_SHA256_FALLBACK_URL" "$CONTROL_NATIVE_TRUST_URL" "$CONTROL_NATIVE_TRUST_FALLBACK_URL" \
    "$TRUSTED_KEYS_URL" "$TRUSTED_KEYS_FALLBACK_URL" "$EDGE_AGENT_URL" "$EDGE_AGENT_FALLBACK_URL" \
    "$EDGE_AGENT_SHA256_URL" "$EDGE_AGENT_SHA256_FALLBACK_URL" "$EDGE_ARTIFACT_TRUST_URL" "$EDGE_ARTIFACT_TRUST_FALLBACK_URL" \
    "$RUNTIME_ARCHIVE_URL" "$RUNTIME_ARCHIVE_FALLBACK_URL"; do
    if ! valid_https_url "$value" || ! no_newlines "$value"; then
      fail 'native installation requires HTTPS download and authorization URLs'
    fi
  done
  if [ -n "$PUBLIC_CERT_FILE" ] || [ -n "$PUBLIC_KEY_FILE" ]; then
    [ -n "$PUBLIC_CERT_FILE" ] && [ -n "$PUBLIC_KEY_FILE" ] || fail 'public HTTPS certificate and private key must be provided together'
  fi
  if [ -n "$CONTROL_NATIVE_FILE" ] || [ -n "$CONTROL_NATIVE_TRUST_FILE" ]; then
    [[ "$CONTROL_NATIVE_FILE" = /* && "$CONTROL_NATIVE_TRUST_FILE" = /* ]] || fail 'local signed package and public trust require paired absolute paths'
  fi
  for value in "$INSTALLATION_NAME" "$ADMIN_USERNAME" "$ADMIN_EMAIL" "$ADMIN_PASSWORD_FILE" "$CONTROL_VERSION" "$DATABASE_URL" "$REDIS_URL"; do
    no_newlines "$value" || fail 'installer values must not contain newlines'
  done
  REDIS_URL=${REDIS_URL:-redis://127.0.0.1:$REDIS_PORT/0}
  valid_redis_url "$REDIS_URL" || fail 'invalid Redis URL'
  [ -z "$CONTROL_VERSION" ] || [[ "$CONTROL_VERSION" =~ ^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$ ]] ||
    fail 'expected version must be stable without leading zeros or metadata'
  if [ -z "$DATABASE_URL" ]; then
    DATABASE_PASSWORD=$(openssl rand -hex 24)
    DATABASE_URL="postgres://cdnca:$DATABASE_PASSWORD@127.0.0.1:$PG_PORT/cdnca?sslmode=disable"
  fi
  [[ "$INSTALLATION_ID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || fail 'installation ID must be a canonical UUID'
  [ ${#INSTALLATION_NAME} -le 200 ] || fail 'installation name is too long'
}
read_owner_only_value() {
  local file=$1 label=$2 destination=$3
  [ -f "$file" ] || fail "${label} file does not exist"
  [ "$(stat -c '%u' "$file" 2>/dev/null || stat -f '%u' "$file")" = "0" ] ||
    fail "${label} file must be owned by root"
  local mode
  mode=$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file")
  case "$mode" in
    400|600|700) ;;
    *) fail "${label} file must not be group/world readable or writable" ;;
  esac
  local value
  IFS= read -r value <"$file" || true
  [ -n "$value" ] || fail "${label} cannot be empty"
  printf -v "$destination" '%s' "$value"
}


TEMP_DIR=$(mktemp -d -t cdnca-control-install.XXXXXX)
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
  local status=$?
  [ -z "${PROGRESS_PREFIX:-}" ] || progress_on_exit "$status"
  [ "$status" -eq 0 ] || control_install_failed_hint
  rm -rf -- "$TEMP_DIR"
  [ "${#PAUSED_APT_TIMERS[@]}" -eq 0 ] || systemctl start "${PAUSED_APT_TIMERS[@]}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# A freshly booted host runs unattended-upgrades, which holds the dpkg lock for
# minutes; without a timeout every apt-get here and in the signed helpers fails
# immediately. APT_CONFIG is read in addition to the system configuration.
printf 'DPkg::Lock::Timeout "900";\n' >"$TEMP_DIR/apt-lock.conf"
export APT_CONFIG="$TEMP_DIR/apt-lock.conf"

host_architecture() {
  case "$(uname -m)" in
    x86_64) printf 'amd64' ;;
    aarch64|arm64) printf 'arm64' ;;
    *) fail "unsupported host architecture: $(uname -m)" ;;
  esac
}

download_verified() {
  local primary=$1 fallback=$2 sums_primary=$3 sums_fallback=$4 output=$5 expected_name=$6 label=$7
  local checksum_output=${8:-} candidate sums expected actual index
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
    progress_download "$label" curl --proto '=https' --proto-redir '=https' -fL --connect-timeout 10 --max-time 600 \
      --max-filesize 1073741824 --retry 1 --output "$candidate" "${artifact_urls[$index]}" || continue
    # A reverse proxy can return a branded HTML error page with HTTP 200.  Do
    # this check before accepting the pair so a bad primary can fall back.
    if file "$candidate" | grep -Eqi 'HTML|text, Unicode|ASCII text'; then
      continue
    fi
    curl --proto '=https' --proto-redir '=https' -fL --connect-timeout 10 --max-time 60 \
      --max-filesize 1048576 --retry 1 --output "$sums" "${checksum_urls[$index]}" || continue
    expected=$(awk -v name="$expected_name" '$2 == name || $2 == "./" name {print $1; exit}' "$sums")
    [[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || continue
    actual=$(sha256sum "$candidate" | awk '{print $1}')
    [ "$actual" = "$expected" ] || continue
    cp -- "$candidate" "$output"
    [ -z "$checksum_output" ] || cp -- "$sums" "$checksum_output"
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
    curl --proto '=https' --proto-redir '=https' -fL --connect-timeout 10 --max-time 60 \
      --max-filesize 1048576 --retry 1 --output "$candidate" "${urls[$index]}" || continue
    jq -e "$expression" "$candidate" >/dev/null 2>&1 || continue
    cp -- "$candidate" "$output"
    return 0
  done
  return 1
}

assert_not_html() {
  local file=$1 label=$2
  if file "$file" | grep -Eqi 'HTML|text, Unicode|ASCII text'; then
    fail "${label} download is not a release artifact"
  fi
}

generate_identity() {
  mkdir -p "$KEY_DIR" "$RESPONSE_DIR" "$INSTALL_ROOT" "$DATA_DIR"
  chmod 0700 "$CONFIG_DIR" "$KEY_DIR" "$RESPONSE_DIR"
  chmod 0755 "$DATA_DIR"
  "$ED25519_TOOL" genkey "${KEY_DIR}/installation.key" || fail 'failed to generate the installation key'
  chmod 0600 "${KEY_DIR}/installation.key"
  "$ED25519_TOOL" pubkey "${KEY_DIR}/installation.key" >"${KEY_DIR}/installation.pub" || fail 'failed to derive the installation public key'
  chmod 0400 "${KEY_DIR}/installation.pub"
  PUBLIC_KEY=$("$ED25519_TOOL" pubkey "${KEY_DIR}/installation.key" --der | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=\n')
  [ ${#PUBLIC_KEY} -eq 43 ] || fail 'generated installation public key is invalid'
  # cdncaCE: X25519 key that opens rule packs bought on the plugin market
  # (the official service wraps their content key for this installation).
  "$CONTROL_BINARY" generate-installation-encryption-key --out "${KEY_DIR}/installation-encryption.key" >/dev/null ||
    fail 'failed to generate the installation encryption key'
}

# cdncaCE: the official service's public signing keyset verifies the
# per-installation artifact catalog that delivers market purchases. A host
# without access keeps working; community-register retries it.
fetch_community_trusted_keys() {
  local keyset="${TEMP_DIR}/community-signing-keyset.json" base=${COMMUNITY_SERVICE_URL:-https://auth.cdnca.com}
  install -d -m 0700 "${CONFIG_DIR}/community"
  if download_json_verified "${base%/}/public/v1/signing-keyset" "${base%/}/public/v1/signing-keyset" "$keyset" \
    '.schema == "cdnca.signing-keyset/v2" and (.keys | type == "array" and length > 0)'; then
    jq '{keys: [.keys[] | {key_id, public_key}]}' "$keyset" >"${CONFIG_DIR}/community/trusted-keys.json"
    chmod 0400 "${CONFIG_DIR}/community/trusted-keys.json"
  else
    warn 'official signing keyset not reachable now; market purchases sync once it is fetched (rerun community-register)'
  fi
  write_upgrade_trust
}

# cdncaCE: control-api (ENTITLEMENT_TRUSTED_KEYS_FILE) and the native upgrade
# runner (configure-native-upgrade.py) need pinned public signing keys. The
# community edition is issued no lease and no upgrade grant; they get the
# official public keyset, or, offline, one public key whose private half is
# discarded here, so they trust no signed document at all.
write_upgrade_trust() {
  local target="${CONFIG_DIR}/entitlement-trusted-keys.json" scratch public
  if [ -s "${CONFIG_DIR}/community/trusted-keys.json" ]; then
    install -m 0400 "${CONFIG_DIR}/community/trusted-keys.json" "$target"
    return
  fi
  scratch=$(mktemp -d "${TEMP_DIR}/upgrade-trust.XXXXXX")
  "$ED25519_TOOL" genkey "${scratch}/discarded.key" || fail 'failed to generate the upgrade trust placeholder key'
  public=$("$ED25519_TOOL" pubkey "${scratch}/discarded.key" --der | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=\n')
  rm -rf "$scratch"
  [ ${#public} -eq 43 ] || fail 'generated upgrade trust placeholder key is invalid'
  jq -n --arg key "$public" '{keys: [{key_id: "cdnca-ce-no-upgrade-grants", public_key: $key}]}' >"$target"
  chmod 0400 "$target"
}


generate_ca() {
  local common_name=$1 key_file=$2 cert_file=$3
  # Extensions from a config file: "-addext" needs OpenSSL 1.1.1+.
  printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = ca' '[dn]' 'CN = Common Name' '[ca]' \
    'subjectKeyIdentifier = hash' 'basicConstraints = critical,CA:TRUE' 'keyUsage = critical,keyCertSign,cRLSign' \
    >"${TEMP_DIR}/ca-req.cnf"
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 -batch -config "${TEMP_DIR}/ca-req.cnf" \
    -subj "/CN=${common_name}" \
    -keyout "$key_file" -out "$cert_file" >/dev/null 2>&1
  rm -f -- "${TEMP_DIR}/ca-req.cnf"
  chmod 0600 "$key_file"
  chmod 0444 "$cert_file"
}

host_san() {
  local host=$1
  if [[ "$host" =~ ^[0-9]+(\.[0-9]+){3}$ || "$host" =~ ^[0-9A-Fa-f:]+$ ]]; then
    printf 'IP:%s' "$host"
  else
    printf 'DNS:%s' "$host"
  fi
}

issue_certificate() {
  local prefix=$1 common_name=$2 san=$3 eku=$4 ca_cert=$5 ca_key=$6
  openssl genrsa -out "${PKI_DIR}/${prefix}-key.pem" 2048 >/dev/null 2>&1
  chmod 0600 "${PKI_DIR}/${prefix}-key.pem"
  openssl req -new -sha256 -key "${PKI_DIR}/${prefix}-key.pem" \
    -subj "/CN=${common_name}" -out "${TEMP_DIR}/${prefix}.csr" >/dev/null 2>&1
  {
    printf '%s\n' 'basicConstraints=critical,CA:FALSE'
    printf '%s\n' 'keyUsage=critical,digitalSignature,keyEncipherment'
    printf 'extendedKeyUsage=%s\n' "$eku"
    printf 'subjectAltName=%s\n' "$san"
  } >"${TEMP_DIR}/${prefix}.ext"
  openssl x509 -req -sha256 -days 825 \
    -in "${TEMP_DIR}/${prefix}.csr" -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
    -extfile "${TEMP_DIR}/${prefix}.ext" -out "${PKI_DIR}/${prefix}.pem" >/dev/null 2>&1
  rm -f -- "${TEMP_DIR}/${prefix}.csr" "${TEMP_DIR}/${prefix}.ext" "${PKI_DIR}"/*.srl
  chmod 0444 "${PKI_DIR}/${prefix}.pem"
}

generate_pki() {
  log 'generating control, Gateway and node PKI'
  mkdir -p "$PKI_DIR" "$DOWNLOAD_DIR"
  chmod 0700 "$PKI_DIR"
  chmod 0755 "$DOWNLOAD_DIR"
  generate_ca 'CDNCA local control root' "${PKI_DIR}/root-ca-key.pem" "${PKI_DIR}/root-ca-cert.pem"
  generate_ca 'CDNCA Gateway client CA' "${PKI_DIR}/gateway-client-ca-key.pem" "${PKI_DIR}/gateway-client-ca-cert.pem"
  generate_ca 'CDNCA node CA' "${PKI_DIR}/node-ca-key.pem" "${PKI_DIR}/node-ca-cert.pem"
  issue_certificate control-internal-server localhost "$(control_internal_server_san)" serverAuth \
    "${PKI_DIR}/root-ca-cert.pem" "${PKI_DIR}/root-ca-key.pem"
  issue_certificate gateway-server "$GATEWAY_HOST" "$(host_san "$GATEWAY_HOST"),DNS:localhost,IP:127.0.0.1" serverAuth \
    "${PKI_DIR}/root-ca-cert.pem" "${PKI_DIR}/root-ca-key.pem"
  issue_certificate public-server "$CONTROL_DOMAIN" "$(host_san "$CONTROL_DOMAIN"),DNS:localhost,IP:127.0.0.1" serverAuth \
    "${PKI_DIR}/root-ca-cert.pem" "${PKI_DIR}/root-ca-key.pem"
  issue_certificate gateway-control-client 'cdnca-agent-gateway' \
    'URI:spiffe://cdn-platform/gateway/control' clientAuth \
    "${PKI_DIR}/gateway-client-ca-cert.pem" "${PKI_DIR}/gateway-client-ca-key.pem"
  if [ -n "$PUBLIC_CERT_FILE" ]; then
    [ -f "$PUBLIC_CERT_FILE" ] || fail 'public certificate file does not exist'
    [ -f "$PUBLIC_KEY_FILE" ] || fail 'public key file does not exist'
    openssl x509 -in "$PUBLIC_CERT_FILE" -noout >/dev/null 2>&1 || fail 'public certificate is invalid'
    # "pkey -check" needs OpenSSL 1.1.1+; "ec -check" covers EC keys on 1.0.2.
    openssl rsa -in "$PUBLIC_KEY_FILE" -check -noout >/dev/null 2>&1 ||
      openssl pkey -in "$PUBLIC_KEY_FILE" -check -noout >/dev/null 2>&1 ||
      openssl ec -in "$PUBLIC_KEY_FILE" -check -noout >/dev/null 2>&1 || fail 'public key is invalid'
    PUBLIC_CERT_PATH="${PKI_DIR}/public-cert.pem"
    PUBLIC_KEY_PATH="${PKI_DIR}/public-key.pem"
    install -m 0444 "$PUBLIC_CERT_FILE" "$PUBLIC_CERT_PATH"
    install -m 0600 "$PUBLIC_KEY_FILE" "$PUBLIC_KEY_PATH"
  else
    PUBLIC_CERT_PATH="${PKI_DIR}/public-server.pem"
    PUBLIC_KEY_PATH="${PKI_DIR}/public-server-key.pem"
  fi
  install -m 0644 "${PKI_DIR}/root-ca-cert.pem" "${DOWNLOAD_DIR}/gateway-ca.pem"
}

generate_runtime_secrets() {
  API_KEY_PEPPER_BASE64=$(openssl rand -base64 32 | tr -d '\n')
  DNS_CREDENTIAL_KEY_BASE64=$(openssl rand -base64 32 | tr -d '\n')
  ACCESS_TOKEN_SECRET=$(openssl rand -base64 48 | tr -d '\n')
  IMPERSONATION_HMAC_KEY_BASE64=$(openssl rand -base64 48 | tr -d '\n')
  OPENRESTY_SECURITY_SECRET_KEY_BASE64=$(openssl rand -base64 32 | tr -d '\n')
  OBSERVABILITY_LOG_CURSOR_KEY_BASE64=$(openssl rand -base64 32 | tr -d '\n')
  ANNOUNCEMENT_CURSOR_KEY_BASE64=$(openssl rand -base64 32 | tr -d '\n')
  JOB_QUERY_CURSOR_KEY_BASE64=$(openssl rand -base64 32 | tr -d '\n')
  CNAME_ALLOCATION_HMAC_KEY_BASE64=$(openssl rand -base64 32 | tr -d '\n')
  MFA_ENCRYPTION_KEY_BASE64=$(openssl rand -base64 32 | tr -d '\n')
  CUSTOM_RBAC_CURSOR_KEY_BASE64=$(openssl rand -base64 32 | tr -d '\n')
  CACHE_CONTROL_CURSOR_KEY_BASE64=$(openssl rand -base64 32 | tr -d '\n')
  CHALLENGE_POLICY_CURSOR_KEY_BASE64=$(openssl rand -base64 32 | tr -d '\n')
  CHALLENGE_POLICY_FACT_KEK_BASE64=$(openssl rand -base64 32 | tr -d '\n')
  IDENTITY_VERIFICATION_CURSOR_KEY_BASE64=$(openssl rand -base64 32 | tr -d '\n')
  CONTROL_BACKUP_RUN_CURSOR_KEY_BASE64=$(openssl rand -base64 32 | tr -d '\n')
  [ ${#API_KEY_PEPPER_BASE64} -ge 40 ] || fail 'failed to generate API key pepper'
  [ ${#DNS_CREDENTIAL_KEY_BASE64} -ge 40 ] || fail 'failed to generate DNS credential key'
  [ ${#IMPERSONATION_HMAC_KEY_BASE64} -ge 64 ] || fail 'failed to generate impersonation HMAC key'
  [ ${#OPENRESTY_SECURITY_SECRET_KEY_BASE64} -eq 44 ] || fail 'failed to generate OpenResty security secret key'
  [ ${#OBSERVABILITY_LOG_CURSOR_KEY_BASE64} -eq 44 ] || fail 'failed to generate observability log cursor key'
  [ ${#ANNOUNCEMENT_CURSOR_KEY_BASE64} -eq 44 ] || fail 'failed to generate announcement cursor key'
  [ ${#JOB_QUERY_CURSOR_KEY_BASE64} -eq 44 ] || fail 'failed to generate job query cursor key'
  [ ${#CNAME_ALLOCATION_HMAC_KEY_BASE64} -eq 44 ] || fail 'failed to generate CNAME allocation key'
  [ ${#MFA_ENCRYPTION_KEY_BASE64} -eq 44 ] || fail 'failed to generate MFA encryption key'
  [ ${#CUSTOM_RBAC_CURSOR_KEY_BASE64} -eq 44 ] || fail 'failed to generate custom RBAC cursor key'
  [ ${#CACHE_CONTROL_CURSOR_KEY_BASE64} -eq 44 ] || fail 'failed to generate cache control cursor key'
  [ ${#CHALLENGE_POLICY_CURSOR_KEY_BASE64} -eq 44 ] || fail 'failed to generate challenge policy cursor key'
  [ ${#CHALLENGE_POLICY_FACT_KEK_BASE64} -eq 44 ] || fail 'failed to generate challenge policy fact key'
  [ ${#IDENTITY_VERIFICATION_CURSOR_KEY_BASE64} -eq 44 ] || fail 'failed to generate identity verification cursor key'
  [ ${#CONTROL_BACKUP_RUN_CURSOR_KEY_BASE64} -eq 44 ] || fail 'failed to generate backup history cursor key'
}





verify_native_install_package() {
  # This verifier belongs to the installer, not to the untrusted download.
  python3 -I -B - "$1" "$2" "$3" "${4:-}" "$CDNCA_ED25519_TOOL_SHA256" <<'PY_NATIVE_CONTROL'
import base64, contextlib, datetime, hashlib, json, os, re, stat, struct, subprocess, sys, tarfile, tempfile
from pathlib import Path

OWNER = 0
SCHEMAS = ('cdnca.native-management.install/v1', 'cdnca.native-management.install/v2')
SMALL, ARCHIVE = 8 << 20, 285229182
MODES = {'native-management.tar': 0o600, 'source.bundle': 0o600,
         'release.manifest.json': 0o644, 'control-upgrade-runner': 0o755, 'analytics-history-bootstrap': 0o755,
         'nats-server': 0o755, 'NATS-LICENSE': 0o644, 'cdnca-ed25519': 0o755}
TOOL = 'cdnca-ed25519'

for name in ('install-ubuntu-dependencies.sh', 'configure-clickhouse.py', 'configure-nats.py',
             'native-nats-profile.json', 'install-rustfs.py', 'rustfs-1.0.1.json',
             'install-native-baseline.py', 'configure-control-runtime.py', 'configure-certificate-runtime.py', 'configure-native-upgrade.py'):
    MODES['scripts/native-runtime/' + name] = 0o755 if name.endswith('.sh') else 0o644
MODES['deploy/systemd/install-native-control-upgrade-runner.sh'] = 0o755
MODES['scripts/install-node.sh'] = 0o755
# ClickHouse migrations are not a fixed list: any contiguous 001..N set the
# signed manifest names (configure-clickhouse.py ledgers and applies them).
CLICKHOUSE_MIGRATION = re.compile(r'infra/clickhouse/migrations/([0-9]{3})_[a-z0-9]+(?:_[a-z0-9]+)*[.]up[.]sql')
LIMITS = {name: SMALL for name in MODES}
LIMITS.update({'native-management.tar': ARCHIVE, 'source.bundle': 512 << 20, 'control-upgrade-runner': ARCHIVE,
               'analytics-history-bootstrap': ARCHIVE, 'nats-server': ARCHIVE})
METADATA = {'install.manifest.json': SMALL, 'install.manifest.sig': 128}
ALLOWED_MODES = {**MODES, 'release.manifest.sig': 0o644}
LIMITS['release.manifest.sig'] = 128

def native_install_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON member')
        result[key] = value
    return result

@contextlib.contextmanager
def native_install_open(path, maximum):
    assert path.is_absolute() and str(path) == os.path.normpath(path)
    for parent in reversed((path.parent, *path.parent.parents)):
        info = parent.lstat()
        sticky = str(parent) in ('/tmp', '/private/tmp') and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        assert stat.S_ISDIR(info.st_mode) and info.st_uid in (0, OWNER) and (not info.st_mode & 0o022 or sticky)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        before = os.fstat(source.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_uid == OWNER and before.st_nlink == 1
        assert not before.st_mode & 0o7022 and 0 < before.st_size <= maximum
        yield source
        after = os.fstat(source.fileno())
        assert all(getattr(before, key) == getattr(after, key) for key in
                   ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def verify_native_install_manifest(encoded):
    manifest = json.loads(encoded, object_pairs_hook=native_install_pairs)
    assert type(manifest) is dict and set(manifest) == {'schema', 'key_id', 'version', 'built_at', 'source', 'platform', 'files'}
    assert manifest['schema'] in SCHEMAS
    modes = dict(MODES)
    if manifest['schema'] == SCHEMAS[1]:
        del modes['source.bundle']
        modes['release.manifest.sig'] = 0o644
    assert type(manifest['key_id']) is str and re.fullmatch(r'[A-Za-z0-9._-]{1,128}', manifest['key_id'])
    assert type(manifest['version']) is str and re.fullmatch(r'(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})', manifest['version'])
    assert type(manifest['built_at']) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z', manifest['built_at'])
    # fromisoformat (3.7+) on Python 3.6: the regex fixed the shape, check the values.
    datetime.datetime(*map(int, re.match(r'(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)', manifest['built_at']).groups()))
    # An initial baseline (1.0.35) has no predecessor and therefore no previous_commit.
    assert type(manifest['source']) is dict and set(manifest['source']) in ({'commit', 'tree'}, {'commit', 'tree', 'previous_commit'})
    assert all(type(value) is str and re.fullmatch(r'[0-9a-f]{40}', value) for value in manifest['source'].values())
    assert manifest['source']['commit'] != manifest['source'].get('previous_commit')
    assert manifest['platform'] == {'os': 'linux', 'arch': 'amd64'}
    assert type(manifest['files']) is list
    migrations = [item.get('path') for item in manifest['files'] if type(item) is dict and type(item.get('path')) is str and
                  item['path'].startswith('infra/clickhouse/')]
    assert migrations and all(CLICKHOUSE_MIGRATION.fullmatch(name) and int(CLICKHOUSE_MIGRATION.fullmatch(name)[1]) == index
                              for index, name in enumerate(migrations, 1))
    modes.update({name: 0o644 for name in migrations})
    assert len(manifest['files']) == len(modes)
    previous, inventory = '', {}
    for item in manifest['files']:
        assert type(item) is dict and set(item) == {'path', 'bytes', 'mode', 'sha256'}
        name = item['path']
        assert type(name) is str and name in modes and name > previous
        assert type(item['bytes']) is int and 0 < item['bytes'] <= LIMITS.get(name, SMALL)
        assert type(item['mode']) is int and item['mode'] == modes[name]
        assert type(item['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', item['sha256'])
        inventory[name], previous = item, name
    assert set(inventory) == set(modes)
    return manifest, inventory

def native_install_verify_signature(tool, keys, key_id, domain, encoded, encoded_signature, scratch):
    keyfile, signature, message = (Path(scratch) / name for name in ('public.pem', 'signature', 'message'))
    keyfile.write_text(keys[key_id], encoding='ascii')
    assert 0 < len(encoded_signature) <= 128
    encoded_signature = encoded_signature[:-1] if encoded_signature.endswith(b'\n') else encoded_signature
    decoded = base64.b64decode(encoded_signature, validate=True)
    assert len(decoded) == 64 and base64.b64encode(decoded) == encoded_signature
    signature.write_bytes(decoded)
    message.write_bytes(domain + encoded)
    subprocess.run([str(tool), 'verify', str(keyfile), str(message), str(signature)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})

try:
    assert os.geteuid() == OWNER
    archive, trust_path, destination = map(Path, sys.argv[1:4])
    required_schema = sys.argv[4] if len(sys.argv) > 4 else ''
    tool_sha256 = sys.argv[5] if len(sys.argv) > 5 else ''
    assert re.fullmatch(r'[0-9a-f]{64}', tool_sha256)
    assert not required_schema or required_schema in SCHEMAS
    assert destination.is_absolute() and str(destination) == os.path.normpath(destination)
    assert not os.path.lexists(destination) and destination.parent == archive.parent
    assert stat.S_IMODE(destination.parent.lstat().st_mode) == 0o700
    with native_install_open(trust_path, 65536) as source:
        trust = json.loads(source.read(), object_pairs_hook=native_install_pairs)
    assert type(trust) is dict and set(trust) == {'version', 'keys'} and type(trust['version']) is int and trust['version'] == 1
    assert type(trust['keys']) is list and 0 < len(trust['keys']) <= 32
    keys = {}
    for key in trust['keys']:
        assert type(key) is dict and set(key) == {'key_id', 'public_key_pem'}
        assert type(key['key_id']) is str and re.fullmatch(r'[A-Za-z0-9._-]{1,128}', key['key_id']) and key['key_id'] not in keys
        assert type(key['public_key_pem']) is str and 0 < len(key['public_key_pem']) <= 4096
        match = re.fullmatch(r'-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)-----END PUBLIC KEY-----\n?', key['public_key_pem'])
        assert match
        public = base64.b64decode(match[1].replace('\n', ''), validate=True)
        assert len(public) == 44 and public[:12] == bytes.fromhex('302a300506032b6570032100')
        keys[key['key_id']] = key['public_key_pem']
    with native_install_open(archive, 1 << 30) as raw:
        assert os.fstat(raw.fileno()).st_size % 512 == 0
        members, metadata = {}, {}
        while True:
            header = raw.read(512)
            assert len(header) == 512
            if header == bytes(512):
                assert raw.read(512) == bytes(512)
                for padding in iter(lambda: raw.read(65536), b''):
                    assert not any(padding)
                break
            assert header[257:265] == b'ustar\x0000' and header[156:157] in (b'0', b'\0')
            for offset, width in ((100, 8), (108, 8), (116, 8), (124, 12), (136, 12), (148, 8), (329, 8), (337, 8)):
                assert re.fullmatch(rb'[0-7 \x00]+', header[offset:offset + width])
            member = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
            name = member.name
            assert name in ALLOWED_MODES or name in METADATA or CLICKHOUSE_MIGRATION.fullmatch(name)
            assert name not in members and not member.linkname and member.uid == member.gid == member.mtime == 0
            assert member.mode == ALLOWED_MODES.get(name, 0o644) and 0 < member.size <= LIMITS.get(name, METADATA.get(name, SMALL))
            start, digest, remaining, body, head = raw.tell(), hashlib.sha256(), member.size, bytearray(), b''
            while remaining:
                chunk = raw.read(min(65536, remaining))
                assert chunk
                digest.update(chunk)
                head = (head + chunk)[:64]
                if name in METADATA or name in ('release.manifest.json', 'release.manifest.sig', TOOL):
                    body.extend(chunk)
                remaining -= len(chunk)
            padding = (512 - member.size % 512) % 512
            assert raw.read(padding) == bytes(padding)
            members[name] = (start, member.size, member.mode, digest.hexdigest())
            if name in METADATA or name in ('release.manifest.json', 'release.manifest.sig', TOOL):
                metadata[name] = bytes(body)
            if name in ('control-upgrade-runner', 'analytics-history-bootstrap', 'nats-server'):
                assert len(head) == 64 and head[:7] == b'\x7fELF\x02\x01\x01'
                assert struct.unpack_from('<H', head, 16)[0] in (2, 3) and struct.unpack_from('<H', head, 18)[0] == 62
        manifest, inventory = verify_native_install_manifest(metadata['install.manifest.json'])
        assert not required_schema or manifest['schema'] == required_schema
        assert set(members) == set(inventory) | set(METADATA)
        for name, item in inventory.items():
            assert members[name][1:] == (item['bytes'], item['mode'], item['sha256'])
        sidecar = json.loads(metadata['release.manifest.json'], object_pairs_hook=native_install_pairs)
        signed = manifest['schema'] == SCHEMAS[1]
        assert type(sidecar) is dict and set(sidecar) == {'schema', 'version', 'built_at', 'source', 'platform', 'files'} | ({'key_id'} if signed else set())
        assert sidecar['schema'] == ('cdnca.native-management.release/v2' if signed else 'cdnca.native-management.release/v1')
        assert type(sidecar['files']) is list and sidecar['files']
        assert all(sidecar[name] == manifest[name] for name in ('version', 'built_at', 'source', 'platform'))
        # The signature tool travels inside the package it verifies, so it is
        # trusted only by this installer's own pin, checked before it executes.
        assert hashlib.sha256(metadata[TOOL]).hexdigest() == tool_sha256 == inventory[TOOL]['sha256']
        with tempfile.TemporaryDirectory(prefix='.native-install-verify-', dir=archive.parent) as scratch:
            tool = Path(scratch) / TOOL
            with os.fdopen(os.open(tool, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500), 'wb') as output:
                output.write(metadata[TOOL])
                output.flush()
                os.fsync(output.fileno())
            native_install_verify_signature(tool, keys, manifest['key_id'], (manifest['schema'] + '\n').encode(),
                                            metadata['install.manifest.json'], metadata['install.manifest.sig'], scratch)
            if signed:
                assert type(sidecar['key_id']) is str and re.fullmatch(r'[A-Za-z0-9._-]{1,128}', sidecar['key_id'])
                native_install_verify_signature(tool, keys, sidecar['key_id'], b'cdnca.native-management.release/v2\n',
                                                metadata['release.manifest.json'], metadata['release.manifest.sig'], scratch)
        # No member is extracted (and no helper is executed) until all checks pass.
        destination.mkdir(mode=0o700)
        for name, (start, size, mode, expected) in members.items():
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            raw.seek(start)
            digest, remaining = hashlib.sha256(), size
            with os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), 'wb') as output:
                os.fchmod(output.fileno(), mode)
                while remaining:
                    chunk = raw.read(min(65536, remaining))
                    assert chunk
                    digest.update(chunk)
                    output.write(chunk)
                    remaining -= len(chunk)
                output.flush()
                os.fsync(output.fileno())
            assert digest.hexdigest() == expected
    print(json.dumps({'status': 'signed_install_package_verified', 'schema': manifest['schema'], 'version': manifest['version'], 'source': manifest['source']}))
except Exception:
    print('native install package rejected; no downloaded code was executed', file=sys.stderr)
    sys.exit(1)
PY_NATIVE_CONTROL
}

# The authorization server only serves the master package to the license's
# registered master IP (or a valid 授权IP下载文件 IP). Probe once so a refusal is
# reported in plain Chinese instead of a generic download failure.
check_master_download_authorization() {
  local url code body observed='' denied=0 total=0
  body="${TEMP_DIR}/master-download-probe"
  for url in "$@"; do
    total=$((total + 1))
    rm -f -- "$body"
    code=$(curl -q --proto '=https' --proto-redir '=https' -s --connect-timeout 10 --max-time 30 \
      --max-filesize 65536 -o "$body" -w '%{http_code}' "$url") || code=000
    if [ "$code" = 403 ]; then
      denied=$((denied + 1))
      [ -n "$observed" ] || observed=$(grep -Eo '公网 IP [0-9A-Fa-f:.]+' "$body" 2>/dev/null | head -n 1 | sed 's/^公网 IP //' || true)
    else
      return 0
    fi
  done
  [ "$denied" -eq "$total" ] || return 0
  printf '[cdnca-control] 错误：授权服务器拒绝向本机下载主控安装包（HTTP 403）。\n' >&2
  [ -z "$observed" ] || printf '[cdnca-control] 授权服务器看到的本机公网 IP：%s\n' "$observed" >&2
  printf '[cdnca-control] 请在授权门户“我的授权”确认主控 IP 与本机出口 IP 一致；迁移或换机时在“授权IP下载文件”填写本机 IP 后重试。\n' >&2
  fail 'master_download_ip_not_registered'
}

download_native_support() {
  local archive="$TEMP_DIR/cdnca-control-native.tar" trust="$TEMP_DIR/native-install-trust.json" required_schema=cdnca.native-management.install/v2
  log 'downloading one signed management, Gateway, Web and runtime-support release'
  if [ -n "$CONTROL_NATIVE_FILE" ]; then
    [ -f "$CONTROL_NATIVE_FILE" ] && [ ! -L "$CONTROL_NATIVE_FILE" ] || fail 'local package must be a regular file'
    install -m 0600 "$CONTROL_NATIVE_FILE" "$archive"
    trust=$CONTROL_NATIVE_TRUST_FILE
    required_schema=''
  else
    download_json_verified "$CONTROL_NATIVE_TRUST_URL" "$CONTROL_NATIVE_TRUST_FALLBACK_URL" "$trust" \
      '.version == 1 and (.keys | type == "array" and length > 0)' || fail 'unable to fetch native release trust'
    download_verified "$CONTROL_NATIVE_URL" "$CONTROL_NATIVE_FALLBACK_URL" \
      "$CONTROL_NATIVE_SHA256_URL" "$CONTROL_NATIVE_SHA256_FALLBACK_URL" "$archive" 'cdnca-control-native.tar' 'native management'
  fi
  NATIVE_SUPPORT="$TEMP_DIR/native-support"
  verify_native_install_package "$archive" "$trust" "$NATIVE_SUPPORT" "$required_schema" >"$TEMP_DIR/native-install-facts.json" ||
    fail 'native installation package failed verification; nothing was installed'
  NATIVE_ARTIFACT_TRUST_FILE=$trust
  install_ed25519_tool "$NATIVE_SUPPORT/cdnca-ed25519"
}

# Publish the verified tool at its fixed root-only path (helpers call nothing
# else) and next to the node artifacts, where install-node.sh pins the same hash.
install_ed25519_tool() {
  local source=$1
  [ -f "$source" ] && [ ! -L "$source" ] && [ "$(sha256sum "$source" | awk '{print $1}')" = "$CDNCA_ED25519_TOOL_SHA256" ] ||
    fail 'the Ed25519 tool differs from the installer pin'
  if [ -e "$ED25519_TOOL" ] || [ -L "$ED25519_TOOL" ]; then
    [ -f "$ED25519_TOOL" ] && [ ! -L "$ED25519_TOOL" ] && [ "$(stat -c '%u:%a:%h' "$ED25519_TOOL")" = 0:555:1 ] &&
      [ "$(sha256sum "$ED25519_TOOL" | awk '{print $1}')" = "$CDNCA_ED25519_TOOL_SHA256" ] ||
      fail "existing ${ED25519_TOOL} differs; refusing to replace it"
  else
    install -d -m 0755 "$(dirname "$ED25519_TOOL")"
    install -m 0555 "$source" "$ED25519_TOOL"
  fi
  [ "$("$ED25519_TOOL" --version)" = 'cdnca-ed25519 1' ] || fail 'the Ed25519 tool does not run on this host'
}

# Fetch one portable runtime archive named by the signed dependency helper and
# accept it only with the helper's pinned SHA-256.
fetch_runtime_archive() {
  local name=$1 sha256=$2 output=$3 base
  [[ "$name" =~ ^[A-Za-z0-9._-]+$ && "$sha256" =~ ^[0-9a-f]{64}$ ]] || fail 'invalid runtime archive requirement'
  for base in "$RUNTIME_ARCHIVE_URL" "$RUNTIME_ARCHIVE_FALLBACK_URL"; do
    rm -f -- "$output"
    progress_download "$name" curl --proto '=https' --proto-redir '=https' -fL --connect-timeout 10 --max-time 900 --max-filesize 536870912 \
      --retry 1 --output "$output" "$base/$name" || continue
    [ "$(sha256sum "$output" | awk '{print $1}')" = "$sha256" ] && return 0
  done
  fail "runtime archive $name could not be downloaded with the pinned SHA-256 from ${RUNTIME_ARCHIVE_URL}"
}

configure_runtime_dependencies() {
  local runtime="$NATIVE_SUPPORT/scripts/native-runtime" action=install archive="$TEMP_DIR/rustfs.zip" url
  local kind name sha256
  local -a inputs=()
  [ "$SKIP_DEPENDENCIES" = false ] || action=check
  if [ "$action" = install ]; then
    while read -r kind name sha256; do
      case "$kind" in postgresql|clamav) ;; *) fail 'unknown runtime archive requirement' ;; esac
      fetch_runtime_archive "$name" "$sha256" "$TEMP_DIR/$name"
      inputs+=("--$kind-archive" "$TEMP_DIR/$name")
    done < <(bash "$runtime/install-ubuntu-dependencies.sh" requirements)
  fi
  # ${inputs[@]+...}: bash 4.2 (CentOS 7) treats an empty array as unset under set -u.
  progress_run '安装 PostgreSQL、ClickHouse、Redis、ClamAV、nginx 等依赖（约 3–8 分钟）' \
    bash "$runtime/install-ubuntu-dependencies.sh" "$action" ${inputs[@]+"${inputs[@]}"}
  # 依赖已装完并就绪：之后失败时 --cleanup-failed 保留依赖软件包与配置，重装走 helper 的已装分支。
  control_install_state_add step=dependencies_ready
  if [ -e /etc/cdnca-analytics ] || [ -L /etc/cdnca-analytics ]; then
    python3 -I -B "$runtime/configure-clickhouse.py" preflight
    # Ledgered and idempotent: applies only this package's not yet applied migrations.
    python3 -I -B "$runtime/configure-clickhouse.py" migrate --migrations "$NATIVE_SUPPORT/infra/clickhouse/migrations"
  else
    # The helper refuses an existing cdnca_analytics database or users; from here they belong to this install.
    control_install_state_add "created=clickhouse:${CH_TCP_PORT}"
    progress_run '初始化 ClickHouse' python3 -I -B "$runtime/configure-clickhouse.py" install --migrations "$NATIVE_SUPPORT/infra/clickhouse/migrations"
  fi
  url=$(jq -er '.archive_url | select(startswith("https://"))' "$runtime/rustfs-1.0.1.json")
  progress_download RustFS curl --proto '=https' --proto-redir '=https' -fL --connect-timeout 10 --max-time 600 --max-filesize 300000000 \
    --retry 1 --output "$archive" "$url"
  # The signed helper pins both the ZIP and the binary, and never resets state.
  if [ -e /etc/cdnca-objectstore ] || [ -L /etc/cdnca-objectstore ]; then
    python3 -I -B "$runtime/install-rustfs.py" preflight --archive "$archive"
  else
    progress_run '安装 RustFS 对象存储' python3 -I -B "$runtime/install-rustfs.py" install --archive "$archive"
  fi
  bash "$runtime/install-ubuntu-dependencies.sh" check
}

prepare_native_baseline() {
  local manifest="$NATIVE_SUPPORT/install.manifest.json" git_dir="$TEMP_DIR/source.git" commit version schema
  commit=$(jq -er .source.commit "$manifest")
  schema=$(jq -er .schema "$manifest")
  if [ "$schema" = cdnca.native-management.install/v1 ]; then
    # Ignore the host Git configuration and import only the authenticated bundle.
    export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_COUNT=0
    [ "$(git --no-replace-objects bundle list-heads "$NATIVE_SUPPORT/source.bundle")" = "$commit HEAD" ] ||
      fail 'native source bundle has unexpected advertised references'
    git init --bare --template= "$git_dir" >"$TEMP_DIR/source-import.log" 2>&1
    git --no-replace-objects --git-dir="$git_dir" bundle verify "$NATIVE_SUPPORT/source.bundle" >>"$TEMP_DIR/source-import.log" 2>&1
    git --no-replace-objects --git-dir="$git_dir" bundle unbundle "$NATIVE_SUPPORT/source.bundle" >>"$TEMP_DIR/source-import.log" 2>&1
    git --no-replace-objects --git-dir="$git_dir" update-ref refs/heads/baseline "$commit"
    git --no-replace-objects --git-dir="$git_dir" symbolic-ref HEAD refs/heads/baseline
  else
    [ "$schema" = cdnca.native-management.install/v2 ] || fail 'unsupported native installation schema'
  fi
  jq --arg support "$NATIVE_SUPPORT" --arg source_git "$git_dir" --arg artifact_trust_file "${NATIVE_ARTIFACT_TRUST_FILE:-}" '
    . as $root | .schema as $schema |
    (.files | map({key:.path, value:.}) | from_entries) as $files |
    {schema:"cdnca.native-management.baseline-input/v1", archive:($support+"/native-management.tar"),
     archive_sha256:$files["native-management.tar"].sha256, archive_bytes:$files["native-management.tar"].bytes,
     manifest:($support+"/release.manifest.json"), manifest_sha256:$files["release.manifest.json"].sha256,
     source_commit:.source.commit, source_tree:.source.tree,
     version:.version, runner:($support+"/control-upgrade-runner"),
     runner_sha256:$files["control-upgrade-runner"].sha256,
     installation_id_file:"/etc/cdnca-upgrade/installation-id", runner_environment_file:"/etc/cdnca-upgrade/runner-input.env"} +
    (if $root.source | has("previous_commit") then {previous_source_commit:$root.source.previous_commit} else {} end) |
    if $schema == "cdnca.native-management.install/v2" then
      . + {schema:"cdnca.native-management.baseline-input/v2", artifact_trust_file:$artifact_trust_file}
    else . + {source_git:$source_git} end' \
    "$manifest" >"$TEMP_DIR/native-baseline-input.json"
  chmod 0600 "$TEMP_DIR/native-baseline-input.json"
  python3 -I -B "$NATIVE_SUPPORT/scripts/native-runtime/install-native-baseline.py" check \
    --inputs "$TEMP_DIR/native-baseline-input.json" --stage-directory "$TEMP_DIR/native-stage"
  CONTROL_BINARY="$TEMP_DIR/native-stage/bin/control-api"
  version=$("$CONTROL_BINARY" --version) || fail 'verified control binary has no compiled version'
  [ "$version" = "$(jq -er .version "$manifest")" ] || fail 'compiled control version differs from the signed package'
  [ -z "$CONTROL_VERSION" ] || [ "$CONTROL_VERSION" = "$version" ] || fail '--control-version differs from the signed package'
  CONTROL_VERSION=$version
  PROGRESS_VERSION=$version
  progress_line "安装版本 ${version}"
}

configure_control_runtime() {
  python3 -I -B "$NATIVE_SUPPORT/scripts/native-runtime/configure-control-runtime.py" install
  python3 -I -B "$NATIVE_SUPPORT/scripts/native-runtime/configure-certificate-runtime.py" install "$CERTIFICATE_EMAIL"
  # Retain package-signing trust and add only this installation's public publisher key.
  jq -s -e 'select(length == 2 and all(.[]; .version == 1 and (.keys | type == "array"))) |
    [.[].keys[]] as $keys | select(($keys | map(.key_id) | unique | length) == ($keys | length)) |
    {version:1,keys:$keys}' "$DOWNLOAD_DIR/edge-agent/artifacts.json" "$CONFIG_DIR/runtime-publisher-trust.json" \
    >"$TEMP_DIR/combined-artifact-trust.json" || fail 'publisher and package trust keys conflict'
  install -m 0644 "$TEMP_DIR/combined-artifact-trust.json" "$DOWNLOAD_DIR/edge-agent/artifacts.json"
}

setup_native_upgrade() {
  local -a artifact_options=()
  if [ "$(jq -er .schema "$TEMP_DIR/native-baseline-input.json")" = cdnca.native-management.baseline-input/v2 ]; then
    # The upgrade configurator rejects any world-writable ancestor, so a trust
    # file downloaded under /tmp must be read from the root-private response dir.
    install -m 0600 "$NATIVE_ARTIFACT_TRUST_FILE" "${RESPONSE_DIR}/native-artifact-trust.json"
    artifact_options=(--artifact-trust-file "${RESPONSE_DIR}/native-artifact-trust.json")
  fi
  # An operator certificate the system store cannot verify (same rule as the
  # local self-checks) becomes the runner's console-index CA; otherwise the
  # runner keeps the system roots and never trusts the private CA for it.
  if [ -n "$PUBLIC_CERT_FILE" ] && [ -n "$(public_https_trust_args)" ]; then
    artifact_options+=(--web-ca-file "$PUBLIC_CERT_PATH")
  elif [ -z "$PUBLIC_CERT_FILE" ] && control_domain_is_ip; then
    # An IP-literal console is served with the private root CA's certificate
    # (issue_public_certificate): the runner's console-index check trusts it.
    artifact_options+=(--web-ca-file "${PKI_DIR}/root-ca-cert.pem")
  fi
  python3 -I -B "$NATIVE_SUPPORT/scripts/native-runtime/configure-native-upgrade.py" prepare \
    --installation-id "$INSTALLATION_ID" --web-index-url "$CONTROL_ORIGIN/dashboard/" "${artifact_options[@]}"
  python3 -I -B "$NATIVE_SUPPORT/scripts/native-runtime/install-native-baseline.py" install --inputs "$TEMP_DIR/native-baseline-input.json"
  bash "$NATIVE_SUPPORT/deploy/systemd/install-native-control-upgrade-runner.sh" --install \
    --binary "$NATIVE_SUPPORT/control-upgrade-runner" \
    --binary-sha256 "$(jq -er .runner_sha256 "$TEMP_DIR/native-baseline-input.json")" \
    --environment /etc/cdnca-upgrade/runner-input.env \
    --baseline-sha256 "$(jq -er .archive_sha256 "$TEMP_DIR/native-baseline-input.json")"
  CONTROL_BINARY="$NATIVE_ROOT/current/bin/control-api"
}

download_nats_binaries() {
  local architecture binary expected
  architecture=$(host_architecture)
  binary="$NATIVE_SUPPORT/nats-server"
  expected=$(jq -er --arg version "$NATS_SERVER_VERSION" \
    'select(.server_version == $version) | .server_artifact.sha256 | select(type == "string" and test("^[a-f0-9]{64}$"))' \
    "$NATIVE_SUPPORT/scripts/native-runtime/native-nats-profile.json") || fail 'signed NATS dependency pin is missing'
  [ -f "$binary" ] && [ ! -L "$binary" ] && [ "$(stat -c '%u:%a:%h' "$binary")" = 0:755:1 ] &&
    [ "$(sha256sum "$binary" | awk '{print $1}')" = "$expected" ] || fail 'signed NATS dependency differs'
  if [ -e "$NATS_SERVER_BIN" ] || [ -L "$NATS_SERVER_BIN" ]; then
    [ -f "$NATS_SERVER_BIN" ] && [ ! -L "$NATS_SERVER_BIN" ] &&
      [ "$(stat -c '%u:%a:%h' "$NATS_SERVER_BIN")" = 0:755:1 ] &&
      [ "$(sha256sum "$NATS_SERVER_BIN" | awk '{print $1}')" = "$expected" ] || fail 'existing NATS binary differs; use the controlled upgrade procedure'
  else
    log 'installing local NATS server from the signed complete package'
    install -m 0755 "$binary" "$NATS_SERVER_BIN"
  fi
  [ "$("$NATS_SERVER_BIN" --version)" = "nats-server: v$NATS_SERVER_VERSION" ] || fail 'signed NATS version differs'
  install -m 0644 "$NATIVE_SUPPORT/NATS-LICENSE" "$CONFIG_DIR/NATS-LICENSE"
  if [ ! -x "$NATS_CLI_BIN" ]; then
    log 'downloading NATS CLI'
    download_verified "$NATS_CLI_URL" "$NATS_CLI_URL" "$NATS_CLI_SHA256_URL" "$NATS_CLI_SHA256_URL" \
      "${TEMP_DIR}/nats-cli.zip" "nats-${NATS_CLI_VERSION}-linux-${architecture}.zip" 'NATS CLI'
    assert_not_html "${TEMP_DIR}/nats-cli.zip" 'NATS CLI'
    mkdir -p "${TEMP_DIR}/nats-cli"
    unzip -q "${TEMP_DIR}/nats-cli.zip" -d "${TEMP_DIR}/nats-cli"
    binary=$(find "${TEMP_DIR}/nats-cli" -type f -name nats -perm -u+x -print -quit)
    [ -n "$binary" ] || fail 'nats CLI binary is missing from the release archive'
    install -m 0755 "$binary" "$NATS_CLI_BIN"
  fi
}

download_node_assets() {
  log 'publishing node installer and signed edge artifacts'
  mkdir -p "$DOWNLOAD_DIR/edge-agent/latest"
  chmod 0755 "$DOWNLOAD_DIR" "$DOWNLOAD_DIR/edge-agent" "$DOWNLOAD_DIR/edge-agent/latest"
  install -m 0644 "$NATIVE_SUPPORT/scripts/install-node.sh" "${DOWNLOAD_DIR}/install-node.sh"
  # install-node.sh pins the same hash before executing its download.
  install -m 0644 "$ED25519_TOOL" "${DOWNLOAD_DIR}/edge-agent/cdnca-ed25519"
  local checksum_file="${DOWNLOAD_DIR}/edge-agent/latest/SHA256SUMS"
  download_verified "$EDGE_AGENT_URL" "$EDGE_AGENT_FALLBACK_URL" "$EDGE_AGENT_SHA256_URL" \
    "$EDGE_AGENT_SHA256_FALLBACK_URL" "${DOWNLOAD_DIR}/edge-agent/latest/cdnca-edge-agent.tar.gz" \
    'cdnca-edge-agent.tar.gz' 'edge-agent' "$checksum_file"
  assert_not_html "${DOWNLOAD_DIR}/edge-agent/latest/cdnca-edge-agent.tar.gz" 'edge-agent'
  tar -tzf "${DOWNLOAD_DIR}/edge-agent/latest/cdnca-edge-agent.tar.gz" >/dev/null ||
    fail 'edge-agent download is not a valid tar archive'
  local trust_file="${DOWNLOAD_DIR}/edge-agent/artifacts.json"
  download_json_verified "$EDGE_ARTIFACT_TRUST_URL" "$EDGE_ARTIFACT_TRUST_FALLBACK_URL" "$trust_file" \
    '.version == 1 and (.keys | type == "array" and length > 0)' ||
    fail 'unable to download a valid edge artifact trust manifest'
  chmod 0644 "$trust_file"
  # The verified checksum file is copied beside the matching archive; the node
  # installer must never receive a checksum from a different origin pair.
  chmod 0644 "$checksum_file" "${DOWNLOAD_DIR}/edge-agent/latest/cdnca-edge-agent.tar.gz"
  CDNCA_ED25519_TOOL_PATH="$ED25519_TOOL" bash "$NATIVE_SUPPORT/scripts/install-node.sh" --verify-native-package \
    "$DOWNLOAD_DIR/edge-agent/latest/cdnca-edge-agent.tar.gz" "$trust_file" "$TEMP_DIR/node-preflight" \
    >"$TEMP_DIR/node-release-facts.json" || fail 'node package signature verification failed before installation'
  jq -e --argjson source "$(jq -c .source "$NATIVE_SUPPORT/install.manifest.json")" --arg version "$CONTROL_VERSION" \
    '.version == $version and .source.commit == $source.commit and .source.tree == $source.tree' \
    "$TEMP_DIR/node-release-facts.json" >/dev/null || fail 'node and management packages must come from the same source and version'
}

# Node upgrade trust. Two root-only Ed25519 keys sign every upgrade execution
# (control and edge domains must differ). Their public halves and the artifact
# download policy are published as cdnca.edge-upgrade-trust/v1; the copied node
# command pins its SHA-256, so the document needs no signature of its own. It
# also carries the signer revocation offline root pin (signer_trust_root) when
# one was given, so nodes verify signer-trust.json against it, and the
# artifacts.json keys as they stand once configure_control_runtime has added
# the publisher key (artifact_trust): nodes accept no artifact key outside it
# or the offline-root-verified signer trust document, so it runs after that step.
# Nodes download upgrade artifacts from this control plane: control-api caches
# each license-signed artifact under ${DOWNLOAD_DIR}/edge-agent/upgrades/sha256
# (verified against the signed digest and size) and points executions there,
# so nodes never contact the licensing server. root_ca "system" means the
# node's own OS trust bundle (public WebPKI certificate); otherwise the
# document embeds the root of upgrade_download_root_ca_file. The document is
# built by control-api from control.env (download host/port from
# CONTROL_UPGRADE_ARTIFACT_BASE_URL, root from CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE,
# addresses resolved now): the same implementation republishes it after a
# migration restore, with node-install-defaults and runtime-config.js.
publish_upgrade_trust() {
  local control_key="${UPGRADE_KEY_DIR}/control-execution.pem" edge_key="${UPGRADE_KEY_DIR}/edge-execution.pem"
  [ ! -e "$UPGRADE_KEY_DIR" ] && [ ! -L "$UPGRADE_KEY_DIR" ] || fail 'upgrade signing keys already exist; refusing to replace them'
  install -d -m 0700 "$UPGRADE_KEY_DIR"
  "$ED25519_TOOL" genkey "$control_key" || fail 'failed to generate the control upgrade signing key'
  "$ED25519_TOOL" genkey "$edge_key" || fail 'failed to generate the edge upgrade signing key'
  chmod 0400 "$control_key" "$edge_key"
  "$ED25519_TOOL" pubkey "$control_key" >"$TEMP_DIR/control-execution.pub.pem" &&
    "$ED25519_TOOL" pubkey "$edge_key" >"$TEMP_DIR/edge-execution.pub.pem" ||
    fail 'failed to derive upgrade signing public keys'
  ! cmp -s "$TEMP_DIR/control-execution.pub.pem" "$TEMP_DIR/edge-execution.pub.pem" || fail 'upgrade signing keys must be distinct'
  install -d -m 0755 "${DOWNLOAD_DIR}/edge-agent/upgrades" "${DOWNLOAD_DIR}/edge-agent/upgrades/sha256"
  # artifact_trust pins artifacts.json after configure_control_runtime added
  # the publisher key; the signer revocation offline root comes from control.env
  # (signer_revocation_environment, --signer-revocation-offline-root-*).
  UPGRADE_TRUST_SHA256=$("$CONTROL_BINARY" native-backup publish-node-install-trust) ||
    fail 'failed to build the node upgrade trust document (control-plane domain resolution, root CA or artifact keys)'
  [[ "$UPGRADE_TRUST_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail 'node upgrade trust was not published'
  [ "$(sha256sum "${DOWNLOAD_DIR}/edge-agent/upgrade-trust.json" | awk '{print $1}')" = "$UPGRADE_TRUST_SHA256" ] ||
    fail 'published node upgrade trust does not match its digest'
}

# Plugin webhook publication attestation key (migration 084). Generated on
# every install so enabling PLUGIN_WEBHOOK_RUNTIME_ENABLED never starts with an
# empty key; rotation: docs/runbooks/plugin-webhook-key.md.
generate_plugin_webhook_attestation_key() {
  local key="${KEY_DIR}/plugin-webhook-attestation-v1.pem"
  [ ! -e "$key" ] && [ ! -L "$key" ] || fail 'plugin webhook attestation key already exists; refusing to replace it'
  "$ED25519_TOOL" genkey "$key" || fail 'failed to generate the plugin webhook attestation key'
  chmod 0400 "$key"
  "$ED25519_TOOL" pubkey "$key" >/dev/null || fail 'generated plugin webhook attestation key is invalid'
}

write_web_runtime_config() {
  local gateway_address gateway_enrollment server_name licensing licensing_fallback
  grep -Fq '/runtime-config.js' "${WEB_ROOT}/index.html" || fail 'control web release does not load runtime configuration'
  [[ "$UPGRADE_TRUST_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail 'node upgrade trust was not published'
  gateway_address=$(jq -Rn --arg value "${GATEWAY_HOST}:${GATEWAY_AGENT_PORT}" '$value')
  gateway_enrollment=$(jq -Rn --arg value "${GATEWAY_HOST}:${GATEWAY_ENROLLMENT_PORT}" '$value')
  server_name=$(jq -Rn --arg value "$GATEWAY_HOST" '$value')
  licensing=$(jq -Rn --arg value "$LICENSING_SERVER" '$value')
  licensing_fallback=$(jq -Rn --arg value "$LICENSING_SERVER_FALLBACK" '$value')
  cat >"${DATA_DIR}/runtime-config.js" <<EOF
window.__CDNCA_GATEWAY_ADDRESS__ = ${gateway_address};
window.__CDNCA_GATEWAY_ENROLLMENT_ADDRESS__ = ${gateway_enrollment};
window.__CDNCA_GATEWAY_SERVER_NAME__ = ${server_name};
window.__CDNCA_LICENSING_SERVER__ = ${licensing};
window.__CDNCA_LICENSING_SERVER_FALLBACK__ = ${licensing_fallback};
window.__CDNCA_DOWNLOAD_FALLBACK_ORIGIN__ = ${licensing};
window.__CDNCA_NODE_UPGRADE_TRUST_SHA256__ = "${UPGRADE_TRUST_SHA256}";
EOF
  chmod 0644 "${DATA_DIR}/runtime-config.js"
  write_node_install_defaults
}

# Read by install-node.sh for the short copied command
# (`curl ... | bash -s -- --control-plane <console> --token <token>`).
write_node_install_defaults() {
  local gateway_host=$GATEWAY_HOST fallback=""
  case "$gateway_host" in *:*) gateway_host="[$gateway_host]" ;; esac
  [[ "$LICENSING_SERVER" =~ ^https://[^/?#@[:space:]]+$ ]] && fallback=$LICENSING_SERVER
  {
    printf 'upgrade_trust_sha256=%s\n' "$UPGRADE_TRUST_SHA256"
    printf 'gateway_enrollment_address=%s:%s\n' "$gateway_host" "$GATEWAY_ENROLLMENT_PORT"
    printf 'gateway_address=%s:%s\n' "$gateway_host" "$GATEWAY_AGENT_PORT"
    printf 'gateway_server_name=%s\n' "$GATEWAY_HOST"
    [ -z "$fallback" ] || printf 'download_fallback_origin=%s\n' "$fallback"
  } >"$TEMP_DIR/node-install-defaults"
  install -m 0644 "$TEMP_DIR/node-install-defaults" "${DOWNLOAD_DIR}/node-install-defaults"
}

# Signer-revocation consumer (签名密钥泄露吊销). The offline-root pin must be
# provisioned independently of the authorization center, so it is only taken
# from installer arguments. With a complete pin the consumer is enabled; it
# allows everything until a verified checkpoint exists and keeps the last
# verified checkpoint when the center is unreachable.
signer_revocation_environment() {
  local id=${SIGNER_REVOCATION_OFFLINE_ROOT_KEY_ID:-} generation=${SIGNER_REVOCATION_OFFLINE_ROOT_GENERATION:-}
  local key=${SIGNER_REVOCATION_OFFLINE_ROOT_PUBLIC_KEY:-}
  if [ -z "$id$generation$key" ]; then
    printf '[cdnca-control] warning: %s\n' '未提供签名密钥泄露吊销的离线根公钥，主控吊销判定保持关闭；如需启用，请用 --signer-revocation-offline-root-* 重新安装或在 control.env 中补齐。' >&2
    printf 'SIGNER_REVOCATION_CONSUMER_ENABLED=false\n'
    # Node signer trust shares the offline-root pin; =true without it stops control-api.
    printf 'EDGE_SIGNER_TRUST_ENABLED=false\n'
    return 0
  fi
  [[ "$id" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] || fail 'invalid --signer-revocation-offline-root-key-id'
  [[ "$generation" =~ ^[1-9][0-9]{0,18}$ ]] || fail 'invalid --signer-revocation-offline-root-generation'
  [[ "$key" =~ ^[A-Za-z0-9_-]{43}$ ]] || fail 'invalid --signer-revocation-offline-root-public-key'
  [[ "$LICENSING_SERVER" =~ ^https://[^/?#@[:space:]]+$ ]] ||
    fail 'signer revocation requires --licensing-server to be an https origin without a path'
  printf 'SIGNER_REVOCATION_CONSUMER_ENABLED=true\n'
  printf 'SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_KEY_ID=%s\n' "$id"
  printf 'SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_GENERATION=%s\n' "$generation"
  printf 'SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_PUBLIC_KEY_BASE64=%s\n' "$key"
  # Node signer trust (same pin): control-api keeps the node installer's
  # edge-agent/artifacts.json and signer-trust.json in step with the
  # offline-signed document (internal/edgesignertrustsync).
  printf 'EDGE_SIGNER_TRUST_ENABLED=true\n'
  printf 'EDGE_SIGNER_TRUST_DOWNLOADS_DIR=%s\n' "${DOWNLOAD_DIR}/edge-agent"
}

write_environment() {
  [ -n "$API_KEY_PEPPER_BASE64" ] || fail 'runtime secrets were not generated'
  [ -n "$DNS_CREDENTIAL_KEY_BASE64" ] || fail 'runtime secrets were not generated'
  [ -n "$ACCESS_TOKEN_SECRET" ] || fail 'runtime secrets were not generated'
  [ -n "$IMPERSONATION_HMAC_KEY_BASE64" ] || fail 'runtime secrets were not generated'
  [ -n "$OPENRESTY_SECURITY_SECRET_KEY_BASE64" ] || fail 'runtime secrets were not generated'
  [ -n "$OBSERVABILITY_LOG_CURSOR_KEY_BASE64" ] || fail 'runtime secrets were not generated'
  [ -n "$ANNOUNCEMENT_CURSOR_KEY_BASE64" ] || fail 'runtime secrets were not generated'
  [ -n "$JOB_QUERY_CURSOR_KEY_BASE64" ] || fail 'runtime secrets were not generated'
  [ -n "$CNAME_ALLOCATION_HMAC_KEY_BASE64" ] || fail 'runtime secrets were not generated'
  [ -n "$MFA_ENCRYPTION_KEY_BASE64" ] || fail 'runtime secrets were not generated'
  [ -n "$CUSTOM_RBAC_CURSOR_KEY_BASE64" ] || fail 'runtime secrets were not generated'
  [ -n "$CACHE_CONTROL_CURSOR_KEY_BASE64" ] || fail 'runtime secrets were not generated'
  [ -n "$CHALLENGE_POLICY_CURSOR_KEY_BASE64" ] || fail 'runtime secrets were not generated'
  [ -n "$CHALLENGE_POLICY_FACT_KEK_BASE64" ] || fail 'runtime secrets were not generated'
  [ -n "$IDENTITY_VERIFICATION_CURSOR_KEY_BASE64" ] || fail 'runtime secrets were not generated'
  [ -n "$CONTROL_BACKUP_RUN_CURSOR_KEY_BASE64" ] || fail 'runtime secrets were not generated'
  # DNS write runtime (site CNAME targets, node pause/auto-disable re-targeting).
  # Authoritative servers are discovered per zone from its NS delegation through
  # the recursive bootstrap resolvers; public propagation needs 2 of 3 to agree.
  # No workload mTLS listener: nothing on a single host reports to it. Existing
  # consoles get the same values from scripts/native-runtime/converge-dns-runtime.py.
  # Automatic edge publication (market leaf delivery, L4 auto publish): all seven
  # keys or none; it needs EDGE_PUBLISH_RUNTIME_ENABLED=true, which
  # runtime-extra.env (a later EnvironmentFile) sets. The operation timeout must
  # not exceed the control-api shutdown period (20s with analytics ingest on).
  # Each setting lives in exactly one generated file: EDGE_PUBLISH_*,
  # CDNCA_SECURITY_ACTIVATION_*, SYSTEM_CONFIGURATION_RUNTIME_* and ANALYTICS_*
  # (including the realtime API and geo artifact switches) belong to
  # runtime-extra.env (configure-control-runtime.py), never to control.env.
  # Feature switches below are on when their dependencies are generated here.
  # CONTROL_ORIGIN records the console origin for later gateway releases
  # (gateway_access_control_domain). Identity verification mounts without a KYC
  # provider (provider calls answer identity_verification_provider_unavailable).
  # Off, because they need external setup before control-api can start:
  # account recovery/registration (notification channels + templates,
  # Turnstile secret), the identity verification issuer (KYC provider, mTLS
  # listener and workload identities). Market buyer settings are operator
  # supplied through optional.env (deploy/systemd/cdnca-control-optional.env.example).
  # Plugin webhooks stay off: the runtime requires NATS credentials and a CA
  # file (internal/config loadPluginWebhook) and the local NATS has neither, so
  # =true stops control-api; the console hides the page (plugin_webhooks in
  # GET /v1/runtime-features). Backup history: only the installation binding
  # and cursor key are known here; the runner bindings (manifest directory,
  # source cluster, signing key) belong to an external backup runner, and
  # without them the history reads as "no backup target" instead of 503.
  cat >"${CONFIG_DIR}/control.env" <<EOF
HTTP_ADDR=127.0.0.1:8080
API_KEY_TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128
DATABASE_URL=${DATABASE_URL}
REDIS_URL=${REDIS_URL}
EDGE_DEPLOYMENT_NATS_URL=${NATS_URL}
NODE_PRESENCE_NATS_URL=${NATS_URL}
NODE_PRESENCE_REDIS_URL=${REDIS_URL}
ACCESS_TOKEN_SECRET=${ACCESS_TOKEN_SECRET}
IMPERSONATION_HMAC_KEY_BASE64=${IMPERSONATION_HMAC_KEY_BASE64}
OPENRESTY_SECURITY_SECRET_KEY_BASE64=${OPENRESTY_SECURITY_SECRET_KEY_BASE64}
OBSERVABILITY_LOG_CURSOR_KEY_BASE64=${OBSERVABILITY_LOG_CURSOR_KEY_BASE64}
ANNOUNCEMENT_ENABLED=true
ANNOUNCEMENT_EXTERNAL_CHANNEL=disabled
ANNOUNCEMENT_CURSOR_ACTIVE_KEY_ID=announcement-v1
ANNOUNCEMENT_CURSOR_KEYS_JSON='{"announcement-v1":"${ANNOUNCEMENT_CURSOR_KEY_BASE64}"}'
NOTIFICATION_RUNTIME_ENABLED=false
NODE_SCHEDULING_RUNTIME_ENABLED=true
JOB_QUERY_ENABLED=true
JOB_QUERY_CURSOR_ACTIVE_KEY_ID=jobs-v1
JOB_QUERY_CURSOR_KEYS_JSON='{"jobs-v1":"${JOB_QUERY_CURSOR_KEY_BASE64}"}'
MFA_ENABLED=true
MFA_ENCRYPTION_ACTIVE_KEY_ID=mfa-v1
MFA_ENCRYPTION_KEYS_JSON='{"mfa-v1":"${MFA_ENCRYPTION_KEY_BASE64}"}'
CUSTOM_RBAC_RUNTIME_ENABLED=true
CUSTOM_RBAC_CURSOR_KEY_BASE64=${CUSTOM_RBAC_CURSOR_KEY_BASE64}
CACHE_CONTROL_RUNTIME_ENABLED=true
CACHE_CONTROL_RUNTIME_NATS_URL=${NATS_URL}
CACHE_CONTROL_RUNTIME_NATS_NAME=cdnca-control-api-cache-control
CACHE_CONTROL_RUNTIME_CURSOR_KEY_BASE64=${CACHE_CONTROL_CURSOR_KEY_BASE64}
CACHE_CONTROL_RUNTIME_COMMAND_STREAM=AGENT_COMMANDS
CACHE_CONTROL_RUNTIME_STATUS_STREAM=AGENT_DEPLOYMENT_STATUS
CACHE_CONTROL_RUNTIME_COMMAND_SUBJECT_PREFIX=cdnca.agent.commands.cache
CACHE_CONTROL_RUNTIME_STATUS_SUBJECT_PREFIX=cdnca.agent.deployment-status.cache
CACHE_CONTROL_RUNTIME_DLQ_SUBJECT_PREFIX=cdnca.agent.deployment-status.cache-dlq
CACHE_CONTROL_RUNTIME_DURABLE=control_api_cache_status
CACHE_CONTROL_RUNTIME_WORKER_ID=control-api-cache-runtime
ORIGIN_AUTH_RUNTIME_ENABLED=false
EDGE_AUTOMATIC_PUBLICATION_ENABLED=true
EDGE_AUTOMATIC_PUBLICATION_WORKER_ID=edge-autopublish-1
EDGE_AUTOMATIC_PUBLICATION_POLL_INTERVAL=250ms
EDGE_AUTOMATIC_PUBLICATION_ERROR_BACKOFF=1s
EDGE_AUTOMATIC_PUBLICATION_OPERATION_TIMEOUT=10s
EDGE_AUTOMATIC_PUBLICATION_LEASE_DURATION=1m
EDGE_AUTOMATIC_PUBLICATION_RETRY_DELAY=5s
API_KEY_PEPPER_VERSION=control-v1
API_KEY_PEPPER_BASE64=${API_KEY_PEPPER_BASE64}
DNS_CREDENTIAL_KEY_ID=dns-credentials-v1
DNS_CREDENTIAL_KEY_BASE64=${DNS_CREDENTIAL_KEY_BASE64}
DNS_RECONCILE_ENABLED=true
DNS_RECONCILE_WORKLOAD_MTLS_ENABLED=false
DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS=cloudflare=1.1.1.1:53,google=8.8.8.8:53,alidns=223.5.5.5:53
DNS_RECONCILE_PROPAGATION_PUBLIC_RESOLVERS=cloudflare=1.1.1.1:53,google=8.8.8.8:53,alidns=223.5.5.5:53
DNS_RECONCILE_PROPAGATION_PUBLIC_QUORUM=2
CNAME_ALLOCATION_HMAC_KEY_ID=cname-allocation-v1
CNAME_ALLOCATION_HMAC_KEY=${CNAME_ALLOCATION_HMAC_KEY_BASE64}
LICENSE_SERVICE_URL=
# Market member and plugin runtime mTLS ride the T1 tunnel (wss://<host>:443/mtls/v1/tunnel/<target>
# through the CDN, inner TLS unchanged); direct dials host:port.
PLUGIN_RUNTIME_MTLS_TRANSPORT=tunnel
MARKET_MTLS_TRANSPORT=tunnel
# cdncaCE: anonymous installation report once after install, then every 7 days (installation ID, version, node/site counts); set to off to opt out.
COMMUNITY_REPORT_URL=
# cdncaCE: official service for community-register (market purchases) and the identity it stores.
COMMUNITY_SERVICE_URL=https://auth.cdnca.com
COMMUNITY_IDENTITY_FILE=${CONFIG_DIR}/community/identity.json
COMMUNITY_TRUSTED_KEYS_FILE=${CONFIG_DIR}/community/trusted-keys.json
CONTROL_INSTALLATION_ENCRYPTION_KEY_FILE=${KEY_DIR}/installation-encryption.key
CONTROL_INSTALLATION_ID=${INSTALLATION_ID}
CONTROL_INSTALLATION_NAME=${INSTALLATION_NAME}
CONTROL_INSTALLATION_PRIVATE_KEY_FILE=${KEY_DIR}/installation.key
CONTROL_VERSION=${CONTROL_VERSION}
COOKIE_SECURE=true
CONTROL_INTERNAL_GRPC_ADDR=127.0.0.1:9091
CONTROL_INTERNAL_SERVER_CERT_FILE=${PKI_DIR}/control-internal-server.pem
CONTROL_INTERNAL_SERVER_PRIVATE_KEY_FILE=${PKI_DIR}/control-internal-server-key.pem
CONTROL_INTERNAL_GATEWAY_CLIENT_CA_FILE=${PKI_DIR}/gateway-client-ca-cert.pem
CONTROL_INTERNAL_GATEWAY_WORKLOAD_URI_SAN=spiffe://cdn-platform/gateway/control
NODE_CA_CERTIFICATE_CHAIN_FILE=${PKI_DIR}/node-ca-cert.pem
NODE_CA_PRIVATE_KEY_FILE=${PKI_DIR}/node-ca-key.pem
CDNCA_GATEWAY_CLIENT_CA_CERT_FILE=${PKI_DIR}/gateway-client-ca-cert.pem
CDNCA_GATEWAY_CLIENT_CA_KEY_FILE=${PKI_DIR}/gateway-client-ca-key.pem
CDNCA_GATEWAY_ROOT_CA_CERT_FILE=${PKI_DIR}/root-ca-cert.pem
CDNCA_GATEWAY_ROOT_CA_KEY_FILE=${PKI_DIR}/root-ca-key.pem
# cdncaCE: online control/node upgrades need license-issued upgrade grants (commercial edition).
CONTROL_UPGRADE_RUNTIME_ENABLED=false
CONTROL_UPGRADE_NATS_NAME=cdnca-control-upgrade
CONTROL_UPGRADE_WORKER_ID=control-upgrade-1
CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE=${CONFIG_DIR}/entitlement-trusted-keys.json
# cdncaCE: the public keys the control plane verifies signed documents with (write_upgrade_trust);
# the community entitlement is built in and never read from a lease.
ENTITLEMENT_TRUSTED_KEYS_FILE=${CONFIG_DIR}/entitlement-trusted-keys.json
CONTROL_UPGRADE_CONTROL_SIGNING_KEY_ID=${UPGRADE_CONTROL_KEY_ID}
CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE=${UPGRADE_KEY_DIR}/control-execution.pem
CONTROL_UPGRADE_EDGE_SIGNING_KEY_ID=${UPGRADE_EDGE_KEY_ID}
CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE=${UPGRADE_KEY_DIR}/edge-execution.pem
CONTROL_UPGRADE_COMMAND_ISSUANCE_TTL=6h
CONTROL_UPGRADE_EXECUTION_TTL=10m
CONTROL_UPGRADE_ACTIVATION_TIMEOUT=5m
CONTROL_UPGRADE_OBSERVATION_WINDOW=2m
CONTROL_UPGRADE_HEALTH_INTERVAL=10s
CONTROL_UPGRADE_PROBE_TIMEOUT=3s
CONTROL_UPGRADE_REQUIRED_CONSECUTIVE_SUCCESSES=3
CONTROL_UPGRADE_NATS_CONNECT_TIMEOUT=5s
CONTROL_UPGRADE_NATS_RECONNECT_WAIT=1s
CONTROL_UPGRADE_NATS_DRAIN_TIMEOUT=5s
CONTROL_UPGRADE_SHUTDOWN_TIMEOUT=10s
CONTROL_UPGRADE_ARTIFACT_CACHE_DIR=${DOWNLOAD_DIR}/edge-agent/upgrades/sha256
CONTROL_SITE_THEMES_DIR=${DATA_DIR}/site-themes
CONTROL_UPGRADE_ARTIFACT_BASE_URL=$(upgrade_download_origin)/downloads/edge-agent/upgrades/sha256
$(upgrade_download_root_env)
PLUGIN_WEBHOOK_ATTESTATION_KEY_ID=plugin-webhook-attestation-v1
PLUGIN_WEBHOOK_ATTESTATION_PRIVATE_KEY_FILE=${KEY_DIR}/plugin-webhook-attestation-v1.pem
SYSTEM_SETTINGS_RUNTIME_ENABLED=true
HTTP_POLICY_RUNTIME_ENABLED=true
CHALLENGE_POLICY_RUNTIME_ENABLED=true
CHALLENGE_POLICY_CURSOR_KEY_ID=challenge-policy-v1
CHALLENGE_POLICY_CURSOR_KEY_BASE64=${CHALLENGE_POLICY_CURSOR_KEY_BASE64}
CHALLENGE_POLICY_FACT_KEK_ID=challenge-fact-v1
CHALLENGE_POLICY_FACT_KEK_BASE64=${CHALLENGE_POLICY_FACT_KEK_BASE64}
CONTROL_ORIGIN=${CONTROL_ORIGIN}
IDENTITY_VERIFICATION_RUNTIME_ENABLED=true
IDENTITY_VERIFICATION_SETTLEMENT_WORKER_ENABLED=true
IDENTITY_VERIFICATION_RESOLVER_NAME=cdnca-control
IDENTITY_VERIFICATION_CURSOR_KEY_BASE64=${IDENTITY_VERIFICATION_CURSOR_KEY_BASE64}
IDENTITY_VERIFICATION_ISSUER_ENABLED=false
ACCOUNT_RECOVERY_ENABLED=false
ACCOUNT_REGISTRATION_ENABLED=false
PLUGIN_WEBHOOK_RUNTIME_ENABLED=false
CONTROL_BACKUP_RUN_INSTALLATION_ID=${INSTALLATION_ID}
CONTROL_BACKUP_RUN_CURSOR_KEY_BASE64=${CONTROL_BACKUP_RUN_CURSOR_KEY_BASE64}
EOF
  signer_revocation_environment >>"${CONFIG_DIR}/control.env"
  ! remote_gateway_access || gateway_access_environment >>"${CONFIG_DIR}/control.env"
  local_gateway_environment >>"${CONFIG_DIR}/control.env"
  chmod 0600 "${CONFIG_DIR}/control.env"
  # The administrator password is only handed to the bootstrap command below;
  # it is not persisted in the service environment.
}

control_database_psql() {
  # PGDATABASE is a literal database name, not a connection URI. libpq parses
  # the full URI here without exposing credentials in argv or error messages.
  DATABASE_URL="$DATABASE_URL" python3 -I -B - "$1" <<'PY'
import ctypes
import ctypes.util
import os
import sys

checks = {
    "empty": ("SELECT NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' AND (n.nspname <> 'public' OR EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.refclassid='pg_catalog.pg_namespace'::pg_catalog.regclass AND d.refobjid=n.oid))) AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extname <> 'plpgsql')", (b"t", b"f")),
    "reachable": ("SELECT 1", (b"1",)),
    "analytics": ("SELECT bool_and(has_function_privilege(current_user, signature, 'EXECUTE')) FROM unnest(ARRAY['analytics_ingest_mark_prepared_098(uuid,numeric,bytea,timestamptz)','analytics_ingest_mark_broker_ack_observed_098(uuid,numeric,bytea,timestamptz)','analytics_history_schedule_recovery_098(uuid,text,timestamptz)','analytics_history_claim_recovery_098(uuid,text,uuid,timestamptz,timestamptz)','analytics_history_reconcile_recovery_098(uuid,uuid,numeric,numeric,timestamptz)','analytics_history_complete_recovery_098(uuid,uuid,timestamptz)']) AS functions(signature)", (b"t", b"f")),
    }
connection = result = None
try:
    query, allowed = checks[sys.argv[1]]
    uri = os.environ.pop("DATABASE_URL")
    if not uri.startswith(("postgresql://", "postgres://")) or any(c in uri for c in "\r\n\0"):
        raise ValueError("invalid database URI")
    for name in list(os.environ):
        if name.startswith("PG"):
            del os.environ[name]
    # The system libpq first (TLS for external databases); hosts on the portable
    # PostgreSQL build (no system libpq) use its bundled loopback-only libpq.
    # CDLL(None) is the running process, so a missing library must be skipped.
    for candidate in (ctypes.util.find_library("pq"), "libpq.so.5", "/opt/cdnca-postgresql-17/lib/libpq.so.5"):
        try:
            pq = ctypes.CDLL(candidate) if candidate else None
        except OSError:
            pq = None
        if pq is not None and hasattr(pq, "PQconnectdb"):
            break
    else:
        raise ValueError("libpq unavailable")
    pointer, string, integer = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int
    for name, arguments, returns in (
        ("PQconnectdb", [string], pointer), ("PQstatus", [pointer], integer),
        ("PQexec", [pointer, string], pointer), ("PQresultStatus", [pointer], integer),
        ("PQntuples", [pointer], integer), ("PQnfields", [pointer], integer),
        ("PQgetisnull", [pointer, integer, integer], integer),
        ("PQgetvalue", [pointer, integer, integer], string),
        ("PQclear", [pointer], None), ("PQfinish", [pointer], None),
    ):
        function = getattr(pq, name)
        function.argtypes, function.restype = arguments, returns
    connection = pq.PQconnectdb(uri.encode("utf-8"))
    if not connection or pq.PQstatus(connection) != 0:
        raise ValueError("connection failed")
    result = pq.PQexec(connection, query.encode("utf-8"))
    if (not result or pq.PQresultStatus(result) != 2 or pq.PQntuples(result) != 1
            or pq.PQnfields(result) != 1 or pq.PQgetisnull(result, 0, 0)):
        raise ValueError("query failed")
    value = pq.PQgetvalue(result, 0, 0)
    if value not in allowed:
        raise ValueError("unexpected query result")
    print(value.decode("ascii"))
except Exception:
    print("PostgreSQL connection check failed", file=sys.stderr)
    sys.exit(1)
finally:
    if result:
        pq.PQclear(result)
    if connection:
        pq.PQfinish(connection)
PY
}

prepare_database() {
  if [ -z "$DATABASE_PASSWORD" ]; then
    log 'checking the configured external PostgreSQL database'
    local empty
    empty=$(control_database_psql empty) \
      || fail 'configured PostgreSQL database is not reachable; check --database-url and credentials'
    [ "$empty" = t ] || fail 'fresh installation requires an empty external PostgreSQL database; existing state was not changed'
    return 0
  fi
  command -v psql >/dev/null 2>&1 || fail 'psql is required for the local PostgreSQL database'
  # PGDG on RHEL keeps pg_isready under /usr/pgsql-17/bin only.
  command -v pg_isready >/dev/null 2>&1 || [ ! -x /usr/pgsql-17/bin/pg_isready ] || PATH="$PATH:/usr/pgsql-17/bin"
  if ! pg_isready -h 127.0.0.1 -p "$PG_PORT" -U postgres -d postgres >/dev/null 2>&1; then
    local setup_bin data_dir unit units started=false
    data_dir=/var/lib/pgsql/data
    if [ ! -f "${data_dir}/PG_VERSION" ]; then
      setup_bin=$(command -v postgresql-setup 2>/dev/null || true)
      if [ -z "$setup_bin" ]; then
        for setup_bin in /usr/pgsql-*/bin/postgresql-setup; do
          [ -x "$setup_bin" ] && break
        done
        [ -x "$setup_bin" ] || setup_bin=''
      fi
      if [ -n "$setup_bin" ]; then
        "$setup_bin" --initdb >/dev/null 2>&1 || fail 'PostgreSQL cluster initialization failed'
      fi
    fi
    if systemctl enable --now postgresql >/dev/null 2>&1; then
      started=true
    else
      units=$(systemctl list-unit-files --type=service --no-legend 'postgresql*.service' 2>/dev/null | awk '{print $1}')
      for unit in $units; do
        if systemctl enable --now "$unit" >/dev/null 2>&1; then
          started=true
          break
        fi
      done
    fi
    [ "$started" = true ] || fail 'PostgreSQL service could not be started'
  fi
  for _ in $(seq 1 30); do
    pg_isready -h 127.0.0.1 -p "$PG_PORT" -U postgres -d postgres >/dev/null 2>&1 && break
    progress_tick ' PostgreSQL 就绪' 30
    sleep 1
  done
  pg_isready -h 127.0.0.1 -p "$PG_PORT" -U postgres -d postgres >/dev/null 2>&1 || fail 'PostgreSQL did not become ready'
  local -a psql_runner=()
  if command -v runuser >/dev/null 2>&1; then
    psql_runner=(runuser -u postgres -- psql -p "$PG_PORT")
  elif command -v sudo >/dev/null 2>&1; then
    psql_runner=(sudo -u postgres psql -p "$PG_PORT")
  else
    fail 'runuser or sudo is required to initialize PostgreSQL'
  fi
  local existing
  existing=$("${psql_runner[@]}" -XAt -v ON_ERROR_STOP=1 --dbname postgres --command \
    "SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('cdnca','cdnca_control_app','cdnca_plugin_webhook_runtime','cdnca_control_runtime','cdnca_retention_cleanup')) OR EXISTS (SELECT 1 FROM pg_database WHERE datname='cdnca') THEN 'occupied' ELSE 'empty' END") ||
    fail 'cannot inspect PostgreSQL before fresh installation'
  [ "$existing" = empty ] || fail 'existing PostgreSQL installation identity or database found; no password or schema was changed'
  # The generated password is kept only in a mode-0600 temporary SQL file and
  # the connection URL; it is never passed as a psql argument or echoed.
  # psql does not interpolate variables inside a dollar-quoted PL/pgSQL body,
  # so generate the escaped CREATE statement outside DO with format()+gexec.
  local sql_file="${TEMP_DIR}/postgres-init.sql"
  cat >"$sql_file" <<SQL
\\set cdnca_password '${DATABASE_PASSWORD}'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', 'cdnca', :'cdnca_password')\gexec
CREATE ROLE cdnca_control_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_plugin_webhook_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_control_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
-- FX01: only this role may delete expired history (migration 306); the
-- application login switches to it with SET LOCAL ROLE for cleanup batches.
CREATE ROLE cdnca_retention_cleanup NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
GRANT cdnca_retention_cleanup TO cdnca;
CREATE DATABASE cdnca OWNER cdnca;
\connect cdnca
ALTER SCHEMA public OWNER TO cdnca;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL
  chmod 0600 "$sql_file"
  # 检查已确认这些角色与库此前都不存在：从这里起它们属于本次安装（--cleanup-failed 可删）。
  control_install_state_add "created=postgresql:${PG_PORT}"
  "${psql_runner[@]}" -X -v ON_ERROR_STOP=1 --dbname postgres <"$sql_file" >/dev/null
  control_database_psql reachable >/dev/null \
    || fail 'created PostgreSQL role/database cannot be accessed with the generated credentials'
}

setup_redis() {
  [ "$REDIS_LOCAL" = true ] || return 0
  log 'starting local Redis'
  # EL10 replaced Redis with the protocol-compatible Valkey (valkey-cli).
  local cli=redis-cli
  command -v redis-cli >/dev/null 2>&1 || cli=valkey-cli
  if ! systemctl enable --now redis-server >/dev/null 2>&1 &&
    ! systemctl enable --now redis >/dev/null 2>&1 &&
    ! systemctl enable --now valkey >/dev/null 2>&1; then
    fail 'Redis service could not be started'
  fi
  if remote_gateway_access; then
    configure_redis_gateway_access "$cli"
    systemctl restart redis-server >/dev/null 2>&1 || systemctl restart redis >/dev/null 2>&1 ||
      systemctl restart valkey >/dev/null 2>&1 || fail 'Redis service could not be restarted with Gateway access'
  fi
  for _ in $(seq 1 30); do
    if "$cli" -u "$REDIS_URL" ping 2>/dev/null | grep -qx PONG; then
      return 0
    fi
    progress_tick ' Redis 就绪' 30
    sleep 1
  done
  fail 'Redis did not become ready'
}

setup_nats() {
  [ "$NATS_LOCAL" = true ] || return 0
  log 'starting local NATS JetStream'
  mkdir -p "$NATS_DATA_DIR"
  chmod 0700 "$NATS_DATA_DIR"
  write_nats_config
  cat >"/etc/systemd/system/${NATS_SERVICE_NAME}.service" <<EOF
[Unit]
Description=CDNCA local NATS JetStream
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
UMask=0077
ExecStart=${NATS_SERVER_BIN} -c ${CONFIG_DIR}/nats.json
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectHome=read-only
ProtectSystem=full
ReadWritePaths=${NATS_DATA_DIR}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  systemd_compat_apply "/etc/systemd/system/${NATS_SERVICE_NAME}.service" "${NATS_SERVICE_NAME}.service" || fail "cannot render systemd compatibility for ${NATS_SERVICE_NAME}"
  systemctl daemon-reload
  systemctl enable --now "$NATS_SERVICE_NAME" >/dev/null
  for _ in $(seq 1 30); do
    if curl -fsS --connect-timeout 2 --max-time 3 http://127.0.0.1:8222/varz >/dev/null 2>&1 &&
      "$NATS_CLI_BIN" --server "$NATS_URL" server check jetstream >/dev/null 2>&1; then
      return 0
    fi
    progress_tick ' NATS JetStream 就绪' 30
    sleep 1
  done
  journalctl -u "$NATS_SERVICE_NAME" -n 80 --no-pager >&2 || true
  fail 'NATS JetStream did not become ready'
}

preprovision_nats() {
  log 'verifying the complete NATS stream and durable consumer profile'
  python3 -I -B "$NATIVE_SUPPORT/scripts/native-runtime/configure-nats.py" install \
    --server "$NATS_URL" --receipt "$CONFIG_DIR/native-nats-receipt.json"
}
# ---- Standalone Gateway access (--mode control, ADR 0013 §3.3, GW-09) ----
# Loopback consumers keep 127.0.0.1:4222 / 127.0.0.1:6379 unchanged. Bound
# Gateways use three TLS listeners that only bound Gateway addresses reach:
# ControlInternal 9446 (mTLS), NATS websocket 4223 (TLS client certificate +
# shared Gateway user) and Redis 6380 (TLS client certificate + ACL user).
# 1.0.35 uses one shared Gateway account per service; a deleted Gateway is cut
# off by certificate revocation and the address allow list (per-Gateway
# accounts: 1.0.36, ADR 0013 §3.3).
remote_gateway_access() { [ "${INSTALL_MODE:-all}" = control ]; }

generate_gateway_access_secrets() {
  remote_gateway_access || return 0
  REDIS_DEFAULT_PASSWORD=$(openssl rand -hex 24)
  REDIS_GATEWAY_PASSWORD=$(openssl rand -hex 24)
  NATS_LOCAL_PASSWORD=$(openssl rand -hex 24)
  NATS_GATEWAY_PASSWORD=$(openssl rand -hex 24)
  # The local Redis gets a password; every local consumer reads REDIS_URL.
  REDIS_URL="redis://:${REDIS_DEFAULT_PASSWORD}@127.0.0.1:${REDIS_PORT}/0"
}

# Subjects a Gateway publishes/subscribes (services/agent-gateway: command,
# status, heartbeat, telemetry and JetStream API). Stream/consumer deletion
# and purges stay with the control plane.
nats_gateway_permissions() {
  jq -n '{publish:{allow:["cdnca.>","cdnca.>","$JS.API.>","_INBOX.>"],
      deny:["$JS.API.STREAM.DELETE.>","$JS.API.STREAM.PURGE.>","$JS.API.CONSUMER.DELETE.>","$JS.API.STREAM.SNAPSHOT.>","$JS.API.STREAM.RESTORE.>","$JS.API.ACCOUNT.PURGE.>"]},
    subscribe:{allow:["cdnca.>","cdnca.>","_INBOX.>"]}}'
}

# nats.json: the fixed local profile, plus (control mode) users and the
# Gateway websocket listener. no_auth_user keeps loopback clients unchanged;
# a remote websocket client without credentials maps to "local", whose
# connection type is STANDARD only, and is refused.
write_nats_config() {
  local base
  base=$(jq -n --arg store "$NATS_DATA_DIR" '{host:"127.0.0.1",port:4222,http:"127.0.0.1:8222",
    max_payload:4194304,jetstream:{store_dir:$store}}')
  if remote_gateway_access; then
    base=$(jq --arg local_password "$NATS_LOCAL_PASSWORD" --arg gateway_password "$NATS_GATEWAY_PASSWORD" \
      --argjson gateway_permissions "$(nats_gateway_permissions)" --argjson port "$NATS_GATEWAY_WS_PORT" \
      --arg cert "${PKI_DIR}/control-internal-server.pem" --arg key "${PKI_DIR}/control-internal-server-key.pem" \
      --arg ca "${PKI_DIR}/gateway-client-ca-cert.pem" \
      '. + {no_auth_user:"local",
        authorization:{users:[
          {user:"local",password:$local_password,allowed_connection_types:["STANDARD"]},
          {user:"cdnca-gateway",password:$gateway_password,allowed_connection_types:["WEBSOCKET"],permissions:$gateway_permissions}]},
        websocket:{host:"0.0.0.0",port:$port,compression:false,
          tls:{cert_file:$cert,key_file:$key,ca_file:$ca,verify:true,min_version:"1.2"}}}' <<<"$base")
  fi
  printf '%s\n' "$base" >"$CONFIG_DIR/nats.json"
  chmod 0600 "$CONFIG_DIR/nats.json"
}

# Redis: a root-owned include next to the distribution's redis.conf adds the
# default password, the TLS listener and the Gateway ACL user. Port 6379 stays
# bound to loopback by the distribution profile.
configure_redis_gateway_access() {
  remote_gateway_access || return 0
  local cli=$1 conf dir include
  conf=$("$cli" -h 127.0.0.1 -p "$REDIS_PORT" --no-auth-warning INFO server | tr -d '\r' | awk -F: '$1 == "config_file" {print $2}')
  [ -n "$conf" ] && [ -f "$conf" ] || fail 'cannot locate the Redis configuration file to enable Gateway access'
  dir=$(dirname "$conf")/cdnca-gateway
  install -d -m 0750 "$dir"
  install -m 0640 "${PKI_DIR}/control-internal-server.pem" "$dir/server.pem"
  install -m 0640 "${PKI_DIR}/control-internal-server-key.pem" "$dir/server-key.pem"
  install -m 0640 "${PKI_DIR}/gateway-client-ca-cert.pem" "$dir/client-ca.pem"
  include="$dir/redis-gateway.conf"
  # Gateway commands: session lease scripts (EVALSHA/EVAL), tunnel nonce SET NX,
  # and the readiness PING; keys only under cdnca:agent-gateway*. Rules stay
  # within Redis 6.0 ACL syntax (Ubuntu 22.04); pub/sub is denied by -@all.
  cat >"$include" <<CONF
# CDNCA standalone Gateway access (install-control.sh --mode control)
requirepass ${REDIS_DEFAULT_PASSWORD}
tls-port ${REDIS_GATEWAY_TLS_PORT}
tls-cert-file ${dir}/server.pem
tls-key-file ${dir}/server-key.pem
tls-ca-cert-file ${dir}/client-ca.pem
tls-auth-clients yes
tls-protocols "TLSv1.2 TLSv1.3"
user cdnca-gateway on >${REDIS_GATEWAY_PASSWORD} ~cdnca:agent-gateway* -@all +ping +hello +auth +select +eval +evalsha +script|load +set +get +del +pexpire +incr +hget +hset +hincrby
CONF
  chmod 0640 "$include"
  chown -R --reference="$conf" "$dir"
  grep -Fxq "include $include" "$conf" || printf '\ninclude %s\n' "$include" >>"$conf"
}

# Server certificate shared by ControlInternal (remote), NATS websocket and
# Redis TLS: Gateways verify it with the installation root CA by CONTROL_DOMAIN.
control_internal_server_san() {
  local san='DNS:localhost,IP:127.0.0.1'
  if remote_gateway_access; then san="$san,$(host_san "$CONTROL_DOMAIN")"; fi
  printf '%s' "$san"
}

# control.env additions: the remote listener, what bound Gateways are told to
# connect to (BindResult.Endpoints) and the firewall allow-list file.
gateway_access_environment() {
  remote_gateway_access || return 0
  local host=$CONTROL_DOMAIN
  case "$host" in *:*) host="[$host]" ;; esac
  printf 'CDNCA_CONTROL_INTERNAL_REMOTE_ADDR=0.0.0.0:%s\n' "$CONTROL_INTERNAL_REMOTE_PORT"
  printf 'CDNCA_GATEWAY_ACCESS_FILE=%s\n' "$GATEWAY_ACCESS_FILE"
  printf 'CDNCA_GATEWAY_REMOTE_CONTROL_ADDRESS=%s:%s\n' "$host" "$CONTROL_INTERNAL_REMOTE_PORT"
  printf 'CDNCA_GATEWAY_REMOTE_CONTROL_SERVER_NAME=%s\n' "$CONTROL_DOMAIN"
  printf 'CDNCA_GATEWAY_REMOTE_REDIS_URL=rediss://cdnca-gateway:%s@%s:%s/0\n' "$REDIS_GATEWAY_PASSWORD" "$host" "$REDIS_GATEWAY_TLS_PORT"
  printf 'CDNCA_GATEWAY_REMOTE_NATS_URL=wss://cdnca-gateway:%s@%s:%s\n' "$NATS_GATEWAY_PASSWORD" "$host" "$NATS_GATEWAY_WS_PORT"
  printf 'CDNCA_GATEWAY_REMOTE_TELEMETRY_NATS_URL=wss://%s:%s\n' "$host" "$NATS_GATEWAY_WS_PORT"
}

# control.env: the co-located Gateway (all/control mode) as nodes reach it.
# control-api publishes it after the online standalone Gateways, so nodes on a
# disabled standalone Gateway migrate back here without an extra entry point.
local_gateway_environment() {
  local host=$GATEWAY_HOST
  case "$host" in *:*) host="[$host]" ;; esac
  printf 'CDNCA_GATEWAY_LOCAL_ADDRESS=%s:%s\n' "$host" "$GATEWAY_AGENT_PORT"
  printf 'CDNCA_GATEWAY_LOCAL_SERVER_NAME=%s\n' "$GATEWAY_HOST"
  printf 'CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS=%s:%s\n' "$host" "$GATEWAY_ENROLLMENT_PORT"
}

# nftables: only addresses in the allow-list file (control-api writes it from
# bound Gateways, the same list as the ControlInternal listener filter) reach
# the three Gateway ports; everyone else is dropped. A path unit re-syncs the
# set whenever the file changes.
setup_gateway_access_firewall() {
  remote_gateway_access || return 0
  command -v nft >/dev/null 2>&1 || fail 'control mode needs nftables (nft) to restrict Gateway access'
  local sync=/usr/local/libexec/cdnca/cdnca-gateway-access-sync
  install -d -m 0755 "$(dirname "$GATEWAY_ACCESS_FILE")" /usr/local/libexec/cdnca
  [ -e "$GATEWAY_ACCESS_FILE" ] || install -m 0644 /dev/null "$GATEWAY_ACCESS_FILE"
  cat >"$sync" <<SYNC
#!/usr/bin/env bash
# Generated by install-control.sh: loads ${GATEWAY_ACCESS_FILE} into the
# cdnca_gateway_access nftables sets (ADR 0013 §3.3).
set -Eeuo pipefail
v4=() v6=()
while IFS= read -r ip; do
  case "\$ip" in
    *:*) [[ "\$ip" =~ ^[0-9A-Fa-f:.]+\$ ]] && v6+=("\$ip") ;;
    *.*) [[ "\$ip" =~ ^[0-9]+(\\.[0-9]+){3}\$ ]] && v4+=("\$ip") ;;
  esac
done < ${GATEWAY_ACCESS_FILE}
elements() { [ "\$#" -eq 0 ] || { local IFS=,; printf 'elements = { %s }; ' "\$*"; }; }
{
  printf 'table inet cdnca_gateway_access\n'
  printf 'delete table inet cdnca_gateway_access\n'
  printf 'table inet cdnca_gateway_access {\n'
  printf '  set gateways4 { type ipv4_addr; %s}\n' "\$(elements \${v4[@]+"\${v4[@]}"})"
  printf '  set gateways6 { type ipv6_addr; %s}\n' "\$(elements \${v6[@]+"\${v6[@]}"})"
  printf '  chain input {\n    type filter hook input priority -5; policy accept;\n'
  printf '    tcp dport { ${CONTROL_INTERNAL_REMOTE_PORT}, ${NATS_GATEWAY_WS_PORT}, ${REDIS_GATEWAY_TLS_PORT} } iif lo accept\n'
  printf '    tcp dport { ${CONTROL_INTERNAL_REMOTE_PORT}, ${NATS_GATEWAY_WS_PORT}, ${REDIS_GATEWAY_TLS_PORT} } ip saddr @gateways4 accept\n'
  printf '    tcp dport { ${CONTROL_INTERNAL_REMOTE_PORT}, ${NATS_GATEWAY_WS_PORT}, ${REDIS_GATEWAY_TLS_PORT} } ip6 saddr @gateways6 accept\n'
  printf '    tcp dport { ${CONTROL_INTERNAL_REMOTE_PORT}, ${NATS_GATEWAY_WS_PORT}, ${REDIS_GATEWAY_TLS_PORT} } drop\n  }\n}\n'
} | nft -f -
SYNC
  chmod 0755 "$sync"
  cat >/etc/systemd/system/cdnca-gateway-access.service <<UNIT
[Unit]
Description=CDNCA standalone Gateway access firewall (nftables)
Before=${SERVICE_NAME}.service ${NATS_SERVICE_NAME}.service
After=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${sync}

[Install]
WantedBy=multi-user.target
UNIT
  cat >/etc/systemd/system/cdnca-gateway-access.path <<UNIT
[Unit]
Description=Reload the Gateway access firewall when bound Gateways change

[Path]
PathChanged=${GATEWAY_ACCESS_FILE}
Unit=cdnca-gateway-access-reload.service

[Install]
WantedBy=multi-user.target
UNIT
  cat >/etc/systemd/system/cdnca-gateway-access-reload.service <<UNIT
[Unit]
Description=Re-sync the Gateway access nftables sets

[Service]
Type=oneshot
ExecStart=${sync}
UNIT
  systemctl daemon-reload
  "$sync" || fail 'cannot load the Gateway access nftables rules'
  systemctl enable cdnca-gateway-access.service cdnca-gateway-access.path >/dev/null
  systemctl start cdnca-gateway-access.path
}

# ---- install-control.sh enable-gateway-access [--domain HOST] ----
# Opens standalone Gateway access on a console installed with --mode all:
# the same listeners, accounts, certificate name and firewall as --mode
# control. control.env is pinned by runtime-receipt.json, so the settings go
# to root-only env files that systemd drop-ins load after the units' own
# EnvironmentFile lines (as converge-dns-runtime.py does). The secrets are
# kept and reused: a rerun converges and restarts nothing when already open.
# Any failure after the first change restores every file and restarts.
readonly SYSTEMD_UNIT_DIR=/etc/systemd/system
readonly GATEWAY_ACCESS_SECRETS="${CONFIG_DIR}/gateway-access.secrets"
readonly GATEWAY_ACCESS_CONTROL_ENV="${CONFIG_DIR}/gateway-access.env"
readonly GATEWAY_ACCESS_LOCAL_ENV="${CONFIG_DIR}/gateway-access-local.env"
readonly GATEWAY_ACCESS_SYNC=/usr/local/libexec/cdnca/cdnca-gateway-access-sync
readonly GATEWAY_ACCESS_LOCK=/run/lock/cdnca-management-release.lock
GATEWAY_ACCESS_WAIT=45
GATEWAY_ACCESS_REDIS_CLI=redis-cli
GATEWAY_ACCESS_BACKUP=""
GATEWAY_ACCESS_SAVED=()
GATEWAY_ACCESS_TOUCHED=false
GATEWAY_ACCESS_FIREWALL_NEW=false

gateway_access_parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --domain) need_value "$@"; CONTROL_DOMAIN=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]'); shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) fail "unsupported option for enable-gateway-access: $1" ;;
    esac
  done
}

# KEY's value in an installer-written env file (unquoted KEY=value lines).
gateway_access_env_value() {
  awk -v key="$1" 'index($0, key "=") == 1 { value = substr($0, length(key) + 2) } END { print value }' "$2"
}

# The installation's CONTROL_DOMAIN: control.env keeps CONTROL_ORIGIN
# (https://host[:port]); installs from before the community edition kept it
# as PAYMENT_CHANNELS_NOTIFY_BASE.
gateway_access_control_domain() {
  local origin host
  origin=$(gateway_access_env_value CONTROL_ORIGIN "$CONFIG_DIR/control.env")
  [ -n "$origin" ] || origin=$(gateway_access_env_value PAYMENT_CHANNELS_NOTIFY_BASE "$CONFIG_DIR/control.env")
  host=${origin#https://}
  [ "$host" != "$origin" ] || return 1
  host=${host%%/*}
  case "$host" in
    \[*) host=${host#\[}; host=${host%%\]*} ;;
    *) host=${host%%:*} ;;
  esac
  printf '%s' "$host" | tr '[:upper:]' '[:lower:]'
}

gateway_access_lock() {
  [ ! -L "$GATEWAY_ACCESS_LOCK" ] || fail 'unsafe management release lock'
  exec 7<>"$GATEWAY_ACCESS_LOCK"
  flock -n 7 || fail 'a control-plane upgrade or release is running; retry later'
}

# Reuses the secrets of an earlier run so the result is identical.
gateway_access_load_secrets() {
  local name value
  if [ ! -e "$GATEWAY_ACCESS_SECRETS" ]; then generate_gateway_access_secrets; return 0; fi
  for name in REDIS_DEFAULT_PASSWORD REDIS_GATEWAY_PASSWORD NATS_LOCAL_PASSWORD NATS_GATEWAY_PASSWORD; do
    value=$(gateway_access_env_value "$name" "$GATEWAY_ACCESS_SECRETS")
    [[ "$value" =~ ^[0-9a-f]{48}$ ]] || fail "${GATEWAY_ACCESS_SECRETS} is damaged (${name}); restore it from a backup"
    printf -v "$name" '%s' "$value"
  done
  REDIS_URL="redis://:${REDIS_DEFAULT_PASSWORD}@127.0.0.1:${REDIS_PORT}/0"
}

# redis-cli/valkey-cli that authenticates once the default password is set.
gateway_access_redis_cli() {
  if [ "$("$GATEWAY_ACCESS_REDIS_CLI" -h 127.0.0.1 -p "$REDIS_PORT" PING 2>/dev/null | tr -d '\r')" = PONG ]; then
    "$GATEWAY_ACCESS_REDIS_CLI" "$@"
  else
    REDISCLI_AUTH=$REDIS_DEFAULT_PASSWORD "$GATEWAY_ACCESS_REDIS_CLI" "$@"
  fi
}

# Copies each path (file or directory, possibly absent) for the rollback.
gateway_access_backup() {
  local path copy
  for path in "$@"; do
    copy="$GATEWAY_ACCESS_BACKUP/${#GATEWAY_ACCESS_SAVED[@]}"
    if [ -e "$path" ] || [ -L "$path" ]; then cp -a "$path" "$copy" || fail "cannot back up $path"; fi
    GATEWAY_ACCESS_SAVED+=("$path")
  done
}

# Succeeds when any backed-up path now differs from its copy.
gateway_access_changed() {
  local index path copy
  for index in "${!GATEWAY_ACCESS_SAVED[@]}"; do
    path=${GATEWAY_ACCESS_SAVED[$index]} copy="$GATEWAY_ACCESS_BACKUP/$index"
    [ -e "$copy" ] || [ -e "$path" ] || continue
    { [ -e "$copy" ] && [ -e "$path" ] && diff -r "$copy" "$path" >/dev/null 2>&1; } || return 0
  done
  return 1
}

gateway_access_restore() {
  local index path copy
  for index in "${!GATEWAY_ACCESS_SAVED[@]}"; do
    path=${GATEWAY_ACCESS_SAVED[$index]} copy="$GATEWAY_ACCESS_BACKUP/$index"
    rm -rf -- "$path"
    if [ -e "$copy" ] || [ -L "$copy" ]; then cp -a "$copy" "$path"; fi
  done
}

gateway_access_certificate_covers() {
  local option=-checkhost
  case "$(host_san "$CONTROL_DOMAIN")" in IP:*) option=-checkip ;; esac
  openssl x509 -in "${PKI_DIR}/control-internal-server.pem" -noout "$option" "$CONTROL_DOMAIN" 2>/dev/null | grep -q ' does match certificate'
}

gateway_access_write() {
  local unit env
  printf '%s=%s\n' REDIS_DEFAULT_PASSWORD "$REDIS_DEFAULT_PASSWORD" REDIS_GATEWAY_PASSWORD "$REDIS_GATEWAY_PASSWORD" \
    NATS_LOCAL_PASSWORD "$NATS_LOCAL_PASSWORD" NATS_GATEWAY_PASSWORD "$NATS_GATEWAY_PASSWORD" >"$GATEWAY_ACCESS_SECRETS"
  chmod 0600 "$GATEWAY_ACCESS_SECRETS"
  # The local Gateway keeps verifying it as "localhost"; Gateways need the domain.
  gateway_access_certificate_covers || issue_certificate control-internal-server localhost "$(control_internal_server_san)" serverAuth \
    "${PKI_DIR}/root-ca-cert.pem" "${PKI_DIR}/root-ca-key.pem"
  gateway_access_certificate_covers || fail 'cannot issue the control-plane certificate for the Gateway domain'
  write_nats_config
  configure_redis_gateway_access gateway_access_redis_cli
  { printf 'REDIS_URL=%s\nNODE_PRESENCE_REDIS_URL=%s\n' "$REDIS_URL" "$REDIS_URL"; gateway_access_environment; } >"$GATEWAY_ACCESS_CONTROL_ENV"
  printf 'CDNCA_REDIS_URL=%s\n' "$REDIS_URL" >"$GATEWAY_ACCESS_LOCAL_ENV"
  chmod 0600 "$GATEWAY_ACCESS_CONTROL_ENV" "$GATEWAY_ACCESS_LOCAL_ENV"
  for unit in "$SERVICE_NAME:$GATEWAY_ACCESS_CONTROL_ENV" "$GATEWAY_SERVICE_NAME:$GATEWAY_ACCESS_LOCAL_ENV"; do
    env=${unit#*:} unit=${unit%%:*}
    install -d -m 0755 "${SYSTEMD_UNIT_DIR}/${unit}.service.d"
    printf '[Service]\nEnvironmentFile=%s\n' "$env" >"${SYSTEMD_UNIT_DIR}/${unit}.service.d/60-gateway-access.conf"
    chmod 0644 "${SYSTEMD_UNIT_DIR}/${unit}.service.d/60-gateway-access.conf"
  done
  setup_gateway_access_firewall
  ! { command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; } || restorecon -RF "$PKI_DIR" >/dev/null 2>&1 || true
}

gateway_access_restart() {
  systemctl daemon-reload || return 1
  systemctl restart redis-server >/dev/null 2>&1 || systemctl restart redis >/dev/null 2>&1 ||
    systemctl restart valkey >/dev/null 2>&1 || return 1
  systemctl restart "$NATS_SERVICE_NAME" && systemctl restart "$SERVICE_NAME" && systemctl restart "$GATEWAY_SERVICE_NAME"
}

gateway_access_services_ready() {
  curl -fsS --connect-timeout 2 --max-time 5 http://127.0.0.1:8080/health/ready >/dev/null 2>&1 &&
    curl -fsS --connect-timeout 2 --max-time 5 http://127.0.0.1:8082/health/ready >/dev/null 2>&1
}

gateway_access_ready() {
  local port listening
  [ "$(REDISCLI_AUTH=$REDIS_DEFAULT_PASSWORD "$GATEWAY_ACCESS_REDIS_CLI" -h 127.0.0.1 -p "$REDIS_PORT" PING 2>/dev/null | tr -d '\r')" = PONG ] || return 1
  curl -fsS --connect-timeout 2 --max-time 3 http://127.0.0.1:8222/varz >/dev/null 2>&1 || return 1
  "$NATS_CLI_BIN" --server nats://127.0.0.1:4222 server check jetstream >/dev/null 2>&1 || return 1
  gateway_access_services_ready || return 1
  listening=$(preflight_listening_ports)
  for port in "$CONTROL_INTERNAL_REMOTE_PORT" "$NATS_GATEWAY_WS_PORT" "$REDIS_GATEWAY_TLS_PORT"; do
    grep -qx "$port" <<<"$listening" || return 1
  done
}

# Runs CHECK until it passes, GATEWAY_ACCESS_WAIT attempts 2 seconds apart.
gateway_access_wait() {
  local attempt
  for attempt in $(seq 1 "$GATEWAY_ACCESS_WAIT"); do
    "$1" && return 0
    [ "$attempt" -ge "$GATEWAY_ACCESS_WAIT" ] || sleep 2
  done
  return 1
}

gateway_access_rollback() {
  warn '开启独立网关接入失败，正在恢复原配置并重启主控服务'
  if [ "$GATEWAY_ACCESS_FIREWALL_NEW" = true ]; then
    systemctl disable --now cdnca-gateway-access.path cdnca-gateway-access.service >/dev/null 2>&1 || true
    nft delete table inet cdnca_gateway_access >/dev/null 2>&1 || true
  fi
  gateway_access_restore
  if gateway_access_restart && gateway_access_wait gateway_access_services_ready; then
    warn '已恢复原配置，本机网关与节点连接照旧；请按上面的错误处理后重试'
  else
    warn '原配置文件已恢复，但服务没有全部就绪：请执行 systemctl status cdnca-control-api cdnca-agent-gateway 查看'
  fi
}

gateway_access_on_exit() {
  local status=$?
  if [ "$status" -ne 0 ] && [ "$GATEWAY_ACCESS_TOUCHED" = true ]; then
    GATEWAY_ACCESS_TOUCHED=false
    gateway_access_rollback || true
  fi
  cleanup
  exit "$status"
}

gateway_access_main() {
  local command conf
  INSTALL_MODE=control
  gateway_access_parse_args "$@"
  [ "$EUID" -eq 0 ] || fail 'run this installer as root'
  [ -f "${CONFIG_DIR}/control.env" ] || fail 'no installed control plane on this host (control.env is missing)'
  if grep -q '^CDNCA_CONTROL_INTERNAL_REMOTE_ADDR=' "${CONFIG_DIR}/control.env"; then
    log '本主控安装时已开放独立网关接入（--mode control），无需再开启'
    return 0
  fi
  # A BaoTa host may run our Redis on a moved loopback port.
  [[ "$(gateway_access_env_value REDIS_URL "${CONFIG_DIR}/control.env")" =~ ^redis://127\.0\.0\.1:([0-9]{4,5})/0$ ]] ||
    fail 'only the local Redis of a default installation can be opened to Gateways'
  REDIS_PORT=${BASH_REMATCH[1]}
  [ "$(gateway_access_env_value EDGE_DEPLOYMENT_NATS_URL "${CONFIG_DIR}/control.env")" = nats://127.0.0.1:4222 ] ||
    fail 'only the local NATS of a default installation can be opened to Gateways'
  for command in nft openssl jq curl systemctl flock diff; do
    command -v "$command" >/dev/null 2>&1 || fail "$command is required"
  done
  command -v redis-cli >/dev/null 2>&1 || GATEWAY_ACCESS_REDIS_CLI=valkey-cli
  command -v "$GATEWAY_ACCESS_REDIS_CLI" >/dev/null 2>&1 || fail 'redis-cli (or valkey-cli) is required'
  [ -n "$CONTROL_DOMAIN" ] || CONTROL_DOMAIN=$(gateway_access_control_domain) || CONTROL_DOMAIN=""
  if [ -z "$CONTROL_DOMAIN" ] || ! valid_host "$CONTROL_DOMAIN"; then fail 'cannot determine the control-plane domain; pass --domain'; fi
  gateway_access_lock
  gateway_access_load_secrets
  conf=$(gateway_access_redis_cli -h 127.0.0.1 -p "$REDIS_PORT" --no-auth-warning INFO server | tr -d '\r' | awk -F: '$1 == "config_file" {print $2}')
  [ -n "$conf" ] && [ -f "$conf" ] || fail 'cannot locate the Redis configuration file'
  GATEWAY_ACCESS_BACKUP="$TEMP_DIR/gateway-access-backup"
  install -d -m 0700 "$GATEWAY_ACCESS_BACKUP"
  [ -e "${SYSTEMD_UNIT_DIR}/cdnca-gateway-access.service" ] || GATEWAY_ACCESS_FIREWALL_NEW=true
  gateway_access_backup "${PKI_DIR}/control-internal-server.pem" "${PKI_DIR}/control-internal-server-key.pem" \
    "${CONFIG_DIR}/nats.json" "$conf" "$(dirname "$conf")/cdnca-gateway" \
    "$GATEWAY_ACCESS_SECRETS" "$GATEWAY_ACCESS_CONTROL_ENV" "$GATEWAY_ACCESS_LOCAL_ENV" \
    "${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service.d/60-gateway-access.conf" \
    "${SYSTEMD_UNIT_DIR}/${GATEWAY_SERVICE_NAME}.service.d/60-gateway-access.conf" "$GATEWAY_ACCESS_SYNC" \
    "${SYSTEMD_UNIT_DIR}/cdnca-gateway-access.service" "${SYSTEMD_UNIT_DIR}/cdnca-gateway-access.path" \
    "${SYSTEMD_UNIT_DIR}/cdnca-gateway-access-reload.service"
  trap gateway_access_on_exit EXIT
  GATEWAY_ACCESS_TOUCHED=true
  gateway_access_write
  if ! gateway_access_changed && gateway_access_ready; then
    GATEWAY_ACCESS_TOUCHED=false
    log '独立网关接入已经开启，配置没有变化，未重启任何服务'
    return 0
  fi
  log '正在重启 Redis、NATS、主控与本机网关（节点会自动重连）'
  gateway_access_restart || fail 'services could not be restarted with Gateway access'
  gateway_access_wait gateway_access_ready || fail 'services did not become ready with Gateway access (journalctl -u cdnca-control-api)'
  GATEWAY_ACCESS_TOUCHED=false
  log "已开启独立网关接入。刷新主控「系统 → 网关管理」即可添加网关；请在云安全组放行 TCP ${CONTROL_INTERNAL_REMOTE_PORT},${NATS_GATEWAY_WS_PORT},${REDIS_GATEWAY_TLS_PORT}（本机防火墙只放行已绑定的网关）"
}

# ---- Standalone Gateway package and --mode gateway (ADR 0013 §3.1/§3.2, GW-10) ----
# The control host publishes its own agent-gateway binary with a manifest
# signed by the installation root CA key. A Gateway host pins that root by the
# binding token's fingerprint, then verifies the signature and digest: no
# authorization-center IP registration is involved.
publish_gateway_package() {
  local dir="${DOWNLOAD_DIR}/agent-gateway" binary="${NATIVE_ROOT}/current/bin/agent-gateway"
  [ -f "$binary" ] || fail 'agent-gateway binary is missing from the native release'
  install -d -m 0755 "$dir"
  install -m 0644 "$binary" "$dir/agent-gateway"
  jq -n --arg version "$CONTROL_VERSION" --arg sha256 "$(sha256sum "$dir/agent-gateway" | awk '{print $1}')" \
    '{schema:"cdnca.gateway-package/v1",version:$version,sha256:$sha256}' >"$TEMP_DIR/gateway-manifest.json"
  openssl dgst -sha256 -sign "${PKI_DIR}/root-ca-key.pem" -out "$TEMP_DIR/gateway-manifest.sig" "$TEMP_DIR/gateway-manifest.json" ||
    fail 'cannot sign the Gateway package manifest'
  install -m 0644 "$TEMP_DIR/gateway-manifest.json" "$dir/manifest.json"
  install -m 0644 "$TEMP_DIR/gateway-manifest.sig" "$dir/manifest.sig"
}

GATEWAY_TOKEN=""
GATEWAY_TOKEN_FILE=""
GATEWAY_SERVER_CERT=""
GATEWAY_SERVER_KEY=""
GATEWAY_CONTROL=""
readonly GATEWAY_ROOT=/usr/local/cdnca-gateway
readonly GATEWAY_STATE_DIR=/etc/cdnca-gateway

gateway_parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --mode) need_value "$@"; shift 2 ;;
      --control) need_value "$@"; GATEWAY_CONTROL=${2%/}; shift 2 ;;
      --gateway-token-file) need_value "$@"; GATEWAY_TOKEN_FILE=$2; shift 2 ;;
      --gateway-host) need_value "$@"; GATEWAY_HOST=$2; shift 2 ;;
      --gateway-ports) need_value "$@"; GATEWAY_PORTS=$2; shift 2 ;;
      --server-cert) need_value "$@"; GATEWAY_SERVER_CERT=$2; shift 2 ;;
      --server-key) need_value "$@"; GATEWAY_SERVER_KEY=$2; shift 2 ;;
      --skip-firewall) SKIP_FIREWALL=true; shift ;;
      -y|--yes) ASSUME_YES=true; shift ;;
      -h|--help) usage; exit 0 ;;
      *) fail "unsupported option for --mode gateway: $1" ;;
    esac
  done
}

# The token is read from a root-only file, stdin (-) or the terminal, never argv.
gateway_read_token() {
  if [ -n "$GATEWAY_TOKEN_FILE" ]; then
    if [ "$GATEWAY_TOKEN_FILE" = - ]; then IFS= read -r GATEWAY_TOKEN || true
    else read_owner_only_value "$GATEWAY_TOKEN_FILE" 'Gateway binding token' GATEWAY_TOKEN; fi
  elif [ -t 0 ]; then
    printf '网关绑定令牌（主控“系统 → 网关管理”生成，输入不回显）: ' >&2
    IFS= read -rs GATEWAY_TOKEN; printf '\n' >&2
  else
    IFS= read -r GATEWAY_TOKEN || true
  fi
  [[ "$GATEWAY_TOKEN" =~ ^gwt1\.[0-9a-f-]{36}\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$ ]] || fail 'invalid Gateway binding token'
}

# Root CA: fetched once (possibly without TLS trust, the console may use the
# private CA) and accepted only if its fingerprint equals the token's.
gateway_fetch_root_ca() {
  local root="$TEMP_DIR/root-ca.pem" expected actual
  expected=$(printf '%s' "$GATEWAY_TOKEN" | cut -d. -f3)
  curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 10 --max-time 60 --max-filesize 65536 \
    --output "$root" "$GATEWAY_CONTROL/downloads/gateway-ca.pem" 2>/dev/null ||
    curl --proto '=https' --proto-redir '=https' --insecure -fsSL --connect-timeout 10 --max-time 60 --max-filesize 65536 \
      --output "$root" "$GATEWAY_CONTROL/downloads/gateway-ca.pem" || fail 'cannot download the control-plane root CA'
  actual=$(openssl x509 -in "$root" -outform DER 2>/dev/null | sha256sum | cut -c1-32)
  [ -n "$actual" ] && [ "$actual" = "$expected" ] ||
    fail 'the control plane root CA does not match the binding token; check --control'
  GATEWAY_ROOT_CA_FILE=$root
}

gateway_curl() { curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 10 --max-time 300 --cacert "$GATEWAY_ROOT_CA_FILE" "$@" ||
  curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 10 --max-time 300 "$@"; }

gateway_download_package() {
  local dir="$TEMP_DIR/gateway-package" public="$TEMP_DIR/root-public.pem" sha256 version
  mkdir -p "$dir"
  gateway_curl --max-filesize 65536 --output "$dir/manifest.json" "$GATEWAY_CONTROL/downloads/agent-gateway/manifest.json" &&
    gateway_curl --max-filesize 4096 --output "$dir/manifest.sig" "$GATEWAY_CONTROL/downloads/agent-gateway/manifest.sig" ||
    fail 'cannot download the Gateway package manifest'
  openssl x509 -in "$GATEWAY_ROOT_CA_FILE" -pubkey -noout >"$public"
  openssl dgst -sha256 -verify "$public" -signature "$dir/manifest.sig" "$dir/manifest.json" >/dev/null 2>&1 ||
    fail 'Gateway package manifest signature is invalid'
  jq -e '.schema == "cdnca.gateway-package/v1"' "$dir/manifest.json" >/dev/null || fail 'unsupported Gateway package manifest'
  sha256=$(jq -r .sha256 "$dir/manifest.json"); version=$(jq -r .version "$dir/manifest.json")
  [[ "$sha256" =~ ^[0-9a-f]{64}$ && "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'Gateway package manifest is invalid'
  gateway_curl --max-filesize 285229182 --output "$dir/agent-gateway" "$GATEWAY_CONTROL/downloads/agent-gateway/agent-gateway" ||
    fail 'cannot download agent-gateway'
  [ "$(sha256sum "$dir/agent-gateway" | awk '{print $1}')" = "$sha256" ] || fail 'agent-gateway digest does not match the signed manifest'
  install -d -m 0755 "$GATEWAY_ROOT/bin"
  install -m 0755 "$dir/agent-gateway" "$GATEWAY_ROOT/bin/agent-gateway"
  CONTROL_VERSION=$version
}

# --server-cert/--server-key (optional, both or neither): a public certificate
# for the CDN-facing tunnel TLS. Checked before binding so a bad pair never
# consumes the one-time token; copied root-only into the state directory.
gateway_check_public_certificate() {
  [ -n "$GATEWAY_SERVER_CERT$GATEWAY_SERVER_KEY" ] || return 0
  [ -n "$GATEWAY_SERVER_CERT" ] && [ -n "$GATEWAY_SERVER_KEY" ] || fail '--server-cert and --server-key must be given together'
  [ -f "$GATEWAY_SERVER_CERT" ] && [ -f "$GATEWAY_SERVER_KEY" ] || fail '--server-cert/--server-key must be regular files'
  local cert_key key_key
  cert_key=$(openssl x509 -in "$GATEWAY_SERVER_CERT" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  key_key=$(openssl pkey -in "$GATEWAY_SERVER_KEY" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  [ -n "$cert_key" ] && [ "$cert_key" = "$key_key" ] && [ "$cert_key" != "$(printf '' | sha256sum | awk '{print $1}')" ] ||
    fail '--server-cert and --server-key do not match'
  openssl x509 -in "$GATEWAY_SERVER_CERT" -noout -checkend 0 >/dev/null 2>&1 || fail '--server-cert is expired'
  openssl x509 -in "$GATEWAY_SERVER_CERT" -noout -checkhost "$GATEWAY_HOST" 2>/dev/null | grep -q 'does match' ||
    { [[ $GATEWAY_HOST =~ ^[0-9.]+$|: ]] &&  # OpenSSL 3.0 对非 IP 的 -checkip 也回 "does match"
      openssl x509 -in "$GATEWAY_SERVER_CERT" -noout -checkip "$GATEWAY_HOST" 2>/dev/null | grep -q 'does match'; } ||
    warn "--server-cert does not name $GATEWAY_HOST; make sure it matches the origin name your CDN verifies"
}

gateway_install_public_certificate() {
  [ -n "$GATEWAY_SERVER_CERT" ] || return 0
  install -m 0644 "$GATEWAY_SERVER_CERT" "$GATEWAY_STATE_DIR/public-server.pem"
  install -m 0600 "$GATEWAY_SERVER_KEY" "$GATEWAY_STATE_DIR/public-server-key.pem"
}

gateway_write_service() {
  local env="$GATEWAY_STATE_DIR/gateway.env"
  gateway_install_public_certificate
  {
    printf 'CDNCA_GATEWAY_ENROLLMENT_ADDR=0.0.0.0:%s\n' "$GATEWAY_ENROLLMENT_PORT"
    printf 'CDNCA_GATEWAY_AGENT_ADDR=0.0.0.0:%s\n' "$GATEWAY_AGENT_PORT"
    printf 'CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT=%s:%s\n' "$GATEWAY_HOST" "$GATEWAY_AGENT_PORT"
    printf 'CDNCA_GATEWAY_HEALTH_ADDR=127.0.0.1:8082\n'
    printf 'CDNCA_GATEWAY_VERSION=%s\n' "$CONTROL_VERSION"
    cat "$GATEWAY_STATE_DIR/pki/binding.env"
    if [ -n "$GATEWAY_SERVER_CERT" ]; then
      printf 'CDNCA_GATEWAY_TUNNEL_TLS_CERT_FILE=%s\n' "$GATEWAY_STATE_DIR/public-server.pem"
      printf 'CDNCA_GATEWAY_TUNNEL_TLS_KEY_FILE=%s\n' "$GATEWAY_STATE_DIR/public-server-key.pem"
    fi
  } >"$TEMP_DIR/gateway.env"
  install -m 0600 "$TEMP_DIR/gateway.env" "$env"
  cat >"/etc/systemd/system/${GATEWAY_SERVICE_NAME}.service" <<UNIT
[Unit]
Description=CDNCA standalone Agent Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
UMask=0077
EnvironmentFile=${env}
ExecStart=${GATEWAY_ROOT}/bin/agent-gateway
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectHome=read-only
ProtectSystem=full
ReadWritePaths=${GATEWAY_STATE_DIR}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT
  systemd_compat_apply "/etc/systemd/system/${GATEWAY_SERVICE_NAME}.service" "${GATEWAY_SERVICE_NAME}.service" ||
    fail "cannot render systemd compatibility for ${GATEWAY_SERVICE_NAME}"
  systemctl daemon-reload
  systemctl enable "$GATEWAY_SERVICE_NAME" >/dev/null
  systemctl restart "$GATEWAY_SERVICE_NAME"
  for _ in $(seq 1 30); do
    if systemctl is-active --quiet "$GATEWAY_SERVICE_NAME" &&
      curl -fsS --connect-timeout 2 --max-time 5 http://127.0.0.1:8082/health/ready >/dev/null; then
      return 0
    fi
    progress_tick ' Agent Gateway 就绪' 60
    sleep 2
  done
  journalctl -u "$GATEWAY_SERVICE_NAME" -n 80 --no-pager >&2 || true
  fail 'Agent Gateway did not become ready; check that the control plane allows this host (Gateway page) and its ports 9446/4223/6380'
}

# One command: --control <console> + token, everything else from the control
# plane (ADR 0013 §3.1). Ports: random 20000-29999 or --gateway-ports; on a
# dedicated Gateway host 443 is allowed (MASTER_PORT is not ours here).
# --mode gateway takes a different option set, so it is dispatched before parse_args.
gateway_mode_requested() {
  local previous=""
  for argument in "$@"; do
    [ "$previous" != --mode ] || [ "$argument" != gateway ] || return 0
    previous=$argument
  done
  return 1
}

gateway_main() {
  [ "$EUID" -eq 0 ] || fail 'run this installer as root'
  gateway_parse_args "$@"
  [ -n "$GATEWAY_CONTROL" ] && valid_https_url "$GATEWAY_CONTROL" && no_newlines "$GATEWAY_CONTROL" ||
    fail '--mode gateway requires --control https://<management console>'
  [ ! -e "$GATEWAY_STATE_DIR" ] || fail 'a Gateway is already installed on this host; delete it in the Gateway page and remove /etc/cdnca-gateway first'
  for command in curl jq openssl sha256sum systemctl ss; do command -v "$command" >/dev/null 2>&1 || fail "missing $command"; done
  [ -n "$GATEWAY_HOST" ] || GATEWAY_HOST=$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)
  GATEWAY_HOST=$(printf '%s' "$GATEWAY_HOST" | tr '[:upper:]' '[:lower:]')
  valid_host "$GATEWAY_HOST" || fail '--gateway-host is required (this Gateway public name or IP)'
  MASTER_PORT=0
  select_gateway_ports
  gateway_check_public_certificate
  gateway_read_token
  gateway_fetch_root_ca
  gateway_download_package
  install -d -m 0700 "$GATEWAY_STATE_DIR"
  printf '%s\n' "$GATEWAY_TOKEN" | "$GATEWAY_ROOT/bin/agent-gateway" bind --control "$GATEWAY_CONTROL" \
    --root-ca "$GATEWAY_ROOT_CA_FILE" --output "$GATEWAY_STATE_DIR/pki" \
    --enrollment-port "$GATEWAY_ENROLLMENT_PORT" --agent-port "$GATEWAY_AGENT_PORT" --version "$CONTROL_VERSION" ||
    fail 'Gateway binding failed; generate a new token in the Gateway page (tokens are single-use, 1 hour)'
  gateway_write_service
  [ "$SKIP_FIREWALL" = true ] || warn "firewall was not changed; allow TCP ${GATEWAY_ENROLLMENT_PORT},${GATEWAY_AGENT_PORT} on this host"
  print_gateway_ports
  log "standalone Gateway bound to $GATEWAY_CONTROL and ready"
}

write_gateway_environment() {
  cat >"$GATEWAY_ENV_FILE" <<EOF
CDNCA_GATEWAY_ENROLLMENT_ADDR=0.0.0.0:${GATEWAY_ENROLLMENT_PORT}
CDNCA_GATEWAY_AGENT_ADDR=0.0.0.0:${GATEWAY_AGENT_PORT}
CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT=${GATEWAY_HOST}:${GATEWAY_AGENT_PORT}
CDNCA_GATEWAY_HEALTH_ADDR=127.0.0.1:8082
CDNCA_GATEWAY_INSTANCE_ID=${INSTALLATION_ID}
CDNCA_GATEWAY_VERSION=${CONTROL_VERSION}
CDNCA_GATEWAY_TLS_CERT_FILE=${PKI_DIR}/gateway-server.pem
CDNCA_GATEWAY_TLS_KEY_FILE=${PKI_DIR}/gateway-server-key.pem
CDNCA_GATEWAY_AGENT_CLIENT_CA_FILE=${PKI_DIR}/node-ca-cert.pem
CDNCA_CONTROL_ADDRESS=127.0.0.1:9091
CDNCA_CONTROL_SERVER_NAME=localhost
CDNCA_CONTROL_CLIENT_CERT_FILE=${PKI_DIR}/gateway-control-client.pem
CDNCA_CONTROL_CLIENT_KEY_FILE=${PKI_DIR}/gateway-control-client-key.pem
CDNCA_CONTROL_SERVER_CA_FILE=${PKI_DIR}/root-ca-cert.pem
CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN=spiffe://cdn-platform/gateway/control
CDNCA_REDIS_URL=${REDIS_URL}
CDNCA_NATS_URL=${NATS_URL}
CDNCA_TELEMETRY_NATS_URL=${NATS_TELEMETRY_URL}
EOF
  chmod 0600 "$GATEWAY_ENV_FILE"
}

setup_gateway() {
  log 'starting Agent Gateway'
  write_gateway_environment
  cat >"/etc/systemd/system/${GATEWAY_SERVICE_NAME}.service" <<EOF
[Unit]
Description=CDNCA Agent Gateway
After=${SERVICE_NAME}.service ${NATS_SERVICE_NAME}.service redis-server.service
Wants=network-online.target

[Service]
Type=simple
User=root
UMask=0077
EnvironmentFile=${GATEWAY_ENV_FILE}
ExecStart=${NATIVE_ROOT}/current/bin/agent-gateway
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectHome=read-only
ProtectSystem=full
ReadWritePaths=${CONFIG_DIR} ${DATA_DIR}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  systemd_compat_apply "/etc/systemd/system/${GATEWAY_SERVICE_NAME}.service" "${GATEWAY_SERVICE_NAME}.service" || fail "cannot render systemd compatibility for ${GATEWAY_SERVICE_NAME}"
  systemctl daemon-reload
  systemctl enable "$GATEWAY_SERVICE_NAME" >/dev/null
  systemctl restart "$GATEWAY_SERVICE_NAME"
  for _ in $(seq 1 30); do
    if systemctl is-active --quiet "$GATEWAY_SERVICE_NAME" &&
      curl -fsS --connect-timeout 2 --max-time 5 http://127.0.0.1:8082/health/ready >/dev/null; then
      return 0
    fi
    progress_tick ' Agent Gateway 就绪' 60
    sleep 2
  done
  journalctl -u "$GATEWAY_SERVICE_NAME" -n 80 --no-pager >&2 || true
  fail 'Agent Gateway did not become ready'
}

write_nginx_config() {
  local nginx_bin
  nginx_bin=$(control_nginx_bin)
  mkdir -p "$NGINX_RUNTIME_DIR" "$NGINX_RUNTIME_DIR"/{client_temp,proxy_temp,fastcgi_temp,uwsgi_temp,scgi_temp}
  chmod 0755 "$NGINX_RUNTIME_DIR"
  cat >"$NGINX_CONF" <<EOF
pid ${NGINX_RUNTIME_DIR}/nginx.pid;
error_log stderr warn;

events { worker_connections 1024; }

http {
    large_client_header_buffers 4 16k;
    include $(control_nginx_mime_types);
    include /etc/cdnca-upgrade/plan-source-nginx.conf;
    default_type application/octet-stream;
    server_tokens off;
    client_body_temp_path ${NGINX_RUNTIME_DIR}/client_temp;
    proxy_temp_path ${NGINX_RUNTIME_DIR}/proxy_temp;
    fastcgi_temp_path ${NGINX_RUNTIME_DIR}/fastcgi_temp;
    uwsgi_temp_path ${NGINX_RUNTIME_DIR}/uwsgi_temp;
    scgi_temp_path ${NGINX_RUNTIME_DIR}/scgi_temp;
    sendfile on;
    keepalive_timeout 65;
    gzip on;
    gzip_static on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 5;
    gzip_min_length 1024;
    # API JSON is not compressed: nginx would weaken its ETag and break revision checks.
    gzip_types application/javascript text/javascript text/css image/svg+xml text/plain;

    # One server-level Cache-Control: a location add_header would drop the
    # inherited security headers. Only successful content-hashed Vite assets
    # are immutable; an empty value lets the brand-asset upstream policy pass.
    map "\$status:\$uri" \$cdnca_cache_control {
        default "no-store";
        "~^(?:200|304):/(?:dashboard/)?assets/[^/]+-[-_A-Za-z0-9]{8,}\.[^/]+\$" "public, max-age=31536000, immutable";
        "~^(?:200|304):/site/assets/[^/]+-[-_A-Za-z0-9]{8,}\.[^/]+\$" "public, max-age=31536000, immutable";
        "~^(?:200|304):/v1/brand-assets/(?:favicon|logo|login_ad)\$" "";
    }

    server {
        listen ${WEB_LISTEN} ssl http2;
        server_name _;${WEB_REAL_IP}
        root ${WEB_ROOT};
        ssl_certificate ${PUBLIC_CERT_PATH};
        ssl_certificate_key ${PUBLIC_KEY_PATH};
        ssl_protocols TLSv1.2 TLSv1.3;
        add_header Cache-Control \$cdnca_cache_control always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;

        location = /healthz {
            access_log off;
            default_type text/plain;
            return 200 "ok\\n";
        }
        location = /favicon.ico { access_log off; log_not_found off; try_files /site/favicon.ico =404; }
        location = /robots.txt { try_files /site/robots.txt =404; }
        location = /downloads/gateway-ca.pem {
            alias ${DOWNLOAD_DIR}/gateway-ca.pem;
            default_type application/x-pem-file;
        }
        location = /runtime-config.js {
            alias ${DATA_DIR}/runtime-config.js;
            default_type application/javascript;
        }
        location = /dashboard/runtime-config.js {
            alias ${DATA_DIR}/runtime-config.js;
            default_type application/javascript;
        }
        location = /v1/brand-assets/favicon {
            proxy_intercept_errors on;
            error_page 404 = @brand_favicon_fallback;
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_pass http://127.0.0.1:8080;
        }
        location = /v1/brand-assets/logo {
            proxy_intercept_errors on;
            error_page 404 = @brand_logo_fallback;
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_pass http://127.0.0.1:8080;
        }
        location = /v1/brand-assets/login_ad {
            proxy_intercept_errors on;
            error_page 404 = @brand_login_ad_fallback;
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_pass http://127.0.0.1:8080;
        }
        location @brand_favicon_fallback {
            if (\$request_method !~ "^(GET|HEAD)\$") { return 404; }
            rewrite ^ /dashboard/favicon.png last;
        }
        location @brand_logo_fallback {
            if (\$request_method !~ "^(GET|HEAD)\$") { return 404; }
            rewrite ^ /dashboard/logo.png last;
        }
        location @brand_login_ad_fallback {
            if (\$request_method !~ "^(GET|HEAD)\$") { return 404; }
            rewrite ^ /dashboard/ad.jpeg last;
        }
        # Served from the active release so a management upgrade refreshes the
        # node installer; releases that predate it fall back to the copy
        # published at install time.
        location = /downloads/install-node.sh {
            root ${NATIVE_ROOT}/current/static/web;
            default_type text/x-shellscript;
            try_files \$uri @published_node_installer;
        }
        location @published_node_installer {
            root ${DATA_DIR};
            default_type text/x-shellscript;
            try_files /downloads/install-node.sh =404;
        }
        # Billing integration PHP modules (ADR 0019) ship with the active release.
        location ^~ /downloads/billing-bridge/ {
            root ${NATIVE_ROOT}/current/static/web;
            try_files \$uri =404;
            default_type application/zip;
        }
        location ^~ /downloads/ {
            root ${DATA_DIR};
            try_files \$uri =404;
            default_type application/octet-stream;
        }
        location = /health/live { proxy_pass http://127.0.0.1:8080/health/live; }
        location = /health/ready { proxy_pass http://127.0.0.1:8080/health/ready; }
        location = /v1/internal { return 404; }
        location ^~ /v1/internal/ { return 404; }
        location ^~ /v1/auth/ {
            # Token-bearing credential responses are never compressed (BREACH).
            gzip off;
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_pass http://127.0.0.1:8080;
        }
        location ^~ /v1/ {
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_pass http://127.0.0.1:8080;
        }
        location ~* ^/(?:dashboard/)?(?:assets/.*|.*\.(?:css|js|mjs|map|json|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf))\$ {
            rewrite ^/dashboard/(.*)\$ /\$1 break;
            try_files \$uri =404;
        }
        # /dashboard without a trailing slash is the console entry too; otherwise it
        # falls to location / -> @website and serves the public website shell.
        location = /dashboard {
            rewrite ^ /index.html break;
        }
        location /dashboard/ {
            rewrite ^/dashboard/(.*)\$ /\$1 break;
            try_files \$uri \$uri/ /index.html;
        }
        # Theme plugin page bundles (/site/t/<theme-id>/<version>/, installed by
        # control-api): sandboxed without allow-same-origin, in an opaque origin
        # that cannot read the console's cookies or storage. Only here: the
        # built-in website (/site/index.html, /site/assets/) is not sandboxed.
        # Headers set here replace the server's, so those are repeated.
        # A raw /site/t/ request with a dot segment (../, %2e%2e, dot files,
        # also behind an encoded slash) is refused before nginx normalizes it
        # into a path outside the bundles.
        if (\$request_uri ~ "^/site/t/(?:[^?]*(?:/|%2[fF]))?(?:\\.|%2[eE])") { return 404; }
        location ^~ /site/t/ {
            alias ${DATA_DIR}/site-themes/;
            limit_except GET { deny all; }
            add_header Cache-Control \$cdnca_cache_control always;
            add_header X-Content-Type-Options "nosniff" always;
            add_header X-Frame-Options "DENY" always;
            add_header Referrer-Policy "strict-origin-when-cross-origin" always;
            add_header Content-Security-Policy "sandbox allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox allow-top-navigation-by-user-activation; default-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'" always;
            # Module scripts, fonts and fetches of the opaque origin are CORS
            # requests (Origin: null); never with credentials.
            add_header Access-Control-Allow-Origin "*" always;
            error_page 403 404 405 500 502 503 504 /site/t/.error;
            # Bundle paths never start a segment with a dot: those are
            # control-api's staging directories and link swaps.
            location ~ ^/site/t/(?:.*/)?\. { return 404; }
            location = /site/t/.error {
                internal;
                default_type text/plain;
                return 200 "error\\n";
            }
        }
        # The website answers every path outside the console.
        location / {
            try_files \$uri @website;
        }
        # The active page bundle's entry (control-api links site-themes/current.html
        # to it; an internal redirect into /site/t/, under its CSP), else the
        # release's built-in website, else the console entry.
        location @website {
            if (-f ${DATA_DIR}/site-themes/current.html) { rewrite ^ /site/t/current.html last; }
            try_files /site/index.html /index.html;
        }
    }
$(node_download_server)
}
EOF
  "$nginx_bin" -t -c "$NGINX_CONF" -p "$NGINX_RUNTIME_DIR" >/dev/null
}

# 验证节点升级下载端点的根证书文件；空 = 节点用安装时从系统信任库选出的根（公网证书）。
# 升级信任文档与 control.env CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE（签进升级执行的下载策略）
# 用同一规则。宝塔环境：节点经直连端口 NODE_DOWNLOAD_PORT 下载（public-server.pem，
# 本机私有根 CA 签发），不依赖宝塔站点证书是否受信。系统信任库验不过的运营者证书（如 Let's
# Encrypt 限流期间的临时自签）按其自身信任，与本机自检同一规则，须为 CA（CA:TRUE）。
upgrade_download_root_ca_file() {
  if [ "${INSTALL_ENV:-}" = bt ] || [ -z "$PUBLIC_CERT_FILE" ]; then
    printf '%s' "${PKI_DIR}/root-ca-cert.pem"
  elif [ "$(public_https_trust_args | head -n 1)" = --cacert ]; then
    printf '%s' "$PUBLIC_CERT_PATH"
  fi
}

upgrade_download_root_env() {
  local root
  root=$(upgrade_download_root_ca_file)
  [ -z "$root" ] || printf 'CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE=%s' "$root"
}

upgrade_download_origin() {
  if [ "${INSTALL_ENV:-}" = bt ]; then printf 'https://%s:%s' "$CONTROL_DOMAIN" "$NODE_DOWNLOAD_PORT"; else printf '%s' "$CONTROL_ORIGIN"; fi
}

# 宝塔模式的直连下载 server：只提供升级制品（内容寻址、经签名摘要校验），其余一律 404。
node_download_server() {
  [ "${INSTALL_ENV:-}" = bt ] || return 0
  cat <<EOF

    # 宝塔环境节点升级下载直连端口：证书由本机私有根 CA 签发，节点已信任。
    server {
        listen ${NODE_DOWNLOAD_PORT} ssl;
        server_name _;
        ssl_certificate ${PKI_DIR}/public-server.pem;
        ssl_certificate_key ${PKI_DIR}/public-server-key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        add_header X-Content-Type-Options "nosniff" always;
        location ^~ /downloads/edge-agent/upgrades/sha256/ {
            alias ${DOWNLOAD_DIR}/edge-agent/upgrades/sha256/;
            limit_except GET { deny all; }
            default_type application/octet-stream;
        }
        location / { return 404; }
    }
EOF
}

# public_https_trust_args: prints, one per line, the curl trust options for the
# local self-checks of the public HTTPS listener. The private CA signs the
# built-in certificate; an operator-supplied certificate the system store
# cannot verify (for example a temporary self-signed one while Let's Encrypt
# is rate limited) is trusted as itself, so the self-check tests the service.
# 管理端网页的 nginx：宝塔环境用宝塔自带的 nginx 二进制另起实例（独立配置与 pid，
# 不碰宝塔的 nginx.conf）；依赖 helper 在宝塔主机上不装发行版 nginx。
control_nginx_bin() {
  if [ "$INSTALL_ENV" = bt ] && [ -x "${BT_ROOT}/www/server/nginx/sbin/nginx" ]; then
    printf '%s' "${BT_ROOT}/www/server/nginx/sbin/nginx"
  else
    command -v nginx
  fi
}
control_nginx_mime_types() {
  if [ "$INSTALL_ENV" = bt ] && [ -x "${BT_ROOT}/www/server/nginx/sbin/nginx" ]; then
    printf '%s' "${BT_ROOT}/www/server/nginx/conf/mime.types"
  else
    printf '/etc/nginx/mime.types'
  fi
}

# 本机自检地址：管理端网页实际监听端口（宝塔环境是回环 WEB_PORT，普通环境即 MASTER_PORT）。
local_web_origin() {
  local host=$CONTROL_DOMAIN
  case "$host" in *:*) host="[$host]" ;; esac
  if [ "$WEB_PORT" = 443 ]; then printf 'https://%s' "$host"; else printf 'https://%s:%s' "$host" "$WEB_PORT"; fi
}

public_https_trust_args() {
  if [ -z "$PUBLIC_CERT_FILE" ]; then
    printf '%s\n' --cacert "${PKI_DIR}/root-ca-cert.pem"
  elif ! openssl verify -untrusted "$PUBLIC_CERT_PATH" "$PUBLIC_CERT_PATH" >/dev/null 2>&1; then
    printf '%s\n' --cacert "$PUBLIC_CERT_PATH"
  fi
}

setup_web() {
  local nginx_bin
  local -a trust_args=()
  local option
  while IFS= read -r option; do trust_args+=("$option"); done < <(public_https_trust_args)
  nginx_bin=$(control_nginx_bin)
  log 'starting control web'
  write_nginx_config
  cat >"/etc/systemd/system/${WEB_SERVICE_NAME}.service" <<EOF
[Unit]
Description=CDNCA control web
After=${SERVICE_NAME}.service ${GATEWAY_SERVICE_NAME}.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${nginx_bin} -c ${NGINX_CONF} -p ${NGINX_RUNTIME_DIR} -g 'daemon off;'
ExecReload=${nginx_bin} -s reload -c ${NGINX_CONF} -p ${NGINX_RUNTIME_DIR}
ExecStop=/bin/kill -s QUIT \$MAINPID
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectHome=read-only
ProtectSystem=full
ReadWritePaths=${NGINX_RUNTIME_DIR}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  systemd_compat_apply "/etc/systemd/system/${WEB_SERVICE_NAME}.service" "${WEB_SERVICE_NAME}.service" || fail "cannot render systemd compatibility for ${WEB_SERVICE_NAME}"
  systemctl daemon-reload
  systemctl enable "$WEB_SERVICE_NAME" >/dev/null
  systemctl restart "$WEB_SERVICE_NAME"
  for _ in $(seq 1 30); do
    if systemctl is-active --quiet "$WEB_SERVICE_NAME" &&
      curl -fsS "${trust_args[@]}" --connect-timeout 2 --max-time 5 \
        --resolve "${CONTROL_DOMAIN}:${WEB_PORT}:127.0.0.1" "$(local_web_origin)/healthz" >/dev/null; then
      return 0
    fi
    progress_tick '管理端网页就绪' 60
    sleep 2
  done
  journalctl -u "$WEB_SERVICE_NAME" -n 80 --no-pager >&2 || true
  fail 'control web did not become ready'
}

verify_native_plan_source() {
  local path=/v1/internal/control-upgrade/plan code header="$TEMP_DIR/plan-source-header" certificate key
  local commit tree artifact runner
  local -a public_trust=()
  local option
  while IFS= read -r option; do public_trust+=("$option"); done < <(public_https_trust_args)
  {
    printf 'Authorization: Bearer '
    tr -d '\n' </etc/cdnca-upgrade/plan-source-token
    printf '\n'
  } >"$header"
  chmod 0600 "$header"
  certificate=/etc/cdnca-upgrade/plan-source-client.pem
  key=/etc/cdnca-upgrade/plan-source-client-key.pem
  code=$(curl -sS --connect-timeout 2 --max-time 15 --cacert /etc/cdnca-upgrade/plan-source-ca.pem \
    --cert "$certificate" --key "$key" -H "@$header" -D "$TEMP_DIR/plan-source-headers" \
    -o "$TEMP_DIR/plan-source-body" -w '%{http_code}' "https://127.0.0.1:9445$path") || fail 'private plan source mTLS request failed'
  [ "$code" = 204 ] && [ ! -s "$TEMP_DIR/plan-source-body" ] || fail 'fresh plan source must have no upgrade plan'
  tr -d '\r' <"$TEMP_DIR/plan-source-headers" | grep -Fxiq "X-CDNCA-Installation-ID: $INSTALLATION_ID" || fail 'plan source installation binding differs'
  tr -d '\r' <"$TEMP_DIR/plan-source-headers" | grep -Fxiq 'X-CDNCA-Control-Upgrade-Operation: control-upgrade' || fail 'plan source operation binding differs'
  code=$(curl -sS --connect-timeout 2 --max-time 15 --cacert /etc/cdnca-upgrade/plan-source-ca.pem \
    --cert "$certificate" --key "$key" -H 'Authorization: Bearer deliberately-invalid-test-token' \
    -o /dev/null -w '%{http_code}' "https://127.0.0.1:9445$path") || fail 'wrong-token rejection request failed'
  [ "$code" = 401 ] || fail 'private plan source accepted an invalid token'
  code=$(curl -sS --connect-timeout 2 --max-time 15 --cacert /etc/cdnca-upgrade/plan-source-ca.pem \
    -H "@$header" -o /dev/null -w '%{http_code}' "https://127.0.0.1:9445$path" 2>/dev/null) || code=000
  [[ "$code" = 000 || "$code" = 400 ]] || fail 'private plan source did not reject a missing client certificate'
  code=$(curl -sS --connect-timeout 2 --max-time 15 --cacert /etc/cdnca-upgrade/plan-source-ca.pem \
    --cert "${PKI_DIR}/gateway-control-client.pem" --key "${PKI_DIR}/gateway-control-client-key.pem" \
    -H "@$header" -o /dev/null -w '%{http_code}' "https://127.0.0.1:9445$path" 2>/dev/null) || code=000
  [[ "$code" = 000 || "$code" = 400 ]] || fail 'private plan source did not reject a different client CA'
  code=$(curl -sS "${public_trust[@]}" --connect-timeout 2 --max-time 15 \
    --resolve "${CONTROL_DOMAIN}:${WEB_PORT}:127.0.0.1" -H "@$header" \
    -o /dev/null -w '%{http_code}' "$(local_web_origin)$path") || fail 'public internal-path rejection request failed'
  [ "$code" = 404 ] || fail 'public listener exposed the internal plan API'
  rm -f -- "$header"
  commit=$(jq -er .source_commit "$TEMP_DIR/native-baseline-input.json")
  tree=$(jq -er .source_tree "$TEMP_DIR/native-baseline-input.json")
  artifact=$(jq -er .archive_sha256 "$TEMP_DIR/native-baseline-input.json")
  runner=$(jq -er .runner_sha256 "$TEMP_DIR/native-baseline-input.json")
  systemctl enable --now cdnca-native-control-upgrade-runner.service >/dev/null
  for _ in $(seq 1 30); do
    if systemctl is-active --quiet cdnca-native-control-upgrade-runner.service &&
      timeout 2s "$CONTROL_BINARY" verify-native-upgrade --installation-id "$INSTALLATION_ID" --version "$CONTROL_VERSION" \
        --source-commit "$commit" --source-tree "$tree" --artifact-sha256 "$artifact" --runner-sha256 "$runner" >/dev/null 2>&1; then
      return 0
    fi
    progress_tick '升级执行器就绪' 60
    sleep 2
  done
  fail 'native upgrade runner could not prove live readiness for the installed release'
}

migrate_database() {
  log 'applying the release database migrations'
  DATABASE_URL="$DATABASE_URL" "$CONTROL_BINARY" migrate up >"${TEMP_DIR}/migration.log" 2>&1 \
    || fail "control-api database migration failed; $(progress_keep_output "${TEMP_DIR}/migration.log" 'control-api migrate up')"
}

# cdncaCE: no license service. Record the control installation (the row node
# CA epochs, node identity and telemetry key on); the community entitlement is
# built into control-api.
install_community() {
  log 'recording the community edition installation'
  DATABASE_URL="$DATABASE_URL" "$CONTROL_BINARY" install-community --installation-id "$INSTALLATION_ID" \
    >"${TEMP_DIR}/community.log" 2>&1 \
    || fail "community installation record failed; $(progress_keep_output "${TEMP_DIR}/community.log" 'control-api install-community')"
}



prompt_admin_username() {
  if [ -z "$ADMIN_USERNAME" ]; then
    [ -t 0 ] || fail '--admin-username is required for a non-interactive installation'
    printf '管理员用户名（小写字母开头，3-128 位）: ' >&2
    IFS= read -r ADMIN_USERNAME
  fi
  ADMIN_USERNAME=$(printf '%s' "$ADMIN_USERNAME" | tr '[:upper:]' '[:lower:]')
  [[ "$ADMIN_USERNAME" =~ ^[a-z][a-z0-9_.-]{2,127}$ ]] ||
    fail 'administrator username must start with a lowercase letter and contain only lowercase letters, digits, dot, underscore, or dash'
}

# Same rule as libs/passwordpolicy: 8-1024
# printable ASCII characters (no space), at least two of upper case, lower
# case, digits and symbols. Prints the reason and returns 1 when unmet.
check_admin_password_policy() {
  local value=$1 classes=0
  if [ "${#value}" -lt 8 ] || [ "${#value}" -gt 1024 ]; then
    printf '%s\n' 'administrator password must contain 8 to 1024 characters' >&2
    return 1
  fi
  if ! LC_ALL=C grep -Eq '^[!-~]+$' <<<"$value"; then
    printf '%s\n' 'administrator password may contain only ASCII letters, digits and symbols (no space, Chinese or full-width characters)' >&2
    return 1
  fi
  LC_ALL=C grep -q '[A-Z]' <<<"$value" && classes=$((classes + 1))
  LC_ALL=C grep -q '[a-z]' <<<"$value" && classes=$((classes + 1))
  LC_ALL=C grep -q '[0-9]' <<<"$value" && classes=$((classes + 1))
  LC_ALL=C grep -q '[^A-Za-z0-9]' <<<"$value" && classes=$((classes + 1))
  if [ "$classes" -lt 2 ]; then
    printf '%s\n' 'administrator password needs at least two of upper case, lower case, digits and symbols' >&2
    return 1
  fi
}

prompt_admin_password() {
  if [ -n "$ADMIN_PASSWORD" ]; then
    check_admin_password_policy "$ADMIN_PASSWORD" || fail 'administrator password does not meet the password policy'
    return 0
  fi
  if [ -n "$ADMIN_PASSWORD_FILE" ]; then
    read_owner_only_value "$ADMIN_PASSWORD_FILE" 'administrator password' ADMIN_PASSWORD
  else
    [ -t 0 ] || fail '--admin-password-file is required for a non-interactive installation'
    local confirmation
    printf '管理员密码（8-1024 位，至少包含大写字母、小写字母、数字、符号中的两种，不能含空格或中文；输入不回显）: ' >&2
    IFS= read -r -s ADMIN_PASSWORD
    printf '\n再次输入管理员密码: ' >&2
    IFS= read -r -s confirmation
    printf '\n' >&2
    [ "$ADMIN_PASSWORD" = "$confirmation" ] || fail 'administrator password confirmation did not match'
    unset confirmation
  fi
  check_admin_password_policy "$ADMIN_PASSWORD" || fail 'administrator password does not meet the password policy'
}

prompt_certificate_email() {
  if [ -z "$CERTIFICATE_EMAIL" ]; then
    [ -t 0 ] || fail '--certificate-email is required for a non-interactive installation'
    printf '证书联系邮箱（用于管理端与网站 HTTPS 证书自动申请，需真实可用）: ' >&2
    IFS= read -r CERTIFICATE_EMAIL
  fi
  [[ "$CERTIFICATE_EMAIL" =~ ^[A-Za-z0-9_%+.-]+@[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}$ ]] || fail 'invalid certificate contact email'
  [[ ${#CERTIFICATE_EMAIL} -le 254 && "$CERTIFICATE_EMAIL" != *..* && "$CERTIFICATE_EMAIL" != .* && "$CERTIFICATE_EMAIL" != *.@* ]] || fail 'invalid certificate contact email'
  local lower_email
  lower_email=$(printf '%s' "$CERTIFICATE_EMAIL" | tr '[:upper:]' '[:lower:]')
  case "$lower_email" in *.local|*.localhost|*.invalid|*.test) fail 'certificate contact requires a public email domain' ;; esac
}

setup_service() {
  cat >"/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=CDNCA control API
After=network-online.target postgresql.service redis-server.service systemd-tmpfiles-setup.service$(control_dependency_units)
Requires=systemd-tmpfiles-setup.service
Wants=network-online.target

[Service]
Type=simple
User=root
SupplementaryGroups=$(control_clamav_group)
UMask=0077
EnvironmentFile=${CONFIG_DIR}/control.env
EnvironmentFile=${CONFIG_DIR}/runtime-extra.env
EnvironmentFile=${CONFIG_DIR}/certificate-runtime/environment.env
EnvironmentFile=/etc/cdnca-upgrade/api.env
ExecStart=${NATIVE_ROOT}/current/bin/control-api serve
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectHome=read-only
ProtectSystem=full
ReadWritePaths=${CONFIG_DIR} ${DATA_DIR}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  systemd_compat_apply "/etc/systemd/system/${SERVICE_NAME}.service" "${SERVICE_NAME}.service" || fail "cannot render systemd compatibility for ${SERVICE_NAME}"
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null
  systemctl restart "$SERVICE_NAME"
  for _ in $(seq 1 30); do
    if systemctl is-active --quiet "$SERVICE_NAME" && curl -fsS --connect-timeout 2 --max-time 5 http://127.0.0.1:8080/health/ready >/dev/null; then
      return 0
    fi
    progress_tick ' control-api 就绪' 60
    sleep 2
  done
  journalctl -u "$SERVICE_NAME" -n 80 --no-pager >&2 || true
  fail 'control-api did not become ready'
}

resolved_addresses() { getent ahosts "$1" 2>/dev/null | awk '{ print $1 }' | sort -u | paste -sd, -; }

# A copied install command carries no certificate files, so a DNS control domain
# gets a publicly trusted Let's Encrypt certificate here instead of the private
# CA (which browsers reject). Port 80 is free: the packaged nginx is disabled and
# the control web only listens on MASTER_PORT, so standalone HTTP-01 also renews.
# Prints the certbot lineage (/etc/letsencrypt/live/<name>) holding both
# operator-supplied files, or nothing when they are not one certbot lineage.
public_certificate_lineage() {
  local cert_dir key_dir
  cert_dir=$(dirname "$PUBLIC_CERT_FILE")
  key_dir=$(dirname "$PUBLIC_KEY_FILE")
  [[ "$cert_dir" =~ ^/etc/letsencrypt/live/[^/]+$ ]] && [ "$cert_dir" = "$key_dir" ] || return 0
  printf '%s\n' "$cert_dir"
}

# Renewals replace the lineage's live files; copy them to the paths nginx
# serves and reload. Copies the same file names the installation used.
install_public_certificate_renewal_hook() {
  local live=$1 hook="/etc/letsencrypt/renewal-hooks/deploy/cdnca-control-web.sh"
  install -d -m 0755 "$(dirname "$hook")"
  cat >"$hook" <<EOF
#!/bin/sh
set -eu
[ "\${RENEWED_LINEAGE:-}" = "${live}" ] || exit 0
install -m 0444 "${live}/$(basename "$PUBLIC_CERT_FILE")" "${PKI_DIR}/public-cert.pem"
install -m 0600 "${live}/$(basename "$PUBLIC_KEY_FILE")" "${PKI_DIR}/public-key.pem"
systemctl reload "${WEB_SERVICE_NAME}"
EOF
  chmod 0755 "$hook"
}

# certbot 签发判断（去掉 certbot 的“保留未到期证书”参数）：输出 new / skip / renew。
# 没有证书 new；已有证书与这次同为正式或同为测试、SAN 与这次域名一致且 30 天内不到期 skip（不请求 CA，
# 重装不打满频率）；测试证书（签发者含 "(STAGING)"/"Fake LE"，或 renewal 配置指向 staging）换正式、
# 域名变化、临近到期 renew（--force-renewal）。已有正式证书而这次要测试证书 skip（保留正式证书）。
acme_issue_mode() { # <live 目录> <renewal 配置文件> <这次是否测试证书 true|false> <域名...>
  local cert=$1/cert.pem conf=$2 staging=$3 issuer existing=false have want
  shift 3
  [ -s "$cert" ] || { echo new; return 0; }
  issuer=$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null || true)
  case $issuer in *'(STAGING)'* | *'Fake LE'*) existing=true ;; esac
  if [ -f "$conf" ] && grep -Eq '^[[:space:]]*server[[:space:]]*=.*staging' "$conf"; then existing=true; fi
  if [ "$existing" = false ] && [ "$staging" = true ]; then echo skip; return 0; fi
  if [ "$existing" != "$staging" ]; then echo renew; return 0; fi
  have=$(openssl x509 -in "$cert" -noout -text 2>/dev/null | sed -n '/Subject Alternative Name/{n;p;}' |
    grep -o 'DNS:[^, ]*' | cut -c5- | sort -u || true)
  want=$(printf '%s
' "$@" | sort -u)
  if [ "$have" = "$want" ] && openssl x509 -in "$cert" -noout -checkend 2592000 >/dev/null 2>&1; then
    echo skip
  else
    echo renew
  fi
}

issue_public_certificate() {
  local live
  if [ -n "$PUBLIC_CERT_FILE" ]; then
    # Operator-supplied files from a certbot lineage renew there: hook them up
    # like our own request. Anything else is renewed by the operator
    # (report_public_certificate_renewal tells how at the end).
    live=$(public_certificate_lineage)
    if [ -n "$live" ]; then
      log "public certificate comes from ${live}; installing the renewal deploy hook"
      install_public_certificate_renewal_hook "$live"
    fi
    return 0
  fi
  if control_domain_is_ip; then
    warn 'control-plane address is an IP literal; using the private CA certificate'
    return 0
  fi
  if [ "$INSTALL_ENV" = bt ]; then
    # 宝塔 nginx 占着 80/443，公网证书由宝塔站点申请；回环网页用私有 CA 证书。
    log 'BaoTa environment: the public certificate is issued by the BaoTa site; the loopback web uses the private CA'
    return 0
  fi
  local -a domains=(-d "$CONTROL_DOMAIN") names=("$CONTROL_DOMAIN") renew=()
  local mode
  # The web server answers every name, so cover www.<domain> as well when it
  # points at the same host; otherwise HTTP-01 for it would fail the request.
  if [[ "$CONTROL_DOMAIN" != www.* ]] && [ -n "$(resolved_addresses "www.$CONTROL_DOMAIN")" ] &&
    [ "$(resolved_addresses "www.$CONTROL_DOMAIN")" = "$(resolved_addresses "$CONTROL_DOMAIN")" ]; then
    domains+=(-d "www.$CONTROL_DOMAIN")
    names+=("www.$CONTROL_DOMAIN")
  fi
  live="/etc/letsencrypt/live/${CONTROL_DOMAIN}"
  mode=$(acme_issue_mode "$live" "/etc/letsencrypt/renewal/$CONTROL_DOMAIN.conf" false "${names[@]}")
  case $mode in renew) renew=(--force-renewal) ;; esac
  if [ "$mode" = skip ]; then
    log "${live} already holds a production certificate for ${names[*]} valid for more than 30 days; not requesting a new one"
    PUBLIC_CERT_FILE="${live}/fullchain.pem"
    PUBLIC_KEY_FILE="${live}/privkey.pem"
    install_public_certificate_renewal_hook "$live"
    return 0
  fi
  log "requesting a public HTTPS certificate for ${CONTROL_DOMAIN}"
  if ! command -v certbot >/dev/null 2>&1; then
    if [ "$(control_os_family)" = rhel ]; then
      dnf -y -q install certbot >/dev/null
    else
      DEBIAN_FRONTEND=noninteractive progress_run '安装 certbot' apt-get install -y -qq --no-install-recommends certbot >/dev/null
    fi
  fi
  ss -H -ltn | awk '$4 ~ /:80$/ { exit 1 }' || fail 'port 80 is in use; free it or pass --public-cert-file/--public-key-file'
  PROGRESS_RUN_OUTPUT="$TEMP_DIR/certbot.log" progress_run '向 Let'"'"'s Encrypt 申请证书' \
    certbot certonly --standalone --non-interactive --agree-tos --email "$CERTIFICATE_EMAIL" \
    --cert-name "$CONTROL_DOMAIN" "${domains[@]}" ${renew[@]+"${renew[@]}"} || {
    tail -n 20 "$TEMP_DIR/certbot.log" >&2
    fail "public certificate request failed; ensure ${CONTROL_DOMAIN} resolves here and TCP 80 is reachable, or pass --public-cert-file/--public-key-file"
  }
  PUBLIC_CERT_FILE="${live}/fullchain.pem"
  PUBLIC_KEY_FILE="${live}/privkey.pem"
  install_public_certificate_renewal_hook "$live"
}

# End of installation: an operator certificate outside a certbot lineage is not
# renewed here. Print its expiry and how to replace it.
report_public_certificate_renewal() {
  local not_after
  [ -n "$PUBLIC_CERT_FILE" ] && [ -z "$(public_certificate_lineage)" ] || return 0
  not_after=$(openssl x509 -in "$PUBLIC_CERT_PATH" -noout -enddate 2>/dev/null | sed 's/^notAfter=//') || true
  warn "管理端公网证书由你提供（${PUBLIC_CERT_FILE}），安装器不会自动续期；到期时间：${not_after:-无法读取}。"
  warn "续期后替换证书：install -m 0444 <新证书链> ${PKI_DIR}/public-cert.pem && install -m 0600 <新私钥> ${PKI_DIR}/public-key.pem && systemctl reload ${WEB_SERVICE_NAME}"
  warn '证书由 certbot 签发时，安装参数直接指向 /etc/letsencrypt/live/<名>/ 下的文件，安装器会装续期 hook 自动替换。'
}

# RHEL family with SELinux enabled (Debian/Ubuntu: no-op). Stock nginx stays
# confined in httpd_t: label what it serves or writes, its listen ports and the
# loopback proxying boolean. Our own Go services and RustFS run from bin_t as
# unconfined_service_t, like any third-party binary started by systemd.
selinux_fcontext() {
  semanage fcontext -a -t "$1" "$2" 2>/dev/null || semanage fcontext -m -t "$1" "$2"
}
selinux_http_port() {
  semanage port -a -t http_port_t -p tcp "$1" 2>/dev/null || semanage port -m -t http_port_t -p tcp "$1" 2>/dev/null ||
    semanage port -l | awk -v port="$1" '$1 == "http_port_t" { gsub(/,/, " "); for (i = 3; i <= NF; i++) if ($i == port) found = 1 } END { exit !found }' ||
    fail "cannot label TCP ${1} as http_port_t"
}
configure_selinux() {
  command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled || return 0
  command -v semanage >/dev/null 2>&1 && command -v restorecon >/dev/null 2>&1 ||
    fail 'SELinux is enabled but semanage/restorecon are missing; install policycoreutils-python-utils'
  log 'labelling the native runtime for SELinux'
  local native_parent=${NATIVE_ROOT%/cdnca}
  selinux_fcontext usr_t "${native_parent}(/.*)?"
  selinux_fcontext bin_t "${NATIVE_ROOT}(/.*)?"
  selinux_fcontext httpd_sys_content_t "${NATIVE_ROOT}/releases/[^/]+/static/web(/.*)?"
  selinux_fcontext bin_t '/usr/local/lib/cdnca-runtime(/.*)?'
  selinux_fcontext bin_t '/usr/local/libexec/cdnca(/.*)?'
  selinux_fcontext httpd_sys_content_t "${DOWNLOAD_DIR}(/.*)?"
  selinux_fcontext httpd_sys_content_t "${DATA_DIR}/runtime-config\\.js"
  selinux_fcontext httpd_sys_content_t "${DATA_DIR}/site-themes(/.*)?"
  selinux_fcontext httpd_var_run_t "${NGINX_RUNTIME_DIR}(/.*)?"
  selinux_fcontext cert_t "${PKI_DIR}(/.*)?"
  selinux_http_port "$WEB_PORT"
  [ "$INSTALL_ENV" != bt ] || selinux_http_port "$NODE_DOWNLOAD_PORT"
  selinux_http_port 9445
  setsebool -P httpd_can_network_connect on
  restorecon -RF "$native_parent" /usr/local/lib/cdnca-runtime /usr/local/libexec/cdnca "$DATA_DIR" "$PKI_DIR" \
    /usr/local/bin/nats-server "$NATS_CLI_BIN" 2>/dev/null || fail 'restorecon failed while labelling the native runtime'
}

configure_firewall() {
  [ "$SKIP_FIREWALL" = true ] && return 0
  warn "firewall was not changed; allow TCP ${MASTER_PORT} (management) and ${GATEWAY_ENROLLMENT_PORT},${GATEWAY_AGENT_PORT} (Gateway) in the host policy"
  ! remote_gateway_access ||
    warn "standalone Gateways reach TCP ${CONTROL_INTERNAL_REMOTE_PORT},${NATS_GATEWAY_WS_PORT},${REDIS_GATEWAY_TLS_PORT}; nftables already limits them to bound Gateways, open them in the cloud security group as well"
}

# Shown at the end of the installation (ADR 0013 §3.5; same text as the Gateway page).
print_gateway_ports() {
  cat >&2 <<EOF

节点通道（网关）端口：注册 ${GATEWAY_ENROLLMENT_PORT}，通道 ${GATEWAY_AGENT_PORT}，请在防火墙/安全组放行。
不套 CDN：节点直连这两个端口，无需其他配置。
套 CDN：在 CDN 上添加网关域名，开启 WebSocket，回源协议 HTTPS，回源端口填 ${GATEWAY_ENROLLMENT_PORT}，
       不缓存、对 /agent/v1/* 关闭 WAF 挑战；然后在"网关管理"把该入口的传输改为 WebSocket，
       并把该 CDN 的回源 IP 段加入"可信 CDN 回源段"。
阿里云经典 CDN 不支持 WebSocket，不能用；百度云 CDN 须把回源超时调到 60 秒以上。
EOF
}

bootstrap_admin() {
  prompt_admin_password
  log "creating administrator ${ADMIN_USERNAME}"
  BOOTSTRAP_PASSWORD="$ADMIN_PASSWORD" DATABASE_URL="$DATABASE_URL" "$CONTROL_BINARY" bootstrap-user --username "$ADMIN_USERNAME" --email "$ADMIN_EMAIL" --display-name "$ADMIN_USERNAME" --existing-ok \
    >"${TEMP_DIR}/bootstrap.log" 2>&1 || fail "administrator bootstrap failed; $(progress_keep_output "${TEMP_DIR}/bootstrap.log" 'control-api bootstrap-user')"
  unset ADMIN_PASSWORD
  printf '\nControl plane URL: https://%s\nAdministrator: %s (%s)\n' "$CONTROL_DOMAIN" "$ADMIN_USERNAME" "$ADMIN_EMAIL"
  printf '忘记管理员密码且没有其他管理员时，按本机手册以 root 恢复：%s\n' "${NATIVE_ROOT}/current/docs/platform-admin-recovery.md"
}

bootstrap_node_ca() {
  log 'registering the generated node CA epoch'
  DATABASE_URL="$DATABASE_URL" "$CONTROL_BINARY" bootstrap-node-ca \
    --username "$ADMIN_USERNAME" \
    --certificate-file "${PKI_DIR}/node-ca-cert.pem" \
    --key-id 'node-ca-bootstrap-v1' \
    >"${TEMP_DIR}/bootstrap-node-ca.log" 2>&1 ||
    fail "node CA epoch bootstrap failed; $(progress_keep_output "${TEMP_DIR}/bootstrap-node-ca.log" 'control-api bootstrap-node-ca')"
}

# Activate the project default system configuration (revision 1) so default
# TCP node monitoring is in force before the first node enrolls. The command is
# idempotent, audited and never replaces an existing active revision.
bootstrap_system_configuration() {
  log 'activating the default system configuration'
  DATABASE_URL="$DATABASE_URL" "$CONTROL_BINARY" bootstrap-system-configuration --username "$ADMIN_USERNAME" \
    >"${TEMP_DIR}/bootstrap-system-configuration.log" 2>&1 ||
    fail "system configuration bootstrap failed; $(progress_keep_output "${TEMP_DIR}/bootstrap-system-configuration.log" 'control-api bootstrap-system-configuration')"
}

bootstrap_analytics_history() {
  [ "$(control_database_psql analytics)" = t ] ||
    fail 'analytics runtime function privileges are missing; follow analytics-bootstrap-loopback.md without widening database privileges'
  # The signed official command reads secrets only from its protected environment.
  DATABASE_URL="$DATABASE_URL" CONTROL_INSTALLATION_ID="$INSTALLATION_ID" ANALYTICS_INGEST_NATS_URL="$NATS_URL" \
    python3 -I -B - "$NATIVE_SUPPORT/analytics-history-bootstrap" "$NATIVE_SUPPORT/install.manifest.json" \
    >"$TEMP_DIR/analytics-bootstrap.log" 2>&1 <<'PY_ANALYTICS_BOOTSTRAP' || fail 'analytics history initialization failed; no Control service was started'
import fcntl, hashlib, json, os, stat, struct, subprocess, sys
from pathlib import Path

OWNER = 0
LOCK = Path('/run/lock/cdnca-management-release.lock')
try:
    assert os.geteuid() == OWNER
    binary, manifest = map(Path, sys.argv[1:])
    assert binary.resolve(strict=True) == binary and manifest.resolve(strict=True) == manifest
    item = next(item for item in json.loads(manifest.read_bytes())['files'] if item['path'] == 'analytics-history-bootstrap')
    with os.fdopen(os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        info = os.fstat(source.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_uid == OWNER and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == item['mode'] == 0o755
        digest = hashlib.sha256()
        for chunk in iter(lambda: source.read(1 << 20), b''):
            digest.update(chunk)
        assert info.st_size == item['bytes'] and digest.hexdigest() == item['sha256']
        source.seek(0); header = source.read(64)
        assert len(header) == 64 and header[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H', header, 18)[0] == 62
    environment = {name: os.environ[name] for name in ('DATABASE_URL', 'CONTROL_INSTALLATION_ID', 'ANALYTICS_INGEST_NATS_URL')}
    assert environment['ANALYTICS_INGEST_NATS_URL'] == 'nats://127.0.0.1:4222'
    environment.update({'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    with os.fdopen(os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC), 'r+') as lock:
        info = os.fstat(lock.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_uid == OWNER and info.st_gid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        live = LOCK.lstat()
        assert (live.st_dev, live.st_ino) == (info.st_dev, info.st_ino)
        subprocess.run([str(binary)], env=environment, stdin=subprocess.DEVNULL, check=True, timeout=60)
except Exception:
    print('native analytics history bootstrap failed; inspect private log before retrying', file=sys.stderr)
    sys.exit(1)
PY_ANALYTICS_BOOTSTRAP
}


# Native backup, restore and migration (control-api native-backup). Keep the
# verified dependency installer so a later migration can prepare a new host
# with the same pinned PostgreSQL/ClickHouse/Redis/ClamAV/nginx without a
# second package download, then enable the root backup agent units.
# cdncaCE: renew the community identity (community-register, 30 days) once a day;
# a never-registered installation has nothing to refresh and exits 0.
setup_community_identity_refresh() {
  cat >/etc/systemd/system/cdnca-community-identity-refresh.service <<EOF
[Unit]
Description=CDNCA community identity refresh
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=${CONFIG_DIR}/control.env
EnvironmentFile=-${CONFIG_DIR}/runtime-extra.env
ExecStart=${CONTROL_BINARY} community-refresh
EOF
  cat >/etc/systemd/system/cdnca-community-identity-refresh.timer <<'EOF'
[Unit]
Description=Daily CDNCA community identity refresh

[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now cdnca-community-identity-refresh.timer >/dev/null
}

setup_backup_agent() {
  install -d -m 0755 "${INSTALL_ROOT}/support"
  install -m 0700 "$NATIVE_SUPPORT/scripts/native-runtime/install-ubuntu-dependencies.sh" \
    "${INSTALL_ROOT}/support/install-ubuntu-dependencies.sh"
  # Create the signing identity before enabling the timer: past OnBootSec the
  # timer starts the agent at once, and both would create the keys.
  "$CONTROL_BINARY" native-backup fingerprint >/dev/null || fail 'backup signing identity could not be created'
  "$CONTROL_BINARY" native-backup install-units || fail 'backup agent units could not be installed'
}

MIGRATE_SOURCE=""
MIGRATE_SSH_PORT=22
MIGRATE_SSH_KEY=""
MIGRATE_DEPENDENCIES_SCRIPT=""
MIGRATE_WAIT_NODES=0s
MIGRATE_STAGE=/var/lib/cdnca-control-backup/migrate-in
MIGRATE_SSH=()

migrate_usage() {
  cat <<'EOF'
用法: install-control.sh migrate-from root@旧主控 [选项]
  在全新的新主控上执行：冻结旧主控 → 加密备份 → 传输 → 安装同版本依赖 → 恢复 → 校验。
  旧主控保持冻结（control-api/Gateway 已停并禁用），可在旧主控执行
  /data/cdnca-native-root/cdnca/current/bin/control-api native-backup unfreeze 回切。
  --ssh-port PORT                 旧主控 SSH 端口，默认 22
  --ssh-key FILE                  登录旧主控的私钥（默认使用 ssh-agent / ~/.ssh）
  --dependencies-script FILE      旧主控没有保存依赖安装脚本时，提供同版本签名包里的 install-ubuntu-dependencies.sh
  --wait-nodes DURATION           恢复后等待节点重连（如 10m），默认不等待
  --env auto|bt|plain             本机（新主控）环境；auto（默认）检测到宝塔面板即按宝塔环境预检与安装依赖
  --keep-unattended-upgrades      保留系统自动更新（默认停用，同全新安装）
  -y, --yes                       安装前检测只有“警告”时不再询问
EOF
}

migrate_remote() { "${MIGRATE_SSH[@]}" "$MIGRATE_SOURCE" "$@"; }

migrate_parse_args() {
  [ "$#" -ge 1 ] && [[ "$1" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.:-]+$|^[A-Za-z0-9.:-]+$ ]] || { migrate_usage; fail 'migrate-from requires root@OLD_HOST'; }
  MIGRATE_SOURCE=$1
  shift
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --ssh-port) need_value "$@"; MIGRATE_SSH_PORT=$2; shift 2 ;;
      --ssh-key) need_value "$@"; MIGRATE_SSH_KEY=$2; shift 2 ;;
      --dependencies-script) need_value "$@"; MIGRATE_DEPENDENCIES_SCRIPT=$2; shift 2 ;;
      --wait-nodes) need_value "$@"; MIGRATE_WAIT_NODES=$2; shift 2 ;;
      --env) need_value "$@"; INSTALL_ENV=$2; shift 2 ;;
      --keep-unattended-upgrades) KEEP_UNATTENDED_UPGRADES=true; shift ;;
      -y|--yes) ASSUME_YES=true; shift ;;
      -h|--help) migrate_usage; exit 0 ;;
      *) fail "unsupported migrate-from option: $1" ;;
    esac
  done
  valid_port "$MIGRATE_SSH_PORT" || fail 'invalid --ssh-port'
  [[ "$MIGRATE_WAIT_NODES" =~ ^[0-9]+[smh]$ ]] || fail 'invalid --wait-nodes'
}

migrate_main() {
  migrate_parse_args "$@"
  [ "$EUID" -eq 0 ] || fail 'run this installer as root'
  assert_fresh_installation
  command -v ssh >/dev/null 2>&1 && command -v scp >/dev/null 2>&1 || fail 'ssh and scp are required on the new host'
  install -d -m 0700 /var/lib/cdnca-control-backup "$MIGRATE_STAGE"
  # One authenticated connection, reused: the operator types a password once.
  MIGRATE_SSH=(ssh -p "$MIGRATE_SSH_PORT" -o ControlMaster=auto -o "ControlPath=$TEMP_DIR/ssh-%C" -o ControlPersist=30m
    -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30)
  [ -z "$MIGRATE_SSH_KEY" ] || MIGRATE_SSH+=(-i "$MIGRATE_SSH_KEY")
  local old_binary=/data/cdnca-native-root/cdnca/current/bin/control-api status signer version
  trap 'ssh -o "ControlPath=$TEMP_DIR/ssh-%C" -O exit "$MIGRATE_SOURCE" >/dev/null 2>&1 || true; cleanup' EXIT
  log "connecting to the old control plane ${MIGRATE_SOURCE}"
  migrate_remote "test \"\$(id -u)\" = 0" || fail 'the old control plane must be reached as root'
  status=$(migrate_remote "$old_binary native-backup status") || fail 'old control plane has no native-backup support (needs 1.0.35 or later)'
  signer=$(jq -er '.signer_fingerprint | select(test("^SHA256:[A-Za-z0-9+/]{43}$"))' <<<"$status") || fail 'old control plane signer is unreadable'
  version=$(migrate_remote "jq -er .version /data/cdnca-native-root/cdnca/current/release.manifest.json") || fail 'old release manifest is unreadable'
  LICENSING_SERVER=$(migrate_remote "awk -F= '\$1==\"LICENSE_SERVICE_URL\"{print \$2}' /etc/cdnca-control/control.env") || true
  LICENSING_SERVER_FALLBACK=$LICENSING_SERVER
  log "old control plane: version ${version}, backup signer ${signer}"
  run_preflight
  quiesce_package_automation
  if ! require_commands; then install_dependencies; fi
  acquire_control_install_lock
  assert_fresh_installation
  # The exact control-api of the old host performs the restore; check it
  # against the old host's own signed release manifest.
  scp -q -P "$MIGRATE_SSH_PORT" -o "ControlPath=$TEMP_DIR/ssh-%C" ${MIGRATE_SSH_KEY:+-i "$MIGRATE_SSH_KEY"} \
    "$MIGRATE_SOURCE:$old_binary" "$MIGRATE_SOURCE:/data/cdnca-native-root/cdnca/current/release.manifest.json" "$MIGRATE_STAGE/" ||
    fail 'cannot copy control-api from the old control plane'
  [ "$(jq -er '.files[] | select(.path == "bin/control-api") | .sha256' "$MIGRATE_STAGE/release.manifest.json")" = \
    "$(sha256sum "$MIGRATE_STAGE/control-api" | awk '{print $1}')" ] || fail 'copied control-api does not match the old release manifest'
  chmod 0755 "$MIGRATE_STAGE/control-api"
  if [ -n "$MIGRATE_DEPENDENCIES_SCRIPT" ]; then
    install -m 0700 "$MIGRATE_DEPENDENCIES_SCRIPT" "$MIGRATE_STAGE/install-ubuntu-dependencies.sh"
  else
    scp -q -P "$MIGRATE_SSH_PORT" -o "ControlPath=$TEMP_DIR/ssh-%C" ${MIGRATE_SSH_KEY:+-i "$MIGRATE_SSH_KEY"} \
      "$MIGRATE_SOURCE:/usr/local/cdnca-control/support/install-ubuntu-dependencies.sh" "$MIGRATE_STAGE/" ||
      fail 'old control plane has no saved dependency installer; pass --dependencies-script from the same signed package'
  fi
  log 'installing pinned runtime dependencies (PostgreSQL, ClickHouse, Redis, ClamAV, nginx)'
  # 宝塔环境：依赖按 run_preflight 规划的替代端口安装（端口档案）。
  write_dependency_ports
  bash "$MIGRATE_STAGE/install-ubuntu-dependencies.sh" install
  local recipient backup_id
  rm -f "$MIGRATE_STAGE/identity"
  recipient=$("$MIGRATE_STAGE/control-api" native-backup new-identity --file "$MIGRATE_STAGE/identity") || fail 'cannot create the receive identity'
  log 'freezing the old control plane and taking the migration backup (the old console stops now)'
  backup_id=$(migrate_remote "$old_binary native-backup create --reason migration --hold --recipient $recipient" | jq -er .backup_id) ||
    fail 'migration backup on the old control plane failed; it was restarted'
  migrate_rollback() {
    warn "migration failed; restarting the old control plane ${MIGRATE_SOURCE}"
    migrate_remote "$old_binary native-backup unfreeze" || warn "run on the old host: $old_binary native-backup unfreeze"
  }
  install -d -m 0700 "/var/lib/cdnca-control-backup/bundles/$backup_id"
  migrate_remote "tar -C /var/lib/cdnca-control-backup/bundles/$backup_id -cf - ." |
    tar -C "/var/lib/cdnca-control-backup/bundles/$backup_id" -xf - || { migrate_rollback; fail 'bundle transfer failed'; }
  log "restoring ${backup_id}"
  if ! "$MIGRATE_STAGE/control-api" native-backup restore --bundle "/var/lib/cdnca-control-backup/bundles/$backup_id" \
    --signer "$signer" --identity "$MIGRATE_STAGE/identity"; then
    migrate_rollback
    fail 'restore failed and was compensated on this host'
  fi
  rm -f "$MIGRATE_STAGE/identity" "$MIGRATE_STAGE/control-api"
  if ! /data/cdnca-native-root/cdnca/current/bin/control-api native-backup verify-migration \
    --bundle "/var/lib/cdnca-control-backup/bundles/$backup_id" --wait-nodes "$MIGRATE_WAIT_NODES"; then
    fail 'restored, but verification failed; the old control plane stays frozen - inspect journalctl -u cdnca-control-api'
  fi
  log '迁移完成。下一步：把管理端与 Gateway 域名的 DNS 改到本机，节点会自动重连；在授权门户把主控 IP 改为本机。'
  log "切换 DNS 后最长 10 分钟，本机 control-api 自动按新地址重新发布节点安装信任文档（控制台节点安装命令随之更新）；也可立即执行 /data/cdnca-native-root/cdnca/current/bin/control-api native-backup verify-migration --bundle /var/lib/cdnca-control-backup/bundles/$backup_id"
  if [ "$INSTALL_ENV" = bt ]; then
    # 恢复时 control-api 已按端口档案写好 bt-proxy.conf（与全新安装同文）。
    log "宝塔环境：管理端网页只监听 127.0.0.1:${WEB_PORT}；请在宝塔为管理端域名建站点并配置反向代理，配置见 ${CONFIG_DIR}/bt-proxy.conf"
  fi
  log "确认无误前旧主控保持冻结；回切：在旧主控管理端“回退到本机”（或执行 $old_binary native-backup unfreeze），再在本机执行 $MIGRATE_STAGE/control-api native-backup clean-target --bundle /var/lib/cdnca-control-backup/bundles/$backup_id --signer <旧主控签名指纹>"
}

main() {
  [ "${1:-}" != migrate-from ] || { shift; migrate_main "$@"; return; }
  [ "${1:-}" != enable-gateway-access ] || { shift; gateway_access_main "$@"; return; }
  [ "${1:-}" != --cleanup-failed ] || { shift; cleanup_failed_main "$@"; return; }
  ! gateway_mode_requested "$@" || { INSTALL_MODE=gateway; gateway_main "$@"; return; }
  parse_args "$@"
  # Validate the values that do not require host utilities before attempting
  # dependency installation.  normalise_defaults intentionally runs only
  # after openssl/uuidgen/etc. are available.
  [ "$EUID" -eq 0 ] || fail 'run this installer as root'
  [ "$INSTALL_MODE" = all ] || [ "$INSTALL_MODE" = control ] || fail '--mode must be all, control or gateway'
  progress_init
  progress_stage
  assert_fresh_installation
  run_preflight
  valid_url "${LICENSING_SERVER:-https://release.example.invalid}" || fail '--release-server must be an http(s) URL'
  prompt_public_endpoints
  prompt_certificate_email
  progress_stage
  quiesce_package_automation
  if [ "$SKIP_DEPENDENCIES" = false ] && ! require_commands; then install_dependencies; fi
  require_commands || fail 'required bootstrap tools are missing'
  control_install_state_prepare
  ssh_guard_setup
  acquire_control_install_lock
  assert_fresh_installation
  control_install_state_begin
  normalise_defaults
  progress_stage
  prompt_admin_username
  prompt_admin_password
  progress_stage
  download_native_support
  progress_stage
  write_dependency_ports
  configure_runtime_dependencies
  progress_stage
  prepare_native_baseline
  generate_identity
  issue_public_certificate
  generate_pki
  generate_runtime_secrets
  generate_gateway_access_secrets
  progress_stage
  download_nats_binaries
  download_node_assets
  generate_plugin_webhook_attestation_key
  write_environment
  progress_stage
  prepare_database
  migrate_database
  setup_redis
  setup_nats
  preprovision_nats
  configure_control_runtime
  publish_upgrade_trust
  progress_stage
  install_community
  fetch_community_trusted_keys
  progress_stage
  setup_native_upgrade
  bootstrap_analytics_history
  write_web_runtime_config
  bootstrap_admin
  bootstrap_node_ca
  bootstrap_system_configuration
  progress_stage
  configure_selinux
  setup_gateway_access_firewall
  setup_service
  setup_gateway
  publish_gateway_package
  setup_web
  verify_native_plan_source
  setup_backup_agent
  setup_community_identity_refresh
  configure_firewall
  progress_stage
  print_gateway_ports
  bt_report
  report_public_certificate_renewal
  control_install_state_done
  log 'cdnca community edition installed and ready'
  log "to buy on the node/plugin market, register once (free portal account): ${CONTROL_BINARY} community-register --account <portal account> --password-stdin"
  progress_done
}

main "$@"
