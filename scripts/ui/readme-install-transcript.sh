#!/usr/bin/env bash
# README 安装指南的终端截图文本：用真实的 scripts/lib/install-progress.sh、install-i18n.sh 和安装器里的
# PROGRESS_STAGES、提示语与安装完成摘要函数生成输出（终端模式、带颜色），只把各阶段耗时设成区间内的值、
# 地址等换成示例值，不真的安装。省略各步骤内部的日志行。
# 用法：scripts/ui/readme-install-transcript.sh control|node [zh|en]   输出到 stdout（含 ANSI 颜色）
set -euo pipefail
role=${1:?control|node}
lang=${2:-zh}
root=$(cd "$(dirname "$0")/../.." && pwd)
logdir=$(mktemp -d)
trap 'rm -rf "$logdir"' EXIT

installer="$root/scripts/install-$role.sh"
# 取安装器里的一段：从“名字() {”到下一行“}”。
fn() { awk -v n="$1() {" '$0 == n {on=1} on {print} on && /^}$/ {exit}' "$installer"; }
# 阶段定义（PROGRESS_LABEL 到 PROGRESS_STAGES 的右括号）。
eval "$(awk '/^PROGRESS_LABEL=/{on=1} on{print} on&&/^\)$/{exit}' "$installer")"
# shellcheck source=../lib/install-i18n.sh
. "$root/scripts/lib/install-i18n.sh"
install_lang_init --lang "$lang"
# shellcheck source=../lib/install-progress.sh
. "$root/scripts/lib/install-progress.sh"

{
  PROGRESS_LOG_DIR=$logdir
  spend() { SECONDS=$((SECONDS + $1)); }
  say() { printf '%s\n' "$*"; }
  log() { printf '%s %s\n' "$PROGRESS_LABEL" "$*"; }
  warn() { printf '%s warning: %s\n' "$PROGRESS_LABEL" "$*"; }
  if [ "$role" = control ]; then
    eval "$(fn summary_certificate)"; eval "$(fn control_install_summary)"
    summary_host_addresses() { printf '203.0.113.10|'; }
    public_certificate_lineage() { printf 'console.example.com'; }
    remote_gateway_access() { return 1; }
    say "root@console:~# bash install-control.sh --release-server https://www.cdnca.com/downloads/ce --lang $lang"
    progress_init; PROGRESS_TTY=true PROGRESS_COLOR=true
    progress_stage
    say "$(msg '管理端公网域名或 IP: ' 'Public domain or IP of the management console: ')console.example.com"
    say "$(msg '管理端 HTTPS 端口 [443]: ' 'Management HTTPS port [443]: ')"
    say "$(msg '证书联系邮箱（用于管理端与网站 HTTPS 证书自动申请，需真实可用）: ' 'Certificate contact email (used to request HTTPS certificates for the console and websites; must be real): ')ops@example.com"
    spend 25; progress_stage; spend 48; progress_stage
    say "$(msg '管理员用户名（小写字母开头，3-128 位）: ' 'Administrator user name (starts with a lowercase letter, 3-128 chars): ')admin"
    say "$(msg '再次输入管理员密码: ' 'Repeat the administrator password: ')"
    spend 20; progress_stage; spend 72; progress_stage; spend 365; progress_stage; spend 41; progress_stage
    spend 63; progress_stage; spend 87; progress_stage; spend 9; progress_stage; spend 52; progress_stage; spend 78; progress_stage
    log 'cdnca community edition installed and ready'
    TEMP_DIR=$logdir CONTROL_SUMMARY_FILE=$logdir/summary.txt CONTROL_ORIGIN=https://console.example.com
    CONTROL_VERSION=1.0.35 INSTALLATION_ID=0f6b9c2e-4d1a-4c8e-9b3f-2a7d5e1c8f40 INSTALLATION_NAME=console.example.com
    NATIVE_ROOT=/data/cdnca-native-root/cdnca CONFIG_DIR=/etc/cdnca-control DATA_DIR=/var/lib/cdnca-control
    CONTROL_DOMAIN=console.example.com GATEWAY_HOST=console.example.com ADMIN_USERNAME=admin INSTALL_ENV=plain MASTER_PORT=443
    GATEWAY_ENROLLMENT_PORT=24817 GATEWAY_AGENT_PORT=27305 PUBLIC_CERT_FILE=/etc/letsencrypt/live/console.example.com/fullchain.pem
    PUBLIC_CERT_PATH=/nonexistent SERVICE_NAME=cdnca-control-api GATEWAY_SERVICE_NAME=cdnca-agent-gateway WEB_SERVICE_NAME=cdnca-control-web
    control_install_summary 2>&1 | sed -E "s/(Let's Encrypt[^;]*); [^0-9]*[^ ]*.*/\1/" | grep -vE '^  [3-6]\. |^.*(以上信息已保存|Saved to)'
    spend 4; progress_done
  else
    eval "$(fn node_install_summary)"; eval "$(fn node_next_steps)"
    say "root@edge-01:~# (f=\$(mktemp) || exit 1; ... | bash \"\$f\" --control-plane 'https://console.example.com' --registration-key-stdin --lang $lang)"
    progress_init; PROGRESS_TTY=true PROGRESS_COLOR=true
    progress_stage; spend 12; progress_stage; spend 36; progress_stage; spend 8; progress_stage
    spend 65; progress_stage; spend 41; progress_stage; spend 11; progress_stage; spend 9; progress_stage
    log "edge-agent installed and enrolled; identity is /etc/cdnca-edge-agent/identity/identity.json"
    printf '{"node_id":"7c2e4b1a-5d3f-4e8a-9c6b-0f1d2a3b4c5d"}' >"$logdir/identity.json"
    IDENTITY_DIR=$logdir NODE_NAME=edge-01 CONTROL_PLANE=https://console.example.com GATEWAY_ADDRESS=console.example.com:27305
    GATEWAY_TRANSPORT=grpc SERVICE_NAME=cdnca-edge-agent INSTALLER_COPY=/var/lib/cdnca-node-install/install-node.sh PROGRESS_LOG=''
    node_install_summary 2>&1 | grep -vE '(核对|Verify|卸载|Uninstall|健康检查|Health check)'
    node_next_steps 2>&1 | head -3
    spend 24; progress_done
  fi
} 2>&1 | sed "s#${logdir}#/var/log#g"
