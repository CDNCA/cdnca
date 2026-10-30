#!/usr/bin/env bash
# README 安装指南的终端截图文本：用真实的 scripts/lib/install-progress.sh 和安装器里的
# PROGRESS_STAGES 生成进度输出（终端模式、带颜色），只把各阶段耗时设成区间内的值，不真的安装。
# 提示语、结果行取自 install-control.sh / install-node.sh 原文（节选，省略各步骤内部的日志行）。
# 用法：scripts/ui/readme-install-transcript.sh control|node   输出到 stdout（含 ANSI 颜色）
set -euo pipefail
role=${1:?control|node}
root=$(cd "$(dirname "$0")/../.." && pwd)
logdir=$(mktemp -d)
trap 'rm -rf "$logdir"' EXIT

installer="$root/scripts/install-$role.sh"
# 取安装器里的阶段定义（PROGRESS_LABEL 到 PROGRESS_STAGES 的右括号）。
eval "$(awk '/^PROGRESS_LABEL=/{on=1} on{print} on&&/^\)$/{exit}' "$installer")"
# shellcheck source=../lib/install-progress.sh
. "$root/scripts/lib/install-progress.sh"

{
  PROGRESS_LOG_DIR=$logdir
  spend() { SECONDS=$((SECONDS + $1)); }
  say() { printf '%s\n' "$*"; }
  if [ "$role" = control ]; then
    say 'root@console:~# bash install-control.sh --release-server https://www.cdnca.com/downloads/ce'
    progress_init; PROGRESS_TTY=true PROGRESS_COLOR=true
    progress_stage
    say '管理端公网域名或 IP: console.example.com'
    say '管理端 HTTPS 端口 [443]: '
    say '证书联系邮箱（用于管理端与网站 HTTPS 证书自动申请，需真实可用）: ops@example.com'
    spend 25; progress_stage; spend 48; progress_stage
    say '管理员用户名（小写字母开头，3-128 位）: admin'
    say '管理员密码（8-1024 位，至少包含大写字母、小写字母、数字、符号中的两种，不能含空格或中文；输入不回显）: '
    say '再次输入管理员密码: '
    spend 20; progress_stage; spend 72; progress_stage; spend 365; progress_stage; spend 41; progress_stage
    spend 63; progress_stage; spend 87; progress_stage; spend 9; progress_stage
    say '[cdnca-control] creating administrator admin'
    printf '\nControl plane URL: https://%s\nAdministrator: %s (%s)\n' console.example.com admin admin@local
    spend 52; progress_stage; spend 78; progress_stage
    say ''
    say '节点通道（网关）端口：注册 24817，通道 27305，请在防火墙/安全组放行。'
    say '不套 CDN：节点直连这两个端口，无需其他配置。'
    say '[cdnca-control] cdnca community edition installed and ready'
    spend 4; progress_done
  else
    say "root@edge-01:~# (f=\$(mktemp) || exit 1; ... printf '%s\\n' 'nrk1.…' | bash \"\$f\" --control-plane 'https://console.example.com' --registration-key-stdin)"
    progress_init; PROGRESS_TTY=true PROGRESS_COLOR=true
    progress_stage; spend 12; progress_stage; spend 36; progress_stage; spend 8; progress_stage
    spend 65; progress_stage; spend 41; progress_stage; spend 11; progress_stage; spend 9; progress_stage
    say '[cdnca-edge] 已与主控网关 console.example.com:27305 建立会话'
    say '[cdnca-edge] 健康端口 127.0.0.1:18080 尚未监听：主控下发首个配置后由 Agent 启动 OpenResty'
    say '[cdnca-edge] edge-agent installed and enrolled; identity is /etc/cdnca-edge-agent/identity/identity.json'
    spend 24; progress_done
  fi
} 2>&1 | sed "s#${logdir}#/var/log#g"
