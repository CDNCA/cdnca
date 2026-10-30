#!/usr/bin/env bash
# 宝塔环境预检容器验收：单个 python:3.12-slim 容器（Debian，自带 python3；--rm --cpus 1 --network none），模拟
# /www/server/panel（版本 9.2.0、面板端口 8888）与宝塔 nginx，并用 python3 占住
# 80/443/5432/6379/8888，只运行 install-control.sh 的 run_preflight（不安装、不改系统）。
# 断言：宝塔模式不因 443/80/5432/6379 不通过，中文清单列出版本、端口调整、手工步骤与防火墙。
# 用法：bash scripts/install-control-bt-preflight-docker.sh
set -Eeuo pipefail
repository=$(cd "$(dirname "$0")/.." && pwd)
image=${BTENV_IMAGE:-python:3.12-slim}
name=cdnca-btenv-preflight-$$
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

docker run --rm --name "$name" --cpus 1 --memory 1g --network none \
  -v "$repository/scripts/install-control.sh:/opt/install-control.sh:ro" "$image" bash -c '
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
command -v python3 >/dev/null || { echo "image lacks python3: set BTENV_IMAGE to an image with python3 (network is disabled)"; exit 2; }
mkdir -p /www/server/panel/class /www/server/panel/data /www/server/nginx/sbin
printf "import os\n    g.version = \x279.2.0\x27\n" > /www/server/panel/class/common.py
echo 8888 > /www/server/panel/data/port.pl
printf "#!/bin/sh\nexit 0\n" > /www/server/nginx/sbin/nginx; chmod 755 /www/server/nginx/sbin/nginx
for port in 80 443 5432 6379 8888; do python3 -m http.server "$port" --bind 0.0.0.0 >/dev/null 2>&1 & done
sleep 2
# 只取函数定义（main 之前），再调用 run_preflight；授权端连通性检测在断网下记为不通过，单独排除。
sed "/^main \"\$@\"$/d" /opt/install-control.sh > /tmp/installer.sh
set +e
output=$(bash -c "source /tmp/installer.sh; LICENSING_SERVER=https://auth.cdnca.com MASTER_HOST=cdnca.com CONTROL_DOMAIN=cdnca.com ASSUME_YES=true run_preflight" 2>&1)
set -e
printf "%s\n" "$output"
check() { grep -Fq -- "$1" <<<"$output" || { echo "MISSING: $1"; exit 1; }; }
check "宝塔环境：检测到宝塔面板 9.2.0，面板端口 8888"
check "端口调整：PostgreSQL 5432 已被占用，改用 15432"
check "端口调整：Redis 6379 已被占用，改用 16379"
check "管理端网页：本机 127.0.0.1:18443"
check "节点升级下载：直连端口 19445"
check "端口规划：管理端网页 127.0.0.1:18443、节点升级下载 19445、PostgreSQL 15432、Redis 16379"
check "宝塔站点证书：站点 cdnca.com 还没有证书"
check "宝塔手工步骤"
check "宝塔防火墙"
if grep -E "端口占用：已被占用.*(443|5432|6379|80（)" <<<"$output"; then echo "BT mode must not fail on BaoTa ports"; exit 1; fi
echo "PASS btenv preflight"
'
