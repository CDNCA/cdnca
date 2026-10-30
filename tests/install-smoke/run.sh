#!/usr/bin/env bash
# 社区版主控全新安装容器冒烟：静态发布站 + install-control.sh --release-server（免激活）。
# 不起授权端、不走激活码、不依赖已删除的授权安装脚本或授权服务。
# 用法：tests/install-smoke/run.sh <artifacts-dir> <debian12|rocky9|ubuntu2404|ubuntu2204|none> [--keep]
# none：只核产物存在后退出（CE 无授权端-only 模式）。
set -Eeuo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
ART=${1:?artifacts-dir}; TARGET=${2:?target}; KEEP=0
[ "${3:-}" = --keep ] && KEEP=1
case $TARGET in debian12|rocky9|ubuntu2404|ubuntu2204|none) ;; *)
  echo "usage: $0 <artifacts-dir> <debian12|rocky9|ubuntu2404|ubuntu2204|none> [--keep]" >&2; exit 2;; esac

die() { echo "error: $*" >&2; exit 1; }
VERSION=$(sed -n 's/^version=//p' "$ART/BUILD" | head -1)
[ -n "$VERSION" ] || die "artifacts BUILD 无 version"

need_files() {
  local f
  for f in \
    "$ART/BUILD" \
    "$ART/downloads/install-control.sh" \
    "$ART/downloads/control-native/latest/cdnca-control-native.tar" \
    "$ART/downloads/edge-agent/latest/cdnca-edge-agent.tar.gz"
  do
    [ -e "$f" ] || die "缺少产物 $f（先跑 build-artifacts.sh）"
  done
}
need_files
[ "$TARGET" = none ] && { echo "CE smoke: none — 产物齐全，跳过主控安装"; exit 0; }

case $TARGET in
  debian12)   IMAGE=debian:12-slim; INIT=/lib/systemd/systemd ;;
  rocky9)     IMAGE=rockylinux:9; INIT=/usr/lib/systemd/systemd ;;
  ubuntu2404) IMAGE=ubuntu:24.04; INIT=/lib/systemd/systemd ;;
  ubuntu2204) IMAGE=ubuntu:22.04; INIT=/lib/systemd/systemd ;;
esac

NET=cdnca-install-smoke-$$
REL=cdnca-smoke-release-$$
CTRL=cdnca-smoke-control-$$
ADMIN_PASS='InstallSmoke!pass1'
cleanup() {
  docker rm -f "$CTRL" "$REL" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
[ "$KEEP" -eq 1 ] || trap cleanup EXIT

docker network create "$NET" >/dev/null

# 静态发布站：挂载 downloads，自签 TLS，hostname release.cdnca.smoke
mkdir -p "$ART/smoke-tls"
if [ ! -s "$ART/smoke-tls/cert.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$ART/smoke-tls/key.pem" -out "$ART/smoke-tls/cert.pem" \
    -subj '/CN=release.cdnca.smoke' >/dev/null 2>&1
fi
cat >"$ART/smoke-tls/nginx.conf" <<'NGX'
worker_processes 1;
error_log /dev/stderr warn;
pid /tmp/nginx.pid;
events { worker_connections 64; }
http {
  access_log /dev/stdout;
  server {
    listen 443 ssl;
    server_name release.cdnca.smoke;
    ssl_certificate     /tls/cert.pem;
    ssl_certificate_key /tls/key.pem;
    location /downloads/ {
      alias /downloads/;
      autoindex on;
    }
  }
}
NGX
docker run -d --name "$REL" --network "$NET" --network-alias release.cdnca.smoke \
  -v "$ART/downloads:/downloads:ro" \
  -v "$ART/smoke-tls:/tls:ro" \
  -v "$ART/smoke-tls/nginx.conf:/etc/nginx/nginx.conf:ro" \
  nginx:1.27-alpine >/dev/null

# 等发布站起
for i in $(seq 1 30); do
  docker exec "$REL" wget -q -O /dev/null --no-check-certificate \
    https://127.0.0.1/downloads/install-control.sh && break
  [ "$i" -eq 30 ] && die '发布站未就绪'
  sleep 1
done

# 主控 systemd 容器
docker run -d --name "$CTRL" --privileged --cgroupns=host \
  --network "$NET" --hostname control.cdnca.smoke \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -e container=docker \
  "$IMAGE" "$INIT" >/dev/null

# mask 干扰单元（与旧冒烟同思路，失败忽略）
docker exec "$CTRL" bash -c 'systemctl mask --now systemd-binfmt.service 2>/dev/null || true'

# 基础包 + 把 install-control 拷进容器
case $TARGET in
  debian12|ubuntu2404|ubuntu2204)
    docker exec "$CTRL" bash -c 'export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq ca-certificates curl openssl >/dev/null'
    ;;
  rocky9)
    docker exec "$CTRL" bash -c 'dnf install -y -q ca-certificates curl openssl >/dev/null'
    ;;
esac

# 信任冒烟自签 CA（把发布站证书塞进信任锚）
docker cp "$ART/smoke-tls/cert.pem" "$CTRL:/usr/local/share/ca-certificates/release.cdnca.smoke.crt"
docker exec "$CTRL" bash -c 'command -v update-ca-certificates >/dev/null && update-ca-certificates || true
  command -v update-ca-trust >/dev/null && update-ca-trust extract || true'

# 管理员密码文件（install-control 非交互只要 --admin-password-file）
umask 077
printf '%s' "$ADMIN_PASS" >"$ART/smoke-admin.pass"
chmod 600 "$ART/smoke-admin.pass"
docker cp "$ART/downloads/install-control.sh" "$CTRL:/root/install-control.sh"
docker cp "$ART/smoke-admin.pass" "$CTRL:/root/admin.pass"
docker exec "$CTRL" bash -c 'chmod 600 /root/admin.pass; chmod +x /root/install-control.sh'

# 社区免激活安装
docker exec "$CTRL" bash /root/install-control.sh \
  --release-server https://release.cdnca.smoke \
  --master-host control.cdnca.smoke \
  --installation-name install-smoke-ce \
  --admin-username admin \
  --admin-email admin@cdnca.com \
  --admin-password-file /root/admin.pass \
  --certificate-email install-smoke@cdnca.com \
  -y

# 健康 + 登录（control-api：/health/ready + /v1/auth/login）
for i in $(seq 1 60); do
  docker exec "$CTRL" bash -c 'curl -fsS http://127.0.0.1:8080/health/ready >/dev/null 2>&1' && break
  [ "$i" -eq 60 ] && die 'control /health/ready 超时'
  sleep 2
done
docker exec "$CTRL" bash -c "curl -fsS -X POST http://127.0.0.1:8080/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{\"username\":\"admin\",\"password\":\"$ADMIN_PASS\"}'" | grep -q . \
  || die 'admin 登录失败'

echo "PASS install-smoke CE control target=$TARGET"
[ "$KEEP" -eq 1 ] && echo "kept: net=$NET release=$REL control=$CTRL"
