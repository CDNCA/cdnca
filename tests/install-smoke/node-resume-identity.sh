#!/usr/bin/env bash
# BLOCKED（CE）：依赖旧授权端拓扑；等 CE run.sh --keep 提供发布站后再改。勿当现行步骤执行。
# 节点续装取回身份实机冒烟（fz-x13）。待出包前全量跑（本任务只写好，未跑）。
#
# 场景：网关注册已在主控提交（证书已签发），但响应没回到本机，身份目录没写下来。
# 原先 --resume 会重复注册（409 node_already_registered）；现在应该用注册凭据从主控取回身份。
#
# 前提：先跑 `run.sh <产物> <target> --keep`，留下授权端与主控容器、专用网络。
# 本脚本再起一个 Ubuntu 24.04 systemd 节点容器，用管理端复制给节点的同一条命令：
#   1. 网关 19444 被拦，安装失败、保留身份目录（与 node-resume.sh 第 1 步相同）；
#   2. 用 edge-enroll-pending-fixture 把 identity 退回 identity.enrolling/pending.json，模拟"主控已签发、本机未写身份"；
#   3. 放行后原命令加 --resume：应走 POST /v1/node-registrations/identity 取回身份、跳过注册，
#      主控节点数不变，审计里有 node.registration.identity_fetch；
#   4. 用另一台机器的指纹加第一台的 CSR 摘要去查，应得 404 node_identity_not_found。
# 需要宿主有 go（构建测试夹具）。
#
# 用法：bash tests/install-smoke/node-resume-identity.sh <主控容器名> <docker 网络名> <管理员密码文件>
set -Eeuo pipefail
trap 'printf "node-resume-identity: 第 %s 行失败：%s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
CTL=${1:?usage: node-resume-identity.sh <control container> <network> <admin password file>}
NET=${2:?network}
ADMIN_PASSWORD=$(cat "${3:?admin password file}")
CTL_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$CTL")
NODE=cdnca-install-smoke-rid-$$
NODE_IP=${CDNCA_SMOKE_NODE_IP:-203.0.113.31}
IDENTITY=/etc/cdnca-edge-agent/identity
log() { printf '[node-resume-identity] %s %s\n' "$(date +%T)" "$*"; }
die() { printf '[node-resume-identity] 失败：%s\n' "$*" >&2; exit 1; }
in_ctl() { docker exec -i "$CTL" bash -c "$1"; }
in_node() { docker exec -i "$NODE" bash -c "$1"; }
cleanup() {
  local rc=$?
  in_ctl 'iptables -D INPUT -p tcp --dport 19444 -j REJECT 2>/dev/null || true' || true
  [ -n "${CDNCA_SMOKE_KEEP_NODE:-}" ] || docker rm -f -v "$NODE" >/dev/null 2>&1 || true
  exit "$rc"
}
trap cleanup EXIT

image=$(docker inspect -f '{{.Config.Image}}' "$CTL")
docker run -d --name "$NODE" --hostname "$NODE" --platform linux/amd64 --privileged --cgroupns=private \
  --network "$NET" --ip "$NODE_IP" --add-host "release.cdnca.smoke:$(in_ctl "getent hosts release.cdnca.smoke | awk '{print \$1}'")" \
  --tmpfs /run --tmpfs /run/lock --tmpfs /tmp:exec "$image" >/dev/null
for _ in $(seq 1 60); do in_node 'systemctl is-system-running 2>/dev/null | grep -Eq "running|degraded"' && break; sleep 2; done

token=$(in_ctl "curl -sk -X POST -H 'Content-Type: application/json' -H 'Origin: https://$CTL_IP' \
  --data-binary '{\"username\":\"smoke-admin\",\"password\":\"$ADMIN_PASSWORD\"}' https://$CTL_IP/v1/auth/login | jq -er .access_token")
credential=$(in_ctl "curl -sk -H 'Authorization: Bearer $token' https://$CTL_IP/v1/nodes/registration-credential | jq -er .credential")
in_ctl "curl -sk https://$CTL_IP/downloads/gateway-ca.pem" | in_node 'cat >/root/control-ca.pem'
in_node "curl -fsS --cacert /root/control-ca.pem -o /root/install-node.sh https://$CTL_IP/downloads/install-node.sh"
umask 077; printf '%s\n' "$credential" | in_node 'cat >/root/registration-key'
install_node() { # [--resume]
  set +e
  in_node "bash /root/install-node.sh --control-plane https://$CTL_IP --control-plane-ca-file /root/control-ca.pem \
    --registration-key-stdin --no-ssh-guard -y $* </root/registration-key" >"/tmp/$NODE-install.log" 2>&1
  local rc=$?; set -e
  printf '%s' "$rc"
}
# 主控库：install-control.sh 写在 /etc/cdnca-control/control.env 的 DATABASE_URL（本地 PG）。
ctl_sql() { in_ctl "set -a; . /etc/cdnca-control/control.env; psql \"\$DATABASE_URL\" -tAc \"$1\""; }
node_count() { ctl_sql "SELECT count(*) FROM nodes WHERE admin_state <> 'retired'"; }

log '1. 网关 19444 被拦：安装失败并保留身份'
in_ctl 'iptables -I INPUT -p tcp --dport 19444 -j REJECT'
in_ctl 'iptables -I INPUT -p tcp --dport 19443 -j ACCEPT'
rc=$(install_node)
[ "$rc" != 0 ] || die '网关不可达时安装仍返回 0'
in_node "test -f $IDENTITY/identity.json" || die '第一次安装没有拿到身份，无法模拟"已签发未落盘"'
nodes_before=$(node_count)

log '2. 模拟"主控已签发、本机未写身份"：身份目录退回 pending 状态'
# edge-enroll-pending-fixture 用已提交身份的私钥重建同一份 CSR（Ed25519 确定性签名，
# 单测 TestPendingCSRIsReproducibleFromClientKey），写回 identity.enrolling/pending.json。
FIXTURE_BIN=$(mktemp -d)/edge-enroll-pending-fixture
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go -C "$(git rev-parse --show-toplevel)/agents/edge-agent" \
  build -o "$FIXTURE_BIN" ./cmd/edge-enroll-pending-fixture
docker cp "$FIXTURE_BIN" "$NODE:/root/edge-enroll-pending-fixture"
rm -rf -- "$(dirname "$FIXTURE_BIN")"
in_node "systemctl stop cdnca-edge-agent; /root/edge-enroll-pending-fixture $IDENTITY"
in_node "test -f $IDENTITY.enrolling/pending.json && test ! -e $IDENTITY" || die '没有退回 pending 状态'
csr=$(in_node "/usr/lib/cdnca-edge-agent/current/edge-agent enroll --print-pending-csr-sha256 --identity-dir $IDENTITY")

log '3. 放行后 --resume：取回身份、跳过注册、节点数不变'
in_ctl 'iptables -D INPUT -p tcp --dport 19444 -j REJECT'
rc=$(install_node --resume)
[ "$rc" = 0 ] || { tail -40 "/tmp/$NODE-install.log" >&2; die "--resume rc=$rc"; }
grep -q '续装：已从主控取回本机已签发的身份，跳过注册' "/tmp/$NODE-install.log" || die '续装没有走取回身份'
! grep -q 'registering this host' "/tmp/$NODE-install.log" || die '续装又发起了注册'
[ "$(node_count)" = "$nodes_before" ] || die '续装后节点数变化（重复注册）'
in_node "test -f $IDENTITY/identity.json && test ! -e $IDENTITY.enrolling" || die '身份目录没有组装好'
[ "$(ctl_sql "SELECT count(*) FROM audit_events WHERE action='node.registration.identity_fetch' AND result='success'")" -ge 1 ] ||
  die '审计缺 node.registration.identity_fetch（success）'

log '4. 另一台机器指纹 + 同一 CSR 摘要查询：404，不泄露节点存在'
status=$(in_node "jq -n --arg c \"\$(cat /root/registration-key)\" --arg f $(printf 'f%.0s' $(seq 64)) --arg s $csr \
  '{credential:\$c,machine_fingerprint:\$f,csr_sha256:\$s}' | curl -s --cacert /root/control-ca.pem -o /dev/null -w '%{http_code}' \
  -X POST -H 'Content-Type: application/json' --data-binary @- https://$CTL_IP/v1/node-registrations/identity")
[ "$status" = 404 ] || die "他机查询应为 404，实际 $status"
log '通过：fz-x13 续装取回已签发身份，不重复注册；他机查询 404'
