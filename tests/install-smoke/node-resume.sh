#!/usr/bin/env bash
# BLOCKED（CE）：依赖旧授权端拓扑；等 CE run.sh --keep 提供发布站后再改。勿当现行步骤执行。
# 节点安装器 X7 实机冒烟（freeze-audit X7：PJ-E05 / PJ-E06）。待出包前全量跑。
#
# 前提：先跑 `run.sh <产物> <target> --keep`，留下授权端与主控容器、专用网络。
# 本脚本再起一个 Ubuntu 24.04 systemd 节点容器，用管理端复制给节点的同一条命令：
#   1. 主控网关 19444 被 iptables 拦住：安装必须非 0 退出，报“服务已起但未连上主控网关”，
#      并保留服务与安装记录；
#   2. 原命令重跑（不加 --resume）：被空机门禁拒绝，并提示加 --resume；
#   3. 放行后原命令加 --resume：跳过注册（身份已存在），自检连上网关，退出 0；
#   4. 再次 --resume：提示已安装完成并拒绝。
#
# 用法：bash tests/install-smoke/node-resume.sh <主控容器名> <docker 网络名> <管理员密码文件>
set -Eeuo pipefail
trap 'printf "node-resume: 第 %s 行失败：%s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
CTL=${1:?usage: node-resume.sh <control container> <network> <admin password file>}
NET=${2:?network}
ADMIN_PASSWORD=$(cat "${3:?admin password file}")
CTL_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$CTL")
NODE=cdnca-install-smoke-node-$$
NODE_IP=${CDNCA_SMOKE_NODE_IP:-203.0.113.30}
log() { printf '[node-resume] %s %s\n' "$(date +%T)" "$*"; }
die() { printf '[node-resume] 失败：%s\n' "$*" >&2; exit 1; }
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

# 管理端给节点的命令：注册凭据走 stdin，安装器从主控下载。
token=$(in_ctl "curl -sk -X POST -H 'Content-Type: application/json' -H 'Origin: https://$CTL_IP' \
  --data-binary '{\"username\":\"smoke-admin\",\"password\":\"$ADMIN_PASSWORD\"}' https://$CTL_IP/v1/auth/login | jq -er .access_token")
credential=$(in_ctl "curl -sk -H 'Authorization: Bearer $token' https://$CTL_IP/v1/nodes/registration-credential | jq -er .credential")
# 主控 HTTPS 与网关同一私有根（install-control.sh 发布为 downloads/gateway-ca.pem）。
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

log '1. 网关 19444 被拦：安装应报未连上主控并保留服务'
in_ctl 'iptables -I INPUT -p tcp --dport 19444 -j REJECT'
in_ctl "iptables -I INPUT -p tcp --dport 19443 -j ACCEPT"
rc=$(install_node)
[ "$rc" != 0 ] || die '网关不可达时安装仍返回 0'
grep -q '服务已起但未连上主控网关' "/tmp/$NODE-install.log" || { tail -30 "/tmp/$NODE-install.log" >&2; die '缺少“服务已起但未连上主控网关”'; }
in_node 'systemctl is-active --quiet cdnca-edge-agent' || die '未连上网关时服务被停掉了'
in_node 'test -f /var/lib/cdnca-node-install/state && ! grep -qx step=done /var/lib/cdnca-node-install/state' || die '安装记录缺失或被标成完成'

log '2. 原命令重跑：空机门禁拒绝并提示 --resume'
rc=$(install_node)
[ "$rc" != 0 ] || die '原命令重跑不应通过空机门禁'
grep -q -- '--resume' "/tmp/$NODE-install.log" || die '重跑没有提示 --resume'

log '3. 放行后 --resume：跳过注册，自检连上网关'
in_ctl 'iptables -D INPUT -p tcp --dport 19444 -j REJECT'
rc=$(install_node --resume)
[ "$rc" = 0 ] || { tail -40 "/tmp/$NODE-install.log" >&2; die "--resume rc=$rc"; }
grep -q '续装：本机已向网关注册' "/tmp/$NODE-install.log" || die '续装没有跳过注册'
grep -q '已与主控网关' "/tmp/$NODE-install.log" || die '续装后没有确认网关会话'
in_node 'grep -qx step=done /var/lib/cdnca-node-install/state' || die '续装完成后没有记 step=done'

log '4. 已完成后再 --resume：拒绝'
rc=$(install_node --resume)
[ "$rc" != 0 ] && grep -q '已安装完成' "/tmp/$NODE-install.log" || die '已完成的节点不应再续装'
log '通过：PJ-E05 未连上主控明确报错、PJ-E06 半途失败可 --resume 续装'
