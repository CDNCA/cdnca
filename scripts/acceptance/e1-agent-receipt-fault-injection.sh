#!/usr/bin/env bash
# E1（PJ-E02/E03/E04）节点回执与防护状态真实性：真实 Linux 节点故障注入验收。
#
# 只在测试节点上以 root 执行，不要在生产节点上跑：
# 第 2、3 步会临时让节点状态目录不可写、让 nft 失败，结束时恢复。
#
# 用法（在节点上）：
#   sudo bash e1-agent-receipt-fault-injection.sh <step>
#   step: prepare-e02 | restore-e02 | prepare-e03 | restore-e03 | check-e04 | status
#
# 每一步之间，在主控上对该节点发一次站点发布，再按“主控核对”看结果。
#
# 主控核对（平台管理员）：
#   E02：发布 -> 部署列表该节点 state=healthy、节点告警列含“已激活、维护失败”
#        （warnings=post_activation_maintenance_failed）；不是 failed，error_code 为空。
#   E03：发布 -> 节点告警列含“防护异常”（ddos_protection_fault）；节点列表 XDP 过滤列显示“防护异常”。
#   E04：节点列表 XDP 过滤列显示“防护不可用”，提示含“没有安装 nftables”；
#        安装器在缺 nftables 且装不上时以 “nftables (the nft command) could not be installed” 退出。
set -Eeuo pipefail

STATE_ROOT=${DYNROUTE_STATE_ROOT:-/var/lib/dynroute/state}
STATE_JSON="$STATE_ROOT/state.json"
NFT_WRAPPER=/run/e1-nft-wrapper
NFT_REAL_COPY=/run/e1-nft-real
NFT_MOUNT_RECORD=/run/e1-nft-mounted
UNIT=cdnca-edge-agent

die() { printf 'e1-accept: %s\n' "$*" >&2; exit 1; }
log() { printf 'e1-accept: %s\n' "$*"; }
[ "$(id -u)" -eq 0 ] || die 'run as root on the test node'
[ "$(uname -s)" = Linux ] || die 'Linux only'

agent_log() { journalctl -u "$UNIT" --since "-${1:-10} min" --no-pager 2>/dev/null | grep -E "$2" | tail -n 20 || true; }

case "${1:-}" in
  prepare-e02)
    # state.json 不能被替换：在 state.json.tmp 位置放一个目录，os.WriteFile 失败。
    # 激活与健康检查照常完成，之后的 save_state 失败。
    [ -d "$STATE_ROOT" ] || die "no dynamic routing state root $STATE_ROOT"
    rm -f "$STATE_JSON.tmp"
    mkdir "$STATE_JSON.tmp"
    log "save_state will fail: $STATE_JSON.tmp is a directory. Publish a site to this node now, then run: $0 restore-e02"
    ;;
  restore-e02)
    agent_log 15 'post-activation|maintenance' | sed 's/^/  agent: /'
    rmdir "$STATE_JSON.tmp" 2>/dev/null || true
    log 'restored. Expect on the console: deployment healthy + warning post_activation_maintenance_failed, not failed/RunningConfigUnchanged.'
    log 'Publish once more: the warning must disappear (state saved, retention done).'
    ;;
  prepare-e03)
    # 用 bind mount 把 agent 解析到的 nft 换成包装脚本：读和探测照常转给真 nft，
    # 应用 DDoS 表（nft [--check] --file <含 cdnca_ddos 的规则文件>）一律失败。
    real=$(command -v nft) || die 'nft not installed (E03 needs a node with nftables)'
    real=$(readlink -f "$real")
    ! mountpoint -q "$real" || die "$real is already diverted"
    cp -p "$real" "$NFT_REAL_COPY"
    cat >"$NFT_WRAPPER" <<EOF
#!/bin/sh
previous=''
for argument in "\$@"; do
  if [ "\$previous" = --file ] && grep -qs cdnca_ddos "\$argument"; then
    echo 'Error: e1 injected failure' >&2; exit 1
  fi
  previous=\$argument
done
exec $NFT_REAL_COPY "\$@"
EOF
    chmod 0755 "$NFT_WRAPPER"
    mount --bind "$NFT_WRAPPER" "$real"
    printf '%s\n' "$real" >"$NFT_MOUNT_RECORD"
    log "$real now fails DDoS table changes. Publish a site to this node now, then run: $0 restore-e03"
    ;;
  restore-e03)
    agent_log 15 'DDoS protection' | sed 's/^/  agent: /'
    if [ -f "$NFT_MOUNT_RECORD" ]; then umount "$(cat "$NFT_MOUNT_RECORD")"; rm -f "$NFT_MOUNT_RECORD"; fi
    rm -f "$NFT_WRAPPER" "$NFT_REAL_COPY"
    log 'restored. Expect: deployment healthy + warning ddos_protection_fault; node list shows 防护异常.'
    log 'Publish once more: the warning and 防护异常 must clear (the table is retried with every apply).'
    ;;
  check-e04)
    # 不卸载 nftables：在 agent 视角隐藏 nft，确认上报“防护不可用”。
    dropin=/run/systemd/system/$UNIT.service.d/e1-no-nft.conf
    if [ -f "$dropin" ]; then
      rm -f "$dropin"; systemctl daemon-reload; systemctl restart "$UNIT"
      log 'e04 drop-in removed, agent restarted with nft visible again.'
      exit 0
    fi
    mkdir -p "$(dirname "$dropin")"
    # agent 进程看不到 nft（exec.LookPath 找不到可执行文件），等同最小系统未装 nftables。
    printf '[Service]\nInaccessiblePaths=-/usr/sbin/nft -/sbin/nft -/usr/local/sbin/nft\n' >"$dropin"
    systemctl daemon-reload; systemctl restart "$UNIT"
    sleep 5
    agent_log 2 'DDoS protection unavailable' | sed 's/^/  agent: /'
    log 'Expect: agent log "DDoS protection unavailable reason=nft_missing"; console node list shows 防护不可用 within one load sample.'
    log "Run $0 check-e04 again to restore."
    ;;
  status)
    log "state root $STATE_ROOT"; ls -ld "$STATE_JSON" "$STATE_JSON.tmp" 2>/dev/null || true
    [ -f "$NFT_MOUNT_RECORD" ] && log "nft diverted at $(cat "$NFT_MOUNT_RECORD")"
    agent_log 30 'DDoS protection|post-activation' | sed 's/^/  agent: /'
    ;;
  *) die 'usage: prepare-e02 | restore-e02 | prepare-e03 | restore-e03 | check-e04 | status' ;;
esac
