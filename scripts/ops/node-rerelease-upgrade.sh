#!/usr/bin/env bash
# 已装节点升级到同版本重出包。在节点上以 root 执行。
# 用法：bash node-rerelease-upgrade.sh [下载源，默认 https://www.cdnca.com/downloads/ce]
# 打包层规则见 agents/edge-agent/packaging/scripts/lib.sh 的 stage_rerelease_release。
# 步骤：下载 latest 节点原生包 → 用节点已钉的信任文件经 install-node.sh --verify-native-package 校验解包
#   → 比较签名清单 release_sequence（不高于已装的直接退出，不改任何东西）
#   → 从新包刷新打包脚本与 helper（install.sh --refresh-toolset）
#   → 从新包运行 upgrade.sh（带原生包）：签名、公钥钉、序号防回滚照旧，停 Agent 换 versions/<版本>，健康失败自动换回
#   → 读回 release 序号、源码提交、agent build_id 与服务状态。
set -euo pipefail
BASE=${1:-https://www.cdnca.com/downloads/ce}
[ "$(id -u)" -eq 0 ] || { echo "请用 root 执行" >&2; exit 2; }
TRUST=/etc/cdnca-edge-agent/trust/artifacts.json
[ -r "$TRUST" ] || { echo "缺少 $TRUST，这台机器不是已装节点" >&2; exit 2; }
CUR=/usr/lib/cdnca-edge-agent/current
[ -L "$CUR" ] || { echo "缺少 $CUR，这台机器没有已装 release" >&2; exit 2; }
W=$(mktemp -d /var/tmp/cdnca-rerelease.XXXXXX); chmod 0755 "$W"; trap 'rm -rf "$W"' EXIT
cd "$W"
curl -fsS -o SHA256SUMS "$BASE/edge-agent/latest/SHA256SUMS"
curl -fsS -o cdnca-edge-agent.tar.gz "$BASE/edge-agent/latest/cdnca-edge-agent.tar.gz"
grep -E ' cdnca-edge-agent\.tar\.gz$' SHA256SUMS | sha256sum -c -
curl -fsS -o install-node.sh "$BASE/install-node.sh"
bash install-node.sh --verify-native-package "$W/cdnca-edge-agent.tar.gz" "$TRUST" "$W/pkg"
N=$W/pkg
field() { sed -n "$2s/^$3=//p" "$1"; }
show() { printf '%s：版本 %s 序号 %s 提交 %s\n' "$1" "$(field "$2" 3 version)" "$(field "$2" 2 release_sequence)" "$(field "$2" 13 source_commit)"; }
show 已装 "$CUR/manifest"
show 新包 "$N/upgrade/manifest"
old_seq=$(field "$CUR/manifest" 2 release_sequence)
new_seq=$(field "$N/upgrade/manifest" 2 release_sequence)
if [ "$new_seq" -le "$old_seq" ]; then
  echo "新包序号不高于已装序号，无需升级；未做任何改动"
  exit 0
fi
BUNDLE=(--artifact "$N/bin/edge-agent" --sbom "$N/evidence/edge-agent.spdx.json"
  --manifest "$N/upgrade/manifest" --signature "$N/upgrade/manifest.sig" --public-key "$N/upgrade/package-signing.pem")
"$N/packaging/scripts/install.sh" --refresh-toolset "${BUNDLE[@]}"
"$N/packaging/scripts/upgrade.sh" "${BUNDLE[@]}" --native "$W/cdnca-edge-agent.tar.gz"
show 升级后 "$CUR/manifest"
"$CUR/edge-agent" --version
echo "agent 状态：$(systemctl is-active cdnca-edge-agent)"
