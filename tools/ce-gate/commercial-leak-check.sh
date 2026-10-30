#!/usr/bin/env bash
# cdncaCE 公开前与每次从商业 main 同步后的门禁：商业版授权锚定、冗余判定、二进制混淆的代码不得进入社区版。
# "trust anchor" 在基线 ff631864a 里本来就是回源 TLS、CA 证书安装、授权守卫错误码的通用词，宽匹配会大量误报，
# 所以与基线快照提交（56cdfd92）对比：只要出现基线里没有的命中行就失败。
# 专用名字（商业文件、钩子变量、fix-anchorsplit 合入后由主任务告知）放 STRICT，任何命中都失败。
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
BASE=56cdfd92
BROAD='entitlementroot|trust[-_]?anchor|VerifyPins|anchorEntitlementTrust|anchorUpgradeTrust|\bgarble\b|licredund|commercial[-_]?(trust[-_]?)?anchor'
STRICT='entitlementroot|VerifyPins|anchorEntitlementTrust|anchorUpgradeTrust|CDNCA_GARBLE|\bgarble\b|licredund|entitlement-trust-anchor|ENTITLEMENT_TRUST_ANCHOR_FILE|CONTROL_UPGRADE_TRUST_ANCHOR_FILE|commercial_trust_anchor|commercial_anchor|commercial-trust-anchor|embedded = "cdnca-offline-root/'
EXCLUDE=(-- . ':!CE-PROGRESS.md' ':!tools/ce-gate')
fail=0
strict=$(git grep -niE "$STRICT" "${EXCLUDE[@]}" | grep -viE 'garbled' || true)
if [ -n "$strict" ]; then printf 'STRICT 命中:\n%s\n' "$strict"; fail=1; fi
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
{ git grep -niE "$BROAD" "${EXCLUDE[@]}" || true; } | sed -E 's/^[^:]*:[0-9]+://' | grep -viE 'garbled' | sort -u >"$tmp/now" || true
# baseline-hits.txt：基线 56cdfd92 的宽匹配命中行内容（一次性生成，见文件头部注释）。
added=$(comm -23 "$tmp/now" tools/ce-gate/baseline-hits.txt)
if [ -n "$added" ]; then printf '相对基线 %s 新增的命中行:\n%s\n' "$BASE" "$added"; fail=1; fi
# 迁移 SQL 注释（主任务 10-29 建议）：注释里出现 recheck/redundan/anchor，且相对基线是新增的，就失败
# （基线已有 rechecked、period anchor 等正常用法，清单在 baseline-migration-comment-hits.txt）。
{ git grep -hiE -- '--.*(recheck|redundan|anchor)' -- 'services/control-api/migrations/*.sql' || true; } | sort -u >"$tmp/mig"
mig_added=$(comm -23 "$tmp/mig" tools/ce-gate/baseline-migration-comment-hits.txt)
if [ -n "$mig_added" ]; then printf '迁移注释里新增的敏感词:\n%s\n' "$mig_added"; fail=1; fi
[ $fail = 0 ] && { echo "commercial-leak-check: PASS"; exit 0; }
echo "commercial-leak-check: FAIL" >&2; exit 1
