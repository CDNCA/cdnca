#!/usr/bin/env bash
# install-site.sh / install-control.sh / install-market.sh 的 certbot 签发判断（去掉
# --keep-until-expiring）。三个脚本都带同一个 acme_issue_mode：没有证书 new；已有证书与这次同为
# 正式或同为测试、域名一致且 30 天内不到期 skip（不请求 CA）；测试证书（签发者含 "(STAGING)"/"Fake LE"，
# 或 renewal 配置指向 staging）换正式、域名变化、临近到期 renew（--force-renewal）；已有正式证书而这次
# 要测试证书 skip。本脚本从三份脚本各抽出该函数，用 openssl 现造的证书逐一核对；同时核对脚本里不再出现
# --keep-until-expiring、certbot 调用按判断结果走。只需 bash + openssl，不连网、不碰 /etc/letsencrypt。
set -Eeuo pipefail
REPO=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAILED=0
command -v openssl >/dev/null || { echo 'SKIP: openssl is not available'; exit 0; }

# <目录> <签发者 CN> <有效天数> <renewal 配置里的 server，空为不写> <SAN 域名...>
lineage() {
  local dir=$WORK/$1 cn=$2 days=$3 server=$4 san="" d
  shift 4
  for d in "$@"; do san+="${san:+,}DNS:$d"; done
  mkdir -p "$dir/live"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days "$days" \
    -subj "/CN=$cn" -addext "subjectAltName=$san" -keyout "$dir/live/privkey.pem" -out "$dir/live/cert.pem" 2>/dev/null
  if [ -n "$server" ]; then printf 'version = 2.9.0\nserver = %s\n' "$server" >"$dir/renewal.conf"; fi
}
PROD=https://acme-v02.api.letsencrypt.org/directory
lineage prod-fresh 'R11' 80 "$PROD" cdnca.com www.cdnca.com
lineage prod-expiring 'R11' 10 "$PROD" cdnca.com www.cdnca.com
lineage staging-issuer '(STAGING) Pseudo Plum E5' 80 '' cdnca.com www.cdnca.com
lineage fake-le 'Fake LE Intermediate X1' 80 '' cdnca.com www.cdnca.com
lineage staging-server 'R11' 80 https://acme-staging-v02.api.letsencrypt.org/directory cdnca.com www.cdnca.com
mkdir -p "$WORK/none/live"

for script in install-site install-control install-market; do
  file=$REPO/scripts/$script.sh
  body=$(sed -n '/^acme_issue_mode() {/,/^}/p' "$file")
  if [ -z "$body" ]; then
    printf '!!!! %s 没有 acme_issue_mode\n' "$script"; FAILED=1; continue
  fi
  if grep -n -- '--keep-until-expiring' "$file"; then
    printf '!!!! %s 仍出现 --keep-until-expiring\n' "$script"; FAILED=1
  fi
  if grep -n 'acme_renewal_flag' "$file"; then printf '!!!! %s 仍用旧的 acme_renewal_flag\n' "$script"; FAILED=1; fi
  grep -q '=$(acme_issue_mode ' "$file" || { printf '!!!! %s 的 certbot 调用没有经 acme_issue_mode 判断\n' "$script"; FAILED=1; }
  grep -q 'renew) .*--force-renewal\|renew=(--force-renewal)' "$file" ||
    { printf '!!!! %s 没有把 renew 落成 --force-renewal\n' "$script"; FAILED=1; }
  eval "$body"
  check() { # <证书目录> <要测试证书> <期望> <域名...>
    local dir=$1 staging=$2 want=$3 got
    shift 3
    got=$(acme_issue_mode "$WORK/$dir/live" "$WORK/$dir/renewal.conf" "$staging" "$@")
    if [ "$got" = "$want" ]; then printf 'ok   %s %s staging=%s %s -> %s\n' "$script" "$dir" "$staging" "$*" "$got"
    else printf '!!!! %s %s staging=%s %s -> %s，期望 %s\n' "$script" "$dir" "$staging" "$*" "$got" "$want"; FAILED=1; fi
  }
  check none false new cdnca.com
  check none true new cdnca.com
  # 同 CA 正式证书未临近到期、域名一致：不请求 CA（重装不打满频率）；域名顺序不影响。
  check prod-fresh false skip cdnca.com www.cdnca.com
  check prod-fresh false skip www.cdnca.com cdnca.com
  # 域名变化（多了或少了）必须重签，否则新域名没证书。
  check prod-fresh false renew cdnca.com
  check prod-fresh false renew cdnca.com www.cdnca.com developer.cdnca.com
  check prod-expiring false renew cdnca.com www.cdnca.com
  # staging → 正式必重签（deploy-1026 第 24 行：去掉 --acme-staging 重跑仍拿着测试证书）。
  check staging-issuer false renew cdnca.com www.cdnca.com
  check fake-le false renew cdnca.com www.cdnca.com
  check staging-server false renew cdnca.com www.cdnca.com
  check staging-issuer true skip cdnca.com www.cdnca.com
  check staging-issuer true renew cdnca.com
  # 已有正式证书时又加了 --acme-staging：保留正式证书，不拿测试证书顶掉它（certbot 非交互下本就拒绝）。
  check prod-fresh true skip cdnca.com www.cdnca.com
  check prod-expiring true skip cdnca.com www.cdnca.com
  unset -f acme_issue_mode check
done
[ "$FAILED" = 0 ] && echo 'PASS install-acme-renewal' || { echo 'FAIL install-acme-renewal'; exit 1; }
