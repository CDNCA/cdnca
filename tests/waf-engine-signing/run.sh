#!/bin/sh
# OWASP CRS engine extension signing with test-generated keys only (no
# network, no docker). Real binaries: waf-engine-package / waf-engine-smoke of
# this tree, driven through scripts/waf-engine-release.sh prepare|finalize.
# Only platform release signatures in signatures.json count; a raw
# manifest.sig (the removed 1.0.34 transitional edge execution signature) is
# not accepted.
# Keys: A = platform release key (artifacts.json, signs node packages),
# B = its successor (rotation), E = a control plane's edge execution key.
#   tests/waf-engine-signing/run.sh            -> SUMMARY failures=0
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
openssl="${OPENSSL:-openssl}"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-waf-signing.XXXXXX")"
work="$(cd "${work}" && pwd -P)"
trap 'rm -rf "${work}"' EXIT INT TERM
failures=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1 expected=$2 actual=$3 $4"; else echo "FAIL $1 expected=$2 actual=$3 $4"; failures=$((failures + 1)); fi; }

version="$(tr -d '[:space:]' <"${repo_root}/edge/openresty/modsecurity/VERSION")"
openresty="$(sed -n 's/.*"version": "\([0-9.]*\)".*/\1/p' "${repo_root}/edge/openresty/native/sources.lock.json" | head -1)"
dir="waf-crs-module/${version}/openresty-${openresty}/linux-amd64"

# Tools.
mkdir -p "${work}/bin"
go -C "${repo_root}/agents/edge-agent" build -o "${work}/bin/package" ./internal/wafengine/cmd/waf-engine-package
go -C "${repo_root}/agents/edge-agent" build -o "${work}/bin/smoke" ./internal/wafengine/cmd/waf-engine-smoke

# Keys (test only) and the platform trust document as published: Ed25519
# release keys next to an ECDSA P-256 anchor, which the extension skips.
for key in A B E; do
  "${openssl}" genpkey -algorithm ed25519 -out "${work}/${key}.pem" 2>/dev/null
  "${openssl}" pkey -in "${work}/${key}.pem" -pubout -out "${work}/${key}.pub" 2>/dev/null
done
"${openssl}" ecparam -name prime256v1 -genkey -noout -out "${work}/P.pem" 2>/dev/null
"${openssl}" ec -in "${work}/P.pem" -pubout -out "${work}/P.pub" 2>/dev/null
json_pem() { awk 'BEGIN{ORS=""} {gsub(/"/,"\\\""); print $0 "\\n"}' "$1"; }
trust() { # key-id:pubfile...
  printf '{"version":1,"keys":['
  sep=''
  for entry in "$@"; do printf '%s{"key_id":"%s","public_key_pem":"%s"}' "${sep}" "${entry%%:*}" "$(json_pem "${entry#*:}")"; sep=','; done
  printf ']}\n'
}
trust platform-a:"${work}/A.pub" platform-b:"${work}/B.pub" native-edge-p256:"${work}/P.pub" >"${work}/artifacts.json"
sign_data() { "${openssl}" pkeyutl -sign -rawin -inkey "$1" -in "$2" -out "$3.raw" && "${openssl}" base64 -A -in "$3.raw" -out "$3"; }

# A fake extension tree with the files a module build has.
tree="${work}/tree"
mkdir -p "${tree}/modules" "${tree}/lib"
printf 'module' >"${tree}/modules/ngx_http_modsecurity_module.so"
printf 'lib' >"${tree}/lib/libmodsecurity.so.3"
printf 'mapping' >"${tree}/unicode.mapping"
printf 'Apache-2.0' >"${tree}/LICENSE.libmodsecurity"

release() { # name, platform keys (A, B or AB): release script
  name=$1 platform=$2 out="${work}/out-$1"
  WAF_ENGINE_TOOL="${work}/bin/package" WAF_ENGINE_TREE="${tree}" WAF_ENGINE_KEY_ID=platform-a \
    sh "${repo_root}/scripts/waf-engine-release.sh" prepare "${out}" amd64 >"${work}/${name}.prepare.log"
  set --
  case "${platform}" in *A*) sign_data "${work}/A.pem" "${out}/waf-amd64/release.signing-data" "${out}/a.sig"; set -- "$@" "platform-a=${out}/a.sig" ;; esac
  case "${platform}" in *B*) sign_data "${work}/B.pem" "${out}/waf-amd64/release.signing-data" "${out}/b.sig"; set -- "$@" "platform-b=${out}/b.sig" ;; esac
  WAF_ENGINE_TOOL="${work}/bin/package" sh "${repo_root}/scripts/waf-engine-release.sh" finalize "${out}" amd64 \
    "${work}/artifacts.json" "$@" >"${work}/${name}.finalize.log"
  printf '%s' "${out}/${dir}"
}
P="$(release P A)"       # platform signature (the release)
R="$(release R AB)"      # rotation overlap: A and B
# L: the removed 1.0.34 transitional form -- only a raw edge execution
# signature over manifest.json in manifest.sig, listed in SHA256SUMS.
L="${work}/out-L"
cp -R "${P}" "${L}" && chmod -R u+w "${L}" && rm "${L}/signatures.json"
"${openssl}" pkeyutl -sign -rawin -inkey "${work}/E.pem" -in "${L}/manifest.json" -out "${L}/manifest.sig"
{ grep -v ' signatures.json$' "${P}/SHA256SUMS"; printf '%s  manifest.sig\n' "$(shasum -a 256 "${L}/manifest.sig" | cut -d' ' -f1)"; } >"${L}/SHA256SUMS"

check FILES-P "SHA256SUMS cdnca-waf-crs-module-${version}-openresty-${openresty}-linux-amd64.tar.gz manifest.json signatures.json" \
  "$(ls "${P}" | tr '\n' ' ' | sed 's/ $//')" "只有平台签名，无 manifest.sig"
check KEYID-P platform-a "$(sed -n 's/.*"key_id": "\([^"]*\)".*/\1/p' "${P}/manifest.json")" "manifest.key_id 为平台 key"
check SIGS-R 2 "$(grep -c '"key_id"' "${R}/signatures.json")" "轮换期两把平台 key 都签"
(cd "${P}" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1) && sums=ok || sums=fail
check SUMS-P ok "${sums}" "SHA256SUMS 自洽"

# finalize refuses what a node would refuse.
refuse() { # name, signer function, description[, expected]: finalize must fail and leave no SHA256SUMS
  name=$1 signer=$2 description=$3 expected=${4:-refused}
  out="${work}/out-refuse-${name}"
  WAF_ENGINE_TOOL="${work}/bin/package" WAF_ENGINE_TREE="${tree}" WAF_ENGINE_KEY_ID=platform-a \
    sh "${repo_root}/scripts/waf-engine-release.sh" prepare "${out}" amd64 >/dev/null
  "${signer}" "${out}"
  WAF_ENGINE_TOOL="${work}/bin/package" sh "${repo_root}/scripts/waf-engine-release.sh" finalize "${out}" amd64 \
    "${work}/artifacts.json" "${REFUSE_PAIR}" >/dev/null 2>&1 && result=accepted || result=refused
  [ -e "${out}/${dir}/SHA256SUMS" ] && result="${result}+sums"
  check "REFUSE-${name}" "${expected}" "${result}" "${description}"
}
good() { sign_data "${work}/A.pem" "$1/waf-amd64/release.signing-data" "$1/x.sig"; REFUSE_PAIR="platform-a=$1/x.sig"; }
REFUSE_PAIR=''; refuse CONTROL good "对照：同一路径下正确签名被接受" accepted+sums
unlisted() { sign_data "${work}/E.pem" "$1/waf-amd64/release.signing-data" "$1/x.sig"; REFUSE_PAIR="edge-execution-v1=$1/x.sig"; }
refuse UNLISTED-KEY unlisted "不在 artifacts.json 的 key（edge 执行 key）签名被拒"
wrongkey() { sign_data "${work}/B.pem" "$1/waf-amd64/release.signing-data" "$1/x.sig"; REFUSE_PAIR="platform-a=$1/x.sig"; }
refuse WRONG-KEY wrongkey "签名与声明的 key_id 不符被拒"
rawmanifest() { sign_data "${work}/A.pem" "$1/${dir}/manifest.json" "$1/x.sig"; REFUSE_PAIR="platform-a=$1/x.sig"; }
refuse NO-DOMAIN rawmanifest "平台 key 直接签 manifest.json（无域前缀）被拒"
p256() { sign_data "${work}/A.pem" "$1/waf-amd64/release.signing-data" "$1/x.sig"; REFUSE_PAIR="native-edge-p256=$1/x.sig"; }
refuse ECDSA-ANCHOR p256 "ECDSA 锚点不能作为扩展签名 key"

# Agent installs. state/reason (and the new agent's recorded signer).
install() { # name, smoke binary, package dir, smoke key args...
  name=$1 binary=$2 pkg=$3; shift 3
  base="${work}/node-${name}"
  mkdir -p "${base}/release/security/modsecurity"
  printf 'include %s/waf-engine/v1/load[.]conf;\nevents {}\nhttp {}\n' "${base}/state" >"${base}/release/nginx.conf"
  printf '{"schema":"cdnca.edge.waf-engine/v2","engine":"modsecurity","crs_version":"4.30.0","sites":[{"site_id":"11111111-1111-4111-8111-111111111111","exclusions":[]}]}' \
    >"${base}/release/security/modsecurity/engine.json"
  "${binary}" install --pkg "${pkg}" "$@" --root "${base}/root" --state "${base}/state" --release "${base}/release" \
    --version-id v1 --version "${version}" --openresty "${openresty}" --arch amd64 >"${base}/out.json"
  state="$(sed -n 's/.*"state":"\([a-z_]*\)".*/\1/p' "${base}/out.json")"
  reason="$(sed -n 's/.*"reason":"\([a-z_]*\)".*/\1/p' "${base}/out.json")"
  signer="$(sed -n 's/.*"signer":{"key_id":"\([^"]*\)"}.*/\1/p' "${base}/root/installed.json" 2>/dev/null || true)"
  printf '%s' "${state}${reason:+/${reason}}${signer:+ ${signer}}"
}
new_A="--public-key ${work}/A.pub --key-id platform-a"
new_B="--public-key ${work}/B.pub --key-id platform-b"
new_E="--public-key ${work}/E.pub --key-id edge-execution-v1"     # an edge execution key passed as a release key
# shellcheck disable=SC2086
{
check NEW-P "active platform-a" "$(install new-P "${work}/bin/smoke" "${P}" ${new_A})" "平台签名：安装"
check MANIFEST-SIG degraded/signature_invalid "$(install sig-L "${work}/bin/smoke" "${L}" ${new_A})" "只有 manifest.sig（已删的过渡签名）：拒绝"
check MANIFEST-SIG-EDGE degraded/signature_invalid "$(install sig-LE "${work}/bin/smoke" "${L}" ${new_E})" "节点即使信任该 edge 执行 key，manifest.sig 也不被接受"
check ROT-OLD "active platform-a" "$(install rot-a "${work}/bin/smoke" "${R}" ${new_A})" "轮换期：只认旧 key 的节点"
check ROT-NEW "active platform-b" "$(install rot-b "${work}/bin/smoke" "${R}" ${new_B})" "轮换期：只认新 key 的节点"
check RETIRED degraded/signature_invalid "$(install retired "${work}/bin/smoke" "${P}" ${new_B})" "节点信任里已去掉的 key 签的扩展被拒"
}
# Tampering with signatures.json after finalize: SHA256SUMS rejects it.
cp -R "${P}" "${work}/tampered" && chmod -R u+w "${work}/tampered"
sed 's/"algorithm": "ed25519"/"algorithm":  "ed25519"/' "${P}/signatures.json" >"${work}/tampered/signatures.json"
# shellcheck disable=SC2086
check TAMPER degraded/install_rejected "$(install tamper "${work}/bin/smoke" "${work}/tampered" ${new_A})" "改动 signatures.json：SHA256SUMS 不符"
echo "SUMMARY failures=${failures}"
[ "${failures}" -eq 0 ]
