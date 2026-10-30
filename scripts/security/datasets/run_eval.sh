#!/bin/sh
# 用 waf-strict-algo 分支的 cdnca-waf-check -only eval（真实 OpenResty + libmodsecurity，四档 CRS 档位包）
# 跑 build_eval_corpus.py 产出的一个批次。跟 tests/dynroute-waf/run.sh 的 eval 分支一致，只是 -corpus 换成本批次。
#   用法：run_eval.sh <batch.json> <out.log>
#   STRICT_WT  评测工具所在工作树（默认本脚本所在仓库，只读、只构建）
#   IMAGE      节点运行时镜像（默认 cdnca-native-runtime:edge-golden）
set -eu
batch=$1
out=$2
wt=${STRICT_WT:-$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)}
image=${IMAGE:-cdnca-native-runtime:edge-golden}
runtime=${MODSECURITY_RUNTIME:-$(sh "${wt}/scripts/security/modsecurity-runtime.sh")}
[ -f "${runtime}/modules/ngx_http_modsecurity_module.so" ] || { echo "BLOCKED: no ModSecurity runtime" >&2; exit 69; }
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/rs-eval-run.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${wt}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/edgegolden/goldendyn/cmd/cdnca-waf-check
mkdir -p "${work}/lua"
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${wt}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
		cp "${wt}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
	done
cp "${batch}" "${work}/corpus.json"
chmod -R a+rX "${work}"
docker run --rm --init --network none -v "${work}:/d11:ro" -v "${runtime}:/usr/local/openresty/modsecurity:ro" \
	--entrypoint /d11/check "${image}" -lua /d11/lua -workers "${WORKERS:-2}" -only eval -corpus /d11/corpus.json >"${out}" 2>&1
