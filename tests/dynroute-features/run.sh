#!/bin/sh
# 真实 OpenResty 冒烟：RUM 注入/上报/缓存原始字节、第三方人机验证降级、
# 生产挑战安装器写入后节点预加载并拦截放行（challenge_root）。
# 一个 --rm --network none 容器，节点运行时镜像。
#   tests/dynroute-features/run.sh <image> [ONLY=rum,c3,install]
# 镜像必须显式传入（本分支构建的 cdnca-native-runtime:edge-golden），不设默认值。
set -eu
image=${1:?usage: run.sh <image>, the native runtime image built from this branch}
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-feat.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/edgegolden/goldendyn/cmd/cdnca-features-check
mkdir -p "${work}/lua"
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
		cp "${repo_root}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
	done
chmod -R a+rX "${work}"
docker run --rm --init --network none -v "${work}:/feat:ro" --entrypoint /feat/check "${image}" \
	-lua /feat/lua -workers "${WORKERS:-2}" -only "${ONLY:-rum,c3,install}"
