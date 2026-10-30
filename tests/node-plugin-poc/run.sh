#!/bin/sh
# ADR 0017 PoC (results in docs/adr/0017-third-party-node-plugins.md §6).
#   tests/node-plugin-poc/run.sh
# Builds the plugin host, the sample plugin and the bench client on the host,
# then runs scenario.sh in one --rm --network none container of the real node
# runtime image (OpenResty 1.31.1.1, NODE_PLUGIN_POC_IMAGE). The container is
# capped at 2 CPUs / 512 MiB. On a shared machine set NODE_PLUGIN_POC_WRAP to
# the job-queue wrapper.
set -eu
here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
image="${NODE_PLUGIN_POC_IMAGE:-cdnca-native-runtime:edge-golden}"
arch="$(docker image inspect "${image}" --format '{{.Architecture}}')"
wrap="${NODE_PLUGIN_POC_WRAP:-}"
bin="$(mktemp -d)"
trap 'rm -rf "${bin}"' EXIT
export GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0
GOOS=linux GOARCH="${arch}" go -C "${here}" build -o "${bin}/host" ./host
GOOS=linux GOARCH="${arch}" go -C "${here}" build -o "${bin}/bench" ./bench
GOOS=wasip1 GOARCH=wasm go -C "${here}" build -buildmode=c-shared -o "${bin}/plugin.wasm" ./plugin
${wrap} docker run --rm --network none --cpus 2 --memory 512m \
  -v "${here}:/poc:ro" -v "${bin}:/pocbin:ro" --entrypoint sh "${image}" /poc/scenario.sh
