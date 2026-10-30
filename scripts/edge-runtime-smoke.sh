#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
. "${repo_root}/edge/openresty/runtime.env"

docker_arch="$(docker info --format '{{.Architecture}}')"
case "${docker_arch}" in
  arm64|aarch64) go_arch=arm64 ;;
  amd64|x86_64) go_arch=amd64 ;;
  *)
    echo "unsupported Docker architecture: ${docker_arch}" >&2
    exit 69
    ;;
esac

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-runtime.XXXXXX")"
suffix="$(basename "${workdir}" | sed 's/^cdnca-edge-runtime\.//')"
container="cdnca-edge-runtime-${suffix}"
image="cdnca/openresty-runtime:smoke-${suffix}"
repeat_image="cdnca/openresty-runtime:smoke-${suffix}-repeat"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  docker image rm "${image}" >/dev/null 2>&1 || true
  docker image rm "${repeat_image}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-runtime.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

mkdir -p "${workdir}/state"
(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go build -trimpath -ldflags '-s -w -buildid=' \
    -o "${workdir}/edge-runtime-smoke" ./cmd/edge-runtime-smoke
)

if ! "${repo_root}/scripts/edge-runtime-build.sh" "${image}" >"${workdir}/build-first.log" 2>&1; then
  cat "${workdir}/build-first.log" >&2
  exit 1
fi
if ! CDNCA_EDGE_NO_CACHE=1 "${repo_root}/scripts/edge-runtime-build.sh" "${repeat_image}" >"${workdir}/build-repeat.log" 2>&1; then
  cat "${workdir}/build-repeat.log" >&2
  exit 1
fi
image_id="$(docker image inspect "${image}" --format '{{.Id}}')"
repeat_image_id="$(docker image inspect "${repeat_image}" --format '{{.Id}}')"
image_id_match=false
[ "${image_id}" = "${repeat_image_id}" ] && image_id_match=true
image_config="$(docker image inspect "${image}" --format '{{json .Config}}')"
repeat_image_config="$(docker image inspect "${repeat_image}" --format '{{json .Config}}')"
test "${image_config}" = "${repeat_image_config}"
image_config_sha256="$(printf '%s' "${image_config}" | shasum -a 256 | awk '{print $1}')"
image_created="$(docker image inspect "${image}" --format '{{.Created}}')"
repeat_image_created="$(docker image inspect "${repeat_image}" --format '{{.Created}}')"
test "${image_created}" = "${repeat_image_created}"
image_layers="$(docker image inspect "${image}" --format '{{range .RootFS.Layers}}{{println .}}{{end}}')"
repeat_image_layers="$(docker image inspect "${repeat_image}" --format '{{range .RootFS.Layers}}{{println .}}{{end}}')"
source_layers="$(docker image inspect "${OPENRESTY_IMAGE}" --format '{{range .RootFS.Layers}}{{println .}}{{end}}')"
test "$(printf '%s\n' "${image_layers}" | wc -l | tr -d ' ')" = "$(printf '%s\n' "${repeat_image_layers}" | wc -l | tr -d ' ')"
source_layer_count="$(printf '%s\n' "${source_layers}" | wc -l | tr -d ' ')"
test "${source_layer_count}" -gt 0
base_layers="$(printf '%s\n' "${image_layers}" | sed -n "1,${source_layer_count}p")"
repeat_base_layers="$(printf '%s\n' "${repeat_image_layers}" | sed -n "1,${source_layer_count}p")"
test -n "${base_layers}"
test "${base_layers}" = "${source_layers}"
test "${repeat_base_layers}" = "${source_layers}"
base_layers_sha256="$(printf '%s' "${base_layers}" | shasum -a 256 | awk '{print $1}')"
entrypoint_sha256="$(shasum -a 256 "${repo_root}/edge/openresty/entrypoint.sh" | awk '{print $1}')"
image_entrypoint_sha256="$(docker run --rm --entrypoint /bin/sh "${image}" -c 'sha256sum /usr/local/bin/cdnca-openresty-entrypoint' | awk '{print $1}')"
repeat_entrypoint_sha256="$(docker run --rm --entrypoint /bin/sh "${repeat_image}" -c 'sha256sum /usr/local/bin/cdnca-openresty-entrypoint' | awk '{print $1}')"
test "${image_entrypoint_sha256}" = "${entrypoint_sha256}"
test "${repeat_entrypoint_sha256}" = "${entrypoint_sha256}"
base_digest_label="$(docker image inspect "${image}" --format '{{index .Config.Labels "org.opencontainers.image.base.digest"}}')"
test "${base_digest_label}" = "${OPENRESTY_SOURCE_DIGEST}"
actual_version="$(docker run --rm --entrypoint /bin/sh "${image}" -c '/usr/local/openresty/bin/openresty -V 2>&1 | sed -n "s/^nginx version: openresty\///p"')"
test "${actual_version}" = "${OPENRESTY_VERSION}"

docker run --detach \
  --name "${container}" \
  --publish 127.0.0.1::18080 \
  --volume "${workdir}/state:/var/lib/cdnca-edge" \
  --volume "${workdir}/edge-runtime-smoke:/usr/local/bin/edge-runtime-smoke:ro" \
  --entrypoint /bin/sh \
  "${image}" \
  -c 'trap "exit 0" TERM INT; while :; do sleep 3600; done' >/dev/null

published="$(docker port "${container}" 18080/tcp | tail -n 1)"
case "${published}" in
  127.0.0.1:*) ;;
  *) echo "runtime was not published to a random loopback port: ${published}" >&2; exit 1 ;;
esac
host_port="${published##*:}"
test "${host_port}" != "15173"
test "${host_port}" != "8080"

docker exec "${container}" /usr/local/bin/edge-runtime-smoke \
  -state-root /var/lib/cdnca-edge \
  -listen-port 18080 \
  -keep-runtime

body="$(curl --fail --silent --show-error "http://${published}/healthz")"
test "${body}" = "ok:cfg-v2"

docker rm -f "${container}" >/dev/null
docker run --detach \
  --name "${container}" \
  --publish 127.0.0.1::18080 \
  --volume "${workdir}/state:/var/lib/cdnca-edge" \
  "${image}" >/dev/null
restart_published="$(docker port "${container}" 18080/tcp | tail -n 1)"
case "${restart_published}" in
  127.0.0.1:*) ;;
  *) echo "restarted runtime was not published to a random loopback port: ${restart_published}" >&2; exit 1 ;;
esac
restart_host_port="${restart_published##*:}"
test "${restart_host_port}" != "15173"
test "${restart_host_port}" != "8080"
restart_body=""
attempt=0
while [ "${attempt}" -lt 40 ]; do
  restart_body="$(curl --silent "http://${restart_published}/healthz" 2>/dev/null || true)"
  [ "${restart_body}" = "ok:cfg-v2" ] && break
  attempt=$((attempt + 1))
  sleep 0.25
done
test "${restart_body}" = "ok:cfg-v2"

printf 'openresty_version=%s\nimage_source=%s\nimage_created=%s\nimage_id=%s\nrepeat_image_id=%s\nimage_id_match=%s\nnormalized_config_sha256=%s\nbase_layers_sha256=%s\nentrypoint_sha256=%s\npublished=%s\nexternal_health=%s\nrestart_published=%s\nrestart_health=%s\n' \
  "${actual_version}" "${OPENRESTY_SOURCE_DIGEST}" "${image_created}" "${image_id}" "${repeat_image_id}" "${image_id_match}" \
  "${image_config_sha256}" "${base_layers_sha256}" "${entrypoint_sha256}" "${published}" "${body}" \
  "${restart_published}" "${restart_body}"
