#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

for command_name in docker go openssl curl rg; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "required command is unavailable: ${command_name}" >&2
    exit 69
  fi
done
if [ -z "${TEST_DATABASE_URL:-}" ]; then
  echo "TEST_DATABASE_URL is required for the PostgreSQL publication smoke" >&2
  exit 69
fi

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
workdir="$(mktemp -d "${tmp_base%/}/cdnca-certificate-publication.XXXXXX")"
suffix="$(basename "${workdir}" | sed 's/^cdnca-certificate-publication\.//')"
container="cdnca-certificate-publication-${suffix}"
proxy_container="cdnca-certificate-publication-proxy-${suffix}"
network="cdnca-certificate-publication-${suffix}"
proxy_image="alpine/socat@sha256:7460121640bff33376cd25006e45920a69dc5b6ac3339b6db36bfff5d373afca"
edge_pid=""

cleanup() {
  if [ -n "${edge_pid}" ]; then
    kill "${edge_pid}" >/dev/null 2>&1 || true
    wait "${edge_pid}" >/dev/null 2>&1 || true
  fi
  docker rm -f "${proxy_container}" >/dev/null 2>&1 || true
  docker rm -f "${container}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-certificate-publication.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

mkdir -p "${workdir}/fixture" "${workdir}/state/certstore"
chmod 0700 "${workdir}" "${workdir}/fixture" "${workdir}/state" "${workdir}/state/certstore"
smoke_now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

smoke_source="${repo_root}/services/control-api/internal/certificatepublish/cmd/certificate-publish-smoke"
(
  cd "${repo_root}/services/control-api"
  GOWORK=off CGO_ENABLED=0 \
    CERTIFICATE_PUBLICATION_FIXTURE_DIR="${workdir}/fixture" \
    CERTIFICATE_PUBLICATION_SMOKE_NOW="${smoke_now}" \
    TEST_DATABASE_URL="${TEST_DATABASE_URL}" \
    go test -tags=integration -count=1 \
    -run '^TestPublicationRuntimeAtomicReplacementAndRevocation$' \
    ./internal/certificatepublish
) >"${workdir}/producer.out"

edge_virtual="${repo_root}/agents/edge-agent/internal/gatewayclient/certificate_publication_smoke_test.go"
printf '{"Replace":{"%s":"%s"}}\n' \
  "${edge_virtual}" "${smoke_source}/edge_consumer_smoke_test.go.txt" \
  >"${workdir}/edge-overlay.json"
printf 'go 1.27.0\n\nuse (\n\t%s\n\t%s\n\t%s\n\t%s\n)\n' \
  "${repo_root}/agents/edge-agent" \
  "${repo_root}/services/agent-gateway" \
  "${repo_root}/proto/gen/go" \
  "${repo_root}/libs/edgeconfig" \
  >"${workdir}/go.work"
(
  cd "${repo_root}/agents/edge-agent"
  GOWORK="${workdir}/go.work" CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go test -c -overlay="${workdir}/edge-overlay.json" \
    -o "${workdir}/edge-certificate-publication-smoke.test" \
    ./internal/gatewayclient
)

docker network create "${network}" >/dev/null
docker run --detach \
  --name "${container}" \
  --network "${network}" \
  --publish 127.0.0.1::28443 \
  --volume "${workdir}/fixture:/fixture:rw" \
  --volume "${workdir}/state:/state:rw" \
  --volume "${workdir}/edge-certificate-publication-smoke.test:/usr/local/bin/edge-certificate-publication-smoke.test:ro" \
  --entrypoint /bin/sh \
  "${OPENRESTY_IMAGE}" \
  -c 'trap "exit 0" TERM INT; while :; do sleep 3600; done' >/dev/null

docker exec \
  -e CERTIFICATE_PUBLICATION_FIXTURE_DIR=/fixture \
  -e CERTIFICATE_PUBLICATION_STATE_ROOT=/state/certstore \
  -e CERTIFICATE_PUBLICATION_OPENRESTY_BIN=/usr/local/openresty/bin/openresty \
  -e CERTIFICATE_PUBLICATION_LISTEN_ADDRESS=127.0.0.1 \
  -e CERTIFICATE_PUBLICATION_LISTEN_PORT=18443 \
  -e CERTIFICATE_PUBLICATION_READY_FILE=/state/ready \
  -e CERTIFICATE_PUBLICATION_RELEASE_FILE=/state/release \
  "${container}" /usr/local/bin/edge-certificate-publication-smoke.test \
  -test.run '^TestCertificatePublicationConsumerSmoke$' -test.v \
  >"${workdir}/edge.out" 2>&1 &
edge_pid=$!

ready_attempt=0
while [ ! -f "${workdir}/state/ready" ]; do
  if ! kill -0 "${edge_pid}" 2>/dev/null; then
    wait "${edge_pid}" || true
    edge_pid=""
    cat "${workdir}/edge.out" >&2
    docker logs "${container}" >&2 || true
    exit 1
  fi
  ready_attempt=$((ready_attempt + 1))
  if [ "${ready_attempt}" -ge 300 ]; then
    echo "Edge publication smoke did not become ready" >&2
    cat "${workdir}/edge.out" >&2
    exit 1
  fi
  sleep 0.1
done

docker run --detach \
  --name "${proxy_container}" \
  --network "container:${container}" \
  "${proxy_image}" \
  TCP-LISTEN:28443,fork,reuseaddr TCP:127.0.0.1:18443 >/dev/null

published="$(docker port "${container}" 28443/tcp)"
host_port="${published##*:}"
case "${host_port}" in
  ''|*[!0-9]*)
    echo "invalid published TLS port: ${published}" >&2
    exit 1
    ;;
esac

openssl_attempt=0
while ! openssl s_client \
  -connect "127.0.0.1:${host_port}" \
  -servername publication.example.test \
  -CAfile "${workdir}/fixture/ca.pem" \
  -verify_return_error -showcerts </dev/null \
  >"${workdir}/openssl.out" 2>&1; do
  openssl_attempt=$((openssl_attempt + 1))
  if [ "${openssl_attempt}" -ge 50 ] || \
    [ "$(docker inspect --format '{{.State.Running}}' "${proxy_container}" 2>/dev/null || true)" != true ]; then
    cat "${workdir}/openssl.out" >&2
    docker logs "${proxy_container}" >&2 || true
    docker logs "${container}" >&2 || true
    exit 1
  fi
  sleep 0.1
done
if ! rg -F 'Verify return code: 0 (ok)' "${workdir}/openssl.out" >/dev/null; then
  cat "${workdir}/openssl.out" >&2
  exit 1
fi
certificate_count="$(rg -c -- '-----BEGIN CERTIFICATE-----' "${workdir}/openssl.out")"
if [ "${certificate_count}" -ne 2 ]; then
  echo "OpenResty presented ${certificate_count} certificates, want leaf and intermediate" >&2
  exit 1
fi

curl --silent --show-error --fail --noproxy '*' \
  --resolve "publication.example.test:${host_port}:127.0.0.1" \
  --cacert "${workdir}/fixture/ca.pem" \
  "https://publication.example.test:${host_port}/" \
  >"${workdir}/curl.out"
config_version_id="$(sed -n 's/^[[:space:]]*"config_version_id":[[:space:]]*"\([^"]*\)".*/\1/p' "${workdir}/fixture/evidence.json")"
if [ -z "${config_version_id}" ] || \
  [ "$(tr -d '\r\n' <"${workdir}/curl.out")" != "certificate-version:${config_version_id}" ]; then
  cat "${workdir}/curl.out" >&2
  exit 1
fi

docker exec "${container}" touch /state/release
if ! wait "${edge_pid}"; then
  edge_pid=""
  cat "${workdir}/edge.out" >&2
  docker logs "${container}" >&2 || true
  exit 1
fi
edge_pid=""

if rg -i 'private_key_pem|begin (rsa |ec )?private key|certificate-integration-kek' \
  "${workdir}/producer.out" "${workdir}/edge.out" \
  "${workdir}/openssl.out" "${workdir}/curl.out" "${workdir}/fixture/evidence.json" >/dev/null; then
  echo "private certificate material appeared in smoke output or metadata" >&2
  exit 1
fi

cat "${workdir}/fixture/evidence.json"
printf '%s\n' \
  'gateway_fetch_artifact=passed-real-tls13-mtls' \
  'edge_gatewayclient_hpke=passed' \
  'edge_certstore_install=passed' \
  'openssl_sni_chain_verify=passed' \
  'curl_tls_response=passed' \
  'control_and_gateway_offline_serving=passed' \
  "openresty_version=${OPENRESTY_VERSION}" \
  "image=${OPENRESTY_IMAGE}" \
  "proxy_image=${proxy_image}" \
  'isolation=task-owned-container-network-state-and-random-host-port'
