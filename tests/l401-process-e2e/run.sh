#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
readonly SCRIPT_DIR REPO_ROOT

readonly POSTGRES_IMAGE='postgres:17.9-alpine'
readonly NATS_IMAGE='nats:2.11.4-alpine'
readonly NATS_BOX_IMAGE='natsio/nats-box:0.19.1'
readonly REDIS_IMAGE='redis:7.4.4-alpine'
readonly GO_IMAGE='docker.io/library/golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5'
# The runner's OpenResty is the node runtime pinned in edge/openresty/runtime.env.
OPENRESTY_IMAGE="$(sed -n 's/^OPENRESTY_IMAGE=//p' "${REPO_ROOT}/edge/openresty/runtime.env")"
OPENRESTY_VERSION="$(sed -n 's/^OPENRESTY_VERSION=//p' "${REPO_ROOT}/edge/openresty/runtime.env")"
readonly OPENRESTY_IMAGE OPENRESTY_VERSION
readonly RUNNER_IMAGE="${L401_RUNNER_IMAGE:-}"
readonly RUNNER_PROVENANCE_INPUT_SHA256="${L401_RUNNER_PROVENANCE_INPUT_SHA256:-}"

OWNERSHIP_TOKEN="l401-$(date -u +%Y%m%d%H%M%S)-$$-${RANDOM}"
RESOURCE_LABEL="io.cdnca.test.owner=${OWNERSHIP_TOKEN}"
NETWORK_NAME="${OWNERSHIP_TOKEN}-network"
POSTGRES_CONTAINER="${OWNERSHIP_TOKEN}-postgres"
NATS_CONTAINER="${OWNERSHIP_TOKEN}-nats"
REDIS_CONTAINER="${OWNERSHIP_TOKEN}-redis"
RUNNER_CONTAINER="${OWNERSHIP_TOKEN}-runner"
readonly OWNERSHIP_TOKEN RESOURCE_LABEL NETWORK_NAME POSTGRES_CONTAINER NATS_CONTAINER REDIS_CONTAINER
readonly RUNNER_CONTAINER RUNNER_IMAGE

WORK_DIR=''
cleanup_complete=0

fail() {
  printf 'L401_BOOTSTRAP FAIL stage=%s\n' "$1" >&2
  exit 1
}

cleanup() {
  local status=${1:-$?} resource
  local -a containers=()
  trap - EXIT HUP INT TERM

  if command -v docker >/dev/null 2>&1; then
    while IFS= read -r resource; do
      [ -z "${resource}" ] || containers+=("${resource}")
    done < <(docker ps -aq --filter "label=${RESOURCE_LABEL}" 2>/dev/null || true)
    if [ "${#containers[@]}" -gt 0 ]; then
      docker rm -f -- "${containers[@]}" >/dev/null 2>&1 || status=1
    fi
    docker network rm "${NETWORK_NAME}" >/dev/null 2>&1 || true

    if [ -n "$(docker ps -aq --filter "label=${RESOURCE_LABEL}" 2>/dev/null || true)" ] ||
       [ -n "$(docker network ls -q --filter "label=${RESOURCE_LABEL}" 2>/dev/null || true)" ] ||
       [ -n "$(docker image ls -q --filter "label=${RESOURCE_LABEL}" 2>/dev/null || true)" ]; then
      printf 'L401_BOOTSTRAP cleanup=FAIL reason=labeled-resource-remains\n' >&2
      status=1
    else
      printf 'L401_BOOTSTRAP cleanup=PASS containers=0 networks=0 images=0 processes=0\n'
    fi
  fi

  if [ -n "${WORK_DIR}" ]; then
    case "${WORK_DIR}" in
      "${TMPDIR:-/tmp}"/cdnca-l401.*) rm -rf -- "${WORK_DIR}" ;;
      *)
        printf 'L401_BOOTSTRAP cleanup=FAIL reason=unsafe-work-dir\n' >&2
        status=1
        ;;
    esac
  fi
  cleanup_complete=1
  exit "${status}"
}

preflight_runner_image() {
  local labels

  [[ ${OPENRESTY_IMAGE} =~ ^openresty/openresty@sha256:[0-9a-f]{64}$ ]] || fail 'runtime-env-openresty-image'
  [[ ${OPENRESTY_VERSION} =~ ^[0-9]+(\.[0-9]+){3}$ ]] || fail 'runtime-env-openresty-version'
  [ -n "${RUNNER_IMAGE}" ] || fail 'missing-l401-runner-image'
  [[ ${RUNNER_IMAGE} =~ ^sha256:[0-9a-f]{64}$ || \
     ${RUNNER_IMAGE} =~ ^[[:alnum:]][[:alnum:].:_/-]*@sha256:[0-9a-f]{64}$ ]] || \
    fail 'runner-image-not-digest-pinned'
  [[ ${RUNNER_PROVENANCE_INPUT_SHA256} =~ ^[0-9a-f]{64}$ ]] || \
    fail 'runner-provenance-input-not-pinned'
  labels="$(docker image inspect --format '{{json .Config.Labels}}' "${RUNNER_IMAGE}" 2>/dev/null)" || \
    fail 'runner-image-not-prefetched'
  jq -e \
    --arg go_image "${GO_IMAGE}" \
    --arg openresty_image "${OPENRESTY_IMAGE}" \
    --arg openresty_version "${OPENRESTY_VERSION}" \
    --arg provenance "${RUNNER_PROVENANCE_INPUT_SHA256}" \
    '.["io.cdnca.l401.runner.contract"] == "v1" and
     .["io.cdnca.l401.runner.go-image"] == $go_image and
     .["io.cdnca.l401.runner.openresty-image"] == $openresty_image and
     .["io.cdnca.l401.runner.openresty-version"] == $openresty_version and
     .["io.cdnca.l401.runner.provenance-input-sha256"] == $provenance' \
    <<<"${labels}" >/dev/null || fail 'runner-image-contract'
}

trap 'cleanup "$?"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "${L401_BOOTSTRAP_STATIC_ONLY:-0}" = '1' ]; then
  printf 'L401_BOOTSTRAP_STATIC PASS\n'
  exit 0
fi

for command in bash chmod curl date docker id jq mktemp openssl sed sha256sum; do
  command -v "${command}" >/dev/null 2>&1 || fail "missing-command-${command}"
done
docker info >/dev/null 2>&1 || fail 'docker-daemon'
preflight_runner_image

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-l401.XXXXXX")"
chmod 0700 "${WORK_DIR}"
mkdir -p "${WORK_DIR}/home" "${WORK_DIR}/go" "${WORK_DIR}/nats" "${WORK_DIR}/runtime"
chmod 0700 "${WORK_DIR}/home" "${WORK_DIR}/go" "${WORK_DIR}/nats" "${WORK_DIR}/runtime"

write_stream_config() {
  local name=$1 payload=$2
  printf '%s\n' "${payload}" >"${WORK_DIR}/nats/${name}.json"
  chmod 0600 "${WORK_DIR}/nats/${name}.json"
}

write_stream_config AGENT_COMMANDS "$(jq -cn '{
  name:"AGENT_COMMANDS",
  subjects:["cdnca.agent.commands.*","cdnca.agent.commands.acme-http01.*",
    "cdnca.agent.commands.cache.*","cdnca.agent.commands.cache-dlq.*",
    "cdnca.agent.commands.upgrade.*","cdnca.agent.commands.drain.*",
    "cdnca.agent.commands.gateway-port.*"],
  retention:"workqueue",max_consumers:-1,max_msgs:-1,max_bytes:-1,discard:"new",
  max_age:0,max_msgs_per_subject:-1,max_msg_size:1048576,storage:"file",
  num_replicas:1,duplicate_window:120000000000
}')"
write_stream_config AGENT_DEPLOYMENT_STATUS "$(jq -cn '{
  name:"AGENT_DEPLOYMENT_STATUS",
  subjects:["cdnca.agent.deployment-status.*","cdnca.agent.deployment-status.generic-v2.*.*",
    "cdnca.agent.deployment-status.terminal-receipt.*.*",
    "cdnca.agent.deployment-status.terminal-receipt-confirmation.*.*",
    "cdnca.agent.deployment-status.terminal-receipt-confirmation-index.*",
    "cdnca.agent.deployment-status.acme-http01.*","cdnca.agent.deployment-status.cache.*","cdnca.agent.deployment-status.cache-dlq.*",
    "cdnca.agent.deployment-status.upgrade.*","cdnca.agent.deployment-status.upgrade-v2.*",
    "cdnca.agent.deployment-status.upgrade-proof.pending.*",
    "cdnca.agent.deployment-status.upgrade-proof.confirmed.*.*",
    "cdnca.agent.deployment-status.upgrade-proof.completed.*.*.*",
    "cdnca.agent.deployment-status.upgrade-proof.status.*.*",
    "cdnca.agent.deployment-status.drain.*","cdnca.agent.deployment-status.gateway-port.*"],
  retention:"limits",max_consumers:-1,max_msgs:-1,max_bytes:-1,discard:"old",
  max_age:0,max_msgs_per_subject:-1,max_msg_size:1048576,storage:"file",
  num_replicas:1,duplicate_window:120000000000
}')"
write_stream_config AGENT_HEARTBEATS "$(jq -cn '{
  name:"AGENT_HEARTBEATS",subjects:["cdnca.agent.heartbeats.*"],retention:"workqueue",
  max_consumers:-1,max_msgs:-1,max_bytes:-1,discard:"new",max_age:0,
  max_msgs_per_subject:-1,max_msg_size:1048576,storage:"file",num_replicas:1,
  duplicate_window:120000000000
}')"
write_stream_config NODE_MONITORING_COMMANDS "$(jq -cn '{
  name:"NODE_MONITORING_COMMANDS",subjects:["cdnca.agent.node-monitoring.commands.*"],
  retention:"workqueue",max_consumers:-1,max_msgs:-1,max_bytes:-1,discard:"new",
  max_age:0,max_msgs_per_subject:-1,max_msg_size:1048576,storage:"file",num_replicas:1,
  duplicate_window:120000000000
}')"
write_stream_config NODE_MONITORING_STATUS "$(jq -cn '{
  name:"NODE_MONITORING_STATUS",subjects:["cdnca.agent.node-monitoring.status.*"],
  retention:"workqueue",max_consumers:-1,max_msgs:-1,max_bytes:-1,discard:"new",
  max_age:0,max_msgs_per_subject:-1,max_msg_size:1048576,storage:"file",num_replicas:1,
  duplicate_window:120000000000
}')"
write_stream_config ANALYTICS_INGEST_V1 "$(jq -cn '{
  name:"ANALYTICS_INGEST_V1",subjects:["cdnca.analytics.ingest.v1.*"],retention:"workqueue",
  max_consumers:1,max_msgs:10000000,max_bytes:10737418240,discard:"new",max_age:0,
  max_msgs_per_subject:-1,max_msg_size:1048576,storage:"file",num_replicas:1,
  duplicate_window:600000000000
}')"
write_stream_config SECURITY_CC_COORDINATION_V1 "$(jq -cn '{
  name:"SECURITY_CC_COORDINATION_V1",subjects:["cdnca.security.cccoord.v1.*.*"],
  retention:"workqueue",max_consumers:1,max_msgs:2000000,max_bytes:2147483648,
  discard:"new",max_age:86400000000000,max_msgs_per_subject:-1,max_msg_size:1048576,
  storage:"file",num_replicas:1,duplicate_window:600000000000
}')"
write_stream_config L4_SESSIONS_INGEST_V1 "$(jq -cn '{
  name:"L4_SESSIONS_INGEST_V1",subjects:["cdnca.l4.sessions.v1.*.*.*"],retention:"workqueue",
  max_consumers:1,max_msgs:5000000,max_bytes:5368709120,discard:"new",
  max_age:2592000000000000,max_msgs_per_subject:-1,max_msg_size:1048576,
  storage:"file",num_replicas:1,duplicate_window:600000000000
}')"

cat >"${WORK_DIR}/runtime/entitlement.go" <<'GO'
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

type signer struct {
	id  string
	key ed25519.PrivateKey
}

func (s signer) KeyID() string { return s.id }
func (s signer) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(s.key, payload), nil
}

func main() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { panic(err) }
	now := time.Now().UTC()
	lease := entitlement.Lease{
		Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience,
		CustomerID: "l401-customer", InstallationID: os.Getenv("CONTROL_INSTALLATION_ID"),
		LicenseID: "l401-license", Serial: 1,
		NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(24*time.Hour).Unix(),
		GraceUntil: now.Add(48*time.Hour).Unix(),
		Version: entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "0.1.0"},
		Features: []entitlement.Feature{{Code: "sites.manage"}},
		Quotas: []entitlement.Quota{
			{Code: entitlement.QuotaDomainsCount, Limit: 10},
			{Code: entitlement.QuotaNodesCount, Limit: 10},
			{Code: entitlement.QuotaSitesCount, Limit: 10},
		},
	}
	signed, err := entitlement.Sign(context.Background(), lease, signer{id: "l401-entitlement", key: privateKey})
	if err != nil { panic(err) }
	bundle := struct {
		InstallationID string `json:"installation_id"`
		RevokedSerials []uint64 `json:"revoked_serials"`
		SignedLease entitlement.SignedLease `json:"signed_lease"`
	}{lease.InstallationID, []uint64{}, signed}
	trust := struct { Keys []struct {
		KeyID string `json:"key_id"`
		PublicKey string `json:"public_key"`
	} `json:"keys"` }{}
	trust.Keys = append(trust.Keys, struct {
		KeyID string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}{"l401-entitlement", base64.RawURLEncoding.EncodeToString(publicKey)})
	write("/work/secrets/entitlement-bundle.json", bundle)
	write("/work/secrets/entitlement-trust.json", trust)
}

func write(path string, value any) {
	encoded, err := json.Marshal(value)
	if err != nil { panic(err) }
	if err := os.WriteFile(path, encoded, 0o600); err != nil { panic(err) }
}
GO
chmod 0600 "${WORK_DIR}/runtime/entitlement.go"

cat >"${WORK_DIR}/runtime/nats-precheck.go" <<'GO'
package main

import (
	"fmt"
	"os"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

func main() {
	if len(os.Args) != 5 { panic("usage: nats-precheck NODE OLD_DEPLOYMENT NEW_DEPLOYMENT NATS_URL") }
	nodeID, oldID, newID, natsURL := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	connection, err := nats.Connect(natsURL, nats.MaxReconnects(0))
	if err != nil { panic(err) }
	defer connection.Close()
	js, err := connection.JetStream(nats.MaxWait(nats.DefaultTimeout))
	if err != nil { panic(err) }
	info, err := js.StreamInfo("AGENT_COMMANDS")
	if err != nil || info.State.Msgs < 2 || info.State.Consumers != 0 { panic("commands are not queued without an Agent consumer") }
	wanted := map[string]uint64{oldID: 0, newID: 0}
	for sequence := info.State.FirstSeq; sequence <= info.State.LastSeq; sequence++ {
		message, getErr := js.GetMsg("AGENT_COMMANDS", sequence)
		if getErr != nil { continue }
		command := new(agentv1.DeploymentCommand)
		if proto.Unmarshal(message.Data, command) != nil || command.GetNodeId() != nodeID { continue }
		if _, ok := wanted[command.GetDeploymentId()]; ok { wanted[command.GetDeploymentId()] = sequence }
	}
	if wanted[oldID] == 0 || wanted[newID] == 0 || wanted[oldID] >= wanted[newID] {
		panic("Control did not publish exact ordered old/new deployment commands")
	}
	fmt.Printf("L401_NATS_PREFLIGHT PASS old_sequence=%d new_sequence=%d consumers=0 ack_pending=0\n", wanted[oldID], wanted[newID])
}
GO
chmod 0600 "${WORK_DIR}/runtime/nats-precheck.go"

cat >"${WORK_DIR}/bootstrap-runtime.sh" <<'RUNTIME'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly REPO_ROOT='/repo'
readonly WORK_DIR='/work'
OPENRESTY_VERSION="$(sed -n 's/^OPENRESTY_VERSION=//p' "${REPO_ROOT}/edge/openresty/runtime.env")"
readonly OPENRESTY_VERSION
readonly DATABASE_URL="postgres://cdnca:${POSTGRES_PASSWORD}@${POSTGRES_CONTAINER}:5432/cdnca?sslmode=disable"
readonly NATS_URL="nats://${NATS_CONTAINER}:4222"
readonly REDIS_URL="redis://${REDIS_CONTAINER}:6379/0"
readonly CONTROL_INSTALLATION_ID='70000000-0000-4000-8000-000000000401'
readonly TENANT_ID='10000000-0000-4000-8000-000000000401'
readonly TENANT_SCOPE_ID='11000000-0000-4000-8000-000000000401'
readonly NODE_ID='30000000-0000-4000-8000-000000000401'
readonly SITE_ID='20000000-0000-4000-8000-000000000401'
readonly TOKEN_ID='71000000-0000-4000-8000-000000000401'
readonly CA_EPOCH_ID='72000000-0000-4000-8000-000000000401'
readonly CA_REQUEST_ID='73000000-0000-4000-8000-000000000401'

control_pid=''
gateway_pid=''

runtime_fail() {
  printf 'L401_RUNTIME FAIL stage=%s\n' "$1" >&2
  exit 1
}

runtime_cleanup() {
  local status=${1:-$?} pid
  trap - EXIT HUP INT TERM
  for pid in "${gateway_pid}" "${control_pid}"; do
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
      kill -TERM "${pid}" 2>/dev/null || true
    fi
  done
  for pid in "${gateway_pid}" "${control_pid}"; do
    [ -z "${pid}" ] || wait "${pid}" 2>/dev/null || true
  done
  exit "${status}"
}

trap 'runtime_cleanup "$?"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for command in bash base64 cat chmod curl date go jq openssl psql sed seq sha256sum sleep tr; do
  command -v "${command}" >/dev/null 2>&1 || runtime_fail "runner-missing-command-${command}"
done
[ "$(go env GOVERSION)" = 'go1.27.3' ] || runtime_fail 'runner-go-version'
actual_openresty="$(/usr/local/openresty/bin/openresty -V 2>&1 | sed -n 's/^nginx version: openresty\///p')"
[[ ${OPENRESTY_VERSION} =~ ^[0-9]+(\.[0-9]+){3}$ ]] || runtime_fail 'runtime-env-openresty-version'
[ "${actual_openresty}" = "${OPENRESTY_VERSION}" ] || runtime_fail 'runner-openresty-version'

mkdir -p "${WORK_DIR}/bin" "${WORK_DIR}/certs" "${WORK_DIR}/secrets" \
  "${WORK_DIR}/edge-identity" "${WORK_DIR}/edge-state" "${WORK_DIR}/edge-journal" \
  "${WORK_DIR}/edge-certificates"
chmod 0700 "${WORK_DIR}/bin" "${WORK_DIR}/certs" "${WORK_DIR}/secrets" \
  "${WORK_DIR}/edge-identity" "${WORK_DIR}/edge-state" "${WORK_DIR}/edge-journal" \
  "${WORK_DIR}/edge-certificates"

(
  cd "${REPO_ROOT}/services/control-api"
  GOWORK=off go build -trimpath -o "${WORK_DIR}/bin/control-api" ./cmd/control-api
)
(
  cd "${REPO_ROOT}/services/agent-gateway"
  GOWORK=off go build -trimpath -o "${WORK_DIR}/bin/agent-gateway" ./cmd/agent-gateway
)
(
  cd "${REPO_ROOT}/agents/edge-agent"
  GOWORK=off go build -trimpath -o "${WORK_DIR}/bin/edge-agent" ./cmd/edge-agent
)

DATABASE_URL="${DATABASE_URL}" "${WORK_DIR}/bin/control-api" migrate up

bootstrap_password="l401_$(openssl rand -hex 24)"
DATABASE_URL="${DATABASE_URL}" BOOTSTRAP_PASSWORD="${bootstrap_password}" \
  "${WORK_DIR}/bin/control-api" bootstrap-user \
  --username l401_admin --display-name 'L4-01 Administrator'

CONTROL_INSTALLATION_ID="${CONTROL_INSTALLATION_ID}" \
  go run "${WORK_DIR}/runtime/entitlement.go"
chmod 0600 "${WORK_DIR}/secrets/entitlement-bundle.json" "${WORK_DIR}/secrets/entitlement-trust.json"
DATABASE_URL="${DATABASE_URL}" "${WORK_DIR}/bin/control-api" install-entitlement \
  --bundle "${WORK_DIR}/secrets/entitlement-bundle.json" \
  --trusted-keys "${WORK_DIR}/secrets/entitlement-trust.json"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=CDNCA L4-01 E2E CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "${WORK_DIR}/certs/ca.key" -out "${WORK_DIR}/certs/ca.crt" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "${WORK_DIR}/certs/node-ca.key" >/dev/null 2>&1
openssl req -new -x509 -days 2 -subj '/CN=CDNCA L4-01 Node CA' \
  -key "${WORK_DIR}/certs/node-ca.key" -out "${WORK_DIR}/certs/node-ca.crt" \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=localhost' \
  -keyout "${WORK_DIR}/certs/server.key" -out "${WORK_DIR}/certs/server.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' \
  >"${WORK_DIR}/certs/server.ext"
openssl x509 -req -days 2 -in "${WORK_DIR}/certs/server.csr" \
  -CA "${WORK_DIR}/certs/ca.crt" -CAkey "${WORK_DIR}/certs/ca.key" -CAcreateserial \
  -extfile "${WORK_DIR}/certs/server.ext" -out "${WORK_DIR}/certs/server.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=agent-gateway' \
  -keyout "${WORK_DIR}/certs/gateway.key" -out "${WORK_DIR}/certs/gateway.csr" >/dev/null 2>&1
printf 'subjectAltName=URI:spiffe://cdnca/l401/gateway\nextendedKeyUsage=clientAuth\n' \
  >"${WORK_DIR}/certs/gateway.ext"
openssl x509 -req -days 2 -in "${WORK_DIR}/certs/gateway.csr" \
  -CA "${WORK_DIR}/certs/ca.crt" -CAkey "${WORK_DIR}/certs/ca.key" -CAcreateserial \
  -extfile "${WORK_DIR}/certs/gateway.ext" -out "${WORK_DIR}/certs/gateway.crt" >/dev/null 2>&1
openssl genpkey -algorithm Ed25519 -out "${WORK_DIR}/secrets/edge-signing-key.pem"
openssl pkey -in "${WORK_DIR}/secrets/edge-signing-key.pem" -pubout \
  -out "${WORK_DIR}/secrets/edge-signing-public.pem"
jq -n --rawfile key "${WORK_DIR}/secrets/edge-signing-public.pem" \
  '{version:1,keys:[{key_id:"l401-artifact",public_key_pem:$key}]}' \
  >"${WORK_DIR}/secrets/artifact-trust.json"
chmod 0600 "${WORK_DIR}/certs/"*.key "${WORK_DIR}/secrets/"*

enrollment_token="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
enrollment_sha="$(printf '%s' "${enrollment_token}" | sha256sum | awk '{print $1}')"
printf '%s\n' "${enrollment_token}" >"${WORK_DIR}/secrets/enrollment-token"
printf 'l401-machine-id\n' >"${WORK_DIR}/secrets/machine-id"
chmod 0600 "${WORK_DIR}/secrets/enrollment-token" "${WORK_DIR}/secrets/machine-id"

openssl x509 -in "${WORK_DIR}/certs/node-ca.crt" -outform DER \
  -out "${WORK_DIR}/certs/node-ca.der"
openssl x509 -in "${WORK_DIR}/certs/node-ca.crt" -pubkey -noout \
  >"${WORK_DIR}/certs/node-ca-public.pem"
openssl pkey -pubin -in "${WORK_DIR}/certs/node-ca-public.pem" -outform DER \
  -out "${WORK_DIR}/certs/node-ca-public.der"
node_ca_cert_sha="$(sha256sum "${WORK_DIR}/certs/node-ca.der" | awk '{print $1}')"
node_ca_public_sha="$(sha256sum "${WORK_DIR}/certs/node-ca-public.der" | awk '{print $1}')"
node_ca_base64="$(base64 -w0 <"${WORK_DIR}/certs/node-ca.crt")"

platform_user_id="$(psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -qAtX \
  -c "SELECT id FROM users WHERE username='l401_admin'")"
platform_scope_id="$(psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -qAtX \
  -c "SELECT membership.scope_id FROM memberships membership JOIN access_scopes scope ON scope.id=membership.scope_id WHERE membership.user_id='${platform_user_id}' AND scope.kind='platform'")"
[ -n "${platform_user_id}" ] && [ -n "${platform_scope_id}" ] || runtime_fail 'bootstrap-user-readback'

psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 <<SQL
BEGIN;
INSERT INTO tenants(id,display_name) VALUES('${TENANT_ID}','L4-01 process tenant');
INSERT INTO access_scopes(id,kind,tenant_id) VALUES('${TENANT_SCOPE_ID}','tenant','${TENANT_ID}');
INSERT INTO memberships(scope_id,user_id) VALUES('${TENANT_SCOPE_ID}','${platform_user_id}');
INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id)
  VALUES('${NODE_ID}','${TENANT_SCOPE_ID}','l401-edge','active','${platform_user_id}');
INSERT INTO sites(id,scope_id,owner_user_id,domain,http_ports,origins,origin_hosts,
  created_by_user_id,updated_by_user_id)
  VALUES('${SITE_ID}','${TENANT_SCOPE_ID}','${platform_user_id}','l401.example.test',
    ARRAY['18081'],ARRAY['192.0.2.40:8080'],ARRAY['192.0.2.40'],
    '${platform_user_id}','${platform_user_id}');
INSERT INTO site_origin_pools(site_id,balance_method,failover_tries,connect_timeout_ms,read_timeout_ms)
  VALUES('${SITE_ID}','round_robin',1,1000,5000);
INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
  VALUES('${SITE_ID}',1,'192.0.2.40',8080,1,true);
INSERT INTO node_enrollment_tokens(id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at)
  VALUES('${TOKEN_ID}','${NODE_ID}','initial_enrollment',decode('${enrollment_sha}','hex'),
    '${platform_user_id}',clock_timestamp(),clock_timestamp()+interval '1 hour');
INSERT INTO node_ca_key_epochs(id,installation_id,epoch,key_id,ca_certificate_pem,
  ca_certificate_sha256,public_key_sha256,not_before,not_after,status,request_id,
  request_digest,created_by_scope_id,created_by_user_id,created_at)
  VALUES('${CA_EPOCH_ID}','${CONTROL_INSTALLATION_ID}',1,'l401-node-ca',
    decode('${node_ca_base64}','base64'),decode('${node_ca_cert_sha}','hex'),
    decode('${node_ca_public_sha}','hex'),clock_timestamp()-interval '5 minutes',
    clock_timestamp()+interval '47 hours','active','${CA_REQUEST_ID}',
    decode(repeat('41',32),'hex'),'${TENANT_SCOPE_ID}','${platform_user_id}',clock_timestamp());
COMMIT;
SQL

control_http_port=18040
control_grpc_port=19040
gateway_enrollment_port=19440
gateway_agent_port=19441
gateway_health_port=19442
access_secret="$(openssl rand -hex 32)"
api_pepper="$(openssl rand -base64 32 | tr -d '\n')"
dns_key="$(openssl rand -base64 32 | tr -d '\n')"
impersonation_key="$(openssl rand -base64 32 | tr -d '\n')"
mfa_key="$(openssl rand -base64 32 | tr -d '\n')"
cursor_key="$(openssl rand -base64 32 | tr -d '\n')"
edge_cursor_key="$(openssl rand -base64 32 | tr -d '\n')"

env \
  "DATABASE_URL=${DATABASE_URL}" \
  "CONTROL_INSTALLATION_ID=${CONTROL_INSTALLATION_ID}" \
  'CONTROL_VERSION=0.1.0' \
  "HTTP_ADDR=127.0.0.1:${control_http_port}" \
  "CONTROL_INTERNAL_GRPC_ADDR=127.0.0.1:${control_grpc_port}" \
  "ACCESS_TOKEN_SECRET=${access_secret}" \
  'API_KEY_PEPPER_VERSION=legacy-v1' "API_KEY_PEPPER_BASE64=${api_pepper}" \
  "IMPERSONATION_HMAC_KEY_BASE64=${impersonation_key}" \
  'MFA_ENABLED=true' 'MFA_ENCRYPTION_ACTIVE_KEY_ID=l401' \
  "MFA_ENCRYPTION_KEYS_JSON={\"l401\":\"${mfa_key}\"}" \
  'DNS_CREDENTIAL_KEY_ID=l401' "DNS_CREDENTIAL_KEY_BASE64=${dns_key}" \
  "OBSERVABILITY_LOG_CURSOR_KEY_BASE64=${cursor_key}" \
  'ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID=l401' \
  "ANALYTICS_LOGS_CURSOR_KEYS_JSON={\"l401\":\"${cursor_key}\"}" \
  "ENTITLEMENT_TRUSTED_KEYS_FILE=${WORK_DIR}/secrets/entitlement-trust.json" \
  'EDGE_PUBLISH_RUNTIME_ENABLED=true' \
  'EDGE_PUBLISH_CURSOR_ACTIVE_KEY_ID=l401' \
  "EDGE_PUBLISH_CURSOR_KEYS_JSON={\"l401\":\"${edge_cursor_key}\"}" \
  'EDGE_PUBLISH_SIGNING_KEY_ID=l401-artifact' \
  "EDGE_PUBLISH_SIGNING_PRIVATE_KEY_FILE=${WORK_DIR}/secrets/edge-signing-key.pem" \
  "EDGE_DEPLOYMENT_NATS_URL=${NATS_URL}" \
  'EDGE_OUTBOX_POLL_INTERVAL=50ms' \
  "CONTROL_INTERNAL_SERVER_CERT_FILE=${WORK_DIR}/certs/server.crt" \
  "CONTROL_INTERNAL_SERVER_PRIVATE_KEY_FILE=${WORK_DIR}/certs/server.key" \
  "CONTROL_INTERNAL_GATEWAY_CLIENT_CA_FILE=${WORK_DIR}/certs/ca.crt" \
  'CONTROL_INTERNAL_GATEWAY_WORKLOAD_URI_SAN=spiffe://cdnca/l401/gateway' \
  "NODE_CA_CERTIFICATE_CHAIN_FILE=${WORK_DIR}/certs/node-ca.crt" \
  "NODE_CA_PRIVATE_KEY_FILE=${WORK_DIR}/certs/node-ca.key" \
  'ACCOUNT_RECOVERY_ENABLED=false' 'ACCOUNT_REGISTRATION_ENABLED=false' \
  'ACME_RUNTIME_ENABLED=false' 'ANALYTICS_CONNECTIONS_RUNTIME_ENABLED=false' \
  'ANALYTICS_GEO_ARTIFACT_ENABLED=false' 'ANALYTICS_QUERY_ENABLED=false' \
  'ANALYTICS_REALTIME_RUNTIME_ENABLED=false' 'ANNOUNCEMENT_ENABLED=false' \
  'CACHE_CONTROL_RUNTIME_ENABLED=false' 'CHALLENGE_POLICY_RUNTIME_ENABLED=false' \
  'CONTROL_UPGRADE_PLAN_WRITER_ENABLED=false' 'CONTROL_UPGRADE_RUNTIME_ENABLED=false' \
  'CONTROL_UPGRADE_SYSTEMD_PLAN_SOURCE_ENABLED=false' 'CUSTOM_RBAC_RUNTIME_ENABLED=false' \
  'DNS_RECONCILE_ENABLED=false' 'EDGE_AUTOMATIC_PUBLICATION_ENABLED=false' \
  'ORIGIN_AUTH_RUNTIME_ENABLED=false' 'CDNCA_SECURITY_ACTIVATION_ENABLED=false' \
  'ERROR_PAGE_RUNTIME_ENABLED=false' 'HTTP_POLICY_RUNTIME_ENABLED=false' \
  'IDENTITY_VERIFICATION_RUNTIME_ENABLED=false' 'JA4_BLOCK_RUNTIME_ENABLED=false' \
  'JOB_QUERY_ENABLED=false' 'NODE_PORT_TRANSITION_RUNTIME_ENABLED=false' \
  'NODE_PRESENCE_NATS_URL=' 'NODE_PRESENCE_REDIS_URL=' \
  'NODE_SCHEDULING_RUNTIME_ENABLED=false' 'NOTIFICATION_RUNTIME_ENABLED=false' \
  'PACKAGE_COMMERCE_RUNTIME_ENABLED=false' 'PACKAGE_COMMERCE_WORKER_ENABLED=false' \
  'PACKAGE_CYCLE_RUNTIME_ENABLED=false' 'PACKAGE_MONITOR_HTTP_ENABLED=false' \
  'PACKAGE_MONITOR_RUNTIME_ENABLED=false' 'PACKAGE_PERIOD_RESET_RUNTIME_ENABLED=false' \
  'PACKAGE_USAGE_RUNTIME_ENABLED=false' 'PLUGIN_WEBHOOK_RUNTIME_ENABLED=false' \
  'PROMOTION_HTTP_ENABLED=false' 'PAYMENT_CHANNELS_ENABLED=false' \
  'SIGNER_REVOCATION_CONSUMER_ENABLED=false' \
  'SITE_STATUS_RECOVERY_RUNTIME_ENABLED=false' 'SYSTEM_CONFIGURATION_RUNTIME_ENABLED=false' \
  'TRAFFIC_PACKAGE_RUNTIME_ENABLED=false' 'TRAFFIC_PACKAGE_WORKLOAD_RUNTIME_ENABLED=false' \
  'URL_AUTH_POLICY_RUNTIME_ENABLED=false' 'ANALYTICS_INGEST_ENABLED=false' \
  'SHUTDOWN_PERIOD=10s' \
  "${WORK_DIR}/bin/control-api" serve >"${WORK_DIR}/control.log" 2>&1 &
control_pid=$!

for _ in $(seq 1 100); do
  kill -0 "${control_pid}" 2>/dev/null || runtime_fail 'control-exited'
  if curl --silent --fail "http://127.0.0.1:${control_http_port}/health/ready" >/dev/null 2>&1; then break; fi
  sleep 0.1
done
curl --silent --fail "http://127.0.0.1:${control_http_port}/health/ready" >/dev/null || runtime_fail 'control-readiness'

env \
  "CDNCA_GATEWAY_ENROLLMENT_ADDR=127.0.0.1:${gateway_enrollment_port}" \
  "CDNCA_GATEWAY_AGENT_ADDR=127.0.0.1:${gateway_agent_port}" \
  "CDNCA_GATEWAY_HEALTH_ADDR=127.0.0.1:${gateway_health_port}" \
  'CDNCA_GATEWAY_INSTANCE_ID=70000000-0000-4000-8000-000000000402' \
  'CDNCA_GATEWAY_VERSION=l401-e2e' \
  "CDNCA_GATEWAY_TLS_CERT_FILE=${WORK_DIR}/certs/server.crt" \
  "CDNCA_GATEWAY_TLS_KEY_FILE=${WORK_DIR}/certs/server.key" \
  "CDNCA_GATEWAY_AGENT_CLIENT_CA_FILE=${WORK_DIR}/certs/node-ca.crt" \
  "CDNCA_CONTROL_ADDRESS=127.0.0.1:${control_grpc_port}" \
  'CDNCA_CONTROL_SERVER_NAME=localhost' \
  "CDNCA_CONTROL_CLIENT_CERT_FILE=${WORK_DIR}/certs/gateway.crt" \
  "CDNCA_CONTROL_CLIENT_KEY_FILE=${WORK_DIR}/certs/gateway.key" \
  "CDNCA_CONTROL_SERVER_CA_FILE=${WORK_DIR}/certs/ca.crt" \
  'CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN=spiffe://cdnca/l401/gateway' \
  "CDNCA_REDIS_URL=${REDIS_URL}" "CDNCA_NATS_URL=${NATS_URL}" \
  "CDNCA_TELEMETRY_NATS_URL=${NATS_URL}" \
  'CDNCA_GATEWAY_STARTUP_TIMEOUT=5s' 'CDNCA_GATEWAY_SHUTDOWN_TIMEOUT=10s' \
  "${WORK_DIR}/bin/agent-gateway" >"${WORK_DIR}/gateway.log" 2>&1 &
gateway_pid=$!

for _ in $(seq 1 100); do
  kill -0 "${gateway_pid}" 2>/dev/null || runtime_fail 'gateway-exited'
  if curl --silent --fail "http://127.0.0.1:${gateway_health_port}/health/live" >/dev/null 2>&1; then break; fi
  sleep 0.1
done
curl --silent --fail "http://127.0.0.1:${gateway_health_port}/health/live" >/dev/null || runtime_fail 'gateway-readiness'

"${WORK_DIR}/bin/edge-agent" enroll \
  --gateway-address "127.0.0.1:${gateway_enrollment_port}" \
  --gateway-server-name localhost \
  --gateway-root-ca-file "${WORK_DIR}/certs/ca.crt" \
  --identity-dir "${WORK_DIR}/edge-identity" \
  --machine-id-file "${WORK_DIR}/secrets/machine-id" \
  --token-file "${WORK_DIR}/secrets/enrollment-token" \
  --openresty-version "${OPENRESTY_VERSION}" --timeout 20s \
  >"${WORK_DIR}/edge-enrollment.json"

jq -n \
  --arg identity "${WORK_DIR}/edge-identity" \
  --arg trust "${WORK_DIR}/secrets/artifact-trust.json" \
  --arg deployment "${WORK_DIR}/edge-state" \
  --arg journal "${WORK_DIR}/edge-journal" \
  --arg gateway "127.0.0.1:${gateway_agent_port}" \
  --arg ca "${WORK_DIR}/certs/ca.crt" \
  --arg certificates "${WORK_DIR}/edge-certificates" \
  --arg openresty_version "${OPENRESTY_VERSION}" \
  '{version:2,identity_dir:$identity,artifact_trust_file:$trust,deployment_root:$deployment,
    journal_dir:$journal,gateway:{address:$gateway,server_name:"localhost",root_ca_file:$ca},
    openresty:{binary:"/usr/local/openresty/bin/openresty",config_file:"nginx.conf",
      health_url:"http://127.0.0.1:18080/healthz",version:$openresty_version},
    certificate_runtime:{state_root:$certificates,listen_address:"127.0.0.1",listen_port:18443},
    limits:{max_command_bytes:1048576,max_status_bytes:262144,max_artifact_bytes:134217728,
      max_decompressed_bytes:134217728,max_artifact_chunk_bytes:1048576,max_active_deployments:8,
      command_queue_size:8,max_files:4096,max_file_bytes:16777216,max_total_bytes:134217728,
      retain_releases:5},
    timeouts:{handshake:"10s",artifact_fetch:"2m",initial_backoff:"250ms",maximum_backoff:"5s",
      precheck:"15s",reload:"15s",health:"30s",health_interval:"500ms",health_request:"2s"}}' \
  >"${WORK_DIR}/secrets/edge-agent.json"
chmod 0600 "${WORK_DIR}/secrets/edge-agent.json"

login_body="$(jq -cn --arg password "${bootstrap_password}" --arg scope "${platform_scope_id}" \
  '{username:"l401_admin",password:$password,scope_id:$scope}')"
curl --silent --show-error --fail-with-body \
  -H 'Content-Type: application/json' --data-binary "${login_body}" \
  "http://127.0.0.1:${control_http_port}/v1/auth/login" >"${WORK_DIR}/login.json"
jq -er '.access_token' "${WORK_DIR}/login.json" >"${WORK_DIR}/secrets/control-bearer-token"
chmod 0600 "${WORK_DIR}/secrets/control-bearer-token"
bearer_token="$(<"${WORK_DIR}/secrets/control-bearer-token")"

uuid() { cat /proc/sys/kernel/random/uuid; }
traceparent() { printf '00-%s-%s-01\n' "$(openssl rand -hex 16)" "$(openssl rand -hex 8)"; }

publish() {
  local source_revision=$1 idempotency_key=$2 output=$3 deadline request_id correlation_id
  deadline="$(date -u -d '+10 minutes' +%Y-%m-%dT%H:%M:%SZ)"
  request_id="$(uuid)"
  correlation_id="$(uuid)"
  jq -cn --arg scope "${TENANT_SCOPE_ID}" --arg node "${NODE_ID}" \
    --arg deadline "${deadline}" --argjson revision "${source_revision}" \
    '{configuration_scope_id:$scope,expected_source_revision:$revision,
      target:{kind:"nodes",node_ids:[$node]},
      health_check:{activation_timeout_ms:60000,observation_window_ms:5000,
        required_consecutive_successes:2},max_attempts:3,deadline:$deadline,
      rollout:{strategy:"all_at_once",canary_size:0,batch_size:1,failure_threshold:1,
        auto_start:true}}' >"${WORK_DIR}/publish-request.json"
  curl --silent --show-error --fail-with-body \
    -H 'Content-Type: application/json' -H "Authorization: Bearer ${bearer_token}" \
    -H "Idempotency-Key: ${idempotency_key}" -H "X-Request-ID: ${request_id}" \
    -H "X-Correlation-ID: ${correlation_id}" -H "Traceparent: $(traceparent)" \
    --data-binary @"${WORK_DIR}/publish-request.json" \
    "http://127.0.0.1:${control_http_port}/v1/admin/site-publications" >"${output}"
}

deployment_for_rollout() {
  local rollout_id=$1 output=$2
  for _ in $(seq 1 100); do
    curl --silent --show-error --fail-with-body \
      -H "Authorization: Bearer ${bearer_token}" \
      "http://127.0.0.1:${control_http_port}/v1/admin/site-rollouts/${rollout_id}/deployments?scope_id=${TENANT_SCOPE_ID}&limit=100" \
      >"${output}"
    if jq -e --arg node "${NODE_ID}" '.items | length == 1 and .[0].node_id == $node' "${output}" >/dev/null; then
      jq -er '.items[0].id' "${output}"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

old_revision="$(psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -qAtX \
  -c "SELECT source_revision FROM edge_configuration_scopes WHERE scope_id='${TENANT_SCOPE_ID}'")"
publish "${old_revision}" 'l401-publication-old' "${WORK_DIR}/old-publication.json"
old_publication_id="$(jq -er '.id' "${WORK_DIR}/old-publication.json")"
old_rollout_id="$(jq -er '.rollout_id' "${WORK_DIR}/old-publication.json")"
old_deployment_id="$(deployment_for_rollout "${old_rollout_id}" "${WORK_DIR}/old-deployments.json")" || \
  runtime_fail 'old-deployment'

psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 \
  -c "UPDATE sites SET cname='new.l401.example.test',updated_by_user_id='${platform_user_id}',updated_at=clock_timestamp() WHERE id='${SITE_ID}'" >/dev/null
new_revision="$(psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -qAtX \
  -c "SELECT source_revision FROM edge_configuration_scopes WHERE scope_id='${TENANT_SCOPE_ID}'")"
[ "${new_revision}" -gt "${old_revision}" ] || runtime_fail 'source-revision-order'
publish "${new_revision}" 'l401-publication-new' "${WORK_DIR}/new-publication.json"
new_publication_id="$(jq -er '.id' "${WORK_DIR}/new-publication.json")"
new_rollout_id="$(jq -er '.rollout_id' "${WORK_DIR}/new-publication.json")"
new_deployment_id="$(deployment_for_rollout "${new_rollout_id}" "${WORK_DIR}/new-deployments.json")" || \
  runtime_fail 'new-deployment'

[ "${old_publication_id}" != "${new_publication_id}" ] && \
  [ "${old_rollout_id}" != "${new_rollout_id}" ] && \
  [ "${old_deployment_id}" != "${new_deployment_id}" ] || runtime_fail 'ordered-identity-distinctness'

for _ in $(seq 1 200); do
  published_count="$(psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -qAtX -c \
    "SELECT count(*) FROM edge_command_outbox WHERE deployment_id IN ('${old_deployment_id}','${new_deployment_id}') AND status='published'")"
  [ "${published_count}" = '2' ] && break
  sleep 0.1
done
[ "${published_count}" = '2' ] || runtime_fail 'control-outbox-publication'

(
  cd "${REPO_ROOT}/services/agent-gateway"
  GOWORK=off go run "${WORK_DIR}/runtime/nats-precheck.go" \
    "${NODE_ID}" "${old_deployment_id}" "${new_deployment_id}" "${NATS_URL}"
)

L401_PROCESS_E2E=1 \
L401_NATS_URL="${NATS_URL}" \
L401_CONTROL_BASE_URL="http://127.0.0.1:${control_http_port}" \
L401_CONTROL_BEARER_TOKEN_FILE="${WORK_DIR}/secrets/control-bearer-token" \
L401_CONTROL_SCOPE_ID="${TENANT_SCOPE_ID}" \
L401_NODE_ID="${NODE_ID}" \
L401_OLD_ROLLOUT_ID="${old_rollout_id}" \
L401_NEW_ROLLOUT_ID="${new_rollout_id}" \
L401_OLD_DEPLOYMENT_ID="${old_deployment_id}" \
L401_NEW_DEPLOYMENT_ID="${new_deployment_id}" \
L401_AGENT_BINARY="${WORK_DIR}/bin/edge-agent" \
L401_AGENT_CONFIG_FILE="${WORK_DIR}/secrets/edge-agent.json" \
GOWORK=off go test -C "${REPO_ROOT}/services/agent-gateway" \
  -run '^TestL401GatewayProcessE2E$' -count=1 -timeout=5m .

printf 'L401_BOOTSTRAP PASS old_rollout=%s new_rollout=%s\n' "${old_rollout_id}" "${new_rollout_id}"
RUNTIME
chmod 0700 "${WORK_DIR}/bootstrap-runtime.sh"

docker network create --label "${RESOURCE_LABEL}" "${NETWORK_NAME}" >/dev/null || fail 'network-create'
postgres_password="$(openssl rand -hex 24)"
readonly postgres_password
docker run -d --name "${POSTGRES_CONTAINER}" --network "${NETWORK_NAME}" \
  --label "${RESOURCE_LABEL}" -e POSTGRES_USER=cdnca -e POSTGRES_PASSWORD="${postgres_password}" \
  -e POSTGRES_DB=cdnca "${POSTGRES_IMAGE}" >/dev/null || fail 'postgres-start'
docker run -d --name "${NATS_CONTAINER}" --network "${NETWORK_NAME}" \
  --label "${RESOURCE_LABEL}" "${NATS_IMAGE}" -js >/dev/null || fail 'nats-start'
docker run -d --name "${REDIS_CONTAINER}" --network "${NETWORK_NAME}" \
  --label "${RESOURCE_LABEL}" "${REDIS_IMAGE}" redis-server --save '' --appendonly no >/dev/null || \
  fail 'redis-start'

for _ in {1..100}; do
  if docker exec "${POSTGRES_CONTAINER}" pg_isready -U cdnca -d cdnca >/dev/null 2>&1; then break; fi
  sleep 0.1
done
docker exec "${POSTGRES_CONTAINER}" pg_isready -U cdnca -d cdnca >/dev/null || fail 'postgres-readiness'
for _ in {1..100}; do
  if docker exec "${REDIS_CONTAINER}" redis-cli ping 2>/dev/null | grep -qx PONG; then break; fi
  sleep 0.1
done
docker exec "${REDIS_CONTAINER}" redis-cli ping 2>/dev/null | grep -qx PONG || fail 'redis-readiness'

for stream_config in "${WORK_DIR}/nats/"*.json; do
  docker run --rm --network "${NETWORK_NAME}" --label "${RESOURCE_LABEL}" \
    -v "${stream_config}:/config/stream.json:ro" "${NATS_BOX_IMAGE}" \
    nats --server "nats://${NATS_CONTAINER}:4222" stream add --config /config/stream.json >/dev/null || \
    fail "nats-stream-$(basename "${stream_config}" .json)"
done

docker run --pull=never --name "${RUNNER_CONTAINER}" --network "${NETWORK_NAME}" \
  --label "${RESOURCE_LABEL}" --entrypoint /bin/bash --user "$(id -u):$(id -g)" \
  -e 'HOME=/work/home' -e 'GOPATH=/work/go' \
  -e "POSTGRES_PASSWORD=${postgres_password}" \
  -e "POSTGRES_CONTAINER=${POSTGRES_CONTAINER}" \
  -e "NATS_CONTAINER=${NATS_CONTAINER}" \
  -e "REDIS_CONTAINER=${REDIS_CONTAINER}" \
  -v "${REPO_ROOT}:/repo:ro" -v "${WORK_DIR}:/work" \
  "${RUNNER_IMAGE}" /work/bootstrap-runtime.sh || fail 'runner'

[ "${cleanup_complete}" -eq 0 ] || fail 'cleanup-ran-early'
