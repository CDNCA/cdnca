#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'local stack: %s\n' "$1" >&2
  exit 1
}

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
project_name="cdnca-local-${UID}"
state_parent=${XDG_STATE_HOME:-${TMPDIR:-/tmp}}
state_dir=${LOCAL_STACK_STATE_DIR:-${state_parent%/}/cdnca-local-stack-${UID}}
env_file=${LOCAL_STACK_ENV_FILE:-${repo_root}/infra/env/development.env}
case "$env_file" in /*) ;; *) env_file="${repo_root}/${env_file}" ;; esac
runtime_env="${state_dir}/runtime.env"
ready_marker="${state_dir}/.ready-v1"
port_override_keys=(
  POSTGRES_PORT REDIS_PORT CLICKHOUSE_HTTP_PORT CLICKHOUSE_NATIVE_PORT
  NATS_CLIENT_PORT NATS_MONITOR_PORT EDGE_NATS_PORT
  MAILPIT_UI_PORT MAILPIT_SMTP_PORT
  CONTROL_API_PORT AGENT_GATEWAY_AGENT_PORT AGENT_GATEWAY_ENROLLMENT_PORT
  WEB_PORT
)

[ -f "$env_file" ] || fail "environment file not found: ${env_file}"
case "$state_dir" in /*) ;; *) fail 'LOCAL_STACK_STATE_DIR must be an absolute path' ;; esac
case "$state_dir" in
  /|"$repo_root"|"$repo_root"/*) fail 'LOCAL_STACK_STATE_DIR must be outside the repository' ;;
esac

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

random_b64() {
  openssl rand -base64 "$1" | tr -d '\n'
}

issue_server_certificate() {
  name=$1
  common_name=$2
  subject_alt_names=$3
  secrets=$4
  openssl genrsa -out "${secrets}/${name}-key.pem" 2048 >/dev/null 2>&1
  openssl req -new -key "${secrets}/${name}-key.pem" -subj "/CN=${common_name}" \
    -out "${secrets}/${name}.csr" >/dev/null 2>&1
  printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' "subjectAltName=${subject_alt_names}" >"${secrets}/${name}.ext"
  openssl x509 -req -in "${secrets}/${name}.csr" -CA "${secrets}/root-ca-cert.pem" \
    -CAkey "${secrets}/root-ca-key.pem" -CAcreateserial -days 825 -sha256 \
    -extfile "${secrets}/${name}.ext" -out "${secrets}/${name}-cert.pem" >/dev/null 2>&1
  rm -f "${secrets}/${name}.csr" "${secrets}/${name}.ext"
}

generate_gateway_pki() {
  local secrets=$1
  issue_server_certificate gateway-server agent-gateway 'DNS:agent-gateway,DNS:localhost,IP:127.0.0.1' "$secrets"
  openssl genrsa -out "${secrets}/gateway-control-client-key.pem" 2048 >/dev/null 2>&1
  openssl req -new -key "${secrets}/gateway-control-client-key.pem" \
    -subj '/CN=CDNCA local agent-gateway' \
    -out "${secrets}/gateway-control-client.csr" >/dev/null 2>&1
  printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=clientAuth' 'subjectAltName=URI:spiffe://cdnca/local/agent-gateway' \
    >"${secrets}/gateway-control-client.ext"
  openssl x509 -req -in "${secrets}/gateway-control-client.csr" \
    -CA "${secrets}/gateway-client-ca-cert.pem" -CAkey "${secrets}/gateway-client-ca-key.pem" \
    -CAcreateserial -days 825 -sha256 -extfile "${secrets}/gateway-control-client.ext" \
    -out "${secrets}/gateway-control-client-cert.pem" >/dev/null 2>&1
  rm -f "${secrets}/gateway-control-client.csr" "${secrets}/gateway-control-client.ext"
}

write_transport_proxy_configs() {
  local secrets=$1
  cat >"${secrets}/analytics-nats-haproxy.cfg" <<'HAPROXY'
global
  log stdout format raw local0
  ssl-default-bind-options ssl-min-ver TLSv1.2
defaults
  mode tcp
  timeout connect 5s
  timeout client 60s
  timeout server 60s
resolvers docker
  nameserver embedded_dns 127.0.0.11:53
  resolve_retries 3
  timeout resolve 1s
  timeout retry 1s
  hold other 2s
  hold refused 2s
  hold nx 2s
  hold timeout 2s
  hold valid 2s
  hold obsolete 2s
frontend analytics_nats_tls
  bind :4222 ssl crt /run/local-secrets/analytics-nats-haproxy.pem
  default_backend analytics_nats_plain
backend analytics_nats_plain
  server analytics_nats nats:4222 check resolvers docker resolve-prefer ipv4 init-addr libc,none
HAPROXY
  cat >"${secrets}/clickhouse-haproxy.cfg" <<'HAPROXY'
global
  log stdout format raw local0
  ssl-default-bind-options ssl-min-ver TLSv1.2
defaults
  mode tcp
  timeout connect 5s
  timeout client 60s
  timeout server 60s
resolvers docker
  nameserver embedded_dns 127.0.0.11:53
  resolve_retries 3
  timeout resolve 1s
  timeout retry 1s
  hold other 2s
  hold refused 2s
  hold nx 2s
  hold timeout 2s
  hold valid 2s
  hold obsolete 2s
frontend clickhouse_tls
  bind :8443 ssl crt /run/local-secrets/clickhouse-haproxy.pem
  default_backend clickhouse_plain
backend clickhouse_plain
  server clickhouse clickhouse:8123 check resolvers docker resolve-prefer ipv4 init-addr libc,none
HAPROXY
  chmod 0600 "${secrets}/analytics-nats-haproxy.cfg" "${secrets}/clickhouse-haproxy.cfg"
}

generate_material() {
  require_command openssl
  require_command base64
  umask 077
  mkdir -p "$state_dir"
  if [ -e "$runtime_env" ] || [ -e "${state_dir}/secrets" ]; then
    fail "incomplete generated state exists at ${state_dir}; move it aside before retrying"
  fi
  work=$(mktemp -d "${state_dir}/.generate.XXXXXX")
  trap 'rm -rf "$work"' EXIT
  secrets="${work}/secrets"
  mkdir -p "$secrets"

  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -subj '/CN=CDNCA local root CA' -keyout "${secrets}/root-ca-key.pem" \
    -out "${secrets}/root-ca-cert.pem" >/dev/null 2>&1
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -subj '/CN=CDNCA local Gateway client CA' -keyout "${secrets}/gateway-client-ca-key.pem" \
    -out "${secrets}/gateway-client-ca-cert.pem" >/dev/null 2>&1
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -subj '/CN=CDNCA local node CA' -keyout "${secrets}/node-ca-key.pem" \
    -out "${secrets}/node-ca-cert.pem" >/dev/null 2>&1
  generate_gateway_pki "$secrets"
  issue_server_certificate control-server control-api 'DNS:control-api,DNS:localhost,IP:127.0.0.1' "$secrets"
  issue_server_certificate analytics-nats analytics-nats-tls 'DNS:analytics-nats-tls' "$secrets"
  issue_server_certificate clickhouse clickhouse-tls 'DNS:clickhouse-tls' "$secrets"
  issue_server_certificate mailpit mailpit 'DNS:mailpit,DNS:localhost,IP:127.0.0.1' "$secrets"
  cat "${secrets}/analytics-nats-cert.pem" "${secrets}/analytics-nats-key.pem" \
    >"${secrets}/analytics-nats-haproxy.pem"
  cat "${secrets}/clickhouse-cert.pem" "${secrets}/clickhouse-key.pem" \
    >"${secrets}/clickhouse-haproxy.pem"
  write_transport_proxy_configs "$secrets"

  openssl genpkey -algorithm ED25519 -out "${secrets}/control-installation-key.pem" >/dev/null 2>&1
  openssl genpkey -algorithm ED25519 -out "${secrets}/plugin-webhook-attestation-key.pem" >/dev/null 2>&1

  cat >"${secrets}/edge-command-stream.json" <<'JSON'
{"name":"AGENT_COMMANDS","subjects":["cdnca.agent.commands.*","cdnca.agent.commands.acme-http01.*","cdnca.agent.commands.cache.*","cdnca.agent.commands.cache-dlq.*","cdnca.agent.commands.upgrade.*","cdnca.agent.commands.drain.*","cdnca.agent.commands.gateway-port.*"],"retention":"limits","max_consumers":-1,"max_msgs":1000000,"max_bytes":1073741824,"discard":"old","max_age":604800000000000,"max_msgs_per_subject":-1,"max_msg_size":1048576,"storage":"file","num_replicas":1,"duplicate_window":120000000000}
JSON
  cat >"${secrets}/edge-status-stream.json" <<'JSON'
{"name":"AGENT_DEPLOYMENT_STATUS","subjects":["cdnca.agent.deployment-status.*","cdnca.agent.deployment-status.generic-v2.*.*","cdnca.agent.deployment-status.terminal-receipt.*.*","cdnca.agent.deployment-status.terminal-receipt-confirmation.*.*","cdnca.agent.deployment-status.terminal-receipt-confirmation-index.*","cdnca.agent.deployment-status.acme-http01.*","cdnca.agent.deployment-status.cache.*","cdnca.agent.deployment-status.cache-dlq.*","cdnca.agent.deployment-status.upgrade.*","cdnca.agent.deployment-status.upgrade-v2.*","cdnca.agent.deployment-status.upgrade-proof.pending.*","cdnca.agent.deployment-status.upgrade-proof.confirmed.*.*","cdnca.agent.deployment-status.upgrade-proof.completed.*.*.*","cdnca.agent.deployment-status.upgrade-proof.status.*.*","cdnca.agent.deployment-status.drain.*","cdnca.agent.deployment-status.gateway-port.*"],"retention":"limits","max_consumers":32,"max_msgs":1000000,"max_bytes":1073741824,"discard":"old","max_age":604800000000000,"max_msgs_per_subject":-1,"max_msg_size":1048576,"storage":"file","num_replicas":1,"duplicate_window":120000000000}
JSON
  cat >"${secrets}/edge-status-consumer.json" <<'JSON'
{"stream_name":"AGENT_DEPLOYMENT_STATUS","config":{"durable_name":"control_api_edge_status","deliver_policy":"all","ack_policy":"explicit","ack_wait":120000000000,"max_deliver":-1,"filter_subjects":["cdnca.agent.deployment-status.*","cdnca.agent.deployment-status.generic-v2.*.*"],"replay_policy":"instant","max_waiting":32,"max_ack_pending":256,"max_batch":1,"max_expires":5000000000,"num_replicas":0,"mem_storage":false}}
JSON
  cat >"${secrets}/edge-heartbeat-stream.json" <<'JSON'
{"name":"AGENT_HEARTBEATS","subjects":["cdnca.agent.heartbeats.*"],"retention":"limits","max_consumers":-1,"max_msgs":1000000,"max_bytes":1073741824,"discard":"old","max_age":604800000000000,"max_msgs_per_subject":-1,"max_msg_size":1048576,"storage":"file","num_replicas":1,"duplicate_window":120000000000}
JSON
  # Mirrors cachecontrolruntime.expectedConsumer: the cache runtime only binds.
  cat >"${secrets}/edge-cache-status-consumer.json" <<'JSON'
{"stream_name":"AGENT_DEPLOYMENT_STATUS","config":{"durable_name":"control_api_cache_status","deliver_policy":"all","ack_policy":"explicit","ack_wait":120000000000,"max_deliver":5,"filter_subject":"cdnca.agent.deployment-status.cache.*","replay_policy":"instant","max_waiting":16,"max_ack_pending":64,"max_batch":1,"max_expires":2000000000,"max_bytes":1048576,"num_replicas":0,"mem_storage":false}}
JSON
  cat >"${secrets}/edge-node-monitoring-status-stream.json" <<'JSON'
{"name":"NODE_MONITORING_STATUS","subjects":["cdnca.agent.node-monitoring.status.*"],"retention":"workqueue","max_consumers":-1,"max_msgs":-1,"max_bytes":-1,"discard":"new","max_age":0,"max_msgs_per_subject":-1,"max_msg_size":1048576,"storage":"file","num_replicas":1,"duplicate_window":120000000000}
JSON
  cat >"${secrets}/edge-node-monitoring-consumer.json" <<'JSON'
{"stream_name":"NODE_MONITORING_STATUS","config":{"durable_name":"control_api_node_metrics","deliver_policy":"all","ack_policy":"explicit","ack_wait":120000000000,"max_deliver":-1,"filter_subject":"cdnca.agent.node-monitoring.status.*","replay_policy":"instant","max_waiting":32,"max_ack_pending":256,"max_batch":1,"max_expires":5000000000,"num_replicas":0,"mem_storage":false}}
JSON

  control_access=$(openssl rand -hex 32)
  api_pepper=$(random_b64 32)
  dns_key=$(random_b64 32)
  impersonation_key=$(random_b64 32)
  mfa_key=$(random_b64 32)
  cache_control_cursor_key=$(random_b64 32)
  observability_key=$(random_b64 32)
  analytics_logs_cursor_key=$(random_b64 32)
  analytics_key=$(random_b64 32)
  openresty_security_key=$(random_b64 32)
  edge_nats_password=$(openssl rand -hex 24)
  nats_preprovision_password=$(openssl rand -hex 24)
  nats_control_consumer_password=$(openssl rand -hex 24)
  nats_gateway_publisher_password=$(openssl rand -hex 24)
  local_smtp_username=$(openssl rand -hex 16)
  local_smtp_password=$(openssl rand -hex 24)

  {
    printf 'LOCAL_STACK_STATE_DIR=%s\n' "$state_dir"
    printf 'EDGE_NATS_USERNAME=cdnca-edge-local\n'
    printf 'EDGE_NATS_PASSWORD=%s\n' "$edge_nats_password"
    printf 'NATS_PREPROVISION_USERNAME=cdnca-analytics-preprovision-local\n'
    printf 'NATS_PREPROVISION_PASSWORD=%s\n' "$nats_preprovision_password"
    printf 'NATS_CONTROL_CONSUMER_USERNAME=cdnca-control-analytics-consumer-local\n'
    printf 'NATS_CONTROL_CONSUMER_PASSWORD=%s\n' "$nats_control_consumer_password"
    printf 'NATS_GATEWAY_PUBLISHER_USERNAME=cdnca-gateway-analytics-publisher-local\n'
    printf 'NATS_GATEWAY_PUBLISHER_PASSWORD=%s\n' "$nats_gateway_publisher_password"
    printf 'LOCAL_SMTP_USERNAME=%s\n' "$local_smtp_username"
    printf 'LOCAL_SMTP_PASSWORD=%s\n' "$local_smtp_password"
    printf 'CONTROL_ACCESS_TOKEN_SECRET=%s\n' "$control_access"
    printf 'CONTROL_API_KEY_PEPPER_BASE64=%s\n' "$api_pepper"
    printf 'CONTROL_DNS_CREDENTIAL_KEY_BASE64=%s\n' "$dns_key"
    printf 'CONTROL_IMPERSONATION_HMAC_KEY_BASE64=%s\n' "$impersonation_key"
    printf 'CONTROL_MFA_ENCRYPTION_KEY_BASE64=%s\n' "$mfa_key"
    printf 'CONTROL_CACHE_CONTROL_CURSOR_KEY_BASE64=%s\n' "$cache_control_cursor_key"
    printf 'CONTROL_OBSERVABILITY_LOG_CURSOR_KEY_BASE64=%s\n' "$observability_key"
    printf 'CONTROL_ANALYTICS_LOGS_CURSOR_KEY_BASE64=%s\n' "$analytics_logs_cursor_key"
    printf 'CONTROL_ANALYTICS_ISOLATION_KEY_BASE64=%s\n' "$analytics_key"
    printf 'OPENRESTY_SECURITY_SECRET_KEY_BASE64=%s\n' "$openresty_security_key"
  } >"${work}/runtime.env"
  chmod 0600 "${work}/runtime.env" "${secrets}"/*
  mv "$secrets" "${state_dir}/secrets"
  mv "${work}/runtime.env" "$runtime_env"
  : >"$ready_marker"
  chmod 0600 "$ready_marker"
  trap - EXIT
  rm -rf "$work"
}

validate_explicit_port_overrides() {
  local key value
  for key in "${port_override_keys[@]}"; do
    [ "${!key+x}" = x ] || continue
    value=${!key}
    case "$value" in
      ''|0*|*[!0-9]*) fail "invalid local stack port override for ${key}; expected a decimal integer from 1 to 65535" ;;
    esac
    if [ "${#value}" -gt 5 ] || [ "$value" -gt 65535 ]; then
      fail "invalid local stack port override for ${key}; expected a decimal integer from 1 to 65535"
    fi
  done
}

persist_explicit_port_overrides() {
  local count index key key_pattern migrated_env value
  local -a override_keys override_values
  override_keys=()
  override_values=()
  count=0

  for key in "${port_override_keys[@]}"; do
    [ "${!key+x}" = x ] || continue
    value=${!key}
    override_keys[count]=$key
    override_values[count]=$value
    count=$((count + 1))
  done
  [ "$count" -gt 0 ] || return 0

  require_command awk
  key_pattern=$(IFS='|'; printf '%s' "${override_keys[*]}")
  umask 077
  migrated_env=$(mktemp "${state_dir}/.runtime.env.XXXXXX")
  trap 'rm -f "$migrated_env"' EXIT
  awk -v pattern="^(${key_pattern})=" '$0 !~ pattern { print }' "$runtime_env" >"$migrated_env"
  for ((index = 0; index < count; index++)); do
    printf '%s=%s\n' "${override_keys[$index]}" "${override_values[$index]}" >>"$migrated_env"
  done
  chmod 0600 "$migrated_env"
  mv "$migrated_env" "$runtime_env"
  trap - EXIT
}

ensure_material() {
  validate_explicit_port_overrides
  if [ ! -f "$ready_marker" ]; then
    generate_material
  fi
  [ -f "$runtime_env" ] && [ -d "${state_dir}/secrets" ] || fail 'generated local stack state is incomplete'
  persist_explicit_port_overrides
  write_transport_proxy_configs "${state_dir}/secrets"
  ensure_openresty_security_key
  ensure_analytics_nats_credentials
  ensure_gateway_pki
}

ensure_openresty_security_key() {
  grep -q '^OPENRESTY_SECURITY_SECRET_KEY_BASE64=' "$runtime_env" && return 0
  require_command openssl
  require_command base64
  local migrated_env openresty_security_key
  umask 077
  migrated_env=$(mktemp "${state_dir}/.runtime.env.XXXXXX")
  trap 'rm -f "$migrated_env"' EXIT
  openresty_security_key=$(random_b64 32)
  cp "$runtime_env" "$migrated_env"
  printf 'OPENRESTY_SECURITY_SECRET_KEY_BASE64=%s\n' "$openresty_security_key" >>"$migrated_env"
  chmod 0600 "$migrated_env"
  mv "$migrated_env" "$runtime_env"
  trap - EXIT
}

ensure_analytics_nats_credentials() {
  if grep -q '^NATS_PREPROVISION_USERNAME=' "$runtime_env" &&
    grep -q '^NATS_PREPROVISION_PASSWORD=' "$runtime_env" &&
    grep -q '^NATS_CONTROL_CONSUMER_USERNAME=' "$runtime_env" &&
    grep -q '^NATS_CONTROL_CONSUMER_PASSWORD=' "$runtime_env" &&
    grep -q '^NATS_GATEWAY_PUBLISHER_USERNAME=' "$runtime_env" &&
    grep -q '^NATS_GATEWAY_PUBLISHER_PASSWORD=' "$runtime_env"; then
    return 0
  fi
  require_command openssl
  local migrated_env
  umask 077
  migrated_env=$(mktemp "${state_dir}/.runtime.env.XXXXXX")
  trap 'rm -f "$migrated_env"' EXIT
  cp "$runtime_env" "$migrated_env"
  grep -q '^NATS_PREPROVISION_USERNAME=' "$migrated_env" ||
    printf 'NATS_PREPROVISION_USERNAME=cdnca-analytics-preprovision-local\n' >>"$migrated_env"
  grep -q '^NATS_PREPROVISION_PASSWORD=' "$migrated_env" ||
    printf 'NATS_PREPROVISION_PASSWORD=%s\n' "$(openssl rand -hex 24)" >>"$migrated_env"
  grep -q '^NATS_CONTROL_CONSUMER_USERNAME=' "$migrated_env" ||
    printf 'NATS_CONTROL_CONSUMER_USERNAME=cdnca-control-analytics-consumer-local\n' >>"$migrated_env"
  grep -q '^NATS_CONTROL_CONSUMER_PASSWORD=' "$migrated_env" ||
    printf 'NATS_CONTROL_CONSUMER_PASSWORD=%s\n' "$(openssl rand -hex 24)" >>"$migrated_env"
  grep -q '^NATS_GATEWAY_PUBLISHER_USERNAME=' "$migrated_env" ||
    printf 'NATS_GATEWAY_PUBLISHER_USERNAME=cdnca-gateway-analytics-publisher-local\n' >>"$migrated_env"
  grep -q '^NATS_GATEWAY_PUBLISHER_PASSWORD=' "$migrated_env" ||
    printf 'NATS_GATEWAY_PUBLISHER_PASSWORD=%s\n' "$(openssl rand -hex 24)" >>"$migrated_env"
  chmod 0600 "$migrated_env"
  mv "$migrated_env" "$runtime_env"
  trap - EXIT
}

ensure_gateway_pki() {
  local existing file migrated_pki secrets
  secrets="${state_dir}/secrets"
  existing=0
  for file in gateway-server-cert.pem gateway-server-key.pem \
    gateway-control-client-cert.pem gateway-control-client-key.pem; do
    [ -e "${secrets}/${file}" ] && existing=$((existing + 1))
  done
  [ "$existing" -eq 4 ] && return 0
  [ "$existing" -eq 0 ] || fail 'generated local Gateway PKI is incomplete; move the local stack state aside before retrying'
  for file in root-ca-cert.pem root-ca-key.pem gateway-client-ca-cert.pem gateway-client-ca-key.pem node-ca-cert.pem; do
    [ -s "${secrets}/${file}" ] || fail "generated local Gateway PKI authority is missing: ${file}"
  done

  require_command openssl
  umask 077
  migrated_pki=$(mktemp -d "${state_dir}/.gateway-pki.XXXXXX")
  trap 'rm -rf "$migrated_pki"' EXIT
  cp -p "${secrets}/root-ca-cert.pem" "${secrets}/root-ca-key.pem" \
    "${secrets}/gateway-client-ca-cert.pem" "${secrets}/gateway-client-ca-key.pem" "$migrated_pki/"
  generate_gateway_pki "$migrated_pki"
  for file in gateway-server-cert.pem gateway-server-key.pem \
    gateway-control-client-cert.pem gateway-control-client-key.pem; do
    mv "${migrated_pki}/${file}" "${secrets}/${file}"
  done
  chmod 0600 "${secrets}/gateway-server-key.pem" "${secrets}/gateway-control-client-key.pem"
  rm -rf "$migrated_pki"
  trap - EXIT
}

require_material() {
  [ -f "$ready_marker" ] && [ -f "$runtime_env" ] || fail "local stack has not been initialized; run make up first"
}

compose() {
  docker compose --project-name "$project_name" \
    --env-file "$env_file" --env-file "$runtime_env" \
    -f "${repo_root}/compose.yaml" -f "${repo_root}/compose.full.yaml" \
    -f "${repo_root}/deploy/compose/clickhouse-migrate.yaml" "$@"
}

# The license service is external to this repository: a community license is
# activated on the official license service for CONTROL_INSTALLATION_ID with
# the generated installation key, and its signed bundle is imported here.
install_entitlement() {
  local bundle=$1 trusted_keys=$2 migrated_env secrets
  [ -f "$bundle" ] && [ -f "$trusted_keys" ] ||
    fail 'usage: scripts/local-stack.sh install-entitlement BUNDLE.json TRUSTED-KEYS.json'
  secrets="${state_dir}/secrets"
  umask 077
  cp "$bundle" "${secrets}/entitlement-bundle.json"
  cp "$trusted_keys" "${secrets}/entitlement-trusted-keys.json"
  chmod 0600 "${secrets}/entitlement-bundle.json" "${secrets}/entitlement-trusted-keys.json"
  migrated_env=$(mktemp "${state_dir}/.runtime.env.XXXXXX")
  trap 'rm -f "$migrated_env"' EXIT
  grep -v '^ENTITLEMENT_TRUSTED_KEYS_FILE=' "$runtime_env" >"$migrated_env" || true
  printf 'ENTITLEMENT_TRUSTED_KEYS_FILE=/run/local-secrets/entitlement-trusted-keys.json\n' >>"$migrated_env"
  chmod 0600 "$migrated_env"
  mv "$migrated_env" "$runtime_env"
  trap - EXIT
  compose run --rm --no-deps local-secrets-install
  compose run --rm --no-deps control-api install-entitlement \
    --bundle /run/local-secrets/entitlement-bundle.json \
    --trusted-keys /run/local-secrets/entitlement-trusted-keys.json
}

license_notice() {
  if grep -q '^ENTITLEMENT_TRUSTED_KEYS_FILE=.' "$runtime_env"; then
    return 0
  fi
  printf '%s\n' \
    'No entitlement has been imported: control-api feature gates deny requests until one is (expected).' \
    'Activate a community license on the official license service, then run:' \
    '  scripts/local-stack.sh install-entitlement BUNDLE.json TRUSTED-KEYS.json' \
    'See infra/env/development.env for the installation ID and key location.'
}

verify_project_ownership() {
  ids=$(compose ps -aq)
  [ -n "$ids" ] || return 0
  for id in $ids; do
    owner=$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}' "$id")
    [ "$owner" = "$project_name" ] || fail "refusing cleanup for container outside ${project_name}: ${id}"
  done
}

action=${1:-}
case "$action" in
  up)
    require_command docker
    ensure_material
    compose up -d --build --wait
    web_address=$(compose port web 8080)
    printf 'CDNCA local stack is ready: web=http://%s\n' "$web_address"
    license_notice
    ;;
  install-entitlement)
    require_command docker
    require_material
    install_entitlement "${2:-}" "${3:-}"
    printf 'entitlement imported; run make up to restart control-api with the trusted keys\n'
    ;;
  down)
    require_command docker
    require_material
    verify_project_ownership
    compose down --remove-orphans
    ;;
  status)
    require_command docker
    require_material
    compose ps
    ;;
  logs)
    require_command docker
    require_material
    compose logs --tail=200 -f
    ;;
  config)
    require_command docker
    ensure_material
    compose config
    ;;
  *)
    fail 'usage: scripts/local-stack.sh up|down|status|logs|config|install-entitlement BUNDLE.json TRUSTED-KEYS.json'
    ;;
esac
