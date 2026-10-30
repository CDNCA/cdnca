#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
makefile="${repo_root}/Makefile"
infra_compose="${repo_root}/compose.yaml"
compose="${repo_root}/compose.full.yaml"
clickhouse_migrate_compose="${repo_root}/deploy/compose/clickhouse-migrate.yaml"
runner="${repo_root}/scripts/local-stack.sh"
readme="${repo_root}/README.md"
notification_runbook="${repo_root}/docs/runbooks/notification-runtime-wiring.md"
nats_config="${repo_root}/infra/nats/analytics-server.conf"
nats_preprovision="${repo_root}/infra/nats/analytics-preprovision.sh"
web_nginx="${repo_root}/apps/web/nginx.conf"

fail() {
  printf 'LOCAL_STACK_STATIC RED: %s\n' "$1" >&2
  exit 1
}

file_mode() {
  stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1"
}

runtime_env_value() {
  local key=$1 runtime_file=$2
  sed -n "s/^${key}=//p" "$runtime_file"
}

assert_runtime_port() {
  local count expected key runtime_file
  key=$1
  expected=$2
  runtime_file=$3
  count=$(grep -c "^${key}=" "$runtime_file" || true)
  [ "$count" -eq 1 ] || fail "runtime.env must contain exactly one ${key}"
  [ "$(runtime_env_value "$key" "$runtime_file")" = "$expected" ] ||
    fail "runtime.env contains an unexpected ${key} value"
}

unset_local_stack_port_overrides() {
  unset POSTGRES_PORT REDIS_PORT CLICKHOUSE_HTTP_PORT CLICKHOUSE_NATIVE_PORT \
    NATS_CLIENT_PORT NATS_MONITOR_PORT EDGE_NATS_PORT \
    MAILPIT_UI_PORT MAILPIT_SMTP_PORT \
    CONTROL_API_PORT AGENT_GATEWAY_AGENT_PORT AGENT_GATEWAY_ENROLLMENT_PORT \
    WEB_PORT
}

assert_analytics_nats_credentials() {
  local count key password preprovision_password control_password publisher_password runtime_file
  local preprovision_user control_user publisher_user
  runtime_file=$1
  for key in \
    NATS_PREPROVISION_USERNAME NATS_PREPROVISION_PASSWORD \
    NATS_CONTROL_CONSUMER_USERNAME NATS_CONTROL_CONSUMER_PASSWORD \
    NATS_GATEWAY_PUBLISHER_USERNAME NATS_GATEWAY_PUBLISHER_PASSWORD; do
    count=$(grep -c "^${key}=" "$runtime_file" || true)
    [ "$count" -eq 1 ] || fail "runtime.env must contain exactly one ${key}"
    [ -n "$(runtime_env_value "$key" "$runtime_file")" ] || fail "runtime.env contains an empty ${key}"
  done
  preprovision_user=$(runtime_env_value NATS_PREPROVISION_USERNAME "$runtime_file")
  control_user=$(runtime_env_value NATS_CONTROL_CONSUMER_USERNAME "$runtime_file")
  publisher_user=$(runtime_env_value NATS_GATEWAY_PUBLISHER_USERNAME "$runtime_file")
  [ "$preprovision_user" != "$control_user" ] && [ "$preprovision_user" != "$publisher_user" ] &&
    [ "$control_user" != "$publisher_user" ] || fail 'analytics NATS usernames are not isolated by workload'
  preprovision_password=$(runtime_env_value NATS_PREPROVISION_PASSWORD "$runtime_file")
  control_password=$(runtime_env_value NATS_CONTROL_CONSUMER_PASSWORD "$runtime_file")
  publisher_password=$(runtime_env_value NATS_GATEWAY_PUBLISHER_PASSWORD "$runtime_file")
  [ "$preprovision_password" != "$control_password" ] && [ "$preprovision_password" != "$publisher_password" ] &&
    [ "$control_password" != "$publisher_password" ] || fail 'analytics NATS passwords are not isolated by workload'
  for password in "$preprovision_password" "$control_password" "$publisher_password"; do
    [[ "$password" =~ ^[0-9a-f]{48}$ ]] || fail 'generated analytics NATS password is not 24 random bytes'
  done
}

assert_gateway_pki() {
  local file secrets
  secrets=$1
  for file in root-ca-cert.pem gateway-client-ca-cert.pem node-ca-cert.pem \
    gateway-server-cert.pem gateway-server-key.pem \
    gateway-control-client-cert.pem gateway-control-client-key.pem; do
    [ -s "${secrets}/${file}" ] || fail "generated Gateway PKI file is missing: ${file}"
  done
  openssl verify -purpose sslserver -CAfile "${secrets}/root-ca-cert.pem" \
    "${secrets}/gateway-server-cert.pem" >/dev/null 2>&1 || fail 'Gateway server certificate does not verify against the local root CA'
  openssl verify -purpose sslclient -CAfile "${secrets}/gateway-client-ca-cert.pem" \
    "${secrets}/gateway-control-client-cert.pem" >/dev/null 2>&1 || fail 'Gateway Control client certificate does not verify against its dedicated CA'
  cmp -s <(openssl x509 -in "${secrets}/gateway-server-cert.pem" -pubkey -noout) \
    <(openssl pkey -in "${secrets}/gateway-server-key.pem" -pubout 2>/dev/null) || fail 'Gateway server certificate and key do not match'
  cmp -s <(openssl x509 -in "${secrets}/gateway-control-client-cert.pem" -pubkey -noout) \
    <(openssl pkey -in "${secrets}/gateway-control-client-key.pem" -pubout 2>/dev/null) || fail 'Gateway Control client certificate and key do not match'
  openssl x509 -in "${secrets}/gateway-server-cert.pem" -text -noout | grep -F 'DNS:agent-gateway' >/dev/null ||
    fail 'Gateway server certificate does not contain the service DNS SAN'
  openssl x509 -in "${secrets}/gateway-control-client-cert.pem" -text -noout |
    grep -F 'URI:spiffe://cdnca/local/agent-gateway' >/dev/null || fail 'Gateway Control client certificate does not contain the workload URI SAN'
  [ "$(file_mode "${secrets}/gateway-server-key.pem")" = 600 ] || fail 'Gateway server private key is not owner-only'
  [ "$(file_mode "${secrets}/gateway-control-client-key.pem")" = 600 ] || fail 'Gateway Control client private key is not owner-only'
}

seed_gateway_authorities() {
  local secrets=$1
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 -subj '/CN=local stack test root' \
    -keyout "${secrets}/root-ca-key.pem" -out "${secrets}/root-ca-cert.pem" >/dev/null 2>&1
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -subj '/CN=local stack test Gateway client CA' -keyout "${secrets}/gateway-client-ca-key.pem" \
    -out "${secrets}/gateway-client-ca-cert.pem" >/dev/null 2>&1
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -subj '/CN=local stack test node CA' -keyout "${secrets}/node-ca-key.pem" \
    -out "${secrets}/node-ca-cert.pem" >/dev/null 2>&1
}

check_port_override_persistence() {
  local fake_bin invalid output runtime_file setting state tmp_root true_path
  local -a initial_ports updated_ports
  tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-port-persistence.XXXXXX")
  port_persistence_tmp_root=$tmp_root
  trap 'find "$port_persistence_tmp_root" -depth -delete 2>/dev/null || true' EXIT
  state="${tmp_root}/state"
  runtime_file="${state}/runtime.env"
  fake_bin="${tmp_root}/bin"
  mkdir -p "$fake_bin"
  true_path=$(type -P true)
  ln -s "$true_path" "${fake_bin}/docker"
  if output=$(
    unset_local_stack_port_overrides
    env PATH="${fake_bin}:${PATH}" LOCAL_STACK_STATE_DIR="${tmp_root}/invalid-state" \
      LOCAL_STACK_ENV_FILE="${repo_root}/infra/env/development.env" \
      WEB_PORT=0 "$runner" config 2>&1
  ); then
    fail 'an invalid initial local stack port override was accepted'
  fi
  [ ! -e "${tmp_root}/invalid-state/runtime.env" ] ||
    fail 'an invalid initial local stack port override generated runtime.env'
  initial_ports=(
    POSTGRES_PORT=1
    REDIS_PORT=16379
    CLICKHOUSE_HTTP_PORT=18123
    CLICKHOUSE_NATIVE_PORT=19000
    NATS_CLIENT_PORT=14222
    NATS_MONITOR_PORT=18222
    EDGE_NATS_PORT=14223
    MAILPIT_UI_PORT=18025
    MAILPIT_SMTP_PORT=11025
    CONTROL_API_PORT=18080
    AGENT_GATEWAY_AGENT_PORT=18443
    AGENT_GATEWAY_ENROLLMENT_PORT=18444
    WEB_PORT=65535
  )

  output=$(
    unset_local_stack_port_overrides
    env PATH="${fake_bin}:${PATH}" LOCAL_STACK_STATE_DIR="$state" \
      LOCAL_STACK_ENV_FILE="${repo_root}/infra/env/development.env" \
      "${initial_ports[@]}" "$runner" config 2>&1
  ) || fail 'explicit local stack ports could not be persisted'
  [ -z "$output" ] || fail 'port persistence wrote generated material to output'
  for setting in "${initial_ports[@]}"; do
    assert_runtime_port "${setting%%=*}" "${setting#*=}" "$runtime_file"
  done
  [ "$(file_mode "$runtime_file")" = 600 ] || fail 'port persistence did not keep runtime.env owner-only'

  cp "$runtime_file" "${tmp_root}/before-no-override.env"
  output=$(
    unset_local_stack_port_overrides
    env PATH="${fake_bin}:${PATH}" LOCAL_STACK_STATE_DIR="$state" \
      LOCAL_STACK_ENV_FILE="${repo_root}/infra/env/development.env" \
      UNSUPPORTED_PORT=12345 "$runner" config 2>&1
  ) || fail 'persisted local stack ports could not be reused'
  [ -z "$output" ] || fail 'port reuse wrote generated material to output'
  cmp -s "${tmp_root}/before-no-override.env" "$runtime_file" ||
    fail 'runtime.env changed without an explicit supported port override'
  ! grep -q '^UNSUPPORTED_PORT=' "$runtime_file" || fail 'an unsupported port override was persisted'

  printf 'WEB_PORT=9999\n' >>"$runtime_file"
  updated_ports=(NATS_MONITOR_PORT=28222 WEB_PORT=23000)
  output=$(
    unset_local_stack_port_overrides
    env PATH="${fake_bin}:${PATH}" LOCAL_STACK_STATE_DIR="$state" \
      LOCAL_STACK_ENV_FILE="${repo_root}/infra/env/development.env" \
      "${updated_ports[@]}" "$runner" config 2>&1
  ) || fail 'explicit local stack ports could not be updated'
  [ -z "$output" ] || fail 'port update wrote generated material to output'
  for setting in "${updated_ports[@]}"; do
    assert_runtime_port "${setting%%=*}" "${setting#*=}" "$runtime_file"
  done
  assert_runtime_port POSTGRES_PORT 1 "$runtime_file"
  assert_runtime_port MAILPIT_SMTP_PORT 11025 "$runtime_file"

  cp "$runtime_file" "${tmp_root}/before-invalid.env"
  for invalid in '' 0 65536 not-a-port; do
    if output=$(
      unset_local_stack_port_overrides
      env PATH="${fake_bin}:${PATH}" LOCAL_STACK_STATE_DIR="$state" \
        LOCAL_STACK_ENV_FILE="${repo_root}/infra/env/development.env" \
        WEB_PORT="$invalid" "$runner" config 2>&1
    ); then
      fail 'an invalid local stack port override was accepted'
    fi
    cmp -s "${tmp_root}/before-invalid.env" "$runtime_file" ||
      fail 'an invalid local stack port override changed runtime.env'
  done
  [ -z "$(find "$state" -maxdepth 1 -name '.runtime.env.*' -print -quit)" ] ||
    fail 'port persistence left a temporary runtime.env file'

  find "$tmp_root" -depth -delete
  port_persistence_tmp_root=
  trap - EXIT
}

check_notification_runtime_wiring() {
  grep -Eq 'MP_SMTP_REQUIRE_STARTTLS([=:][[:space:]]*)"?true"?' "${compose}" ||
    fail 'Mailpit does not require STARTTLS'
  grep -F "MP_SMTP_AUTH: \"\${LOCAL_SMTP_USERNAME:" "${compose}" >/dev/null ||
    fail 'Mailpit SMTP authentication does not use the dedicated generated username'
  grep -F ":\${LOCAL_SMTP_PASSWORD:" "${compose}" >/dev/null ||
    fail 'Mailpit SMTP authentication does not use the dedicated generated password'
  for variable in NOTIFICATION_SMTP_USERNAME NOTIFICATION_SMTP_PASSWORD; do
    grep -Eq "${variable}([=:][[:space:]]*)\\\$\\{LOCAL_SMTP_(USERNAME|PASSWORD):" "${compose}" ||
      fail "${variable} does not use dedicated generated local SMTP authentication"
  done
  grep -F "local_smtp_username=\$(openssl rand -hex 16)" "${runner}" >/dev/null ||
    fail 'dedicated local SMTP username is not generated cryptographically'
  grep -F "local_smtp_password=\$(openssl rand -hex 24)" "${runner}" >/dev/null ||
    fail 'dedicated local SMTP password is not generated cryptographically'
  grep -F "printf 'LOCAL_SMTP_USERNAME=%s\\n' \"\$local_smtp_username\"" "${runner}" >/dev/null ||
    fail 'generated local SMTP username is not exported to the runtime environment'
  grep -F "printf 'LOCAL_SMTP_PASSWORD=%s\\n' \"\$local_smtp_password\"" "${runner}" >/dev/null ||
    fail 'generated local SMTP password is not exported to the runtime environment'
  if grep -Eq '^[[:space:]]+(MP_SMTP_AUTH|NOTIFICATION_SMTP_(USERNAME|PASSWORD)):.*EDGE_NATS_' "${compose}"; then
    fail 'SMTP authentication reuses Edge NATS credentials'
  fi
  grep -F "NOTIFICATION_RUNTIME_ENABLED: \${NOTIFICATION_RUNTIME_ENABLED:-false}" "${compose}" >/dev/null ||
    fail 'notification runtime is not explicitly overridable with a disabled default'
  for setting in \
    'NOTIFICATION_EMAIL_PROVIDER: smtp_starttls' \
    'NOTIFICATION_SMTP_ADDRESS: mailpit:1025' \
    'NOTIFICATION_SMTP_SERVER_NAME: mailpit' \
    "NOTIFICATION_SMTP_USERNAME: \${LOCAL_SMTP_USERNAME:" \
    "NOTIFICATION_SMTP_PASSWORD: \${LOCAL_SMTP_PASSWORD:" \
    'NOTIFICATION_SMTP_FROM: cdnca-local@example.test' \
    'NOTIFICATION_SMTP_CA_FILE: /run/local-secrets/root-ca-cert.pem' \
    "ACCOUNT_RECOVERY_EMAIL_TEMPLATE_ID: \${ACCOUNT_RECOVERY_EMAIL_TEMPLATE_ID:-account_recovery_email}" \
    "ACCOUNT_RECOVERY_EMAIL_TEMPLATE_VERSION: \${ACCOUNT_RECOVERY_EMAIL_TEMPLATE_VERSION:-1}"; do
    grep -F "${setting}" "${compose}" >/dev/null || fail "notification setting is missing: ${setting}"
  done
  for variable in NOTIFICATION_WORKER_BATCH_SIZE NOTIFICATION_WORKER_LEASE_DURATION \
    NOTIFICATION_WORKER_LEASE_SAFETY_MARGIN NOTIFICATION_WORKER_MAX_ATTEMPTS \
    NOTIFICATION_WORKER_BASE_DELAY NOTIFICATION_WORKER_MAX_DELAY NOTIFICATION_RUNTIME_IDLE_WAIT \
    NOTIFICATION_RUNTIME_ERROR_BACKOFF_BASE NOTIFICATION_RUNTIME_ERROR_BACKOFF_MAX \
    NOTIFICATION_RUNTIME_MAX_CONSECUTIVE_FAILURES NOTIFICATION_RUNTIME_SEND_TIMEOUT \
    NOTIFICATION_RUNTIME_STARTUP_TIMEOUT NOTIFICATION_RUNTIME_SHUTDOWN_TIMEOUT; do
    grep -Eq "^[[:space:]]+${variable}:[[:space:]]+[^[:space:]]+" "${compose}" ||
      fail "notification timing setting is missing: ${variable}"
  done
  if grep -Eq 'MP_SMTP_AUTH:[[:space:]]*"?[[:alnum:]_.-]+:[[:alnum:]_./+=-]+"?[[:space:]]*$' "${compose}"; then
    fail 'Mailpit contains a literal SMTP credential'
  fi
  for phrase in email-only SMS-only 'both delivery channels' smtp_tls smtp_starttls \
    'no plaintext fallback or downgrade path' 'NOTIFICATION_SMTP_SERVER_NAME' \
    'same origin' 'fails readiness closed' 'dedicated generated local SMTP credentials' \
    'not shared with Edge NATS'; do
    grep -F "${phrase}" "${notification_runbook}" >/dev/null ||
      fail "notification runbook omits required boundary: ${phrase}"
  done
}

check_frontend_runtime_wiring() {
  cache_mounts=$(grep -Fc -- '- /var/cache/nginx:uid=65532,gid=65532,mode=0755' "${compose}" || true)
  run_mounts=$(grep -Fc -- '- /var/run:uid=65532,gid=65532,mode=0755' "${compose}" || true)
  [ "${cache_mounts}" -eq 1 ] || fail 'Web must have a non-root writable Nginx cache tmpfs'
  [ "${run_mounts}" -eq 1 ] || fail 'Web must have a non-root writable Nginx run tmpfs'
  web_block=$(sed -n '/^  web:/,/^volumes:/p' "${compose}")
  grep -F 'gateway-secrets-install:' <<<"${web_block}" >/dev/null ||
    fail 'Web must wait for the Gateway secret installer before serving the Gateway CA'
  grep -F 'gateway_secrets:/run/cdnca-gateway:ro' <<<"${web_block}" >/dev/null ||
    fail 'Web must mount the Gateway CA volume read-only'
  grep -F 'alias /run/cdnca-gateway/root-ca-cert.pem' "${web_nginx}" >/dev/null ||
    fail 'Web download route must use the mounted Gateway CA file'
  grep -F '"~^/(?:dashboard/)?assets/[^/]+-[-_A-Za-z0-9]{8,}\.[^/]+$"' "${web_nginx}" >/dev/null ||
    fail 'Web hashed-asset regex is not a single quoted Nginx map key'
}

check_control_security_runtime_wiring() {
  grep -F 'OPENRESTY_SECURITY_SECRET_KEY_BASE64: ${OPENRESTY_SECURITY_SECRET_KEY_BASE64:' "${compose}" >/dev/null ||
    fail 'Control API OpenResty security secret is not mapped from runtime.env'
  generated_keys=$(grep -Fc "printf 'OPENRESTY_SECURITY_SECRET_KEY_BASE64=%s\\n'" "${runner}" || true)
  [ "${generated_keys}" -eq 2 ] || fail 'OpenResty security secret must be generated for new and legacy local state'
  grep -F 'mv "$migrated_env" "$runtime_env"' "${runner}" >/dev/null ||
    fail 'legacy runtime.env migration is not atomic'
  grep -F 'web_address=$(compose port web 8080)' "${runner}" >/dev/null ||
    fail 'ready message does not resolve the actual Web port'
}

check_analytics_nats_identity_wiring() {
  local js_permission_count publisher_block setting
  for setting in \
    'NATS_PREPROVISION_USERNAME: ${NATS_PREPROVISION_USERNAME:?set NATS_PREPROVISION_USERNAME}' \
    'NATS_PREPROVISION_PASSWORD: "\"${NATS_PREPROVISION_PASSWORD:?set NATS_PREPROVISION_PASSWORD}\""' \
    'NATS_CONTROL_CONSUMER_USERNAME: ${NATS_CONTROL_CONSUMER_USERNAME:?set NATS_CONTROL_CONSUMER_USERNAME}' \
    'NATS_CONTROL_CONSUMER_PASSWORD: "\"${NATS_CONTROL_CONSUMER_PASSWORD:?set NATS_CONTROL_CONSUMER_PASSWORD}\""' \
    'NATS_GATEWAY_PUBLISHER_USERNAME: ${NATS_GATEWAY_PUBLISHER_USERNAME:?set NATS_GATEWAY_PUBLISHER_USERNAME}' \
    'NATS_GATEWAY_PUBLISHER_PASSWORD: "\"${NATS_GATEWAY_PUBLISHER_PASSWORD:?set NATS_GATEWAY_PUBLISHER_PASSWORD}\""'; do
    grep -F "$setting" "$infra_compose" >/dev/null || fail "analytics NATS broker identity wiring is missing: ${setting%%:*}"
  done
  grep -F 'ANALYTICS_INGEST_NATS_USER: ${NATS_CONTROL_CONSUMER_USERNAME:' "$compose" >/dev/null ||
    fail 'Control analytics ingest does not use its dedicated consumer username'
  grep -F 'ANALYTICS_INGEST_NATS_PASSWORD: ${NATS_CONTROL_CONSUMER_PASSWORD:' "$compose" >/dev/null ||
    fail 'Control analytics ingest does not use its dedicated consumer password'
  grep -F 'ANALYTICS_CONNECTIONS_NATS_USER: ${NATS_CONTROL_CONSUMER_USERNAME:' "$compose" >/dev/null ||
    fail 'Control connections ingest does not use its dedicated consumer username'
  grep -F 'ANALYTICS_CONNECTIONS_NATS_PASSWORD: ${NATS_CONTROL_CONSUMER_PASSWORD:' "$compose" >/dev/null ||
    fail 'Control connections ingest does not use its dedicated consumer password'
  grep -F 'user: $NATS_CONTROL_CONSUMER_USERNAME' "$nats_config" >/dev/null ||
    fail 'analytics NATS config omits the Control consumer identity'
  grep -F 'user: $NATS_GATEWAY_PUBLISHER_USERNAME' "$nats_config" >/dev/null ||
    fail 'analytics NATS config omits the Gateway publisher identity'
  publisher_block=$(sed -n '/user: \$NATS_GATEWAY_PUBLISHER_USERNAME/,/subscribe: \["_INBOX\.>"\]/p' "$nats_config")
  [ -n "$publisher_block" ] || fail 'analytics NATS Gateway publisher ACL block is missing'
  for setting in \
    '$JS.API.STREAM.INFO.ANALYTICS_INGEST_V1' \
    '$JS.API.STREAM.INFO.SECURITY_CC_COORDINATION_V1' \
    '$JS.API.STREAM.INFO.CONNECTIONS_INGEST_V1' \
    '$JS.API.STREAM.INFO.L4_SESSIONS_INGEST_V1'; do
    grep -F "\"$setting\"" <<<"$publisher_block" >/dev/null ||
      fail "Gateway publisher stream readiness permission is missing: ${setting}"
  done
  js_permission_count=$(grep -Fc '"$JS.API.' <<<"$publisher_block")
  [ "$js_permission_count" -eq 4 ] || fail 'Gateway publisher has an unexpected JetStream API permission'
  if grep -F '$JS.API.' <<<"$publisher_block" | grep -Eq '[*>]|\.(CREATE|UPDATE|DELETE|PURGE|CONSUMER)\.'; then
    fail 'Gateway publisher has wildcard, management, or consumer JetStream API access'
  fi
  if grep -Eq 'NATS_(RUNTIME|PUBLISHER)_(USERNAME|PASSWORD)' "$infra_compose" "$compose" "$nats_config"; then
    fail 'legacy generic analytics NATS identity or fallback is still wired'
  fi
  if grep -Eq 'CDNCA_TELEMETRY_NATS_(USER|PASSWORD):.*NATS_CONTROL_CONSUMER' "$compose"; then
    fail 'Gateway telemetry reuses the Control analytics consumer identity'
  fi
  if grep -Eq '^  agent-gateway:$' "$compose"; then
    grep -F 'CDNCA_TELEMETRY_NATS_USER: ${NATS_GATEWAY_PUBLISHER_USERNAME:' "$compose" >/dev/null ||
      fail 'Gateway telemetry does not use its dedicated publisher username'
    grep -F 'CDNCA_TELEMETRY_NATS_PASSWORD: ${NATS_GATEWAY_PUBLISHER_PASSWORD:' "$compose" >/dev/null ||
      fail 'Gateway telemetry does not use its dedicated publisher password'
  fi
  if grep -Eq 'NATS_(CONTROL_CONSUMER|GATEWAY_PUBLISHER)_(USERNAME|PASSWORD)' "$nats_preprovision"; then
    fail 'analytics preprovision script can access a runtime workload identity'
  fi
}

check_gateway_runtime_wiring() {
  local gateway_block installer_block setting
  gateway_block=$(sed -n '/^  agent-gateway:/,/^  web:/p' "$compose")
  installer_block=$(sed -n '/^  gateway-secrets-install:/,/^  control-migrate:/p' "$compose")
  [ -n "$gateway_block" ] || fail 'agent-gateway Compose service is missing'
  [ -n "$installer_block" ] || fail 'Gateway secret installer is missing'
  for setting in \
    'dockerfile: services/agent-gateway/Dockerfile' \
    'CDNCA_CONTROL_ADDRESS: control-api:9090' \
    'CDNCA_GATEWAY_AGENT_CLIENT_CA_FILE: /run/gateway-secrets/node-ca-cert.pem' \
    'CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN: spiffe://cdnca/local/agent-gateway' \
    'CDNCA_NATS_URL: nats://${EDGE_NATS_USERNAME:' \
    '@edge-nats:4222' \
    'CDNCA_TELEMETRY_NATS_URL: tls://analytics-nats-tls:4222' \
    'CDNCA_TELEMETRY_NATS_USER: ${NATS_GATEWAY_PUBLISHER_USERNAME:' \
    'CDNCA_TELEMETRY_NATS_PASSWORD: ${NATS_GATEWAY_PUBLISHER_PASSWORD:' \
    'SSL_CERT_FILE: /run/gateway-secrets/root-ca-cert.pem' \
    'test: ["CMD", "/healthcheck"]' \
    'gateway_secrets:/run/gateway-secrets:ro'; do
    grep -F "$setting" <<<"$gateway_block" >/dev/null || fail "agent-gateway wiring is missing: ${setting}"
  done
  for dependency in gateway-secrets-install redis edge-nats-preprovision nats-analytics-preprovision analytics-nats-tls control-ready; do
    grep -F "${dependency}:" <<<"$gateway_block" >/dev/null || fail "agent-gateway dependency is missing: ${dependency}"
  done
  if grep -Eq 'local_secrets|node-ca-key|control-installation|gateway-client-ca-key|root-ca-key' <<<"$gateway_block"; then
    fail 'agent-gateway can access a control-plane private key outside its runtime identity'
  fi
  grep -F 'network_mode: "none"' <<<"$installer_block" >/dev/null || fail 'Gateway secret installer must not have network access'
  grep -F 'gateway_secrets:/target' <<<"$installer_block" >/dev/null || fail 'Gateway secret installer does not target the dedicated volume'
  for file in gateway-server-cert.pem gateway-server-key.pem node-ca-cert.pem \
    gateway-control-client-cert.pem gateway-control-client-key.pem root-ca-cert.pem; do
    grep -F "$file" <<<"$installer_block" >/dev/null || fail "Gateway secret installer omits ${file}"
  done
  if grep -F 'cp -p /source/*' <<<"$installer_block" >/dev/null; then
    fail 'Gateway secret installer copies the whole control-plane secret directory'
  fi
}

check_transport_proxy_wiring() {
  local analytics_config clickhouse_config fake_bin refresh_output resolver_count revision_count
  local state tmp_root true_path
  tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-transport-proxy.XXXXXX")
  transport_proxy_tmp_root=$tmp_root
  trap 'find "$transport_proxy_tmp_root" -depth -delete 2>/dev/null || true' EXIT
  state="${tmp_root}/state"
  fake_bin="${tmp_root}/bin"
  mkdir -p "$fake_bin"
  true_path=$(type -P true)
  ln -s "$true_path" "${fake_bin}/docker"

  refresh_output=$(PATH="${fake_bin}:${PATH}" LOCAL_STACK_STATE_DIR="$state" \
    LOCAL_STACK_ENV_FILE="${repo_root}/infra/env/development.env" "$runner" config 2>&1) ||
    fail 'transport proxy material generation failed'
  [ -z "$refresh_output" ] || fail 'transport proxy material generation wrote generated material to output'
  assert_analytics_nats_credentials "${state}/runtime.env"
  assert_gateway_pki "${state}/secrets"
  grep -qx -- '-----BEGIN PRIVATE KEY-----' "${state}/secrets/plugin-webhook-attestation-key.pem" ||
    fail 'plugin webhook attestation key was not generated'

  analytics_config="${state}/secrets/analytics-nats-haproxy.cfg"
  clickhouse_config="${state}/secrets/clickhouse-haproxy.cfg"
  for config in "$analytics_config" "$clickhouse_config"; do
    [ -s "$config" ] || fail "generated transport proxy config is missing: ${config##*/}"
    grep -F 'nameserver embedded_dns 127.0.0.11:53' "$config" >/dev/null ||
      fail "generated transport proxy does not use Docker embedded DNS: ${config##*/}"
    grep -F 'hold valid 2s' "$config" >/dev/null ||
      fail "generated transport proxy does not refresh valid DNS answers: ${config##*/}"
  done
  grep -F 'server analytics_nats nats:4222 check resolvers docker resolve-prefer ipv4 init-addr libc,none' \
    "$analytics_config" >/dev/null || fail 'analytics NATS proxy backend is not dynamically resolved'
  grep -F 'bind :4222 ssl crt /run/local-secrets/analytics-nats-haproxy.pem' "$analytics_config" >/dev/null ||
    fail 'analytics NATS external transport is not TLS terminated'
  grep -F 'server clickhouse clickhouse:8123 check resolvers docker resolve-prefer ipv4 init-addr libc,none' \
    "$clickhouse_config" >/dev/null || fail 'ClickHouse proxy backend is not dynamically resolved'
  resolver_count=$(awk '/^resolvers docker$/ { count++ } END { print count + 0 }' \
    "$analytics_config" "$clickhouse_config")
  [ "$resolver_count" -eq 2 ] || fail 'both transport proxies must define Docker DNS resolvers'

  printf 'stale\n' >"$analytics_config"
  printf 'stale\n' >"$clickhouse_config"
  refresh_output=$(PATH="${fake_bin}:${PATH}" LOCAL_STACK_STATE_DIR="$state" \
    LOCAL_STACK_ENV_FILE="${repo_root}/infra/env/development.env" "$runner" config 2>&1) ||
    fail 'existing transport proxy material refresh failed'
  [ -z "$refresh_output" ] || fail 'transport proxy material refresh wrote generated material to output'
  grep -F 'resolvers docker' "$analytics_config" >/dev/null || fail 'existing analytics NATS proxy config is not refreshed'
  grep -F 'resolvers docker' "$clickhouse_config" >/dev/null || fail 'existing ClickHouse proxy config is not refreshed'

  grep -Eq '^tls[[:space:]]*\{[[:space:]]*\}$' "$nats_config" ||
    fail 'analytics NATS does not advertise TLS availability behind the terminating proxy'
  grep -Eq '^allow_non_tls:[[:space:]]*true$' "$nats_config" ||
    fail 'analytics NATS internal plaintext boundary is not explicit'
  grep -F 'NATS_URL: nats://nats:4222' "$infra_compose" >/dev/null ||
    fail 'analytics preprovision does not use the project-internal plaintext endpoint'
  grep -F '"127.0.0.1:${NATS_CLIENT_PORT:-4222}:4222"' "$infra_compose" >/dev/null ||
    fail 'analytics NATS plaintext host port is not loopback-only'
  grep -F 'ANALYTICS_INGEST_NATS_URL: tls://analytics-nats-tls:4222' "$compose" >/dev/null ||
    fail 'Control analytics ingest does not use the TLS endpoint'
  revision_count=$(awk '/io\.cdnca\.local\.transport-revision: "2"/ { count++ } END { print count + 0 }' \
    "$infra_compose" "$compose")
  [ "$revision_count" -eq 4 ] || fail 'transport config revision does not recreate all affected local services once'

  find "$tmp_root" -depth -delete
  transport_proxy_tmp_root=
  trap - EXIT
}

check_legacy_runtime_migration() {
  local after_without_generated decoded_bytes fake_bin key_count key_value migration_output mode
  local state tmp_root true_path
  tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-ready-v1.XXXXXX")
  migration_tmp_root=$tmp_root
  trap 'find "$migration_tmp_root" -depth -delete 2>/dev/null || true' EXIT
  state="${tmp_root}/state"
  fake_bin="${tmp_root}/bin"
  mkdir -p "${state}/secrets" "$fake_bin"
  seed_gateway_authorities "${state}/secrets"
  true_path=$(type -P true)
  ln -s "$true_path" "${fake_bin}/docker"
  : >"${state}/.ready-v1"
  printf '%s\n' \
    'PRESERVE_ONE=alpha' \
    'PRESERVE_TWO=beta' \
    'NATS_RUNTIME_USERNAME=legacy-runtime' \
    'NATS_RUNTIME_PASSWORD=legacy-runtime-password' \
    'NATS_PUBLISHER_USERNAME=legacy-publisher' \
    'NATS_PUBLISHER_PASSWORD=legacy-publisher-password' >"${state}/runtime.env"
  chmod 0600 "${state}/.ready-v1" "${state}/runtime.env"
  cp "${state}/runtime.env" "${tmp_root}/before.env"

  migration_output=$(PATH="${fake_bin}:${PATH}" LOCAL_STACK_STATE_DIR="$state" \
    LOCAL_STACK_ENV_FILE="${repo_root}/infra/env/development.env" "$runner" config 2>&1) ||
    fail 'legacy .ready-v1 runtime migration failed'
  [ -z "$migration_output" ] || fail 'legacy runtime migration wrote generated material to output'

  key_count=$(grep -c '^OPENRESTY_SECURITY_SECRET_KEY_BASE64=' "${state}/runtime.env" || true)
  [ "$key_count" -eq 1 ] || fail 'legacy runtime migration must add exactly one OpenResty security key'
  assert_analytics_nats_credentials "${state}/runtime.env"
  assert_gateway_pki "${state}/secrets"
  grep -Ev '^(OPENRESTY_SECURITY_SECRET_KEY_BASE64|NATS_PREPROVISION_(USERNAME|PASSWORD)|NATS_CONTROL_CONSUMER_(USERNAME|PASSWORD)|NATS_GATEWAY_PUBLISHER_(USERNAME|PASSWORD))=' \
    "${state}/runtime.env" >"${tmp_root}/after-without-generated.env"
  after_without_generated="${tmp_root}/after-without-generated.env"
  cmp -s "${tmp_root}/before.env" "$after_without_generated" ||
    fail 'legacy runtime migration changed existing runtime values'
  key_value=$(sed -n 's/^OPENRESTY_SECURITY_SECRET_KEY_BASE64=//p' "${state}/runtime.env")
  [[ "$key_value" =~ ^[A-Za-z0-9+/]{43}=$ ]] ||
    fail 'legacy runtime migration did not generate canonical Base64'
  decoded_bytes=$(printf '%s' "$key_value" | openssl base64 -d -A | wc -c | tr -d ' ')
  [ "$decoded_bytes" -eq 32 ] || fail 'legacy runtime migration key is not 32 bytes'
  mode=$(file_mode "${state}/runtime.env")
  [ "$mode" = 600 ] || fail 'legacy runtime migration did not preserve owner-only permissions'
  [ -z "$(find "$state" -maxdepth 1 -name '.runtime.env.*' -print -quit)" ] ||
    fail 'legacy runtime migration left a temporary file'
  [ -z "$(find "$state" -maxdepth 1 -name '.gateway-pki.*' -print -quit)" ] ||
    fail 'legacy Gateway PKI migration left a temporary directory'

  cp "${state}/runtime.env" "${tmp_root}/after-first.env"
  mkdir "${tmp_root}/gateway-pki-after-first"
  cp "${state}/secrets/gateway-server-cert.pem" "${state}/secrets/gateway-server-key.pem" \
    "${state}/secrets/gateway-control-client-cert.pem" "${state}/secrets/gateway-control-client-key.pem" \
    "${tmp_root}/gateway-pki-after-first/"
  migration_output=$(PATH="${fake_bin}:${PATH}" LOCAL_STACK_STATE_DIR="$state" \
    LOCAL_STACK_ENV_FILE="${repo_root}/infra/env/development.env" "$runner" config 2>&1) ||
    fail 'migrated .ready-v1 runtime could not be reused'
  [ -z "$migration_output" ] || fail 'migrated runtime reuse wrote generated material to output'
  cmp -s "${tmp_root}/after-first.env" "${state}/runtime.env" ||
    fail 'legacy runtime migration is not idempotent'
  for file in gateway-server-cert.pem gateway-server-key.pem \
    gateway-control-client-cert.pem gateway-control-client-key.pem; do
    cmp -s "${tmp_root}/gateway-pki-after-first/${file}" "${state}/secrets/${file}" ||
      fail 'legacy Gateway PKI migration is not idempotent'
  done

  find "$tmp_root" -depth -delete
  migration_tmp_root=
  trap - EXIT
}

for file in "${infra_compose}" "${compose}" "${clickhouse_migrate_compose}" "${runner}" "${notification_runbook}" "${nats_config}" "${web_nginx}"; do
  [ -f "${file}" ] || fail "missing ${file#"${repo_root}/"}"
done

case ${LOCAL_STACK_STATIC_SCOPE:-full} in
  notification)
    check_notification_runtime_wiring
    printf 'LOCAL_STACK_NOTIFICATION_STATIC PASS\n'
    exit 0
    ;;
  frontend)
    check_frontend_runtime_wiring
    printf 'LOCAL_STACK_FRONTEND_STATIC PASS\n'
    exit 0
    ;;
  startup)
    check_port_override_persistence
    check_frontend_runtime_wiring
    check_control_security_runtime_wiring
    check_analytics_nats_identity_wiring
    check_gateway_runtime_wiring
    check_transport_proxy_wiring
    check_legacy_runtime_migration
    printf 'LOCAL_STACK_STARTUP_STATIC PASS\n'
    exit 0
    ;;
  ports)
    check_port_override_persistence
    printf 'LOCAL_STACK_PORTS_STATIC PASS\n'
    exit 0
    ;;
  full) check_port_override_persistence ;;
  *) fail 'LOCAL_STACK_STATIC_SCOPE must be full, notification, frontend, startup, or ports' ;;
esac

grep -Eq '^up:[[:space:]]*$' "${makefile}" || fail 'Makefile up target is missing'
grep -Eq '^[[:space:]]*LOCAL_STACK_ENV_FILE="\$\(ENV_FILE\)" ./scripts/local-stack\.sh up$' "${makefile}" ||
  fail 'make up does not invoke the full-stack owner'
for target in down status logs; do
  grep -Eq "^${target}:[[:space:]]*$" "${makefile}" || fail "Makefile ${target} target is missing"
  grep -Eq "^[[:space:]]*LOCAL_STACK_ENV_FILE=\"\\\$\\(ENV_FILE\\)\" ./scripts/local-stack\\.sh ${target}$" "${makefile}" ||
    fail "make ${target} does not invoke the full-stack owner"
done
grep -Eq '^infra-up:[[:space:]]*$' "${makefile}" || fail 'explicit infrastructure-only target is missing'

for service in postgres-bootstrap gateway-secrets-install control-migrate edge-nats \
  edge-nats-preprovision mailpit control-api agent-gateway web; do
  grep -Eq "^  ${service}:$" "${compose}" || fail "compose service ${service} is missing"
done
# cdncaCE: the license service and operator console are not part of this
# repository; control-api talks to an external license service instead.
for service in license-migrate license-service license-ready operator-console control-install-community; do
  if grep -Eq "^  ${service}:$" "${compose}"; then
    fail "compose still defines the removed ${service} service"
  fi
done
if grep -Eq 'cdnca_license|license-service|operator-console|LICENSE_(SIGNING|TOTP|CREDENTIAL|IDENTITY|BILLING|SIGNER|RUNTIME|CALLBACK)' "${compose}" "${runner}"; then
  fail 'local stack still wires the removed license service or operator console'
fi
if grep -Eq 'license-signing-key|offline-root-key' "${runner}"; then
  fail 'local stack still generates license-service-only signing material'
fi
control_block=$(sed -n '/^  control-api:/,/^  control-ready:/p' "${compose}")
for setting in \
  'LICENSE_SERVICE_URL: ${LICENSE_SERVICE_URL:-}' \
  'ENTITLEMENT_TRUSTED_KEYS_FILE: ${ENTITLEMENT_TRUSTED_KEYS_FILE:-}' \
  'CONTROL_INSTALLATION_ID: ${CONTROL_INSTALLATION_ID:-' \
  'CONTROL_INSTALLATION_NAME: ${CONTROL_INSTALLATION_NAME:-' \
  'CONTROL_INSTALLATION_PRIVATE_KEY_FILE: /run/local-secrets/control-installation-key.pem'; do
  grep -F "${setting}" <<<"${control_block}" >/dev/null || fail "control-api license wiring is missing: ${setting}"
done
grep -F 'control-migrate:' <<<"${control_block}" >/dev/null || fail 'control-api does not wait for control migrations'
for key in LICENSE_SERVICE_URL ENTITLEMENT_TRUSTED_KEYS_FILE CONTROL_INSTALLATION_ID CONTROL_INSTALLATION_NAME; do
  grep -Eq "^${key}=" "${repo_root}/infra/env/development.env" || fail "development.env does not declare ${key}"
done
grep -Eq '^LICENSE_SERVICE_URL=$' "${repo_root}/infra/env/development.env" ||
  fail 'development.env must not point at a license service by default'
grep -F 'control-api install-entitlement' "${repo_root}/infra/env/development.env" >/dev/null ||
  fail 'development.env does not explain importing a community entitlement'
grep -F 'openssl genpkey -algorithm ED25519 -out "${secrets}/control-installation-key.pem"' "${runner}" >/dev/null ||
  fail 'control-api installation identity key is not generated'
grep -F 'compose run --rm --no-deps control-api install-entitlement' "${runner}" >/dev/null ||
  fail 'runner does not import entitlements through control-api install-entitlement'
grep -F 'ENTITLEMENT_TRUSTED_KEYS_FILE=/run/local-secrets/entitlement-trusted-keys.json' "${runner}" >/dev/null ||
  fail 'runner does not wire imported trusted keys into control-api'
grep -F 'feature gates deny requests until one is (expected)' "${runner}" >/dev/null ||
  fail 'runner does not explain the missing-entitlement state'
grep -F "SELECT 'CREATE ROLE cdnca_control_runtime NOLOGIN'" "${compose}" >/dev/null ||
  fail 'postgres-bootstrap does not create the cdnca_control_runtime role required by migrations'

grep -F 'condition: service_completed_successfully' "${compose}" >/dev/null ||
  fail 'migration/startup ordering is not fail-closed'
grep -F 'services/control-api/Dockerfile' "${compose}" >/dev/null || fail 'control-api production image is not used'
grep -F 'services/agent-gateway/Dockerfile' "${compose}" >/dev/null || fail 'agent-gateway production image is not used'
grep -F 'apps/web/Dockerfile' "${compose}" >/dev/null || fail 'web production image is not used'
# ClickHouse schema goes only through the ledgered migrator (f11-ch-deploy):
# compose.full.yaml defines no ClickHouse migrator of its own.
grep -F -- '-f "${repo_root}/deploy/compose/clickhouse-migrate.yaml"' "${runner}" >/dev/null ||
  fail 'runner does not apply the ledgered ClickHouse migrator'
if grep -Eq '^  clickhouse-migrate:$|clickhouse-client' "${compose}"; then
  fail 'compose.full.yaml defines an unledgered ClickHouse migration'
fi
grep -Fq 'clickhouse-migrate:' "${compose}" ||
  fail 'control-api no longer waits for the ClickHouse migrator'
if grep -Eq '!reset|!override' "${clickhouse_migrate_compose}"; then
  fail 'ledgered ClickHouse migrator still overrides a removed compose.full.yaml service'
fi
grep -Eq '^  clickhouse-migrate:$' "${clickhouse_migrate_compose}" ||
  fail 'ledgered ClickHouse migrator service is missing'
grep -F 'dockerfile: deploy/clickhouse-migrate/Dockerfile' "${clickhouse_migrate_compose}" >/dev/null ||
  fail 'ClickHouse migrator is not built from deploy/clickhouse-migrate/Dockerfile'
grep -F '/opt/cdnca/clickhouse/cdnca-clickhouse-migrate.py' "${clickhouse_migrate_compose}" >/dev/null ||
  fail 'ClickHouse migrator does not run cdnca-clickhouse-migrate.py'
grep -F 'COPY infra/clickhouse/migrations/ /opt/cdnca/clickhouse/migrations/' \
  "${repo_root}/deploy/clickhouse-migrate/Dockerfile" >/dev/null ||
  fail 'ClickHouse migrator image does not carry infra/clickhouse/migrations'
grep -Eq 'CONTROL_INTERNAL_SERVER_CERT_FILE([=:][[:space:]]*)/run/local-secrets/control-server-cert.pem' "${compose}" ||
  fail 'ControlInternal generated TLS material is not wired'
grep -Eq 'NODE_CA_PRIVATE_KEY_FILE([=:][[:space:]]*)/run/local-secrets/node-ca-key.pem' "${compose}" ||
  fail 'generated node CA is not wired'
grep -Eq 'PLUGIN_WEBHOOK_ATTESTATION_PRIVATE_KEY_FILE([=:][[:space:]]*)/run/local-secrets/plugin-webhook-attestation-key.pem' "${compose}" ||
  fail 'generated plugin webhook attestation key is not wired'
check_notification_runtime_wiring
check_frontend_runtime_wiring
check_control_security_runtime_wiring
check_analytics_nats_identity_wiring
check_gateway_runtime_wiring
check_transport_proxy_wiring
check_legacy_runtime_migration
grep -F 'ANALYTICS_INGEST_ENABLED: ${ANALYTICS_INGEST_ENABLED:-true}' "${compose}" >/dev/null ||
  fail 'analytics ingest runtime is not enabled'
grep -F 'ANALYTICS_CONNECTIONS_RUNTIME_ENABLED: ${ANALYTICS_CONNECTIONS_RUNTIME_ENABLED:-true}' "${compose}" >/dev/null ||
  fail 'analytics connections runtime is not enabled'
grep -F 'stop_grace_period: 30s' "${compose}" >/dev/null ||
  fail 'control API stop grace period does not cover the analytics operation and shutdown budgets'
grep -F 'ANALYTICS_QUERY_ENABLED: ${ANALYTICS_QUERY_ENABLED:-true}' "${compose}" >/dev/null ||
  fail 'analytics query runtime is not enabled'

grep -F 'umask 077' "${runner}" >/dev/null || fail 'generated material does not default to owner-only access'
grep -F 'openssl rand' "${runner}" >/dev/null || fail 'development secrets are not generated cryptographically'
grep -F 'openssl req' "${runner}" >/dev/null || fail 'development certificates are not generated'
grep -F 'com.docker.compose.project' "${runner}" >/dev/null || fail 'cleanup does not verify task ownership labels'
grep -F 'docker compose' "${runner}" >/dev/null || fail 'runner does not use Compose'
grep -F 'compose.yaml' "${runner}" >/dev/null || fail 'runner does not include the infrastructure stack'
grep -F 'compose.full.yaml' "${runner}" >/dev/null || fail 'runner does not include the application stack'
if grep -Eq 'docker compose[^\n]*(down[^\n]*-v|rm[^\n]*-v)|docker volume (rm|prune)' "${runner}"; then
  fail 'runner contains destructive volume cleanup'
fi
for action in up down status logs; do
  grep -Eq "(^|[[:space:]|])${action}(\)|[[:space:]|])" "${runner}" || fail "runner action ${action} is missing"
done

grep -F 'location = /healthz' "${repo_root}/apps/web/nginx.conf" >/dev/null || fail 'web health endpoint is missing'
grep -F 'proxy_pass http://control-api:8080' "${repo_root}/apps/web/nginx.conf" >/dev/null ||
  fail 'web does not proxy the Control API'

grep -F 'make up' "${readme}" >/dev/null || fail 'README omits the one-command entrypoint'
grep -F '`make up` 会启动' "${readme}" >/dev/null || fail 'README does not describe the full local stack'

printf 'LOCAL_STACK_STATIC PASS\n'
