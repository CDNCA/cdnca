#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
unit_input="$script_dir/control-upgrade-runner.service"
install_root="${DESTDIR:-}"
systemctl_bin="${SYSTEMCTL_BIN:-systemctl}"
binary_input=""
binary_sha256=""
environment_input=""
unit_sha256=""
environment_sha256=""
temporary_paths=("")
sync_supports_file=false

fail() {
  printf 'control-upgrade-runner install: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local path
  for path in "${temporary_paths[@]}"; do
    [[ -n "$path" ]] && rm -rf -- "$path"
  done
}
trap cleanup EXIT

usage() {
  printf 'usage: %s --binary PATH --binary-sha256 HEX --environment PATH\n' "$0" >&2
  exit 2
}

root_path() {
  printf '%s%s' "$install_root" "$1"
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

stat_links() {
	stat -c '%h' "$1" 2>/dev/null || stat -f '%l' "$1"
}

stat_mode() {
	stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

stat_uid() {
	stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1"
}

sync_path() {
	if [[ "$sync_supports_file" == "true" ]]; then
		sync -f "$1"
	else
		sync
	fi
}

assert_absolute_path() {
  local value="$1" label="$2"
  [[ "$value" == /* && "$value" != *//* && "$value" != */./* && "$value" != */../* && "$value" != */ ]] ||
    fail "$label must be a normalized absolute path"
}

assert_regular_input() {
  local path="$1" label="$2" mode links permission
  assert_absolute_path "$path" "$label"
  [[ -f "$path" && ! -L "$path" && -r "$path" ]] || fail "$label must be a readable regular file"
	links="$(stat_links "$path")"
	mode="$(stat_mode "$path")"
  [[ "$links" == "1" && "$mode" =~ ^[0-7]{3,4}$ ]] || fail "$label metadata is unsafe"
  permission=$((8#$mode))
  (( (permission & 8#022) == 0 )) || fail "$label must not be group/world writable"
}

assert_bound_file() {
  local configured="$1" label="$2" secret="$3" path mode owner links permission
  assert_absolute_path "$configured" "$label"
  path="$(root_path "$configured")"
  [[ -f "$path" && ! -L "$path" && -r "$path" ]] || fail "$label must be a readable regular file"
	owner="$(stat_uid "$path")"
	links="$(stat_links "$path")"
	mode="$(stat_mode "$path")"
  [[ "$owner" == "$EUID" && "$links" == "1" && "$mode" =~ ^[0-7]{3,4}$ ]] || fail "$label metadata is unsafe"
  permission=$((8#$mode))
  (( (permission & 8#022) == 0 )) || fail "$label must not be group/world writable"
  if [[ "$secret" == "true" ]]; then
    (( (permission & 8#077) == 0 )) || fail "$label must be owner-only"
  fi
}

env_value() {
  local key="$1" count value
  count="$(awk -F= -v key="$key" '$1==key {count++} END {print count+0}' "$environment_input")"
  [[ "$count" == "1" ]] || fail "environment key $key must occur exactly once"
  value="$(awk -F= -v key="$key" '$1==key {sub(/^[^=]*=/, ""); print}' "$environment_input")"
  [[ -n "$value" ]] || fail "environment key $key is empty"
  printf '%s' "$value"
}

validate_https_url_path() {
  local value="$1" expected_path="$2" label="$3" remainder authority path
  [[ "$value" == https://* && "$value" != *'?'* && "$value" != *'#'* && "$value" != *'@'* ]] ||
    fail "$label must use a fixed HTTPS URL"
  remainder="${value#https://}"
  [[ "$remainder" == */* ]] || fail "$label is missing a path"
  authority="${remainder%%/*}"
  path="/${remainder#*/}"
  [[ "$authority" =~ ^[A-Za-z0-9.-]+(:[0-9]{1,5})?$ && "$path" == "$expected_path" ]] ||
    fail "$label authority or path is invalid"
}

validate_environment() {
	local line key value path expected_replicas quorum maximum ca_file cert_file key_file cert_public key_public token_bytes
  local required_keys=(
    CONTROL_UPGRADE_TARGET CONTROL_UPGRADE_INSTALLATION_ID_FILE CONTROL_UPGRADE_TRUST_FILE
    CONTROL_UPGRADE_INTERNAL_TOKEN_FILE CONTROL_UPGRADE_PLAN_SOURCE_URL
    CONTROL_UPGRADE_PLAN_SOURCE_CA_FILE CONTROL_UPGRADE_PLAN_SOURCE_CERT_FILE
    CONTROL_UPGRADE_PLAN_SOURCE_KEY_FILE CONTROL_UPGRADE_PLAN_SOURCE_TIMEOUT
    CONTROL_UPGRADE_PLAN_SOURCE_MAX_BYTES CONTROL_UPGRADE_POLL_INTERVAL
    CONTROL_UPGRADE_EXPECTED_REPLICAS CONTROL_UPGRADE_QUORUM CONTROL_UPGRADE_STATE_DIR
    CONTROL_UPGRADE_PLAN_LKG_FILE CONTROL_UPGRADE_RELEASE_ROOT CONTROL_UPGRADE_CURRENT_LINK
    CONTROL_UPGRADE_SYSTEMD_UNIT CONTROL_UPGRADE_DRAIN_URL CONTROL_UPGRADE_RESUME_URL
    CONTROL_UPGRADE_HEALTH_URL CONTROL_UPGRADE_CURRENT_VERSION CONTROL_UPGRADE_PROTOCOL_VERSION
    CONTROL_UPGRADE_STEP_TIMEOUT CONTROL_UPGRADE_HEALTH_TIMEOUT
  )

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" == \#* || "$line" =~ ^[A-Z0-9_]+=[^[:space:]]+$ ]] ||
      fail "environment contains an invalid line"
  done <"$environment_input"
  if grep -Eq '^(CONTROL_UPGRADE_(INTERNAL_TOKEN|.*PASSWORD|.*SECRET|.*PRIVATE_KEY))=' "$environment_input"; then
    fail "environment must contain credential paths, never credential values"
  fi
  for key in "${required_keys[@]}"; do
    env_value "$key" >/dev/null
  done
  [[ "$(env_value CONTROL_UPGRADE_TARGET)" == "systemd" ]] || fail "CONTROL_UPGRADE_TARGET must be systemd"

  for key in CONTROL_UPGRADE_INSTALLATION_ID_FILE CONTROL_UPGRADE_TRUST_FILE CONTROL_UPGRADE_INTERNAL_TOKEN_FILE \
    CONTROL_UPGRADE_PLAN_SOURCE_CA_FILE CONTROL_UPGRADE_PLAN_SOURCE_CERT_FILE CONTROL_UPGRADE_PLAN_SOURCE_KEY_FILE; do
    value="$(env_value "$key")"
    case "$key" in
      CONTROL_UPGRADE_INTERNAL_TOKEN_FILE|CONTROL_UPGRADE_PLAN_SOURCE_KEY_FILE)
        assert_bound_file "$value" "$key" true
        ;;
      *)
        assert_bound_file "$value" "$key" false
        ;;
    esac
  done

  path="$(root_path "$(env_value CONTROL_UPGRADE_INSTALLATION_ID_FILE)")"
  grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' "$path" ||
    fail "installation ID is not a canonical UUID"
	path="$(root_path "$(env_value CONTROL_UPGRADE_INTERNAL_TOKEN_FILE)")"
	token_bytes="$(wc -c <"$path" | tr -d '[:space:]')"
	if ! [[ "$token_bytes" =~ ^[0-9]+$ ]] || ! (( token_bytes >= 32 && token_bytes <= 256 )) ||
		! LC_ALL=C grep -Eq '^[!-~]+$' "$path"; then
		fail "internal token must be one bounded printable line"
	fi
	ca_file="$(root_path "$(env_value CONTROL_UPGRADE_PLAN_SOURCE_CA_FILE)")"
	cert_file="$(root_path "$(env_value CONTROL_UPGRADE_PLAN_SOURCE_CERT_FILE)")"
	key_file="$(root_path "$(env_value CONTROL_UPGRADE_PLAN_SOURCE_KEY_FILE)")"
	grep -Fq -- '-----BEGIN CERTIFICATE-----' "$ca_file" || fail "plan CA is not PEM"
	grep -Fq -- '-----BEGIN CERTIFICATE-----' "$cert_file" || fail "plan client certificate is not PEM"
	grep -Eq -- '^-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----$' "$key_file" || fail "plan client key is not PEM"
	openssl x509 -in "$ca_file" -noout >/dev/null 2>&1 || fail "plan CA certificate is invalid"
	openssl x509 -in "$cert_file" -noout >/dev/null 2>&1 || fail "plan client certificate is invalid"
	openssl pkey -in "$key_file" -check -noout >/dev/null 2>&1 || fail "plan client key is invalid"
	openssl verify -CAfile "$ca_file" "$cert_file" >/dev/null 2>&1 || fail "plan client certificate is not trusted by the configured CA"
	cert_public="$(openssl x509 -in "$cert_file" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
	key_public="$(openssl pkey -in "$key_file" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
	[[ -n "$cert_public" && "$cert_public" == "$key_public" ]] || fail "plan client certificate and key do not match"

  validate_https_url_path "$(env_value CONTROL_UPGRADE_PLAN_SOURCE_URL)" \
    /v1/internal/control-upgrade/plan CONTROL_UPGRADE_PLAN_SOURCE_URL
  validate_https_url_path "$(env_value CONTROL_UPGRADE_DRAIN_URL)" \
    /v1/internal/control-upgrade/drain CONTROL_UPGRADE_DRAIN_URL
  validate_https_url_path "$(env_value CONTROL_UPGRADE_RESUME_URL)" \
    /v1/internal/control-upgrade/resume CONTROL_UPGRADE_RESUME_URL
  validate_https_url_path "$(env_value CONTROL_UPGRADE_HEALTH_URL)" \
    /v1/internal/control-upgrade/health CONTROL_UPGRADE_HEALTH_URL

  for key in CONTROL_UPGRADE_PLAN_SOURCE_TIMEOUT CONTROL_UPGRADE_POLL_INTERVAL \
    CONTROL_UPGRADE_STEP_TIMEOUT CONTROL_UPGRADE_HEALTH_TIMEOUT; do
    [[ "$(env_value "$key")" =~ ^[1-9][0-9]*(ms|s|m)$ ]] || fail "$key is not a bounded duration"
  done
  maximum="$(env_value CONTROL_UPGRADE_PLAN_SOURCE_MAX_BYTES)"
	if ! [[ "$maximum" =~ ^[0-9]+$ ]] || ! (( maximum >= 1024 && maximum <= 2097152 )); then
		fail "CONTROL_UPGRADE_PLAN_SOURCE_MAX_BYTES is out of range"
	fi
  expected_replicas="$(env_value CONTROL_UPGRADE_EXPECTED_REPLICAS)"
  quorum="$(env_value CONTROL_UPGRADE_QUORUM)"
  [[ "$expected_replicas" =~ ^[0-9]+$ && "$quorum" =~ ^[0-9]+$ ]] || fail "HA values must be integers"
  (( expected_replicas >= 2 && quorum <= expected_replicas && quorum > expected_replicas / 2 )) ||
    fail "systemd HA requires at least two replicas and a strict-majority quorum"
  [[ "$(env_value CONTROL_UPGRADE_PROTOCOL_VERSION)" =~ ^[1-9][0-9]*$ ]] || fail "protocol version is invalid"
  [[ "$(env_value CONTROL_UPGRADE_CURRENT_VERSION)" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$ ]] ||
    fail "current version is invalid"

  [[ "$(env_value CONTROL_UPGRADE_STATE_DIR)" == "/var/lib/cdnca-control-upgrade/state" &&
     "$(env_value CONTROL_UPGRADE_PLAN_LKG_FILE)" == "/var/lib/cdnca-control-upgrade/lkg/plan.bundle" &&
     "$(env_value CONTROL_UPGRADE_RELEASE_ROOT)" == "/opt/cdnca/control-api/releases" &&
     "$(env_value CONTROL_UPGRADE_CURRENT_LINK)" == "/opt/cdnca/control-api/current" &&
     "$(env_value CONTROL_UPGRADE_SYSTEMD_UNIT)" == "cdnca-control-api.service" ]] ||
    fail "state, LKG, release, current link, or unit binding is invalid"
}

control_upgrade_runner_preflight() {
  local dependency
  [[ -n "$install_root" || "$EUID" == "0" ]] || fail "root is required without DESTDIR"
  if [[ -n "$install_root" ]]; then
    [[ "$install_root" == /* && "$install_root" != "/" && "$install_root" != */ && ! -L "$install_root" ]] ||
      fail "DESTDIR must be a non-root normalized absolute directory"
    [[ -d "$install_root" ]] || fail "DESTDIR does not exist"
  fi
	for dependency in awk cmp grep install mktemp mv openssl rm sha256sum stat sync tr wc; do
    require_command "$dependency"
  done
	if [[ "$systemctl_bin" == */* ]]; then
		[[ -x "$systemctl_bin" ]] || fail "SYSTEMCTL_BIN is not executable"
	else
		systemctl_bin="$(type -P -- "$systemctl_bin")"
		[[ -n "$systemctl_bin" ]] || fail "systemctl is unavailable"
  fi
  assert_regular_input "$binary_input" "runner binary"
  assert_regular_input "$environment_input" "environment input"
  assert_regular_input "$unit_input" "unit input"
  [[ "$binary_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "binary SHA-256 is invalid"
	[[ "$(sha256sum "$binary_input" | awk '{print $1}')" == "$binary_sha256" ]] || fail "runner binary SHA-256 mismatch"
	if sync -f "$binary_input" 2>/dev/null; then
		sync_supports_file=true
	fi
  unit_sha256="$(sha256sum "$unit_input" | awk '{print $1}')"
  environment_sha256="$(sha256sum "$environment_input" | awk '{print $1}')"
  validate_environment
}

control_upgrade_runner_install_atomic() {
  local input="$1" target="$2" mode="$3" parent temporary
  parent="$(dirname -- "$target")"
  temporary="$(mktemp "$parent/.control-upgrade-install.XXXXXX")"
  temporary_paths+=("$temporary")
  install -m "$mode" "$input" "$temporary"
	sync_path "$temporary"
	if ! mv -Tf "$temporary" "$target" 2>/dev/null; then
		mv -f "$temporary" "$target"
	fi
	sync_path "$parent"
}

systemctl() {
  "$systemctl_bin" "$@"
}

commit_install() {
  local staging_parent staging binary_target environment_target unit_target
  staging_parent="$(root_path /var/lib/cdnca-control-upgrade/install-staging)"
  install -d -m 0755 "$(root_path /usr/local/libexec/cdnca)" "$(root_path /etc/cdnca)" \
    "$(root_path /etc/systemd/system)" "$(root_path /opt/cdnca/control-api/releases)"
  install -d -m 0700 "$(root_path /var/lib/cdnca-control-upgrade)" \
    "$(root_path /var/lib/cdnca-control-upgrade/state)" "$(root_path /var/lib/cdnca-control-upgrade/lkg)" \
    "$staging_parent"
  staging="$(mktemp -d "$staging_parent/.install.XXXXXX")"
  temporary_paths+=("$staging")
  install -m 0755 "$binary_input" "$staging/control-upgrade-runner"
  install -m 0600 "$environment_input" "$staging/control-upgrade-runner.env"
  install -m 0644 "$unit_input" "$staging/control-upgrade-runner.service"
	[[ "$(sha256sum "$staging/control-upgrade-runner" | awk '{print $1}')" == "$binary_sha256" ]] ||
		fail "staged runner binary changed"
  [[ "$(sha256sum "$staging/control-upgrade-runner.env" | awk '{print $1}')" == "$environment_sha256" ]] ||
    fail "staged environment changed"
  [[ "$(sha256sum "$staging/control-upgrade-runner.service" | awk '{print $1}')" == "$unit_sha256" ]] ||
    fail "staged unit changed"

  binary_target="$(root_path /usr/local/libexec/cdnca/control-upgrade-runner)"
  environment_target="$(root_path /etc/cdnca/control-upgrade-runner.env)"
  unit_target="$(root_path /etc/systemd/system/cdnca-control-upgrade-runner.service)"
  control_upgrade_runner_install_atomic "$staging/control-upgrade-runner" "$binary_target" 0755
  control_upgrade_runner_install_atomic "$staging/control-upgrade-runner.env" "$environment_target" 0600
  control_upgrade_runner_install_atomic "$staging/control-upgrade-runner.service" "$unit_target" 0644
  systemctl daemon-reload
  systemctl enable cdnca-control-upgrade-runner.service
}

while (($# > 0)); do
  case "$1" in
    --binary)
      (($# >= 2)) || usage
      binary_input="$2"
      shift 2
      ;;
    --binary-sha256)
      (($# >= 2)) || usage
      binary_sha256="$2"
      shift 2
      ;;
    --environment)
      (($# >= 2)) || usage
      environment_input="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

[[ -n "$binary_input" && -n "$binary_sha256" && -n "$environment_input" ]] || usage
control_upgrade_runner_preflight
commit_install
printf 'control-upgrade-runner installed and enabled; service was not started\n'
