#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
unit="$root/deploy/systemd/control-upgrade-runner.service"
environment="$root/deploy/systemd/control-upgrade-runner.env.example"
installer="$root/deploy/systemd/install-control-upgrade-runner.sh"
runbook="$root/docs/runbooks/control-upgrade-systemd.md"

for required_file in "$unit" "$environment" "$installer" "$runbook"; do
  [[ -f "$required_file" ]] || { echo "missing $required_file" >&2; exit 1; }
done
[[ -x "$installer" ]] || { echo "installer is not executable" >&2; exit 1; }
bash -n "$installer"

for fragment in \
  'EnvironmentFile=/etc/cdnca/control-upgrade-runner.env' \
  "ExecStartPre=/usr/bin/test -s \${CONTROL_UPGRADE_INSTALLATION_ID_FILE}" \
  "ExecStartPre=/usr/bin/test -s \${CONTROL_UPGRADE_PLAN_SOURCE_CA_FILE}" \
  "ExecStartPre=/usr/bin/test -s \${CONTROL_UPGRADE_PLAN_SOURCE_CERT_FILE}" \
  "ExecStartPre=/usr/bin/test -s \${CONTROL_UPGRADE_PLAN_SOURCE_KEY_FILE}" \
  'NoNewPrivileges=true' 'CapabilityBoundingSet=' 'AmbientCapabilities=' \
  'ProtectSystem=strict' 'ProtectHome=true' 'PrivateTmp=true' 'PrivateDevices=true' \
  'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' 'SystemCallFilter=@system-service' \
  'ReadWritePaths=/opt/cdnca/control-api /var/lib/cdnca-control-upgrade'; do
  grep -Fq "$fragment" "$unit" || { echo "unit missing $fragment" >&2; exit 1; }
done
if grep -Eq '^(Environment=|ExecStart=.*(curl|wget|bash|sh)[[:space:]])' "$unit"; then
  echo "unit embeds environment values or a remote/script launcher" >&2
  exit 1
fi

for key in \
  CONTROL_UPGRADE_TARGET CONTROL_UPGRADE_INSTALLATION_ID_FILE CONTROL_UPGRADE_TRUST_FILE \
  CONTROL_UPGRADE_INTERNAL_TOKEN_FILE CONTROL_UPGRADE_PLAN_SOURCE_URL \
  CONTROL_UPGRADE_PLAN_SOURCE_CA_FILE CONTROL_UPGRADE_PLAN_SOURCE_CERT_FILE \
  CONTROL_UPGRADE_PLAN_SOURCE_KEY_FILE CONTROL_UPGRADE_PLAN_SOURCE_TIMEOUT \
  CONTROL_UPGRADE_PLAN_SOURCE_MAX_BYTES CONTROL_UPGRADE_POLL_INTERVAL \
  CONTROL_UPGRADE_EXPECTED_REPLICAS CONTROL_UPGRADE_QUORUM CONTROL_UPGRADE_STATE_DIR \
  CONTROL_UPGRADE_PLAN_LKG_FILE CONTROL_UPGRADE_RELEASE_ROOT CONTROL_UPGRADE_CURRENT_LINK \
  CONTROL_UPGRADE_SYSTEMD_UNIT CONTROL_UPGRADE_DRAIN_URL CONTROL_UPGRADE_RESUME_URL \
  CONTROL_UPGRADE_HEALTH_URL CONTROL_UPGRADE_CURRENT_VERSION CONTROL_UPGRADE_PROTOCOL_VERSION \
  CONTROL_UPGRADE_STEP_TIMEOUT CONTROL_UPGRADE_HEALTH_TIMEOUT; do
  [[ "$(grep -Ec "^${key}=" "$environment")" == "1" ]] || { echo "environment key $key is not unique" >&2; exit 1; }
done
grep -Fq 'CONTROL_UPGRADE_PLAN_SOURCE_URL=https://control.internal.example/v1/internal/control-upgrade/plan' "$environment"
if grep -Eq '^(CONTROL_UPGRADE_(INTERNAL_TOKEN|.*PASSWORD|.*SECRET|.*PRIVATE_KEY))=' "$environment"; then
  echo "environment example embeds a secret" >&2
  exit 1
fi

for fragment in \
  'control_upgrade_runner_preflight' 'control_upgrade_runner_install_atomic' \
  'runner binary SHA-256 mismatch' 'sync -f' 'mv -Tf' \
  'systemctl daemon-reload' 'systemctl enable cdnca-control-upgrade-runner.service'; do
  grep -Fq "$fragment" "$installer" || { echo "installer missing $fragment" >&2; exit 1; }
done
if grep -Eq '(^|[[:space:]])(curl|wget|eval|source)([[:space:]]|$)|systemctl (start|restart|enable --now)' "$installer"; then
  echo "installer contains a remote/script execution or starts the runner" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

rootfs="$work/root"
mkdir -p "$rootfs/etc/cdnca/control-upgrade" "$work/bin"
artifact="$work/control-upgrade-runner"
printf '#!/usr/bin/env sh\nexit 0\n' >"$artifact"
chmod 0755 "$artifact"
artifact_sha="$(sha256sum "$artifact" | awk '{print $1}')"
configured_environment="$work/control-upgrade-runner.env"
cp "$environment" "$configured_environment"

printf '%s\n' '00000000-0000-4000-8000-000000000006' >"$rootfs/etc/cdnca/control-upgrade/installation-id"
printf '%s\n' '{}' >"$rootfs/etc/cdnca/control-upgrade/upgrade-trust.json"
printf '%s' 'internal-token-32-bytes-long-value' >"$rootfs/etc/cdnca/control-upgrade/internal-token"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=control-upgrade-test-ca' \
  -keyout "$work/ca-key.pem" -out "$rootfs/etc/cdnca/control-upgrade/plan-source-ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=control-upgrade-runner' \
  -keyout "$rootfs/etc/cdnca/control-upgrade/plan-source-client-key.pem" -out "$work/client.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$work/client.csr" -CA "$rootfs/etc/cdnca/control-upgrade/plan-source-ca.pem" \
  -CAkey "$work/ca-key.pem" -CAcreateserial -out "$rootfs/etc/cdnca/control-upgrade/plan-source-client.pem" >/dev/null 2>&1
chmod 0600 "$rootfs/etc/cdnca/control-upgrade/internal-token" "$rootfs/etc/cdnca/control-upgrade/plan-source-client-key.pem"
chmod 0644 "$rootfs/etc/cdnca/control-upgrade/installation-id" "$rootfs/etc/cdnca/control-upgrade/upgrade-trust.json" \
  "$rootfs/etc/cdnca/control-upgrade/plan-source-ca.pem" "$rootfs/etc/cdnca/control-upgrade/plan-source-client.pem"

systemctl_log="$work/systemctl.log"
cat >"$work/bin/systemctl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$SYSTEMCTL_LOG"
SH
chmod 0755 "$work/bin/systemctl"

if DESTDIR="$rootfs" SYSTEMCTL_BIN="$work/bin/systemctl" SYSTEMCTL_LOG="$systemctl_log" \
  bash "$installer" --binary "$artifact" --binary-sha256 "$(printf '0%.0s' {1..64})" \
  --environment "$configured_environment"; then
  echo "invalid artifact digest was accepted" >&2
  exit 1
fi
[[ ! -e "$rootfs/usr/local/libexec/cdnca/control-upgrade-runner" ]]
[[ ! -e "$rootfs/etc/systemd/system/cdnca-control-upgrade-runner.service" ]]

DESTDIR="$rootfs" SYSTEMCTL_BIN="$work/bin/systemctl" SYSTEMCTL_LOG="$systemctl_log" \
  bash "$installer" --binary "$artifact" --binary-sha256 "$artifact_sha" \
  --environment "$configured_environment"

cmp -s "$artifact" "$rootfs/usr/local/libexec/cdnca/control-upgrade-runner"
cmp -s "$unit" "$rootfs/etc/systemd/system/cdnca-control-upgrade-runner.service"
cmp -s "$configured_environment" "$rootfs/etc/cdnca/control-upgrade-runner.env"
[[ "$(file_mode "$rootfs/usr/local/libexec/cdnca/control-upgrade-runner")" == "755" ]]
[[ "$(file_mode "$rootfs/etc/systemd/system/cdnca-control-upgrade-runner.service")" == "644" ]]
[[ "$(file_mode "$rootfs/etc/cdnca/control-upgrade-runner.env")" == "600" ]]
[[ "$(file_mode "$rootfs/var/lib/cdnca-control-upgrade/state")" == "700" ]]
[[ "$(file_mode "$rootfs/var/lib/cdnca-control-upgrade/lkg")" == "700" ]]
systemctl_calls="$(<"$systemctl_log")"
[[ "$systemctl_calls" == $'daemon-reload\nenable cdnca-control-upgrade-runner.service' ]]

for fragment in '安装不会启动升级' 'HTTPS 计划源与 mTLS' '最小权限' 'LKG' 'shared mount'; do
  grep -Fq "$fragment" "$runbook" || { echo "runbook missing $fragment" >&2; exit 1; }
done

echo "CONTROL_UPGRADE_SYSTEMD_STATIC PASS"
