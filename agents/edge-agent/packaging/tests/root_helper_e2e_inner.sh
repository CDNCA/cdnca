#!/bin/bash
# Runs as root inside the disposable systemd container started by
# root_helper_e2e.sh. Provisions a native-style node exactly as install-node.sh
# does (packaging install --runtime-identity root, helper units, key-init,
# socket, verified helper probe, root Agent unit) and then drives a v1 -> v2
# upgrade and a failed v3 upgrade through the production helper.
set -Eeuo pipefail

repo=/workspace
bin=/e2e-bin
work=$(mktemp -d /var/tmp/cdnca-root-helper-e2e.XXXXXX)
chmod 0755 "${work}"
fail() { printf 'root helper e2e failed: %s\n' "$*" >&2; exit 1; }
step() { printf '== %s\n' "$*"; }

arch=$(dpkg --print-architecture)
cp -a "${repo}/agents/edge-agent/packaging" "${work}/packaging"
chown -R 0:0 "${work}/packaging"

step 'release key and three fixture releases (1.0.24 healthy, 1.0.25 healthy, 1.0.26 never healthy)'
openssl genpkey -algorithm ED25519 -out "${work}/release-private.pem"
openssl pkey -in "${work}/release-private.pem" -pubout -out "${work}/package-signing.pem"
chmod 0444 "${work}/package-signing.pem"
sequence=0
for version in 1.0.24 1.0.25 1.0.26; do
  sequence=$((sequence + 1))
  release=${work}/release-${version}
  mkdir -m 0755 "${release}"
  install -m 0555 "${bin}/fixture-${version}" "${release}/edge-agent"
  printf '{"SPDXID":"SPDXRef-DOCUMENT","creationInfo":{"created":"2026-07-22T00:00:00Z","creators":["Tool: root-helper-e2e"]},"dataLicense":"CC0-1.0","documentNamespace":"https://example.invalid/spdx/%s","name":"cdnca-edge-agent-%s","spdxVersion":"SPDX-2.3"}\n' \
    "${version}" "${version}" >"${release}/edge-agent.spdx.json"
  jq -n --arg arch "${arch}" --arg version "${version}" \
    --arg artifact "$(sha256sum "${release}/edge-agent" | cut -d' ' -f1)" --argjson size "$(stat -c %s "${release}/edge-agent")" \
    --arg sbom "$(sha256sum "${release}/edge-agent.spdx.json" | cut -d' ' -f1)" \
    '{schema:"cdnca.edge.release-provenance/v1",arch:$arch,version:$version,
      source_repository:"https://example.invalid/cdnca.git",source_commit:("a"*40),created:"2026-07-22T00:00:00Z",
      artifact:{path:"edge-agent",sha256:$artifact,size:$size},sbom:{path:"edge-agent.spdx.json",sha256:$sbom}}' \
    >"${release}/edge-agent.provenance.json"
  prepared=${work}/prep-${version}
  "${bin}/cdnca-edge-release-bundle" prepare --release-dir "${release}" --release-sequence "${sequence}" --output-dir "${prepared}" >/dev/null
  chmod 0755 "${prepared}"
  openssl pkeyutl -sign -rawin -inkey "${work}/release-private.pem" -in "${prepared}/manifest.signing-data" -out "${work}/sig-${version}"
  "${bin}/cdnca-edge-release-bundle" finalize --prepared-dir "${prepared}" --signature "${work}/sig-${version}" \
    --public-key "${work}/package-signing.pem" --download-base-url https://auth.example.test/downloads >/dev/null
done

step 'packaging install as the root runtime identity (install-node.sh install_agent_packaging)'
"${work}/packaging/scripts/install.sh" --runtime-identity root \
  --artifact "${work}/prep-1.0.24/edge-agent" --sbom "${work}/prep-1.0.24/edge-agent.spdx.json" \
  --manifest "${work}/prep-1.0.24/manifest" --signature "${work}/prep-1.0.24/manifest.sig" \
  --public-key "${work}/package-signing.pem"
[ "$(readlink /usr/lib/cdnca-edge-agent/current)" = versions/1.0.24 ] || fail 'current is not 1.0.24'
cmp -s /usr/lib/systemd/system/cdnca-edge-agent.service "${work}/packaging/systemd/cdnca-edge-agent-root.service" || fail 'root unit'
[ "$(cat /var/lib/cdnca-edge-agent-packaging/runtime-identity)" = root ] || fail 'runtime identity marker'

step 'helper binary, units, key-init and socket (install-node.sh start_packaging_helper)'
install -m 0555 "${bin}/cdnca-edge-agent-helper" /usr/libexec/cdnca-edge-agent-helper
for unit in cdnca-edge-agent-helper.service cdnca-edge-agent-helper.socket; do
  install -m 0644 "${work}/packaging/systemd/${unit}" "/usr/lib/systemd/system/${unit}"
done
systemctl daemon-reload
/usr/libexec/cdnca-edge-agent-helper key-init
systemctl enable --now cdnca-edge-agent-helper.socket >/dev/null
[ "$(stat -c '%U:%G:%a' /run/cdnca-edge-agent/helper.sock)" = cdnca-edge:cdnca-edge:600 ] || fail 'socket policy'
step 'install-node.sh probe_packaging_helper against the real helper'
sed -n '/^probe_packaging_helper() {$/,/^PY_PACKAGING_HELPER$/p' "${repo}/scripts/install-node.sh" >"${work}/probe.sh"
printf '}\n' >>"${work}/probe.sh"
# shellcheck source=/dev/null
. "${work}/probe.sh"
receipt_trust=/etc/cdnca-edge-agent/trust/installer-receipt.json
if probe_packaging_helper /run/cdnca-edge-agent/helper.sock /etc/cdnca-edge-agent/helper-receipt-public.json 9.9.9 "${receipt_trust}" 2>/dev/null; then
  fail 'probe accepted a receipt for another version'
fi
[ ! -e "${receipt_trust}" ] || fail 'a rejected probe wrote receipt trust'
probe_packaging_helper /run/cdnca-edge-agent/helper.sock /etc/cdnca-edge-agent/helper-receipt-public.json 1.0.24 "${receipt_trust}"
[ "$(stat -c '%u:%g:%a' "${receipt_trust}")" = 0:0:400 ] || fail 'receipt trust policy'
# The socket-activated helper must keep CAP_SETUID/CAP_SETGID (0xcb) for the
# packaging setpriv probes; an explicit User=root in its unit drops SETUID.
helper_pid=$(systemctl show cdnca-edge-agent-helper.service --property=MainPID --value)
helper_caps=$(awk '$1 == "CapEff:" {print $2}' "/proc/${helper_pid}/status")
[ "${helper_caps}" = 00000000000000cb ] || fail "helper effective capabilities ${helper_caps}, want 00000000000000cb"
printf 'helper pid %s CapEff %s\n' "${helper_pid}" "${helper_caps}"

step 'peer credentials: root and cdnca-edge accepted, partial identities rejected'
agent_uid=$(id -u cdnca-edge); agent_gid=$(id -g cdnca-edge)
for identity in "0:0:ok" "${agent_uid}:${agent_gid}:ok" "0:${agent_gid}:ERR_UNAUTHORIZED" "${agent_uid}:0:ERR_UNAUTHORIZED"; do
  python3 - "${identity}" <<'PY'
import json, os, socket, sys
uid, gid, expected = sys.argv[1].split(':')
os.setgroups([])
os.setgid(int(gid))
os.setuid(int(uid))
connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
connection.connect('/run/cdnca-edge-agent/helper.sock')
# An unauthorized peer may be rejected before its request is read; the stable
# error packet is still delivered, so a failed send is not a failure.
try:
    connection.send(b'{"protocol_version":1,"operation":"current"}')
    connection.shutdown(socket.SHUT_WR)
except (BrokenPipeError, ConnectionResetError):
    pass
response = json.loads(connection.recv(32768))
got = 'ok' if response.get('ok') else response.get('error_code')
if got != expected:
    sys.exit(f'peer {uid}:{gid} got {got}, want {expected}')
print(f'peer {uid}:{gid} -> {got}')
PY
done

step 'root Agent unit starts through preflight'
printf '{"fixture":true}\n' >/etc/cdnca-edge-agent/config.json
chmod 0600 /etc/cdnca-edge-agent/config.json
systemctl enable --now cdnca-edge-agent.service >/dev/null
for _ in $(seq 1 30); do systemctl is-active --quiet cdnca-edge-agent.service && break; sleep 1; done
systemctl is-active --quiet cdnca-edge-agent.service || { journalctl -u cdnca-edge-agent -n 40 --no-pager; fail 'agent unit inactive'; }

if [ "${CDNCA_ROOT_HELPER_E2E_TRACE:-0}" = 1 ]; then
  # The helper discards packaging output by design; for diagnosis only, wrap
  # the fixed entrypoint (same path, owner and mode) and keep its stderr.
  mv /usr/libexec/cdnca-edge-agent/upgrade.sh /usr/libexec/cdnca-edge-agent/upgrade.real.sh
  printf '#!/bin/sh\nexec /bin/sh -x /usr/libexec/cdnca-edge-agent/upgrade.real.sh "$@" 2>>/var/lib/cdnca-edge-agent-packaging/e2e-trace.log\n' \
    >/usr/libexec/cdnca-edge-agent/upgrade.sh
  chmod 0555 /usr/libexec/cdnca-edge-agent/upgrade.sh
fi

step 'root Agent upgrade through the production helper (Go updater client)'
CDNCA_ROOT_HELPER_E2E_DIR=${work} "${bin}/updater.e2e.test" -test.run TestRootAgentUpgradesThroughProductionHelper -test.v -test.timeout 8m

step 'post-conditions'
[ "$(readlink /usr/lib/cdnca-edge-agent/current)" = versions/1.0.25 ] || fail 'final current'
systemctl is-active --quiet cdnca-edge-agent.service || fail 'agent not active after failed upgrade'
grep -Fx 'release_sequence=2' /var/lib/cdnca-edge-agent-packaging/accepted-manifest >/dev/null || fail 'accepted manifest'
ls /var/lib/cdnca-edge-agent-backups
printf 'ROOT_HELPER_E2E PASS\n'
