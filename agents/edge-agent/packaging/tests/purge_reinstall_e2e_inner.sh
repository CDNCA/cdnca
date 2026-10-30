#!/bin/bash
# Runs as root inside the disposable systemd container started by
# purge_reinstall_e2e.sh. See that script for what is proven.
set -Eeuo pipefail

repo=/workspace
bin=/e2e-bin
work=$(mktemp -d /var/tmp/cdnca-purge-reinstall-e2e.XXXXXX)
chmod 0755 "${work}"
fail() { printf 'purge reinstall e2e failed: %s\n' "$*" >&2; exit 1; }
step() { printf '== %s\n' "$*"; }

command -v jq >/dev/null || { apt-get update -qq >/dev/null && apt-get install -y -qq jq >/dev/null; } || fail 'jq is required'
cp -a "${repo}/agents/edge-agent/packaging" "${work}/packaging"
chown -R 0:0 "${work}/packaging"
arch=$(dpkg --print-architecture)

# install-node.sh functions without running main; uname is pinned to x86_64
# because the gate only admits amd64 hosts and this container may be arm64.
sed -e '/^main "\$@"$/d' "${repo}/scripts/install-node.sh" >"${work}/install-node-lib.sh"
blank_host_gate() {
  # shellcheck disable=SC2016
  bash -c '
    source "$1"
    uname() { if [ "${1:-}" = -s ]; then printf Linux; else printf x86_64; fi; }
    trap - EXIT
    assert_blank_host
  ' _ "${work}/install-node-lib.sh"
}

step 'blank container passes the first-install gate'
blank_host_gate || fail 'blank container refused'

step 'signed fixture release 1.0.24'
openssl genpkey -algorithm ED25519 -out "${work}/release-private.pem"
openssl pkey -in "${work}/release-private.pem" -pubout -out "${work}/package-signing.pem"
chmod 0444 "${work}/package-signing.pem"
release=${work}/release
mkdir -m 0755 "${release}"
install -m 0555 "${bin}/fixture-1.0.24" "${release}/edge-agent"
printf '{"SPDXID":"SPDXRef-DOCUMENT","creationInfo":{"created":"2026-07-22T00:00:00Z","creators":["Tool: purge-e2e"]},"dataLicense":"CC0-1.0","documentNamespace":"https://example.invalid/spdx/1.0.24","name":"cdnca-edge-agent-1.0.24","spdxVersion":"SPDX-2.3"}\n' \
  >"${release}/edge-agent.spdx.json"
jq -n --arg arch "${arch}" --arg artifact "$(sha256sum "${release}/edge-agent" | cut -d' ' -f1)" \
  --argjson size "$(stat -c %s "${release}/edge-agent")" --arg sbom "$(sha256sum "${release}/edge-agent.spdx.json" | cut -d' ' -f1)" \
  '{schema:"cdnca.edge.release-provenance/v1",arch:$arch,version:"1.0.24",
    source_repository:"https://example.invalid/cdnca.git",source_commit:("a"*40),created:"2026-07-22T00:00:00Z",
    artifact:{path:"edge-agent",sha256:$artifact,size:$size},sbom:{path:"edge-agent.spdx.json",sha256:$sbom}}' \
  >"${release}/edge-agent.provenance.json"
"${bin}/cdnca-edge-release-bundle" prepare --release-dir "${release}" --release-sequence 1 --output-dir "${work}/prep" >/dev/null
chmod 0755 "${work}/prep"
openssl pkeyutl -sign -rawin -inkey "${work}/release-private.pem" -in "${work}/prep/manifest.signing-data" -out "${work}/sig"
"${bin}/cdnca-edge-release-bundle" finalize --prepared-dir "${work}/prep" --signature "${work}/sig" \
  --public-key "${work}/package-signing.pem" --download-base-url https://auth.example.test/downloads >/dev/null

step 'native node layout as install-node.sh builds it'
# activate_native_package: release tree, current link and the three runtime links; install record.
mkdir -p /opt/cdnca-node/releases/fixture/runtime/openresty /opt/cdnca-node/releases/fixture/lua/share/cdnca \
  /opt/cdnca-node/releases/fixture/lua/l4geo /usr/local/share /opt/cdnca
ln -s releases/fixture /opt/cdnca-node/current
ln -s /opt/cdnca-node/current/runtime/openresty /usr/local/openresty
ln -s /opt/cdnca-node/current/lua/share/cdnca /usr/local/share/cdnca
ln -s /opt/cdnca-node/current/lua/l4geo /opt/cdnca/l4geo
mkdir -m 0700 /var/lib/cdnca-node-install /var/lib/cdnca-node-monitoring
printf 'schema=cdnca.node-install-state/v1\nstep=done\n' >/var/lib/cdnca-node-install/state
# install_agent_packaging
"${work}/packaging/scripts/install.sh" --runtime-identity root \
  --artifact "${work}/prep/edge-agent" --sbom "${work}/prep/edge-agent.spdx.json" \
  --manifest "${work}/prep/manifest" --signature "${work}/prep/manifest.sig" \
  --public-key "${work}/package-signing.pem" >/dev/null
# start_packaging_helper (+ a systemd_compat_apply drop-in per unit, as on older systemd)
install -m 0555 "${bin}/cdnca-edge-agent-helper" /usr/libexec/cdnca-edge-agent-helper
for unit in cdnca-edge-agent-helper.service cdnca-edge-agent-helper.socket; do
  install -m 0644 "${work}/packaging/systemd/${unit}" "/usr/lib/systemd/system/${unit}"
done
for unit in cdnca-edge-agent.service cdnca-edge-agent-helper.service cdnca-edge-agent-helper.socket; do
  install -d -m 0755 "/etc/systemd/system/${unit}.d"
  printf '# purge e2e compat drop-in\n[Unit]\n' >"/etc/systemd/system/${unit}.d/zz-cdnca-systemd-compat.conf"
done
systemctl daemon-reload
/usr/libexec/cdnca-edge-agent-helper key-init >/dev/null
systemctl enable --now cdnca-edge-agent-helper.socket >/dev/null
python3 - <<'PY'
import json, socket
c = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
c.connect('/run/cdnca-edge-agent/helper.sock')
c.send(b'{"protocol_version":1,"operation":"current"}'); c.shutdown(socket.SHUT_WR)
r = json.loads(c.recv(32768))
assert r.get('ok'), r
print('helper current ok')
PY
systemctl is-active --quiet cdnca-edge-agent-helper.service || fail 'helper service not active'
# setup_service
printf '{"fixture":true}\n' >/etc/cdnca-edge-agent/config.json
chmod 0600 /etc/cdnca-edge-agent/config.json
systemctl enable --now cdnca-edge-agent.service >/dev/null
for _ in $(seq 1 30); do systemctl is-active --quiet cdnca-edge-agent.service && break; sleep 1; done
systemctl is-active --quiet cdnca-edge-agent.service || { journalctl -u cdnca-edge-agent -n 40 --no-pager; fail 'agent unit inactive'; }

step 'installed node is refused by the first-install gate'
if blank_host_gate 2>"${work}/gate-installed.err"; then fail 'installed node passed the blank-host gate'; fi
cat "${work}/gate-installed.err"

step 'uninstall.sh --purge'
/usr/libexec/cdnca-edge-agent/uninstall.sh --purge --non-interactive --confirm-purge DELETE-EDGE-IDENTITY-AND-STATE
for unit in cdnca-edge-agent.service cdnca-edge-agent-helper.service cdnca-edge-agent-helper.socket; do
  [ "$(systemctl show "${unit}" --property=LoadState --value)" = not-found ] || fail "${unit} still loaded after purge"
  [ ! -e "/etc/systemd/system/${unit}.d" ] || fail "${unit} drop-in directory left"
done
[ ! -e /etc/systemd/system/sockets.target.wants/cdnca-edge-agent-helper.socket ] || fail 'socket wants link left'
pgrep -f 'cdnca-edge-agent-helper serve' >/dev/null && fail 'helper process still running'
for path in /usr/libexec/cdnca-edge-agent-helper /var/lib/cdnca-edge-agent-helper /opt/cdnca-node /usr/local/openresty \
  /usr/local/share/cdnca /opt/cdnca/l4geo /var/lib/cdnca-node-install /var/lib/cdnca-node-monitoring /etc/cdnca-edge-agent; do
  [ ! -e "${path}" ] && [ ! -L "${path}" ] || fail "${path} left after purge"
done

step 'same first-install gate passes after purge'
blank_host_gate || fail 'reinstall refused after uninstall --purge'
printf 'PURGE_REINSTALL_E2E PASS\n'
