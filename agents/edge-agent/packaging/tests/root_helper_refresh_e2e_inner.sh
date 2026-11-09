#!/bin/bash
# Runs as root inside the container started by root_helper_refresh_e2e.sh.
# Provisions a root node as the previous release does (its scripts and helper), plants the
# Agent's version pointer links, then drives the Go updater client through the
# production helper; hook.sh asserts each step.
set -Eeuo pipefail

repo=/workspace
bin=/e2e-bin
work=$(mktemp -d /var/tmp/cdnca-root-helper-refresh.XXXXXX)
chmod 0755 "${work}"
fail() { printf 'helper refresh e2e failed: %s\n' "$*" >&2; exit 1; }
step() { printf '== %s\n' "$*"; }
command -v jq >/dev/null || { apt-get update -qq >/dev/null && apt-get install -y -qq jq >/dev/null; } || fail 'jq is required'

if [ -S /run/dbus/system_bus_socket ]; then printf '== D-Bus system bus: present\n'; else printf '== D-Bus system bus: absent\n'; fi
arch=$(dpkg --print-architecture)
cp -a "${bin}/old/agents/edge-agent/packaging" "${work}/old-packaging"
cp -a "${repo}/agents/edge-agent/packaging" "${work}/packaging"
chown -R 0:0 "${work}/old-packaging" "${work}/packaging"
cmp -s "${bin}/old-helper" "${bin}/cdnca-edge-agent-helper" && fail 'previous and new helpers are identical'

step 'release key and four fixture releases: v1 bundles without a native section, SBOM carries scripts and helper'
openssl genpkey -algorithm ED25519 -out "${work}/release-private.pem"
openssl pkey -in "${work}/release-private.pem" -pubout -out "${work}/package-signing.pem"
chmod 0444 "${work}/package-signing.pem"
sequence=0
for version in 1.0.24 1.0.25 1.0.26 1.0.27; do
  sequence=$((sequence + 1))
  release=${work}/release-${version}
  mkdir -m 0755 "${release}"
  install -m 0555 "${bin}/fixture-${version}" "${release}/edge-agent"
  toolset=${work}/toolset-${version}
  mkdir -p "${toolset}/packaging/scripts"
  : >"${work}/files.jsonl"
  for script in lib install preflight rollback uninstall upgrade; do
    cp "${work}/packaging/scripts/${script}.sh" "${toolset}/packaging/scripts/${script}.sh"
    printf '# toolset %s\n' "${version}" >>"${toolset}/packaging/scripts/${script}.sh"
    base64 -w0 "${toolset}/packaging/scripts/${script}.sh" >"${work}/content.b64"
    jq -cn --arg name "${script}" --arg digest "$(sha256sum "${toolset}/packaging/scripts/${script}.sh" | cut -d' ' -f1)" \
      --rawfile content "${work}/content.b64" \
      '{SPDXID:("SPDXRef-File-packaging-" + $name),checksums:[{algorithm:"SHA256",checksumValue:$digest}],
        fileName:("packaging/scripts/" + $name + ".sh"),annotations:[{annotationDate:"2026-07-22T00:00:00Z",
        annotationType:"OTHER",annotator:"Tool: refresh-e2e",comment:("cdnca.packaging-script/v1 base64:" + $content)}]}' \
      >>"${work}/files.jsonl"
  done
  # The new helper, made distinct per release (trailing bytes after the ELF are not loaded).
  { cat "${bin}/cdnca-edge-agent-helper"; printf '\ncdnca fixture helper %s\n' "${version}"; } >"${work}/helper-${version}"
  base64 -w0 "${work}/helper-${version}" >"${work}/content.b64"
  jq -cn --arg digest "$(sha256sum "${work}/helper-${version}" | cut -d' ' -f1)" --rawfile content "${work}/content.b64" \
    '{SPDXID:"SPDXRef-File-packaging-helper",checksums:[{algorithm:"SHA256",checksumValue:$digest}],
      fileName:"packaging/bin/cdnca-edge-agent-helper",annotations:[{annotationDate:"2026-07-22T00:00:00Z",
      annotationType:"OTHER",annotator:"Tool: refresh-e2e",comment:("cdnca.packaging-helper/v1 base64:" + $content)}]}' \
    >>"${work}/files.jsonl"
  jq -cs --arg version "${version}" \
    '{SPDXID:"SPDXRef-DOCUMENT",creationInfo:{created:"2026-07-22T00:00:00Z",creators:["Tool: refresh-e2e"]},dataLicense:"CC0-1.0",
      documentNamespace:("https://example.invalid/spdx/" + $version),files:.,name:("cdnca-edge-agent-" + $version),spdxVersion:"SPDX-2.3"}' \
    "${work}/files.jsonl" >"${release}/edge-agent.spdx.json"
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
  # Same arguments as the release bundle build: no --native.
  "${bin}/cdnca-edge-release-bundle" finalize --prepared-dir "${prepared}" --signature "${work}/sig-${version}" \
    --public-key "${work}/package-signing.pem" --download-base-url https://auth.example.test/downloads >/dev/null
  bundle_file=${prepared}/$(jq -r .bundle_file "${prepared}/bundle.json")
  [ "$(head -c 29 "${bundle_file}" | od -An -c | tr -d ' \n')" = 'cdnca-edge-release-bundle/v1\0' ] || fail "${version} is not a v1 bundle"
done

step 'root node installed as the previous release installs it (its scripts and helper)'
"${work}/old-packaging/scripts/install.sh" --runtime-identity root \
  --artifact "${work}/prep-1.0.24/edge-agent" --sbom "${work}/prep-1.0.24/edge-agent.spdx.json" \
  --manifest "${work}/prep-1.0.24/manifest" --signature "${work}/prep-1.0.24/manifest.sig" \
  --public-key "${work}/package-signing.pem" >/dev/null
install -m 0555 "${bin}/old-helper" /usr/libexec/cdnca-edge-agent-helper
for unit in cdnca-edge-agent-helper.service cdnca-edge-agent-helper.socket; do
  install -m 0644 "${work}/old-packaging/systemd/${unit}" "/usr/lib/systemd/system/${unit}"
done
systemctl daemon-reload
/usr/libexec/cdnca-edge-agent-helper key-init
systemctl enable --now cdnca-edge-agent-helper.socket >/dev/null
sed -n '/^probe_packaging_helper() {$/,/^PY_PACKAGING_HELPER$/p' "${repo}/scripts/install-node.sh" >"${work}/probe.sh"
printf '}\n' >>"${work}/probe.sh"
# shellcheck source=/dev/null
. "${work}/probe.sh"
# shellcheck disable=SC2034 # Read by the sourced probe_packaging_helper.
ED25519_TOOL=${bin}/cdnca-ed25519
probe_packaging_helper /run/cdnca-edge-agent/helper.sock /etc/cdnca-edge-agent/helper-receipt-public.json 1.0.24 \
  /etc/cdnca-edge-agent/trust/installer-receipt.json
printf '{"fixture":true}\n' >/etc/cdnca-edge-agent/config.json
chmod 0600 /etc/cdnca-edge-agent/config.json
systemctl enable --now cdnca-edge-agent.service >/dev/null
for _ in $(seq 1 30); do systemctl is-active --quiet cdnca-edge-agent.service && break; sleep 1; done
active=/var/lib/cdnca-edge-agent-backups/active-state
digest=$(printf '%064d' 0)
for runtime in l4-runtime http3-runtime; do
  install -d -m 0700 "${active}/${runtime}" "${active}/${runtime}/versions"
  install -d -m 0500 "${active}/${runtime}/versions/dynroute-l4-none-${digest}"
  ln -s "versions/dynroute-l4-none-${digest}" "${active}/${runtime}/current"
done
install -d -m 0700 "${active}/certificates" "${active}/certificates/versions"
install -d -m 0500 "${active}/certificates/versions/cert-v1-${digest}"
ln -s "versions/cert-v1-${digest}" "${active}/certificates/current"
ln -s "versions/cert-v1-${digest}" "${active}/certificates/lkg"
printf '%s\n' refresh-state >"${active}/state.txt"
cat >"${work}/hook.sh" <<EOF
#!/bin/bash
set -euo pipefail
fail() { printf 'hook failed: %s\n' "\$*" >&2; exit 1; }
work=${work}
bin=${bin}
active=${active}
digest=${digest}
helper=/usr/libexec/cdnca-edge-agent-helper
record=/var/lib/cdnca-edge-agent-packaging/toolset-refresh
sha() { sha256sum "\$1" | cut -d' ' -f1; }
serving() {
  [ "\$(readlink /usr/lib/cdnca-edge-agent/current)" = "versions/\$1" ] || fail "current is not \$1"
  systemctl is-active --quiet cdnca-edge-agent.service || fail 'agent is not running'
  systemctl is-enabled --quiet cdnca-edge-agent.service || fail 'agent is not enabled'
  [ ! -e /var/lib/cdnca-edge-agent-packaging/transaction ] || fail 'a package transaction was left'
  for runtime in l4-runtime http3-runtime; do
    [ "\$(readlink "\${active}/\${runtime}/current")" = "versions/dynroute-l4-none-\${digest}" ] || fail "\${runtime} link"
  done
  for pointer in current lkg; do
    [ "\$(readlink "\${active}/certificates/\${pointer}")" = "versions/cert-v1-\${digest}" ] || fail "certificates/\${pointer}"
  done
  [ "\$(cat "\${active}/state.txt")" = refresh-state ] || fail 'state.txt'
  for release in /usr/lib/cdnca-edge-agent/versions/*; do [ ! -e "\${release}/native.tar.gz" ] || fail "\${release} has native"; done
  [ -z "\$(find /var/lib/cdnca-edge-agent-packaging -maxdepth 1 -name '.toolset-staging.*')" ] || fail 'toolset staging left'
  [ -z "\$(find /usr/libexec -maxdepth 1 -name '.cdnca-edge-agent-helper.*')" ] || fail 'helper staging left'
  [ "\$(stat -c '%u:%g:%a:%h' "\${helper}")" = 0:0:555:1 ] || fail 'helper policy'
  echo "serving \$1, state and links intact"
}
helper_file() { cmp -s "\${helper}" "\$1" || fail "helper file is not \$1"; echo "helper file is \$1"; }
helper_running() {
  pid=\$(systemctl show -p MainPID --value cdnca-edge-agent-helper.service)
  [ "\${pid}" -gt 0 ] || fail 'packaging helper is not running'
  [ "\$(sha256sum "/proc/\${pid}/exe" | cut -d' ' -f1)" = "\$(sha "\$1")" ] || fail "running helper is not \$1"
  echo "running helper is \$1"
}
scripts() {
  for script in lib install preflight rollback uninstall upgrade; do
    cmp -s "/usr/libexec/cdnca-edge-agent/\${script}.sh" "\${work}/toolset-\$1/packaging/scripts/\${script}.sh" || fail "\${script}.sh is not \$1"
  done
}
recorded() { # status version helper_status
  cat "\${record}"
  grep -Fx "status=\$1" "\${record}" >/dev/null && grep -Fx "version=\$2" "\${record}" >/dev/null || fail "record is not \$1 \$2"
  if [ -n "\$3" ]; then grep -Fx "helper_status=\$3" "\${record}" >/dev/null || fail "helper_status is not \$3"
  else ! grep -q '^helper_status=' "\${record}" || fail 'previous record has a helper status'; fi
}
report() { # status version helper_status: what the Agent's heartbeat carries
  "\${bin}/toolsetreportprobe" >"\${work}/report.json" || fail 'report refused'
  cat "\${work}/report.json"
  jq -e --arg s "\$1" --arg v "\$2" --arg h "\$3" --arg helper "\$(sha "\${helper}")" \
    '.refresh_status == \$s and .refresh_version == \$v and .helper_status == \$h and .helper_sha256 == \$helper and
     (.scripts_sha256 | test("^[0-9a-f]{64}\$"))' "\${work}/report.json" >/dev/null || fail 'report does not match the node'
}
case "\$1" in
  baseline)
    serving 1.0.24; helper_file "\${bin}/old-helper"; helper_running "\${bin}/old-helper"
    [ ! -e "\${record}" ] || fail 'record before any refresh'
    "\${bin}/toolsetreportprobe" | jq -e '.refresh_status == "none" and .refresh_version == ""' >/dev/null || fail 'report before refresh'
    ;;
  after-first)
    serving 1.0.25; scripts 1.0.25; helper_file "\${bin}/old-helper"; recorded ok 1.0.25 ''
    report ok 1.0.25 ''
    ;;
  after-second)
    serving 1.0.26; scripts 1.0.26; helper_file "\${work}/helper-1.0.26"; recorded ok 1.0.26 ok
    helper_running "\${bin}/old-helper"; report ok 1.0.26 ok
    ! systemctl list-units --all --failed --no-legend | grep -q . || { systemctl list-units --all --failed; fail 'a unit failed'; }
    ;;
  restart-helper) systemctl restart cdnca-edge-agent-helper.service ;;
  after-takeover) serving 1.0.26; helper_running "\${work}/helper-1.0.26" ;;
  after-rollback)
    serving 1.0.25; scripts 1.0.26; helper_file "\${work}/helper-1.0.26"; recorded ok 1.0.26 ok
    helper_running "\${work}/helper-1.0.26"; report ok 1.0.26 ok
    ;;
  after-again)
    serving 1.0.27; scripts 1.0.27; helper_file "\${work}/helper-1.0.27"; recorded ok 1.0.27 ok
    [ "\$(systemctl show -p Result --value cdnca-edge-agent-helper.service)" = success ] || fail 'helper did not exit cleanly'
    ;;
  after-self-exit) helper_running "\${work}/helper-1.0.27"; report ok 1.0.27 ok ;;
  operator-refresh)
    # A node whose helper is still the first-install one and running.
    install -m 0555 "\${bin}/old-helper" "\${helper}.e2e"; mv -Tf "\${helper}.e2e" "\${helper}"
    systemctl restart cdnca-edge-agent-helper.service; helper_running "\${bin}/old-helper"
    "\${work}/packaging/scripts/install.sh" --refresh-toolset \
      --artifact "\${work}/prep-1.0.27/edge-agent" --sbom "\${work}/prep-1.0.27/edge-agent.spdx.json" \
      --manifest "\${work}/prep-1.0.27/manifest" --signature "\${work}/prep-1.0.27/manifest.sig" \
      --public-key "\${work}/package-signing.pem" | tee "\${work}/refresh.out"
    grep -Fx 'restarted the packaging helper on the refreshed binary' "\${work}/refresh.out" >/dev/null || fail 'helper not restarted'
    serving 1.0.27; helper_file "\${work}/helper-1.0.27"; helper_running "\${work}/helper-1.0.27"
    recorded ok 1.0.27 ok; report ok 1.0.27 ok
    ;;
  *) fail "unknown phase \$1" ;;
esac
EOF
chmod 0755 "${work}/hook.sh"

step 'upgrade (previous scripts), upgrade (helper replaced), restart, rollback, upgrade (self exit), operator refresh through the production helper'
CDNCA_ROOT_HELPER_E2E_DIR=${work} CDNCA_REFRESH_HOOK=${work}/hook.sh "${bin}/updater.e2e.test" \
  -test.run TestRootHelperRefreshesThroughProductionHelper -test.v -test.timeout 10m
printf 'ROOT_HELPER_REFRESH_E2E PASS\n'
