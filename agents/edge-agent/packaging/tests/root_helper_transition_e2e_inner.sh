#!/bin/bash
# Runs as root inside the container started by root_helper_transition_e2e.sh.
# Provisions a root node with the OLD packaging toolset (as install-node.sh
# does), plants the Agent's four version pointer links, then drives the Go
# updater client through the production helper; hook.sh asserts each step.
set -Eeuo pipefail

repo=/workspace
bin=/e2e-bin
work=$(mktemp -d /var/tmp/cdnca-root-helper-transition.XXXXXX)
chmod 0755 "${work}"
fail() { printf 'toolset transition e2e failed: %s\n' "$*" >&2; exit 1; }
step() { printf '== %s\n' "$*"; }
command -v jq >/dev/null || { apt-get update -qq >/dev/null && apt-get install -y -qq jq >/dev/null; } || fail 'jq is required'

arch=$(dpkg --print-architecture)
cp -a "${bin}/old/agents/edge-agent/packaging" "${work}/old-packaging"
cp -a "${repo}/agents/edge-agent/packaging" "${work}/packaging"
chown -R 0:0 "${work}/old-packaging" "${work}/packaging"
cmp -s "${work}/old-packaging/scripts/lib.sh" "${work}/packaging/scripts/lib.sh" && fail 'old and new toolsets are identical'

step 'release key and six healthy fixture releases, all v1 bundles without a native section'
openssl genpkey -algorithm ED25519 -out "${work}/release-private.pem"
openssl pkey -in "${work}/release-private.pem" -pubout -out "${work}/package-signing.pem"
chmod 0444 "${work}/package-signing.pem"
# The SBOM signs the packaging scripts like recipe.sh write_sbom: each listed
# with its SHA256 and its bytes (base64) in one tool annotation. 1.0.26 lists
# the digests only (the format before the bytes were carried); 1.0.29 signs
# digests its carried rollback.sh does not match (a broken or tampered build).
sequence=0
for version in 1.0.24 1.0.25 1.0.26 1.0.27 1.0.28 1.0.29; do
  sequence=$((sequence + 1))
  release=${work}/release-${version}
  mkdir -m 0755 "${release}"
  install -m 0555 "${bin}/fixture-${version}" "${release}/edge-agent"
  toolset=${work}/toolset-${version}
  mkdir -p "${toolset}/packaging/scripts"
  : >"${work}/files.jsonl"
  for script in lib install preflight rollback uninstall upgrade; do
    cp "${work}/packaging/scripts/${script}.sh" "${toolset}/packaging/scripts/${script}.sh"
    case "${version}" in 1.0.24|1.0.25|1.0.26) ;; *) printf '# toolset %s\n' "${version}" >>"${toolset}/packaging/scripts/${script}.sh" ;; esac
    carried=${toolset}/packaging/scripts/${script}.sh
    if [ "${version}" = 1.0.29 ] && [ "${script}" = rollback ]; then
      carried=${work}/tampered-rollback.sh
      cp "${toolset}/packaging/scripts/${script}.sh" "${carried}"
      printf '# tampered after signing\n' >>"${carried}"
    fi
    # The base64 of lib.sh exceeds one argument (MAX_ARG_STRLEN); pass files.
    base64 -w0 "${carried}" >"${work}/content.b64"
    jq -cn --arg name "${script}" --arg digest "$(sha256sum "${toolset}/packaging/scripts/${script}.sh" | cut -d' ' -f1)" \
      --rawfile content "${work}/content.b64" --argjson carry "$([ "${version}" = 1.0.26 ] && echo false || echo true)" \
      '{SPDXID:("SPDXRef-File-packaging-" + $name),checksums:[{algorithm:"SHA256",checksumValue:$digest}],fileName:("packaging/scripts/" + $name + ".sh")}
        + (if $carry then {annotations:[{annotationDate:"2026-07-22T00:00:00Z",annotationType:"OTHER",annotator:"Tool: transition-e2e",
          comment:("cdnca.packaging-script/v1 base64:" + $content)}]} else {} end)' >>"${work}/files.jsonl"
  done
  jq -cs --arg version "${version}" \
    '{SPDXID:"SPDXRef-DOCUMENT",creationInfo:{created:"2026-07-22T00:00:00Z",creators:["Tool: transition-e2e"]},dataLicense:"CC0-1.0",
      documentNamespace:("https://example.invalid/spdx/" + $version),files:.,name:("cdnca-edge-agent-" + $version),spdxVersion:"SPDX-2.3"}' \
    "${work}/files.jsonl" \
    >"${release}/edge-agent.spdx.json"
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
  # Full v1 bundle without --native.
  "${bin}/cdnca-edge-release-bundle" finalize --prepared-dir "${prepared}" --signature "${work}/sig-${version}" \
    --public-key "${work}/package-signing.pem" --download-base-url https://auth.example.test/downloads >/dev/null
  bundle_file=${prepared}/$(jq -r .bundle_file "${prepared}/bundle.json")
  [ "$(head -c 29 "${bundle_file}" | od -An -c | tr -d ' \n')" = 'cdnca-edge-release-bundle/v1\0' ] || fail "${version} is not a v1 bundle"
  cmp -s "${prepared}/edge-agent.spdx.json" "${release}/edge-agent.spdx.json" || fail "${version} bundle SBOM differs"
done

step 'root node installed with the old packaging toolset'
"${work}/old-packaging/scripts/install.sh" --runtime-identity root \
  --artifact "${work}/prep-1.0.24/edge-agent" --sbom "${work}/prep-1.0.24/edge-agent.spdx.json" \
  --manifest "${work}/prep-1.0.24/manifest" --signature "${work}/prep-1.0.24/manifest.sig" \
  --public-key "${work}/package-signing.pem" >/dev/null
cmp -s /usr/libexec/cdnca-edge-agent/lib.sh "${work}/old-packaging/scripts/lib.sh" || fail 'installed toolset is not the old one'
install -m 0555 "${bin}/cdnca-edge-agent-helper" /usr/libexec/cdnca-edge-agent-helper
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
systemctl is-active --quiet cdnca-edge-agent.service || fail 'agent unit inactive'

step 'the Agent version pointer links in its state'
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
printf '%s\n' transition-state >"${active}/state.txt"

cat >"${work}/hook.sh" <<EOF
#!/bin/bash
set -euo pipefail
fail() { printf 'hook failed: %s\n' "\$*" >&2; exit 1; }
work=${work}
active=${active}
digest=${digest}
links() {
  root=\$1
  for runtime in l4-runtime http3-runtime; do
    [ "\$(readlink "\${root}/\${runtime}/current")" = "versions/dynroute-l4-none-\${digest}" ] || fail "\${root}/\${runtime}/current"
  done
  for pointer in current lkg; do
    [ "\$(readlink "\${root}/certificates/\${pointer}")" = "versions/cert-v1-\${digest}" ] || fail "\${root}/certificates/\${pointer}"
  done
  [ "\$(cat "\${root}/state.txt")" = transition-state ] || fail "\${root}/state.txt"
}
toolset() {
  for script in lib install preflight rollback uninstall upgrade; do
    cmp -s "/usr/libexec/cdnca-edge-agent/\${script}.sh" "\${work}/toolset-\$1/packaging/scripts/\${script}.sh" || fail "\${script}.sh is not the \$1 toolset"
    [ "\$(stat -c '%u:%g:%a:%h' "/usr/libexec/cdnca-edge-agent/\${script}.sh")" = 0:0:555:1 ] || fail "\${script}.sh policy"
  done
  echo "installed toolset is \$1"
}
serving() {
  [ "\$(readlink /usr/lib/cdnca-edge-agent/current)" = "versions/\$1" ] || fail "current is not \$1"
  systemctl is-active --quiet cdnca-edge-agent.service || fail 'agent is not running'
  systemctl is-enabled --quiet cdnca-edge-agent.service || fail 'agent is not enabled'
  [ ! -e /var/lib/cdnca-edge-agent-packaging/transaction ] || fail 'a package transaction was left'
  links "\${active}"
  for release in /usr/lib/cdnca-edge-agent/versions/*; do
    [ ! -e "\${release}/native.tar.gz" ] || fail "\${release} has a native section"
  done
  echo "serving \$1 with the links intact"
}
record() {
  cat /var/lib/cdnca-edge-agent-packaging/toolset-refresh
  grep -Fx "status=\$1" /var/lib/cdnca-edge-agent-packaging/toolset-refresh >/dev/null || fail "refresh status is not \$1"
  grep -Fx "version=\$2" /var/lib/cdnca-edge-agent-packaging/toolset-refresh >/dev/null || fail "refresh record is not for \$2"
}
case "\$1" in
  after-refused) serving 1.0.24 ;;
  refresh)
    "\${work}/packaging/scripts/install.sh" --refresh-toolset \
      --artifact "\${work}/prep-1.0.25/edge-agent" --sbom "\${work}/prep-1.0.25/edge-agent.spdx.json" \
      --manifest "\${work}/prep-1.0.25/manifest" --signature "\${work}/prep-1.0.25/manifest.sig" \
      --public-key "\${work}/package-signing.pem"
    for script in lib install preflight rollback uninstall upgrade; do
      cmp -s "/usr/libexec/cdnca-edge-agent/\${script}.sh" "\${work}/packaging/scripts/\${script}.sh" || fail "\${script}.sh not refreshed"
      [ "\$(stat -c '%u:%g:%a:%h' "/usr/libexec/cdnca-edge-agent/\${script}.sh")" = 0:0:555:1 ] || fail "\${script}.sh policy"
    done
    grep -Fx release_sequence=1 /var/lib/cdnca-edge-agent-packaging/accepted-manifest >/dev/null || fail 'refresh changed replay state'
    serving 1.0.24
    ;;
  after-upgrade)
    serving 1.0.25; record ok 1.0.25; toolset 1.0.25
    backup=/var/lib/cdnca-edge-agent-backups/\$(readlink /var/lib/cdnca-edge-agent-backups/last-upgrade)
    links "\${backup}/state"
    ;;
  after-rollback) serving 1.0.24 ;;
  after-again) serving 1.0.26; record skipped 1.0.26; toolset 1.0.25 ;;
  after-auto) serving 1.0.27; record ok 1.0.27; toolset 1.0.27 ;;
  after-auto-rollback) serving 1.0.26; toolset 1.0.27 ;;
  after-auto-again) serving 1.0.28; record ok 1.0.28; toolset 1.0.28 ;;
  after-tampered)
    serving 1.0.29; record failed 1.0.29; toolset 1.0.28
    grep -Fx 'reason=cdnca-edge-agent packaging: packaging/scripts/rollback.sh differs from the signed SBOM' \
      /var/lib/cdnca-edge-agent-packaging/toolset-refresh >/dev/null || fail 'tampered toolset reason'
    [ -z "\$(find /var/lib/cdnca-edge-agent-packaging -maxdepth 1 -name '.toolset-staging.*')" ] || fail 'toolset staging was left'
    ;;
  *) fail "unknown phase \$1" ;;
esac
EOF
chmod 0755 "${work}/hook.sh"

step 'refused, refresh, upgrade, rollback, upgrade, auto refresh, rollback, upgrade, tampered through the production helper'
CDNCA_ROOT_HELPER_E2E_DIR=${work} CDNCA_TRANSITION_HOOK=${work}/hook.sh "${bin}/updater.e2e.test" \
  -test.run TestRootAgentToolsetTransitionThroughProductionHelper -test.v -test.timeout 10m
printf 'ROOT_HELPER_TRANSITION_E2E PASS\n'
