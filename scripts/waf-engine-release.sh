#!/bin/sh
# Prepares the OWASP CRS engine extension for the download server. The
# extension is signed by the platform release key, the same key and the same
# flow as the native node package (release.signing-data -> raw Ed25519 on the
# release signing host -> base64 signature), so one published extension is
# valid for the nodes of every control plane.
#
#   WAF_ENGINE_KEY_ID=<platform release key ID> \
#     scripts/waf-engine-release.sh prepare <out-dir> [amd64|arm64]
#     1. builds the extension with edge/openresty/modsecurity/Dockerfile for
#        linux/<arch>: the native runtime's own pinned base image and verified,
#        patched OpenResty source (a module only loads into that nginx/musl);
#     2. builds waf-engine-package in the edge-agent builder image of
#        agents/edge-agent/packaging/build/contract.json and runs prepare there:
#        <out-dir>/<download path>/{cdnca-waf-crs-module-*.tar.gz, manifest.json}
#        and <out-dir>/waf-<arch>/release.signing-data (not uploaded);
#     3. prints what to sign. No private key is ever read here.
#
#   scripts/waf-engine-release.sh finalize <out-dir> <amd64|arm64> <artifacts.json> <KEY_ID=signature-file>...
#     <artifacts.json> is the published platform trust document
#     (downloads/edge-agent/artifacts.json); every KEY_ID must be listed there.
#     Several KEY_ID=file pairs sign with several keys (release key rotation).
#     Verifies every signature exactly as a node does and writes
#     signatures.json and SHA256SUMS.
#
# Upload the resulting directory as downloads/waf-crs-module/<version>/openresty-<openresty>/linux-<arch>/.
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
command="${1:?prepare|finalize}"
out="${2:?output directory}"
contract="${repo_root}/agents/edge-agent/packaging/build/contract.json"
builder="$(sed -n 's/.*"image": "\([^"]*\)".*/\1/p' "${contract}" | head -1)"
version="$(tr -d '[:space:]' <"${repo_root}/edge/openresty/modsecurity/VERSION")"
openresty="$(sed -n 's/.*"version": "\([0-9.]*\)".*/\1/p' "${repo_root}/edge/openresty/native/sources.lock.json" | head -1)"
[ -n "${builder}" ] && [ -n "${version}" ] && [ -n "${openresty}" ] || { echo "cannot read builder/version/openresty" >&2; exit 1; }
# WAF_ENGINE_TOOL=<host binary of waf-engine-package> skips the builder image
# (tests); the release always uses the contract builder.
tool() { # args...: run waf-engine-package with /out = <out-dir>
  if [ -n "${WAF_ENGINE_TOOL:-}" ]; then
    "${WAF_ENGINE_TOOL}" "$@"
    return
  fi
  docker run --rm --platform linux/amd64 -v "${repo_root}:/src:ro" -v "${out}:/out" -v "${GOMODCACHE:-${HOME}/go/pkg/mod}:/go/pkg/mod" \
    -e GOCACHE=/tmp/gocache -w /src/agents/edge-agent \
    -e GOFLAGS=-mod=readonly -e GOWORK=off "${builder}" \
    sh -c 'go run -trimpath ./internal/wafengine/cmd/waf-engine-package "$@"' waf-engine-package "$@"
}
# p PATH: PATH below <out-dir> as the tool sees it.
p() { if [ -n "${WAF_ENGINE_TOOL:-}" ]; then printf '%s/%s' "${out}" "$1"; else printf '/out/%s' "$1"; fi; }
case "${command}" in
  prepare)
    arch="${3:-amd64}"
    path="waf-crs-module/${version}/openresty-${openresty}/linux-${arch}"
    key_id="${WAF_ENGINE_KEY_ID:?platform release key ID (the key_id of downloads/edge-agent/artifacts.json that signs node packages)}"
    [ ! -e "${out}/${path}" ] && [ ! -e "${out}/waf-${arch}" ] || { echo "${out}/${path} or ${out}/waf-${arch} exists" >&2; exit 1; }
    mkdir -p "$(dirname "${out}/${path}")" "${out}/waf-${arch}"
    if [ -n "${WAF_ENGINE_TREE:-}" ]; then # tests: an already built extension tree
      cp -R "${WAF_ENGINE_TREE}" "${out}/build-${arch}"
    else
      mkdir -p "${out}/build-${arch}"
      docker buildx build --platform "linux/${arch}" -f "${repo_root}/edge/openresty/modsecurity/Dockerfile" \
        --target extension --output "type=local,dest=${out}/build-${arch}" "${repo_root}"
      [ "$(cat "${out}/build-${arch}/nginx-version.txt")" = "${openresty%.*}" ] ||
        { echo "extension was not built against OpenResty ${openresty}" >&2; exit 1; }
    fi
    set -- --tree "$(p "build-${arch}")" --version "${version}" --openresty "${openresty}" --arch "${arch}" \
      --key-id "${key_id}" --out "$(p "${path}")" --signing-data "$(p "waf-${arch}/release.signing-data")"
    tool prepare "$@"
    echo "sign ${out}/waf-${arch}/release.signing-data with the platform release key ${key_id}"
    echo "  (the same raw Ed25519 + base64 flow as a node package's release.signing-data; output ${out}/waf-${arch}.sig)"
    echo "then: $0 finalize ${out} ${arch} <downloads/edge-agent/artifacts.json> ${key_id}=${out}/waf-${arch}.sig"
    ;;
  finalize)
    arch="${3:?amd64|arm64}"
    trust="${4:?platform artifact trust document}"
    shift 4
    [ "$#" -gt 0 ] || { echo "at least one KEY_ID=signature-file is required" >&2; exit 1; }
    path="waf-crs-module/${version}/openresty-${openresty}/linux-${arch}"
    stage="${out}/.finalize-${arch}"
    rm -rf "${stage}" && mkdir -m 0700 "${stage}"
    trap 'rm -rf "${stage}"' EXIT INT TERM
    cp "${trust}" "${stage}/trust.json"
    args=""
    index=0
    for pair in "$@"; do
      key="${pair%%=*}"; file="${pair#*=}"
      case "${key}" in ''|*[!A-Za-z0-9._-]*) echo "invalid key ID in ${pair}" >&2; exit 1 ;; esac
      [ "${key}" != "${pair}" ] && [ -f "${file}" ] || { echo "invalid signature argument ${pair}" >&2; exit 1; }
      index=$((index + 1))
      cp "${file}" "${stage}/platform-${index}.sig"
      args="${args} --signature ${key}=$(p ".finalize-${arch}/platform-${index}.sig")"
    done
    # Key IDs are [A-Za-z0-9._-] (checked above) and the staged file names
    # are fixed, so word splitting of ${args} is safe.
    # shellcheck disable=SC2086
    tool finalize --dir "$(p "${path}")" --trust "$(p ".finalize-${arch}/trust.json")" ${args}
    cat "${out}/${path}/SHA256SUMS"
    ;;
  *) echo "unknown command ${command}" >&2; exit 1 ;;
esac
