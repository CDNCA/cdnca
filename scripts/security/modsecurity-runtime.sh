#!/bin/sh
# Prints the directory holding libmodsecurity + ModSecurity-nginx + CRS built
# for the pinned e2e OpenResty image (edge/openresty/runtime.env), building it
# once with edge/openresty/modsecurity/build.sh. The cache key is the sha256 of
# the recipe, the lock file, the patches and the image, so any change rebuilds.
#   MODSECURITY_CACHE (default ~/.cache/cdnca-modsecurity)
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
recipe="${repo_root}/edge/openresty/modsecurity"
cache="${MODSECURITY_CACHE:-${HOME}/.cache/cdnca-modsecurity}"
key="$(cat "${recipe}/build.sh" "${recipe}/sources.lock.json" "${recipe}"/patches/*.patch | { cat; printf '%s' "${OPENRESTY_IMAGE}"; } | shasum -a 256 | cut -c1-16)"
# An existing build of the same engine sources may be reused explicitly.
[ -n "${MODSECURITY_RUNTIME:-}" ] && { printf '%s\n' "${MODSECURITY_RUNTIME}"; exit 0; }
out="${cache}/${key}"
if [ ! -f "${out}/modules/ngx_http_modsecurity_module.so" ]; then
  sh "${recipe}/fetch-sources.sh" "${cache}/src" >&2
  tarball="${cache}/src/openresty-${OPENRESTY_VERSION}.tar.gz"
  # Same rule as fetch-sources.sh: a wrong digest is re-downloaded, and the
  # download is renamed into place only after it verifies.
  if ! printf '%s  %s\n' "${OPENRESTY_TARBALL_SHA256}" "${tarball}" | shasum -a 256 -c - >/dev/null 2>&1; then
    part="${cache}/src/.openresty-${OPENRESTY_VERSION}.tar.gz.$$.part"
    curl -fsSL "${OPENRESTY_TARBALL_URL}" -o "${part}" \
      && printf '%s  %s\n' "${OPENRESTY_TARBALL_SHA256}" "${part}" | shasum -a 256 -c - >&2 || { rm -f "${part}"; exit 1; }
    mv -f "${part}" "${tarball}"
  fi
  # A per-process build directory: concurrent callers must not share or delete it.
  tmp="${out}.tmp.$$"
  rm -rf "${tmp}" && mkdir -p "${tmp}"
  docker run --rm --network none -v "${recipe}:/recipe:ro" -v "${cache}/src:/src:ro" -v "${tmp}:/out" \
    --entrypoint sh "${OPENRESTY_IMAGE}" -c "BUILD_JOBS=\${BUILD_JOBS:-8} sh /recipe/build.sh /src /src/openresty-${OPENRESTY_VERSION}.tar.gz /usr/local/openresty/modsecurity >/out/build.sha256 && cp -a /usr/local/openresty/modsecurity/. /out/" >&2
  # mv onto an existing directory would nest it: keep the first finished build.
  if [ -d "${out}" ]; then rm -rf "${tmp}"; else mv "${tmp}" "${out}"; fi
fi
printf '%s\n' "${out}"
