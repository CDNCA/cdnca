#!/bin/sh
# Downloads every source named in sources.lock.json into <dir> and checks the
# pinned sha256 (an existing file with the right digest is reused).
#   fetch-sources.sh <dir>
set -eu
dir="$1"
lock="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/sources.lock.json"
mkdir -p "${dir}"
if command -v sha256sum >/dev/null 2>&1; then check() { sha256sum -c -; }; else check() { shasum -a 256 -c -; }; fi
for source in libmodsecurity modsecurity_nginx yajl libxml2; do
  block="$(sed -n "/\"${source}\": {/,/}/p" "${lock}")"
  url="$(printf '%s\n' "${block}" | sed -n 's/.*"url": "\([^"]*\)".*/\1/p')"
  file="$(printf '%s\n' "${block}" | sed -n 's/.*"file": "\([^"]*\)".*/\1/p')"
  sum="$(printf '%s\n' "${block}" | sed -n 's/.*"sha256": "\([^"]*\)".*/\1/p')"
  if ! printf '%s  %s\n' "${sum}" "${dir}/${file}" | check >/dev/null 2>&1; then
    # Download beside the target and rename only after the digest matches, so a
    # concurrent or interrupted run never leaves a partial file under the final name.
    part="${dir}/.${file}.$$.part"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' "${url}" -o "${part}" \
      && printf '%s  %s\n' "${sum}" "${part}" | check >/dev/null || { rm -f "${part}"; echo "${file}: download or sha256 check failed" >&2; exit 1; }
    mv -f "${part}" "${dir}/${file}"
  fi
done
