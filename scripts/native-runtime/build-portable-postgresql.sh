#!/bin/sh
# Builds the portable PostgreSQL 17.11 runtime used by install-ubuntu-dependencies.sh
# on hosts without a PGDG 17.11 package (Ubuntu 16.04/18.04/20.04, Debian 9/10,
# CentOS 7; docs/install/os-support-matrix.md). Built on glibc 2.17 so it runs on
# every supported host. The control plane only uses core features
# (gen_random_uuid, no extensions) over loopback with sslmode=disable, so ICU,
# readline and OpenSSL are left out and the runtime needs only glibc and zlib.
#
# Usage (on any Docker host): build-portable-postgresql.sh OUTPUT_DIRECTORY
# Produces postgresql-17.11-portable-linux-amd64.tar.gz and SHA256SUMS; the
# digest is then pinned in portable-postgresql-17.11.json and the archive is
# published at its download_url (same release process as the other pins).
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 OUTPUT_DIRECTORY" >&2; exit 64; }
output=$(cd "$1" && pwd -P)
here=$(cd "$(dirname "$0")" && pwd -P)
builder=quay.io/pypa/manylinux2014_x86_64@sha256:f6a6f153c9cf45470507ebbc27013e5db14ce21331b62fd2c540561f25e5f0a5
docker run --rm --platform linux/amd64 -e CENTOS_VAULT_MIRROR="${CENTOS_VAULT_MIRROR:-https://mirrors.aliyun.com/centos-vault}" -v "$output:/out" -v "$here/build-portable-postgresql-inner.sh:/build.sh:ro" "$builder" bash /build.sh
cat "$output/SHA256SUMS" "$output/glibc-floor.txt"
