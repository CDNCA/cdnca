#!/bin/sh
# Repacks the official ClamAV 1.4.6 LTS Linux x86_64 build into the portable
# runtime used by install-ubuntu-dependencies.sh on Debian 10/11 and Ubuntu
# 20.04 (docs/install/os-support-matrix.md). Their own ClamAV 0.103 packages are
# refused by the signature CDN ("Blocked by CDN"), so freshclam cannot update.
# Nothing is compiled: the upstream RPM is verified against its pinned SHA-256
# (the digest GitHub publishes for the release asset), its /usr/local tree is
# moved under one prefix and the absolute RPATH becomes $ORIGIN-relative.
# The upstream build needs glibc 2.28 (libclamav uses statx/fcntl64).
#
# Usage (on any Docker host): build-portable-clamav.sh OUTPUT_DIRECTORY
# Produces clamav-1.4.6-portable-linux-amd64.tar.gz and SHA256SUMS; the digest
# is pinned in install-ubuntu-dependencies.sh and the archive is published next
# to the portable PostgreSQL build.
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 OUTPUT_DIRECTORY" >&2; exit 64; }
output=$(cd "$1" && pwd -P)
here=$(cd "$(dirname "$0")" && pwd -P)
builder=debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
docker run --rm --platform linux/amd64 -v "$output:/out" -v "$here/build-portable-clamav-inner.sh:/build.sh:ro" "$builder" bash /build.sh
cat "$output/SHA256SUMS" "$output/glibc-floor.txt"
