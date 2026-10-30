#!/bin/sh
# Builds ClamAV 1.4.6 LTS from the official source release against musl, with
# its own loader and libraries, for hosts whose glibc is older than the 2.28
# the official binary build needs (Ubuntu 18.04, CentOS 7; see
# docs/install/os-support-matrix.md). The result never loads a host library:
# every ELF's interpreter is the bundled ld-musl and its RPATH is $ORIGIN-based.
# Same prefix and layout as build-portable-clamav.sh, so install-ubuntu-dependencies.sh
# only switches the pinned archive name and digest per host profile.
#
# Usage (on any Docker host): build-portable-clamav-musl.sh OUTPUT_DIRECTORY
# Produces clamav-1.4.6-portable-musl-linux-amd64.tar.gz and SHA256SUMS.
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 OUTPUT_DIRECTORY" >&2; exit 64; }
output=$(cd "$1" && pwd -P)
here=$(cd "$(dirname "$0")" && pwd -P)
# alpine:3.22 (index digest, 2026-09-17)
builder=alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
docker run --rm --platform linux/amd64 -v "$output:/out" -v "$here/build-portable-clamav-musl-inner.sh:/build.sh:ro" "$builder" sh /build.sh
cat "$output/SHA256SUMS"
