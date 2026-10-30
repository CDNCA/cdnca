#!/usr/bin/env bash
# Build the narrowly scoped upstream creation-time fixes, not an official binary.
set -euo pipefail

build_native_nats() {
  [[ $# == 2 && $1 == /* && $2 == /* && -f $1 && ! -L $1 && ! -e $2 && ! -L $2 ]] || {
    printf '%s\n' 'usage: build-nats-backport.sh ABSOLUTE_SOURCE_ARCHIVE NEW_ABSOLUTE_OUTPUT_DIRECTORY' >&2
    return 1
  }
  local archive=$1 output=$2 script_directory archive_digest
  script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
  archive_digest=$(shasum -a 256 "$archive")
  [[ ${archive_digest%% *} == eae064b528154b5392ffef0dc993e1c53aee0ab491dcf1bf9185da59003daf03 ]] || {
    printf '%s\n' 'nats_source_checksum_mismatch' >&2
    return 1
  }
  mkdir -m 0700 -- "$output"
  mkdir -m 0700 -- "$output/source"
  tar -xzf "$archive" -C "$output/source" --strip-components=1
  git -C "$output/source" apply --unidiff-zero --check "$script_directory/nats-server-2.12.15-cdnca.1.patch"
  git -C "$output/source" apply --unidiff-zero "$script_directory/nats-server-2.12.15-cdnca.1.patch"
  (
    cd -- "$output/source"
    GOWORK=off GOTOOLCHAIN=go1.27.3 GOSUMDB=sum.golang.org CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$output/nats-server-2.12.15-cdnca.1" .
  )
  cp -- "$output/source/LICENSE" "$output/NATS-LICENSE"
  shasum -a 256 "$output/nats-server-2.12.15-cdnca.1" "$script_directory/nats-server-2.12.15-cdnca.1.patch"
}

build_native_nats "$@"
