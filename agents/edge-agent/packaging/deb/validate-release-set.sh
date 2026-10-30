#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf 'edge native release set: %s\n' "$1" >&2
  exit 1
}

[ "$#" -eq 1 ] || fail 'usage: validate-release-set.sh PACKAGES_MANIFEST'
manifest=$1
[ -f "${manifest}" ] && [ ! -L "${manifest}" ] && [ -r "${manifest}" ] || fail 'unsafe packages manifest'

LC_ALL=C awk -F '\t' '
  function reject(message) {
    print "edge native release set: " message > "/dev/stderr"
    exit 1
  }

  NF != 6 { reject("packages manifest must contain exactly six fields") }
  $1 != "amd64" && $1 != "arm64" { reject("unsupported architecture " $1) }
  $3 !~ /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)([-+][0-9A-Za-z.-]+)?$/ {
    reject("invalid release version " $3)
  }
  $4 !~ /^[1-9][0-9]*$/ { reject("invalid release sequence " $4) }
  $5 !~ /^[A-Za-z0-9][A-Za-z0-9._\/-]*$/ || $5 ~ /(^|\/)\.\.?($|\/)/ || $5 ~ /\/\// {
    reject("invalid package path " $5)
  }
  $6 !~ /^[0-9a-f]+$/ || length($6) != 64 { reject("invalid package digest") }

  {
    architecture_key = $3 SUBSEP $1
    if (architecture_key in seen_architecture) {
      reject("duplicate " $3 "/" $1 " package")
    }
    seen_architecture[architecture_key] = 1
    version_count[$3]++

    if (($3 in version_sequence) && version_sequence[$3] != $4) {
      reject("version " $3 " has multiple release sequences")
    }
    version_sequence[$3] = $4
    if (($4 in sequence_version) && sequence_version[$4] != $3) {
      reject("release sequence " $4 " is shared by multiple versions")
    }
    sequence_version[$4] = $3
  }

  END {
    if (NR == 0) {
      reject("packages manifest is empty")
    }
    for (version in version_count) {
      if (version_count[version] != 2 ||
          !((version SUBSEP "amd64") in seen_architecture) ||
          !((version SUBSEP "arm64") in seen_architecture)) {
        reject("version " version " does not contain exactly amd64 and arm64")
      }
    }
  }
' "${manifest}"

printf 'EDGE_AGENT_NATIVE_RELEASE_SET PASS\n'
