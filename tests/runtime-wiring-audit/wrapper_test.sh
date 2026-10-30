#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd -P)
candidate=$repo_root/tools/runtime-wiring-audit/.wrapper-output-must-not-exist
stderr_file=$(mktemp "${TMPDIR:-/tmp}/runtime-wiring-wrapper.XXXXXX")
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/runtime-wiring-fixture.XXXXXX")
report_root=$(mktemp -d "${TMPDIR:-/tmp}/runtime-wiring-report.XXXXXX")
trap 'rm -f "$stderr_file"; rm -rf "$fixture_root" "$report_root"' EXIT HUP INT TERM

if [ -e "$candidate" ]; then
  echo "wrapper fixture path already exists: $candidate" >&2
  exit 1
fi
if "$repo_root/scripts/runtime-wiring-audit.sh" --root "$repo_root" --out "$candidate" 2>"$stderr_file"; then
  echo "wrapper accepted a repository-internal output path" >&2
  exit 1
fi
if [ -e "$candidate" ]; then
  echo "wrapper created repository-internal output before rejecting it" >&2
  exit 1
fi
if ! grep -q "output directory must be outside the repository" "$stderr_file"; then
  echo "wrapper did not return the expected rejection" >&2
  exit 1
fi

cp -R "$repo_root/tests/runtime-wiring-audit/fixtures/project/." "$fixture_root/"
"$repo_root/scripts/runtime-wiring-audit.sh" --root "$fixture_root" --out "$report_root/audit" >/dev/null
manifest=$report_root/audit/run-1/source-manifest.json
"$repo_root/scripts/runtime-wiring-audit.sh" --root "$fixture_root" --verify-source-manifest "$manifest" >/dev/null

mkdir -p "$fixture_root/services/control-api/internal/wrapperdrift"
printf '%s\n' 'package wrapperdrift' >"$fixture_root/services/control-api/internal/wrapperdrift/new.go"
if "$repo_root/scripts/runtime-wiring-audit.sh" --root "$fixture_root" --verify-source-manifest "$manifest" > /dev/null 2>"$stderr_file"; then
  echo "wrapper accepted a stale source manifest" >&2
  exit 1
fi
if ! grep -q "source manifest stale" "$stderr_file"; then
  echo "wrapper did not report source manifest drift" >&2
  exit 1
fi
