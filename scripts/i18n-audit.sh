#!/bin/sh

set -eu

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

if [ -n "${I18N_AUDIT_OUTPUT_DIR:-}" ]; then
  output_directory=$I18N_AUDIT_OUTPUT_DIR
else
  output_directory=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-i18n-audit.XXXXXX")
fi

if [ -n "${I18N_AUDIT_BASELINE:-}" ]; then
  exec node "$repository_root/tools/i18n-audit/cli.mjs" \
    --root "$repository_root" \
    --output-dir "$output_directory" \
    --baseline "$I18N_AUDIT_BASELINE"
fi

exec node "$repository_root/tools/i18n-audit/cli.mjs" \
  --root "$repository_root" \
  --output-dir "$output_directory"
