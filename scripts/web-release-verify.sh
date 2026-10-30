#!/usr/bin/env bash
set -euo pipefail

ARCHIVE_PATH=""
MANIFEST_PATH=""
RELEASE_DIR=""
CURRENT_MANIFEST_PATH=""

usage() {
  cat <<'EOF'
Usage: scripts/web-release-verify.sh --archive FILE --manifest FILE [options]

Verify a Web release archive, its manifest, and an optional extracted directory.

Options:
  --archive FILE          Release archive
  --manifest FILE         Release manifest
  --release-dir DIR       Extracted release directory to verify
  --current-manifest FILE Active release manifest; candidate must be newer
  -h, --help              Show this help
EOF
}

fail() {
  printf 'WEB_RELEASE_VERIFY FAIL: %s\n' "$1" >&2
  exit 1
}

while (($# > 0)); do
  case "$1" in
    --archive)
      (($# >= 2)) || fail '--archive requires a value'
      ARCHIVE_PATH=$2
      shift 2
      ;;
    --manifest)
      (($# >= 2)) || fail '--manifest requires a value'
      MANIFEST_PATH=$2
      shift 2
      ;;
    --release-dir)
      (($# >= 2)) || fail '--release-dir requires a value'
      RELEASE_DIR=$2
      shift 2
      ;;
    --current-manifest)
      (($# >= 2)) || fail '--current-manifest requires a value'
      CURRENT_MANIFEST_PATH=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "$ARCHIVE_PATH" ]] || fail '--archive is required'
[[ -n "$MANIFEST_PATH" ]] || fail '--manifest is required'
[[ -f "$ARCHIVE_PATH" ]] || fail "archive does not exist: $ARCHIVE_PATH"
[[ -f "$MANIFEST_PATH" ]] || fail "manifest does not exist: $MANIFEST_PATH"
[[ -z "$RELEASE_DIR" || -d "$RELEASE_DIR" ]] || fail "release directory does not exist: $RELEASE_DIR"
[[ -z "$CURRENT_MANIFEST_PATH" || -f "$CURRENT_MANIFEST_PATH" ]] || fail "current manifest does not exist: $CURRENT_MANIFEST_PATH"

for command in jq tar mktemp; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is unavailable: $command"
done

if command -v sha256sum >/dev/null 2>&1; then
  sha256_file() { sha256sum "$1" | awk '{print $1}'; }
else
  command -v shasum >/dev/null 2>&1 || fail 'sha256sum or shasum is required'
  sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

manifest_schema=$(jq -er '.schema' "$MANIFEST_PATH") || fail 'manifest is not valid JSON'
[[ "$manifest_schema" == 'cdnca.web.release/v1' ]] || fail "unsupported manifest schema: $manifest_schema"
package_commerce_enabled=$(jq -er '.build.package_commerce_enabled | if type == "boolean" then tostring else empty end' "$MANIFEST_PATH") ||
  fail 'manifest build.package_commerce_enabled is missing or not boolean'
[[ "$package_commerce_enabled" == true ]] || fail 'production Web release must keep package commerce enabled'
archive_name=$(jq -er '.artifact.file' "$MANIFEST_PATH") || fail 'manifest artifact file is missing'
[[ "$archive_name" == "$(basename "$ARCHIVE_PATH")" ]] || fail 'manifest artifact file does not match archive name'
archive_sha256=$(jq -er '.artifact.sha256' "$MANIFEST_PATH") || fail 'manifest archive digest is missing'
[[ "$archive_sha256" == "$(sha256_file "$ARCHIVE_PATH")" ]] || fail 'archive SHA-256 does not match manifest'

built_at=$(jq -er '.built_at | select(test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))' "$MANIFEST_PATH") ||
  fail 'manifest built_at is missing or not canonical UTC'
source_commit=$(jq -er '.source.commit | select(test("^[0-9a-f]{40}$"))' "$MANIFEST_PATH") ||
  fail 'manifest source commit is missing or invalid'
source_tree=$(jq -er '.source.tree | select(test("^[0-9a-f]{40}$"))' "$MANIFEST_PATH") ||
  fail 'manifest source tree is missing or invalid'
file_count=$(jq -er '.files | if type == "array" then length else error end' "$MANIFEST_PATH") ||
  fail 'manifest files is not an array'
[[ "$file_count" -gt 0 ]] || fail 'manifest has no files'

if [[ -n "$CURRENT_MANIFEST_PATH" ]]; then
  current_built_at=$(jq -er '.built_at | select(test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))' "$CURRENT_MANIFEST_PATH") ||
    fail 'current manifest built_at is missing or not canonical UTC'
  [[ "$built_at" > "$current_built_at" ]] || fail "candidate built_at=$built_at is not newer than current=$current_built_at"
fi

VERIFY_DIR="$RELEASE_DIR"
TEMP_DIR=""
cleanup() {
  [[ -z "$TEMP_DIR" ]] || rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

if [[ -z "$VERIFY_DIR" ]]; then
  TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-web-release-verify.XXXXXX")"
  VERIFY_DIR=$TEMP_DIR
  tar -xzf "$ARCHIVE_PATH" -C "$VERIFY_DIR" || fail 'archive extraction failed'
fi

while IFS=$'\t' read -r expected_sha expected_bytes relative_path; do
  [[ -n "$relative_path" ]] || fail 'manifest contains an empty file path'
  case "$relative_path" in
    /*|.|..|./*|../*|*/../*|*/..) fail "unsafe file path: $relative_path" ;;
  esac
  file_path="$VERIFY_DIR/$relative_path"
  [[ -f "$file_path" && ! -L "$file_path" ]] || fail "release file is missing or is a symlink: $relative_path"
  actual_bytes=$(wc -c <"$file_path" | tr -d '[:space:]')
  [[ "$actual_bytes" == "$expected_bytes" ]] || fail "file size mismatch: $relative_path"
  actual_sha=$(sha256_file "$file_path")
  [[ "$actual_sha" == "$expected_sha" ]] || fail "file SHA-256 mismatch: $relative_path"
done < <(jq -er '.files[] | [.sha256, (.bytes | tostring), .path] | @tsv' "$MANIFEST_PATH") ||
  fail 'manifest file verification failed'

printf 'WEB_RELEASE_VERIFY PASS\n'
printf 'source_commit=%s\n' "$source_commit"
printf 'source_tree=%s\n' "$source_tree"
printf 'built_at=%s\n' "$built_at"
printf 'archive_sha256=%s\n' "$archive_sha256"
printf 'file_count=%s\n' "$file_count"
