#!/bin/sh
set -eu

usage() {
  echo "usage: scripts/runtime-wiring-audit.sh [--root REPOSITORY] (--out TEMP_DIRECTORY | --verify-source-manifest MANIFEST)" >&2
}

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
tool_repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd -P)
repo_root=$tool_repo_root
out_dir=
verify_manifest=

while [ "$#" -gt 0 ]; do
  case "$1" in
    --root)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      repo_root=$2
      shift 2
      ;;
    --out)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      out_dir=$2
      shift 2
      ;;
    --verify-source-manifest)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      verify_manifest=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

repo_root=$(CDPATH='' cd -- "$repo_root" && pwd -P)

if [ -n "$verify_manifest" ]; then
  [ -z "$out_dir" ] || { usage; exit 2; }
  case "$verify_manifest" in
    /*) ;;
    *) verify_manifest=$(pwd -P)/$verify_manifest ;;
  esac
  (
    cd "$tool_repo_root/tools/runtime-wiring-audit"
    GOWORK=off go run . --root "$repo_root" --verify-source-manifest "$verify_manifest"
  )
  exit 0
fi

[ -n "$out_dir" ] || { usage; exit 2; }
case "$out_dir" in
  /*) ;;
  *) out_dir=$(pwd -P)/$out_dir ;;
esac

case "$out_dir" in
  "$repo_root"|"$repo_root"/*)
    echo "runtime-wiring-audit: output directory must be outside the repository" >&2
    exit 1
    ;;
esac

if [ -e "$out_dir" ] && [ -n "$(find "$out_dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
  echo "runtime-wiring-audit: output directory must be absent or empty" >&2
  exit 1
fi

run_audit() {
  destination=$1
  (
    cd "$tool_repo_root/tools/runtime-wiring-audit"
    GOWORK=off go run . --root "$repo_root" --tool-root "$tool_repo_root" --out "$destination"
  )
}

verify_source() {
  manifest=$1
  (
    cd "$tool_repo_root/tools/runtime-wiring-audit"
    GOWORK=off go run . --root "$repo_root" --verify-source-manifest "$manifest"
  )
}

run_audit "$out_dir/run-1"
verify_source "$out_dir/run-1/source-manifest.json"
run_audit "$out_dir/run-2"
verify_source "$out_dir/run-1/source-manifest.json"

for artifact in report.json report.md source-manifest.json tool-source-manifest.json SHA256SUMS; do
  if ! cmp -s "$out_dir/run-1/$artifact" "$out_dir/run-2/$artifact"; then
    echo "runtime-wiring-audit: non-deterministic artifact: $artifact" >&2
    exit 1
  fi
done

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$out_dir/run-1/report.json" "$out_dir/run-1/report.md" >"$out_dir/determinism.sha256"
else
  shasum -a 256 "$out_dir/run-1/report.json" "$out_dir/run-1/report.md" >"$out_dir/determinism.sha256"
fi

echo "runtime-wiring-audit: deterministic report written under $out_dir"
sed -n '1p' "$out_dir/determinism.sha256"
