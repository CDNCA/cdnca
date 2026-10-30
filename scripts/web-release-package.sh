#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_REF="HEAD"
OUTPUT_DIR="${WEB_RELEASE_OUTPUT_DIR:-${ROOT_DIR}/output/web-releases}"
TURNSTILE_SITE_KEY="${VITE_TURNSTILE_SITE_KEY:-}"
PACKAGE_COMMERCE_ENABLED="${VITE_PACKAGE_COMMERCE_ENABLED:-true}"
PREVIOUS_MANIFEST_PATH=""
PREVIOUS_ARCHIVE_PATH=""
ALLOW_EMPTY_TURNSTILE_SITE_KEY=false

usage() {
  cat <<'EOF'
Usage: scripts/web-release-package.sh [options]

Build a Web release from an immutable Git commit and emit an archive plus manifest.
The current working tree is never used as build input.

Options:
  --source-ref REF          Git commit/ref to package (default: HEAD)
  --output-dir DIR          Directory for the archive and manifest
  --turnstile-site-key KEY  Public VITE_TURNSTILE_SITE_KEY build value
  --package-commerce-enabled
                            Build with VITE_PACKAGE_COMMERCE_ENABLED=true
  --allow-empty-turnstile-site-key
                            Preserve a verified active release with no site key
  --previous-manifest FILE  Active release manifest; candidate must descend from it and retain its hash assets
  -h, --help                Show this help

The key can also be supplied through VITE_TURNSTILE_SITE_KEY.
EOF
}

while (($# > 0)); do
  case "$1" in
    --source-ref)
      (($# >= 2)) || { printf '%s\n' '--source-ref requires a value' >&2; exit 2; }
      SOURCE_REF=$2
      shift 2
      ;;
    --output-dir)
      (($# >= 2)) || { printf '%s\n' '--output-dir requires a value' >&2; exit 2; }
      OUTPUT_DIR=$2
      shift 2
      ;;
    --turnstile-site-key)
      (($# >= 2)) || { printf '%s\n' '--turnstile-site-key requires a value' >&2; exit 2; }
      TURNSTILE_SITE_KEY=$2
      shift 2
      ;;
    --package-commerce-enabled)
      PACKAGE_COMMERCE_ENABLED=true
      shift
      ;;
    --allow-empty-turnstile-site-key)
      ALLOW_EMPTY_TURNSTILE_SITE_KEY=true
      shift
      ;;
    --previous-manifest)
      (($# >= 2)) || { printf '%s\n' '--previous-manifest requires a value' >&2; exit 2; }
      PREVIOUS_MANIFEST_PATH=$2
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

[[ "$PACKAGE_COMMERCE_ENABLED" == true ]] || {
  printf 'production Web releases require VITE_PACKAGE_COMMERCE_ENABLED=true; refusing a disabled package menu build\n' >&2
  exit 2
}

for command in git node pnpm tar gzip shasum; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'required command is unavailable: %s\n' "$command" >&2
    exit 1
  }
done

REPO_ROOT="$(git -C "$ROOT_DIR" rev-parse --show-toplevel)"
[[ "$REPO_ROOT" == "$ROOT_DIR" ]] || {
  printf 'unexpected repository root: %s\n' "$REPO_ROOT" >&2
  exit 1
}

SOURCE_COMMIT="$(git -C "$ROOT_DIR" rev-parse --verify "${SOURCE_REF}^{commit}")" || {
  printf 'source ref is not a commit: %s\n' "$SOURCE_REF" >&2
  exit 1
}
SOURCE_TREE="$(git -C "$ROOT_DIR" rev-parse --verify "${SOURCE_COMMIT}^{tree}")"
BUILT_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ -n "$PREVIOUS_MANIFEST_PATH" ]]; then
  [[ -f "$PREVIOUS_MANIFEST_PATH" ]] || {
    printf 'previous manifest does not exist: %s\n' "$PREVIOUS_MANIFEST_PATH" >&2
    exit 1
  }
  PREVIOUS_COMMIT="$(node - "$PREVIOUS_MANIFEST_PATH" <<'NODE'
const fs = require('node:fs')

const manifest = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))
const commit = manifest?.source?.commit
if (!/^[0-9a-f]{40}$/.test(commit ?? '')) process.exit(1)
process.stdout.write(commit)
NODE
)" || {
    printf 'previous manifest has no valid source commit: %s\n' "$PREVIOUS_MANIFEST_PATH" >&2
    exit 1
  }
  PREVIOUS_ARCHIVE_PATH="$(node - "$PREVIOUS_MANIFEST_PATH" <<'NODE'
const fs = require('node:fs')
const path = require('node:path')

const manifestPath = process.argv[2]
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
const archive = manifest?.artifact?.file
const base = path.resolve(path.dirname(manifestPath))
const resolved = typeof archive === 'string' && archive.length > 0 && !path.isAbsolute(archive)
  ? path.resolve(base, archive)
  : ''
if (!resolved || (resolved !== base && !resolved.startsWith(`${base}${path.sep}`))) process.exit(1)
process.stdout.write(resolved)
NODE
)" || {
    printf 'previous manifest has no safe artifact file: %s\n' "$PREVIOUS_MANIFEST_PATH" >&2
    exit 1
  }
  [[ -f "$PREVIOUS_ARCHIVE_PATH" && ! -L "$PREVIOUS_ARCHIVE_PATH" ]] || {
    printf 'previous manifest artifact does not exist beside the manifest: %s\n' "$PREVIOUS_ARCHIVE_PATH" >&2
    exit 1
  }
  [[ "$PREVIOUS_COMMIT" != "$SOURCE_COMMIT" ]] || {
    printf 'source commit is unchanged from the previous release: %s\n' "$SOURCE_COMMIT" >&2
    exit 1
  }
  git -C "$ROOT_DIR" merge-base --is-ancestor "$PREVIOUS_COMMIT" "$SOURCE_COMMIT" || {
    printf 'source commit %s is not a descendant of previous release %s\n' "$SOURCE_COMMIT" "$PREVIOUS_COMMIT" >&2
    exit 1
  }
fi

[[ -n "$TURNSTILE_SITE_KEY" || "$ALLOW_EMPTY_TURNSTILE_SITE_KEY" == true ]] || {
  printf 'VITE_TURNSTILE_SITE_KEY is required; pass --turnstile-site-key or set the environment variable\n' >&2
  printf 'Use --allow-empty-turnstile-site-key only when the active release is verified to use an empty key\n' >&2
  exit 2
}

if [[ -n "$(git -C "$ROOT_DIR" status --short)" ]]; then
  printf 'warning: working tree is dirty; only commit %s will be packaged\n' "$SOURCE_COMMIT"
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-web-release.XXXXXX")"
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

mkdir -p "$WORK_DIR/source" "$OUTPUT_DIR"
git -C "$ROOT_DIR" archive --format=tar "$SOURCE_COMMIT" | tar -xf - -C "$WORK_DIR/source"

(
  cd "$WORK_DIR/source"
  VITE_TURNSTILE_SITE_KEY="$TURNSTILE_SITE_KEY" \
  VITE_PACKAGE_COMMERCE_ENABLED="$PACKAGE_COMMERCE_ENABLED" \
    pnpm install --frozen-lockfile --filter @cdnca/web...
  VITE_TURNSTILE_SITE_KEY="$TURNSTILE_SITE_KEY" \
  VITE_PACKAGE_COMMERCE_ENABLED="$PACKAGE_COMMERCE_ENABLED" \
    pnpm --filter @cdnca/web build
)

DIST_DIR="$WORK_DIR/source/apps/web/dist"
[[ -f "$DIST_DIR/index.html" ]] || {
  printf 'Web build did not produce apps/web/dist/index.html\n' >&2
  exit 1
}

PRESERVED_ASSET_COUNT=0
if [[ -n "$PREVIOUS_ARCHIVE_PATH" ]]; then
  PREVIOUS_DIST_DIR="$WORK_DIR/previous-dist"
  mkdir "$PREVIOUS_DIST_DIR"
  tar -xzf "$PREVIOUS_ARCHIVE_PATH" -C "$PREVIOUS_DIST_DIR"
  [[ -d "$PREVIOUS_DIST_DIR/assets" ]] || {
    printf 'previous Web archive has no assets directory: %s\n' "$PREVIOUS_ARCHIVE_PATH" >&2
    exit 1
  }
  while IFS= read -r -d '' previous_asset; do
    relative_asset="${previous_asset#"$PREVIOUS_DIST_DIR/"}"
    current_asset="$DIST_DIR/$relative_asset"
    if [[ ! -e "$current_asset" ]]; then
      mkdir -p "$(dirname "$current_asset")"
      cp -p -- "$previous_asset" "$current_asset"
      chmod 0644 "$current_asset"
      PRESERVED_ASSET_COUNT=$((PRESERVED_ASSET_COUNT + 1))
    fi
  done < <(find "$PREVIOUS_DIST_DIR/assets" -type f -print0)
fi

RELEASE_ID="web-${SOURCE_COMMIT}"
ARCHIVE_PATH="$OUTPUT_DIR/${RELEASE_ID}.tar.gz"
MANIFEST_PATH="$OUTPUT_DIR/${RELEASE_ID}.manifest.json"
[[ ! -e "$ARCHIVE_PATH" && ! -e "$MANIFEST_PATH" ]] || {
  printf 'release already exists: %s\n' "$RELEASE_ID" >&2
  exit 1
}

FILE_LIST="$WORK_DIR/files.list"
find "$DIST_DIR" -type f -exec touch -t 200001010000 {} +
find "$DIST_DIR" -type f -exec chmod 0644 {} +
(
  cd "$DIST_DIR"
  LC_ALL=C find . -type f -print | LC_ALL=C sort
) >"$FILE_LIST"

TAR_PATH="$WORK_DIR/${RELEASE_ID}.tar"
tar --format=ustar --uid 0 --gid 0 --uname root --gname root --no-mac-metadata \
  -cf "$TAR_PATH" -C "$DIST_DIR" -T "$FILE_LIST"
gzip -n <"$TAR_PATH" >"$ARCHIVE_PATH"

MANIFEST_TMP="$WORK_DIR/${RELEASE_ID}.manifest.json"
node - "$DIST_DIR" "$MANIFEST_TMP" "$SOURCE_COMMIT" "$SOURCE_TREE" "$BUILT_AT" "$(basename "$ARCHIVE_PATH")" "$PACKAGE_COMMERCE_ENABLED" "$PRESERVED_ASSET_COUNT" <<'NODE'
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')

const dist = process.argv[2]
const output = process.argv[3]
const commit = process.argv[4]
const tree = process.argv[5]
const builtAt = process.argv[6]
const archive = process.argv[7]
const packageCommerceEnabled = process.argv[8] === 'true'
const preservedAssetCount = Number(process.argv[9] ?? 0)
if (!Number.isSafeInteger(preservedAssetCount) || preservedAssetCount < 0) throw new Error('invalid preserved asset count')

function digest(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')
}

function collect(directory, prefix = '') {
  const entries = fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))
  const files = []
  for (const entry of entries) {
    const relative = path.posix.join(prefix, entry.name)
    const full = path.join(directory, entry.name)
    if (entry.isSymbolicLink()) throw new Error(`symbolic link is not allowed: ${relative}`)
    if (entry.isDirectory()) files.push(...collect(full, relative))
    else if (entry.isFile()) files.push({ path: relative, bytes: fs.statSync(full).size, sha256: digest(full) })
    else throw new Error(`unsupported file type: ${relative}`)
  }
  return files
}

const manifest = {
  schema: 'cdnca.web.release/v1',
  source: { commit, tree },
  built_at: builtAt,
  build: {
    package_commerce_enabled: packageCommerceEnabled,
    preserved_previous_assets: preservedAssetCount,
  },
  artifact: { file: archive, sha256: null },
  files: collect(dist),
}
fs.writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`)
NODE

ARCHIVE_SHA256="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')"
node - "$MANIFEST_TMP" "$ARCHIVE_SHA256" <<'NODE'
const fs = require('node:fs')

const manifestPath = process.argv[2]
const archiveSha256 = process.argv[3]
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
manifest.artifact.sha256 = archiveSha256
fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)
NODE
mv "$MANIFEST_TMP" "$MANIFEST_PATH"

VERIFY_DIR="$WORK_DIR/verify"
mkdir "$VERIFY_DIR"
tar -xzf "$ARCHIVE_PATH" -C "$VERIFY_DIR"
node - "$VERIFY_DIR" "$MANIFEST_PATH" "$ARCHIVE_SHA256" <<'NODE'
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')

const root = process.argv[2]
const manifest = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'))
const archiveSha256 = process.argv[4]

if (manifest.artifact.sha256 !== archiveSha256) throw new Error('archive digest mismatch')
const expected = new Map(manifest.files.map((file) => [file.path, file]))
const actual = new Set()

function walk(directory, prefix = '') {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const relative = path.posix.join(prefix, entry.name)
    const full = path.join(directory, entry.name)
    if (entry.isDirectory()) walk(full, relative)
    else if (entry.isFile()) actual.add(relative)
    else throw new Error(`unsupported extracted file type: ${relative}`)
  }
}

walk(root)
if (actual.size !== expected.size || [...actual].some((file) => !expected.has(file))) throw new Error('archive file set differs from manifest')
for (const file of expected.values()) {
  const full = path.join(root, file.path)
  const bytes = fs.statSync(full).size
  const sha256 = crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex')
  if (bytes !== file.bytes || sha256 !== file.sha256) throw new Error(`file digest mismatch: ${file.path}`)
}
NODE

printf 'WEB_RELEASE_READY\n'
printf 'source_ref=%s\n' "$SOURCE_REF"
printf 'source_commit=%s\n' "$SOURCE_COMMIT"
printf 'source_tree=%s\n' "$SOURCE_TREE"
if [[ -n "$PREVIOUS_MANIFEST_PATH" ]]; then
  printf 'previous_source_commit=%s\n' "$PREVIOUS_COMMIT"
fi
printf 'built_at=%s\n' "$BUILT_AT"
printf 'archive=%s\n' "$ARCHIVE_PATH"
printf 'archive_sha256=%s\n' "$ARCHIVE_SHA256"
printf 'manifest=%s\n' "$MANIFEST_PATH"
printf 'preserved_previous_assets=%s\n' "$PRESERVED_ASSET_COUNT"
printf 'file_count=%s\n' "$(node -e 'const fs=require("fs"); console.log(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).files.length)' "$MANIFEST_PATH")"
