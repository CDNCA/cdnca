#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
readonly repo_root
readonly redocly_version="1.34.5"
readonly markdownlint_version="0.18.1"
readonly buf_version="1.47.2"

temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-docs.XXXXXX")"
cleanup() {
  rm -rf "$temporary_dir"
}
trap cleanup EXIT

step() {
  printf '\n==> %s\n' "$1"
}

die() {
  printf 'verify-developer-docs: %s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_command node
require_command pnpm
require_command buf

actual_buf_version="$(buf --version)"
[[ "$actual_buf_version" == "$buf_version" ]] ||
  die "buf $buf_version is required, found $actual_buf_version"

step "contract and developer documentation checks"
"$repo_root/scripts/check-contract-docs.sh"

step "Markdown structure"
(
  cd "$repo_root"
  pnpm --package="markdownlint-cli2@$markdownlint_version" dlx markdownlint-cli2 \
    --config docs/developer/.markdownlint-cli2.jsonc \
    "docs/system/**/*.md" \
    "docs/api/**/*.md" \
    "docs/developer/**/*.md"
)

step "OpenAPI lint and normalized bundles"
mkdir -p "$temporary_dir/openapi"
while IFS= read -r source; do
  name="$(basename "$source")"
  REDOCLY_TELEMETRY=off REDOCLY_SUPPRESS_UPDATE_NOTICE=true \
    pnpm --package="@redocly/cli@$redocly_version" dlx redocly lint \
      --extends=minimal "$source"
  REDOCLY_TELEMETRY=off REDOCLY_SUPPRESS_UPDATE_NOTICE=true \
    pnpm --package="@redocly/cli@$redocly_version" dlx redocly bundle \
      "$source" --output "$temporary_dir/openapi/$name.json"
done < <(
  find "$repo_root/api/openapi" -type f \
    \( -name '*.yaml' -o -name '*.yml' -o -name '*.json' \) |
    LC_ALL=C sort
)

step "links, code references, API/RPC indexes, and example hygiene"
node - "$repo_root" "$temporary_dir/openapi" <<'NODE'
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(process.argv[2]);
const bundleRoot = path.resolve(process.argv[3]);
const failures = [];
const methods = new Set([
  "delete", "get", "head", "options", "patch", "post", "put", "trace"
]);

function walk(directory, predicate = () => true) {
  if (!fs.existsSync(directory)) return [];
  const result = [];
  for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
    const current = path.join(directory, entry.name);
    if (entry.isDirectory()) result.push(...walk(current, predicate));
    else if (entry.isFile() && predicate(current)) result.push(current);
  }
  return result.sort();
}

function relative(file) {
  return path.relative(root, file).split(path.sep).join("/");
}

function lineAt(text, offset) {
  return text.slice(0, offset).split("\n").length;
}

function insideRoot(target) {
  return target === root || target.startsWith(root + path.sep);
}

const docRoots = ["system", "api", "developer"].map((name) =>
  path.join(root, "docs", name)
);
const markdownFiles = docRoots.flatMap((directory) =>
  walk(directory, (file) => file.endsWith(".md"))
);

for (const file of markdownFiles) {
  const text = fs.readFileSync(file, "utf8");
  const linkPattern = /!?\[[^\]]*\]\(([^)]+)\)/g;
  for (const match of text.matchAll(linkPattern)) {
    let target = match[1].trim();
    if (target.startsWith("<") && target.includes(">")) {
      target = target.slice(1, target.indexOf(">"));
    } else {
      target = target.split(/\s+["']/)[0];
    }
    if (!target || /^(?:[a-z]+:|#)/i.test(target)) continue;
    try {
      target = decodeURIComponent(target.split("#", 1)[0]);
    } catch {
      failures.push(
        relative(file) + ":" + lineAt(text, match.index) +
        ": invalid percent-encoded link " + target
      );
      continue;
    }
    const resolved = path.resolve(path.dirname(file), target);
    if (!insideRoot(resolved)) {
      failures.push(
        relative(file) + ":" + lineAt(text, match.index) +
        ": link escapes repository " + target
      );
    } else if (!fs.existsSync(resolved)) {
      failures.push(
        relative(file) + ":" + lineAt(text, match.index) +
        ": linked path does not exist " + target
      );
    }
  }

  const codeReferencePattern =
    /\x60((?:apps|services|agents|edge|infra|api|proto|scripts|tests|tools|docs)\/[^\x60\s]+)\x60/g;
  for (const match of text.matchAll(codeReferencePattern)) {
    let target = match[1].replace(/[),.;:]+$/, "");
    if (target.includes("*") || target.includes("<") || target.includes(">")) {
      failures.push(
        relative(file) + ":" + lineAt(text, match.index) +
        ": code path must be concrete " + target
      );
      continue;
    }
    target = target.replace(/#L[0-9]+$/, "");
    const resolved = path.resolve(root, target);
    if (!insideRoot(resolved) || !fs.existsSync(resolved)) {
      failures.push(
        relative(file) + ":" + lineAt(text, match.index) +
        ": inline code path does not exist " + target
      );
    }
  }
}

const actualOperations = new Set();
for (const bundleFile of walk(bundleRoot, (file) => file.endsWith(".json"))) {
  const document = JSON.parse(fs.readFileSync(bundleFile, "utf8"));
  const contract = path.basename(bundleFile, ".json");
  for (const [route, item] of Object.entries(document.paths || {})) {
    for (const [method, operation] of Object.entries(item || {})) {
      if (!methods.has(method)) continue;
      actualOperations.add(
        [contract, method.toUpperCase(), route, operation.operationId].join("\0")
      );
    }
  }
}

const indexPath = path.join(root, "docs", "api", "openapi-index.md");
const indexText = fs.readFileSync(indexPath, "utf8");
const indexedOperations = new Set();
const operationRow =
  /^\| \x60([^\x60]+\.yaml)\x60 \| \x60([A-Z]+)\x60 \| \x60([^\x60]+)\x60 \| \x60([^\x60]+)\x60 \|$/gm;
for (const match of indexText.matchAll(operationRow)) {
  const key = [match[1], match[2], match[3], match[4]].join("\0");
  if (indexedOperations.has(key)) {
    failures.push("docs/api/openapi-index.md: duplicate operation row " +
      [match[1], match[2], match[3], match[4]].join(" "));
  }
  indexedOperations.add(key);
}
for (const key of actualOperations) {
  if (!indexedOperations.has(key)) {
    failures.push("docs/api/openapi-index.md: missing operation " +
      key.split("\0").join(" "));
  }
}
for (const key of indexedOperations) {
  if (!actualOperations.has(key)) {
    failures.push("docs/api/openapi-index.md: unknown operation " +
      key.split("\0").join(" "));
  }
}

const protoFiles = walk(path.join(root, "proto"), (file) =>
  file.endsWith(".proto")
);
const actualServices = new Map();
for (const file of protoFiles) {
  const source = fs.readFileSync(file, "utf8").replace(/\/\/.*$/gm, "");
  const servicePattern = /\bservice\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([^}]*)\}/g;
  for (const serviceMatch of source.matchAll(servicePattern)) {
    const rpcNames = [...serviceMatch[2].matchAll(/\brpc\s+([A-Za-z_][A-Za-z0-9_]*)/g)]
      .map((match) => match[1]);
    actualServices.set(relative(file) + "#" + serviceMatch[1], rpcNames);
  }
}

const grpcIndex = path.join(root, "docs", "api", "grpc-index.md");
const grpcText = fs.readFileSync(grpcIndex, "utf8");
const markedServices = new Set();
const markerPattern =
  /<!--\s*verify-proto\s+file="([^"]+)"\s+service="([^"]+)"\s+methods="([^"]+)"\s*-->/g;
for (const match of grpcText.matchAll(markerPattern)) {
  const source = path.resolve(path.dirname(grpcIndex), match[1]);
  const key = relative(source) + "#" + match[2];
  const expectedMethods = actualServices.get(key);
  const documentedMethods = match[3].split(",").filter(Boolean);
  if (!insideRoot(source) || !fs.existsSync(source)) {
    failures.push("docs/api/grpc-index.md: missing proto file " + match[1]);
  } else if (!expectedMethods) {
    failures.push("docs/api/grpc-index.md: unknown service " + key);
  } else if (
    expectedMethods.join(",") !== documentedMethods.join(",")
  ) {
    failures.push(
      "docs/api/grpc-index.md: RPC drift for " + key +
      " expected=" + expectedMethods.join(",") +
      " documented=" + documentedMethods.join(",")
    );
  }
  if (markedServices.has(key)) {
    failures.push("docs/api/grpc-index.md: duplicate service marker " + key);
  }
  markedServices.add(key);
}
for (const key of actualServices.keys()) {
  if (!markedServices.has(key)) {
    failures.push("docs/api/grpc-index.md: missing service marker " + key);
  }
}

const hygieneFiles = docRoots.flatMap((directory) => walk(directory));
const placeholder =
  /(?:example|placeholder|replace|redacted|test-only|do-not-log|local-only|\$\{|<[^>]+>)/i;
for (const file of hygieneFiles) {
  const text = fs.readFileSync(file, "utf8");
  if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(text)) {
    failures.push(relative(file) + ": contains private-key material");
  }
  if (/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/.test(text) ||
      /\bgh[pousr]_[A-Za-z0-9]{30,}\b/.test(text) ||
      /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/.test(text)) {
    failures.push(relative(file) + ": contains a credential-shaped value");
  }
  if (/\b(?:10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|192\.168\.(?:[0-9]{1,3}\.)[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.(?:[0-9]{1,3}\.)[0-9]{1,3})\b/.test(text)) {
    failures.push(relative(file) + ": contains a private IPv4 address");
  }
  for (const email of text.matchAll(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/gi)) {
    if (!/(?:^|\.)example(?:\.com|\.test|\.invalid)?$/i.test(email[1])) {
      failures.push(relative(file) + ": contains a non-example email address");
    }
  }
  for (const dsn of text.matchAll(/\b(?:postgres(?:ql)?|redis|nats|https?):\/\/([^/\s:@]+):([^@\s/]+)@/gi)) {
    if (!placeholder.test(dsn[1]) || !placeholder.test(dsn[2])) {
      failures.push(relative(file) + ": contains a credential-bearing URL");
    }
  }
  if (file.endsWith(".json")) {
    let value;
    try {
      value = JSON.parse(text);
    } catch (error) {
      failures.push(relative(file) + ": invalid JSON: " + error.message);
      continue;
    }
    const testOnly = value && value.test_only === true;
    const inspect = (node, pointer = "") => {
      if (Array.isArray(node)) {
        node.forEach((item, index) => inspect(item, pointer + "/" + index));
        return;
      }
      if (!node || typeof node !== "object") return;
      for (const [key, item] of Object.entries(node)) {
        const next = pointer + "/" + key;
        if (
          typeof item === "string" &&
          /(?:password|secret|token|private[_-]?key|api[_-]?key)/i.test(key) &&
          item.length > 0 &&
          !placeholder.test(item) &&
          !testOnly
        ) {
          failures.push(relative(file) + "#" + next +
            ": secret-shaped example value is not an explicit placeholder");
        }
        inspect(item, next);
      }
    };
    inspect(value);
  }
}

if (actualOperations.size === 0) {
  failures.push("no OpenAPI operations found");
}
if (actualServices.size === 0) {
  failures.push("no protobuf services found");
}
if (failures.length > 0) {
  failures.forEach((failure) => console.error(failure));
  console.error("developer-doc validation failed with " +
    failures.length + " error(s)");
  process.exit(1);
}
console.log(
  "developer-doc references: passed (" +
  markdownFiles.length + " Markdown files, " +
  actualOperations.size + " OpenAPI operations, " +
  actualServices.size + " protobuf services)"
);
NODE

step "protobuf format, lint, compatibility, and generated drift"
(
  cd "$repo_root/proto"
  buf format --diff --exit-code
  buf lint
  buf build >/dev/null
  buf breaking --against baseline/cdnca.bin
  shasum -a 256 -c baseline/cdnca.bin.sha256
)

temporary_proto="$temporary_dir/proto"
mkdir -p "$temporary_proto"
cp "$repo_root/proto/buf.yaml" "$temporary_proto/buf.yaml"
cp "$repo_root/proto/buf.gen.yaml" "$temporary_proto/buf.gen.yaml"
cp -R "$repo_root/proto/agent" "$temporary_proto/agent"
cp -R "$repo_root/proto/common" "$temporary_proto/common"
cp -R "$repo_root/proto/controlinternal" "$temporary_proto/controlinternal"
(cd "$temporary_proto" && buf generate)

drift=0
while IFS= read -r generated; do
  generated_relative="${generated#"$temporary_proto/"}"
  checked_in="$repo_root/proto/$generated_relative"
  if [[ ! -f "$checked_in" ]]; then
    printf 'missing generated file: proto/%s\n' "$generated_relative" >&2
    drift=1
  elif ! cmp -s "$generated" "$checked_in"; then
    printf 'stale generated file: proto/%s\n' "$generated_relative" >&2
    drift=1
  fi
done < <(find "$temporary_proto/gen/go" -type f -name '*.pb.go' | LC_ALL=C sort)

while IFS= read -r checked_in; do
  checked_in_relative="${checked_in#"$repo_root/proto/"}"
  if [[ ! -f "$temporary_proto/$checked_in_relative" ]]; then
    printf 'orphan generated file: proto/%s\n' "$checked_in_relative" >&2
    drift=1
  fi
done < <(find "$repo_root/proto/gen/go" -type f -name '*.pb.go' | LC_ALL=C sort)

[[ "$drift" -eq 0 ]] || die "protobuf generated files drifted; run the pinned buf generate workflow"

printf '\nverify-developer-docs: passed\n'
