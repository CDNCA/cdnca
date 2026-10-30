#!/usr/bin/env node

import {
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync
} from "node:fs";
import {tmpdir} from "node:os";
import {
  dirname,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep
} from "node:path";
import {spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";

const REDOCLY_VERSION = "1.34.5";
const YAML_VERSION = "2.8.1";
const ROOT_CONTRACTS = ["control", "dns-acme", "license", "sites"];
const HTTP_METHODS = ["get", "post", "put", "patch", "delete", "head", "options", "trace"];
const README_SCOPES = {
  "control.yaml": "客户主控身份、账户、账务、套餐商业、节点、分析、任务、站点发布、缓存与安全",
  "dns-acme.yaml": "DNS provider、zone、record 和证书订单基础契约",
  "license.yaml": "Operator、许可证、发布、插件供应链、签名者撤销、平台策略和安装接口",
  "sites.yaml": "网站、源站、锁定和批量动作"
};

function inside(root, path) {
  return path === root || path.startsWith(root + sep);
}

function parseJSON(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`${path}: invalid JSON: ${error.message}`);
  }
}

function referencesInJSON(value, result = []) {
  if (Array.isArray(value)) {
    value.forEach((item) => referencesInJSON(item, result));
  } else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (key === "$ref" && typeof item === "string") result.push(item);
      else referencesInJSON(item, result);
    }
  }
  return result;
}

function parseYAML(path) {
  const result = spawnSync(
    "pnpm",
    [
      `--package=yaml@${YAML_VERSION}`,
      "dlx",
      "node",
      fileURLToPath(new URL("./parse-yaml.cjs", import.meta.url)),
      YAML_VERSION
    ],
    {
      encoding: "utf8",
      input: readFileSync(path, "utf8"),
      maxBuffer: 16 * 1024 * 1024
    }
  );
  if (result.status !== 0) {
    throw new Error(`${path}: invalid YAML: ${(result.stderr || result.stdout).trim()}`);
  }
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`${path}: YAML parser returned invalid JSON: ${error.message}`);
  }
}

function parseDocument(path) {
  return extname(path) === ".json" ? parseJSON(path) : parseYAML(path);
}

export function compareBytes(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function validatePointer(reference, source) {
  const hash = reference.indexOf("#");
  if (hash < 0 || hash === reference.length - 1) return;
  const pointer = reference.slice(hash + 1);
  if (!pointer.startsWith("/")) {
    throw new Error(`${source}: $ref fragment must be a JSON Pointer: ${reference}`);
  }
  for (const token of pointer.slice(1).split("/")) {
    if (/~(?:[^01]|$)/.test(token)) {
      throw new Error(`${source}: invalid JSON Pointer escape in $ref: ${reference}`);
    }
    token.replaceAll("~1", "/").replaceAll("~0", "~");
  }
}

function externalPath(reference, source, canonicalRoot) {
  validatePointer(reference, source);
  const filePart = reference.split("#", 1)[0];
  if (!filePart) return null;
  if (isAbsolute(filePart) || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(filePart) || filePart.startsWith("//")) {
    throw new Error(`${source}: external $ref escapes repository: ${reference}`);
  }
  let decoded;
  try {
    decoded = decodeURIComponent(filePart);
  } catch (error) {
    throw new Error(`${source}: invalid percent-encoding in $ref ${reference}: ${error.message}`);
  }
  const candidate = resolve(dirname(source), decoded);
  if (!inside(canonicalRoot, candidate)) {
    throw new Error(`${source}: external $ref escapes repository: ${reference}`);
  }
  if (!existsSync(candidate)) {
    throw new Error(`${source}: external $ref target does not exist: ${reference}`);
  }
  const canonical = realpathSync(candidate);
  if (!inside(canonicalRoot, canonical)) {
    throw new Error(`${source}: external $ref realpath escapes repository: ${reference}`);
  }
  return canonical;
}

export function collectReferenceClosure(repoRoot, sources) {
  const canonicalRoot = realpathSync(resolve(repoRoot));
  const queue = sources.map((source) => resolve(source));
  const seen = new Set();
  while (queue.length > 0) {
    const source = queue.shift();
    if (!existsSync(source)) throw new Error(`${source}: OpenAPI source does not exist`);
    const canonical = realpathSync(source);
    if (!inside(canonicalRoot, canonical)) throw new Error(`${source}: OpenAPI source escapes repository`);
    if (seen.has(canonical)) continue;
    seen.add(canonical);
    const references = referencesInJSON(parseDocument(canonical));
    for (const reference of references) {
      const target = externalPath(reference, canonical, canonicalRoot);
      if (target && !seen.has(target)) queue.push(target);
    }
  }
  return [...seen].sort();
}

function rootSources(repoRoot) {
  const directory = join(repoRoot, "api", "openapi", "v1");
  return ROOT_CONTRACTS.map((name) => {
    const matches = [".yaml", ".yml", ".json"]
      .map((extension) => join(directory, name + extension))
      .filter(existsSync);
    if (matches.length !== 1) {
      throw new Error(`${directory}: expected exactly one ${name}.{yaml,yml,json}, found ${matches.length}`);
    }
    return {name, source: matches[0]};
  });
}

function bundleDocument(repoRoot, source, output) {
  const result = spawnSync(
    "pnpm",
    [
      `--package=@redocly/cli@${REDOCLY_VERSION}`,
      "dlx",
      "redocly",
      "bundle",
      source,
      "--output",
      output
    ],
    {
      cwd: repoRoot,
      encoding: "utf8",
      env: {...process.env, REDOCLY_TELEMETRY: "off", REDOCLY_SUPPRESS_UPDATE_NOTICE: "true"}
    }
  );
  if (result.status !== 0) {
    throw new Error(`${source}: Redocly bundle failed: ${(result.stderr || result.stdout).trim()}`);
  }
  return parseJSON(output);
}

export async function loadOpenAPIDocuments(repoRoot) {
  repoRoot = resolve(repoRoot);
  const roots = rootSources(repoRoot);
  collectReferenceClosure(repoRoot, roots.map(({source}) => source));
  const temporary = mkdtempSync(join(tmpdir(), "cdnca-openapi-index-"));
  try {
    return roots.map(({name, source}, index) => {
      const document = bundleDocument(repoRoot, source, join(temporary, `${index}-${name}.json`));
      const version = document?.info?.version;
      if (typeof version !== "string" || version.length === 0) {
        throw new Error(`${source}: info.version is required`);
      }
      return {contract: `${name}.yaml`, source, version, document};
    });
  } finally {
    rmSync(temporary, {recursive: true, force: true});
  }
}

export function collectOpenAPIOperations(documents) {
  const operations = [];
  const globalOperationIDs = new Map();
  const globalWireOperations = new Map();
  const summaries = [];
  for (const entry of documents) {
    const contract = entry.contract;
    const paths = entry.document?.paths;
    if (!paths || typeof paths !== "object" || Array.isArray(paths)) {
      throw new Error(`${contract}: paths object is required`);
    }
    const localOperationIDs = new Set();
    const start = operations.length;
    for (const [route, pathItem] of Object.entries(paths).sort(([left], [right]) => compareBytes(left, right))) {
      if (!pathItem || typeof pathItem !== "object" || Array.isArray(pathItem)) {
        throw new Error(`${contract} ${route}: path item must be an object`);
      }
      for (const method of HTTP_METHODS) {
        if (!Object.hasOwn(pathItem, method)) continue;
        const operation = pathItem[method];
        const operationId = operation?.operationId;
        if (typeof operationId !== "string" || operationId.length === 0 || operationId !== operationId.trim()) {
          throw new Error(`${contract} ${method.toUpperCase()} ${route}: missing operationId`);
        }
        if (localOperationIDs.has(operationId)) {
          throw new Error(`${contract}: duplicate operationId ${operationId}`);
        }
        localOperationIDs.add(operationId);
        const methodName = method.toUpperCase();
        const wire = `${methodName}\0${route}`;
        const existingWire = globalOperationIDs.get(operationId);
        if (existingWire && existingWire !== wire) {
          throw new Error(
            `conflicting operationId ${operationId}: ${existingWire.replace("\0", " ")} != ${methodName} ${route}`
          );
        }
        const existingOperationID = globalWireOperations.get(wire);
        if (existingOperationID && existingOperationID !== operationId) {
          throw new Error(
            `conflicting wire operation ${methodName} ${route}: ${existingOperationID} != ${operationId}`
          );
        }
        globalOperationIDs.set(operationId, wire);
        globalWireOperations.set(wire, operationId);
        operations.push({contract, method: methodName, route, operationId});
      }
    }
    summaries.push({
      contract,
      version: entry.version ?? entry.document?.info?.version,
      operationCount: operations.length - start
    });
  }
  const tupleGroups = new Map();
  for (const operation of operations) {
    const tuple = `${operation.method}\0${operation.route}\0${operation.operationId}`;
    const group = tupleGroups.get(tuple) ?? [];
    group.push(operation.contract);
    tupleGroups.set(tuple, group);
  }
  const overlaps = [];
  for (const [tuple, contracts] of tupleGroups) {
    if (contracts.length < 2) continue;
    const [method, route, operationId] = tuple.split("\0");
    overlaps.push({method, route, operationId, contracts});
  }
  overlaps.sort((left, right) =>
    compareBytes(left.route, right.route) ||
    HTTP_METHODS.indexOf(left.method.toLowerCase()) - HTTP_METHODS.indexOf(right.method.toLowerCase()) ||
    compareBytes(left.operationId, right.operationId)
  );
  return {documents: summaries, operations, distinctTupleCount: tupleGroups.size, overlaps};
}

export function renderOpenAPIIndex(result) {
  const lines = [
    `本索引按契约完整列出当前四份 OpenAPI 的 ${result.operations.length} 个 operation，并包含`,
    `${result.distinctTupleCount} 个 distinct wire tuple。字段、参数、权限、错误和示例仍以源文件为准。`,
    "跨契约重复只允许 method/path/operationId 完全一致。",
    "",
    "按契约跳转：[control.yaml](#controlyaml)、[dns-acme.yaml](#dns-acmeyaml)、",
    "[license.yaml](#licenseyaml)、[sites.yaml](#sitesyaml)。"
  ];
  if (result.overlaps.length > 0) {
    lines.push(
      "",
      "## 跨契约兼容重叠",
      "",
      `以下 ${result.overlaps.length} 个 wire tuple 在多个契约中完全一致：`,
      "",
      "| 方法 | 路径 | operationId | 契约 |",
      "| --- | --- | --- | --- |"
    );
    for (const overlap of result.overlaps) {
      lines.push(
        `| \`${overlap.method}\` | \`${overlap.route}\` | \`${overlap.operationId}\` | ${overlap.contracts.map((contract) => `\`${contract}\``).join("、")} |`
      );
    }
  }
  for (const document of result.documents) {
    lines.push(
      "",
      `## ${document.contract}`,
      "",
      `源文件：[\`${document.contract}\`](../../api/openapi/v1/${document.contract})，${document.operationCount} 个 operation。`,
      "",
      "| 契约 | 方法 | 路径 | operationId |",
      "| --- | --- | --- | --- |"
    );
    for (const operation of result.operations.filter(({contract}) => contract === document.contract)) {
      lines.push(
        `| \`${operation.contract}\` | \`${operation.method}\` | \`${operation.route}\` | \`${operation.operationId}\` |`
      );
    }
  }
  return lines.join("\n");
}

export function renderReadmeCounts(result) {
  const lines = [
    "| 文件 | 版本 | operation 数 | 范围 |",
    "| --- | --- | ---: | --- |"
  ];
  for (const document of result.documents) {
    const scope = README_SCOPES[document.contract];
    if (!scope) throw new Error(`README scope is missing for ${document.contract}`);
    lines.push(
      `| [\`${document.contract}\`](../../api/openapi/v1/${document.contract}) | ${document.version} | ${document.operationCount} | ${scope} |`
    );
  }
  return lines.join("\n");
}

export function replaceGeneratedRegion(source, name, body) {
  const begin = `<!-- generated:${name}:begin -->`;
  const end = `<!-- generated:${name}:end -->`;
  const beginAt = source.indexOf(begin);
  const endAt = source.indexOf(end);
  if (beginAt < 0 || endAt < 0) throw new Error(`missing generated marker for ${name}`);
  if (source.indexOf(begin, beginAt + begin.length) >= 0 || source.indexOf(end, endAt + end.length) >= 0) {
    throw new Error(`duplicate generated marker for ${name}`);
  }
  if (endAt < beginAt) throw new Error(`generated markers are out of order for ${name}`);
  const before = source.slice(0, beginAt + begin.length);
  const after = source.slice(endAt);
  return `${before}\n${body.replace(/^\n+|\n+$/g, "")}\n${after}`;
}

export async function updateDocumentation(repoRoot, {write = false} = {}) {
  repoRoot = resolve(repoRoot);
  const result = collectOpenAPIOperations(await loadOpenAPIDocuments(repoRoot));
  const targets = [
    {
      path: join(repoRoot, "docs", "api", "openapi-index.md"),
      name: "openapi-index",
      body: renderOpenAPIIndex(result)
    },
    {
      path: join(repoRoot, "docs", "api", "README.md"),
      name: "openapi-counts",
      body: renderReadmeCounts(result)
    }
  ];
  const updates = targets.map((target) => {
    const current = readFileSync(target.path, "utf8");
    return {...target, current, next: replaceGeneratedRegion(current, target.name, target.body)};
  });
  const drift = updates.filter(({current, next}) => current !== next);
  if (write) {
    for (const update of drift) writeFileSync(update.path, update.next);
  } else if (drift.length > 0) {
    throw new Error(`generated OpenAPI documentation drift: ${drift.map(({path}) => relative(repoRoot, path)).join(", ")}`);
  }
  return {
    documentCount: result.documents.length,
    operationCount: result.operations.length,
    distinctTupleCount: result.distinctTupleCount,
    overlapCount: result.overlaps.length,
    driftCount: write ? 0 : drift.length
  };
}

async function main() {
  const args = process.argv.slice(2);
  let repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  let mode = null;
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--repo-root") {
      if (!args[index + 1]) throw new Error("--repo-root requires a path");
      repoRoot = resolve(args[++index]);
    } else if (args[index] === "--check" || args[index] === "--write") {
      if (mode) throw new Error("choose exactly one of --check or --write");
      mode = args[index];
    } else {
      throw new Error(`unknown argument: ${args[index]}`);
    }
  }
  if (!mode) throw new Error("choose exactly one of --check or --write");
  const result = await updateDocumentation(repoRoot, {write: mode === "--write"});
  process.stdout.write(
    `${result.documentCount} documents, ${result.operationCount} contract operations, ` +
    `${result.distinctTupleCount} distinct wire tuples, ${result.overlapCount} compatible overlaps, ` +
    `${result.driftCount} drift\n`
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`openapi-index: ${error.message}\n`);
    process.exitCode = 1;
  });
}
