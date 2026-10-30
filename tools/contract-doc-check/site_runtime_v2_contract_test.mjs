import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {isIP} from "node:net";
import test from "node:test";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {TextDecoder} from "node:util";
import {fileURLToPath} from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const schemaPath = resolve(root, "api/schemas/edge/v2/site-runtime.schema.json");
const protoPath = resolve(root, "proto/agent/v1/types.proto");

function readSchema() {
  return JSON.parse(readFileSync(schemaPath, "utf8"));
}

function uniqueBy(field, data) {
  uniqueBy.errors = null;
  if (!Array.isArray(data)) return true;
  const firstIndexes = new Map();
  for (const [index, item] of data.entries()) {
    const value = item?.[field];
    if (firstIndexes.has(value)) {
      uniqueBy.errors = [{
        keyword: "x-cdnca-unique-by",
        message: `must have unique ${field}`,
        params: {field, duplicate: value, firstIndex: firstIndexes.get(value), duplicateIndex: index}
      }];
      return false;
    }
    firstIndexes.set(value, index);
  }
  return true;
}

function orderedBy(field, data) {
  if (!Array.isArray(data)) return true;
  return data.every((item, index) => index === 0 || data[index - 1]?.[field] < item?.[field]);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasSemanticShape(document) {
  return isRecord(document) &&
    Array.isArray(document.required_capabilities) &&
    document.required_capabilities.every((capability) =>
      isRecord(capability) && typeof capability.name === "string") &&
    Array.isArray(document.sites) &&
    document.sites.every((site) =>
      isRecord(site) &&
      Array.isArray(site.listeners) &&
      site.listeners.every((listener) =>
        isRecord(listener) && Array.isArray(listener.protocols) &&
        typeof listener.address_family === "string") &&
      Array.isArray(site.origin_pools) &&
      site.origin_pools.every((pool) =>
        isRecord(pool) && Array.isArray(pool.origins) &&
        pool.origins.every((origin) => isRecord(origin) && typeof origin.host === "string")));
}

function siteRuntimeSemantics(contract, document) {
  if (!contract || !hasSemanticShape(document)) return true;
  const capabilities = new Set(document.required_capabilities?.map(({name}) => name));
  const versions = new Map(document.required_capabilities.map(({name, api_version}) => [name, api_version]));
  for (const site of document.sites) {
    if (isRecord(site.firewall_action) && site.firewall_action.artifact_path !== `firewall-action/${site.id}.json`) return false;
    for (const listener of site.listeners) {
      const security = listener.security;
      if (!isRecord(security)) continue;
      if (Array.isArray(security.policies)) {
        if (security.policies.length > 0 && (versions.get("waf") ?? 0) < 1) return false;
        if (security.policies.reduce((total, policy) => total + (Array.isArray(policy?.rules) ? policy.rules.length : 0), 0) > 128) return false;
      }
      if (isRecord(security.cc)) {
        if ((versions.get("cc") ?? 0) < 2) return false;
        if (isRecord(security.cc.Policy) && (security.cc.Policy.tenant_scope_id !== document.configuration_scope_id || security.cc.Policy.site_id !== site.id)) return false;
      }
    }
    const pools = new Map(site.origin_pools.map((pool) => [pool.id, pool]));
    const defaultPool = pools.get(site.default_pool_id);
    if (!defaultPool) return false;

    const fallbackID = site.l2?.direct_fallback_pool_id;
    const fallback = fallbackID === undefined ? undefined : pools.get(fallbackID);
    if (fallbackID !== undefined && !fallback) return false;
    if (site.l2?.enabled) {
      if (![...pools.values()].some(({kind}) => kind === "l2")) return false;
      if (defaultPool.kind !== contract.l2_enabled_default_pool_kind) return false;
      if (!fallback || fallback.kind !== contract.l2_direct_fallback_pool_kind) return false;
      if (contract.l2_direct_fallback_must_differ_from_default && fallback.id === defaultPool.id) return false;
      if (!fallback.origins?.some(({tier}) => tier === "origin") || site.l2.max_hops !== 1) return false;
    }

    if (contract.infer_origin_address_capabilities) {
      for (const pool of site.origin_pools) {
        for (const origin of pool.origins) {
          const family = isIP(origin.host);
          if (family === 4 && !capabilities.has("ipv4")) return false;
          if (family === 6 && !capabilities.has("ipv6")) return false;
        }
      }
    }
  }
  return true;
}

function validator(schema) {
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    strictRequired: false,
    strictTypes: false
  });
  addFormats(ajv);
  for (const keyword of [
    "x-cdnca-wire-contract",
    "x-cdnca-revision-contract",
    "x-cdnca-activation-contract"
  ]) {
    ajv.addKeyword({keyword, schemaType: ["string", "object"]});
  }
  ajv.addKeyword({
    keyword: "x-cdnca-ordered-by",
    schemaType: "string",
    type: "array",
    validate: orderedBy
  });
  ajv.addKeyword({
    keyword: "x-cdnca-unique-by",
    schemaType: "string",
    type: "array",
    validate: uniqueBy
  });
  ajv.addKeyword({
    keyword: "x-cdnca-site-runtime-semantics",
    schemaType: "object",
    type: "object",
    metaSchema: {
      type: "object",
      additionalProperties: false,
      required: [
        "l2_enabled_default_pool_kind",
        "l2_direct_fallback_pool_kind",
        "l2_direct_fallback_must_differ_from_default",
        "infer_origin_address_capabilities"
      ],
      properties: {
        l2_enabled_default_pool_kind: {const: "l2"},
        l2_direct_fallback_pool_kind: {const: "origin"},
        l2_direct_fallback_must_differ_from_default: {const: true},
        infer_origin_address_capabilities: {const: true}
      }
    },
    validate: siteRuntimeSemantics
  });
  return ajv.compile(schema);
}

function rejectDuplicateObjectKeys(text) {
  let offset = 0;
  const whitespace = () => {
    while (/\s/u.test(text[offset] ?? "")) offset += 1;
  };
  const readString = () => {
    const start = offset++;
    while (offset < text.length) {
      if (text[offset] === "\\") {
        offset += 2;
      } else if (text[offset++] === "\"") {
        return JSON.parse(text.slice(start, offset));
      }
    }
    throw new SyntaxError("unterminated JSON string");
  };
  const visit = () => {
    whitespace();
    if (text[offset] === "{") {
      offset += 1;
      whitespace();
      const keys = new Set();
      while (text[offset] !== "}") {
        const key = readString();
        if (keys.has(key)) throw new SyntaxError(`duplicate JSON key: ${key}`);
        keys.add(key);
        whitespace();
        offset += 1;
        visit();
        whitespace();
        if (text[offset] !== ",") break;
        offset += 1;
        whitespace();
      }
      offset += 1;
      return;
    }
    if (text[offset] === "[") {
      offset += 1;
      whitespace();
      while (text[offset] !== "]") {
        visit();
        whitespace();
        if (text[offset] !== ",") break;
        offset += 1;
      }
      offset += 1;
      return;
    }
    if (text[offset] === "\"") {
      readString();
      return;
    }
    while (offset < text.length && !/[\s,\]}]/u.test(text[offset])) offset += 1;
  };
  visit();
  whitespace();
  if (offset !== text.length) throw new SyntaxError("trailing JSON token");
}

function parseStrictJSON(raw) {
  const text = new TextDecoder("utf-8", {fatal: true}).decode(raw);
  const value = JSON.parse(text);
  rejectDuplicateObjectKeys(text);
  return value;
}

function assertUnicodeScalars(value) {
  for (let index = 0; index < value.length; index += 1) {
    const current = value.charCodeAt(index);
    if (current >= 0xd800 && current <= 0xdbff) {
      const next = value.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError("unpaired high surrogate");
    } else if (current >= 0xdc00 && current <= 0xdfff) {
      throw new TypeError("unpaired low surrogate");
    }
  }
}

function canonicalJSON(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string") {
    assertUnicodeScalars(value);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
  const keys = Object.keys(value).sort();
  keys.forEach(assertUnicodeScalars);
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(",")}}`;
}

function canonicalDigest(value) {
  return createHash("sha256").update(canonicalJSON(value), "utf8").digest("hex");
}

function inferredCapabilities(document) {
  const required = new Set(["site_runtime"]);
  for (const site of document?.sites ?? []) {
    if (site.websocket) required.add("websocket");
    for (const listener of site.listeners ?? []) {
      for (const protocol of listener.protocols ?? []) required.add(protocol);
      if (["ipv4", "dual_stack"].includes(listener.address_family)) required.add("ipv4");
      if (["ipv6", "dual_stack"].includes(listener.address_family)) required.add("ipv6");
    }
    for (const pool of site.origin_pools ?? []) {
      for (const origin of pool.origins ?? []) {
        const family = isIP(origin.host);
        if (family === 4) required.add("ipv4");
        if (family === 6) required.add("ipv6");
      }
    }
  }
  return required;
}

function activate(raw, current) {
  let document;
  try {
    document = parseStrictJSON(raw);
  } catch {
    return {result: "invalid_document", preserve_current: true, current};
  }
  const supportedSchema = "cdnca.edge.site-runtime/v2";
  if (!isRecord(document) || typeof document.schema !== "string" ||
      !/^cdnca\.edge\.site-runtime\/v[1-9][0-9]*$/u.test(document.schema)) {
    return {result: "invalid_document", preserve_current: true, current};
  }
  const validationDocument = document.schema === supportedSchema
    ? document
    : {...document, schema: supportedSchema};
  const validate = validator(readSchema());
  if (!validate(validationDocument)) {
    if (document.schema === supportedSchema && hasSemanticShape(document)) {
      const available = new Set(document.required_capabilities.map(({name}) => name));
      if ([...inferredCapabilities(document)].some((name) => !available.has(name))) {
        return {result: "missing_capability", preserve_current: true, current};
      }
    }
    return {result: "invalid_document", preserve_current: true, current};
  }
  if (document.schema !== supportedSchema) {
    return {result: "unsupported_schema", preserve_current: true, current};
  }

  const digest = canonicalDigest(document);
  if (document.source_revision < current.source_revision) {
    return {result: "stale", preserve_current: true, current};
  }
  if (document.source_revision === current.source_revision) {
    const result = digest === current.canonical_sha256 ? "idempotent" : "conflict";
    return {result, preserve_current: true, current};
  }
  return {
    result: "applied",
    preserve_current: false,
    current: {source_revision: document.source_revision, canonical_sha256: digest, document}
  };
}

function protoTokens(source) {
  const tokens = [];
  for (let offset = 0; offset < source.length;) {
    if (/\s/u.test(source[offset])) {
      offset += 1;
    } else if (source.startsWith("//", offset)) {
      offset = source.indexOf("\n", offset + 2);
      if (offset < 0) break;
    } else if (source.startsWith("/*", offset)) {
      offset = source.indexOf("*/", offset + 2);
      if (offset < 0) throw new SyntaxError("unterminated proto comment");
      offset += 2;
    } else if (source[offset] === '"') {
      const end = source.indexOf('"', offset + 1);
      if (end < 0) throw new SyntaxError("unterminated proto string");
      tokens.push(source.slice(offset, end + 1));
      offset = end + 1;
    } else if (/[A-Za-z_]/u.test(source[offset])) {
      const match = /^[A-Za-z_][A-Za-z0-9_]*/u.exec(source.slice(offset))[0];
      tokens.push(match);
      offset += match.length;
    } else if (/[0-9-]/u.test(source[offset])) {
      const match = /^-?[0-9]+/u.exec(source.slice(offset))?.[0];
      if (!match) throw new SyntaxError("invalid proto number");
      tokens.push(match);
      offset += match.length;
    } else {
      tokens.push(source[offset++]);
    }
  }
  return tokens;
}

function parseProtoEnum(source, enumName) {
  const tokens = protoTokens(source);
  let offset = tokens.findIndex((token, index) => token === "enum" && tokens[index + 1] === enumName);
  if (offset < 0 || tokens[offset + 2] !== "{") throw new SyntaxError(`enum ${enumName} not found`);
  offset += 3;
  const values = [];
  while (tokens[offset] !== "}") {
    // `reserved 30;` / `reserved "NAME";` (ADR 0007) declare no value; the
    // generated descriptor's values omit them too.
    if (tokens[offset] === "reserved") {
      while (offset < tokens.length && tokens[offset] !== ";") offset += 1;
      if (tokens[offset++] !== ";") throw new SyntaxError(`invalid ${enumName} reserved statement`);
      continue;
    }
    const name = tokens[offset++];
    if (tokens[offset++] !== "=") throw new SyntaxError(`invalid ${enumName} value ${name}`);
    const number = Number(tokens[offset++]);
    if (!Number.isSafeInteger(number) || tokens[offset++] !== ";") throw new SyntaxError(`invalid ${enumName} number`);
    values.push({name, number});
  }
  return values;
}

function generatedCapabilityDescriptor() {
  const directory = mkdtempSync(join(tmpdir(), "cdnca-site-runtime-proto-"));
  const programPath = join(directory, "main.go");
  writeFileSync(programPath, `package main

import (
  "encoding/json"
  "os"

  agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

type value struct {
  Name string \`json:"name"\`
  Number int32 \`json:"number"\`
}

func main() {
  descriptor := agentv1.CapabilityName(0).Descriptor()
  values := make([]value, descriptor.Values().Len())
  for index := range values {
    item := descriptor.Values().Get(index)
    values[index] = value{Name: string(item.Name()), Number: int32(item.Number())}
  }
  _ = json.NewEncoder(os.Stdout).Encode(map[string]any{
    "file": descriptor.ParentFile().Path(),
    "full_name": string(descriptor.FullName()),
    "values": values,
  })
}
`);
  try {
    return JSON.parse(execFileSync("go", ["run", programPath], {
      cwd: resolve(root, "proto/gen/go"),
      encoding: "utf8",
      env: {...process.env, GOWORK: "off"}
    }));
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
}

function fixture() {
  return {
    schema: "cdnca.edge.site-runtime/v2",
    configuration_scope_id: "018f47a2-5b9c-7d31-8a60-104c9c0b7101",
    source_revision: 41,
    config_version_id: "018f47a2-5b9c-7d31-8a60-104c9c0b7102",
    sites: [{
      id: "018f47a2-5b9c-7d31-8a60-104c9c0b7103",
      revision: 7,
      domains: ["cdn.example.test"],
      listeners: [{
        id: "public-443",
        position: 0,
        address_family: "dual_stack",
        port: 443,
        protocols: ["http1", "http2", "http3"],
        tls: {
          certificate_version_id: "018f47a2-5b9c-7d31-8a60-104c9c0b7104"
        }
      }],
      origin_pools: [{
        id: "primary",
        position: 0,
        kind: "origin",
        algorithm: "round_robin",
        origins: [{
          id: "origin-a",
          position: 0,
          tier: "origin",
          scheme: "https",
          host: "192.0.2.10",
          port: 443,
          weight: 100,
          sni: "origin.example.test",
          trust_ref: "sha256:8b5e6f57d8f47ec690b6e1e0ef2fd5d7fa6ef74d8d17eb9e9fc2f0901e21a61d"
        }],
        retry: {
          methods: ["GET", "HEAD"],
          bodyless_only: true,
          response_not_started: true,
          retry_on: ["connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"],
          max_attempts: 3,
          connect_timeout_ms: 3000,
          read_timeout_ms: 30000,
          total_budget_ms: 60000
        }
      }, {
        id: "l2",
        position: 1,
        kind: "l2",
        algorithm: "least_conn",
        origins: [{
          id: "l2-a",
          position: 0,
          tier: "l2",
          scheme: "http",
          host: "2001:db8::10",
          port: 8080,
          weight: 100,
          node_id: "018f47a2-5b9c-7d31-8a60-104c9c0b7105"
        }],
        retry: {
          methods: ["GET", "HEAD"],
          bodyless_only: true,
          response_not_started: true,
          retry_on: ["connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"],
          max_attempts: 3,
          connect_timeout_ms: 3000,
          read_timeout_ms: 30000,
          total_budget_ms: 60000
        }
      }],
      default_pool_id: "l2",
      websocket: true,
      range: true,
      l2: {
        enabled: true,
        direct_fallback_pool_id: "primary",
        probe_interval_ms: 10000,
        failure_threshold: 3,
        recovery_threshold: 3,
        single_half_open_probe: true,
        max_hops: 1
      }
    }],
    required_capabilities: [
      {name: "http1", api_version: 1},
      {name: "http2", api_version: 1},
      {name: "http3", api_version: 1},
      {name: "ipv4", api_version: 1},
      {name: "ipv6", api_version: 1},
      {name: "site_runtime", api_version: 2},
      {name: "websocket", api_version: 1}
    ]
  };
}

test("site runtime shared capability fixtures keep v2/v3 and three real v4 payloads compatible", () => {
  const validate = validator(readSchema());
  for (const name of ["v2", "v3", "v4-package", "v4-security", "v4-streams"]) {
    const value = JSON.parse(readFileSync(resolve(root, `api/schemas/edge/v2/testdata/site-runtime-capability-${name}.json`), "utf8"));
    assert.equal(validate(value), true, `${name}: ${JSON.stringify(validate.errors)}`);
    for (const version of [0, 1, 5, 4294967295]) {
      const changed = structuredClone(value);
      changed.required_capabilities.find(({name}) => name === "site_runtime").api_version = version;
      assert.equal(validate(changed), false, `${name}: unknown version ${version}`);
    }
    const wrongVersion = structuredClone(value);
    wrongVersion.required_capabilities.find(({name}) => name === "site_runtime").api_version = name === "v2" ? 4 : 2;
    assert.equal(validate(wrongVersion), false, `${name}: capability must match payload`);
    const unknown = structuredClone(value);
    unknown.sites[0].unknown = true;
    assert.equal(validate(unknown), false, `${name}: unknown site field`);
  }
});

test("site runtime v4 schema rejects malformed nested runtime values", () => {
  const validate = validator(readSchema());
  const read = (name) => JSON.parse(readFileSync(resolve(root, `api/schemas/edge/v2/testdata/site-runtime-capability-v4-${name}.json`), "utf8"));
  const cases = [
    ["negative connections", "package", (value) => { value.sites[0].package_limits.connections = -1; }],
    ["unknown package field", "package", (value) => { value.sites[0].package_limits.execute = "arbitrary"; }],
    ["unknown security field", "security", (value) => { value.sites[0].listeners[0].security.execute = "arbitrary"; }],
    ["unknown nested CC field", "security", (value) => { value.sites[0].listeners[0].security.cc.Policy.execute = "arbitrary"; }],
    ["invalid CC window", "security", (value) => { value.sites[0].listeners[0].security.cc.Policy.rules[0].limit.window_seconds = 0; }],
    ["legacy CC capability", "security", (value) => { value.required_capabilities.find(({name}) => name === "cc").api_version = 1; }],
    ["invalid stream timeout", "streams", (value) => { value.streams.streams_v2[0].connect_timeout_ms = 0; }],
    ["unknown stream field", "streams", (value) => { value.streams.streams_v2[0].execute = "arbitrary"; }],
    ["invalid L4 version", "streams", (value) => { value.streams.streams_v2[0].schema_version = "cdnca.edge.l4/v3"; }],
    ["TLS downgrade", "package", (value) => { value.sites[0].listeners[1].tls.protocols = ["TLSv1.1"]; }]
  ];
  for (const [name, fixtureName, mutate] of cases) {
    const value = read(fixtureName);
    mutate(value);
    assert.equal(validate(value), false, name);
  }
});

test("site runtime v4 schema accepts TLS passthrough streams only with SNI on TCP", () => {
  const validate = validator(readSchema());
  const passthrough = () => {
    const value = JSON.parse(readFileSync(resolve(root, "api/schemas/edge/v2/testdata/site-runtime-capability-v4-streams.json"), "utf8"));
    const stream = value.streams.streams_v2[0];
    stream.listener.protocol = "tcp";
    delete stream.additional_listeners;
    stream.tls_passthrough = true;
    stream.server_names = ["*.example.com", "a.example.com", "b.example.com"];
    return value;
  };
  const valid = passthrough();
  assert.equal(validate(valid), true, JSON.stringify(validate.errors));
  const cases = [
    ["names without passthrough", (stream) => { delete stream.tls_passthrough; }],
    ["passthrough without names", (stream) => { delete stream.server_names; }],
    ["empty names", (stream) => { stream.server_names = []; }],
    ["duplicate names", (stream) => { stream.server_names = ["a.example.com", "a.example.com"]; }],
    ["inner wildcard", (stream) => { stream.server_names = ["a.*.example.com"]; }],
    ["wildcard on a TLD", (stream) => { stream.server_names = ["*.com"]; }],
    ["bare wildcard", (stream) => { stream.server_names = ["*"]; }],
    ["upper-case name", (stream) => { stream.server_names = ["A.example.com"]; }],
    ["udp passthrough", (stream) => { stream.listener.protocol = "udp"; }],
    ["udp additional listener", (stream) => {
      stream.additional_listeners = [{id: "44444444-4444-4444-8444-444444444444", protocol: "udp", address: "*", port: 18444}];
    }]
  ];
  for (const [name, mutate] of cases) {
    const value = passthrough();
    mutate(value.streams.streams_v2[0]);
    assert.equal(validate(value), false, name);
  }
});

test("site runtime v2 publishes exact wire, revision, and activation rules", () => {
  const schema = readSchema();
  assert.deepEqual(schema["x-cdnca-wire-contract"], {
    encoding: "UTF-8",
    canonicalization: "RFC8785",
    digest: "SHA-256",
    reject_duplicate_keys: true,
    reject_invalid_utf8: true,
    reject_trailing_tokens: true,
    reject_unknown_fields: true
  });
  assert.deepEqual(schema["x-cdnca-revision-contract"], {
    same_revision_same_digest: "idempotent_and_preserve_current",
    same_revision_different_digest: "reject_conflict_and_preserve_current",
    lower_revision: "reject_stale_and_preserve_current"
  });
  assert.deepEqual(schema["x-cdnca-activation-contract"], {
    unsupported_schema: "reject_and_preserve_current",
    missing_capability: "reject_and_preserve_current",
    invalid_document: "reject_and_preserve_current"
  });
});

test("site runtime v2 schema accepts the complete contract and rejects unsafe variants", () => {
  const validate = validator(readSchema());
  const valid = fixture();
  assert.equal(validate(valid), true, JSON.stringify(validate.errors));

  const cases = [
    ["unknown field", (value) => { value.unknown = true; }],
    ["missing site runtime capability", (value) => {
      value.required_capabilities = value.required_capabilities.filter(({name}) => name !== "site_runtime");
    }],
    ["missing HTTP3 capability", (value) => {
      value.required_capabilities = value.required_capabilities.filter(({name}) => name !== "http3");
    }],
    ["non-idempotent retry", (value) => { value.sites[0].origin_pools[0].retry.methods = ["POST"]; }],
    ["request body replay", (value) => { value.sites[0].origin_pools[0].retry.bodyless_only = false; }],
    ["response-start replay", (value) => { value.sites[0].origin_pools[0].retry.response_not_started = false; }],
    ["L2 without direct fallback", (value) => { delete value.sites[0].l2.direct_fallback_pool_id; }],
    ["multi-probe half open", (value) => { value.sites[0].l2.single_half_open_probe = false; }],
    ["multi-hop L2", (value) => { value.sites[0].l2.max_hops = 2; }],
    ["HTTPS origin without SNI", (value) => { delete value.sites[0].origin_pools[0].origins[0].sni; }],
    ["L2 origin without node identity", (value) => { delete value.sites[0].origin_pools[1].origins[0].node_id; }]
  ];
  for (const [name, mutate] of cases) {
    const value = structuredClone(valid);
    mutate(value);
    assert.equal(validate(value), false, name);
  }
});

test("site runtime v2 enforces deterministic collection identity and order", () => {
  const validate = validator(readSchema());
  const cases = [
    ["duplicate site ID", (value) => { value.sites.push(structuredClone(value.sites[0])); }],
    ["site order", (value) => {
      const site = structuredClone(value.sites[0]);
      site.id = "018f47a2-5b9c-7d31-8a60-104c9c0b7100";
      value.sites.push(site);
    }],
    ["duplicate capability", (value) => {
      value.required_capabilities.push(structuredClone(value.required_capabilities[0]));
    }],
    ["capability order", (value) => {
      [value.required_capabilities[0], value.required_capabilities[1]] =
        [value.required_capabilities[1], value.required_capabilities[0]];
    }],
    ["duplicate listener ID", (value) => {
      const listener = structuredClone(value.sites[0].listeners[0]);
      listener.position = 1;
      value.sites[0].listeners.push(listener);
    }],
    ["duplicate listener position", (value) => {
      const listener = structuredClone(value.sites[0].listeners[0]);
      listener.id = "public-8443";
      value.sites[0].listeners.push(listener);
    }],
    ["pool order", (value) => { value.sites[0].origin_pools.reverse(); }],
    ["duplicate origin position", (value) => {
      const origin = structuredClone(value.sites[0].origin_pools[0].origins[0]);
      origin.id = "origin-b";
      value.sites[0].origin_pools[0].origins.push(origin);
    }]
  ];
  for (const [name, mutate] of cases) {
    const value = fixture();
    mutate(value);
    assert.equal(validate(value), false, name);
  }
});

test("site runtime v2 binds local pools and a direct L1 fallback", () => {
  const validate = validator(readSchema());
  const cases = [
    ["missing default pool", (value) => { value.sites[0].default_pool_id = "missing"; }],
    ["missing fallback pool", (value) => { value.sites[0].l2.direct_fallback_pool_id = "missing"; }],
    ["self fallback", (value) => { value.sites[0].l2.direct_fallback_pool_id = "l2"; }],
    ["L2 fallback", (value) => {
      value.sites[0].default_pool_id = "primary";
      value.sites[0].l2.direct_fallback_pool_id = "l2";
    }],
    ["enabled without L2 pool", (value) => {
      const backup = structuredClone(value.sites[0].origin_pools[0]);
      backup.id = "backup";
      backup.position = 2;
      backup.origins[0].id = "backup-a";
      value.sites[0].origin_pools = [value.sites[0].origin_pools[0], backup];
      value.sites[0].default_pool_id = "primary";
      value.sites[0].l2.direct_fallback_pool_id = "backup";
    }]
  ];
  for (const [name, mutate] of cases) {
    const value = fixture();
    mutate(value);
    assert.equal(validate(value), false, name);
  }
});

test("site runtime v2 infers address capabilities from listeners and origins", () => {
  const validate = validator(readSchema());
  const missingIPv6 = fixture();
  missingIPv6.sites[0].listeners[0].address_family = "ipv4";
  missingIPv6.required_capabilities = missingIPv6.required_capabilities.filter(({name}) => name !== "ipv6");
  assert.equal(validate(missingIPv6), false, "IPv6 origin requires IPv6 capability");

  const missingIPv4 = fixture();
  missingIPv4.sites[0].listeners[0].address_family = "ipv6";
  missingIPv4.required_capabilities = missingIPv4.required_capabilities.filter(({name}) => name !== "ipv4");
  assert.equal(validate(missingIPv4), false, "IPv4 origin requires IPv4 capability");

  const hostnamesOnly = fixture();
  hostnamesOnly.sites[0].listeners[0].address_family = "ipv4";
  hostnamesOnly.sites[0].origin_pools[0].origins[0].host = "origin.example.test";
  hostnamesOnly.sites[0].origin_pools[1].origins[0].host = "l2.example.test";
  hostnamesOnly.required_capabilities = hostnamesOnly.required_capabilities.filter(({name}) => name !== "ipv6");
  assert.equal(validate(hostnamesOnly), true, JSON.stringify(validate.errors));
});

test("site runtime v2 validates raw bytes, canonical digest, and preserve-current outcomes", () => {
  const valid = fixture();
  const compact = Buffer.from(JSON.stringify(valid));
  const reordered = Buffer.from(JSON.stringify(Object.fromEntries(Object.entries(valid).reverse()), null, 2));
  const expectedDigest = "f671b5706494f4d932ae82d6c5769423d9c5e1feee74032cb75742e850237ee4";
  assert.equal(canonicalDigest(parseStrictJSON(compact)), expectedDigest);
  assert.equal(canonicalDigest(parseStrictJSON(reordered)), expectedDigest);
  assert.notEqual(createHash("sha256").update(compact).digest("hex"), createHash("sha256").update(reordered).digest("hex"));

  const current = {source_revision: valid.source_revision, canonical_sha256: expectedDigest, marker: "active"};
  const duplicate = Buffer.from(JSON.stringify(valid).replace(
    /^\{"schema":/u,
    "{\"schema\":\"cdnca.edge.site-runtime/v2\",\"schema\":"
  ));
  const invalidUTF8 = Buffer.from([0xc3, 0x28]);
  const trailing = Buffer.concat([compact, Buffer.from(" true")]);
  const unsupported = structuredClone(valid);
  unsupported.schema = "cdnca.edge.site-runtime/v1";
  const invalid = structuredClone(valid);
  invalid.unknown = true;
  const missingCapability = structuredClone(valid);
  missingCapability.required_capabilities = missingCapability.required_capabilities.filter(({name}) => name !== "http3");
  const conflict = structuredClone(valid);
  conflict.config_version_id = "018f47a2-5b9c-7d31-8a60-104c9c0b7199";
  const stale = structuredClone(valid);
  stale.source_revision -= 1;

  const cases = [
    ["duplicate key", duplicate, "invalid_document"],
    ["invalid UTF-8", invalidUTF8, "invalid_document"],
    ["trailing token", trailing, "invalid_document"],
    ["invalid schema document", Buffer.from(JSON.stringify(invalid)), "invalid_document"],
    ["unsupported schema", Buffer.from(JSON.stringify(unsupported)), "unsupported_schema"],
    ["missing capability", Buffer.from(JSON.stringify(missingCapability)), "missing_capability"],
    ["same revision conflict", Buffer.from(JSON.stringify(conflict)), "conflict"],
    ["stale revision", Buffer.from(JSON.stringify(stale)), "stale"],
    ["idempotent revision", reordered, "idempotent"]
  ];
  for (const [name, raw, result] of cases) {
    const outcome = activate(raw, current);
    assert.equal(outcome.result, result, name);
    assert.equal(outcome.preserve_current, true, name);
    assert.equal(outcome.current, current, name);
  }
});

test("round 3 requires the enabled L2 path to use an L2 default pool", () => {
  const validate = validator(readSchema());
  const value = fixture();
  const backup = structuredClone(value.sites[0].origin_pools[0]);
  backup.id = "backup";
  backup.position = 2;
  backup.origins[0].id = "backup-a";
  value.sites[0].origin_pools.push(backup);
  value.sites[0].default_pool_id = "primary";
  value.sites[0].l2.direct_fallback_pool_id = "backup";
  assert.equal(validate(value), false, "an unused L2 pool cannot make a non-L2 default valid");
});

test("round 3 rejects malformed valid JSON before semantic evaluation", () => {
  const valid = fixture();
  const current = {
    source_revision: valid.source_revision,
    canonical_sha256: canonicalDigest(valid),
    marker: "active"
  };
  const cases = [
    ["null capabilities", {...valid, required_capabilities: null}],
    ["non-array capabilities", {...valid, required_capabilities: {name: "site_runtime"}}],
    ["null capability entry", {...valid, required_capabilities: [null]}],
    ["nonscalar capability entry", {...valid, required_capabilities: [42]}],
    ["non-array sites", {...valid, sites: {}}],
    ["null site entry", {...valid, sites: [null]}],
    ["nonscalar site entry", {...valid, sites: ["site"]}]
  ];
  for (const [name, document] of cases) {
    let outcome;
    assert.doesNotThrow(() => {
      outcome = activate(Buffer.from(JSON.stringify(document)), current);
    }, name);
    assert.equal(outcome.result, "invalid_document", name);
    assert.equal(outcome.preserve_current, true, name);
    assert.equal(outcome.current, current, name);
  }
});

test("round 3 reports duplicate pool and origin IDs at their exact arrays", () => {
  const validate = validator(readSchema());
  const duplicatePool = fixture();
  const pool = structuredClone(duplicatePool.sites[0].origin_pools[0]);
  pool.position = 2;
  duplicatePool.sites[0].origin_pools.push(pool);
  assert.equal(validate(duplicatePool), false);
  assert.deepEqual(
    validate.errors.find(({instancePath, keyword}) =>
      instancePath === "/sites/0/origin_pools" && keyword === "x-cdnca-unique-by")?.params,
    {field: "id", duplicate: "primary", firstIndex: 0, duplicateIndex: 2}
  );

  const duplicateOrigin = fixture();
  const origin = structuredClone(duplicateOrigin.sites[0].origin_pools[0].origins[0]);
  origin.position = 1;
  duplicateOrigin.sites[0].origin_pools[0].origins.push(origin);
  assert.equal(validate(duplicateOrigin), false);
  assert.deepEqual(
    validate.errors.find(({instancePath, keyword}) =>
      instancePath === "/sites/0/origin_pools/0/origins" && keyword === "x-cdnca-unique-by")?.params,
    {field: "id", duplicate: "origin-a", firstIndex: 0, duplicateIndex: 1}
  );
});

test("round 4 dispatches only structurally valid schema envelopes", () => {
  const valid = fixture();
  const current = {
    source_revision: valid.source_revision,
    canonical_sha256: canonicalDigest(valid),
    marker: "active"
  };
  const missingSchema = structuredClone(valid);
  delete missingSchema.schema;
  const cases = [
    ["top-level null", null],
    ["top-level array", []],
    ["top-level number", 42],
    ["top-level string", "document"],
    ["top-level empty object", {}],
    ["missing schema", missingSchema],
    ["null schema", {...valid, schema: null}],
    ["numeric schema", {...valid, schema: 2}],
    ["array schema", {...valid, schema: []}],
    ["object schema", {...valid, schema: {version: 2}}]
  ];
  for (const [name, document] of cases) {
    let outcome;
    assert.doesNotThrow(() => {
      outcome = activate(Buffer.from(JSON.stringify(document)), current);
    }, name);
    assert.equal(outcome.result, "invalid_document", name);
    assert.equal(outcome.preserve_current, true, name);
    assert.equal(outcome.current, current, name);
  }

  const unsupported = {...valid, schema: "cdnca.edge.site-runtime/v1"};
  const outcome = activate(Buffer.from(JSON.stringify(unsupported)), current);
  assert.equal(outcome.result, "unsupported_schema");
  assert.equal(outcome.preserve_current, true);
  assert.equal(outcome.current, current);
});

test("site runtime v2 proto source equals the generated runtime descriptor", () => {
  const source = parseProtoEnum(readFileSync(protoPath, "utf8"), "CapabilityName");
  const generated = generatedCapabilityDescriptor();
  assert.equal(generated.file, "agent/v1/types.proto");
  assert.equal(generated.full_name, "agent.v1.CapabilityName");
  assert.deepEqual(generated.values, source);
  assert.deepEqual(source.find(({name}) => name === "CAPABILITY_NAME_SITE_RUNTIME"), {name: "CAPABILITY_NAME_SITE_RUNTIME", number: 21});
});
