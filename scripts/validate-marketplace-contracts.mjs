import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";

import Ajv from "ajv";
import addFormats from "ajv-formats";

const root = new URL("../", import.meta.url);

async function readJSON(path) {
  return JSON.parse(await readFile(new URL(path, root), "utf8"));
}

function canonicalize(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
    .join(",")}}`;
}

function decodeBase64url(value) {
  return Buffer.from(value, "base64url");
}

function rawEd25519PublicKey(raw) {
  assert.equal(raw.length, 32, "Ed25519 public key must be 32 bytes");
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({key: Buffer.concat([spkiPrefix, raw]), format: "der", type: "spki"});
}

const [manifestSchema, eventSchema, catalogSchema, manifest, event, catalog, publisher, deploymentEvent, pa24Events] =
  await Promise.all([
    readJSON("api/schemas/marketplace/v1/plugin-manifest.schema.json"),
    readJSON("api/schemas/marketplace/v1/domain-event.schema.json"),
    readJSON("api/schemas/marketplace/v1/extension-catalog.schema.json"),
    readJSON("tests/contracts/plugin-manifest-v1.json"),
    readJSON("tests/contracts/domain-event-v1.json"),
    readJSON("api/schemas/marketplace/v1/extension-catalog.json"),
    readJSON("tests/contracts/plugin-publisher-v1.json"),
    readJSON("tests/contracts/domain-event-deployment-v1.json"),
    readJSON("tests/contracts/domain-event-pa24-v1.json")
  ]);

const ajv = new Ajv({allErrors: true, strict: true});
addFormats(ajv);

for (const schema of [manifestSchema, eventSchema, catalogSchema]) {
  assert.equal(ajv.validateSchema(schema), true, JSON.stringify(ajv.errors));
}

const validateManifest = ajv.compile(manifestSchema);
const validateEvent = ajv.compile(eventSchema);
const validateCatalog = ajv.compile(catalogSchema);

assert.equal(validateManifest(manifest), true, JSON.stringify(validateManifest.errors));
assert.equal(validateEvent(event), true, JSON.stringify(validateEvent.errors));
assert.equal(validateEvent(deploymentEvent), true, JSON.stringify(validateEvent.errors));
for (const pa24Event of pa24Events) {
  assert.equal(validateEvent(pa24Event), true, `${pa24Event.type}: ${JSON.stringify(validateEvent.errors)}`);
  const leaked = structuredClone(pa24Event);
  leaked.data.client_ip = "192.0.2.1";
  assert.equal(validateEvent(leaked), false, `${pa24Event.type} must reject undeclared data fields`);
}

// Every available catalog event has a typed data definition, and only those.
const availableEvents = catalog.events.filter((entry) => entry.status === "available").map((entry) => entry.type).sort();
assert.deepEqual([...eventSchema.properties.type.enum].sort(), availableEvents,
  "domain-event schema type enum must list exactly the available catalog events");
for (const entry of catalog.events.filter((item) => item.status === "available")) {
  assert.equal(catalog.permissions.find((permission) => permission.name === entry.required_permission)?.status,
    "available", `${entry.type} requires an available permission`);
}
const mutatedEvent = structuredClone(event);
mutatedEvent.type = "io.cdnca.deployment.v1.status_changed";
assert.equal(validateEvent(mutatedEvent), false, "site data must not validate as a deployment event");
const reservedEvent = structuredClone(event);
reservedEvent.type = "io.cdnca.dns.v1.changed";
assert.equal(validateEvent(reservedEvent), false, "reserved events must not validate");
assert.equal(validateCatalog(catalog), true, JSON.stringify(validateCatalog.errors));

const semverCases = [
  ["0.0.0", true],
  ["1.2.3-alpha.1", true],
  ["1.2.3-x-7.z.92", true],
  ["1.2.3+build.7", true],
  [`${"1".repeat(124)}.0.0`, true],
  ["v1.2.3", false],
  ["01.2.3", false],
  ["1.2.3-01", false],
  ["1.2.3-alpha..1", false],
  ["1.2.3-.alpha", false],
  ["1.2.3-alpha.", false],
  ["1.2.3+build..1", false],
  ["1.2.3+.build", false],
  ["1.2.3+build.", false],
  ["1.2.3-alpha_1", false],
  [`${"1".repeat(125)}.0.0`, false]
];
for (const [value, expected] of semverCases) {
  const candidate = structuredClone(manifest);
  candidate.metadata.version = value;
  assert.equal(validateManifest(candidate), expected, `schema SemVer parity failed for ${JSON.stringify(value)}`);
}

const keyIDCases = [
  ["A", true],
  ["publisher:key-1", true],
  [`a${".".repeat(127)}`, true],
  ["", false],
  ["-publisher", false],
  [".publisher", false],
  [":publisher", false],
  ["_publisher", false],
  ["publisher key", false],
  ["publisher/key", false],
  ["发布者", false],
  [`a${".".repeat(128)}`, false]
];
for (const [value, expected] of keyIDCases) {
  const candidate = structuredClone(manifest);
  candidate.integrity.key_id = value;
  assert.equal(validateManifest(candidate), expected, `schema key_id parity failed for ${JSON.stringify(value)}`);
}

const knownPermissions = new Set(catalog.permissions.map((entry) => entry.name));
const knownEvents = new Set(catalog.events.map((entry) => entry.type));
assert.equal(knownPermissions.size, catalog.permissions.length, "duplicate permission in extension catalog");
assert.equal(knownEvents.size, catalog.events.length, "duplicate event in extension catalog");
assert.equal(
  catalog.events.every((entry) => knownPermissions.has(entry.required_permission)),
  true,
  "event references an unknown permission"
);
assert.equal(
  manifest.spec.permissions.every((permission) => knownPermissions.has(permission)),
  true,
  "manifest references an unknown permission"
);
assert.equal(
  (manifest.spec.subscriptions ?? []).every((eventType) => knownEvents.has(eventType)),
  true,
  "manifest subscribes to an unknown event"
);

const unsignedManifest = structuredClone(manifest);
delete unsignedManifest.integrity;
const digest = createHash("sha256").update(canonicalize(unsignedManifest), "utf8").digest();
assert.equal(digest.toString("hex"), manifest.integrity.payload_sha256, "manifest digest mismatch");
assert.equal(publisher.key_id, manifest.integrity.key_id, "publisher key ID mismatch");
assert.equal(publisher.algorithm, manifest.integrity.algorithm, "publisher algorithm mismatch");
const signedMessage = Buffer.concat([Buffer.from("cdnca-plugin-manifest/v1\n"), digest]);
assert.equal(
  verify(
    null,
    signedMessage,
    rawEd25519PublicKey(decodeBase64url(publisher.public_key_base64url)),
    decodeBase64url(manifest.integrity.signature)
  ),
  true,
  "manifest signature mismatch"
);

const missingChinese = structuredClone(manifest);
delete missingChinese.metadata.name["zh-CN"];
assert.equal(validateManifest(missingChinese), false, "manifest without zh-CN name was accepted");

const insecureEndpoint = structuredClone(manifest);
insecureEndpoint.spec.entrypoint.base_url = "http://plugin.example.invalid";
assert.equal(validateManifest(insecureEndpoint), false, "HTTP plugin endpoint was accepted");

const unknownPermission = structuredClone(manifest);
unknownPermission.spec.permissions = ["system.root"];
assert.equal(validateManifest(unknownPermission), true, "permission syntax fixture should be valid");
assert.equal(
  unknownPermission.spec.permissions.every((permission) => knownPermissions.has(permission)),
  false,
  "unknown permission unexpectedly exists in the extension catalog"
);

const tamperedManifest = structuredClone(manifest);
tamperedManifest.metadata.version = "1.0.1";
const tamperedUnsigned = structuredClone(tamperedManifest);
delete tamperedUnsigned.integrity;
const tamperedDigest = createHash("sha256").update(canonicalize(tamperedUnsigned), "utf8").digest();
assert.notEqual(tamperedDigest.toString("hex"), manifest.integrity.payload_sha256);

console.log("marketplace contracts: schemas, fixtures, signature, and negative cases passed");
