import assert from "node:assert/strict";
import {createHash, createPublicKey, verify} from "node:crypto";
import {readFile} from "node:fs/promises";

import Ajv from "ajv";
import addFormats from "ajv-formats";

const root = new URL("../../", import.meta.url);
const exampleRoot = new URL("examples/plugins/webhook-audit-sink/", root);

async function readJSON(path, base = root) {
  return JSON.parse(await readFile(new URL(path, base), "utf8"));
}

function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
}

function rawEd25519PublicKey(raw) {
  assert.equal(raw.length, 32, "Ed25519 public key must be 32 bytes");
  return createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]),
    format: "der",
    type: "spki"
  });
}

const [manifestSchema, eventSchema, catalog, manifest, event, configSchema, publisher, installation] = await Promise.all([
  readJSON("api/schemas/marketplace/v1/plugin-manifest.schema.json"),
  readJSON("api/schemas/marketplace/v1/domain-event.schema.json"),
  readJSON("api/schemas/marketplace/v1/extension-catalog.json"),
  readJSON("plugin.json", exampleRoot),
  readJSON("tests/plugin-example/domain-event-v1.json"),
  readJSON("schemas/config.schema.json", exampleRoot),
  readJSON("publisher-public-key.json", exampleRoot),
  readJSON("installation.example.json", exampleRoot)
]);

const ajv = new Ajv({allErrors: true, strict: true});
addFormats(ajv);
for (const schema of [manifestSchema, eventSchema, configSchema]) {
  assert.equal(ajv.validateSchema(schema), true, JSON.stringify(ajv.errors));
}
assert.equal(ajv.compile(manifestSchema)(manifest), true, "example manifest does not match marketplace v1");
// The example event carries one undeclared sensitive field so the receiver's
// journal redaction is exercised; the closed v1 schema must reject it, and the
// event without it must validate.
const validateDomainEvent = ajv.compile(eventSchema);
assert.equal(validateDomainEvent(event), false, "domain-event v1 must reject undeclared data fields");
const declaredEvent = structuredClone(event);
delete declaredEvent.data.api_token;
assert.equal(validateDomainEvent(declaredEvent), true, JSON.stringify(validateDomainEvent.errors));
assert.equal(ajv.compile(configSchema)({}), true, "empty example configuration was rejected");

const permissionByName = new Map(catalog.permissions.map((entry) => [entry.name, entry]));
const eventByType = new Map(catalog.events.map((entry) => [entry.type, entry]));
for (const permission of manifest.spec.permissions) assert.ok(permissionByName.has(permission), `unknown permission: ${permission}`);
for (const eventType of manifest.spec.subscriptions) assert.ok(eventByType.has(eventType), `unknown event: ${eventType}`);
assert.equal(permissionByName.get("events.site.read").status, "available", "site.updated is a public event (PA-20)");
assert.equal(eventByType.get("io.cdnca.site.v1.updated").status, "available", "site.updated is a public event (PA-20)");

// The site.updated business example (examples/plugins/webhook-v2-receiver):
// its manifest (unsigned; cdnca-plugin sign-manifest fills integrity) and the
// event bytes its Go tests feed the receiver match the published contracts.
const receiverRoot = new URL("examples/plugins/webhook-v2-receiver/", root);
const receiverManifest = await readJSON("manifest.json", receiverRoot);
assert.equal(receiverManifest.integrity, undefined, "the receiver example manifest is shipped unsigned");
const signedShape = structuredClone(receiverManifest);
signedShape.integrity = {algorithm: "Ed25519", key_id: "com.example:placeholder", payload_sha256: "0".repeat(64), signature: "A".repeat(86)};
assert.equal(ajv.compile(manifestSchema)(signedShape), true, "receiver example manifest does not match marketplace v1");
for (const permission of receiverManifest.spec.permissions) assert.equal(permissionByName.get(permission)?.status, "available", permission);
for (const eventType of receiverManifest.spec.subscriptions) assert.equal(eventByType.get(eventType)?.status, "available", eventType);
const receiverConfig = await readFile(new URL(receiverManifest.spec.configuration_schema.path, receiverRoot));
assert.equal(createHash("sha256").update(receiverConfig).digest("hex"), receiverManifest.spec.configuration_schema.sha256, "receiver configuration schema digest mismatch");
const siteEvent = await readJSON("testdata/site-updated.json", receiverRoot);
assert.equal(validateDomainEvent(siteEvent), true, JSON.stringify(validateDomainEvent.errors));
assert.ok(receiverManifest.spec.subscriptions.includes(siteEvent.type));

const configBytes = await readFile(new URL(manifest.spec.configuration_schema.path, exampleRoot));
assert.equal(createHash("sha256").update(configBytes).digest("hex"), manifest.spec.configuration_schema.sha256, "configuration schema digest mismatch");
const unsignedManifest = structuredClone(manifest);
delete unsignedManifest.integrity;
const manifestDigest = createHash("sha256").update(canonicalize(unsignedManifest), "utf8").digest();
assert.equal(manifestDigest.toString("hex"), manifest.integrity.payload_sha256, "manifest digest mismatch");
assert.equal(publisher.key_id, manifest.integrity.key_id);
assert.equal(publisher.algorithm, manifest.integrity.algorithm);
assert.equal(
  verify(
    null,
    Buffer.concat([Buffer.from("cdnca-plugin-manifest/v1\n"), manifestDigest]),
    rawEd25519PublicKey(Buffer.from(publisher.public_key_base64url, "base64url")),
    Buffer.from(manifest.integrity.signature, "base64url")
  ),
  true,
  "manifest signature mismatch"
);

assert.equal(installation.example_only, true, "installation fixture must not look like a published API request");
assert.equal(installation.service_account.credential_type, "oauth2_client_credentials");
assert.equal(installation.service_account.tenant_id, event.tenant_id);
assert.ok(installation.service_account.token_ttl_seconds > 0 && installation.service_account.token_ttl_seconds <= 900);
assert.deepEqual(installation.granted_scopes, manifest.spec.permissions);
assert.deepEqual(installation.webhook_subscription.event_types, manifest.spec.subscriptions);
assert.equal(installation.webhook_subscription.endpoint_path, "/webhooks/cdnca/v1");
assert.equal(installation.webhook_subscription.secret_delivery, "out_of_band_once");
assert.equal(JSON.stringify(installation).includes("client_secret"), false, "installation fixture contains a credential");

console.log("plugin example contracts: schema, catalog, manifest signature, scope, and subscription passed");
