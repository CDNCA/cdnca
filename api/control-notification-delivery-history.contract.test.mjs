import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const apiDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(apiDir, "..");
const path = "/v1/admin/notifications/delivery-history";
const fragment = "control-notification-delivery-history.openapi.yaml";
const rootSource = readFileSync(join(apiDir, "openapi/v1/control.yaml"), "utf8");
const handler = readFileSync(join(root, "services/control-api/internal/notificationhttp/handler.go"), "utf8");
const mount = readFileSync(join(root, "services/control-api/internal/httpapi/server.go"), "utf8");
assert.ok(rootSource.includes(`  ${path}:\n    $ref: '../../${fragment}#/paths/${path.replaceAll("/", "~1")}'`));
assert.ok(handler.includes(`mux.HandleFunc("GET ${path}", h.listDeliveryHistory)`));
assert.ok(mount.includes(`"${path}",`));

const directory = mkdtempSync(join(tmpdir(), "cdnca-delivery-history-contract-"));
try {
  const output = join(directory, "history.json");
  execFileSync("pnpm", ["--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle", join(apiDir, fragment), "--output", output], {cwd: root, stdio: "pipe"});
  const document = JSON.parse(readFileSync(output, "utf8"));
  const operation = document.paths[path].get;
  assert.equal(operation.operationId, "listNotificationDeliveryHistory");
  assert.equal(operation["x-required-permissions"], undefined);
  assert.deepEqual(operation["x-required-any-permission"], ["system_configuration.read", "platform.admin"]);
  assert.deepEqual(Object.keys(operation.responses).sort(), ["200", "400", "401", "403", "405", "500"]);
  assert.deepEqual(operation.parameters.map((parameter) => parameter.name).sort(), [
    "channel", "cursor", "event_type", "from", "limit", "message_id", "result", "scope_id", "state", "to", "user_id",
  ]);
  assert.match(operation.description, /Without from\/to the complete history/);
  assert.match(operation.description, /do not promise a snapshot across requests/);
  assert.match(operation.parameters.find((parameter) => parameter.name === "result").description, /success means only delivered; failure means retry_wait, permanent_failed or exhausted/);
  const {DeliveryHistoryPage: page, DeliveryHistoryFact: fact} = document.components.schemas;
  assert.equal(page.properties.schema.const, "cdnca.notification-delivery-history/v1");
  assert.deepEqual(page.required.sort(), ["items", "schema", "total_count"]);
  assert.equal(page.additionalProperties, false);
  assert.equal(fact.additionalProperties, false);
  assert.deepEqual(fact.required.sort(), Object.keys(fact.properties).sort());
  assert.deepEqual(fact.properties.recipient_address.type, ["string", "null"]);
  assert.equal(fact.properties.recipient_address.maxLength, 254);
  assert.deepEqual(fact.properties.recipient_address_state.enum, ["masked", "unavailable"]);
  assert.deepEqual(fact.properties.provider_call_started_at.type, ["string", "null"]);
  assert.equal(fact.properties.provider_call_started_at.format, "date-time");
  assert.match(fact.properties.provider_call_started_at.description, /actual ProviderTransport.Send invocation boundary/);
  assert.match(operation.description, /same attempt/);
  assert.match(operation.description, /never backfilled/);
  assert.deepEqual(fact.properties.recipient_user_id.type, ["string", "null"]);
  assert.match(fact.properties.failure_count.description, /through this row's sequence/);
  assert.match(fact.properties.failure_count.description, /replay outboxes count independently/);
  for (const forbidden of ["subject", "body", "payload", "provider", "provider_response", "lease_token", "dedup_key", "contact"]) {
    assert.ok(!(forbidden in fact.properties), `history exposes ${forbidden}`);
  }
} finally {
  rmSync(directory, {recursive: true, force: true});
}
console.log("notification delivery history OpenAPI contract: passed");
