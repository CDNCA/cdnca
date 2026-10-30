import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const apiDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(apiDir, "..");
const fragmentPath = join(apiDir, "control-account-orders.openapi.yaml");
const aggregatePath = join(apiDir, "openapi/v1/control.yaml");
const aggregateSource = readFileSync(aggregatePath, "utf8");
const temporaryDir = mkdtempSync(join(tmpdir(), "cdnca-account-orders-openapi-"));

const operations = [
  ["get", "/v1/account/orders", "listAccountOrders", "200"],
  ["get", "/v1/account/statement", "listAccountStatement", "200"],
  ["post", "/v1/admin/account/orders", "createAccountOrder", "201"],
  ["patch", "/v1/admin/account/orders/{id}", "updateAccountOrder", "200"],
  ["delete", "/v1/admin/account/orders/{id}", "deleteAccountOrder", "200"],
  ["get", "/v1/admin/account/order-users", "listAccountOrderUsers", "200"],
];

try {
  const fragmentBundle = join(temporaryDir, "fragment.json");
  const aggregateBundle = join(temporaryDir, "aggregate.json");
  for (const [source, output] of [[fragmentPath, fragmentBundle], [aggregatePath, aggregateBundle]]) {
    execFileSync(
      "pnpm",
      ["--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle", source, "--output", output],
      {cwd: root, stdio: "pipe"},
    );
  }
  const fragment = JSON.parse(readFileSync(fragmentBundle, "utf8"));
  const aggregate = JSON.parse(readFileSync(aggregateBundle, "utf8"));

  assert.deepEqual(Object.keys(fragment.paths).sort(), [
    "/v1/account/orders",
    "/v1/account/statement",
    "/v1/admin/account/order-users",
    "/v1/admin/account/orders",
    "/v1/admin/account/orders/{id}",
  ]);
  for (const [method, path, operationId, successStatus] of operations) {
    const fragmentOperation = fragment.paths?.[path]?.[method];
    const aggregateOperation = aggregate.paths?.[path]?.[method];
    assert.equal(fragmentOperation?.operationId, operationId, `${method.toUpperCase()} ${path} fragment drifted`);
    assert.equal(aggregateOperation?.operationId, operationId, `${method.toUpperCase()} ${path} aggregate drifted`);
    assert.ok(fragmentOperation?.responses?.[successStatus], `${operationId} success response missing`);
    assert.ok(fragmentOperation?.responses?.["401"] && fragmentOperation?.responses?.["403"],
      `${operationId} must expose authentication and authorization failures`);
  }

  for (const reference of [
    "../../control-account-orders.openapi.yaml#/paths/~1v1~1account~1orders",
    "../../control-account-orders.openapi.yaml#/paths/~1v1~1admin~1account~1orders",
    "../../control-account-orders.openapi.yaml#/paths/~1v1~1admin~1account~1orders~1{id}",
    "../../control-account-orders.openapi.yaml#/paths/~1v1~1admin~1account~1order-users",
    "../../control-account-orders.openapi.yaml#/paths/~1v1~1account~1statement",
  ]) {
    assert.ok(aggregateSource.includes(reference), `aggregate path reference missing: ${reference}`);
  }

  const input = fragment.components.schemas.AccountOrderInput;
  assert.equal(input.additionalProperties, false);
  assert.deepEqual(input.required, Object.keys(input.properties));
  assert.deepEqual(input.properties.paid_at.oneOf, [
    {type: "string", format: "date-time"},
    {type: "null"},
  ]);

  const output = fragment.components.schemas.AccountOrder;
  assert.equal(output.additionalProperties, false);
  assert.deepEqual(Object.keys(output.properties).sort(), [
    "created_at", "details", "display_id", "editable", "id", "merchant_order_number", "note",
    "original_amount_minor", "paid_amount_minor", "paid_at", "payment_method", "revision",
    "source", "status", "tenant_id", "tenant_scope_id", "transaction_number", "type",
    "user_display_id", "user_display_name", "user_id", "username",
  ]);
  assert.deepEqual(output.required, Object.keys(output.properties).filter((name) => name !== "paid_at"));
  assert.equal(output.properties.paid_at.format, "date-time");

  for (const method of ["post", "patch"]) {
    const path = method === "post" ? "/v1/admin/account/orders" : "/v1/admin/account/orders/{id}";
    assert.ok(fragment.paths[path][method].responses["415"], `${method.toUpperCase()} must expose 415`);
  }
  const errorEnvelope = fragment.components.schemas.ErrorEnvelope;
  assert.equal(errorEnvelope.additionalProperties, false);
  assert.deepEqual(errorEnvelope.required, ["error"]);
  assert.equal(errorEnvelope.properties.error.$ref, "#/components/schemas/Error");
  const error = fragment.components.schemas.Error;
  assert.equal(error.additionalProperties, false);
  assert.deepEqual(error.required, ["code", "message", "request_id"]);
  for (const responseName of [
    "BadRequest", "Unauthorized", "Forbidden", "NotFound", "Conflict",
    "UnsupportedMediaType", "Unavailable",
  ]) {
    assert.equal(
      fragment.components.responses[responseName].content["application/json"].schema.$ref,
      "#/components/schemas/ErrorEnvelope",
      `${responseName} envelope drifted`,
    );
  }
} finally {
  rmSync(temporaryDir, {recursive: true, force: true});
}

console.log(`account order OpenAPI contract: passed (${operations.length} operations)`);
