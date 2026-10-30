import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const apiDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(apiDir, "..");
const fragment = join(apiDir, "control-promotions.openapi.yaml");
const temporaryDirectory = mkdtempSync(join(tmpdir(), "cdnca-promotions-openapi-"));

try {
  const output = join(temporaryDirectory, "fragment.json");
  execFileSync(
    "pnpm",
    ["--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle", fragment, "--output", output],
    {cwd: root, stdio: "pipe"},
  );
  const document = JSON.parse(readFileSync(output, "utf8"));
  const operation = document.paths?.["/v1/admin/promotion-coupon-usage"]?.get;
  assert.ok(operation, "coupon usage GET operation is missing");
  assert.deepEqual(operation.security, [{bearerAuth: []}]);
  assert.deepEqual(operation["x-required-permissions"], ["promotions.read"]);
  assert.equal(operation.requestBody, undefined);
  assert.equal(operation.responses["200"].$ref, "#/components/responses/CouponUsagePageOK");
  assert.equal(operation.responses["401"].$ref, "#/components/responses/Unauthorized");
  assert.equal(operation.responses["403"].$ref, "#/components/responses/Forbidden");

  const parameterNames = operation.parameters.map((parameter) => {
    const name = parameter.$ref?.split("/").at(-1);
    return name ? document.components.parameters[name].name : parameter.name;
  });
  assert.deepEqual(parameterNames, ["policy_id", "tenant_scope_id", "status", "limit", "cursor"]);
  assert.equal(document.components.parameters.UsagePolicyID["x-cdnca-single-value"], true);
  assert.equal(document.components.parameters.UsageTenantScopeID["x-cdnca-single-value"], true);
  assert.deepEqual(document.components.parameters.UsageStatus.schema.enum, [
    "reserved", "consumed", "released", "expired",
  ]);
  assert.match(document.components.parameters.Cursor.description, /actor.*filters.*snapshot.*keyset/is);

  const usage = document.components.schemas.CouponUsage;
  assert.equal(usage.type, "object");
  assert.equal(usage.additionalProperties, false);
  assert.deepEqual(usage.required, [
    "reservation_id", "quote_id", "tenant_scope_id", "user_id", "policy_id",
    "policy_revision", "application_order", "policy_name", "coupon_code", "product_kind",
    "product_id", "product_revision", "use_kind", "currency", "original_amount_minor",
    "discount_amount_minor", "payable_amount_minor", "policy_discount_minor", "status",
    "expires_at", "reserved_at", "updated_at",
  ]);
  assert.equal(usage.properties.coupon_code.pattern, "^[A-Z0-9][A-Z0-9_-]{0,63}$");
  assert.equal(usage.properties.currency.const, "CNY");
  assert.deepEqual(usage.properties.status.enum, ["reserved", "consumed", "released", "expired"]);
  for (const field of [
    "original_amount_minor", "discount_amount_minor", "payable_amount_minor", "policy_discount_minor",
  ]) {
    assert.equal(usage.properties[field].minimum, 0, `${field} must be non-negative`);
  }
  const page = document.components.schemas.CouponUsagePage;
  assert.equal(page.additionalProperties, false);
  assert.deepEqual(page.required, ["items"]);
  assert.equal(page.properties.items.maxItems, 100);
  assert.equal(page.properties.items.items.$ref, "#/components/schemas/CouponUsage");
} finally {
  rmSync(temporaryDirectory, {recursive: true, force: true});
}

console.log("promotion marketing OpenAPI contract: passed");
