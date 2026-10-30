import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const apiDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(apiDir, "..");
const fragment = join(apiDir, "control-recharge-payments.openapi.yaml");
const temporaryDirectory = mkdtempSync(join(tmpdir(), "cdnca-recharge-payment-openapi-"));

try {
  const output = join(temporaryDirectory, "fragment.json");
  execFileSync("pnpm", ["--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle", fragment, "--output", output], {
    cwd: root,
    stdio: "pipe",
  });
  const document = JSON.parse(readFileSync(output, "utf8"));
  assert.deepEqual(Object.keys(document.paths).sort(), [
    "/v1/admin/recharge-payments/orders/{order_id}/reconciliation",
    "/v1/admin/recharge-payments/orders/{order_id}/refunds",
    "/v1/admin/recharge-payments/orders/{order_id}/voids",
    "/v1/recharge-payments/checkouts",
    "/v1/recharge-payments/orders/{order_id}/cancellation",
  ]);
  // Gateways notify /payments/v1/notify/{channel_id} (payment channels).
  assert.equal(document["x-cdnca-provider-signatures"], undefined);
  const resolveParameter = (parameter) => parameter.$ref
    ? document.components.parameters[parameter.$ref.split("/").at(-1)]
    : parameter;
  assert.deepEqual(document.components.schemas.CreateCheckout.properties.provider.enum, ["alipay", "wechat"]);
  assert.deepEqual(document.components.schemas.ReconcileRequest.properties.provider.enum, ["alipay", "wechat"]);
  for (const suffix of ["refunds", "voids"]) {
    const operation = document.paths[`/v1/admin/recharge-payments/orders/{order_id}/${suffix}`].post;
    assert.deepEqual(operation["x-required-permissions"], ["billing.recharges.compensate"]);
    assert.ok(operation.parameters.map(resolveParameter)
      .some((parameter) => parameter.name === "X-Step-Up-Token"));
    assert.equal(operation["x-cdnca-step-up"].consumption, "atomic-before-provider-mutation");
    // 退款/作废需要先审批：step-up 令牌同时绑定 approval_id（rechargepayment.ApprovalID）。
    assert.deepEqual(operation["x-cdnca-step-up"].binding, [
      "actor", "approval_id", "tenant", "order", "operation", "amount_minor", "expected_revision", "idempotency_key", "request_id",
    ]);
    // CFIN-D: the intent is durable before the provider call and retried by its refund number.
    assert.equal(operation["x-cdnca-provider-mutation"].durableIntent, "before-remote-call");
    assert.equal(operation["x-cdnca-provider-mutation"].retryIdentity, "provider_request_id");
    for (const status of ["200", "202"]) {
      assert.equal(operation.responses[status].content["application/json"].schema.$ref, "#/components/schemas/CompensationResult");
    }
  }
  assert.deepEqual(document.components.schemas.CompensationResult.properties.status.enum,
    ["pending", "succeeded", "failed", "unknown"]);
  for (const code of ["recharge_payment_insufficient_balance", "recharge_payment_compensation_not_sent"]) {
    assert.ok(document.components.schemas.ErrorEnvelope.properties.code.enum.includes(code));
  }
  assert.deepEqual(document.components.schemas.SettlementResult.properties.state.enum, [
    "pending", "paid", "partially_refunded", "refunded", "voided", "failed", "canceled", "reconcile_required",
  ]);
  assert.equal(document.components.schemas.SignedCheckout.additionalProperties, false);
  const cancellation = document.paths["/v1/recharge-payments/orders/{order_id}/cancellation"].post;
  assert.deepEqual(cancellation["x-required-permissions"], ["billing.recharges.cancel"]);
  assert.equal(cancellation["x-cdnca-provider-mutation"].durableIntent, "before-remote-call");
  assert.equal(cancellation["x-cdnca-provider-mutation"].retryIdentity, "provider_request_id");
  assert.deepEqual(document.components.schemas.CancellationResult.properties.status.enum,
    ["pending", "succeeded", "failed", "unknown"]);
  assert.ok(document.components.schemas.ErrorEnvelope.properties.code.enum.includes("identity_verification_required"));
  assert.ok(document.components.responses.ProviderUnavailable.headers["Retry-After"]);
  const encoded = JSON.stringify(document);
  for (const forbidden of ["raw_payload", "raw_signature", "provider_secret", "private_key"]) {
    assert.equal(encoded.includes(forbidden), false, `secret-bearing property leaked: ${forbidden}`);
  }
} finally {
  rmSync(temporaryDirectory, {recursive: true, force: true});
}

console.log("recharge payment lifecycle OpenAPI contract: passed");
