import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const apiDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(apiDir, "..");
const fragmentPath = join(apiDir, "control-package-commerce.openapi.yaml");
const authenticator = readFileSync(
  join(root, "services/control-api/internal/packagecommerceprovider/authenticator.go"),
  "utf8",
);
const callbackStore = readFileSync(
  join(root, "services/control-api/internal/packagecommerce/callback.go"),
  "utf8",
);

for (const marker of [
  'SignatureVersion = "1"',
  "MaxCallbackBytes = 256 << 10",
  'strings.HasPrefix(rawSignature, "v1=")',
  "base64.RawURLEncoding.Strict().DecodeString(encodedSignature)",
  "key.AccountID != document.ProviderAccountID",
  '"cdnca.package-commerce.provider-callback.v1"',
]) {
  assert.ok(authenticator.includes(marker), `runtime callback authentication marker missing: ${marker}`);
}
for (const marker of [
  "WHERE provider=$1 AND provider_account_id=$2 AND external_event_id=$3",
  "bytes.Equal(digest, request.PayloadSHA256[:])",
  "result.Replayed = true",
]) {
  assert.ok(callbackStore.includes(marker), `durable callback idempotency marker missing: ${marker}`);
}

const temporaryDirectory = mkdtempSync(join(tmpdir(), "cdnca-package-commerce-openapi-"));
try {
  const output = join(temporaryDirectory, "fragment.json");
  execFileSync(
    "pnpm",
    ["--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle", fragmentPath, "--output", output],
    {cwd: root, stdio: "pipe"},
  );
  const document = JSON.parse(readFileSync(output, "utf8"));
  const operation = document.paths?.["/v1/package-commerce/provider-callbacks/{provider}"]?.post;
  assert.ok(operation, "callback POST operation is missing");
  assert.deepEqual(operation.security, []);

  const parameters = new Map(operation.parameters.map((parameter) => [parameter.name, parameter]));
  for (const name of [
    "X-CDNCA-Callback-Version",
    "X-CDNCA-Callback-Key-ID",
    "X-CDNCA-Callback-Timestamp",
    "X-CDNCA-Callback-Signature",
  ]) {
    const parameter = parameters.get(name);
    assert.ok(parameter, `${name} is missing`);
    assert.equal(parameter.in, "header", `${name} must be a header`);
    assert.equal(parameter.required, true, `${name} must be required`);
    assert.equal(parameter["x-cdnca-single-value"], true, `${name} must be single-valued`);
  }
  assert.equal(parameters.get("X-CDNCA-Callback-Version").schema.const, "1");
  assert.equal(parameters.get("X-CDNCA-Callback-Key-ID").schema.pattern, "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$");
  assert.equal(parameters.get("X-CDNCA-Callback-Timestamp").schema.pattern, "^(0|[1-9][0-9]{0,18})$");
  assert.equal(parameters.get("X-CDNCA-Callback-Signature").schema.pattern, "^v1=[A-Za-z0-9_-]{43}$");

  assert.equal(operation.requestBody.required, true);
  assert.equal(operation.requestBody["x-maxBodyBytes"], 262144);
  assert.deepEqual(Object.keys(operation.requestBody.content), ["application/json"]);
  const request = operation.requestBody.content["application/json"].schema;
  assert.equal(request.type, "object");
  assert.equal(request.additionalProperties, false);
  assert.deepEqual(request.required, [
    "version",
    "provider_account_id",
    "external_event_id",
    "external_payment_id",
    "event_kind",
    "amount_minor",
    "currency",
    "occurred_at",
  ]);
  assert.equal(request.properties.version.const, 1);
  assert.deepEqual(request.properties.event_kind.enum, [
    "payment_succeeded",
    "payment_failed",
    "refund_succeeded",
    "void_succeeded",
  ]);
  assert.equal(request.properties.amount_minor.minimum, 0);
  assert.equal(request.properties.amount_minor.maximum, 1000000000000000);
  assert.equal(request.properties.currency.const, "CNY");
  assert.equal(request.properties.occurred_at.format, "date-time");

  assert.match(operation.description, /HMAC-SHA256/i);
  assert.match(operation.description, /base64url-no-padding/i);
  assert.match(operation.description, /provider.*account.*key/i);
  assert.match(operation.description, /exact.*retries.*durable.*external_event_id.*payload/i);
  assert.doesNotMatch(operation.description, /nonce/i);
  assert.match(document.components.responses.CallbackUnauthorized.description, /single.*header.*JSON.*256 KiB.*commerce core was not invoked/is);
  assert.match(document.components.responses.CallbackUnavailable.description, /verification.*unavailable.*before.*core.*unknown.*after.*verified/is);
  assert.doesNotMatch(JSON.stringify(document), /secret_base64|KEYRING_JSON/);

  const catalogOperation = document.paths?.["/v1/package-commerce/catalog"]?.get;
  assert.ok(catalogOperation, "public package catalog GET operation is missing");
  assert.deepEqual(catalogOperation.security, [{bearerAuth: []}]);
  assert.deepEqual(catalogOperation["x-required-permissions"], ["package_subscriptions.read"]);
  const catalogParameterNames = catalogOperation.parameters.map((parameter) =>
    parameter.$ref
      ? document.components.parameters[parameter.$ref.split("/").at(-1)]?.name
      : parameter.name,
  );
  // BILL-13 (be-gap-1): optional group_id filter, bound to the signed cursor.
  assert.deepEqual(catalogParameterNames, ["kind", "group_id", "limit", "cursor"]);
  assert.equal(document.components.parameters.CatalogGroupID.required, false);
  assert.equal(document.components.parameters.CatalogKind.required, true);
  assert.equal(document.components.parameters.CatalogKind["x-cdnca-single-value"], true);
  assert.equal(document.components.parameters.CatalogKind.schema.const, "package");
  assert.equal(
    catalogOperation.responses["200"].$ref,
    "#/components/responses/CatalogPageOK",
  );

  const protection = document.components.schemas.PackageProtection;
  assert.equal(protection.type, "object");
  assert.equal(protection.additionalProperties, false);
  assert.deepEqual(protection.required, ["cc", "ddos"]);
  assert.equal(protection.properties.cc.maxLength, 256);
  assert.equal(protection.properties.ddos.maxLength, 256);

  const catalogItem = document.components.schemas.PackageCatalogItem;
  assert.equal(catalogItem.additionalProperties, false);
  assert.deepEqual(catalogItem.required, [
    "product_id",
    "product_revision",
    "name",
    "description",
    "limits",
    "protection",
    "prices",
    "purchase_policy",
    "commercial_terms",
  ]);
  assert.equal(
    catalogItem.properties.protection.$ref,
    "#/components/schemas/PackageProtection",
  );
  for (const name of [
    "PackageCatalogLimits",
    "PackageCatalogPrices",
    "PackageCatalogPurchasePolicy",
    "CatalogEligibility",
    "PackageCatalogPage",
  ]) {
    assert.equal(document.components.schemas[name].additionalProperties, false, `${name} must be strict`);
  }
  assert.deepEqual(document.components.schemas.PackageCatalogPage.required, ["items", "eligibility"]);
  assert.equal(document.components.schemas.PackageCatalogPage.properties.items.maxItems, 100);
  assert.deepEqual(document.components.schemas.CatalogEligibility.required, ["purchasable", "code"]);

  const order = document.components.schemas.Order;
  assert.equal(order.properties.protection.allOf[0].$ref, "#/components/schemas/PackageProtection");
  assert.equal(order.required.includes("protection"), false, "traffic orders keep protection optional");
  assert.deepEqual(order.allOf[0].if.properties.product_kind, {const: "package_subscription"});
  assert.deepEqual(order.allOf[0].then.required, ["protection"]);

  const subscription = document.components.schemas.Subscription;
  assert.equal(subscription.properties.product_name.type, "string");
  assert.equal(subscription.required.includes("product_name"), false);
  assert.equal(subscription.properties.product_name.minLength, undefined);
  assert.equal(subscription.properties.product_name.maxLength, undefined);
  assert.equal(subscription.required.includes("protection"), true);
  assert.equal(
    subscription.properties.protection.$ref,
    "#/components/schemas/PackageProtection",
  );

	for (const path of [
		"/v1/package-commerce/subscriptions",
		"/v1/admin/package-commerce/subscriptions",
	]) {
		const list = document.paths?.[path]?.get;
		assert.ok(list, `${path} GET is missing`);
		const names = new Set(list.parameters.map((parameter) => {
			if (!parameter.$ref) return parameter.name;
			const name = parameter.$ref.split("/").at(-1);
			return document.components.parameters[name]?.name;
		}));
		for (const name of ["status", "end_at_from", "end_at_to", "include_product_name"]) {
			assert.ok(names.has(name), `${path} omits ${name}`);
		}
	}
	assert.deepEqual(document.components.parameters.SubscriptionStatus.schema.enum, ["active", "expired", "cancelled"]);
	for (const path of [
		"/v1/package-commerce/orders",
		"/v1/admin/package-commerce/orders",
	]) {
		const list = document.paths?.[path]?.get;
		assert.ok(list, `${path} GET is missing`);
		const names = new Set(list.parameters.map((parameter) => {
			if (!parameter.$ref) return parameter.name;
			const name = parameter.$ref.split("/").at(-1);
			return document.components.parameters[name]?.name;
		}));
		assert.ok(names.has("product_kind"), `${path} omits product_kind`);
		assert.ok(names.has("state"), `${path} omits state`);
	}
	assert.deepEqual(document.components.parameters.OrderProductKind.schema.enum, ["package_subscription", "traffic_package"]);
	assert.deepEqual(document.components.parameters.OrderState.schema.enum, ["created", "paid", "fulfilled", "cancelled", "refund_applied", "void_applied", "failed"]);
	const productName = document.components.parameters.IncludeSubscriptionProductName;
	assert.deepEqual(productName.schema.enum, ["true", "false"]);
	assert.equal(productName.schema.default, "false");
	assert.equal(productName.required, false);
	assert.equal(productName["x-cdnca-single-value"], true);
	assert.match(productName.description, /immutable product_snapshot.name/);
	assert.match(productName.description, /legacy response shape/);
	assert.match(productName.description, /product catalog is never used/);
	assert.match(document.components.parameters.SubscriptionEndAtFrom.description, /inclusive/i);
	assert.match(document.components.parameters.SubscriptionEndAtTo.description, /exclusive/i);
} finally {
  rmSync(temporaryDirectory, {recursive: true, force: true});
}

console.log("package commerce provider callback OpenAPI contract: passed");
