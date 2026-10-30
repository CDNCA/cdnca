import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const apiDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(apiDir, "..");
const canonicalPath = join(apiDir, "openapi/v1/control.yaml");
const dedicatedPath = join(apiDir, "control-api-keys.openapi.yaml");
const server = readFileSync(join(root, "services/control-api/internal/httpapi/server.go"), "utf8");
const handlers = readFileSync(join(root, "services/control-api/internal/httpapi/api_keys.go"), "utf8");

const operations = [
  ["GET", "/v1/account/api-keys", "listSelfAPIKeys", "200", "APIKeyList"],
  ["POST", "/v1/account/api-keys", "createSelfAPIKey", "201", "IssuedAPIKey", "CollectionIfMatch"],
  ["GET", "/v1/account/api-keys/{key_id}", "getSelfAPIKey", "200", "APIKey"],
  ["PATCH", "/v1/account/api-keys/{key_id}", "updateSelfAPIKey", "200", "APIKey", "IfMatch"],
  ["POST", "/v1/account/api-keys/{key_id}/activate", "activateSelfAPIKey", "200", "IssuedAPIKey", "IfMatch"],
  ["POST", "/v1/account/api-keys/{key_id}/rotate", "rotateSelfAPIKey", "200", "IssuedAPIKey", "IfMatch"],
  ["POST", "/v1/account/api-keys/{key_id}/revoke", "revokeSelfAPIKey", "200", "APIKey", "IfMatch"],
  ["GET", "/v1/admin/users/{user_id}/api-keys", "listManagedUserAPIKeys", "200", "APIKeyList"],
  ["POST", "/v1/admin/users/{user_id}/api-keys", "createPendingManagedUserAPIKey", "201", "APIKey", "CollectionIfMatch"],
  ["POST", "/v1/admin/users/{user_id}/api-keys/{key_id}/revoke", "revokeManagedUserAPIKey", "200", "APIKey", "IfMatch"],
];

for (const [method, path] of operations) {
  assert.ok(server.includes(`mux.HandleFunc("${method} ${path}",`), `real route missing: ${method} ${path}`);
}
assert.ok(handlers.includes("s.authenticatedSessionPrincipal(r)"), "API key management must authenticate a bearer session");
assert.ok(!handlers.includes("s.authenticatedPrincipal(r)"), "API key management must reject CdncaKey credentials");
assert.equal((handlers.match(/Header\(\)\.Set\("Cache-Control", "no-store"\)/g) ?? []).length, 2,
  "create, activate, and rotate share two issuance paths that must set no-store");
assert.ok(handlers.includes("parseAPIKeyListRawQuery(r.URL.RawQuery)"),
  "self API key list route must use strict query parsing");
assert.ok(handlers.includes("parseAPIKeyListRawQuery(listQuery)"),
  "admin API key list route must remove only its required tenant scope before strict query parsing");
assert.ok(handlers.includes("s.apiKeys.ListSelfPage(r.Context(), principal, input)"),
  "self list route must use bounded cursor pagination");
assert.ok(handlers.includes("s.apiKeys.AdminListPage(r.Context(), principal, targetScopeID, targetUserID, input)"),
  "admin list route must use bounded cursor pagination");
assert.ok(!handlers.includes("s.apiKeys.ListSelf(r.Context(), principal)"), "self HTTP list must not drain every page");
assert.ok(!handlers.includes("s.apiKeys.AdminList(r.Context(), principal, targetScopeID, targetUserID)"), "admin HTTP list must not drain every page");

const temporaryDir = mkdtempSync(join(tmpdir(), "cdnca-api-key-openapi-"));
const bundlePath = join(temporaryDir, "control.json");
const dedicatedBundlePath = join(temporaryDir, "api-keys.json");
try {
  execFileSync(
    "pnpm",
    ["--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle", canonicalPath, "--output", bundlePath],
    {cwd: root, stdio: "pipe"},
  );
  execFileSync(
    "pnpm",
    ["--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle", dedicatedPath, "--output", dedicatedBundlePath],
    {cwd: root, stdio: "pipe"},
  );
  const document = JSON.parse(readFileSync(bundlePath, "utf8"));
  const dedicatedDocument = JSON.parse(readFileSync(dedicatedBundlePath, "utf8"));

  for (const [method, path, operationId, successStatus, schemaName, revisionParameter] of operations) {
    const pathItem = document.paths?.[path];
    const operation = pathItem?.[method.toLowerCase()];
    assert.ok(operation, `canonical operation missing: ${method} ${path}`);
    assert.equal(operation.operationId, operationId, `${method} ${path} operationId drifted`);
    assert.deepEqual(operation.security, [{bearerAuth: []}], `${operationId} must remain session-only`);
    assert.ok(operation.responses?.["401"] && operation.responses?.["403"], `${operationId} must expose auth failures`);
    assert.equal(
      operation.responses?.[successStatus]?.content?.["application/json"]?.schema?.$ref,
      `#/components/schemas/${schemaName}`,
      `${operationId} success schema drifted`,
    );
    if (revisionParameter) {
      const parameterRefs = [...(pathItem.parameters ?? []), ...(operation.parameters ?? [])]
        .map((parameter) => parameter.$ref);
      assert.ok(parameterRefs.includes("#/components/parameters/IdempotencyKey"), `${operationId} needs idempotency`);
      assert.ok(parameterRefs.includes(`#/components/parameters/${revisionParameter}`), `${operationId} needs revision control`);
      assert.ok(operation.responses?.["400"] && operation.responses?.["409"], `${operationId} must expose write conflicts`);
    }
  }

  const metadata = document.components?.schemas?.APIKey;
  assert.equal(metadata?.additionalProperties, false);
  assert.ok(!("secret" in (metadata?.properties ?? {})), "metadata responses must never expose a secret");
  assert.ok(metadata?.required?.includes("revision"));
  assert.equal(metadata?.properties?.revision?.minimum, 1);

  const list = document.components?.schemas?.APIKeyList;
  assert.equal(list?.additionalProperties, false);

  for (const path of ["/v1/account/api-keys", "/v1/admin/users/{user_id}/api-keys"]) {
    const operation = dedicatedDocument.paths?.[path]?.get;
    const parameterRefs = (operation?.parameters ?? []).map((parameter) => parameter.$ref);
    assert.deepEqual(parameterRefs, [
      "#/components/parameters/ListLimit",
      "#/components/parameters/APIKeyStatusFilter",
      "#/components/parameters/APIKeyNameFilter",
      "#/components/parameters/APIKeyIDFilter",
      "#/components/parameters/ListCursor",
      "#/components/parameters/ListOffset",
    ]);
    assert.ok(operation?.responses?.["400"], `${path} must expose invalid query/cursor errors`);
    assert.match(operation?.description ?? "", /safe to retry/i, `${path} must document read-only retry safety`);
  }

  const parameters = dedicatedDocument.components?.parameters;
  for (const path of ["/v1/admin/users/{user_id}/api-keys", "/v1/admin/users/{user_id}/api-keys/{key_id}/revoke"]) {
    const refs = (dedicatedDocument.paths?.[path]?.parameters ?? []).map((parameter) => parameter.$ref);
    assert.ok(refs.includes("#/components/parameters/TenantScopeID"), `${path} requires explicit tenant scope`);
  }
  assert.equal(parameters?.ListLimit?.schema?.default, 50);
  assert.equal(parameters?.ListLimit?.schema?.minimum, 1);
  assert.equal(parameters?.ListLimit?.schema?.maximum, 100);
  assert.equal(parameters?.ListCursor?.schema?.maxLength, 4096);
  assert.equal(parameters?.ListOffset?.schema?.minimum, 0);
  assert.equal(parameters?.ListOffset?.schema?.maximum, 10000);
  assert.equal(parameters?.APIKeyStatusFilter?.schema?.$ref, "#/components/schemas/APIKeyStatus");
  assert.deepEqual(dedicatedDocument.components?.schemas?.APIKeyStatus?.enum, ["pending_activation", "active", "revoked"]);
  assert.equal(parameters?.APIKeyNameFilter?.schema?.maxLength, 128);
  assert.equal(parameters?.APIKeyIDFilter?.schema?.pattern, "^cfk_[A-Za-z0-9_-]{22}$");

  const dedicatedList = dedicatedDocument.components?.schemas?.APIKeyList;
  assert.equal(dedicatedList?.additionalProperties, false);
  assert.deepEqual(dedicatedList?.required, ["items", "next_cursor", "has_more"]);
  assert.equal(dedicatedList?.properties?.items?.maxItems, 100);
  assert.equal(dedicatedList?.properties?.next_cursor?.maxLength, 4096);
  assert.equal(dedicatedList?.properties?.has_more?.type, "boolean");
  assert.equal(dedicatedList?.properties?.total?.type, "integer");
  const errorParams = dedicatedDocument.components?.schemas?.ErrorParams?.properties ?? {};
  for (const forbidden of ["secret", "matched_prefix", "matched_key_prefix"]) {
    assert.ok(!(forbidden in errorParams), `error params must not expose ${forbidden}`);
  }

  const issuance = document.components?.schemas?.IssuedAPIKey;
  assert.equal(issuance?.additionalProperties, false);
  assert.deepEqual(issuance?.required, ["key", "secret"]);
  assert.equal(issuance?.properties?.secret?.writeOnly, true);
  assert.equal(issuance?.properties?.secret?.format, "password");
  assert.equal(issuance?.properties?.secret?.pattern, "^[A-Za-z0-9_-]{43}$");

  const fields = document.components?.schemas?.APIKeyFieldsRequest;
  assert.deepEqual(fields?.required, ["name", "scopes"]);
  assert.notEqual(fields?.properties?.expires_at?.nullable, true);
  assert.equal(document.components?.securitySchemes?.cdncaApiKey?.type, "apiKey");
  assert.match(document.components?.securitySchemes?.cdncaApiKey?.description ?? "", /live intersection/);
} finally {
  rmSync(temporaryDir, {recursive: true, force: true});
}

console.log(`API key OpenAPI contract: passed (${operations.length} operations)`);
