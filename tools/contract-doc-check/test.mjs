#!/usr/bin/env node

import assert from "node:assert/strict";
import {cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

import {checkRepository} from "./check.mjs";

const toolRoot = dirname(fileURLToPath(import.meta.url));
const validRoot = join(toolRoot, "testdata", "valid");
const cases = JSON.parse(readFileSync(join(toolRoot, "testdata", "negative-cases.json"), "utf8"));

function fixtureRepository() {
  const temporary = mkdtempSync(join(tmpdir(), "cdnca-contract-doc-test-"));
  const root = join(temporary, "repo");
  cpSync(validRoot, root, {recursive: true});
  return {temporary, root};
}

function readJSON(root, path) {
  return JSON.parse(readFileSync(join(root, path), "utf8"));
}

function writeJSON(root, path, value) {
  writeFileSync(join(root, path), JSON.stringify(value, null, 2) + "\n");
}

function mutate(root, mutation) {
  const controlPath = "api/openapi/v1/control.json";
  const overlayPath = "api/openapi/v1/overlay.json";
  const manifestPath = "tests/contracts/plugin-manifest-v1.json";
  switch (mutation) {
    case "duplicate-operation": {
      const document = readJSON(root, controlPath);
      document.paths["/v1/widgets/{id}"].get.operationId = "createWidget";
      writeJSON(root, controlPath, document);
      return;
    }
    case "cross-operation": {
      const document = readJSON(root, overlayPath);
      document.paths["/v1/other"] = document.paths["/v1/widgets/{id}"];
      delete document.paths["/v1/widgets/{id}"];
      writeJSON(root, overlayPath, document);
      return;
    }
    case "missing-security": {
      const document = readJSON(root, controlPath);
      delete document.security;
      writeJSON(root, controlPath, document);
      return;
    }
    case "empty-permission": {
      const document = readJSON(root, controlPath);
      document.paths["/v1/widgets"].post["x-required-permissions"] = [];
      writeJSON(root, controlPath, document);
      return;
    }
    case "permission-marker-without-403": {
      const document = readJSON(root, controlPath);
      document.paths["/v1/widgets"].post.responses["401"] = document.paths["/v1/widgets"].post.responses["403"];
      delete document.paths["/v1/widgets"].post.responses["403"];
      writeJSON(root, controlPath, document);
      return;
    }
    case "secured-operation-without-denial": {
      const document = readJSON(root, controlPath);
      delete document.paths["/v1/widgets/{id}"].get.responses["403"];
      writeJSON(root, controlPath, document);
      return;
    }
    case "missing-idempotency-conflict": {
      const document = readJSON(root, controlPath);
      delete document.paths["/v1/widgets"].post.responses["409"];
      writeJSON(root, controlPath, document);
      return;
    }
    case "optional-idempotency-key": {
      const document = readJSON(root, controlPath);
      document.components.parameters.IdempotencyKey.required = false;
      writeJSON(root, controlPath, document);
      return;
    }
    case "missing-idempotency-lengths": {
      const document = readJSON(root, controlPath);
      delete document.components.parameters.IdempotencyKey.schema.minLength;
      delete document.components.parameters.IdempotencyKey.schema.maxLength;
      writeJSON(root, controlPath, document);
      return;
    }
    case "misleading-idempotency-pattern": {
      const document = readJSON(root, controlPath);
      document.components.parameters.IdempotencyKey.schema.pattern = "^a{2,127}$";
      writeJSON(root, controlPath, document);
      return;
    }
    case "pattern-removes-idempotency-minimum": {
      const document = readJSON(root, controlPath);
      document.components.parameters.IdempotencyKey.schema.pattern = "^a{2,128}$";
      writeJSON(root, controlPath, document);
      return;
    }
    case "pattern-removes-idempotency-maximum": {
      const document = readJSON(root, controlPath);
      document.components.parameters.IdempotencyKey.schema.pattern = "^a{1,127}$";
      writeJSON(root, controlPath, document);
      return;
    }
    case "wrong-idempotency-minimum": {
      const document = readJSON(root, controlPath);
      document.components.parameters.IdempotencyKey.schema.minLength = 2;
      writeJSON(root, controlPath, document);
      return;
    }
    case "short-idempotency-maximum": {
      const document = readJSON(root, controlPath);
      document.components.parameters.IdempotencyKey.schema.maxLength = 127;
      writeJSON(root, controlPath, document);
      return;
    }
    case "long-idempotency-maximum": {
      const document = readJSON(root, controlPath);
      document.components.parameters.IdempotencyKey.schema.maxLength = 129;
      writeJSON(root, controlPath, document);
      return;
    }
    case "operation-parameter-override": {
      const document = readJSON(root, controlPath);
      document.paths["/v1/widgets"].parameters = [{
        name: "IDEMPOTENCY-KEY",
        in: "header",
        required: true,
        schema: {type: "string", minLength: 1, maxLength: 128}
      }];
      document.paths["/v1/widgets"].post.parameters = [{
        name: "idempotency-key",
        in: "header",
        required: false,
        schema: {type: "string", minLength: 1, maxLength: 128}
      }];
      writeJSON(root, controlPath, document);
      return;
    }
    case "idempotency-pattern-boundaries": {
      const document = readJSON(root, controlPath);
      document.components.parameters.IdempotencyKey.schema.pattern = "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$";
      writeJSON(root, controlPath, document);
      return;
    }
    case "redirect-without-idempotency-conflict": {
      const document = readJSON(root, controlPath);
      document.paths["/v1/widgets"].post.responses["302"] = {description: "Redirected"};
      delete document.paths["/v1/widgets"].post.responses["201"];
      delete document.paths["/v1/widgets"].post.responses["409"];
      writeJSON(root, controlPath, document);
      return;
    }
    case "fail-closed-idempotency": {
      const document = readJSON(root, controlPath);
      delete document.paths["/v1/widgets"].post.responses["201"];
      delete document.paths["/v1/widgets"].post.responses["409"];
      writeJSON(root, controlPath, document);
      return;
    }
    case "secured-operation-with-401": {
      const document = readJSON(root, controlPath);
      document.paths["/v1/widgets/{id}"].get.responses["401"] = document.paths["/v1/widgets/{id}"].get.responses["403"];
      delete document.paths["/v1/widgets/{id}"].get.responses["403"];
      writeJSON(root, controlPath, document);
      return;
    }
    case "auth-session-denial-exception": {
      const document = readJSON(root, controlPath);
      document.paths["/v1/auth/logout"] = {
        post: {
          operationId: "logout",
          responses: {"204": {description: "Logged out"}}
        }
      };
      document.paths["/v1/session/refresh"] = {
        post: {
          operationId: "refreshSession",
          responses: {"204": {description: "Refreshed"}}
        }
      };
      writeJSON(root, controlPath, document);
      return;
    }
    case "unstable-error": {
      const document = readJSON(root, controlPath);
      delete document.components.schemas.Error.properties.code;
      writeJSON(root, controlPath, document);
      return;
    }
    case "invalid-example": {
      const document = readJSON(root, controlPath);
      document.paths["/v1/widgets"].post.requestBody.content["application/json"].example.name = 7;
      writeJSON(root, controlPath, document);
      return;
    }
    case "unknown-proto-method": {
      const path = join(root, "docs/developer/grpc.md");
      writeFileSync(path, readFileSync(path, "utf8").replace('methods="GetWidget"', 'methods="MissingMethod"'));
      return;
    }
    case "missing-link": {
      const path = join(root, "docs/developer/README.md");
      writeFileSync(path, readFileSync(path, "utf8") + "\n[missing](missing.md)\n");
      return;
    }
    case "plugin-schema": {
      const manifest = readJSON(root, manifestPath);
      manifest.metadata.id = 7;
      writeJSON(root, manifestPath, manifest);
      return;
    }
    case "plugin-signature": {
      const manifest = readJSON(root, manifestPath);
      manifest.integrity.signature = "AM5YeKrE5vG_lw3Q-d7zyLuFpJU4LGHBzv0hweZ3FTPX5kheKMbWoEFX2muAJ3pAqMVZRC3Fjs_bkahFRPBLDw";
      writeJSON(root, manifestPath, manifest);
      return;
    }
    case "webhook-signature": {
      const path = "docs/developer/examples/webhook-signature-v1.json";
      const vector = readJSON(root, path);
      vector.signature = "v1=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      writeJSON(root, path, vector);
      return;
    }
    case "deprecated-operation": {
      const document = readJSON(root, controlPath);
      document.paths["/v1/widgets"].post.deprecated = true;
      writeJSON(root, controlPath, document);
      return;
    }
    case "policy-drift": {
      const path = "docs/developer/contract-policy.json";
      const policy = readJSON(root, path);
      policy.status = "draft";
      writeJSON(root, path, policy);
      return;
    }
    default:
      throw new Error(`unknown mutation: ${mutation}`);
  }
}

function withFixture(callback) {
  const fixture = fixtureRepository();
  try {
    return callback(fixture.root);
  } finally {
    rmSync(fixture.temporary, {recursive: true, force: true});
  }
}

withFixture((root) => {
  const result = checkRepository(root, {runMarketplace: false});
  assert.deepEqual(result.errors, [], `valid fixture failed:\n${result.errors.join("\n")}`);
});

for (const mutation of ["fail-closed-idempotency", "secured-operation-with-401", "auth-session-denial-exception", "idempotency-pattern-boundaries"]) {
  withFixture((root) => {
    mutate(root, mutation);
    const result = checkRepository(root, {runMarketplace: false});
    assert.deepEqual(result.errors, [], `${mutation}: valid boundary fixture failed:\n${result.errors.join("\n")}`);
  });
}

const plainText = {schema: {type: "string", const: "unauthorized\n"}};
const stableJSON = {schema: {$ref: "#/components/schemas/Error"}};
const invalidJSON = {schema: {type: "object", properties: {code: {type: "string"}}}};
const errorMediaCases = [
  {name: "explicit plain-text error", content: {"text/plain": plainText}},
  {name: "mixed JSON and plain-text error", content: {"application/json": stableJSON, "text/plain": plainText}},
  {name: "vendor JSON error", content: {"application/vnd.cdnca.error+json": stableJSON}},
  {name: "missing error content", invalid: true},
  {name: "empty error content", content: {}, invalid: true},
  {name: "plain-text error without schema", content: {"text/plain": {}}, invalid: true},
  {name: "wildcard error media", content: {"*/*": plainText}, invalid: true},
  {name: "mixed unstable JSON error", content: {"text/plain": plainText, "application/json": invalidJSON}, invalid: true},
  {name: "mixed unstable problem JSON", content: {"application/json": stableJSON, "application/problem+json": invalidJSON}, invalid: true},
  {name: "unstable vendor JSON error", content: {"application/vnd.cdnca.error+json": invalidJSON}, invalid: true},
  {name: "unresolved plain-text schema", content: {"text/plain": {schema: {$ref: "#/components/schemas/Missing"}}}, invalid: true}
];
for (const testCase of errorMediaCases) {
  withFixture((root) => {
    const document = readJSON(root, "api/openapi/v1/control.json");
    document.components.responses.Forbidden = {description: "Permission denied", content: testCase.content};
    writeJSON(root, "api/openapi/v1/control.json", document);
    const result = checkRepository(root, {runMarketplace: false});
    const expected = testCase.invalid ? [
      "api/openapi/v1/control.json#/paths/~1v1~1widgets/post/responses/403: error response must expose stable code and request_id fields",
      "api/openapi/v1/control.json#/paths/~1v1~1widgets~1{id}/get/responses/403: error response must expose stable code and request_id fields"
    ] : [];
    assert.deepEqual(result.errors, expected, `${testCase.name}: unexpected error-media validation result`);
  });
}

for (const testCase of cases) {
  withFixture((root) => {
    mutate(root, testCase.mutation);
    const result = checkRepository(root, {runMarketplace: false});
    const expected = Array.isArray(testCase.expected) ? testCase.expected : [testCase.expected];
    const allowed = testCase.allowed ?? expected;
    for (const diagnostic of expected) {
      assert.equal(
        result.errors.some((error) => error.includes(diagnostic)),
        true,
        `${testCase.name}: expected diagnostic containing:\n${diagnostic}\nactual:\n${result.errors.join("\n")}`
      );
    }
    for (const diagnostic of result.errors) {
      assert.equal(
        allowed.some((fragment) => diagnostic.includes(fragment)),
        true,
        `${testCase.name}: unexpected diagnostic outside allowlist:\n${diagnostic}\nallowed:\n${allowed.join("\n")}`
      );
    }
  });
}

console.log(`contract-doc-check tests: 5 valid fixtures, ${cases.length} negative fixtures, and ${errorMediaCases.length} error-media fixtures passed`);
