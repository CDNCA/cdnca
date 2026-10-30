#!/usr/bin/env node

import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from "node:fs";
import {tmpdir} from "node:os";
import {delimiter, dirname, join, resolve} from "node:path";
import {spawnSync} from "node:child_process";
import test from "node:test";
import {fileURLToPath} from "node:url";

import {
  collectOpenAPIOperations,
  collectReferenceClosure,
  loadOpenAPIDocuments,
  renderOpenAPIIndex,
  renderReadmeCounts,
  replaceGeneratedRegion,
  updateDocumentation
} from "./openapi-index.mjs";

const toolRoot = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(toolRoot, "../..");
const toolPath = join(toolRoot, "openapi-index.mjs");
const legacyMissingOperationIDs = [
  "listCertificateAssets",
  "uploadCertificateAsset",
  "getCertificateAsset",
  "deleteCertificateAsset",
  "activateCertificateAssetVersion",
  "listCertificateAssetBindings",
  "bindCertificateAsset",
  "unbindCertificateAsset",
  "createSecurityPolicyActivation",
  "getSecurityPolicyActivation",
  "reconcileSecurityPolicyActivation",
  "rollbackSecurityPolicyActivation",
  "changeLicensingCustomerStatus",
  "archiveAnnouncement",
  "restoreAnnouncement",
  "listSystemBackupRuns"
];

function hash(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function openapi(paths, version = "0.1.0") {
  return {openapi: "3.1.0", info: {title: "Fixture", version}, paths};
}

function operation(operationId) {
  return {operationId, responses: {"200": {description: "OK"}}};
}

function writeJSON(path, value) {
  mkdirSync(dirname(path), {recursive: true});
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n");
}

function fixtureRepository() {
  const root = mkdtempSync(join(tmpdir(), "cdnca-openapi-index-test-"));
  writeJSON(join(root, "api/openapi/v1/control.json"), openapi({
    "/v1/items": {get: operation("listItems"), post: operation("createItem")}
  }));
  writeJSON(join(root, "api/openapi/v1/dns-acme.json"), openapi({
    "/v1/items": {get: operation("listItems")}
  }));
  writeJSON(join(root, "api/openapi/v1/license.json"), openapi({
    "/operator/v1/items": {post: operation("createLicensedItem")}
  }, "0.8.0"));
  writeJSON(join(root, "api/openapi/v1/sites.json"), openapi({
    "/v1/sites": {get: operation("listSites")}
  }));
  mkdirSync(join(root, "docs/api"), {recursive: true});
  writeFileSync(join(root, "docs/api/openapi-index.md"), [
    "# OpenAPI operation 索引",
    "",
    "manual-before",
    "<!-- generated:openapi-index:begin -->",
    "stale",
    "<!-- generated:openapi-index:end -->",
    "manual-after",
    ""
  ].join("\n"));
  writeFileSync(join(root, "docs/api/README.md"), [
    "# API 文档",
    "",
    "manual-before",
    "<!-- generated:openapi-counts:begin -->",
    "stale",
    "<!-- generated:openapi-counts:end -->",
    "manual-after",
    ""
  ].join("\n"));
  return root;
}

function fakeGateEnvironment() {
  const root = mkdtempSync(join(tmpdir(), "cdnca-openapi-gate-test-"));
  const bin = join(root, "bin");
  const log = join(root, "commands.log");
  const executable = join(bin, "fake-command");
  mkdirSync(bin, {recursive: true});
  writeFileSync(executable, [
    "#!/bin/sh",
    "name=${0##*/}",
    "if [ \"$name\" = pnpm ] && [ \"${1:-}\" = --version ]; then",
    "  printf '10.15.0\\n'",
    "  exit 0",
    "fi",
    "if [ \"$name\" = buf ] && [ \"${1:-}\" = --version ]; then",
    "  printf '1.47.2\\n'",
    "  exit 0",
    "fi",
    "{",
    "  printf '%s' \"$name\"",
    "  for argument in \"$@\"; do printf ' <%s>' \"$argument\"; done",
    "  printf '\\n'",
    "} >> \"$GATE_LOG\"",
    "if [ -n \"${GATE_FAIL_MATCH:-}\" ]; then",
    "  case \"$*\" in",
    "    *\"$GATE_FAIL_MATCH\"*) exit \"${GATE_FAIL_CODE:-41}\" ;;",
    "  esac",
    "fi",
    ""
  ].join("\n"));
  chmodSync(executable, 0o755);
  for (const command of ["buf", "go", "node", "pnpm", "sha256sum"]) {
    symlinkSync(executable, join(bin, command));
  }
  return {
    root,
    log,
    env: {...process.env, GATE_LOG: log, PATH: `${bin}${delimiter}${process.env.PATH}`}
  };
}

function runGate(script, args, fixture, failure = {}) {
  writeFileSync(fixture.log, "");
  const result = spawnSync("bash", [script, ...args], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: {
      ...fixture.env,
      GATE_FAIL_MATCH: failure.match ?? "",
      GATE_FAIL_CODE: String(failure.code ?? 41)
    }
  });
  return {result, commands: readFileSync(fixture.log, "utf8").trim().split("\n").filter(Boolean)};
}

test("collects direct operations, dual methods, and one compatible cross-document overlap", () => {
  const documents = [
    {contract: "control.yaml", version: "0.1.0", document: openapi({
      "/v1/items": {get: operation("listItems"), post: operation("createItem")}
    })},
    {contract: "overlay.yaml", version: "0.1.0", document: openapi({
      "/v1/items": {get: operation("listItems")}
    })}
  ];
  const result = collectOpenAPIOperations(documents);
  assert.equal(result.operations.length, 3);
  assert.equal(result.distinctTupleCount, 2);
  assert.deepEqual(result.overlaps, [{
    method: "GET",
    route: "/v1/items",
    operationId: "listItems",
    contracts: ["control.yaml", "overlay.yaml"]
  }]);
  assert.deepEqual(result.operations.map(({method}) => method), ["GET", "POST", "GET"]);
});

test("sorts paths bytewise independently of source insertion order", () => {
  const forward = collectOpenAPIOperations([{
    contract: "control.yaml",
    document: openapi({
      "/v1/z": {get: operation("getZ")},
      "/v1/a": {get: operation("getA")}
    })
  }]);
  const reverse = collectOpenAPIOperations([{
    contract: "control.yaml",
    document: openapi({
      "/v1/a": {get: operation("getA")},
      "/v1/z": {get: operation("getZ")}
    })
  }]);
  assert.deepEqual(forward, reverse);
  assert.deepEqual(forward.operations.map(({route}) => route), ["/v1/a", "/v1/z"]);
  assert.equal(renderOpenAPIIndex(forward), renderOpenAPIIndex(reverse));
});

test("uses the UTF-8 comparator for non-ASCII paths, operationIds, and overlaps", async () => {
  const {compareBytes} = await import("./openapi-index.mjs");
  assert.equal(typeof compareBytes, "function");
  const supplementaryPath = "/v1/\u{10000}";
  const bmpPath = "/v1/\uE000";
  const supplementaryOperationID = "get\u{10000}";
  const bmpOperationID = "get\uE000";
  const originalLocaleCompare = String.prototype.localeCompare;
  String.prototype.localeCompare = () => {
    throw new Error("localeCompare must not be used");
  };
  try {
    assert.deepEqual([supplementaryPath, bmpPath].sort(compareBytes), [bmpPath, supplementaryPath]);
    assert.deepEqual(
      [supplementaryOperationID, bmpOperationID].sort(compareBytes),
      [bmpOperationID, supplementaryOperationID]
    );
    const result = collectOpenAPIOperations([
      {contract: "control.yaml", document: openapi({
        [supplementaryPath]: {get: operation(supplementaryOperationID)},
        [bmpPath]: {get: operation(bmpOperationID)}
      })},
      {contract: "overlay.yaml", document: openapi({
        [bmpPath]: {get: operation(bmpOperationID)},
        [supplementaryPath]: {get: operation(supplementaryOperationID)}
      })}
    ]);
    assert.deepEqual(result.operations.map(({route}) => route), [
      bmpPath,
      supplementaryPath,
      bmpPath,
      supplementaryPath
    ]);
    assert.deepEqual(
      result.overlaps.map(({route, operationId}) => ({route, operationId})),
      [
        {route: bmpPath, operationId: bmpOperationID},
        {route: supplementaryPath, operationId: supplementaryOperationID}
      ]
    );
  } finally {
    String.prototype.localeCompare = originalLocaleCompare;
  }
});

test("fails closed on missing, duplicate, and conflicting operationId values", () => {
  assert.throws(() => collectOpenAPIOperations([{contract: "a.json", document: openapi({
    "/missing": {get: {responses: {"200": {description: "OK"}}}}
  })}]), /missing operationId/);
  assert.throws(() => collectOpenAPIOperations([{contract: "a.json", document: openapi({
    "/one": {get: operation("same")},
    "/two": {get: operation("same")}
  })}]), /duplicate operationId/);
  assert.throws(() => collectOpenAPIOperations([
    {contract: "a.json", document: openapi({"/one": {get: operation("same")}})},
    {contract: "b.json", document: openapi({"/two": {post: operation("same")}})}
  ]), /conflicting operationId/);
  assert.throws(() => collectOpenAPIOperations([
    {contract: "a.json", document: openapi({"/same": {get: operation("one")}})},
    {contract: "b.json", document: openapi({"/same": {get: operation("two")}})}
  ]), /conflicting wire operation/);
});

test("parses quoted YAML ref keys without treating comments or block scalars as refs", () => {
  const root = mkdtempSync(join(tmpdir(), "cdnca-openapi-ref-test-"));
  try {
    const source = join(root, "api/openapi/v1/control.yaml");
    const fragment = join(root, "api/fragment.yaml");
    mkdirSync(dirname(source), {recursive: true});
    writeFileSync(source, [
      "openapi: 3.1.0",
      "info: {title: Fixture, version: 0.1.0}",
      "description: |",
      "  $ref: '../../../../block-scalar-is-not-a-ref.yaml'",
      "# $ref: '../../../../comment-is-not-a-ref.yaml'",
      "paths:",
      "  /v1/items~details:",
      "    '$ref': '../../fragment.yaml#/paths/~1v1~1items~0details'",
      ""
    ].join("\n"));
    writeFileSync(fragment, [
      "paths:",
      "  /v1/items~details:",
      "    get:",
      "      operationId: getItemDetails",
      ""
    ].join("\n"));
    assert.deepEqual(
      collectReferenceClosure(root, [source]),
      [realpathSync(source), realpathSync(fragment)].sort()
    );

    writeFileSync(source, "paths:\n  /x:\n    '$ref': '../../../../outside.yaml#/paths/~1x'\n");
    assert.throws(() => collectReferenceClosure(root, [source]), /escapes repository/);
  } finally {
    rmSync(root, {recursive: true, force: true});
  }
});

test("parses YAML across stdin chunk boundaries without losing references", () => {
  const root = mkdtempSync(join(tmpdir(), "cdnca-openapi-ref-test-"));
  try {
    const source = join(root, "control.yaml");
    const fragment = join(root, "fragment.yaml");
    // yaml@2.8.1's streaming CLI misparses the key after this 64 KiB boundary.
    writeFileSync(source, "#" + "x".repeat(65525) + "\nschema:\n  type: string\n  minLength: 1\n" +
      "description: 中文字段\npaths:\n  /items:\n    $ref: './fragment.yaml#/paths/~1items'\n");
    writeFileSync(fragment, "paths:\n  /items:\n    get:\n      operationId: listItems\n");
    assert.deepEqual(
      collectReferenceClosure(root, [source]),
      [realpathSync(source), realpathSync(fragment)].sort()
    );
  } finally {
    rmSync(root, {recursive: true, force: true});
  }
});

test("rejects malformed, duplicate-key, multiple-document, and empty YAML inputs", () => {
  const root = mkdtempSync(join(tmpdir(), "cdnca-openapi-ref-test-"));
  try {
    const source = join(root, "control.yaml");
    for (const input of [
      "schema:\n  type: string\n   invalid: nested\n",
      "paths: {}\npaths: {}\n",
      "paths: [\n",
      "paths: {}\n---\npaths: {}\n",
      "# empty document\n",
      "paths: *missing\n",
      "#" + "x".repeat(65525) + "\nschema:\n  type: string\n   invalid: nested\n"
    ]) {
      writeFileSync(source, input);
      assert.throws(() => collectReferenceClosure(root, [source]), /invalid YAML/);
    }
  } finally {
    rmSync(root, {recursive: true, force: true});
  }
});

test("handles transitive refs and cycles and rejects symlink realpath escapes", () => {
  const root = mkdtempSync(join(tmpdir(), "cdnca-openapi-ref-test-"));
  const outsideRoot = mkdtempSync(join(tmpdir(), "cdnca-openapi-outside-test-"));
  try {
    const source = join(root, "api/openapi/v1/control.yaml");
    const fragment = join(root, "api/fragment.yaml");
    const shared = join(root, "api/shared.yaml");
    const outside = join(outsideRoot, "outside.yaml");
    mkdirSync(dirname(source), {recursive: true});
    writeFileSync(source, "paths:\n  /x:\n    $ref: '../../fragment.yaml#/paths/~1x'\n");
    writeFileSync(fragment, "paths:\n  /x:\n    $ref: './shared.yaml#/paths/~1x'\n");
    writeFileSync(shared, "paths:\n  /x:\n    $ref: './openapi/v1/control.yaml#/paths/~1x'\n");
    assert.deepEqual(
      collectReferenceClosure(root, [source]),
      [realpathSync(source), realpathSync(fragment), realpathSync(shared)].sort()
    );

    writeFileSync(outside, "paths: {}\n");
    symlinkSync(outside, join(root, "api/escaped.yaml"));
    writeFileSync(source, "paths:\n  /x:\n    $ref: '../../escaped.yaml#/paths/~1x'\n");
    assert.throws(() => collectReferenceClosure(root, [source]), /realpath escapes repository/);

    writeFileSync(source, "paths:\n  /x:\n    $ref: '../../../../outside.yaml#/paths/~1x'\n");
    assert.throws(() => collectReferenceClosure(root, [source]), /escapes repository/);
    writeFileSync(source, "paths:\n  /x:\n    $ref: '../../missing.yaml#/paths/~1x'\n");
    assert.throws(() => collectReferenceClosure(root, [source]), /does not exist/);
    writeFileSync(source, "paths:\n  /x:\n    $ref: '../../fragment.yaml#/paths/~2x'\n");
    assert.throws(() => collectReferenceClosure(root, [source]), /invalid JSON Pointer escape/);
  } finally {
    rmSync(root, {recursive: true, force: true});
    rmSync(outsideRoot, {recursive: true, force: true});
  }
});

test("rejects unresolved internal JSON pointers in root contracts", async () => {
  const root = fixtureRepository();
  try {
    writeJSON(join(root, "api/openapi/v1/control.json"), openapi({
      "/v1/items": {
        get: {
          ...operation("listItems"),
          responses: {
            "200": {
              description: "OK",
              content: {"application/json": {schema: {$ref: "#/components/schemas/Missing"}}}
            }
          }
        }
      }
    }));
    await assert.rejects(loadOpenAPIDocuments(root), /Redocly bundle failed/);
  } finally {
    rmSync(root, {recursive: true, force: true});
  }
});

test("rejects unresolved internal YAML pointers in root contracts", async () => {
  const root = fixtureRepository();
  try {
    rmSync(join(root, "api/openapi/v1/control.json"));
    writeFileSync(join(root, "api/openapi/v1/control.yaml"), [
      "openapi: 3.1.0",
      "info: {title: Fixture, version: 0.1.0}",
      "paths:",
      "  /v1/items:",
      "    get:",
      "      operationId: listItems",
      "      responses:",
      "        '200':",
      "          description: OK",
      "          content:",
      "            application/json:",
      "              schema:",
      "                $ref: '#/components/schemas/Missing'",
      ""
    ].join("\n"));
    await assert.rejects(loadOpenAPIDocuments(root), /Redocly bundle failed/);
  } finally {
    rmSync(root, {recursive: true, force: true});
  }
});

test("observes authoritative shell gate ordering, arguments, short-circuiting, and target isolation", () => {
  const fixture = fakeGateEnvironment();
  const ci = join(repositoryRoot, "scripts/ci-check.sh");
  const contractDocs = join(repositoryRoot, "scripts/check-contract-docs.sh");
  const ciTest = "node <tools/contract-doc-check/openapi-index.test.mjs>";
  const ciCheck = "node <tools/contract-doc-check/openapi-index.mjs> <--check>";
  const docsTest = `node <${join(repositoryRoot, "tools/contract-doc-check/openapi-index.test.mjs")}>`;
  const docsCheck = `node <${join(repositoryRoot, "tools/contract-doc-check/openapi-index.mjs")}> <--repo-root> <${repositoryRoot}> <--check>`;
  const legacyCheck = `node <${join(repositoryRoot, "tools/contract-doc-check/check.mjs")}> <--repo-root> <${repositoryRoot}>`;
  try {
    const ciSuccess = runGate(ci, ["contracts"], fixture);
    assert.equal(ciSuccess.result.status, 0, ciSuccess.result.stderr);
    assert.deepEqual(ciSuccess.commands.slice(0, 2), [ciTest, ciCheck]);
    assert.equal(ciSuccess.commands.some((command) => command.includes("--write")), false);
    const protoAt = ciSuccess.commands.findIndex((command) => command.startsWith("buf <format>"));
    const openapiAt = ciSuccess.commands.findIndex((command) => command.includes("<redocly> <lint>"));
    assert.ok(protoAt > 1, "check_proto must run after the generator gates");
    assert.ok(openapiAt > protoAt, "check_openapi must run after check_proto");

    const ciFirstFailure = runGate(ci, ["contracts"], fixture, {
      match: "openapi-index.test.mjs",
      code: 41
    });
    assert.equal(ciFirstFailure.result.status, 41);
    assert.deepEqual(ciFirstFailure.commands, [ciTest]);
    const ciSecondFailure = runGate(ci, ["contracts"], fixture, {
      match: "openapi-index.mjs",
      code: 42
    });
    assert.equal(ciSecondFailure.result.status, 42);
    assert.deepEqual(ciSecondFailure.commands, [ciTest, ciCheck]);

    const nonContract = runGate(ci, ["go-control"], fixture);
    assert.equal(nonContract.result.status, 0, nonContract.result.stderr);
    assert.equal(nonContract.commands.some((command) => command.includes("openapi-index")), false);

    const docsSuccess = runGate(contractDocs, [], fixture);
    assert.equal(docsSuccess.result.status, 0, docsSuccess.result.stderr);
    assert.deepEqual(docsSuccess.commands, [docsTest, docsCheck, legacyCheck]);
    assert.equal(docsSuccess.commands.some((command) => command.includes("--write")), false);
    const docsFirstFailure = runGate(contractDocs, [], fixture, {
      match: "openapi-index.test.mjs",
      code: 43
    });
    assert.equal(docsFirstFailure.result.status, 43);
    assert.deepEqual(docsFirstFailure.commands, [docsTest]);
    const docsSecondFailure = runGate(contractDocs, [], fixture, {
      match: "openapi-index.mjs",
      code: 44
    });
    assert.equal(docsSecondFailure.result.status, 44);
    assert.deepEqual(docsSecondFailure.commands, [docsTest, docsCheck]);
    const docsLegacyFailure = runGate(contractDocs, [], fixture, {match: "check.mjs", code: 45});
    assert.equal(docsLegacyFailure.result.status, 45);
    assert.deepEqual(docsLegacyFailure.commands, [docsTest, docsCheck, legacyCheck]);
  } finally {
    rmSync(fixture.root, {recursive: true, force: true});
  }
});

test("replaces exactly one generated region without changing external bytes", () => {
  const source = "prefix\n<!-- generated:demo:begin -->\nold\n<!-- generated:demo:end -->\nsuffix\n";
  const updated = replaceGeneratedRegion(source, "demo", "new\nvalue");
  assert.equal(updated, "prefix\n<!-- generated:demo:begin -->\nnew\nvalue\n<!-- generated:demo:end -->\nsuffix\n");
  assert.throws(() => replaceGeneratedRegion("no markers\n", "demo", "x"), /missing generated marker/);
  assert.throws(() => replaceGeneratedRegion(source + source, "demo", "x"), /duplicate generated marker/);
  assert.throws(
    () => replaceGeneratedRegion("<!-- generated:demo:end -->\n<!-- generated:demo:begin -->\n", "demo", "x"),
    /out of order/
  );
});

test("renders deterministic index and README count regions", () => {
  const result = collectOpenAPIOperations([
    {contract: "control.yaml", version: "0.1.0", document: openapi({
      "/v1/items": {get: operation("listItems"), post: operation("createItem")}
    })}
  ]);
  assert.equal(renderOpenAPIIndex(result), renderOpenAPIIndex(result));
  assert.match(renderOpenAPIIndex(result), /\| `control\.yaml` \| `POST` \| `\/v1\/items` \| `createItem` \|/);
  assert.match(renderReadmeCounts(result), /\| \[`control\.yaml`\].*\| 0\.1\.0 \| 2 \|/);
});

test("current YAML and external refs include all required operations", async () => {
  const documents = await loadOpenAPIDocuments(repositoryRoot);
  const result = collectOpenAPIOperations(documents);
  assert.equal(documents.length, 4);
	// fix-certmenu：证书资产吊销下线（control.yaml 与 dns-acme.yaml 各 1 条，同一 wire tuple）。
	// fix-cacheflow5：缓存写请求回执 GET /v1[/admin]/cache-operation-requests/{key} 两条。
	// 用户端域名解析（ADR 0020 §3，/v1/dns/hub/*）7 条。
	assert.equal(result.operations.length, 1166);
	assert.equal(result.distinctTupleCount, 1141);
	assert.equal(result.overlaps.length, 25);
  const operationIDs = new Set(result.operations.map(({operationId}) => operationId));
  assert.deepEqual(legacyMissingOperationIDs.filter((value) => !operationIDs.has(value)), []);
  for (const operationId of [
    'getNodeRealtimeTop', 'getNodeRealtimeSeries', 'getNodeTraffic', 'getLatestNodeMetricsBatch', 'getLatestNodeMonitoring',
    'transferSite', 'listPlatformJobKinds', 'listTenantJobKinds', 'getNativeControlUpgradePlanStatus',
    'listAdminSiteGroups', 'getSiteGroup', 'listPackageResourceOptions',
    'resellerUpgradeForCustomer', 'resellerDowngradeForCustomer', 'resellerCancelCustomerSubscription',
    'resellerSuspendCustomerSubscription', 'resellerUnsuspendCustomerSubscription',
    'suspendPackageSubscriptionAsPlatform', 'unsuspendPackageSubscriptionAsPlatform',
    'reportInstallationEndpoints', 'getInstallationEndpoints',
    'archiveGlobalAnnouncement', 'restoreGlobalAnnouncement',
    'listL2Configs', 'createL2Config', 'getL2Config', 'updateL2Config', 'deleteL2Config',
    'listL2Conditions', 'createL2Condition', 'updateL2Condition', 'deleteL2Condition',
    'listL2Nodes', 'addL2Nodes', 'updateL2Node', 'deleteL2Node',
    'registerNode', 'getNodeRegistrationCredential', 'resetNodeRegistrationCredential',
    'authorizeMasterDownload', 'getLicenseMasterIP', 'setLicenseMasterIP', 'setPortalLicenseMasterIP',
    'createPortalOrder', 'issuePortalPoWChallenge', 'listIdentityProofProviders', 'updateIdentityProofProvider',
    'testIdentityProofProvider', 'getPortalPurchaseIdentityPolicy', 'setPortalPurchaseIdentityPolicy'
  ]) {
    assert.ok(operationIDs.has(operationId), operationId);
  }
});

test("write is idempotent and check mode never writes", async () => {
  const root = fixtureRepository();
  try {
    const indexPath = join(root, "docs/api/openapi-index.md");
    const readmePath = join(root, "docs/api/README.md");
    const before = [hash(indexPath), hash(readmePath)];
    const stale = spawnSync(process.execPath, [toolPath, "--repo-root", root, "--check"], {encoding: "utf8"});
    assert.equal(stale.status, 1, stale.stderr);
    assert.deepEqual([hash(indexPath), hash(readmePath)], before);

    await updateDocumentation(root, {write: true});
    const first = [hash(indexPath), hash(readmePath)];
    await updateDocumentation(root, {write: true});
    assert.deepEqual([hash(indexPath), hash(readmePath)], first);

    const clean = spawnSync(process.execPath, [toolPath, "--repo-root", root, "--check"], {encoding: "utf8"});
    assert.equal(clean.status, 0, clean.stderr);
    assert.deepEqual([hash(indexPath), hash(readmePath)], first);
  } finally {
    rmSync(root, {recursive: true, force: true});
  }
});
