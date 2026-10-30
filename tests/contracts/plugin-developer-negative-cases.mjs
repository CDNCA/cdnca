import assert from "node:assert/strict";
import {mkdtemp, readFile, rm, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {fileURLToPath} from "node:url";
import {spawnSync} from "node:child_process";

import Ajv from "ajv";
import addFormats from "ajv-formats";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const compatibilitySchemaPath = join(
  repositoryRoot,
  "api/schemas/marketplace/v1/plugin-compatibility-matrix.schema.json"
);
const compatibilityMatrixPath = join(
  repositoryRoot,
  "docs/developer/examples/plugin-compatibility-v1.json"
);
const manifestPath = join(repositoryRoot, "tests/contracts/plugin-manifest-v1.json");
const publisherPath = join(repositoryRoot, "tests/contracts/plugin-publisher-v1.json");
const validatorPath = join(
  repositoryRoot,
  "docs/developer/examples/validate-plugin-manifest.mjs"
);

async function readJSON(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

function runValidator(controlAPIVersion, candidatePath) {
  return spawnSync(process.execPath, [
    validatorPath,
    "--control-api-version",
    controlAPIVersion,
    candidatePath,
    publisherPath
  ], {
    cwd: repositoryRoot,
    encoding: "utf8"
  });
}

const failures = [];
async function check(name, assertion) {
  try {
    await assertion();
  } catch (error) {
    failures.push(`${name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

await check("compatibility matrix schema", async () => {
  const [schema, matrix] = await Promise.all([
    readJSON(compatibilitySchemaPath),
    readJSON(compatibilityMatrixPath)
  ]);
  const ajv = new Ajv({allErrors: true, strict: true});
  addFormats(ajv);
  assert.equal(ajv.validateSchema(schema), true, JSON.stringify(ajv.errors));
  const validate = ajv.compile(schema);
  assert.equal(validate(matrix), true, JSON.stringify(validate.errors));
  assert.deepEqual(
    new Set(matrix.rows.map((row) => row.surface)),
    new Set([
      "manifest", "manifest_signature", "control_api", "license_operator_api",
      "plugin_workload_identity", "agent", "control_plugin_installation_api", "webhook_signature"
    ]),
    "compatibility matrix is missing a shipped client contract"
  );

  for (const field of ["contract", "status", "deprecated_since", "sunset_after", "replacement"]) {
    const missingField = structuredClone(matrix);
    delete missingField.deprecations[0][field];
    assert.equal(validate(missingField), false, `deprecation without ${field} was accepted`);
  }

  const unknownField = structuredClone(matrix);
  unknownField.deprecations[0].unversioned_note = "not allowed";
  assert.equal(validate(unknownField), false, "unknown deprecation field was accepted");

  const unknownStatus = structuredClone(matrix);
  unknownStatus.deprecations[0].status = "removed";
  assert.equal(validate(unknownStatus), false, "unknown deprecation status was accepted");
});

const taskDirectory = await mkdtemp(join(tmpdir(), "cdnca-plugin-developer-contracts."));
try {
  const manifest = await readJSON(manifestPath);

  await check("incompatible Control API version", async () => {
    const result = runValidator("2.0.0", manifestPath);
    assert.notEqual(result.status, 0, "incompatible Control API version was accepted");
    assert.match(result.stderr, /outside .*preserve LKG and deny install\/upgrade/);
  });

  await check("unknown event", async () => {
    const candidate = structuredClone(manifest);
    candidate.spec.subscriptions = ["io.cdnca.unknown.v1.changed"];
    const candidatePath = join(taskDirectory, "unknown-event.json");
    await writeFile(candidatePath, `${JSON.stringify(candidate)}\n`, {mode: 0o600});
    const result = runValidator("0.5.0", candidatePath);
    assert.notEqual(result.status, 0, "unknown event was accepted");
    assert.match(result.stderr, /unknown event: io\.cdnca\.unknown\.v1\.changed/);
  });

  await check("invalid compatibility grammar", async () => {
    const candidate = structuredClone(manifest);
    candidate.spec.compatibility.control_api = ">=0.1.0  <1.0.0";
    const candidatePath = join(taskDirectory, "invalid-compatibility.json");
    await writeFile(candidatePath, `${JSON.stringify(candidate)}\n`, {mode: 0o600});
    const result = runValidator("0.5.0", candidatePath);
    assert.notEqual(result.status, 0, "invalid compatibility grammar was accepted");
  });
} finally {
  await rm(taskDirectory, {recursive: true, force: true});
}

if (failures.length > 0) {
  throw new Error(`plugin developer contract checks failed:\n${failures.join("\n")}`);
}

console.log("plugin developer contracts: matrix schema and negative cases passed");
