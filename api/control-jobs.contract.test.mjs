import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const apiDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(apiDir, "..");
const fragmentPath = join(apiDir, "control-jobs.openapi.yaml");
const aggregatePath = join(apiDir, "openapi/v1/control.yaml");
const handler = readFileSync(join(root, "services/control-api/internal/jobhttp/handler.go"), "utf8");
const command = readFileSync(join(root, "services/control-api/internal/jobhttp/command_postgres.go"), "utf8");

const statuses = ["200", "400", "401", "403", "404", "408", "409", "412", "502", "503", "504"];
const operations = [
  ["/v1/admin/jobs/{task_id}/cancel", "cancelPlatformJob", [{bearerAuth: []}], ["jobs.manage_all", "platform.admin"]],
  ["/v1/admin/jobs/{task_id}/retry", "retryPlatformJob", [{bearerAuth: []}], ["jobs.manage_all", "platform.admin"]],
	["/v1/admin/jobs/{task_id}/replay", "replayPlatformDeadLetteredJob", [{bearerAuth: []}], ["jobs.manage_all", "platform.admin"]],
  ["/v1/jobs/{task_id}/cancel", "cancelTenantJob", [{bearerAuth: []}, {cdncaApiKey: []}], ["jobs.manage"]],
  ["/v1/jobs/{task_id}/retry", "retryTenantJob", [{bearerAuth: []}, {cdncaApiKey: []}], ["jobs.manage"]],
];

for (const marker of [
  'case "cancel":',
  'case "retry":',
  "Operation: operation, IdempotencyKey: idempotencyKeys[0]",
  'http.StatusConflict, "job_idempotency_conflict"',
  'http.StatusConflict, "job_invalid_transition"',
  'http.StatusConflict, "job_retries_exhausted"',
	'http.StatusPreconditionFailed, "job_revision_conflict"',
	'request.Header.Values("If-Match")',
]) {
  assert.ok(handler.includes(marker), `runtime command contract marker missing: ${marker}`);
}
for (const marker of [
  "INSERT INTO background_job_command_receipts",
  'reader.appendCommandAudit(ctx, tx, input, "success"',
  "return CommandResult{Data: receipt.result, Replayed: true}, nil",
]) {
  assert.ok(command.includes(marker), `durable command evidence missing: ${marker}`);
}

const temporaryDirectory = mkdtempSync(join(tmpdir(), "cdnca-jobs-openapi-"));
try {
  const documents = [];
	for (const [name, source] of [["fragment", fragmentPath]]) {
    const output = join(temporaryDirectory, `${name}.json`);
    execFileSync(
      "pnpm",
      ["--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle", source, "--output", output],
      {cwd: root, stdio: "pipe"},
    );
    documents.push([name, JSON.parse(readFileSync(output, "utf8"))]);
  }
	const aggregateSource = readFileSync(aggregatePath, "utf8");
	for (const [path] of operations) {
		const escapedPath = path.replaceAll("~", "~0").replaceAll("/", "~1");
		assert.ok(
			aggregateSource.includes(`#/paths/${escapedPath}`),
			`aggregate OpenAPI must reference the focused job operation ${path}`,
		);
	}

  for (const [name, document] of documents) {
    for (const [path, operationId, security, permissions] of operations) {
      const operation = document.paths?.[path]?.post;
      assert.ok(operation, `${name} missing POST ${path}`);
      assert.equal(operation.operationId, operationId, `${name} ${path} operationId drifted`);
      assert.deepEqual(operation.security, security, `${operationId} authentication drifted`);
      const actualPermissions = operation[permissions.length === 1 ? "x-required-permissions" : "x-required-any-permission"];
      assert.deepEqual(actualPermissions, permissions, `${operationId} RBAC drifted`);
      assert.deepEqual(Object.keys(operation.responses ?? {}).sort(), statuses, `${operationId} status matrix drifted`);
      assert.ok(
        operation.parameters?.some((parameter) =>
          parameter.$ref?.endsWith("IdempotencyKey") ||
          (parameter.name === "Idempotency-Key" && parameter.in === "header" && parameter.required === true)
        ),
        `${operationId} must require Idempotency-Key`,
      );
	  assert.ok(
		operation.parameters?.some((parameter) =>
		  parameter.$ref?.endsWith("JobRevision") ||
		  (parameter.name === "If-Match" && parameter.in === "header" && parameter.required === true)
		),
		`${operationId} must require a strong job revision`,
	  );
      assert.equal(operation.requestBody?.required, true, `${operationId} must require the JSON body`);
      const body = operation.requestBody?.content?.["application/json"]?.schema;
      assert.equal(body?.type, "object");
      assert.equal(body?.additionalProperties, false);
      assert.equal(body?.maxProperties, 0);
      assert.match(operation.description ?? "", /immutable first.*replayed=true/i);
    }
  }

  const fragment = documents[0][1];
  for (const [prefix, permissions] of [["/v1/admin/jobs", ["jobs.read_all", "platform.admin"]], ["/v1/jobs", ["jobs.read"]]]) {
    const list = fragment.paths?.[prefix]?.get;
    assert.ok(list.parameters.some((parameter) => parameter.$ref?.endsWith("PageNumber") || parameter.name === "page"));
    const catalog = fragment.paths?.[`${prefix}/kinds`]?.get;
    assert.ok(catalog, `missing source-backed kind catalog: ${prefix}`);
    assert.deepEqual(catalog[permissions.length === 1 ? "x-required-permissions" : "x-required-any-permission"], permissions);
    assert.match(catalog.description, /runtime/i);
    assert.equal(catalog.parameters, undefined, "catalog must not require a nonempty job page or accept scope overrides");
  }
  const schemas = fragment.components.schemas;
  assert.deepEqual(schemas.NumberedPage.required, ["number", "limit", "total", "total_pages", "consistency"]);
  assert.deepEqual(schemas.NumberedPage.properties.consistency.enum, ["request_snapshot"]);
  assert.equal(schemas.NumberedPage.properties.total.minimum, 0);
  assert.equal(schemas.NumberedPage.properties.total_pages.minimum, 0);
  assert.deepEqual(schemas.JobKind.required, ["kind", "name_key", "integration", "runtime_status"]);
  assert.deepEqual(schemas.JobKind.properties.runtime_status.enum, ["unknown"]);
  assert.ok(schemas.JobListResponse.properties.task_metadata);
  assert.equal(schemas.Job.properties.task_metadata, undefined, "presentation must not change immutable Job revisions");
  assert.deepEqual(schemas.TaskMetadata.properties.priority.properties.policy.enum, ["ready_fifo", "producer_managed", "unknown"]);
  assert.deepEqual(schemas.TaskMetadata.properties.dependencies.properties.state.enum, ["observed", "none", "unknown"]);
  assert.ok(schemas.ItemResult.required.includes("failure_count"));
  assert.equal(schemas.ItemResult.properties.started_at.format, "date-time");
  assert.match(fragment.components.parameters.Resource.description, /node UUID/);
  assert.equal(schemas.TaskMetadata.properties.dependencies.properties.items.maxItems, 1);
  assert.match(fragment.components.parameters.PageNumber.description, /mutually exclusive.*cursor/s);
  const commandResponse = fragment.components?.schemas?.CommandResponse;
  assert.deepEqual(commandResponse?.required, ["data", "replayed"]);
  assert.match(commandResponse?.properties?.replayed?.description ?? "", /durable command receipt/i);
	assert.ok(fragment.components?.schemas?.Job?.required?.includes("revision"));
	assert.match(fragment.components?.schemas?.Job?.properties?.revision?.pattern ?? "", /0-9a-f/);
	assert.match(fragment.components?.responses?.Error412?.description ?? "", /job_revision_conflict/);
  const conflict = fragment.components?.responses?.Error409?.description ?? "";
  for (const code of ["job_idempotency_conflict", "job_invalid_transition", "job_retries_exhausted"]) {
    assert.match(conflict, new RegExp(code), `409 description missing ${code}`);
  }
} finally {
  rmSync(temporaryDirectory, {recursive: true, force: true});
}

console.log(`job OpenAPI contract: passed (${operations.length} commands, numbered pagination, kind catalogs, and read-only task metadata)`);
