import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const apiDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(apiDir, "..");
const canonicalPath = join(apiDir, "openapi/v1/control.yaml");
const workloadPaths = [
  "/v1/internal/traffic-packages/consume",
  "/v1/internal/traffic-packages/refund",
  "/v1/internal/traffic-packages/expire",
  "/v1/internal/traffic-packages/grants/{grant_id}/reverse",
];

const temporaryDir = mkdtempSync(join(tmpdir(), "cdnca-traffic-package-openapi-"));
const bundlePath = join(temporaryDir, "control.json");
try {
  execFileSync(
    "pnpm",
    ["--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle", canonicalPath, "--output", bundlePath],
    {cwd: root, stdio: "pipe"},
  );
  const document = JSON.parse(readFileSync(bundlePath, "utf8"));
  const scheme = document.components?.securitySchemes?.workloadMtls;

  assert.ok(scheme, "canonical control API must define workloadMtls");
  assert.equal(scheme.type, "mutualTLS", "workloadMtls must remain a mutual TLS scheme");

  for (const path of workloadPaths) {
    const operation = document.paths?.[path]?.post;
    assert.ok(operation, `canonical workload operation missing: POST ${path}`);
    assert.deepEqual(
      operation.security,
      [{workloadMtls: []}],
      `POST ${path} must not accept an ordinary bearer session`,
    );
  }
} finally {
  rmSync(temporaryDir, {recursive: true, force: true});
}

console.log(`traffic package root OpenAPI contract: passed (${workloadPaths.length} workload operations)`);
