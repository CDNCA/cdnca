// Marketplace M0 contracts (docs/architecture/marketplace-buildout.md §9.2):
// the OpenAPI skeletons under docs/architecture/marketplace-openapi/ must lint
// clean, every operation must carry owner/summary/security/responses, writes
// must require Idempotency-Key, and the operator API permissions must match
// services/license-service/internal/marketadminproxy/routes.go row by row.
import assert from "node:assert/strict";
import {execFileSync, spawnSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {test} from "node:test";
import {fileURLToPath} from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const dir = join(root, "docs/architecture/marketplace-openapi");
const docs = ["seller", "service", "catalog", "buyer", "payments", "admin-plugins", "admin-nodes", "admin-finance"];
const adminDocs = new Set(["admin-plugins", "admin-nodes", "admin-finance"]);
const owners = new Set(["live", "M1", "M2", "M4", "M6", "M9"]);
const methods = ["get", "put", "post", "delete", "patch"];
const redocly = ["--package=@redocly/cli@1.34.5", "dlx", "redocly"];
const env = {...process.env, REDOCLY_TELEMETRY: "off", REDOCLY_SUPPRESS_UPDATE_NOTICE: "true"};

const prefixes = {
  seller: ["/seller/v1/"],
  service: ["/service/v1/"],
  catalog: ["/catalog/v1/"],
  buyer: ["/v1/"],
  payments: ["/portal/v1/checkout/", "/payments/v1/notify/"],
  "admin-plugins": ["/admin/v1/"],
  "admin-nodes": ["/admin/v1/"],
  "admin-finance": ["/admin/v1/"],
};

function bundle() {
  const out = mkdtempSync(join(tmpdir(), "cdnca-marketplace-openapi-"));
  try {
    execFileSync("pnpm", [...redocly, "bundle", ...docs.map((d) => `${d}.yaml`), "--dereferenced", "--ext", "json",
      "--output", out], {cwd: dir, env, stdio: "pipe"});
    return Object.fromEntries(docs.map((d) => [d, JSON.parse(readFileSync(join(out, `${d}.json`), "utf8"))]));
  } finally {
    rmSync(out, {recursive: true, force: true});
  }
}

function operations(documents) {
  const ops = [];
  for (const [doc, spec] of Object.entries(documents)) {
    for (const [path, item] of Object.entries(spec.paths ?? {})) {
      for (const method of methods) {
        if (item[method]) ops.push({doc, path, method: method.toUpperCase(), op: item[method], spec});
      }
    }
  }
  return ops;
}

// routes.go rows: rt("GET", "sellers/{}", "M1", pending, q(...), PermOverviewView, ...),
function proxyRoutes() {
  const source = readFileSync(join(root, "services/license-service/internal/marketadminproxy/routes.go"), "utf8");
  const constants = Object.fromEntries([...source.matchAll(/^\s*(Perm\w+)\s*=\s*"([^"]+)"/gm)].map((m) => [m[1], m[2]]));
  const rows = [...source.matchAll(/^\s*rt\("([A-Z]+)", "([^"]+)", "([^"]+)", (forwarded|pending), (?:legacyQ|q\([^)]*\)), ([^\n]+)\),$/gm)];
  assert.ok(rows.length > 0, "no rt(...) rows parsed from routes.go");
  return {
    constants,
    routes: rows.map(([, method, path, owner, fwd, perms]) => ({
      method, path, owner, forwarded: fwd === "forwarded",
      permissions: perms.split(",").map((p) => {
        const code = constants[p.trim()];
        assert.ok(code, `routes.go permission ${p.trim()} is not a Perm constant`);
        return code;
      }),
    })),
  };
}

const documents = bundle();
const ops = operations(documents);

test("all marketplace OpenAPI documents lint clean", () => {
  const result = spawnSync("pnpm", [...redocly, "lint", "--extends=minimal", "--format=stylish", ...docs.map((d) => `${d}.yaml`)],
    {cwd: dir, env, encoding: "utf8"});
  const output = result.stdout + result.stderr;
  assert.equal(result.status, 0, output);
  assert.match(output, /Your API descriptions are valid/, output);
  assert.doesNotMatch(output, /warning/i, output);
});

test("every operation has a unique id, owner, summary, security and a success and error response", () => {
  const ids = new Set();
  for (const {doc, path, method, op, spec} of ops) {
    const where = `${doc} ${method} ${path}`;
    assert.ok(op.operationId && !ids.has(op.operationId), `${where}: missing or duplicate operationId`);
    ids.add(op.operationId);
    assert.ok(owners.has(op["x-owner"]), `${where}: x-owner ${op["x-owner"]}`);
    assert.ok(op.summary, `${where}: summary`);
    assert.ok(prefixes[doc].some((p) => path.startsWith(p)), `${where}: path outside the ${doc} surface`);
    const security = op.security ?? spec.security;
    assert.ok(Array.isArray(security), `${where}: security must be declared`);
    // x-public: an explicitly justified unauthenticated operation (seller site
    // config, and the session exchange whose body carries a signed token).
    if (doc !== "catalog" && !op["x-public"]) assert.ok(security.length > 0, `${where}: unauthenticated operation`);
    const codes = Object.keys(op.responses ?? {});
    assert.ok(codes.some((c) => /^2/.test(c)), `${where}: no 2xx response`);
    assert.ok(codes.some((c) => /^4/.test(c)), `${where}: no 4xx response`);
  }
  assert.ok(ops.length >= 120, `expected the full §4 surface, got ${ops.length} operations`);
});

test("new write operations require Idempotency-Key", () => {
  for (const {doc, path, method, op} of ops) {
    if (method === "GET" || op["x-existing"] || op["x-public"] || op["x-idempotent"] ||
      doc === "payments" && path.startsWith("/payments/v1/notify/")) continue;
    const key = (op.parameters ?? []).find((p) => p.in === "header" && p.name === "Idempotency-Key");
    assert.ok(key?.required === true, `${doc} ${method} ${path}: Idempotency-Key header must be required`);
  }
});

// Operations market-service serves whose proxy row the license-side task (M2)
// has not added to routes.go yet. Each still needs its permission annotation;
// once the row lands it is checked like every other row, and this test fails
// until the entry is removed here.
const awaitingProxyRow = new Set([]);

test("operator API permissions match marketadminproxy/routes.go row by row", () => {
  const {constants, routes} = proxyRoutes();
  const fromRoutes = new Map(routes.map((r) => [`${r.method} ${r.path}`, r]));
  const seen = new Set();
  for (const {doc, path, method, op} of ops.filter((o) => adminDocs.has(o.doc))) {
    const rel = path.replace(/^\/admin\/v1\//, "").replace(/\{[^}]+\}/g, "{}");
    const key = `${method} ${rel}`;
    const route = fromRoutes.get(key) ?? fromRoutes.get(`${method} ${rel.replace(/\/(activate|retire)$/, "/{}")}`);
    if (awaitingProxyRow.has(key)) {
      assert.ok(!route, `${doc} ${key}: routes.go has the row now; remove it from awaitingProxyRow`);
      const perms = op["x-required-permissions"] ?? op["x-required-any-permission"];
      assert.ok(perms?.length && perms.every((p) => Object.values(constants).includes(p)), `${doc} ${key}: permission annotation`);
      assert.ok(!op["x-forwarded"] && !op["x-existing"], `${doc} ${key}: not forwarded yet`);
      continue;
    }
    assert.ok(route, `${doc} ${key}: no routes.go row`);
    seen.add(`${route.method} ${route.path}`);
    const single = op["x-required-permissions"];
    const any = op["x-required-any-permission"];
    assert.ok(Boolean(single) !== Boolean(any), `${doc} ${key}: exactly one permission annotation`);
    if (single) assert.equal(single.length, 1, `${doc} ${key}: x-required-permissions takes one code`);
    assert.deepEqual(single ?? any, route.permissions, `${doc} ${key}: permissions drifted from routes.go`);
    assert.equal(op["x-owner"], route.owner, `${doc} ${key}: owner drifted from routes.go`);
    assert.equal(Boolean(op["x-forwarded"]), route.forwarded, `${doc} ${key}: x-forwarded drifted from routes.go`);
    assert.equal(Boolean(op["x-existing"]), route.owner === "live", `${doc} ${key}: x-existing must mark live routes`);
  }
  for (const r of routes) assert.ok(seen.has(`${r.method} ${r.path}`), `routes.go ${r.method} ${r.path} has no OpenAPI operation`);
  assert.equal(Object.keys(constants).length, 11, "§4.1 lists 11 permission codes");
});

test("catalog snapshot schema follows the license-side SignedPluginCatalogSnapshot", () => {
  const source = readFileSync(join(root, "services/license-service/internal/licensing/plugin_catalog_snapshot.go"), "utf8");
  const tags = (type) => {
    const body = source.match(new RegExp(`type ${type} struct \\{([^}]*)\\}`))[1];
    return [...body.matchAll(/json:"([a-z_0-9]+)"/g)].map((m) => m[1]).sort();
  };
  const schema = documents.catalog.paths["/catalog/v1/snapshot"].get.responses["200"]
    .content["application/vnd.cdnca.plugin-catalog.v1+json"].schema;
  assert.deepEqual(Object.keys(schema.properties).sort(), tags("SignedPluginCatalogSnapshot"));
  assert.deepEqual(Object.keys(schema.properties.envelope.properties).sort(), tags("PluginCatalogSnapshotEnvelope"));
  assert.deepEqual(Object.keys(schema.properties.payload.properties).sort(), tags("PluginCatalogPayload"));
  assert.deepEqual(Object.keys(schema.properties.payload.properties.plugins.items.properties).sort(), tags("PluginCatalogPackage"));
  assert.equal(schema.properties.envelope.properties.domain.const,
    source.match(/PluginCatalogSignatureDomain\s*=\s*"([^"]+)"/)[1]);
  assert.equal(schema.properties.payload.properties.schema.const, source.match(/PluginCatalogPayloadSchema\s*=\s*"([^"]+)"/)[1]);
});

test("mount points named by the contracts exist in code", () => {
  const mount = readFileSync(join(root, "services/market-service/internal/httpapi/mount.go"), "utf8");
  for (const name of ["mountBuyer", "mountSeller", "mountService", "mountCatalog", "mountPluginAdmin", "mountNodeAdmin", "mountFinanceAdmin"]) {
    assert.match(mount, new RegExp(`func \\(s \\*Server\\) ${name}\\(`), `market-service ${name}`);
  }
  const text = docs.map((d) => readFileSync(join(dir, `${d}.yaml`), "utf8")).join("\n");
  for (const [, surface] of text.matchAll(/httpapi\.(Surface\w+)/g)) {
    assert.match(mount, new RegExp(`\\b${surface}\\s+Surface = `), `unknown market surface ${surface}`);
  }
  const handler = readFileSync(join(root, "services/license-service/internal/httpapi/handler.go"), "utf8");
  for (const name of ["mountServiceMarket", "mountPortalSeller", "mountPayments"]) {
    assert.match(handler, new RegExp(`func \\(api \\*API\\) ${name}\\(\\)`), `license-service ${name}`);
    assert.match(handler, new RegExp(`api\\.${name}\\(\\)`), `license-service ${name} is not called`);
  }
});

test("buyer plugin views carry every field market-service serves", () => {
  const read = (path) => readFileSync(join(root, path), "utf8");
  const tags = (source, type) => {
    const body = source.match(new RegExp(`type ${type} struct \\{([\\s\\S]*?)\\n\\}`))[1];
    return [...body.matchAll(/json:"([a-z_0-9-]+)/g)].map((m) => m[1]);
  };
  const plugin = read("services/market-service/internal/plugin/plugin.go");
  const review = read("services/market-service/internal/plugin/review.go");
  const ui = read("libs/entitlement/pluginui/pluginui.go");
  const merged = (schema) => Object.assign({}, ...(schema.allOf ?? [schema]).map((part) => part.properties ?? {}));
  const list = documents.buyer.paths["/v1/plugins"].get.responses["200"].content["application/json"].schema;
  const card = merged(list.properties.items.items);
  // revision and created_at are internal: the buyer schema need not list them.
  for (const field of tags(plugin, "Plugin").filter((f) => !["revision", "created_at"].includes(f))) {
    assert.ok(card[field], `buyer list Plugin lacks ${field}`);
  }
  assert.ok(card.price_plans && tags(review, "BuyerListItem").includes("price_plans"), "buyer list price_plans");
  const detail = documents.buyer.paths["/v1/plugins/{id}"].get.responses["200"].content["application/json"].schema;
  assert.deepEqual(Object.keys(detail.properties).sort(), tags(review, "BuyerDetail").sort());
  const version = merged(detail.properties.versions.items);
  assert.ok(version.ui_page && tags(review, "BuyerVersion").includes("ui_page"), "buyer version ui_page");
  assert.deepEqual(Object.keys(version.ui_page.properties).sort(), tags(ui, "Entrypoint").sort());
  assert.deepEqual(Object.keys(version.ui_page.properties.pages.items.properties).sort(), tags(ui, "Page").sort());
  assert.deepEqual(card.publisher_kind.enum, ["official", "certified", "third_party"]);
});
