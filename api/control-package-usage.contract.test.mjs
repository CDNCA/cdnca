import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const apiDir = dirname(fileURLToPath(import.meta.url))
const temporaryDir = mkdtempSync(join(tmpdir(), 'cdnca-package-usage-openapi-'))
const bundlePath = join(temporaryDir, 'package-usage.json')
try {
  execFileSync('pnpm', ['--package=@redocly/cli@1.34.5', 'dlx', 'redocly', 'bundle', 'control-package-usage.openapi.yaml', '--output', bundlePath], { cwd: apiDir, stdio: 'pipe' })
  const document = JSON.parse(readFileSync(bundlePath, 'utf8'))
  const resolveRef = (value) => value?.$ref?.startsWith('#/components/responses/')
    ? document.components.responses[value.$ref.split('/').at(-1)]
    : value
  for (const path of ['/v1/package-usage', '/v1/admin/package-usage']) {
    const operation = document.paths?.[path]?.get
    assert.ok(operation, `missing GET ${path}`)
    assert.deepEqual(operation.security, [{ bearerAuth: [] }])
    const schema = resolveRef(operation.responses?.['200'])?.content?.['application/json']?.schema
    assert.equal(schema?.$ref, '#/components/schemas/PackageUsagePage')
  }
  for (const [path, schemaName] of [
    ['/v1/admin/package-resource-monitor', 'PackageResourceMonitorPage'],
    ['/v1/admin/package-resource-monitor/nodes', 'PackageResourceMonitorNodes'],
  ]) {
    const operation = document.paths?.[path]?.get
    assert.ok(operation, `missing GET ${path}`)
    assert.deepEqual(operation.security, [{ bearerAuth: [] }])
    const schema = resolveRef(operation.responses?.['200'])?.content?.['application/json']?.schema
    assert.equal(schema?.$ref, `#/components/schemas/${schemaName}`)
  }
  for (const path of ['/v1/package-traffic-coverage', '/v1/admin/package-traffic-coverage']) {
    const operation = document.paths?.[path]?.get
    assert.ok(operation, `missing GET ${path}`)
    assert.deepEqual(operation.security, [{ bearerAuth: [] }])
    const schema = resolveRef(operation.responses?.['200'])?.content?.['application/json']?.schema
    assert.equal(schema?.$ref, '#/components/schemas/PackageTrafficCoveragePage')
  }
  assert.equal(document.components.schemas.PackageTrafficCoverageCycle.properties.covered_bytes.$ref, '#/components/schemas/UInt64String')
  const monitorParams = document.paths['/v1/admin/package-resource-monitor'].get.parameters
  for (const name of ['query_version', 'subscription_ids', 'subscription_display_ids']) {
    assert.ok(monitorParams.some((p) => (p.name ?? document.components.parameters[p.$ref?.split('/').at(-1)]?.name) === name), `missing ${name}`)
  }
  assert.equal(document.components.schemas.PackageResourceMonitorItem.properties.subscription_display_id.type, 'string')
  const properties = document.components.schemas.PackageUsagePage.properties
  const search = document.paths['/v1/admin/package-usage/search'].get
  assert.deepEqual(search.security, [{ bearerAuth: [] }])
  for (const field of ['user_ids', 'subscription_ids', 'service_type', 'domains', 'listen_ports']) {
    assert.ok(search.parameters.some((parameter) => parameter.name === field), `missing ${field}`)
    assert.ok(document.components.schemas.UsageSearchFilters.required.includes(field))
  }
  assert.equal(document.components.schemas.UsageSearchPage.properties.series.maxItems, 168)
  for (const field of ['traffic_bytes', 'http_traffic_bytes', 'l4_traffic_bytes', 'peak_bandwidth_bps', 'bandwidth_95th_bps', 'connections', 'source_watermark']) {
    assert.equal(properties[field].type, 'string', `${field} must preserve UInt64 precision`)
    assert.equal(properties[field].pattern, '^[0-9]+$')
  }
  for (const field of ['http_traffic_bytes', 'l4_traffic_bytes']) {
    assert.ok(document.components.schemas.PackageUsagePage.required.includes(field), `page must require ${field}`)
    assert.ok(document.components.schemas.PackageUsagePoint.required.includes(field), `point must require ${field}`)
  }
  console.log('package usage OpenAPI contract: passed')
} finally {
  rmSync(temporaryDir, { recursive: true, force: true })
}
