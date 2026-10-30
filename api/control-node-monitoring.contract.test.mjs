import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import Ajv2020 from 'ajv/dist/2020.js'

const root = fileURLToPath(new URL('../', import.meta.url))
const temporaryDir = mkdtempSync(join(tmpdir(), 'cdnca-node-monitoring-openapi-'))
let schemas
try {
  const bundle = join(temporaryDir, 'system-configuration.json')
  execFileSync('pnpm', [
    '--package=@redocly/cli@1.34.5', 'dlx', 'redocly', 'bundle',
    join(root, 'api/control-system-configuration.openapi.yaml'), '--output', bundle,
  ], { cwd: root, stdio: 'pipe' })
  schemas = JSON.parse(readFileSync(bundle, 'utf8')).components.schemas
} finally {
  rmSync(temporaryDir, { recursive: true, force: true })
}

const schema = schemas.NodeMonitoringConfiguration
const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false })
const validate = ajv.compile(schema)
const legacy = {
  port_mode: 'default', probe_interval_ms: 10000, probe_timeout_ms: 3000,
  failure_threshold: 3, recovery_threshold: 3, failure_debounce_ms: 0,
  recovery_debounce_ms: 0, recovery_notification_enabled: true,
}
const groups = ['domestic', 'telecom', 'unicom', 'mobile', 'overseas']
const reference = {
  monitor_enabled: false, protocol: 'tcp', monitor_port: 80, monitor_groups: groups,
  monitor_action: 'pause', failure_ratio: 90, bandwidth_over_limit: 2,
}

function assertNodeMonitoringContract(value, expected, label) {
  assert.equal(validate(value), expected, `${label}: ${JSON.stringify(validate.errors)}`)
}

test('legacy node monitoring stays valid without materializing optional reference defaults', () => {
  assert.deepEqual(schema.required, Object.keys(legacy))
  assert.equal(schema.additionalProperties, false)
  assertNodeMonitoringContract(legacy, true, 'legacy value')
  assertNodeMonitoringContract({ ...legacy, port_mode: 'custom', custom_port: 65535 }, true, 'custom port')
  for (const key of schema.required) {
    const value = { ...legacy }
    delete value[key]
    assertNodeMonitoringContract(value, false, `missing ${key}`)
  }
  for (const value of [
    { ...legacy, extra: true }, { ...legacy, custom_port: 80 },
    { ...legacy, port_mode: 'custom' }, { ...legacy, port_mode: 'unknown' },
  ]) assertNodeMonitoringContract(value, false, 'legacy strictness')
})

test('all seven optional fields match Go canonical output and migration 240 constraints', () => {
  const expected = {
    monitor_enabled: { type: 'boolean' },
    protocol: { type: 'string', enum: ['http', 'tcp', 'ping'] },
    monitor_port: { type: 'integer', minimum: 1, maximum: 65535 },
    monitor_groups: { type: 'array', minItems: 1, maxItems: 5, uniqueItems: true,
      items: { type: 'string', enum: groups } },
    monitor_action: { type: 'string', enum: ['none', 'pause'] },
    failure_ratio: { type: 'integer', minimum: 1, maximum: 100 },
    bandwidth_over_limit: { type: 'integer', minimum: 1, maximum: 20 },
  }
  assert.deepEqual(Object.keys(schema.properties).sort(), [...Object.keys(legacy), 'custom_port', ...Object.keys(expected)].sort())
  for (const [key, definition] of Object.entries(expected)) {
    assert.deepEqual(schema.properties[key], definition, key)
    assert.equal(schema.required.includes(key), false, `${key} must remain optional`)
    assert.equal('default' in schema.properties[key], false, `${key} must not invent a default`)
  }
})

test('reference fields work independently and together in the existing read and write envelopes', () => {
  for (const [key, value] of Object.entries(reference)) {
    assertNodeMonitoringContract({ ...legacy, [key]: value }, true, key)
  }
  const value = { ...legacy, ...reference }
  assertNodeMonitoringContract(value, true, 'complete canonical value')
  const write = ajv.compile({ ...schemas.NodeMonitoringWriteRequest, components: { schemas } })
  const read = ajv.compile({ ...schemas.CategoryDocument, components: { schemas } })
  assert.equal(write({ value }), true, JSON.stringify(write.errors))
  assert.equal(read({
    schema: 'cdnca.system-configuration/v2', category: 'node_monitoring',
    head_revision: 2, active_revision: 1, revision: 2, status: 'draft',
    snapshot_sha256: 'a'.repeat(64), pending_categories: ['node_monitoring'], value,
  }), true, JSON.stringify(read.errors))
})

test('protocol, action and monitor switch retain every canonical choice', () => {
  for (const protocol of ['http', 'tcp', 'ping']) {
    for (const monitor_action of ['none', 'pause']) {
      for (const monitor_enabled of [false, true]) {
        assertNodeMonitoringContract({ ...legacy, protocol, monitor_action, monitor_enabled }, true, 'canonical choices')
      }
    }
  }
})

test('reference numeric fields retain both inclusive boundaries', () => {
  for (const [key, minimum, maximum] of [
    ['monitor_port', 1, 65535], ['failure_ratio', 1, 100], ['bandwidth_over_limit', 1, 20],
  ]) {
    for (const value of [minimum, maximum]) {
      assertNodeMonitoringContract({ ...legacy, [key]: value }, true, `${key} boundary ${value}`)
    }
    for (const value of [minimum - 1, maximum + 1, 1.5, '1', null]) {
      assertNodeMonitoringContract({ ...legacy, [key]: value }, false, `${key} invalid ${value}`)
    }
  }
})

test('monitor groups preserve known unique values and reject empty, duplicate or unknown groups', () => {
  for (const monitor_groups of groups.map((group) => [group]).concat([groups, [...groups].reverse()])) {
    assertNodeMonitoringContract({ ...legacy, monitor_groups }, true, 'canonical monitor groups')
  }
  for (const monitor_groups of [[], ['domestic', 'domestic'], [...groups, 'domestic'], ['unknown'], [null], null, 'domestic']) {
    assertNodeMonitoringContract({ ...legacy, monitor_groups }, false, 'invalid monitor groups')
  }
})

test('unknown or noncanonical optional field values remain rejected', () => {
  for (const [key, values] of [
    ['monitor_enabled', [0, 'true', null]],
    ['protocol', ['', 'HTTP', 'udp', null, 1]],
    ['monitor_action', ['', 'stop', 'PAUSE', null, false]],
  ]) {
    for (const value of values) {
      assertNodeMonitoringContract({ ...legacy, [key]: value }, false, `${key} invalid ${value}`)
    }
  }
  assertNodeMonitoringContract({ ...legacy, ...reference, unexpected: true }, false, 'unknown reference field')
})
