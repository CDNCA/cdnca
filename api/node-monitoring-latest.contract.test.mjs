import assert from 'node:assert/strict'
import { readFileSync, realpathSync } from 'node:fs'
import { createRequire } from 'node:module'
import test from 'node:test'
import Ajv2020 from 'ajv/dist/2020.js'

const require = createRequire(realpathSync(new URL('../apps/web/node_modules/eslint/package.json', import.meta.url)))
const { load } = require('js-yaml')
const document = load(readFileSync(new URL('./node-monitoring-latest.openapi.yaml', import.meta.url), 'utf8'))
const schemas = document.components.schemas
const ajv = new Ajv2020({ strict: false, validateFormats: false })
const validate = ajv.compile({ ...schemas.NodeMonitoringLatest, components: { schemas } })
const time = '2026-10-10T00:00:00Z'
const id = '018f0000-0000-7000-8000-000000000001'
const empty = {
  schema_version: 1, observed_at: time,
  configuration: { state: 'unconfigured', head_revision: 0, active_revision: null, activated_at: null, policy: null },
  items: [{ node_id: id, freshness: 'not_reported', revision_state: 'unknown', stale_after_ms: null, sample: null }],
}
const policy = { enabled: true, requested_protocol: 'tcp', requested_port: null, probe_interval_ms: 10000, probe_timeout_ms: 3000,
  failure_threshold: 3, recovery_threshold: 3, failure_debounce_ms: 0, recovery_debounce_ms: 0 }
const sample = { source: 'agent_local_tcp', config_revision: 1, active_config_revision: 1, publication_sequence: '9223372036854775807',
  observed_at: time, ingested_at: time, probe_port: 80, healthy: true, probe_succeeded: true, consecutive_failures: 0,
  consecutive_successes: 3, probes_total: '9223372036854775807', probe_failures_total: '9007199254740993', recovered: false,
  recovery_notified: false, rolled_back: false }
const active = { ...empty, configuration: { state: 'active', head_revision: 2, active_revision: 1, activated_at: time, policy },
  items: [{ ...empty.items[0], freshness: 'fresh', revision_state: 'current', stale_after_ms: 43000, sample }] }

function assertMonitoringContract(value, expected, label) {
  assert.equal(validate(value), expected, `${label}: ${JSON.stringify(validate.errors)}`)
}

test('probe-only operation requires platform nodes.read and complete ordered scope membership', () => {
  const operation = document.paths['/v1/nodes/monitoring/latest'].get
  assert.equal(operation.operationId, 'getLatestNodeMonitoring')
  assert.deepEqual(operation.security, [{ bearerAuth: [] }])
  assert.deepEqual(Object.keys(operation.responses).sort(), ['200', '400', '401', '403', '404', '503'])
  assert.equal(operation.parameters.length, 1)
  const parameter = operation.parameters[0]
  assert.equal(parameter.name, 'node_id')
  assert.equal(parameter.required, true)
  assert.equal(parameter.style, 'form')
  assert.equal(parameter.explode, true)
  assert.equal(parameter.schema.minItems, 1)
  assert.equal(parameter.schema.maxItems, 300)
  assert.equal(parameter.schema.uniqueItems, true)
  for (const fact of ['nodes.read', 'repeatable', 'read-only', 'no partial', 'request order', 'node_monitoring_not_found',
    'node_monitoring_unavailable', 'canonical_snapshot', 'no signature', 'HTTP', 'Ping', 'no application ACK']) {
    assert.ok(operation.description.includes(fact), fact)
  }
})

test('unconfigured, draft and active snapshots preserve nullable facts and actual probe source', () => {
  assertMonitoringContract(empty, true, 'unconfigured')
  assertMonitoringContract({ ...empty, configuration: { ...empty.configuration, state: 'not_activated', head_revision: 1 } }, true, 'draft')
  assertMonitoringContract(active, true, 'active with newer draft')
  assertMonitoringContract({ ...empty, items: [{ ...empty.items[0], sample, freshness: 'stale' }] }, true, 'old actual sample without active')
  assertMonitoringContract({ ...active, items: [{ ...empty.items[0], stale_after_ms: 43000 }] }, true, 'active but no report')
  for (const requested_protocol of ['tcp', 'http', 'ping']) {
    assertMonitoringContract({ ...active, configuration: { ...active.configuration, policy: { ...policy, enabled: false, requested_protocol } } }, true, 'requested disabled is not acknowledgement')
  }
})

test('all public objects reject unknown fields and missing keys', () => {
  // Per-node override facts and active serving holds are the only optional item keys.
  const optional = { NodeMonitoringLatestItem: ['effective_policy', 'effective_revision', 'serving_holds'] }
  for (const name of ['NodeMonitoringLatest', 'NodeMonitoringLatestConfiguration', 'NodeMonitoringLatestPolicy', 'NodeMonitoringLatestItem', 'NodeMonitoringLatestProbeSample',
    'NodeMonitoringOverrideFields', 'NodeMonitoringOverrideRequest', 'NodeMonitoringOverrideView', 'NodeServingHold', 'NodeServingEventPage']) {
    assert.equal(schemas[name].additionalProperties, false, name)
    assert.deepEqual([...schemas[name].required].sort(),
      Object.keys(schemas[name].properties).filter((key) => !(optional[name] ?? []).includes(key)).sort(), name)
  }
  for (const value of [
    { ...active, hidden: true }, { ...active, configuration: { ...active.configuration, snapshot: {} } },
    { ...active, items: [{ ...active.items[0], sample: { ...sample, known: true } }] },
    { ...active, items: [{ ...active.items[0], sample: { ...sample, puback_sequence: '1' } }] },
    { ...active, items: [{ ...active.items[0], sample: { ...sample, source: 'host_metric' } }] },
  ]) assertMonitoringContract(value, false, 'excess/false evidence')
})

test('safe revisions and lossless canonical int64 counters reject truncation and coercion', () => {
  for (const key of ['publication_sequence', 'probes_total', 'probe_failures_total']) {
    for (const invalid of [1, '01', '-1', '1.0', '1e3', '9223372036854775808', '9999999999999999999', '', null]) {
      assertMonitoringContract({ ...active, items: [{ ...active.items[0], sample: { ...sample, [key]: invalid } }] }, false, key)
    }
  }
  for (const key of ['config_revision', 'active_config_revision']) {
    for (const invalid of [0, -1, 1.5, '1', 9007199254740992]) {
      assertMonitoringContract({ ...active, items: [{ ...active.items[0], sample: { ...sample, [key]: invalid } }] }, false, key)
    }
  }
  assertMonitoringContract({ ...active, items: [{ ...active.items[0], sample: { ...sample, publication_sequence: '0' } }] }, false, 'positive publication')
})

test('invalid nullable combinations, bounds, states, UUID and UTC are rejected', () => {
  for (const configuration of [
    { ...empty.configuration, head_revision: 1 }, { ...empty.configuration, state: 'not_activated' },
    { ...empty.configuration, policy }, { ...active.configuration, activated_at: null },
    { ...active.configuration, active_revision: null }, { ...active.configuration, policy: null },
    { ...active.configuration, head_revision: 9007199254740992 },
  ]) assertMonitoringContract({ ...active, configuration }, false, 'configuration correlation')
  for (const changes of [
    { sample: null }, { freshness: 'not_reported' }, { freshness: 'unknown' }, { revision_state: 'online' },
    { node_id: '00000000-0000-0000-0000-000000000000' }, { node_id: id.toUpperCase() },
    { stale_after_ms: 0 }, { stale_after_ms: 390001 },
  ]) assertMonitoringContract({ ...active, items: [{ ...active.items[0], ...changes }] }, false, 'item shape')
  for (const observed_at of ['2026-10-10T08:00:00+08:00', 'yesterday', null]) assertMonitoringContract({ ...active, observed_at }, false, 'UTC read time')
  assertMonitoringContract({ ...active, items: [] }, false, 'nonempty exact request cover')
  assertMonitoringContract({ ...active, items: Array.from({ length: 301 }, () => active.items[0]) }, false, 'maximum batch')
})

test('per-node override items carry their own effective revision and policy', () => {
  const overridden = { ...active, items: [{ ...active.items[0], effective_revision: 3,
    effective_policy: { ...policy, requested_protocol: 'http', probe_timeout_ms: 5000 } }] }
  assertMonitoringContract(overridden, true, 'override item')
  const { effective_policy: _policy, ...revisionOnly } = overridden.items[0]
  assertMonitoringContract({ ...active, items: [revisionOnly] }, false, 'revision without policy')
  assertMonitoringContract({ ...active, items: [{ ...overridden.items[0], effective_revision: 0 }] }, false, 'positive revision')
})

test('override endpoints require node permissions, idempotency and bounded fields', () => {
  const route = document.paths['/v1/nodes/{id}/monitoring/override']
  assert.equal(route.get.operationId, 'getNodeMonitoringOverride')
  assert.equal(route.put.operationId, 'putNodeMonitoringOverride')
  assert.deepEqual(Object.keys(route.put.responses).sort(), ['200', '400', '401', '403', '404', '409', '422', '503'])
  assert.ok(route.put.parameters.some((parameter) => parameter.name === 'Idempotency-Key' && parameter.required))
  for (const fact of ['nodes.manage', 'serving', 'node.monitoring_override.update', 'monitor_action pause', 'recovery_threshold', 'probe_timeout_exceeds_interval']) {
    assert.ok(route.put.description.includes(fact), fact)
  }
  const request = ajv.compile({ ...schemas.NodeMonitoringOverrideRequest, components: { schemas } })
  const fields = { monitor_enabled: true, protocol: 'tcp', probe_timeout_ms: 5000, monitor_port: 80, monitor_action: null }
  assert.equal(request({ expected_revision: 0, override: fields }), true, JSON.stringify(request.errors))
  assert.equal(request({ expected_revision: 0, override: { ...fields, monitor_enabled: null, protocol: null, probe_timeout_ms: null, monitor_port: null } }), true)
  for (const invalid of [{ monitor_port: 0 }, { monitor_port: 65536 }, { probe_timeout_ms: 99 }, { probe_timeout_ms: 60001 }, { protocol: 'udp' }, { extra: 1 }]) {
    assert.equal(request({ expected_revision: 0, override: { ...fields, ...invalid } }), false, JSON.stringify(invalid))
  }
  assert.equal(request({ override: fields }), false, 'expected revision required')
})

test('held nodes report serving_holds and their transition log', () => {
  const hold = { source: 'availability_monitor', reason_code: 'probe_unhealthy', held_since: time, protected_groups: 0 }
  assertMonitoringContract({ ...active, items: [{ ...active.items[0], serving_holds: [hold] }] }, true, 'held node')
  assertMonitoringContract({ ...active, items: [{ ...active.items[0], serving_holds: [] }] }, false, 'empty holds are omitted')
  assertMonitoringContract({ ...active, items: [{ ...active.items[0], serving_holds: [{ ...hold, source: 'admin' }] }] }, false, 'unknown source')
  // 376 起保持来源为四种（availability_monitor/auto_disable/config_sync/external_probe），契约须与库约束一致。
  for (const source of ['config_sync', 'external_probe']) {
    assertMonitoringContract({ ...active, items: [{ ...active.items[0], serving_holds: [{ ...hold, source }] }] }, true, `hold source ${source}`)
  }
  const route = document.paths['/v1/nodes/{id}/serving/events'].get
  assert.equal(route.operationId, 'getNodeServingEvents')
  for (const fact of ['nodes.read', 'held', 'released', 'protected', 'auto_disable', 'node_monitoring_not_found']) {
    assert.ok(route.description.includes(fact), fact)
  }
  const page = ajv.compile({ ...schemas.NodeServingEventPage, components: { schemas } })
  const event = { id, source: 'availability_monitor', event: 'held', reason_code: 'probe_stale', hold_revision: 1, detail: {}, occurred_at: time }
  const value = { schema_version: 1, node_id: id, from: time, to: time, page: 1, limit: 10, total: 1, items: [event] }
  assert.equal(page(value), true, JSON.stringify(page.errors))
  assert.equal(page({ ...value, items: [{ ...event, event: 'paused' }] }), false)
  for (const source of ['config_sync', 'external_probe']) {
    assert.equal(page({ ...value, items: [{ ...event, source }] }), true, `event source ${source}`)
  }
  assert.equal(page({ ...value, items: [{ ...event, source: 'admin' }] }), false)
})

test('probe-node: dnspup checkpoint log and node probe settings', () => {
  const history = document.paths['/v1/nodes/{id}/monitoring/history'].get
  assert.equal(history.operationId, 'getNodeMonitoringHistory')
  for (const fact of ['nodes.read', 'source=dnspup', 'group', 'node_monitoring_not_found']) {
    assert.ok(history.description.includes(fact), fact)
  }
  const page = ajv.compile({ ...schemas.NodeDNSPupHistoryPage, components: { schemas } })
  const item = { observed_at: time, address: '198.51.100.7', port: 443, failed: true, failed_checks: 2, total_checks: 3,
    checkpoints: [{ id: 't1', group: 'telecom', ok: false }] }
  const value = { schema_version: 1, source: 'dnspup', node_id: id, group: '', from: time, to: time, page: 1, limit: 10, total: 1, items: [item] }
  assert.equal(page(value), true, JSON.stringify(page.errors))
  assert.equal(page({ ...value, group: 'bgp' }), false)
  assert.equal(page({ ...value, items: [{ ...item, checkpoints: [{ id: 't1', group: 'telecom', ok: false, extra: 1 }] }] }), false)
  const settingsRoute = document.paths['/v1/admin/probe-dnspup/node-monitoring']
  for (const fact of ['system.probe_dnspup.manage', 'balance_unit', 'request']) {
    assert.ok(settingsRoute.get.description.includes(fact), fact)
  }
  const settings = ajv.compile({ ...schemas.DNSPupNodeMonitoringSettings, components: { schemas } })
  const body = { interval_seconds: 300, groups: ['telecom', 'unicom', 'mobile'], points_per_group: 3, failure_percent: 50,
    failure_rounds: 3, recovery_rounds: 1, low_balance: 1000 }
  assert.equal(settings(body), true, JSON.stringify(settings.errors))
  assert.equal(settings({ ...body, interval_seconds: 120 }), false)
  assert.equal(settings({ ...body, failure_percent: 100 }), false)
  assert.equal(settings({ ...body, groups: [] }), false)
})

test('scope-wide switch log lists real serving events with node identity and filters (A10/N06)', () => {
  const route = document.paths['/v1/nodes/serving/events'].get
  assert.equal(route.operationId, 'listScopeNodeServingEvents')
  assert.deepEqual(route.parameters.map((parameter) => parameter.name), ['from', 'to', 'page', 'limit', 'source', 'event', 'node_id', 'ip'])
  const page = document.components.schemas.NodeScopeServingEventPage
  assert.equal(page.additionalProperties, false)
  const item = page.properties.items.items
  for (const field of ['node_id', 'node_name', 'ipv4', 'ipv6', 'source', 'event', 'reason_code', 'occurred_at']) assert.ok(item.required.includes(field), field)
  assert.deepEqual(document.components.schemas.NodeServingEventSource.enum, ['availability_monitor', 'auto_disable', 'config_sync', 'external_probe'])
  assert.equal(route.responses['404'], undefined)
  const validate = ajv.compile({ ...page, components: { schemas } })
  const event = { id, source: 'config_sync', event: 'released', reason_code: 'probe_recovered', hold_revision: 2, detail: {}, occurred_at: time,
    node_id: id, node_name: 'edge-1', ipv4: '192.0.2.10', ipv6: '' }
  const value = { schema_version: 1, from: time, to: time, page: 1, limit: 10, total: 1, items: [event] }
  assert.equal(validate(value), true, JSON.stringify(validate.errors))
  assert.equal(validate({ ...value, items: [] , total: 0 }), true)
  assert.equal(validate({ ...value, items: [{ ...event, node_name: undefined }] }), false)
})
