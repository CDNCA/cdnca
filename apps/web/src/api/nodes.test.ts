import { describe, expect, it, vi } from 'vitest'

import { nativeRuntimeSummary, nodesApi, type NodeInventoryItem } from './nodes'
import { nodeManagementSettingsFixture } from '../test/fixtures'

const nodeID = '018f0000-0000-7000-8000-000000000001'
const inventory: NodeInventoryItem = {
  id: nodeID,
  display_id: '1',
  name: 'Shanghai edge',
  description: 'Primary edge node',
  region: 'CN-East',
  ipv4: '192.0.2.10',
  ipv6: '2001:db8::10',
  admin_state: 'active',
  management_settings: nodeManagementSettingsFixture(),
  revision: 4,
  created_at: '2026-08-01T08:00:00Z',
  updated_at: '2026-08-01T09:00:00Z',
  presence: {
    status: 'online',
    last_heartbeat_at: '2026-08-01T08:59:55Z',
    agent_version: '2.4.1',
    session_epoch: 7,
    heartbeat_sequence: 11,
    projection_freshness: 'fresh',
    lease_signal: 'present',
    projected_at: '2026-08-01T08:59:56Z',
  },
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('node network inventory contract', function nodeNetworkInventoryContract() {
  const report = { schema_version: 1, ipv4_state: 'verified', ipv6_state: 'peer_mismatch', received_at: '2026-08-01T09:00:00Z' }

  it.each<[string, unknown]>([
    ['legacy control', inventory],
    ['legacy empty IPs', { ...inventory, ipv4: undefined, ipv6: undefined }],
    ['manual IPs without a report', { ...inventory, network_inventory: { schema_version: 1, ipv4_state: 'not_reported', ipv6_state: 'not_reported' } }],
    ['empty IPs without a report', { ...inventory, ipv4: undefined, ipv6: undefined, network_inventory: { schema_version: 1, ipv4_state: 'not_reported', ipv6_state: 'not_reported' } }],
    ['IPv4 only', { ...inventory, ipv6: undefined, network_inventory: { ...report, ipv6_state: 'no_global_address' } }],
    ['IPv6 only', { ...inventory, ipv4: undefined, network_inventory: { ...report, ipv4_state: 'no_global_address', ipv6_state: 'verified' } }],
    ['two addresses but only IPv4 verified', { ...inventory, network_inventory: report }],
    ['two independently verified addresses', { ...inventory, network_inventory: { ...report, ipv6_state: 'verified' } }],
    ...['verified', 'address_conflict', 'peer_mismatch', 'no_default_route', 'no_global_address', 'ambiguous_route', 'unavailable'].map((state): [string, unknown] => [
      state, { ...inventory, network_inventory: { ...report, ipv4_state: state } },
    ]),
  ])('preserves %s on both list and detail reads without synthesizing addresses or states', async (_name, value) => {
    const expected = JSON.parse(JSON.stringify(value))
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(value)).mockResolvedValueOnce(json({ items: [value] }))
    await expect(nodesApi.get('node-detail-token', nodeID)).resolves.toEqual(expected)
    await expect(nodesApi.list('node-list-token', { limit: 1 })).resolves.toEqual({ items: [expected] })
  })

  it.each([
    ['null report', null], ['array report', []],
    ['unknown schema', { ...report, schema_version: 2 }],
    ['zero schema', { ...report, schema_version: 0 }],
    ['string schema', { ...report, schema_version: '1' }],
    ['unknown IPv4 state', { ...report, ipv4_state: 'reachable' }],
    ['unknown IPv6 state', { ...report, ipv6_state: 'healthy' }],
    ['missing IPv6 state', { ...report, ipv6_state: undefined }],
    ['raw reason', { ...report, reason: 'untrusted-server-reason' }],
    ['private peer', { ...report, peer: '192.0.2.99' }],
    ['missing received time', { ...report, received_at: undefined }],
    ['null received time', { ...report, received_at: null }],
    ['zero received time', { ...report, received_at: 0 }],
    ['invalid received time', { ...report, received_at: 'not-a-time' }],
    ['unreported with time', { ...report, ipv4_state: 'not_reported', ipv6_state: 'not_reported' }],
    ['mixed unreported IPv4', { ...report, ipv4_state: 'not_reported' }],
    ['mixed unreported IPv6', { ...report, ipv6_state: 'not_reported' }],
  ])('rejects %s rather than displaying unsupported evidence', async (_name, network_inventory) => {
    const value = { ...inventory, network_inventory }
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(value)).mockResolvedValueOnce(json({ items: [value] }))
    await expect(nodesApi.get('node-detail-token', nodeID)).rejects.toMatchObject({ status: 200, code: 'invalid_response' })
    await expect(nodesApi.list('node-list-token', { limit: 1 })).rejects.toMatchObject({ status: 200, code: 'invalid_response' })
  })

  it.each(['ipv4', 'ipv6'] as const)('rejects a verified %s family without its current inventory address', async (family) => {
    const value = { ...inventory, [family]: undefined, network_inventory: { ...report, ipv6_state: 'verified' } }
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(value)).mockResolvedValueOnce(json({ items: [value] }))
    await expect(nodesApi.get('node-detail-token', nodeID)).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(nodesApi.list('node-list-token', { limit: 1 })).rejects.toMatchObject({ code: 'invalid_response' })
  })
})

describe('nodesApi.get', () => {
  it('uses the mounted inventory route and returns a strictly parsed node', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(inventory))

    await expect(nodesApi.get('node-detail-token', nodeID)).resolves.toEqual(inventory)

    expect(fetchSpy).toHaveBeenCalledOnce()
    const [url, init] = fetchSpy.mock.calls[0]!
    expect(url).toBe(`/v1/nodes/${nodeID}`)
    expect(init?.credentials).toBe('include')
    expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer node-detail-token')
  })

  it.each(['probe_only', 'join_market', 'disabled'] as const)('accepts market probe role %s', async (role) => {
    const withRole = { ...inventory, presence: { ...inventory.presence, market_probe_role: role } }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(withRole))

    await expect(nodesApi.get('node-detail-token', nodeID)).resolves.toEqual(withRole)
  })

  it('accepts the OpenResty runtime version of the confirmed session', async () => {
    const withRuntime = { ...inventory, presence: { ...inventory.presence, openresty_version: '1.31.1.1' } }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(withRuntime))

    await expect(nodesApi.get('node-detail-token', nodeID)).resolves.toEqual(withRuntime)
  })

  it('accepts the native runtime switch outcome of the latest heartbeat', async () => {
    const withNative = { ...inventory, presence: { ...inventory.presence,
      native_runtime_state: 'rolled_back', native_runtime_release: 'b'.repeat(64),
      native_runtime_previous_release: 'a'.repeat(64), native_runtime_error_code: 'RUNTIME_PRECHECK_FAILED' } }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(withNative))

    await expect(nodesApi.get('node-detail-token', nodeID)).resolves.toEqual(withNative)
  })

  it('rejects an invalid node identifier before making a request', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    await expect(nodesApi.get('node-detail-token', 'not-a-node')).rejects.toMatchObject({
      status: 400,
      code: 'validation_error',
    })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('rejects a valid node response bound to a different route identifier', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      ...inventory,
      id: '018f0000-0000-7000-8000-000000000002',
    }))

    await expect(nodesApi.get('node-detail-token', nodeID)).rejects.toMatchObject({
      status: 200,
      code: 'invalid_response',
    })
  })

  it.each([
    { ...inventory, tenant_id: nodeID },
    { ...inventory, id: 'not-a-uuid' },
    { ...inventory, display_id: undefined },
    { ...inventory, display_id: '0' },
    { ...inventory, display_id: '01' },
    { ...inventory, display_id: '10000000000000000000' },
    { ...inventory, display_id: 1 },
    { ...inventory, name: '' },
    { ...inventory, admin_state: 'enabled' },
    { ...inventory, management_settings: { ...inventory.management_settings, schema_version: 2 } },
    { ...inventory, management_settings: { ...inventory.management_settings, secondary_ips: ['not-an-ip'] } },
    { ...inventory, management_settings: { ...inventory.management_settings, external_probe: 'yes' } },
    { ...inventory, revision: 0 },
    { ...inventory, created_at: 'not-a-time' },
    { ...inventory, presence: { ...inventory.presence, status: 'healthy' } },
    { ...inventory, presence: { ...inventory.presence, session_epoch: 0 } },
    { ...inventory, presence: { ...inventory.presence, heartbeat_sequence: undefined } },
    { ...inventory, presence: { ...inventory.presence, agent_version: 'bad version' } },
    { ...inventory, presence: { ...inventory.presence, projection_freshness: 'current' } },
    { ...inventory, presence: { ...inventory.presence, lease_signal: 'valid' } },
    { ...inventory, presence: { ...inventory.presence, market_probe_role: 'market' } },
    { ...inventory, presence: { ...inventory.presence, openresty_version: '' } },
    { ...inventory, presence: { ...inventory.presence, openresty_version: 1 } },
    { ...inventory, presence: { ...inventory.presence, openresty_version: 'x'.repeat(129) } },
    { ...inventory, presence: { ...inventory.presence, native_runtime_state: 'failed' } },
    { ...inventory, presence: { ...inventory.presence, native_runtime_release: 'a'.repeat(64) } },
    { ...inventory, presence: { ...inventory.presence, native_runtime_state: 'switched', native_runtime_release: 'A'.repeat(64) } },
    { ...inventory, presence: { ...inventory.presence, native_runtime_state: 'switched', native_runtime_error_code: 'RUNTIME_SWITCH_FAILED' } },
    { ...inventory, presence: { ...inventory.presence, native_runtime_state: 'rolled_back', native_runtime_error_code: 'bad' } },
  ])('rejects malformed inventory response %#', async (invalid) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(invalid))

    await expect(nodesApi.get('node-detail-token', nodeID)).rejects.toMatchObject({
      status: 200,
      code: 'invalid_response',
    })
  })
})

describe('nodesApi.list', () => {
  const second = { ...inventory, id: '018f0000-0000-7000-8000-000000000002', display_id: '2', name: 'Beijing edge' }

  it('returns a strictly parsed stable node page', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      items: [inventory, second],
      next_cursor: second.id,
    }))

    await expect(nodesApi.list('node-list-token', { limit: 2 })).resolves.toEqual({
      items: [inventory, second],
      next_cursor: second.id,
    })
    expect(fetchSpy).toHaveBeenCalledWith('/v1/nodes?limit=2', expect.objectContaining({
      credentials: 'include',
      headers: expect.objectContaining({ Authorization: 'Bearer node-list-token' }),
    }))
  })

  it('serializes a trimmed optional search and omits a blank search', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [inventory] }))

    await nodesApi.list('node-list-token', { limit: 20, search: '  Shanghai edge  ' })
    await nodesApi.list('node-list-token', { limit: 20, search: '   ' })

    expect(fetchSpy.mock.calls[0]?.[0]).toBe('/v1/nodes?limit=20&search=Shanghai+edge')
    expect(fetchSpy.mock.calls[1]?.[0]).toBe('/v1/nodes?limit=20')
  })

  it.each([
    ['missing items', {}],
    ['unknown envelope fact', { items: [inventory], page: 1 }],
    ['non-array items', { items: inventory }],
    ['malformed inventory fact', { items: [{ ...inventory, revision: 0 }] }],
    ['duplicate node ID', { items: [inventory, { ...inventory }] }],
    ['duplicate node display ID', { items: [inventory, { ...second, display_id: inventory.display_id }] }],
    ['invalid next cursor', { items: [inventory], next_cursor: 'not-a-node' }],
    ['cursor not bound to the final item', { items: [inventory, second], next_cursor: inventory.id }],
  ])('rejects %s', async (_name, value) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(value))

    await expect(nodesApi.list('node-list-token', { limit: 20 })).rejects.toMatchObject({
      status: 200,
      code: 'invalid_response',
    })
  })

  it('rejects a response that exceeds the requested page size', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [inventory, second] }))

    await expect(nodesApi.list('node-list-token', { limit: 1 })).rejects.toMatchObject({
      status: 200,
      code: 'invalid_response',
    })
  })
})

describe('nodesApi.getLatestMetrics', () => {
  const metrics = {
    node_id: nodeID,
    node_name: 'Shanghai edge',
    config_revision: 7,
    active_config_revision: 7,
    publication_sequence: 41,
    observed_at: '2026-08-01T09:00:00Z',
    probe_port: 8443,
    healthy: false,
    probe_succeeded: true,
    consecutive_failures: 0,
    consecutive_successes: 2,
    probes_total: 9,
    probe_failures_total: 4,
    recovered: false,
    recovery_notified: false,
    rolled_back: false,
    known: true,
    cpu_percent: 25,
    memory_used_bytes: 512,
    memory_total_bytes: 1024,
    active_connections: 8,
    rx_bandwidth_bps: 1600,
    tx_bandwidth_bps: 800,
    total_rx_bytes: null,
    total_tx_bytes: null,
    puback_stream: 'NODE_MONITORING_STATUS',
    puback_sequence: 91,
    consumer_durable: 'control_api_node_metrics',
    consumer_sequence: 17,
    ingested_at: '2026-08-01T09:00:01Z',
    latest_recovery: {
      config_revision: 6,
      publication_sequence: 40,
      recovered_at: '2026-08-01T08:58:00Z',
      reason_code: 'probe_recovered',
      puback_stream: 'NODE_MONITORING_STATUS',
      puback_sequence: 90,
    },
  } as const

  it('returns strictly bound probe, raw metric, and recovery evidence', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(metrics))

    await expect(nodesApi.getLatestMetrics('node-metrics-token', nodeID)).resolves.toEqual(metrics)
    expect(fetchSpy).toHaveBeenCalledWith(`/v1/nodes/${nodeID}/metrics/latest`, expect.objectContaining({
      credentials: 'include',
      headers: expect.objectContaining({ Authorization: 'Bearer node-metrics-token' }),
    }))
  })

  it.each([
    [{ source: 'default_route', interfaces: ['ens17'] }, true],
    [{ source: 'unavailable', interfaces: [] }, true],
    [{ source: 'default_route', interfaces: ['docker0'] }, false],
    [{ source: 'default_route', interfaces: ['ens17', 'ens17'] }, false],
    [{ source: 'default_route', interfaces: [] }, false],
    [{ source: 'unavailable', interfaces: ['ens17'] }, false],
    [{ source: 'guess', interfaces: ['ens17'] }, false],
  ])('validates egress metadata against the same sample NICs %#', async (selection, valid) => {
    const response = { ...metrics, telemetry: {
      schema_version: 1, disks: [], total_rx_bytes: 100, total_tx_bytes: 200,
      network_interfaces: [{ name: 'ens17', rx_bytes: 100, tx_bytes: 200, rx_bandwidth_bps: 800, tx_bandwidth_bps: 1600 }],
      network_selection: selection,
    }, total_rx_bytes: 100, total_tx_bytes: 200 }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))
    const result = nodesApi.getLatestMetrics('node-metrics-token', nodeID)
    if (valid) await expect(result).resolves.toEqual(response)
    else await expect(result).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each([
    [[{ kind: 'ct_invalid', packets: 3, bytes: 120 }, { kind: 'tcp_xmas', packets: 1, bytes: 40 }], true],
    [[], true],
    [[{ kind: 'tcp_xmas', packets: 1, bytes: 40 }, { kind: 'ct_invalid', packets: 3, bytes: 120 }], false],
    [[{ kind: 'tcp_null', packets: 1, bytes: 40 }, { kind: 'tcp_null', packets: 1, bytes: 40 }], false],
    [[{ kind: 'tcp_ack', packets: 1, bytes: 40 }], false],
    [[{ kind: 'tcp_null', packets: -1, bytes: 40 }], false],
    [[{ kind: 'tcp_null', packets: 1 }], false],
  ])('validates the DDoS drop counters %#', async (drops, valid) => {
    const response = { ...metrics, telemetry: {
      schema_version: 1, disks: [], total_rx_bytes: 100, total_tx_bytes: 200, network_interfaces: [], ddos_drops: drops,
    }, total_rx_bytes: 100, total_tx_bytes: 200 }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))
    const result = nodesApi.getLatestMetrics('node-metrics-token', nodeID)
    if (valid) await expect(result).resolves.toEqual(response)
    else await expect(result).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each([
    [{ site_ids: ['11111111-1111-4111-8111-111111111111'], packets: 5, bytes: 300 }, true],
    [{ site_ids: [], packets: 5, bytes: 300 }, false],
    [{ site_ids: ['22222222-2222-4222-8222-222222222222', '11111111-1111-4111-8111-111111111111'], packets: 1, bytes: 60 }, false],
    [{ site_ids: ['not-a-uuid'], packets: 1, bytes: 60 }, false],
    [{ site_ids: ['11111111-1111-4111-8111-111111111111'], packets: 1 }, false],
  ])('validates the site drop delta %#', async (drop, valid) => {
    const response = { ...metrics, telemetry: {
      schema_version: 1, disks: [], total_rx_bytes: 100, total_tx_bytes: 200, network_interfaces: [], site_drop: drop,
    }, total_rx_bytes: 100, total_tx_bytes: 200 }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))
    const result = nodesApi.getLatestMetrics('node-metrics-token', nodeID)
    if (valid) await expect(result).resolves.toEqual(response)
    else await expect(result).rejects.toMatchObject({ code: 'invalid_response' })
  })

  // The node DDoS protection state (failed / unavailable = protection fault).
  it.each([
    [{ state: 'applied' }, true],
    [{ state: 'pending' }, true],
    [{ state: 'failed', detail: 'nft: Error: Could not process rule' }, true],
    [{ state: 'unavailable', reason: 'nft_missing', detail: 'nft command not found: install nftables' }, true],
    [{ state: 'unavailable' }, false],
    [{ state: 'unavailable', reason: 'gone' }, false],
    [{ state: 'applied', reason: 'nft_missing' }, false],
    [{ state: 'off', detail: 'x' }, false],
    [{ state: 'failed', detail: 'a\nb' }, false],
    [{ state: 'degraded' }, false],
    [{ state: 'applied', extra: true }, false],
  ])('validates the DDoS protection state %#', async (protection, valid) => {
    const response = { ...metrics, telemetry: {
      schema_version: 1, disks: [], total_rx_bytes: 100, total_tx_bytes: 200, network_interfaces: [], ddos_protection: protection,
    }, total_rx_bytes: 100, total_tx_bytes: 200 }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))
    const result = nodesApi.getLatestMetrics('node-metrics-token', nodeID)
    if (valid) await expect(result).resolves.toEqual(response)
    else await expect(result).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each([
    [{ telemetry_detail: true, mounts: [{ path: '/', device: '8:1', fstype: 'ext4', read_only: false, bind: false },
      { path: '/etc', device: '8:1', fstype: 'ext4', read_only: false, bind: true, filter_reason: 'bind_duplicate' }],
    port_group_overrides: [{ port_group_id: 'web-tcp', state: 'inactive', reason: 'manual' }] }, true],
    [{ telemetry_detail: 'yes' }, false],
    [{ mounts: [{ path: '/', device: 'sda', fstype: 'ext4', read_only: false, bind: false }] }, false],
    [{ mounts: [{ path: '/', device: '8:1', fstype: 'ext4', read_only: false, bind: false, filter_reason: 'other' }] }, false],
    [{ port_group_overrides: [{ port_group_id: 'web-tcp', state: 'inactive' }] }, false],
    [{ port_group_overrides: [{ port_group_id: 'web-tcp', state: 'applied', reason: 'manual' }] }, false],
  ])('validates the telemetry detail (mounts, port group overrides) %#', async (detail, valid) => {
    const { telemetry_detail: flag, ...telemetryDetail } = detail as Record<string, unknown>
    const response = { ...metrics, ...(flag === undefined ? {} : { telemetry_detail: flag }), telemetry: {
      schema_version: 1, disks: [], total_rx_bytes: 100, total_tx_bytes: 200, network_interfaces: [], ...telemetryDetail,
    }, total_rx_bytes: 100, total_tx_bytes: 200 }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))
    const result = nodesApi.getLatestMetrics('node-metrics-token', nodeID)
    if (valid) await expect(result).resolves.toEqual(response)
    else await expect(result).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('accepts host-only counters without claiming an active probe policy', async () => {
    const host = { ...metrics, record_kind: 'host_metric', config_revision: 0, active_config_revision: 0,
      probe_port: 0, healthy: false, probe_succeeded: false, consecutive_successes: 0,
      probes_total: 0, probe_failures_total: 0 }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(host))
    await expect(nodesApi.getLatestMetrics('node-metrics-token', nodeID)).resolves.toEqual(host)
  })

  it.each([
    { config_revision: 1 }, { active_config_revision: 1 }, { probe_port: 80 },
    { healthy: true }, { probe_succeeded: true }, { probes_total: 1 }, { known: false },
  ])('rejects fabricated probe evidence on host-only counters %#', async (extra) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ ...metrics, record_kind: 'host_metric',
      config_revision: 0, active_config_revision: 0, probe_port: 0, healthy: false,
      probe_succeeded: false, consecutive_successes: 0, probes_total: 0, probe_failures_total: 0, ...extra }))
    await expect(nodesApi.getLatestMetrics('node-metrics-token', nodeID)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each([
    { ...metrics, node_id: '018f0000-0000-7000-8000-000000000002' },
    { ...metrics, probe_port: 0 },
    { ...metrics, probe_failures_total: 10 },
    { ...metrics, cpu_percent: 101 },
    { ...metrics, latest_recovery: { ...metrics.latest_recovery, reason_code: 'raw-internal-error' } },
    { ...metrics, private_fact: 'must fail closed' },
  ])('rejects malformed or unbound metric response %#', async (value) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(value))

    await expect(nodesApi.getLatestMetrics('node-metrics-token', nodeID)).rejects.toMatchObject({
      status: 200,
      code: 'invalid_response',
    })
  })
})

describe('nodesApi.getLatestMetricsBatch', function nodeMetricsLatestBatchRegression() {
  const otherID = '018f0000-0000-7000-8000-000000000002'
  const metric = {
    record_kind: 'host_metric', node_id: nodeID, node_name: 'Edge one',
    config_revision: 0, active_config_revision: 0, publication_sequence: 1,
    observed_at: '2026-10-10T10:00:00Z', ingested_at: '2026-10-10T10:00:01Z',
    probe_port: 0, healthy: false, probe_succeeded: false, consecutive_failures: 0,
    consecutive_successes: 0, probes_total: 0, probe_failures_total: 0,
    recovered: false, recovery_notified: false, rolled_back: false, known: true,
    cpu_percent: 0, memory_used_bytes: 0, memory_total_bytes: 1, active_connections: 0,
    rx_bandwidth_bps: 0, tx_bandwidth_bps: 0, total_rx_bytes: null, total_tx_bytes: null,
    puback_stream: 'NODE_MONITORING_STATUS', puback_sequence: 1,
    consumer_durable: 'control_api_node_metrics', consumer_sequence: 1,
  }
  const response = { observed_at: '2026-10-10T10:00:02Z', items: [metric], not_reported_node_ids: [otherID] }

  it('makes one bounded abortable batch request and preserves missing samples separately from zero', async () => {
    const controller = new AbortController()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))
    await expect(nodesApi.getLatestMetricsBatch('batch-token', [nodeID, otherID], controller.signal)).resolves.toEqual(response)
    expect(fetchSpy).toHaveBeenCalledOnce()
    expect(fetchSpy).toHaveBeenCalledWith(`/v1/nodes/metrics/latest?node_id=${nodeID}&node_id=${otherID}`, expect.objectContaining({
      signal: controller.signal, cache: 'no-store', credentials: 'include',
      headers: expect.objectContaining({ Authorization: 'Bearer batch-token' }),
    }))
  })

  it.each([
    [], [nodeID, nodeID], ['not-a-node'],
    Array.from({ length: 301 }, (_, index) => `018f0000-0000-7000-8000-${String(index).padStart(12, '0')}`),
  ].map((ids) => [ids]))('rejects invalid or oversized input before fetching %#', async (ids) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(nodesApi.getLatestMetricsBatch('batch-token', ids)).rejects.toMatchObject({ status: 400, code: 'validation_error' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    null, [], { ...response, extra: true }, { ...response, observed_at: 'bad' },
    { ...response, observed_at: '2026-10-10T12:00:02+02:00' },
    { ...response, items: [] }, { ...response, not_reported_node_ids: [] },
    { ...response, items: [metric, metric] },
    { ...response, not_reported_node_ids: [otherID, otherID] },
    { ...response, not_reported_node_ids: [nodeID] },
    { ...response, items: [{ ...metric, node_id: '018f0000-0000-7000-8000-000000000003' }] },
    { ...response, not_reported_node_ids: ['018f0000-0000-7000-8000-000000000003'] },
    { ...response, items: [{ ...metric, known: false }] },
    { ...response, items: [{ ...metric, healthy: true }] },
    { ...response, items: [{ ...metric, cpu_percent: 101 }] },
  ])('rejects malformed, duplicated, omitted, or unbound response %#', async (value) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(value))
    await expect(nodesApi.getLatestMetricsBatch('batch-token', [nodeID, otherID])).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('accepts exactly 300 known nodes without samples', async () => {
    const ids = Array.from({ length: 300 }, (_, index) => `018f0000-0000-7000-8000-${String(index).padStart(12, '0')}`)
    const value = { observed_at: response.observed_at, items: [], not_reported_node_ids: ids }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(value))
    await expect(nodesApi.getLatestMetricsBatch('batch-token', ids)).resolves.toEqual(value)
  })

  it.each([[400, 'validation_error'], [403, 'forbidden'], [404, 'node_metrics_not_found'], [503, 'node_metrics_unavailable']] as const)(
    'preserves the %s stable failure without inventing zero samples', async (status, code) => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ error: { code, message: 'private internal detail' } }, status))
      await expect(nodesApi.getLatestMetricsBatch('batch-token', [nodeID])).rejects.toMatchObject({ status, code })
    },
  )
})

describe('nodesApi.getMetricsHistory', () => {
  const point = {
    node_id: nodeID,
    node_name: 'Shanghai edge',
    publication_sequence: 41,
    observed_at: '2026-08-01T09:00:00Z',
    known: true,
    cpu_percent: 25,
    memory_used_bytes: 512,
    memory_total_bytes: 1024,
    active_connections: 8,
    rx_bandwidth_bps: 1600,
    tx_bandwidth_bps: 800,
    total_rx_bytes: null,
    total_tx_bytes: null,
  } as const

  it('serializes a bounded time window and accepts ascending durable points', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [point] }))
    const params = { from: '2026-08-01T08:00:00Z', to: '2026-08-01T09:00:00Z', limit: 240 }

    await expect(nodesApi.getMetricsHistory('node-history-token', nodeID, params)).resolves.toEqual({ items: [point] })
    expect(fetchSpy).toHaveBeenCalledWith(
      `/v1/nodes/${nodeID}/metrics/history?from=2026-08-01T08%3A00%3A00Z&to=2026-08-01T09%3A00%3A00Z&limit=240`,
      expect.objectContaining({ credentials: 'include' }),
    )
  })

  it.each([
    { items: [{ ...point, node_id: '018f0000-0000-7000-8000-000000000002' }] },
    { items: [{ ...point, private_fact: true }] },
    { items: [{ ...point, known: false }] },
    { items: [{ ...point }, { ...point, publication_sequence: 40 }] },
  ])('rejects malformed history response %#', async (value) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(value))
    await expect(nodesApi.getMetricsHistory('node-history-token', nodeID, {
      from: '2026-08-01T08:00:00Z', to: '2026-08-01T09:00:00Z', limit: 240,
    })).rejects.toMatchObject({ status: 200, code: 'invalid_response' })
  })

  it('rejects an invalid range before making a request', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(nodesApi.getMetricsHistory('node-history-token', nodeID, {
      from: '2026-08-01T09:00:00Z', to: '2026-08-01T08:00:00Z', limit: 240,
    })).rejects.toMatchObject({ status: 400, code: 'validation_error' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})

describe('nodesApi realtime compatibility endpoints', () => {
  it('reads the observed ranking projection with strict fields', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      data: [{ inbound: 1500, nic: 'eth0', node_id: nodeID, node_name: 'Shanghai edge', outbound: 800 }],
      msg: '',
      code: 0,
    }))

    await expect(nodesApi.getNodeRealtimeTop('node-realtime-token', {
      recentTime: '5m', type: 'bandwidth', limit: 10,
    })).resolves.toMatchObject({ code: 0, data: [{ node_id: nodeID }] })
    expect(fetchSpy).toHaveBeenCalledWith('/v1/monitor/node/top?recent_time=5m&type=bandwidth&limit=10', expect.anything())
  })

  it('reads per-NIC series and interval traffic using the competitor query names', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({
        data: { eth0: [{ name: 'inbound', data: [[1722502800000, 1500], [1722502860000, 1800]] }] },
        msg: '',
        code: 0,
      }))
      .mockResolvedValueOnce(json({
        count: 1,
        data: [{ bytes_received: 120, bytes_sent: 240, create_at: '2026-08-01 09:00:00' }],
        msg: '',
        code: 0,
      }))

    await expect(nodesApi.getNodeRealtimeSeries('node-realtime-token', {
      node: nodeID, type: 'bandwidth', start: '2026-08-01T08:00:00Z', end: '2026-08-01T09:00:00Z', limit: 20,
    })).resolves.toMatchObject({ data: { eth0: [{ name: 'inbound' }] } })
    await expect(nodesApi.getNodeTraffic('node-realtime-token', {
      node: nodeID, start: '2026-08-01T08:00:00Z', end: '2026-08-01T09:00:00Z', excludedNIC: ' lo, docker0 ', limit: 20,
    })).resolves.toMatchObject({ count: 1, data: [{ bytes_sent: 240 }] })
    expect(fetchSpy.mock.calls[0]?.[0]).toBe('/v1/monitor/node/realtime?type=bandwidth&start=2026-08-01T08%3A00%3A00Z&end=2026-08-01T09%3A00%3A00Z&node=018f0000-0000-7000-8000-000000000001&limit=20')
    expect(fetchSpy.mock.calls[1]?.[0]).toBe('/v1/node-traffic?start=2026-08-01T08%3A00%3A00Z&end=2026-08-01T09%3A00%3A00Z&node=018f0000-0000-7000-8000-000000000001&excl_nic=lo%2C+docker0&limit=20')
  })

  it('rejects malformed compatibility data and invalid request windows', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      data: [{ inbound: -1, nic: 'eth0', node_id: nodeID, node_name: 'Shanghai edge', outbound: 800 }],
      msg: '',
      code: 0,
    }))
    await expect(nodesApi.getNodeRealtimeTop('node-realtime-token', { type: 'bandwidth' })).rejects.toMatchObject({
      status: 200, code: 'invalid_response',
    })
    await expect(nodesApi.getNodeTraffic('node-realtime-token', {
      node: nodeID, start: '2026-08-01T09:00:00Z', end: '2026-08-01T08:00:00Z',
    })).rejects.toMatchObject({ status: 400, code: 'validation_error' })
  })
})

describe('nodesApi gateway port transitions', () => {
  const transition = {
    id: '018f0000-0000-7000-8000-000000000010',
    scope_id: '018f0000-0000-7000-8000-000000000011',
    node_id: nodeID,
    revision: 1,
    expected_node_revision: 4,
    old_endpoint: { address: 'gateway.example.com:7443', server_name: 'gateway.example.com', listen_address: '0.0.0.0:7443' },
    new_endpoint: { address: 'gateway.example.com:8443', server_name: 'gateway.example.com', listen_address: '0.0.0.0:8443' },
    compatibility_deadline: '2026-08-01T09:30:00Z',
    rollback_deadline: '2026-08-01T10:00:00Z',
    state: 'preparing',
    status_revision: 0,
    active_endpoint: { address: 'gateway.example.com:7443', server_name: 'gateway.example.com', listen_address: '0.0.0.0:7443' },
    error_code: '',
    created_at: '2026-08-01T09:00:00Z',
    updated_at: '2026-08-01T09:00:00Z',
  } as const

  it('creates and strictly parses a transition', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(transition, 201))
    await expect(nodesApi.createGatewayPortTransition('node-transition-token', nodeID, {
      expected_node_revision: 4, old_endpoint: transition.old_endpoint, new_endpoint: transition.new_endpoint,
      compatibility_deadline: transition.compatibility_deadline, rollback_deadline: transition.rollback_deadline,
    }, 'node-transition-create')).resolves.toEqual(transition)
    expect(fetchSpy).toHaveBeenCalledWith(`/v1/nodes/${nodeID}/gateway-port-transitions`, expect.objectContaining({ method: 'POST' }))
  })

  it.each([
    { ...transition, private_fact: true },
    { ...transition, node_id: '018f0000-0000-7000-8000-000000000002' },
    { ...transition, active_endpoint: { ...transition.active_endpoint, address: '' } },
  ])('rejects malformed transition response %#', async (value) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(value))
    await expect(nodesApi.getGatewayPortTransition('node-transition-token', nodeID, transition.id)).rejects.toMatchObject({
      status: 200, code: 'invalid_response',
    })
  })

  it('uses distinct durable action routes', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ ...transition, state: 'switched' }, 202))
    await nodesApi.gatewayPortTransitionAction('node-transition-token', nodeID, transition.id, 'finalize', '018f0000-0000-7000-8000-000000000012')
    expect(fetchSpy).toHaveBeenCalledWith(`/v1/nodes/${nodeID}/gateway-port-transitions/${transition.id}/finalize`, expect.objectContaining({ method: 'POST' }))
  })

  it.each(['finalize', 'rollback'] as const)('retains the %s request identity after a network failure', async (action) => {
    const key = '018f0000-0000-7000-8000-000000000012'
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(new TypeError('Failed to fetch'))
      .mockResolvedValueOnce(json({ ...transition, state: 'switched' }, 202))

    await expect(nodesApi.gatewayPortTransitionAction('node-transition-token', nodeID, transition.id, action, key))
      .rejects.toMatchObject({ code: 'network_error' })
    expect(fetchSpy).toHaveBeenCalledOnce()
    await nodesApi.gatewayPortTransitionAction('node-transition-token', nodeID, transition.id, action, key)

    expect(fetchSpy).toHaveBeenCalledTimes(2)
    for (const [url, init] of fetchSpy.mock.calls) {
      expect(url).toBe(`/v1/nodes/${nodeID}/gateway-port-transitions/${transition.id}/${action}`)
      expect(init).toMatchObject({ method: 'POST', credentials: 'include' })
      expect(init?.body).toBeUndefined()
      const headers = new Headers(init?.headers)
      expect(headers.get('Authorization')).toBe('Bearer node-transition-token')
      expect(headers.get('Idempotency-Key')).toBe(key)
      expect(headers.get('X-Request-ID')).toBe(key)
      expect(headers.has('Content-Type')).toBe(false)
    }
  })

  it('retains an explicit request ID with a non-UUID idempotency key', async () => {
    const key = 'node-transition-finalize'
    const requestID = '018f0000-0000-7000-8000-000000000012'
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(new TypeError('Failed to fetch'))
      .mockResolvedValueOnce(json({ ...transition, state: 'switched' }, 202))

    await expect(nodesApi.gatewayPortTransitionAction('token', nodeID, transition.id, 'finalize', key, requestID))
      .rejects.toMatchObject({ code: 'network_error' })
    await nodesApi.gatewayPortTransitionAction('token', nodeID, transition.id, 'finalize', key, requestID)

    for (const [, init] of fetchSpy.mock.calls) {
      const headers = new Headers(init?.headers)
      expect(headers.get('Idempotency-Key')).toBe(key)
      expect(headers.get('X-Request-ID')).toBe(requestID)
    }
  })

  it('keeps different logical actions on their own caller identities', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ ...transition, state: 'switched' }, 202))
    const keys = ['018f0000-0000-7000-8000-000000000012', '018f0000-0000-7000-8000-000000000013']
    await nodesApi.gatewayPortTransitionAction('token', nodeID, transition.id, 'finalize', keys[0]!)
    await nodesApi.gatewayPortTransitionAction('token', nodeID, transition.id, 'rollback', keys[1]!)
    expect(fetchSpy.mock.calls.map(([, init]) => new Headers(init?.headers).get('X-Request-ID'))).toEqual(keys)
    expect(fetchSpy.mock.calls.map(([, init]) => new Headers(init?.headers).get('Idempotency-Key'))).toEqual(keys)
  })

  it.each([
    ['node-transition-finalize', undefined],
    ['', '018f0000-0000-7000-8000-000000000012'],
    ['invalid key', '018f0000-0000-7000-8000-000000000012'],
    ['x'.repeat(129), '018f0000-0000-7000-8000-000000000012'],
    ['node-transition-finalize', 'not-a-uuid'],
    ['node-transition-finalize', '018F0000-0000-7000-8000-000000000012'],
  ])('rejects an invalid action identity before fetch %#', async (key, requestID) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(transition))
    await expect(nodesApi.gatewayPortTransitionAction('token', nodeID, transition.id, 'finalize', key!, requestID))
      .rejects.toMatchObject({ status: 400, code: 'validation_error' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})

describe('nodesApi.getConfigurationScopes', () => {
  const scopes = {
    node_id: nodeID,
    scopes: [{
      scope_id: '018f0000-0000-7000-8000-0000000000a1', scope_kind: 'tenant',
      tenant_id: '018f0000-0000-7000-8000-0000000000a2', tenant_name: 'Alpha',
      current_config_version_id: null, previous_config_version_id: null, reconciliation_required: false,
      updated_at: '2026-10-16T08:00:00Z',
      latest_deployment: {
        deployment_id: '018f0000-0000-7000-8000-0000000000d1', attempt: 1,
        rollout_id: '018f0000-0000-7000-8000-0000000000e1', config_version_id: '018f0000-0000-7000-8000-0000000000c1',
        action: 'apply', state: 'agent_queued', updated_at: '2026-10-16T08:00:00Z',
      },
      last_apply: {
        deployment_id: '018f0000-0000-7000-8000-0000000000d1', attempt: 1,
        config_version_id: '018f0000-0000-7000-8000-0000000000c1', state: 'superseded', error_code: null,
        finished_at: null, reported_at: '2026-10-16T08:00:00Z',
      },
      telemetry_excluded: 'invalid_config_version',
    }],
    rejections: [{
      scope_id: '018f0000-0000-7000-8000-0000000000a1', tenant_name: 'Alpha', reason: 'domain www.a.example is already served by another tenant',
      request_id: 'r1', occurred_at: '2026-10-16T07:00:00Z',
    }],
  }

  const regression = {
    scope_id: '018f0000-0000-7000-8000-0000000000a1', deployment_id: '018f0000-0000-7000-8000-0000000000d1',
    config_version_id: '018f0000-0000-7000-8000-0000000000c1', feature: 'l4_tls_passthrough',
    capability: 'CAPABILITY_NAME_TCP_PROXY', required: 4, declared: 3, agent_version: '1.0.33',
  }

  it('reads capability regressions', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ ...scopes, capability_regressions: [regression] }))
    await expect(nodesApi.getConfigurationScopes('token', nodeID)).resolves.toMatchObject({ capability_regressions: [regression] })
    // A feature a newer control plane names that this console cannot explain is left out.
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ ...scopes, capability_regressions: [{ ...regression, feature: 'future' }] }))
    await expect(nodesApi.getConfigurationScopes('token', nodeID)).resolves.toMatchObject({ capability_regressions: [] })
  })

  it('rejects a response without capability regressions', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(scopes))
    await expect(nodesApi.getConfigurationScopes('token', nodeID)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each([
    ['a regression without a version', { ...regression, required: '4' }],
    ['a regression of another shape', { ...regression, scope_id: 'tenant' }],
  ])('rejects %s', async (_name, item) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ ...scopes, capability_regressions: [item] }))
    await expect(nodesApi.getConfigurationScopes('token', nodeID)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('reads the node tenants with the session token', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ ...scopes, capability_regressions: [] }))
    await expect(nodesApi.getConfigurationScopes('token', nodeID)).resolves.toEqual({ ...scopes, capability_regressions: [] })
    const [url, init] = fetchSpy.mock.calls[0]!
    expect(String(url)).toContain(`/v1/nodes/${nodeID}/configuration-scopes`)
    expect((init?.headers as Record<string, string>).Authorization).toBe('Bearer token')
  })

  it.each([
    ['another node', { ...scopes, node_id: '018f0000-0000-7000-8000-000000000002' }],
    ['an unknown deployment state', { ...scopes, scopes: [{ ...scopes.scopes[0], latest_deployment: { ...scopes.scopes[0]!.latest_deployment, state: 'superseded' } }] }],
    ['an unknown apply state', { ...scopes, scopes: [{ ...scopes.scopes[0], last_apply: { ...scopes.scopes[0]!.last_apply, state: 'started' } }] }],
    ['a rejection without a reason', { ...scopes, rejections: [{ ...scopes.rejections[0], reason: 1 }] }],
    ['an unknown telemetry exclusion', { ...scopes, scopes: [{ ...scopes.scopes[0], telemetry_excluded: 'other' }] }],
    ['no telemetry exclusion field', { ...scopes, scopes: [{ ...scopes.scopes[0], telemetry_excluded: undefined }] }],
  ])('rejects a response naming %s', async (_name, value) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(value))
    await expect(nodesApi.getConfigurationScopes('token', nodeID)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('does not request an invalid node ID', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(nodesApi.getConfigurationScopes('token', 'node')).rejects.toMatchObject({ status: 400 })
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})

describe('nativeRuntimeSummary', () => {
  it('shows the state, the short release sha and a rollback code', () => {
    expect(nativeRuntimeSummary({ ...inventory.presence, native_runtime_state: 'switched',
      native_runtime_release: 'b'.repeat(64), native_runtime_previous_release: 'a'.repeat(64) }, '已切换', '原'))
      .toBe(`已切换 ${'b'.repeat(12)} (原 ${'a'.repeat(12)})`)
    expect(nativeRuntimeSummary({ ...inventory.presence, native_runtime_state: 'unchanged',
      native_runtime_release: 'a'.repeat(64) }, '未变', '原')).toBe(`未变 ${'a'.repeat(12)}`)
    expect(nativeRuntimeSummary({ ...inventory.presence, native_runtime_state: 'rolled_back',
      native_runtime_release: 'b'.repeat(64), native_runtime_previous_release: 'a'.repeat(64),
      native_runtime_error_code: 'RUNTIME_PRECHECK_FAILED' }, '已回滚', '原'))
      .toBe(`已回滚 ${'b'.repeat(12)} (原 ${'a'.repeat(12)}) RUNTIME_PRECHECK_FAILED`)
  })
})
