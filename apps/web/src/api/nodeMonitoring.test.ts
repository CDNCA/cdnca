import { nodeMonitoringApi } from './nodeMonitoring'

describe('node monitoring batch API', function nodeMonitoringAPIContract() {
  const id = '018f0000-0000-7000-8000-000000000001'
  const other = '018f0000-0000-7000-8000-000000000002'
  const time = '2026-10-10T10:00:00Z'
  const valid = {
    schema_version: 1, observed_at: time,
    configuration: { state: 'active', head_revision: 3, active_revision: 3, activated_at: time,
      policy: { enabled: true, requested_protocol: 'tcp', requested_port: 80,
        probe_interval_ms: 10000, probe_timeout_ms: 3000, failure_threshold: 3, recovery_threshold: 3,
        failure_debounce_ms: 0, recovery_debounce_ms: 0 } },
    items: [{ node_id: id, freshness: 'fresh', revision_state: 'current', delivery_state: 'serving', stale_after_ms: 43000,
      sample: { source: 'agent_local_tcp', config_revision: 3, active_config_revision: 3,
        publication_sequence: '9007199254740993', observed_at: time, ingested_at: time, probe_port: 80,
        healthy: true, probe_succeeded: true, consecutive_failures: 0, consecutive_successes: 3,
        probes_total: '9223372036854775807', probe_failures_total: '9007199254740993',
        recovered: false, recovery_notified: false, rolled_back: false } }],
  }

  it('sends one authenticated no-store GET and preserves int64 decimal counters exactly', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(valid)))
    const controller = new AbortController()
    expect(await nodeMonitoringApi.getLatest('memory-only-token', [id], controller.signal)).toEqual(valid)
    expect(fetchSpy).toHaveBeenCalledExactlyOnceWith(`/v1/nodes/monitoring/latest?node_id=${id}`, expect.objectContaining({
      method: 'GET', cache: 'no-store', credentials: 'include', signal: controller.signal,
      headers: expect.objectContaining({ Authorization: 'Bearer memory-only-token' }),
    }))
  })

  it('accepts exactly 300 nodes in stable request order without fallback requests', async () => {
    const ids = Array.from({ length: 300 }, (_, index) => `018f0000-0000-7000-8000-${String(index + 1).padStart(12, '0')}`)
    const body = { ...valid, items: ids.map((node_id) => ({ node_id, freshness: 'not_reported', revision_state: 'unknown', delivery_state: 'serving', stale_after_ms: 43000, sample: null })) }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body)))
    expect((await nodeMonitoringApi.getLatest('token', ids)).items.map((item) => item.node_id)).toEqual(ids)
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(new URL(String(fetchSpy.mock.calls[0]![0]), 'https://example.test').searchParams.getAll('node_id')).toEqual(ids)
  })

  it.each([[], [id, id], ['not-a-uuid'], ['00000000-0000-0000-0000-000000000000'], [id.toUpperCase()], Array(301).fill(id)])('refuses invalid request identifiers before fetch: %j', async (ids) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(nodeMonitoringApi.getLatest('token', ids)).rejects.toMatchObject({ status: 400, code: 'validation_error' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('accepts the server canonical non-nil UUID contract without inventing a version or variant restriction', async () => {
    const canonical = '01234567-89ab-0def-0123-456789abcdef'
    const body = { ...valid, items: [{ ...valid.items[0]!, node_id: canonical }] }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body)))
    expect(await nodeMonitoringApi.getLatest('token', [canonical])).toEqual(body)
  })

  it.each(['serving', 'awaiting_configuration', 'inactive'])('accepts the %s delivery state', async (delivery_state) => {
    const body = { ...valid, items: [{ ...valid.items[0]!, delivery_state }] }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body)))
    expect(await nodeMonitoringApi.getLatest('token', [id])).toEqual(body)
  })

  it.each([
    ['unconfigured', 0], ['not_activated', 4],
  ])('accepts %s with no policy or sample without fabricating probe state', async (state, head_revision) => {
    const body = { ...valid, configuration: { state, head_revision, active_revision: null, activated_at: null, policy: null },
      items: [{ node_id: id, freshness: 'not_reported', revision_state: 'unknown', delivery_state: 'serving', stale_after_ms: null, sample: null }] }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body)))
    expect(await nodeMonitoringApi.getLatest('token', [id])).toEqual(body)
  })

  it('accepts a saved head ahead of active, requested HTTP with actual TCP and absent explicit port', async () => {
    const body = structuredClone(valid)
    body.configuration.head_revision = 4
    Object.assign(body.configuration.policy, { requested_protocol: 'http', requested_port: null })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body)))
    expect(await nodeMonitoringApi.getLatest('token', [id])).toEqual(body)
  })

  it.each([
    ['schema', (body: typeof valid) => { body.schema_version = 2 }],
    ['extra root', (body: typeof valid) => { Object.assign(body, { hidden: true }) }],
    ['non-UTC time', (body: typeof valid) => { body.observed_at = '2026-10-10T10:00:00+00:00' }],
    ['impossible date', (body: typeof valid) => { body.observed_at = '2026-02-30T10:00:00Z' }],
    ['configuration field', (body: typeof valid) => { Object.assign(body.configuration, { secret: 'do-not-show' }) }],
    ['configuration state', (body: typeof valid) => { body.configuration.state = 'unknown' }],
    ['unsafe revision', (body: typeof valid) => { body.configuration.head_revision = Number.MAX_SAFE_INTEGER + 1 }],
    ['head behind active', (body: typeof valid) => { body.configuration.head_revision = 2 }],
    ['active policy missing', (body: typeof valid) => { Object.assign(body.configuration, { policy: null }) }],
    ['unconfigured policy', (body: typeof valid) => { Object.assign(body.configuration, { state: 'unconfigured', head_revision: 0 }) }],
    ['activation missing', (body: typeof valid) => { Object.assign(body.configuration, { activated_at: null }) }],
    ['enabled is not boolean', (body: typeof valid) => { Object.assign(body.configuration.policy, { enabled: 'false' }) }],
    ['unknown protocol', (body: typeof valid) => { body.configuration.policy.requested_protocol = 'host_metric' }],
    ['protocol array', (body: typeof valid) => { Object.assign(body.configuration.policy, { requested_protocol: ['tcp'] }) }],
    ['port', (body: typeof valid) => { body.configuration.policy.requested_port = 0 }],
    ['timeout exceeds interval', (body: typeof valid) => { body.configuration.policy.probe_timeout_ms = 10001 }],
    ['threshold', (body: typeof valid) => { body.configuration.policy.failure_threshold = 21 }],
    ['debounce', (body: typeof valid) => { body.configuration.policy.recovery_debounce_ms = -1 }],
    ['empty items', (body: typeof valid) => { body.items = [] }],
    ['duplicate item', (body: typeof valid) => { body.items.push(body.items[0]!) }],
    ['foreign item', (body: typeof valid) => { body.items[0]!.node_id = other }],
    ['freshness', (body: typeof valid) => { body.items[0]!.freshness = 'online' }],
    ['freshness array', (body: typeof valid) => { Object.assign(body.items[0]!, { freshness: ['fresh'] }) }],
    ['delivery state', (body: typeof valid) => { Object.assign(body.items[0]!, { delivery_state: 'pending' }) }],
    ['no delivery state', (body: typeof valid) => { delete (body.items[0] as Partial<typeof body.items[0]>).delivery_state }],
    ['revision state', (body: typeof valid) => { body.items[0]!.revision_state = 'active' }],
    ['revision state array', (body: typeof valid) => { Object.assign(body.items[0]!, { revision_state: ['current'] }) }],
    ['stale window', (body: typeof valid) => { body.items[0]!.stale_after_ms = 390000 }],
    ['no sample fresh', (body: typeof valid) => { Object.assign(body.items[0]!, { sample: null }) }],
    ['host metric', (body: typeof valid) => { body.items[0]!.sample.source = 'host_metric' }],
    ['sample extra', (body: typeof valid) => { Object.assign(body.items[0]!.sample, { cpu_percent: 0 }) }],
    ['sample unsafe revision', (body: typeof valid) => { body.items[0]!.sample.config_revision = Number.MAX_SAFE_INTEGER + 1 }],
    ['current mismatch', (body: typeof valid) => { body.items[0]!.sample.config_revision = 2 }],
    ['current predates activation', (body: typeof valid) => { body.items[0]!.sample.observed_at = '2026-10-10T09:59:59Z' }],
    ['rollback mismatch', (body: typeof valid) => { body.items[0]!.sample.rolled_back = true }],
    ['zero publication', (body: typeof valid) => { body.items[0]!.sample.publication_sequence = '0' }],
    ['numeric publication', (body: typeof valid) => { Object.assign(body.items[0]!.sample, { publication_sequence: 1 }) }],
    ['leading zero counter', (body: typeof valid) => { body.items[0]!.sample.probes_total = '01' }],
    ['counter overflow', (body: typeof valid) => { body.items[0]!.sample.probes_total = '9223372036854775808' }],
    ['failures exceed probes', (body: typeof valid) => { body.items[0]!.sample.probes_total = '0' }],
    ['counter exponent', (body: typeof valid) => { body.items[0]!.sample.probes_total = '1e3' }],
    ['probe boolean', (body: typeof valid) => { Object.assign(body.items[0]!.sample, { healthy: 1 }) }],
    ['probe counter', (body: typeof valid) => { body.items[0]!.sample.consecutive_failures = 21 }],
  ] as const)('rejects invalid %s without returning partial items', async (_name, mutate) => {
    const body = structuredClone(valid)
    mutate(body)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body)))
    await expect(nodeMonitoringApi.getLatest('token', [id])).rejects.toMatchObject({ status: 200, code: 'invalid_response' })
  })

  it('rejects shuffled items even when the requested set is complete', async () => {
    const body = { ...valid, items: [{ ...valid.items[0]!, node_id: other }, valid.items[0]!] }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body)))
    await expect(nodeMonitoringApi.getLatest('token', [id, other])).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each([[400, 'validation_error'], [401, 'invalid_session'], [403, 'permission_denied'],
    [404, 'node_monitoring_not_found'], [503, 'node_monitoring_unavailable']])('preserves status %s and stable code %s', async (status, code) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ error: { code, message: 'private-server-detail' } }), { status: Number(status) }))
    await expect(nodeMonitoringApi.getLatest('token', [id])).rejects.toMatchObject({ status, code })
  })

  it('maps malformed JSON and network failures without inventing a success', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response('<html>not JSON</html>'))
      .mockRejectedValueOnce(new Error('private network error'))
    await expect(nodeMonitoringApi.getLatest('token', [id])).rejects.toMatchObject({ status: 200, code: 'invalid_response' })
    await expect(nodeMonitoringApi.getLatest('token', [id])).rejects.toMatchObject({ status: 0, code: 'network_error' })
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  describe('per-node monitoring history', function nodeMonitoringHistoryContract() {
    const page = {
      schema_version: 1, node_id: id, from: '2026-10-10T09:00:00Z', to: time, page: 2, limit: 10, total: 12,
      items: [
        { observed_at: time, config_revision: 3, active_config_revision: 3, probe_port: 80, probe_succeeded: false, healthy: false, failed_checks: 1, total_checks: 1 },
        { observed_at: '2026-10-10T09:59:50Z', config_revision: 3, active_config_revision: 3, probe_port: 80, probe_succeeded: true, healthy: true, failed_checks: 0, total_checks: 1 },
      ],
    }
    const query = { from: '2026-10-10T09:00:00.000Z', to: time, page: 2, limit: 10 }

    it('sends one authenticated no-store GET with the exact window and page', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(page)))
      expect(await nodeMonitoringApi.getHistory('token', id, query)).toEqual(page)
      const [url, init] = fetchSpy.mock.calls[0]!
      const parsed = new URL(String(url), 'https://example.test')
      expect(parsed.pathname).toBe(`/v1/nodes/${id}/monitoring/history`)
      expect(Object.fromEntries(parsed.searchParams)).toEqual({ from: '2026-10-10T09:00:00.000Z', to: '2026-10-10T10:00:00.000Z', page: '2', limit: '10' })
      expect(init).toMatchObject({ method: 'GET', cache: 'no-store', headers: expect.objectContaining({ Authorization: 'Bearer token' }) })
    })

    it.each([
      ['reversed window', { ...query, from: time, to: '2026-10-10T09:00:00Z' }],
      ['window over seven days', { ...query, from: '2026-10-01T00:00:00Z' }],
      ['page zero', { ...query, page: 0 }],
      ['limit over 100', { ...query, limit: 101 }],
    ])('refuses %s before fetch', async (_, invalid) => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch')
      await expect(nodeMonitoringApi.getHistory('token', id, invalid)).rejects.toMatchObject({ status: 400, code: 'validation_error' })
      expect(fetchSpy).not.toHaveBeenCalled()
    })

    it.each([
      ['another node', (body: typeof page) => { body.node_id = other }],
      ['another page', (body: typeof page) => { body.page = 1 }],
      ['excess items', (body: typeof page) => { body.limit = 10; body.items = Array(11).fill(page.items[0]) }],
      ['fabricated failure', (body: typeof page) => { body.items[1]!.failed_checks = 1 }],
      ['carrier points', (body: typeof page) => { Object.assign(body.items[0]!, { total_checks: 5 }) }],
      ['extra field', (body: typeof page) => { Object.assign(body.items[0]!, { group: 'telecom' }) }],
    ])('rejects a response with %s', async (_, mutate) => {
      const body = structuredClone(page)
      mutate(body)
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body)))
      await expect(nodeMonitoringApi.getHistory('token', id, query)).rejects.toMatchObject({ code: 'invalid_response' })
    })
  })

  describe('per-node dnspup checkpoint history (probe-node)', () => {
    const page = {
      schema_version: 1, source: 'dnspup', node_id: id, group: 'telecom', from: '2026-10-10T09:00:00Z', to: time, page: 1, limit: 10, total: 1,
      items: [{ observed_at: time, address: '198.51.100.7', port: 443, failed: true, failed_checks: 2, total_checks: 2,
        checkpoints: [{ id: 't1', group: 'telecom', region: 'cn', ok: false }, { id: 't2', group: 'telecom', ok: false, latency_ms: 30 }] }],
    }
    const query = { from: '2026-10-10T09:00:00.000Z', to: time, page: 1, limit: 10 }

    it('sends source=dnspup and the group filter', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(page)))
      expect(await nodeMonitoringApi.getDNSPupHistory('token', id, { ...query, group: 'telecom' })).toEqual(page)
      const parsed = new URL(String(fetchSpy.mock.calls[0]![0]), 'https://example.test')
      expect(parsed.pathname).toBe(`/v1/nodes/${id}/monitoring/history`)
      expect(parsed.searchParams.get('source')).toBe('dnspup')
      expect(parsed.searchParams.get('group')).toBe('telecom')
    })

    it('omits group for all groups', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...page, group: '' })))
      await nodeMonitoringApi.getDNSPupHistory('token', id, { ...query, group: '' })
      expect(new URL(String(fetchSpy.mock.calls[0]![0]), 'https://example.test').searchParams.has('group')).toBe(false)
    })

    it.each([
      ['another group', (body: typeof page) => { body.group = 'unicom' }],
      ['failed above total', (body: typeof page) => { body.items[0]!.failed_checks = 3 }],
      ['unknown checkpoint group', (body: typeof page) => { body.items[0]!.checkpoints[0]!.group = 'bgp' }],
      ['extra field', (body: typeof page) => { Object.assign(body.items[0]!, { latency: 1 }) }],
    ])('rejects a response with %s', async (_, mutate) => {
      const body = structuredClone(page)
      mutate(body)
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body)))
      await expect(nodeMonitoringApi.getDNSPupHistory('token', id, { ...query, group: 'telecom' })).rejects.toMatchObject({ code: 'invalid_response' })
    })
  })

  describe('peer probe history (fix-probe)', () => {
    const query = { from: '2026-10-27T00:00:00Z', to: '2026-10-27T01:00:00Z', page: 1, limit: 10 }
    const page = { schema_version: 1, source: 'peer', node_id: id, from: query.from, to: query.to, page: 1, limit: 10, total: 1,
      items: [{ observed_at: query.to, address: '198.51.100.7', port: 443, failed: true, controller_ok: false as boolean | null,
        failed_checks: 2, total_checks: 2, checkpoints: [{ id: 'controller', ok: false },
          { id: 'n2', name: 'edge-2', address: '198.51.100.8', groups: ['domestic'], ok: false, latency_ms: 3 }] }] }

    it('sends source=peer without a group', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(page)))
      expect(await nodeMonitoringApi.getPeerHistory('token', id, query)).toEqual(page)
      const parsed = new URL(String(fetchSpy.mock.calls[0]![0]), 'https://example.test')
      expect(parsed.searchParams.get('source')).toBe('peer')
      expect(parsed.searchParams.has('group')).toBe(false)
    })

    it('accepts a round the controller did not probe', async () => {
      const body = structuredClone(page)
      body.items[0]!.controller_ok = null
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body)))
      expect((await nodeMonitoringApi.getPeerHistory('token', id, query)).items[0]!.controller_ok).toBeNull()
    })

    it.each([
      ['another source', (body: typeof page) => { body.source = 'dnspup' }],
      ['failed above total', (body: typeof page) => { body.items[0]!.failed_checks = 3 }],
      ['zero total', (body: typeof page) => { body.items[0]!.total_checks = 0; body.items[0]!.failed_checks = 0 }],
      ['unknown checkpoint group', (body: typeof page) => { body.items[0]!.checkpoints[1]!.groups = ['bgp'] }],
      ['extra checkpoint field', (body: typeof page) => { Object.assign(body.items[0]!.checkpoints[0]!, { location: 'x' }) }],
    ])('rejects a response with %s', async (_, mutate) => {
      const body = structuredClone(page)
      mutate(body)
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body)))
      await expect(nodeMonitoringApi.getPeerHistory('token', id, query)).rejects.toMatchObject({ code: 'invalid_response' })
    })
  })

  describe('per-node monitoring override', () => {
    const effective = { ...valid.configuration.policy, requested_protocol: 'http', probe_timeout_ms: 5000 }
    const overridden = { ...valid, items: [{ ...valid.items[0]!, effective_revision: 5, effective_policy: effective, stale_after_ms: 45000,
      sample: { ...valid.items[0]!.sample, config_revision: 5, active_config_revision: 5, source: 'agent_local_http' } }] }

    it('accepts an overridden item that is current at its own effective revision', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(overridden)))
      expect(await nodeMonitoringApi.getLatest('token', [id])).toEqual(overridden)
    })

    it.each([
      ['revision without policy', { effective_policy: undefined }],
      ['revision not above the platform', { effective_revision: 3 }],
      ['stale threshold from the platform policy', { stale_after_ms: 43000 }],
      ['current against the platform revision', { effective_revision: 6 }],
      ['different interval', { effective_policy: { ...effective, probe_interval_ms: 20000 }, stale_after_ms: 55000 }],
    ])('rejects %s', async (_label, changes) => {
      const item = { ...overridden.items[0]!, ...changes } as Record<string, unknown>
      for (const key of Object.keys(item)) if (item[key] === undefined) delete item[key]
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...overridden, items: [item] })))
      await expect(nodeMonitoringApi.getLatest('token', [id])).rejects.toMatchObject({ code: 'invalid_response' })
    })

    const view = { schema_version: 1, node_id: id, revision: 2, updated_at: time,
      override: { monitor_enabled: false, protocol: 'ping', probe_timeout_ms: 2000, monitor_port: null, monitor_action: null },
      platform_state: 'active', platform_revision: 3, effective_revision: 5, effective_policy: effective,
      effective_action: 'none', delivery_state: 'serving' }

    it('reads and saves the override with idempotency and compare-and-set', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify(view)))
      expect(await nodeMonitoringApi.getOverride('token', id)).toEqual(view)
      expect(await nodeMonitoringApi.putOverride('token', id, 2, view.override as never, 'key-1')).toEqual(view)
      const [, init] = fetchSpy.mock.calls[1]!
      expect(fetchSpy.mock.calls[1]![0]).toBe(`/v1/nodes/${id}/monitoring/override`)
      expect(init).toMatchObject({ method: 'PUT', headers: expect.objectContaining({ 'Idempotency-Key': 'key-1', Authorization: 'Bearer token' }) })
      expect(JSON.parse(String(init!.body))).toEqual({ expected_revision: 2, override: view.override })
    })

    it.each([
      ['effective revision mismatch', { effective_revision: 4 }],
      ['unknown field', { extra: true }],
      ['out of range port', { override: { ...view.override, monitor_port: 0 } }],
      ['inactive with policy', { platform_state: 'not_activated' }],
      ['updated time without revision', { revision: 0 }],
      ['foreign node', { node_id: other }],
    ])('rejects an override view with %s', async (_label, changes) => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...view, ...changes })))
      await expect(nodeMonitoringApi.getOverride('token', id)).rejects.toMatchObject({ code: 'invalid_response' })
    })
  })

  describe('serving holds and pause log', () => {
    const hold = { source: 'availability_monitor', reason_code: 'probe_unhealthy', held_since: time, protected_groups: 1 }

    it('accepts an item with active serving holds', async () => {
      const body = { ...valid, items: [{ ...valid.items[0]!, serving_holds: [hold] }] }
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body)))
      expect((await nodeMonitoringApi.getLatest('token', [id])).items[0]!.serving_holds).toEqual([hold])
    })

    it.each([
      ['empty list', []], ['unknown source', [{ ...hold, source: 'admin' }]], ['extra key', [{ ...hold, why: 'x' }]],
      ['negative protection', [{ ...hold, protected_groups: -1 }]], ['local time', [{ ...hold, held_since: '2026-10-10 10:00:00' }]],
    ])('rejects serving holds with %s', async (_, holds) => {
      const body = { ...valid, items: [{ ...valid.items[0]!, serving_holds: holds }] }
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body)))
      await expect(nodeMonitoringApi.getLatest('token', [id])).rejects.toMatchObject({ code: 'invalid_response' })
    })

    const events = { schema_version: 1, node_id: id, from: '2026-10-09T10:00:00Z', to: time, page: 1, limit: 10, total: 1,
      items: [{ id: other, source: 'auto_disable', event: 'held', reason_code: 'traffic_exceeded', hold_revision: 1,
        detail: { usage_bytes: 1 }, occurred_at: time }] }
    const window = { from: '2026-10-09T10:00:00.000Z', to: time, page: 1, limit: 10 }

    it('pages a node\'s serving events with an authenticated no-store GET', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(events)))
      expect(await nodeMonitoringApi.getServingEvents('token', id, window)).toEqual(events)
      const parsed = new URL(String(fetchSpy.mock.calls[0]![0]), 'https://example.test')
      expect(parsed.pathname).toBe(`/v1/nodes/${id}/serving/events`)
      expect(parsed.searchParams.get('page')).toBe('1')
    })

    it('refuses a window over 31 days before fetch and rejects unknown events', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(
        { ...events, items: [{ ...events.items[0]!, event: 'paused' }] })))
      await expect(nodeMonitoringApi.getServingEvents('token', id, { ...window, from: '2026-08-01T00:00:00Z' }))
        .rejects.toMatchObject({ code: 'validation_error' })
      expect(fetchSpy).not.toHaveBeenCalled()
      await expect(nodeMonitoringApi.getServingEvents('token', id, window)).rejects.toMatchObject({ code: 'invalid_response' })
    })
  })
})

describe('A10/N06 scope switch log API', () => {
  const from = '2026-10-01T00:00:00.000Z'
  const to = '2026-10-24T00:00:00.000Z'
  const item = { id: '018f0000-0000-7000-8000-0000000000e1', source: 'external_probe', event: 'released', reason_code: 'external_probe_recovered',
    hold_revision: 2, detail: {}, occurred_at: '2026-10-23T00:00:00Z', node_id: '018f0000-0000-7000-8000-0000000000a1', node_name: 'edge', ipv4: '', ipv6: '2001:db8::1' }
  const page = { schema_version: 1, from, to, page: 1, limit: 10, total: 1, items: [item] }

  it('sends the filters and accepts the scope page', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(page), { status: 200 }))
    const result = await nodeMonitoringApi.listScopeServingEvents('token', { from, to, page: 1, limit: 10, source: 'external_probe', event: 'released', ip: '2001:db8::1', nodeID: item.node_id })
    expect(result.items[0].node_name).toBe('edge')
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'https://cdnca.test')
    expect(url.pathname).toBe('/v1/nodes/serving/events')
    expect(Object.fromEntries(url.searchParams)).toMatchObject({ source: 'external_probe', event: 'released', ip: '2001:db8::1', node_id: item.node_id, page: '1', limit: '10' })
  })

  it('rejects a response row without node identity and invalid filters before fetching', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...page, items: [{ ...item, node_name: undefined }] }), { status: 200 }))
    await expect(nodeMonitoringApi.listScopeServingEvents('token', { from, to, page: 1, limit: 10 })).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(nodeMonitoringApi.listScopeServingEvents('token', { from, to, page: 1, limit: 10, nodeID: 'abc' })).rejects.toMatchObject({ code: 'validation_error' })
  })
})
