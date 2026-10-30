import {
  nodeSchedulingApi,
  validateNodeLineGroupResponse,
  validateLineResolutionWriteResponse,
  type NodeLineGroup,
  type NodeLineGroupSnapshotInput,
  type NodeSchedulingWriteMetadata,
} from '../api/nodeScheduling'

const groupID = '11111111-1111-4111-8111-111111111111'
const metadata: NodeSchedulingWriteMetadata = {
  requestId: 'node-scheduling-save-request',
  idempotencyKey: 'node-scheduling-save-key',
  expectedRevision: 7,
}
const snapshot: NodeLineGroupSnapshotInput = {
  name: 'primary-line',
  health_policy: {
    probe_interval_ms: 10_000,
    probe_timeout_ms: 3_000,
    failure_threshold: 3,
    recovery_threshold: 3,
    failure_debounce_ms: 0,
    recovery_debounce_ms: 0,
  },
  endpoints: [{
    id: '22222222-2222-4222-8222-222222222222',
    node_id: '33333333-3333-4333-8333-333333333333',
    address: '192.0.2.10',
    port: 443,
    region: 'cn-east',
    carrier: 'telecom',
    priority: 0,
    weight: 80,
    enabled: true,
  }],
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function lineGroupResponseFixture(): NodeLineGroup {
  return { id: groupID, display_id: '7', tenant_scope_id: '44444444-4444-4444-8444-444444444444',
    revision: 8, name: snapshot.name, region: '', resolved_value: 'line', ipv4_resolved_value: 'v4-line',
    l2_config_id: null, failover_mode: 'primary_offline', note: '', sort_order: 100,
    health_policy: snapshot.health_policy, endpoints: snapshot.endpoints.map((endpoint) => ({ ...endpoint,
      health: { status: 'unknown', consecutive_successes: 0, consecutive_failures: 0,
        last_sequence: 0, last_observed_at: null, last_changed_at: '2026-10-09T00:00:00Z', row_revision: 1 } })),
    configuration_digest: 'b'.repeat(64), created_by_user_id: groupID,
    created_at: '2026-10-09T00:00:00Z', sealed_at: '2026-10-09T00:00:00Z' }
}

describe('node scheduling API', () => {
  it('accepts immutable endpoint display IDs but never accepts invalid or duplicate values', () => {
    const group = lineGroupResponseFixture()
    group.endpoints[0]!.display_id = '9223372036854775807'
    expect(validateNodeLineGroupResponse(group)).toEqual(group)
    for (const value of ['0', '01', '-1', '', '9223372036854775808', '1.5']) {
      group.endpoints[0]!.display_id = value
      expect(() => validateNodeLineGroupResponse(group)).toThrow()
    }
    group.endpoints[0]!.display_id = '42'
    group.endpoints.push({ ...group.endpoints[0]!, id: '77777777-7777-4777-8777-777777777777', address: '192.0.2.11' })
    expect(() => validateNodeLineGroupResponse(group)).toThrow()
  })

  it('validates complete line revisions and the existing optional compatibility projections', () => {
    const group = lineGroupResponseFixture()
    expect(validateNodeLineGroupResponse(group)).toEqual(group)
    const compatible = { ...group, statistics: { node_count: 1, site_count: 0, forward_count: 0 },
      mode: 'cache', load_method: 'round-robin' }
    expect(validateNodeLineGroupResponse(compatible)).toEqual(compatible)
    expect(validateLineResolutionWriteResponse({ group, replayed: true }, groupID, group.tenant_scope_id, 7)).toEqual(group)
  })

  it.each([
    ['revision', (group: NodeLineGroup) => { group.revision = 7 }],
    ['scope', (group: NodeLineGroup) => { group.tenant_scope_id = groupID }],
    ['resource', (group: NodeLineGroup) => { group.id = group.tenant_scope_id }],
    ['digest', (group: NodeLineGroup) => { group.configuration_digest = 'B'.repeat(64) }],
    ['policy', (group: NodeLineGroup) => { group.health_policy = { ...group.health_policy, probe_timeout_ms: 10001 } }],
    ['endpoint', (group: NodeLineGroup) => { group.endpoints[0]!.port = 0 }],
    ['duplicate endpoint', (group: NodeLineGroup) => { group.endpoints.push(group.endpoints[0]!) }],
    ['health', (group: NodeLineGroup) => { group.endpoints[0]!.health.row_revision = 0 }],
    ['timestamp', (group: NodeLineGroup) => { group.sealed_at = 'not-a-date' }],
  ] as const)('rejects a successful line write with invalid %s', (_, mutate) => {
    const group = lineGroupResponseFixture()
    const expectedScope = group.tenant_scope_id
    mutate(group)
    expect(() => validateLineResolutionWriteResponse({ group, replayed: false }, groupID, expectedScope, 7))
      .toThrow(expect.objectContaining({ code: 'invalid_response', status: 200 }))
  })

  it('rejects an invalid write envelope and does not treat the revision route as a wrapped write response', async () => {
    const group = lineGroupResponseFixture()
    for (const body of [group, { group }, { group, replayed: 'true' }, { group: null, replayed: false }])
      expect(() => validateLineResolutionWriteResponse(body, groupID, group.tenant_scope_id, 7)).toThrow()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(group))
    const result = await nodeSchedulingApi.getRevision('access-token', { kind: 'platform', targetScopeId: group.tenant_scope_id }, groupID, 8)
    expect(validateNodeLineGroupResponse(result)).toEqual(group)
    expect(fetchSpy.mock.calls[0]![0]).toBe(`/v1/node-line-groups/${groupID}/revisions/8?target_scope_id=${group.tenant_scope_id}`)
  })

  it('keeps legacy optional reads compatible but requires the complete accepted write response', () => {
    const group = lineGroupResponseFixture()
    delete group.ipv4_resolved_value
    delete group.l2_config_id
    delete group.failover_mode
    expect(validateNodeLineGroupResponse(group)).toEqual(group)
    expect(() => validateLineResolutionWriteResponse({ group, replayed: false }, groupID, group.tenant_scope_id, 7))
      .toThrow(expect.objectContaining({ code: 'invalid_response' }))
  })

  it.each(['group', 'policy', 'endpoint', 'health', 'statistics', 'envelope'])('rejects undeclared %s fields without rejecting the declared compatibility projections', (target) => {
    const group = lineGroupResponseFixture()
    group.statistics = { node_count: 1, site_count: 0, forward_count: 0 }
    const envelope = { group, replayed: false }
    const object = target === 'group' ? group : target === 'policy' ? group.health_policy :
      target === 'endpoint' ? group.endpoints[0]! : target === 'health' ? group.endpoints[0]!.health :
        target === 'statistics' ? group.statistics : envelope
    Object.assign(object, { unsupported_schema: 'never trust' })
    expect(() => validateLineResolutionWriteResponse(envelope, groupID, group.tenant_scope_id, 7))
      .toThrow(expect.objectContaining({ code: 'invalid_response' }))
  })

  it('uses Bearer authentication and serializes the platform target scope', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))

    await nodeSchedulingApi.list('access-token', {
      kind: 'platform',
      targetScopeId: '44444444-4444-4444-8444-444444444444',
    })

    expect(fetchSpy).toHaveBeenCalledWith(
      '/v1/node-line-groups?target_scope_id=44444444-4444-4444-8444-444444444444',
      expect.objectContaining({
        credentials: 'include',
        headers: expect.objectContaining({
          Authorization: 'Bearer access-token',
          'X-Request-ID': expect.stringMatching(/^node-scheduling-list-/),
        }),
      }),
    )
    expect(fetchSpy.mock.calls[0][1]?.headers).not.toEqual(expect.objectContaining({ CdncaKey: expect.anything() }))
  })

  it('gets the exact persisted target snapshot revision for tenant and platform scopes', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(
      () => Promise.resolve(json({ id: 'snapshot-id' })),
    )
    const targetScopeID = '44444444-4444-4444-8444-444444444444'

    await nodeSchedulingApi.getTargetSnapshot('access-token', { kind: 'tenant' }, groupID, 7)
    await nodeSchedulingApi.getTargetSnapshot('access-token', {
      kind: 'platform',
      targetScopeId: targetScopeID,
    }, groupID, 9)

    expect(fetchSpy.mock.calls.map(([url]) => url)).toEqual([
      `/v1/node-line-groups/${groupID}/target-snapshots?source_revision=7`,
      `/v1/node-line-groups/${groupID}/target-snapshots?source_revision=9&target_scope_id=${targetScopeID}`,
    ])
    for (const [, init] of fetchSpy.mock.calls) {
      expect(init?.headers).toEqual(expect.objectContaining({ Authorization: 'Bearer access-token' }))
      expect(init?.headers).not.toEqual(expect.objectContaining({ CdncaKey: expect.anything() }))
    }
  })

  it('sends exact write metadata, precondition, and snapshot body for update', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ group_id: groupID }))

    await nodeSchedulingApi.update('access-token', groupID, snapshot, metadata)

    expect(fetchSpy).toHaveBeenCalledWith(
      `/v1/node-line-groups/${groupID}`,
      expect.objectContaining({
        method: 'PUT',
        body: JSON.stringify(snapshot),
        headers: expect.objectContaining({
          Authorization: 'Bearer access-token',
          'X-Request-ID': metadata.requestId,
          'Idempotency-Key': metadata.idempotencyKey,
          'If-Match': '"7"',
        }),
      }),
    )
  })

  it('uses revision zero as the create precondition without changing the caller body', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ group_id: groupID }, 201))
    const createMetadata = { ...metadata, expectedRevision: 0 }

    await nodeSchedulingApi.create('access-token', snapshot, createMetadata)

    expect(fetchSpy).toHaveBeenCalledWith('/v1/node-line-groups', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify(snapshot),
      headers: expect.objectContaining({ 'If-Match': '"0"' }),
    }))
  })

  it('preserves target order and all metadata for snapshot and rollback writes', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(
      () => Promise.resolve(json({ id: 'snapshot-id' })),
    )

    await nodeSchedulingApi.createTargetSnapshot('access-token', groupID, {
      source_revision: 7,
      node_ids: [
        '55555555-5555-4555-8555-555555555555',
        '66666666-6666-4666-8666-666666666666',
      ],
    }, metadata)
    await nodeSchedulingApi.rollback('access-token', groupID, { source_revision: 3 }, metadata)

    expect(fetchSpy.mock.calls.map(([url, init]) => [url, init?.body])).toEqual([
      [
        `/v1/node-line-groups/${groupID}/target-snapshots`,
        '{"source_revision":7,"node_ids":["55555555-5555-4555-8555-555555555555","66666666-6666-4666-8666-666666666666"]}',
      ],
      [`/v1/node-line-groups/${groupID}/rollback`, '{"source_revision":3}'],
    ])
    for (const [, init] of fetchSpy.mock.calls) {
      expect(init?.headers).toEqual(expect.objectContaining({
        'X-Request-ID': metadata.requestId,
        'Idempotency-Key': metadata.idempotencyKey,
      }))
    }
    expect(fetchSpy.mock.calls[0][1]?.headers).not.toEqual(
      expect.objectContaining({ 'If-Match': expect.anything() }),
    )
    expect(fetchSpy.mock.calls[1][1]?.headers).toEqual(expect.objectContaining({ 'If-Match': '"7"' }))
  })

  it('posts an explainable strategy request without a platform API key', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ reason: 'baseline_weighted_selected' }))
    const input = {
      selector: { region: 'cn-east', carrier: 'telecom' },
      requested_mode: 'weighted_baseline' as const,
      stable_key: 'site:example',
    }

    await nodeSchedulingApi.decide('access-token', { kind: 'tenant' }, groupID, input)

    expect(fetchSpy).toHaveBeenCalledWith(
      `/v1/node-line-groups/${groupID}/decisions`,
      expect.objectContaining({ method: 'POST', body: JSON.stringify(input) }),
    )
    expect(fetchSpy.mock.calls[0][1]?.headers).not.toEqual(expect.objectContaining({ CdncaKey: expect.anything() }))
  })

  it('returns a stable network error and never leaks the response message', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new TypeError('private socket detail'))
    await expect(nodeSchedulingApi.get('access-token', { kind: 'tenant' }, groupID)).rejects.toMatchObject({
      status: 0,
      code: 'network_error',
      message: 'Network request failed',
    })

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({
      error: { code: 'topology_cycle_rejected', message: 'private database topology detail' },
    }, 409))
    await expect(nodeSchedulingApi.get('access-token', { kind: 'tenant' }, groupID)).rejects.toMatchObject({
      status: 409,
      code: 'topology_cycle_rejected',
      message: 'API request failed',
    })
  })
})
