import { ApiError } from './auth'
import {
  controlUpgradesApi,
  type ControlUpgradeCheckInput,
  type ControlUpgradeCreateInput,
  type ControlUpgradeListParams,
  type ControlUpgradeRequestMetadata,
  type ControlUpgradeRolloutAction,
  type ControlUpgradeRolloutDetail,
  type ControlUpgradeRolloutSummary,
  type ControlUpgradeStatusReceipt,
  type MaintenanceUpgradeStatus,
} from './controlUpgrades'

const checkInput: ControlUpgradeCheckInput = {
  component: 'control-api',
  current_version: '1.4.0',
  channel: 'stable',
}

const metadata: ControlUpgradeRequestMetadata = {
  requestId: 'control-upgrade-request-1',
  idempotencyKey: 'control-upgrade-rollout-1',
}

const ids = {
  plan: '00000000-0000-4000-8000-000000000010',
  installation: '00000000-0000-4000-8000-000000000011',
  parentGrant: '00000000-0000-4000-8000-000000000012',
  artifact: '00000000-0000-4000-8000-000000000013',
  rollbackArtifact: '00000000-0000-4000-8000-000000000014',
  nodeA: '00000000-0000-4000-8000-000000000021',
  nodeB: '00000000-0000-4000-8000-000000000022',
  nodeC: '00000000-0000-4000-8000-000000000023',
  batch: '00000000-0000-4000-8000-000000000031',
  event: '00000000-0000-4000-8000-000000000041',
  status: '00000000-0000-4000-8000-000000000051',
  command: '00000000-0000-4000-8000-000000000061',
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'X-Request-ID': metadata.requestId },
  })
}

function decision(overrides: Record<string, unknown> = {}) {
  return {
    eligible: true,
    reason: 'eligible',
    component: 'control-api',
    current_version: '1.4.0',
    channel: 'stable',
    entitlement: {
      serial: 12,
      channel: 'stable',
      min_version: '1.0.0',
      max_version: '2.0.0',
    },
    policy: {
      source: 'installation',
      target_revision_id: '019bf7d2-774d-7b16-b4bb-99d03f1cb90a',
      stale: false,
    },
    ...overrides,
  }
}

function summary(overrides: Partial<ControlUpgradeRolloutSummary> = {}): ControlUpgradeRolloutSummary {
  return {
    id: ids.plan,
    schema_version: 2,
    installation_id: ids.installation,
    component: 'edge-agent',
    current_version: '1.4.0',
    target_version: '1.5.0',
    state: 'queued',
    completion: '',
    revision: '9223372036854775807',
    automatic_rollback: true,
    parent_grant_id: ids.parentGrant,
    artifact_id: ids.artifact,
    artifact_sha256: 'A'.repeat(43),
    artifact_size_bytes: 1024,
    rollback_artifact_id: ids.rollbackArtifact,
    rollback_artifact_sha256: `${'B'.repeat(42)}E`,
    rollback_artifact_size_bytes: 900,
    active_batch: -1,
    total_nodes: 2,
    pending_nodes: 2,
    dispatched_nodes: 0,
    healthy_nodes: 0,
    failed_nodes: 0,
    rolled_back_nodes: 0,
    blockers: [],
    created_at: '2026-08-05T01:00:00Z',
    updated_at: '2026-08-05T01:00:00Z',
    ...overrides,
  }
}

function detail(overrides: Partial<ControlUpgradeRolloutDetail> = {}): ControlUpgradeRolloutDetail {
  return {
    ...summary(),
    batches: [
      { id: ids.batch, group_id: 'canary', canary: true, node_ids: [ids.nodeA] },
    ],
    nodes: [
      { node_id: ids.nodeA, agent_version: '1.4.0', protocol_version: 1, state: 'pending', dispatch_revision: '0' },
      { node_id: ids.nodeB, agent_version: '1.4.0', protocol_version: 1, state: 'pending', dispatch_revision: '0' },
    ],
    events: [],
    status_receipts: [],
    ...overrides,
  }
}

function statusReceipt(overrides: Partial<ControlUpgradeStatusReceipt> = {}): ControlUpgradeStatusReceipt {
  return {
    schema: 'cdnca.edge.upgrade.status/v1',
    status_id: ids.status,
    status_revision: '7',
    command_id: ids.command,
    plan_id: ids.plan,
    plan_revision: '2',
    batch_id: ids.batch,
    installation_id: ids.installation,
    node_id: ids.nodeA,
    action: 'upgrade',
    command_sha256: 'a'.repeat(64),
    status_sha256: 'b'.repeat(64),
    state: 'healthy',
    observed_at: '2026-08-05T01:02:03Z',
    delivery_stream: 'CONTROL_UPGRADE_STATUS',
    delivery_consumer: 'control-upgrade-status',
    delivery_sequence: '11',
    ...overrides,
  }
}

const createInput: ControlUpgradeCreateInput = {
  schema: 'cdnca.control-upgrade-rollout.create/v1',
  node_ids: [ids.nodeA, ids.nodeB],
  canary_node_ids: [ids.nodeA],
  batch_size: 1,
  automatic_rollback: true,
}

function maintenanceStatus(): MaintenanceUpgradeStatus {
  return {
    schema: 'cdnca.maintenance-upgrade-status/v1', observed_at: '2026-09-29T01:00:00Z',
    control: {
      component: 'control-api', current_version: '3.4.0', configured_version_matches: true,
      authorization: { state: 'valid', reason: 'eligible', channel: 'stable' },
      candidate: { state: 'available', reason: 'upgrade_available', version: '3.5.0', expires_at: '2026-09-29T01:05:00Z' },
      runtime: { ready: false, reason: 'control_upgrade_execution_unavailable' },
    },
    nodes: [{
      node_id: ids.nodeA, current_version: '2.0.0',
      candidate: { state: 'available', reason: 'upgrade_available', version: '2.1.0', expires_at: '2026-09-29T01:05:00Z' },
      runtime: { ready: true, reason: 'ready' }, reason: 'eligible', eligible: true,
    }],
  }
}

describe('controlUpgradesApi', () => {
  it('reads authoritative maintenance status with sorted repeated node parameters', async () => {
    const data = maintenanceStatus()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(json({ data })))
    await expect(controlUpgradesApi.maintenanceStatus('access-token', [ids.nodeB, ids.nodeA])).resolves.toEqual(data)
    expect(fetchSpy).toHaveBeenCalledWith(`/v1/admin/maintenance-upgrade-status?node_id=${ids.nodeA}&node_id=${ids.nodeB}`, {
      credentials: 'include', headers: { Authorization: 'Bearer access-token' },
    })
  })

  it('reads the control status without a node list permission or query', async () => {
    const data = { ...maintenanceStatus(), nodes: [] }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data }))
    await expect(controlUpgradesApi.maintenanceStatus('access-token')).resolves.toEqual(data)
    expect(fetchSpy.mock.calls[0][0]).toBe('/v1/admin/maintenance-upgrade-status')
  })

  it.each([
    ['blank token', '', []],
    ['duplicate node', 'token', [ids.nodeA, ids.nodeA]],
    ['noncanonical node', 'token', ['FFFFFFFF-FFFF-4FFF-8FFF-FFFFFFFFFFFF']],
    ['too many nodes', 'token', Array.from({ length: 101 }, (_, index) => `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`)],
  ] as const)('rejects maintenance request with %s before sending', async (_name, token, nodeIDs) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(controlUpgradesApi.maintenanceStatus(token, [...nodeIDs])).rejects.toMatchObject({ code: 'invalid_request' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['unknown schema', (data: MaintenanceUpgradeStatus) => ({ ...data, schema: 'future' })],
    ['invalid observation', (data: MaintenanceUpgradeStatus) => ({ ...data, observed_at: 'yesterday' })],
    ['node component as control', (data: MaintenanceUpgradeStatus) => ({ ...data, control: { ...data.control, component: 'edge-agent' } })],
    ['development version', (data: MaintenanceUpgradeStatus) => ({ ...data, control: { ...data.control, current_version: 'development' } })],
    ['array authorization state', (data: MaintenanceUpgradeStatus) => ({ ...data, control: { ...data.control, authorization: { state: ['valid'], reason: 'eligible' } } })],
    ['candidate without local authorization', (data: MaintenanceUpgradeStatus) => ({ ...data, control: { ...data.control, authorization: { state: 'denied', reason: 'entitlement_state_denied' } } })],
    ['array candidate state', (data: MaintenanceUpgradeStatus) => ({ ...data, control: { ...data.control, candidate: { ...data.control.candidate, state: ['available'] } } })],
    ['available downgrade', (data: MaintenanceUpgradeStatus) => ({ ...data, control: { ...data.control, candidate: { ...data.control.candidate, version: '3.3.0' } } })],
    ['available same version', (data: MaintenanceUpgradeStatus) => ({ ...data, control: { ...data.control, candidate: { ...data.control.candidate, version: '3.4.0' } } })],
    ['current release missing', (data: MaintenanceUpgradeStatus) => ({ ...data, control: { ...data.control, current_version: null } })],
    ['incorrect latest', (data: MaintenanceUpgradeStatus) => ({ ...data, control: { ...data.control, candidate: { ...data.control.candidate, state: 'up_to_date' } } })],
    ['leading zero after hyphenated prerelease', (data: MaintenanceUpgradeStatus) => ({ ...data, control: { ...data.control, candidate: { ...data.control.candidate, version: '3.5.0-alpha-beta.01' } } })],
    ['unknown authorization', (data: MaintenanceUpgradeStatus) => ({ ...data, control: { ...data.control, authorization: { state: 'approved', reason: 'eligible' } } })],
    ['secret field', (data: MaintenanceUpgradeStatus) => ({ ...data, control: { ...data.control, secret: 'redacted-test' } })],
    ['candidate without expiry', (data: MaintenanceUpgradeStatus) => ({ ...data, control: { ...data.control, candidate: { ...data.control.candidate, expires_at: null } } })],
    ['unavailable target masquerading as latest', (data: MaintenanceUpgradeStatus) => ({ ...data, control: { ...data.control, candidate: { ...data.control.candidate, state: 'unavailable' } } })],
    ['unknown candidate state', (data: MaintenanceUpgradeStatus) => ({ ...data, control: { ...data.control, candidate: { ...data.control.candidate, state: 'published' } } })],
    ['unrequested node', (data: MaintenanceUpgradeStatus) => ({ ...data, nodes: [{ ...data.nodes[0], node_id: ids.nodeB }] })],
    ['duplicate node', (data: MaintenanceUpgradeStatus) => ({ ...data, nodes: [data.nodes[0], data.nodes[0]] })],
    ['eligible without version', (data: MaintenanceUpgradeStatus) => ({ ...data, nodes: [{ ...data.nodes[0], current_version: null }] })],
    ['eligible without runtime', (data: MaintenanceUpgradeStatus) => ({ ...data, nodes: [{ ...data.nodes[0], runtime: { ready: false, reason: 'node_upgrade_runtime_unavailable' } }] })],
    ['eligible for rollback', (data: MaintenanceUpgradeStatus) => ({ ...data, nodes: [{ ...data.nodes[0], candidate: { ...data.nodes[0].candidate, state: 'rollback_required' } }] })],
    ['eligible with unknown reason', (data: MaintenanceUpgradeStatus) => ({ ...data, nodes: [{ ...data.nodes[0], reason: 'future_reason' }] })],
  ] as const)('rejects malformed maintenance 200: %s', async (_name, mutate) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data: mutate(maintenanceStatus()) }))
    await expect(controlUpgradesApi.maintenanceStatus('access-token', [ids.nodeA])).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each([
    ['3.4.9', '3.4.10', 'available'],
    ['3.4.0-alpha.2', '3.4.0-alpha.10', 'available'],
    ['3.4.0-alpha.999999999999999999999999', '3.4.0-beta', 'available'],
    ['3.4.0-rc.1', '3.4.0', 'available'],
    ['3.4.0-alpha', '3.4.0-alpha.1', 'available'],
    ['3.4.0-alpha-2', '3.4.0-alpha-1', 'rollback_required'],
    ['3.4.0', '3.4.0-rc.1', 'rollback_required'],
    ['3.4.0-alpha-beta.1', '3.4.0-alpha-beta.1', 'up_to_date'],
  ] as const)('preserves semver ordering for %s to %s', async (current, target, state) => {
    const data = maintenanceStatus()
    data.control.current_version = current
    data.control.candidate = { ...data.control.candidate, state, version: target, reason: state === 'available' ? 'upgrade_available' : state === 'up_to_date' ? 'same_version' : 'target_is_older' }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data }))
    await expect(controlUpgradesApi.maintenanceStatus('access-token', [ids.nodeA])).resolves.toEqual(data)
  })

  it('accepts explicit unavailable facts without inventing a version or eligibility', async () => {
    const data = maintenanceStatus()
    data.control.current_version = null
    data.control.configured_version_matches = null
    data.control.authorization = { state: 'unavailable', reason: 'entitlement_unavailable' }
    data.control.candidate = { state: 'unavailable', reason: 'candidate_service_unavailable', version: null, expires_at: null }
    data.nodes = []
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data }))
    await expect(controlUpgradesApi.maintenanceStatus('access-token', [ids.nodeA])).resolves.toEqual(data)
  })

  it('keeps the local eligibility check contract intact', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(decision()))

    await expect(controlUpgradesApi.check('access-token', checkInput, metadata)).resolves.toEqual(decision())

    expect(fetchSpy).toHaveBeenCalledWith('/v1/admin/control-upgrade-checks', {
      method: 'POST',
      credentials: 'include',
      headers: {
        Authorization: 'Bearer access-token',
        'Content-Type': 'application/json',
        'Idempotency-Key': metadata.idempotencyKey,
        'X-Request-ID': metadata.requestId,
      },
      body: JSON.stringify(checkInput),
    })
  })

  it('lists rollout summaries with the exact filters and pagination response', async () => {
    const params: ControlUpgradeListParams = {
      page: 2,
      pageSize: 50,
      state: 'paused',
      nodeId: ids.nodeA,
    }
    const response = { data: [summary({ state: 'paused' })], page: 2, page_size: 50, total: 51 }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))

    await expect(controlUpgradesApi.list('access-token', params)).resolves.toEqual(response)
    expect(fetchSpy).toHaveBeenCalledWith(
      `/v1/admin/control-upgrade-rollouts?page=2&page_size=50&state=paused&node_id=${ids.nodeA}`,
      {
        credentials: 'include',
        headers: { Authorization: 'Bearer access-token' },
      },
    )
  })

  it('gets an exact rollout detail without write metadata', async () => {
    const response = { data: detail({ status_receipts: [statusReceipt()] }) }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))

    const result = await controlUpgradesApi.detail('access-token', ids.plan)

    expect(result).toEqual(response)
    expect(fetchSpy).toHaveBeenCalledWith(`/v1/admin/control-upgrade-rollouts/${ids.plan}`, {
      credentials: 'include',
      headers: { Authorization: 'Bearer access-token' },
    })
    expect(result.data.status_receipts).toEqual([statusReceipt()])
  })

  it('accepts the node outcome fields on a status receipt', async () => {
    const receipt = statusReceipt({ state: 'failed', error_code: 'DOWNLOAD_FAILED', current_version: '2.0.0', previous_version: '2.0.0' })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data: detail({ status_receipts: [receipt] }) }))
    expect((await controlUpgradesApi.detail('access-token', ids.plan)).data.status_receipts[0]).toMatchObject({ error_code: 'DOWNLOAD_FAILED' })
  })

  it.each([
    ['extra receipt field', { ...statusReceipt(), internal_bytes: 'secret' }],
    ['noncanonical receipt revision', statusReceipt({ status_revision: '07' })],
    ['foreign receipt plan', statusReceipt({ plan_id: '00000000-0000-4000-8000-000000000099' })],
    ['unsafe node error code', statusReceipt({ error_code: 'bad code' })],
    ['non-string node version', statusReceipt({ current_version: 2 as unknown as string })],
  ])('fails closed for %s', async (_name, receipt) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data: {
      ...detail(),
      status_receipts: [receipt],
    } }))

    await expect(controlUpgradesApi.detail('access-token', ids.plan)).rejects.toMatchObject({
      code: 'invalid_response',
    })
  })

  it('creates a rollout with canonical input and preserves the durable replay marker', async () => {
    const response = { data: detail(), replayed: false }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response, 201))

    await expect(controlUpgradesApi.create('access-token', createInput, metadata)).resolves.toEqual(response)
    expect(fetchSpy).toHaveBeenCalledWith('/v1/admin/control-upgrade-rollouts', {
      method: 'POST',
      credentials: 'include',
      headers: {
        Authorization: 'Bearer access-token',
        'Content-Type': 'application/json',
        'Idempotency-Key': metadata.idempotencyKey,
        'X-Request-ID': metadata.requestId,
      },
      body: JSON.stringify(createInput),
    })
  })

  it.each<ControlUpgradeRolloutAction>(['start', 'pause', 'resume', 'rollback'])(
    'posts %s to the exact action route with the expected revision',
    async (action) => {
      const input = { expected_revision: '9223372036854775807', reason: `operator_${action}` }
      const response = { data: detail(), replayed: false }
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))

      await expect(controlUpgradesApi[action]('access-token', ids.plan, input, metadata)).resolves.toEqual(response)
      expect(fetchSpy).toHaveBeenCalledWith(`/v1/admin/control-upgrade-rollouts/${ids.plan}/${action}`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          Authorization: 'Bearer access-token',
          'Content-Type': 'application/json',
          'Idempotency-Key': metadata.idempotencyKey,
          'X-Request-ID': metadata.requestId,
        },
        body: JSON.stringify(input),
      })
    },
  )

  it('allows an uncertain action to be replayed with byte-identical body and metadata', async () => {
    let calls = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      calls += 1
      return calls === 1
        ? Promise.reject(new TypeError('connection lost after commit'))
        : Promise.resolve(json({ data: detail({ revision: '2' }), replayed: true }))
    })
    const input = { expected_revision: '1', reason: 'operator_start' }

    await expect(controlUpgradesApi.start('access-token', ids.plan, input, metadata)).rejects.toMatchObject({
      code: 'network_error',
    })
    await expect(controlUpgradesApi.start('access-token', ids.plan, input, metadata)).resolves.toMatchObject({
      replayed: true,
    })
    expect(fetchSpy.mock.calls[1][1]?.body).toBe(fetchSpy.mock.calls[0][1]?.body)
    expect(fetchSpy.mock.calls[1][1]?.headers).toEqual(fetchSpy.mock.calls[0][1]?.headers)
  })

  it.each([
    ['unsorted create nodes', () => controlUpgradesApi.create('access-token', {
      ...createInput,
      node_ids: [ids.nodeB, ids.nodeA],
    }, metadata)],
    ['foreign canary', () => controlUpgradesApi.create('access-token', {
      ...createInput,
      canary_node_ids: ['00000000-0000-4000-8000-000000000099'],
    }, metadata)],
    ['more than two canaries', () => controlUpgradesApi.create('access-token', {
      ...createInput,
      node_ids: [ids.nodeA, ids.nodeB, ids.nodeC],
      canary_node_ids: [ids.nodeA, ids.nodeB, ids.nodeC],
    }, metadata)],
    ['zero action revision', () => controlUpgradesApi.pause('access-token', ids.plan, {
      expected_revision: '0',
      reason: 'operator_pause',
    }, metadata)],
    ['noncanonical action reason', () => controlUpgradesApi.pause('access-token', ids.plan, {
      expected_revision: '1',
      reason: 'operator-pause',
    }, metadata)],
    ['revision above int64', () => controlUpgradesApi.pause('access-token', ids.plan, {
      expected_revision: '9223372036854775808',
      reason: 'operator_pause',
    }, metadata)],
    ...['01', '+1', ' 1', '1.0', '1e0'].map((expectedRevision) => [
      `noncanonical action revision ${expectedRevision}`,
      () => controlUpgradesApi.pause('access-token', ids.plan, {
        expected_revision: expectedRevision,
        reason: 'operator_pause',
      }, metadata),
    ] as const),
    ['numeric action revision', () => controlUpgradesApi.pause('access-token', ids.plan, {
      expected_revision: 1 as unknown as string,
      reason: 'operator_pause',
    }, metadata)],
    ['noncanonical plan id', () => controlUpgradesApi.detail(
      'access-token',
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'.toUpperCase(),
    )],
    ['invalid page size', () => controlUpgradesApi.list('access-token', { page: 1, pageSize: 101 })],
  ] as const)('rejects %s before sending', async (_name, invoke) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(invoke()).rejects.toMatchObject({ code: 'invalid_request' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['extra summary field', { data: [{ ...summary(), secret: 'leak' }], page: 1, page_size: 20, total: 1 }],
    ['inconsistent node counts', { data: [summary({ healthy_nodes: 1 })], page: 1, page_size: 20, total: 1 }],
    ['wrong page echo', { data: [summary()], page: 2, page_size: 20, total: 1 }],
    ['numeric rollout revision', { data: [summary({ revision: 1 as unknown as string })], page: 1, page_size: 20, total: 1 }],
    ['leading-zero rollout revision', { data: [summary({ revision: '01' })], page: 1, page_size: 20, total: 1 }],
    ['overflow rollout revision', {
      data: [summary({ revision: '9223372036854775808' })], page: 1, page_size: 20, total: 1,
    }],
    ['invalid detail event', { data: detail({ events: [{
      id: ids.event,
      revision: '2',
      from: 'queued',
      to: 'canary',
      action: 'future_action' as unknown as ControlUpgradeRolloutDetail['events'][number]['action'],
      reason: 'operator_start',
      batch_id: ids.batch,
      node_id: '',
    }] }) }],
    ['invalid detail event time', { data: detail({ events: [{
      id: ids.event, revision: '2', from: 'queued', to: 'canary', action: 'start',
      reason: 'operator_start', batch_id: ids.batch, node_id: '', occurred_at: '2026-10-14 08:30:15',
    }] }) }],
  ] as const)('fails closed for %s', async (_name, responseBody) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(responseBody))
    const request = 'page' in responseBody
      ? controlUpgradesApi.list('access-token', { page: 1, pageSize: 20 })
      : controlUpgradesApi.detail('access-token', ids.plan)
    await expect(request).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('accepts the committed time on detail events', async () => {
    const event = { id: ids.event, revision: '2', from: 'queued' as const, to: 'canary' as const, action: 'start' as const,
      reason: 'operator_start', batch_id: ids.batch, node_id: '', occurred_at: '2026-10-14T08:30:15.123456Z' }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data: detail({ events: [event] }) }))
    expect((await controlUpgradesApi.detail('access-token', ids.plan)).data.events[0].occurred_at).toBe(event.occurred_at)
  })

  it('rejects a successful create returned with the wrong HTTP status', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data: detail(), replayed: false }, 200))
    await expect(controlUpgradesApi.create('access-token', createInput, metadata)).rejects.toMatchObject({
      code: 'invalid_response',
    })
  })

  it('keeps raw server text out of a permission error while retaining a safe request ID', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: {
        code: 'permission_denied',
        message: 'raw internal permission detail',
        request_id: 'upgrade-denied-42',
      },
    }, 403))

    const error = await controlUpgradesApi.list('access-token', { page: 1, pageSize: 20 })
      .then(() => null, (reason: unknown) => reason)

    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ code: 'permission_denied', requestId: 'upgrade-denied-42' })
    expect((error as ApiError).message).not.toContain('raw internal')
  })
})
