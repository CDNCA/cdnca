import { nodeIsolationApi } from './nodeIsolation'

const scopeID = '11111111-1111-4111-8111-111111111111'
const nodeID = '22222222-2222-4222-8222-222222222222'
const configID = '33333333-3333-4333-8333-333333333333'
const reportID = '44444444-4444-4444-8444-444444444444'

function item(overrides: Record<string, unknown> = {}) {
  return {
    scope_id: scopeID,
    node_id: nodeID,
    status: 'isolated',
    desired: { schema: 1, config_version_id: configID, artifact_sha256: 'a'.repeat(64) },
    consecutive_failures: 3,
    consecutive_healthy: 0,
    last_session_epoch: 4,
    last_health_sequence: 9,
    last_report_id: reportID,
    last_outcome: 'failed',
    last_error_code: 'agent_apply_failed',
    reason_code: 'sync_failure_threshold',
    revision: 7,
    isolated_at: '2026-08-09T00:00:00Z',
    recovered_at: null,
    updated_at: '2026-08-09T00:00:01Z',
    ...overrides,
  }
}

describe('nodeIsolationApi.list', () => {
  afterEach(() => vi.restoreAllMocks())

  it('uses the platform read route and accepts a strict response', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [item()] }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }))
    await expect(nodeIsolationApi.list('isolation-token', [nodeID])).resolves.toHaveLength(1)
    expect(fetchSpy).toHaveBeenCalledWith(`/v1/admin/node-isolations?node_id=${nodeID}`, expect.objectContaining({
      credentials: 'include', headers: { Authorization: 'Bearer isolation-token' },
    }))
  })

  it.each([
    ['extra field', item({ secret: true })],
    ['unsafe counter', item({ revision: Number.MAX_SAFE_INTEGER + 1 })],
    ['unknown reason', item({ reason_code: 'silently_allowed' })],
    ['uppercase digest', item({ desired: { schema: 1, config_version_id: configID, artifact_sha256: 'A'.repeat(64) } })],
  ])('rejects %s', async (_name, invalid) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [invalid] }), { status: 200 }))
    await expect(nodeIsolationApi.list('isolation-token')).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('rejects duplicate filters before network access', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(nodeIsolationApi.list('isolation-token', [nodeID, nodeID])).rejects.toMatchObject({ code: 'validation_error' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
