import { afterEach, describe, expect, it, vi } from 'vitest'

import { nodeTrafficPoliciesApi, type NodeTrafficPolicyState } from './nodeTrafficPolicies'

const scopeId = '22222222-2222-4222-8222-222222222222'
const nodeId = '33333333-3333-4333-8333-333333333333'
const state: NodeTrafficPolicyState = {
  policy: {
    id: '11111111-1111-4111-8111-111111111111', scope_id: scopeId, node_id: nodeId,
    monthly_limit_bytes: 1_000, timezone: 'Asia/Shanghai', windows: [], revision: 4,
    manual_override: { mode: 'none', revision: 0, expires_at: null },
    created_at: '2026-08-09T00:00:00Z', updated_at: '2026-08-09T00:00:00Z',
  },
  admin_state: 'active', current_config_version_id: '44444444-4444-4444-8444-444444444444',
  last_evaluation: null,
}

function jsonResponse(value: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(value), { status: 200, headers: { 'Content-Type': 'application/json', ...headers } })
}

afterEach(() => vi.restoreAllMocks())

describe('nodeTrafficPoliciesApi', () => {
  it('reads a scope-bound strict policy snapshot with a strong ETag', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(state, { ETag: '"4"' }))

    await expect(nodeTrafficPoliciesApi.get('token', scopeId, nodeId)).resolves.toEqual(state)
    expect(fetchMock).toHaveBeenCalledWith(
      `/v1/admin/node-traffic-policies/${nodeId}?scope_id=${scopeId}`,
      expect.objectContaining({ credentials: 'include', headers: { Authorization: 'Bearer token' } }),
    )
  })

  it('writes exact CAS and caller-owned metadata, then evaluates and queries the real sync task', async () => {
    const taskId = '55555555-5555-4555-8555-555555555555'
    const evaluation = {
      id: '66666666-6666-4666-8666-666666666666', scope_id: scopeId, node_id: nodeId,
      decision: {
        period_key: '2026-09', period_start: '2026-08-31T16:00:00Z', period_end: '2026-09-30T16:00:00Z',
        usage_bytes: 0, monthly_limit_bytes: 1_000, suppressed: false, sync_required: true,
        reason_code: 'period_reset', override_revision: 0, evaluated_at: '2026-09-01T00:00:00Z',
        source_snapshot_at: '2026-09-01T00:00:00Z', source_finalized_through: '2026-08-31T23:59:00Z',
        source_digest: 'a'.repeat(64),
      },
      sync_task: {
        id: taskId, scope_id: scopeId, node_id: nodeId,
        config_version_id: state.current_config_version_id, status: 'queued', error_code: null,
        rollout_id: null, created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
      },
      replayed: false,
    }
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(state, { ETag: '"4"', 'Idempotency-Replayed': 'false' }))
      .mockResolvedValueOnce(jsonResponse(evaluation, { 'Idempotency-Replayed': 'false' }))
      .mockResolvedValueOnce(jsonResponse(evaluation.sync_task))

    await nodeTrafficPoliciesApi.put('token', scopeId, nodeId, 4, {
      monthly_limit_bytes: 2_000, timezone: 'Asia/Shanghai', windows: [],
      manual_override: { mode: 'none', revision: 0, expires_at: null },
    }, { requestId: 'policy-write-request', idempotencyKey: 'policy-write-key' })
    await nodeTrafficPoliciesApi.evaluate('token', scopeId, nodeId, {
      requestId: 'policy-evaluate-request', idempotencyKey: 'policy-evaluate-key',
    })
    await expect(nodeTrafficPoliciesApi.getSyncTask('token', taskId)).resolves.toEqual(evaluation.sync_task)

    const putHeaders = new Headers(fetchMock.mock.calls[0]![1]?.headers)
    expect(putHeaders.get('If-Match')).toBe('"4"')
    expect(putHeaders.get('Idempotency-Key')).toBe('policy-write-key')
    expect(fetchMock.mock.calls[1]![0]).toBe(`/v1/admin/node-traffic-policies/${nodeId}/evaluate?scope_id=${scopeId}`)
    expect(fetchMock.mock.calls[2]![0]).toBe(`/v1/admin/node-traffic-sync-tasks/${taskId}`)
  })

  it.each([
    ['extra state field', { ...state, extra: true }, '"4"'],
    ['wrong node binding', { ...state, policy: { ...state.policy, node_id: '77777777-7777-4777-8777-777777777777' } }, '"4"'],
    ['wrong ETag', state, '"5"'],
  ])('rejects %s without accepting partial server truth', async (_label, body, etag) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(body, { ETag: etag }))
    await expect(nodeTrafficPoliciesApi.get('token', scopeId, nodeId))
      .rejects.toMatchObject({ status: 502, code: 'node_traffic_policy_invalid_response' })
  })
})
