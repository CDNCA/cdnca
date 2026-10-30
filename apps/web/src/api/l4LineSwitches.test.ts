import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  createL4LineSwitch,
  getCurrentL4LineSwitch,
  getL4LineSwitch,
  reconcileL4LineSwitch,
  type L4LineSwitchWriteMetadata,
} from './l4LineSwitches'

const scopeID = '11111111-1111-4111-8111-111111111111'
const switchID = '22222222-2222-4222-8222-222222222222'
const metadata: L4LineSwitchWriteMetadata = {
  requestId: '88888888-8888-4888-8888-888888888888',
  correlationId: '99999999-9999-4999-8999-999999999999',
  idempotencyKey: 'switch-1',
  traceparent: '00-11111111111111111111111111111111-2222222222222222-01',
}

function responseValue() {
  return {
    id: switchID,
    configuration_scope_id: scopeID,
    expected_source_revision: 19,
    from: { id: '33333333-3333-4333-8333-333333333333', revision: 3, sha256: '31'.repeat(32) },
    to: { id: '44444444-4444-4444-8444-444444444444', revision: 7, sha256: '72'.repeat(32) },
    prepare_node_count: 3,
    retiring_node_count: 1,
    state: 'health_gate',
    state_revision: 2,
    prepare_publication: {
      id: '55555555-5555-4555-8555-555555555555',
      rollout_id: '66666666-6666-4666-8666-666666666666',
      config_version_id: '77777777-7777-4777-8777-777777777777',
    },
    compensation_publication: {},
    drain_command_count: 0,
    deadline: '2026-08-07T04:00:00Z',
    created_at: '2026-08-07T03:00:00Z',
    updated_at: '2026-08-07T03:01:00Z',
  }
}

describe('l4LineSwitches API', () => {
  afterEach(() => vi.restoreAllMocks())

  it('sends the exact immutable snapshots and write lineage', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(responseValue()), { status: 201 }))
    const input = {
      expected_source_revision: 19,
      from: responseValue().from,
      to: responseValue().to,
      health: { activation_timeout_ms: 60_000, observation_window_ms: 30_000, required_consecutive_successes: 3 },
      drain: { health_timeout_ms: 30_000, max_drain_ms: 600_000 },
      max_attempts: 3,
      deadline: '2026-08-07T04:00:00Z',
    }
    const result = await createL4LineSwitch('token', scopeID, input, metadata)
    expect(result.id).toBe(switchID)
    expect(fetchSpy).toHaveBeenCalledWith(`/v1/tenant-scopes/${scopeID}/l4-line-switches`, expect.objectContaining({
      method: 'POST',
      headers: expect.objectContaining({ 'Idempotency-Key': 'switch-1' }),
      body: JSON.stringify(input),
    }))
  })

  it('rejects response scope and shape drift', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...responseValue(), configuration_scope_id: switchID }), { status: 200 }))
    await expect(getL4LineSwitch('token', scopeID, switchID)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('accepts the DNS gate a waiting reconcile reports and rejects a malformed one', async () => {
    const gate = { state: 'propagation_wait', owners: 2, pending_owners: 0, ready_at: '2026-08-07T03:10:00Z' }
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({ ...responseValue(), dns_gate: gate }), { status: 200 }))
    await expect(getL4LineSwitch('token', scopeID, switchID)).resolves.toMatchObject({ dns_gate: gate })
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({
      ...responseValue(), dns_gate: { ...gate, state: 'skipped' },
    }), { status: 200 }))
    await expect(getL4LineSwitch('token', scopeID, switchID)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('rejects timestamps that Date.parse accepts outside strict RFC3339', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      ...responseValue(),
      updated_at: '2026-08-07 03:01:00Z',
    }), { status: 200 }))
    await expect(getL4LineSwitch('token', scopeID, switchID)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('reconciles with no client-supplied state transition and the complete frozen write lineage', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(responseValue()), { status: 200 }))
    await reconcileL4LineSwitch('token', scopeID, switchID, metadata)
    expect(fetchSpy).toHaveBeenCalledWith(
      `/v1/tenant-scopes/${scopeID}/l4-line-switches/${switchID}/reconcile`,
      expect.objectContaining({
        method: 'POST',
        body: undefined,
        headers: expect.objectContaining({
          'X-Request-ID': metadata.requestId,
          'X-Correlation-ID': metadata.correlationId,
          'Idempotency-Key': metadata.idempotencyKey,
          Traceparent: metadata.traceparent,
        }),
      }),
    )
  })

  it.each([
    ['missing', undefined],
    ['invalid', { ...metadata, traceparent: 'invalid' }],
  ])('rejects %s reconcile metadata before fetch', async (_, value) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(reconcileL4LineSwitch(
      'token', scopeID, switchID, value as L4LineSwitchWriteMetadata,
    )).rejects.toMatchObject({ status: 400, code: 'invalid_request' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('recovers the latest durable switch and treats an empty scope as null', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(responseValue()), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { code: 'l4_line_switch_not_found', request_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' },
      }), { status: 404, headers: { 'Content-Type': 'application/json' } }))
    expect((await getCurrentL4LineSwitch('token', scopeID))?.id).toBe(switchID)
    await expect(getCurrentL4LineSwitch('token', scopeID)).resolves.toBeNull()
    expect(fetchSpy.mock.calls[0]?.[0]).toBe(`/v1/tenant-scopes/${scopeID}/l4-line-switches/current`)
  })
})
