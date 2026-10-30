import { ApiError } from './auth'
import {
  createJA4BlockWriteMetadata,
  ja4BlocksApi,
  type JA4BlockCreateInput,
  type JA4BlockWorkflow,
  type JA4BlockWriteMetadata,
} from './ja4Blocks'

const scopeID = '11111111-1111-4111-8111-111111111111'
const siteID = '22222222-2222-4222-8222-222222222222'
const workflowID = '33333333-3333-4333-8333-333333333333'
const policyID = '44444444-4444-4444-8444-444444444444'
const bindingID = '55555555-5555-4555-8555-555555555555'
const publicationID = '66666666-6666-4666-8666-666666666666'
const rolloutID = '77777777-7777-4777-8777-777777777777'
const rawJA4 = 't13d1516h2_8daaf6152771_02713d6af862'
const digest = 'a'.repeat(64)
const snapshotAt = '2026-08-08T08:00:00Z'

const input: JA4BlockCreateInput = {
  site_id: siteID,
  ja4: rawJA4,
  snapshot_at: snapshotAt,
  duration_seconds: 3600,
  reason: 'manual_security_review',
}
const metadata: JA4BlockWriteMetadata = {
  requestId: 'ja4-block-request-1',
  idempotencyKey: 'ja4-block-create-1',
  stepUpToken: 'opaque-step-up-proof',
}
const workflow: JA4BlockWorkflow = {
  id: workflowID,
  tenant_scope_id: scopeID,
  site_id: siteID,
  ja4_sha256: digest,
  snapshot_at: snapshotAt,
  duration_seconds: 3600,
  reason: 'manual_security_review',
  phase: 'edge_pending',
  revision: 2,
  policy_id: policyID,
  policy_revision: 1,
  binding_id: bindingID,
  binding_revision: 1,
  edge_publication_id: publicationID,
  rollout_id: rolloutID,
  edge_state: 'pending',
  attempt_count: 1,
  replayed: false,
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Request-ID': 'request-1' },
  })
}

describe('ja4BlocksApi', () => {
  it('creates and reads an exact tenant workflow without returning raw JA4', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(workflow, 202))
      .mockResolvedValueOnce(json(workflow))

    await expect(ja4BlocksApi.createTenant('tenant-token', input, metadata)).resolves.toEqual(workflow)
    await expect(ja4BlocksApi.getTenant('tenant-token', workflowID, 'tenant-read-1')).resolves.toEqual(workflow)

    expect(fetchSpy.mock.calls[0]).toEqual([
      '/v1/security/ja4-blocks',
      {
        method: 'POST', credentials: 'include', cache: 'no-store', body: JSON.stringify(input),
        headers: {
          Authorization: 'Bearer tenant-token', 'Content-Type': 'application/json',
          'If-Match': '"0"', 'Idempotency-Key': metadata.idempotencyKey,
          'X-Request-ID': metadata.requestId, 'X-Step-Up-Token': metadata.stepUpToken,
        },
      },
    ])
    expect(fetchSpy.mock.calls[1]).toEqual([
      `/v1/security/ja4-blocks/${workflowID}`,
      {
        method: 'GET', credentials: 'include', cache: 'no-store',
        headers: { Authorization: 'Bearer tenant-token', 'X-Request-ID': 'tenant-read-1' },
      },
    ])
    expect(JSON.stringify(workflow)).not.toContain(rawJA4)
  })

  it('creates and reads an admin workflow with one explicit canonical tenant target', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(workflow, 202))
      .mockResolvedValueOnce(json(workflow))
    const adminInput = { ...input, tenant_scope_id: scopeID }

    await ja4BlocksApi.createAdmin('admin-token', adminInput, metadata)
    await ja4BlocksApi.getAdmin('admin-token', scopeID, workflowID, 'admin-read-1')

    expect(fetchSpy.mock.calls[0]?.[0]).toBe('/v1/admin/security/ja4-blocks')
    expect(fetchSpy.mock.calls[0]?.[1]?.body).toBe(JSON.stringify(adminInput))
    expect(fetchSpy.mock.calls[1]?.[0]).toBe(`/v1/admin/security/ja4-blocks/${workflowID}?tenant_scope_id=${scopeID}`)
    const readHeaders = new Headers(fetchSpy.mock.calls[1]?.[1]?.headers)
    expect(readHeaders.get('Authorization')).toBe('Bearer admin-token')
    expect(readHeaders.get('X-Request-ID')).toBe('admin-read-1')
  })

  it('rejects noncanonical, extra, or unsafe create inputs and metadata before fetch', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const invalidInputs = [
      { ...input, extra: true },
      { ...input, site_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'.toUpperCase() },
      { ...input, ja4: '' },
      { ...input, ja4: 'contains spaces' },
      { ...input, ja4: 'x'.repeat(129) },
      { ...input, snapshot_at: 'not-a-time' },
      { ...input, duration_seconds: 59 },
      { ...input, duration_seconds: 2_592_001 },
      { ...input, reason: 'Not_Stable' },
    ]
    for (const invalid of invalidInputs) {
      await expect(ja4BlocksApi.createTenant('token', invalid as JA4BlockCreateInput, metadata))
        .rejects.toMatchObject({ status: 400, code: 'invalid_request' })
    }
    for (const invalidMetadata of [
      { ...metadata, unexpected: true },
      { ...metadata, requestId: 'contains spaces' },
      { ...metadata, idempotencyKey: '' },
      { ...metadata, stepUpToken: '' },
      { ...metadata, stepUpToken: 'x'.repeat(8193) },
    ]) {
      await expect(ja4BlocksApi.createTenant('token', input, invalidMetadata as JA4BlockWriteMetadata))
        .rejects.toMatchObject({ status: 400, code: 'invalid_request' })
    }
    await expect(ja4BlocksApi.createAdmin('token', {
      ...input, tenant_scope_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'.toUpperCase(),
    }, metadata))
      .rejects.toMatchObject({ status: 400, code: 'invalid_request' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('strictly validates immutable workflow identity, states, optional pairs, and extra fields', async () => {
    const invalid = [
      { ...workflow, unexpected: true },
      { ...workflow, id: siteID },
      { ...workflow, tenant_scope_id: siteID },
      { ...workflow, ja4_sha256: digest.toUpperCase() },
      { ...workflow, phase: 'publishing' },
      { ...workflow, revision: 0 },
      { ...workflow, policy_revision: undefined },
      { ...workflow, binding_id: undefined },
      { ...workflow, edge_state: 'healthy' },
      { ...workflow, attempt_count: 101 },
      { ...workflow, last_error_code: 'RAW ERROR' },
      { ...workflow, replayed: 'false' },
    ]
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    for (const value of invalid) {
      fetchSpy.mockResolvedValueOnce(json(value))
      await expect(ja4BlocksApi.getAdmin('token', scopeID, workflowID))
        .rejects.toMatchObject({ code: 'invalid_response' })
    }
  })

  it('binds POST responses to the exact site, tenant, snapshot, duration, and reason', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    for (const value of [
      { ...workflow, tenant_scope_id: siteID },
      { ...workflow, site_id: scopeID },
      { ...workflow, snapshot_at: '2026-08-08T08:01:00Z' },
      { ...workflow, duration_seconds: 7200 },
      { ...workflow, reason: 'different_reason' },
    ]) {
      fetchSpy.mockResolvedValueOnce(json(value, 202))
      await expect(ja4BlocksApi.createAdmin('token', { ...input, tenant_scope_id: scopeID }, metadata))
        .rejects.toMatchObject({ code: 'invalid_response' })
    }
  })

  it('returns stable errors without server wording and treats non-schema error bodies as invalid', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ error: { code: 'ja4_block_permission_denied', request_id: 'request-403' } }, 403))
      .mockResolvedValueOnce(json({ error: { code: 'ja4_block_unavailable', request_id: 'request-503', message: 'private database topology' } }, 503))

    const denied = await ja4BlocksApi.getTenant('token', workflowID).catch((error: unknown) => error)
    expect(denied).toBeInstanceOf(ApiError)
    expect(denied).toMatchObject({ status: 403, code: 'ja4_block_permission_denied', requestId: 'request-403' })
    if (denied instanceof Error) expect(denied.message).not.toContain('private')
    await expect(ja4BlocksApi.getTenant('token', workflowID)).rejects.toMatchObject({ code: 'invalid_response' })
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('generates caller-owned metadata without retaining the step-up proof elsewhere', () => {
    const value = createJA4BlockWriteMetadata('one-time-step-up')
    expect(value).toEqual({
      requestId: expect.stringMatching(/^ja4-block-request-[A-Za-z0-9._-]+$/),
      idempotencyKey: expect.stringMatching(/^ja4-block-create-[A-Za-z0-9._-]+$/),
      stepUpToken: 'one-time-step-up',
    })
  })
})
