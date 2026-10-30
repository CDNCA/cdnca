import { ApiError } from './auth'
import {
  cnameAllocationsApi,
  type CnameAllocation,
  type CnameAllocationDiagnosis,
} from './cnameAllocations'

const scopeID = '11111111-1111-4111-8111-111111111111'
const allocationID = '22222222-2222-4222-8222-222222222222'
const siteID = '33333333-3333-4333-8333-333333333333'
const allocation: CnameAllocation = {
  id: allocationID,
  mode: 'site',
  owner_id: siteID,
  provider_id: '44444444-4444-4444-8444-444444444444',
  zone_id: '55555555-5555-4555-8555-555555555555',
  domain: 'example.com',
  hostname: 'edge.example.com',
  explicit_hostname: true,
  state: 'done',
  job_id: '66666666-6666-4666-8666-666666666666',
  generation: 3,
  current_revision: 4,
  lkg_revision: 3,
  created_at: '2026-08-07T08:00:00Z',
  updated_at: '2026-08-07T08:05:00Z',
}
const diagnosis: CnameAllocationDiagnosis = {
  site_id: siteID,
  mode: 'site',
  owner_id: siteID,
  allocation_id: allocationID,
  provider_id: allocation.provider_id,
  zone_id: allocation.zone_id,
  domain: allocation.domain,
  hostname: allocation.hostname,
  state: 'done',
  ready: true,
  reason_codes: ['lkg_available', 'ready'],
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('cnameAllocationsApi', () => {
  it('uses exact tenant list, detail, and diagnostic routes without a scope selector', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ items: [allocation], next_cursor: allocationID }))
      .mockResolvedValueOnce(json(allocation))
      .mockResolvedValueOnce(json(diagnosis))

    await expect(cnameAllocationsApi.list('tenant-token', { kind: 'tenant' }, {
      limit: 20,
      cursor: allocationID,
    })).resolves.toEqual({ items: [allocation], next_cursor: allocationID })
    await expect(cnameAllocationsApi.get('tenant-token', { kind: 'tenant' }, allocationID))
      .resolves.toEqual(allocation)
    await expect(cnameAllocationsApi.diagnose('tenant-token', { kind: 'tenant' }, {
      siteID,
      domain: 'example.com',
      hostname: 'edge.example.com',
    })).resolves.toEqual(diagnosis)

    expect(fetchSpy.mock.calls.map(([url]) => url)).toEqual([
      `/v1/cname-allocations?limit=20&cursor=${allocationID}`,
      `/v1/cname-allocations/${allocationID}`,
      `/v1/cname-allocations/diagnose?site_id=${siteID}&domain=example.com&hostname=edge.example.com`,
    ])
    for (const [, init] of fetchSpy.mock.calls) {
      expect(init?.credentials).toBe('include')
      expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer tenant-token')
      expect(new Headers(init?.headers).has('Content-Type')).toBe(false)
    }
  })

  it('uses exact platform variants with the explicit selected tenant scope', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ items: [] }))
      .mockResolvedValueOnce(json(allocation))
      .mockResolvedValueOnce(json(diagnosis))
    const audience = { kind: 'platform', scopeID } as const

    await cnameAllocationsApi.list('admin-token', audience, { limit: 50 })
    await cnameAllocationsApi.get('admin-token', audience, allocationID)
    await cnameAllocationsApi.diagnose('admin-token', audience, { siteID })

    expect(fetchSpy.mock.calls.map(([url]) => url)).toEqual([
      `/v1/admin/cname-allocations?scope_id=${scopeID}&limit=50`,
      `/v1/admin/cname-allocations/${allocationID}?scope_id=${scopeID}`,
      `/v1/admin/cname-allocations/diagnose?scope_id=${scopeID}&site_id=${siteID}`,
    ])
  })

  it.each([
    ['unknown allocation field', { ...allocation, private_claim: 'secret' }],
    ['missing allocation field', { ...allocation, owner_id: undefined }],
    ['uppercase UUID', { ...allocation, id: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }],
    ['unknown mode', { ...allocation, mode: 'tenant' }],
    ['unknown state', { ...allocation, state: 'ready' }],
    ['noncanonical domain', { ...allocation, domain: 'Example.com' }],
    ['invalid revision lineage', { ...allocation, lkg_revision: 5 }],
    ['invalid timestamp order', { ...allocation, updated_at: '2026-08-07T07:59:00Z' }],
  ])('rejects a malformed allocation payload: %s', async (_name, item) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [item] }))

    await expect(cnameAllocationsApi.list('token', { kind: 'tenant' }))
      .rejects.toMatchObject({ status: 502, code: 'cname_allocation_invalid_response' })
  })

  it.each([
    ['unknown page field', { items: [], count: 0 }],
    ['too many items', { items: Array.from({ length: 101 }, () => allocation) }],
    ['noncanonical next cursor', { items: [], next_cursor: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }],
    ['unknown diagnosis field', { ...diagnosis, trace: 'private' }],
    ['empty diagnosis reasons', { ...diagnosis, reason_codes: [] }],
    ['unsafe diagnosis code', { ...diagnosis, reason_codes: ['Raw private reason'] }],
  ])('rejects malformed response shape: %s', async (_name, body) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(body))
    const request = Object.hasOwn(body, 'items')
      ? cnameAllocationsApi.list('token', { kind: 'tenant' })
      : cnameAllocationsApi.diagnose('token', { kind: 'tenant' }, { siteID })

    await expect(request)
      .rejects.toMatchObject({ status: 502, code: 'cname_allocation_invalid_response' })
  })

  it.each([
    ['whitespace token', 'token with space', { kind: 'tenant' }, {}],
    ['invalid platform scope', 'token', { kind: 'platform', scopeID: 'INVALID' }, {}],
    ['unexpected tenant scope', 'token', { kind: 'tenant', scopeID }, {}],
    ['zero limit', 'token', { kind: 'tenant' }, { limit: 0 }],
    ['noncanonical cursor', 'token', { kind: 'tenant' }, { cursor: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }],
  ])('rejects invalid list input locally: %s', async (_name, token, audience, params) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    await expect(cnameAllocationsApi.list(token, audience as never, params as never))
      .rejects.toMatchObject({ status: 400, code: 'cname_allocation_validation_error' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['invalid allocation ID', () => cnameAllocationsApi.get('token', { kind: 'tenant' }, 'INVALID')],
    ['invalid site ID', () => cnameAllocationsApi.diagnose('token', { kind: 'tenant' }, { siteID: 'INVALID' })],
    ['uppercase domain', () => cnameAllocationsApi.diagnose('token', { kind: 'tenant' }, { siteID, domain: 'Example.com' })],
    ['trailing-dot hostname', () => cnameAllocationsApi.diagnose('token', { kind: 'tenant' }, { siteID, hostname: 'edge.example.com.' })],
  ])('rejects %s without a request', async (_name, request) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(request()).rejects.toMatchObject({ status: 400, code: 'cname_allocation_validation_error' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('strictly preserves known codes without exposing raw server or network messages', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ error: {
        code: 'permission_denied',
        message: 'raw tenant topology',
        request_id: 'cname-safe-1',
      } }, 403))
      .mockResolvedValueOnce(json({ error: {
        code: 'private_failure',
        message: 'raw private failure',
        request_id: 'cname-safe-2',
      } }, 503))
      .mockRejectedValueOnce(new TypeError('private socket address'))

    const denied = await cnameAllocationsApi.list('token', { kind: 'tenant' })
      .catch((error: unknown) => error)
    expect(denied).toBeInstanceOf(ApiError)
    expect(denied).toMatchObject({ status: 403, code: 'permission_denied', requestId: 'cname-safe-1' })
    expect(String(denied)).not.toContain('raw tenant topology')

    await expect(cnameAllocationsApi.list('token', { kind: 'tenant' }))
      .rejects.toMatchObject({ status: 503, code: 'request_failed', requestId: undefined })
    await expect(cnameAllocationsApi.list('token', { kind: 'tenant' }))
      .rejects.toMatchObject({ status: 0, code: 'network_error', message: 'Network request failed' })
  })
})
