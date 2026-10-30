import { afterEach, describe, expect, it, vi } from 'vitest'

import { siteCapturePolicyApi, type SiteCapturePolicyDocument } from './siteCapturePolicy'

const scopeID = '11111111-1111-4111-8111-111111111111'
const siteID = '22222222-2222-4222-8222-222222222222'
const userID = '33333333-3333-4333-8333-333333333333'
const document: SiteCapturePolicyDocument = {
  enabled: true, methods: ['POST'], uri_prefixes: ['/api'], request_header_allowlist: ['Authorization'],
  response_header_allowlist: [], request_body_field_allowlist: [], response_body_field_allowlist: [],
  max_value_bytes: 4096, max_body_bytes: 65536, max_event_bytes: 1048576,
}

function policy() {
  return { scope_id: scopeID, site_id: siteID, revision: 4, document, evidence_digest: 'a'.repeat(64),
    updated_at: '2026-08-08T00:00:00Z', updated_by: userID, request_id: 'request-4' }
}

afterEach(() => vi.unstubAllGlobals())

describe('siteCapturePolicyApi', () => {
  it('binds exact tenant/site identity and stable write metadata', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ policy: policy(), replayed: false }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetchMock)
    const input = { expected_revision: 3, document }
    const result = await siteCapturePolicyApi.update('token', scopeID, siteID, input, {
      idempotencyKey: 'capture-3', requestID: 'request-3', traceID: 'trace-3',
    })
    expect(result.policy.revision).toBe(4)
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(`/v1/tenant-scopes/${scopeID}/sites/${siteID}/telemetry-capture-policy`)
    expect(init.method).toBe('PUT')
    expect(init.body).toBe(JSON.stringify(input))
    expect(init.headers).toMatchObject({ Authorization: 'Bearer token', 'Idempotency-Key': 'capture-3', 'X-Request-ID': 'request-3', 'X-Trace-ID': 'trace-3' })
  })

  it('decodes the explicit unconfigured state (revision 0, capture off) and rejects a forged one', async () => {
    const off = { ...document, enabled: false, methods: [], uri_prefixes: [], request_header_allowlist: [] }
    const body = { scope_id: scopeID, site_id: siteID, state: 'unconfigured', revision: 0, document: off }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status: 200 })))
    await expect(siteCapturePolicyApi.get('token', scopeID, siteID)).resolves.toEqual(body)
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ ...body, revision: 1 }), { status: 200 })))
    await expect(siteCapturePolicyApi.get('token', scopeID, siteID)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('rejects a mismatched repository identity as an invalid response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ ...policy(), site_id: scopeID }), { status: 200 })))
    await expect(siteCapturePolicyApi.get('token', scopeID, siteID)).rejects.toMatchObject({ code: 'invalid_response' })
  })
})
