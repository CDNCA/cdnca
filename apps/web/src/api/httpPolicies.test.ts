import { describe, expect, it, vi } from 'vitest'

import {
  emptyHttpPolicyConfig,
  httpPoliciesApi,
  type HttpPolicyConfig,
  type HttpPolicyWriteMetadata,
} from './httpPolicies'

const scopeID = '22222222-2222-4222-8222-222222222222'
const siteID = '33333333-3333-4333-8333-333333333333'
const ownerID = '44444444-4444-4444-8444-444444444444'
const policyID = '11111111-1111-4111-8111-111111111111'

const config: HttpPolicyConfig = {
  max_upload_bytes: 1024,
  request_headers: [{ kind: 'set', name: 'X-Request-Id', values: ['edge'] }],
  response_headers: [{ kind: 'add', name: 'X-Frame-Options', values: ['DENY'] }],
  rewrites: [], redirect_allowed_hosts: [], redirects: [], cors: null, referer_check: null,
}

const policy = {
  id: policyID, tenant_scope_id: scopeID, site_id: siteID, site_owner_user_id: ownerID,
  ...config, enabled: true, deleted: false, revision: 7, publication_revision: 3,
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
}

const metadata: HttpPolicyWriteMetadata = {
  idempotencyKey: 'http-policy-update-11111111-1111-4111-8111-111111111111',
  requestID: 'request-11111111-1111-4111-8111-111111111111',
  traceID: 'trace-11111111-1111-4111-8111-111111111111',
}

describe('httpPoliciesApi', () => {
  it('strictly validates list response shape and tenant/site/owner identity', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
    for (const changed of [
      { tenant_scope_id: '55555555-5555-4555-8555-555555555555' },
      { site_id: '55555555-5555-4555-8555-555555555555' },
      { site_owner_user_id: '55555555-5555-4555-8555-555555555555' },
      { internal: true },
    ]) {
      fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ items: [{ ...policy, ...changed }] }), { status: 200 }))
      await expect(httpPoliciesApi.list('token', scopeID, siteID, ownerID))
        .rejects.toMatchObject({ code: 'invalid_response' })
    }
    fetchMock.mockRestore()
  })

  it('rejects malformed nested configs and uses the contractual upload maximum default', async () => {
    expect(emptyHttpPolicyConfig().max_upload_bytes).toBe(1073741824)
    const fetchMock = vi.spyOn(globalThis, 'fetch')
    for (const changed of [
      { max_upload_bytes: 0 },
      { rewrites: [{ rule_id: 'rewrite-1' }] },
      { redirects: [{ rule_id: 'redirect-1', status: 306 }] },
      { cors: { allowed_origins: ['*'], allowed_methods: ['GET'] } },
    ]) {
      fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ items: [{ ...policy, ...changed }] }), { status: 200 }))
      await expect(httpPoliciesApi.list('token', scopeID, siteID, ownerID))
        .rejects.toMatchObject({ code: 'invalid_response' })
    }
    fetchMock.mockRestore()
  })

  it('sends exact CAS and frozen request metadata for update, toggle, and bodyless delete', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(
      async () => new Response(JSON.stringify(policy), { status: 200 }),
    )
    const identity = { scopeId: scopeID, siteId: siteID, ownerUserId: ownerID }

    await httpPoliciesApi.update('token', scopeID, policyID, 7, config, metadata, identity)
    await httpPoliciesApi.setEnabled('token', scopeID, policyID, 7, false, metadata, identity)
    await httpPoliciesApi.delete('token', scopeID, policyID, 7, metadata, identity)

    for (const call of fetchMock.mock.calls) {
      expect(call[1]?.headers).toEqual(expect.objectContaining({
        'If-Match': '"7"',
        'Idempotency-Key': metadata.idempotencyKey,
        'X-Request-ID': metadata.requestID,
        'X-Trace-ID': metadata.traceID,
      }))
    }
    expect(fetchMock.mock.calls[1]?.[0]).toBe(`/v1/tenant-scopes/${scopeID}/http-policies/${policyID}/disable`)
    expect(fetchMock.mock.calls[1]?.[1]).toEqual(expect.objectContaining({ method: 'POST', body: '{}' }))
    expect(fetchMock.mock.calls[2]?.[1]).toEqual(expect.objectContaining({ method: 'DELETE' }))
    expect(fetchMock.mock.calls[2]?.[1]).not.toHaveProperty('body')
    fetchMock.mockRestore()
  })

  it('validates the exact deterministic publication preview and rejects unknown fields', async () => {
    const preview = {
      state: 'preview', sha256: 'a'.repeat(64),
      snapshot: { schema_version: 'cdnca.edge.http-policy/v1', policy_version: 9, sites: [{ site_id: siteID, ...config }] },
    }
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(preview), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ...preview, signature: 'not-part-of-preview' }), { status: 200 }))

    await expect(httpPoliciesApi.preview('token', scopeID)).resolves.toEqual(preview)
    await expect(httpPoliciesApi.preview('token', scopeID)).rejects.toMatchObject({ code: 'invalid_response' })
    expect(fetchMock.mock.calls[0]?.[0]).toBe(`/v1/tenant-scopes/${scopeID}/http-policies/publication-preview`)
    fetchMock.mockRestore()
  })
})
