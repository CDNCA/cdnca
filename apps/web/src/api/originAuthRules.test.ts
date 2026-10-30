import { ApiError } from './auth'
import {
  originAuthRulesApi,
  type OriginAuthRule,
  type OriginAuthRuleConfig,
} from './originAuthRules'

const scopeID = '11111111-1111-4111-8111-111111111111'
const ruleID = '22222222-2222-4222-8222-222222222222'
const siteID = '33333333-3333-4333-8333-333333333333'
const credentialID = '44444444-4444-4444-8444-444444444444'

const config: OriginAuthRuleConfig = {
  provider: 's3',
  algorithm: 'aws4-hmac-sha256',
  endpoint: 'https://objects.example.com',
  bucket: 'media',
  path_prefix: '/',
  region: 'us-east-1',
  service: 's3',
  signature_ttl_seconds: 900,
  current_credential: { credential_id: credentialID, revision: 2 },
}

const rule: OriginAuthRule = {
  id: ruleID,
  tenant_scope_id: scopeID,
  site_id: siteID,
  source_position: 1,
  ...config,
  enabled: true,
  deleted: false,
  revision: 7,
  created_at: '2026-08-07T01:00:00Z',
  updated_at: '2026-08-07T02:00:00Z',
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json', ETag: '"7"' },
  })
}

describe('originAuthRulesApi', () => {
  it('uses the exact mounted list/detail routes and supported filters', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ items: [rule], next_cursor: 'next-page' }))
      .mockResolvedValueOnce(json(rule))

    await expect(originAuthRulesApi.list('token', scopeID, {
      siteID,
      enabled: false,
      limit: 20,
      cursor: 'current-page',
    })).resolves.toEqual({ items: [rule], next_cursor: 'next-page' })
    await expect(originAuthRulesApi.get('token', scopeID, ruleID)).resolves.toEqual(rule)

    expect(fetchSpy.mock.calls[0]?.[0]).toBe(
      `/v1/tenant-scopes/${scopeID}/origin-auth/rules?site_id=${siteID}&enabled=false&limit=20&cursor=current-page`,
    )
    expect(fetchSpy.mock.calls[1]?.[0]).toBe(
      `/v1/tenant-scopes/${scopeID}/origin-auth/rules/${ruleID}`,
    )
    for (const [, init] of fetchSpy.mock.calls) {
      expect(init?.credentials).toBe('include')
      expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer token')
    }
  })

  it('uses canonical bodies, CAS, and caller-owned idempotency keys for every write', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(rule))

    await originAuthRulesApi.create('token', scopeID, {
      site_id: siteID, source_position: 1, config, enabled: false,
    }, 'create-key')
    await originAuthRulesApi.update('token', scopeID, ruleID, { config }, 7, 'update-key')
    await originAuthRulesApi.remove('token', scopeID, ruleID, 7, 'delete-key')
    await originAuthRulesApi.setEnabled('token', scopeID, ruleID, true, 7, 'enable-key')
    await originAuthRulesApi.setEnabled('token', scopeID, ruleID, false, 8, 'disable-key')
    await originAuthRulesApi.rotate('token', scopeID, ruleID, {
      current_credential: { credential_id: credentialID, revision: 3 },
      activate_current_at: '2026-08-08T01:00:00Z',
    }, 9, 'rotate-key')

    const expected = [
      ['POST', `/v1/tenant-scopes/${scopeID}/origin-auth/rules`, 'create-key', null],
      ['PATCH', `/v1/tenant-scopes/${scopeID}/origin-auth/rules/${ruleID}`, 'update-key', '"7"'],
      ['DELETE', `/v1/tenant-scopes/${scopeID}/origin-auth/rules/${ruleID}`, 'delete-key', '"7"'],
      ['POST', `/v1/tenant-scopes/${scopeID}/origin-auth/rules/${ruleID}/enable`, 'enable-key', '"7"'],
      ['POST', `/v1/tenant-scopes/${scopeID}/origin-auth/rules/${ruleID}/disable`, 'disable-key', '"8"'],
      ['POST', `/v1/tenant-scopes/${scopeID}/origin-auth/rules/${ruleID}/rotate`, 'rotate-key', '"9"'],
    ] as const
    expect(fetchSpy).toHaveBeenCalledTimes(expected.length)
    expected.forEach(([method, path, key, revision], index) => {
      const [url, init] = fetchSpy.mock.calls[index]!
      const headers = new Headers(init?.headers)
      expect(url).toBe(path)
      expect(init?.method).toBe(method)
      expect(headers.get('Idempotency-Key')).toBe(key)
      expect(headers.get('If-Match')).toBe(revision)
    })
    expect(JSON.parse(String(fetchSpy.mock.calls[0]?.[1]?.body))).toEqual({
      site_id: siteID, source_position: 1, config, enabled: false,
    })
    expect(JSON.parse(String(fetchSpy.mock.calls[2]?.[1]?.body))).toEqual({})
    expect(JSON.parse(String(fetchSpy.mock.calls[5]?.[1]?.body))).toEqual({
      current_credential: { credential_id: credentialID, revision: 3 },
      activate_current_at: '2026-08-08T01:00:00Z',
    })
  })

  it.each([
    ['invalid scope', 'not-a-scope', {}, undefined],
    ['invalid site', scopeID, { siteID: 'wrong' }, undefined],
    ['invalid limit', scopeID, { limit: 101 }, undefined],
    ['empty cursor', scopeID, { cursor: '' }, undefined],
    ['token whitespace', scopeID, {}, 'bad token'],
  ])('rejects %s locally with zero requests', async (_name, scope, params, token) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(originAuthRulesApi.list(token ?? 'token', scope, params as never))
      .rejects.toMatchObject({ status: 400, code: 'origin_auth_validation_error' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('rejects malformed success payloads, wrong-scope resources, and leaked secret fields', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ items: [{ ...rule, secret_access_key: 'private' }] }))
      .mockResolvedValueOnce(json({ ...rule, tenant_scope_id: '55555555-5555-4555-8555-555555555555' }))
      .mockResolvedValueOnce(json({ ...rule, revision: 0 }))

    await expect(originAuthRulesApi.list('token', scopeID))
      .rejects.toMatchObject({ status: 502, code: 'origin_auth_invalid_response' })
    await expect(originAuthRulesApi.get('token', scopeID, ruleID))
      .rejects.toMatchObject({ status: 502, code: 'origin_auth_scope_mismatch' })
    await expect(originAuthRulesApi.get('token', scopeID, ruleID))
      .rejects.toMatchObject({ status: 502, code: 'origin_auth_invalid_response' })
  })

  it('maps stable errors without exposing raw server or network messages', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ error: {
        code: 'origin_auth_precondition_failed',
        message: 'raw database revision detail',
        request_id: 'safe-request-1',
        trace_id: 'safe-trace-1',
      } }, 412))
      .mockResolvedValueOnce(json({ error: {
        code: 'BAD CODE', message: 'private topology', request_id: 'unsafe request', trace_id: 'trace',
      } }, 503))
      .mockRejectedValueOnce(new TypeError('private socket address'))

    const stale = await originAuthRulesApi.list('token', scopeID).catch((error: unknown) => error)
    expect(stale).toBeInstanceOf(ApiError)
    expect(stale).toMatchObject({ status: 412, code: 'origin_auth_precondition_failed', requestId: 'safe-request-1' })
    expect(String(stale)).not.toContain('raw database revision detail')
    await expect(originAuthRulesApi.list('token', scopeID))
      .rejects.toMatchObject({ status: 503, code: 'request_failed' })
    await expect(originAuthRulesApi.list('token', scopeID))
      .rejects.toMatchObject({ status: 0, code: 'network_error', message: 'Network request failed' })
  })
})
