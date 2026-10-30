import { vi } from 'vitest'

import { urlAuthPoliciesApi, type URLAuthPolicyFields } from '../api/urlAuthPolicies'

const fields: URLAuthPolicyFields = {
  site_id: '33333333-3333-4333-8333-333333333333', name: 'Downloads', enabled: true,
  algorithm: 'hmac-sha256', signature_parameter: 'sig', expiration_parameter: 'exp', key_id_parameter: 'kid',
  bind_client_ip: true, max_clock_skew_seconds: 30, max_validity_seconds: 600, max_signature_uses: 1,
  excluded_query_parameters: ['utm_source'], trusted_proxy_cidrs: ['10.0.0.0/8'],
}

const policy = {
  ...fields,
  id: '44444444-4444-4444-8444-444444444444',
  scope_id: '22222222-2222-4222-8222-222222222222',
  site_id: undefined,
  site: { id: fields.site_id, domain: 'download.example' },
  current_key: { key_id: 'k-current', created_at: '2026-07-22T12:00:00Z' },
  version: 1,
  created_at: '2026-07-22T12:00:00Z',
  updated_at: '2026-07-22T12:00:00Z',
}

function response(value: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }))
}

describe('urlAuthPoliciesApi', () => {
  it('sends filters, optimistic revisions, idempotency keys, and revoke key IDs', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      const url = String(input)
      return calls.length === 1
        ? response({ items: [policy], total: 1, page: 2, limit: 50 })
        : url.endsWith('/rotate')
          ? response({ policy, secret: 'x'.repeat(43), replayed: false })
          : response({ policy, replayed: false })
    })

    await urlAuthPoliciesApi.list('token', { page: 2, limit: 50, status: 'enabled', name: 'down', site_id: fields.site_id })
    await urlAuthPoliciesApi.update('token', 'policy/id', 3, fields, 'update-key')
    await urlAuthPoliciesApi.rotate('token', 'policy/id', 4, 'rotate-key')
    await urlAuthPoliciesApi.revoke('token', 'policy/id', 5, 'k-previous', 'revoke-key')

    expect(calls[0].url).toContain(`page=2&limit=50&name=down&status=enabled&site_id=${fields.site_id}`)
    expect(calls[1].url).toContain('/v1/url-auth-policies/policy%2Fid')
    expect(new Headers(calls[1].init?.headers).get('If-Match')).toBe('"3"')
    expect(new Headers(calls[1].init?.headers).get('Idempotency-Key')).toBe('update-key')
    expect(new Headers(calls[2].init?.headers).get('If-Match')).toBe('"4"')
    expect(new Headers(calls[2].init?.headers).get('Idempotency-Key')).toBe('rotate-key')
    expect(new Headers(calls[3].init?.headers).get('If-Match')).toBe('"5"')
    expect(JSON.parse(String(calls[3].init?.body))).toEqual({ key_id: 'k-previous' })
  })

  it('keeps weak algorithms out of the typed create contract', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({ policy, secret: 'x'.repeat(43), replayed: false }, 201))
    await urlAuthPoliciesApi.create('token', fields, 'create-key')
    const body = JSON.parse(String(fetcher.mock.calls[0][1]?.body)) as URLAuthPolicyFields
    expect(body.algorithm).toBe('hmac-sha256')
    expect(body).not.toHaveProperty('migration_marker')
  })

  it('uses explicit enable and disable actions with the current revision', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      return response({ policy, replayed: false })
    })

    await urlAuthPoliciesApi.enable('token', 'policy/id', 6, 'enable-key')
    await urlAuthPoliciesApi.disable('token', 'policy/id', 7, 'disable-key')

    expect(calls.map((call) => call.url)).toEqual([
      expect.stringContaining('/v1/url-auth-policies/policy%2Fid/enable'),
      expect.stringContaining('/v1/url-auth-policies/policy%2Fid/disable'),
    ])
    expect(calls.map((call) => call.init?.method)).toEqual(['POST', 'POST'])
    expect(new Headers(calls[0].init?.headers).get('If-Match')).toBe('"6"')
    expect(new Headers(calls[1].init?.headers).get('Idempotency-Key')).toBe('disable-key')
  })

  it('sends the required empty JSON object for bodyless policy actions', async () => {
    const calls: RequestInit[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      calls.push(init ?? {})
      return calls.length === 1
        ? response({ policy, secret: 'x'.repeat(43), replayed: false })
        : response({ policy, replayed: false })
    })

    await urlAuthPoliciesApi.rotate('token', policy.id, 1, 'rotate-key')
    await urlAuthPoliciesApi.enable('token', policy.id, 1, 'enable-key')
    await urlAuthPoliciesApi.disable('token', policy.id, 1, 'disable-key')

    expect(calls.map((call) => call.body)).toEqual(['{}', '{}', '{}'])
    expect(calls.map((call) => new Headers(call.headers).get('Content-Type'))).toEqual([
      'application/json', 'application/json', 'application/json',
    ])
  })

  it('rejects missing first-use secrets and secrets returned on replay', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch')
    fetcher.mockImplementationOnce(() => response({ policy, replayed: false }, 201))
    await expect(urlAuthPoliciesApi.create('token', fields, 'create-key'))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })

    fetcher.mockImplementationOnce(() => response({ policy, secret: 'x'.repeat(43), replayed: true }))
    await expect(urlAuthPoliciesApi.rotate('token', 'policy', 1, 'rotate-key'))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })
})
