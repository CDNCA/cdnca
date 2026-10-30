import { vi } from 'vitest'

import {
  challengePoliciesApi,
  type ChallengePolicy,
  type ChallengePolicyConfig,
} from '../api/challengePolicies'

const scopeID = '22222222-2222-4222-8222-222222222222'
const siteID = '33333333-3333-4333-8333-333333333333'
const policyID = '44444444-4444-4444-8444-444444444444'
const cursor = 'eyJwYWdlIjoxfQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const host253 = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`
const host254 = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(62)}`

const config: ChallengePolicyConfig = {
  priority: 100,
  mode: 'click',
  min_delay_seconds: 0,
  challenge_ttl_seconds: 60,
  pass_ttl_seconds: 900,
  clock_skew_seconds: 5,
  attempts_per_nonce: 1,
  failure_window_seconds: 60,
  max_failures_per_window: 5,
  ip_binding: 'exact',
  bind_user_agent: true,
  bypass_routes: [{ kind: 'prefix', path: '/health/' }],
  key_reference: 'keyref:challenge-primary',
}

const policy: ChallengePolicy = {
  id: policyID,
  tenant_scope_id: scopeID,
  site_id: siteID,
  host: 'app.example.com',
  priority: 100,
  mode: 'click',
  min_delay_seconds: 0,
  challenge_ttl_seconds: 60,
  pass_ttl_seconds: 900,
  clock_skew_seconds: 5,
  attempts_per_nonce: 1,
  failure_window_seconds: 60,
  max_failures_per_window: 5,
  ip_binding: 'exact',
  bind_user_agent: true,
  bypass_routes: [{ kind: 'prefix', path: '/health/' }],
  key_reference_configured: true,
  external_provider_configured: false,
  enabled: true,
  deleted: false,
  revision: 3,
  created_at: '2026-08-01T08:00:00Z',
  updated_at: '2026-08-01T09:00:00Z',
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('challengePoliciesApi', () => {
  it('uses tenant-scoped cursor routes, exact filters, CAS, and durable write headers', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      calls.push({ url, init })
      if (!init?.method) return Promise.resolve(json({ items: [policy], next_cursor: cursor }))
      if (init.method === 'DELETE') return Promise.resolve(json({ ...policy, deleted: true, revision: 5 }))
      if (url.endsWith('/disable')) return Promise.resolve(json({ ...policy, enabled: false, revision: 7 }))
      if (url.endsWith('/enable')) return Promise.resolve(json({ ...policy, revision: 6 }))
      if (init.method === 'PATCH') return Promise.resolve(json({ ...policy, revision: 4 }))
      return Promise.resolve(json({ ...policy, revision: 1 }))
    })

    await challengePoliciesApi.list('token', scopeID, {
      limit: 20, cursor, site_id: siteID, host: 'app.example.com', enabled: true,
    })
    await challengePoliciesApi.create('token', scopeID, {
      site_id: siteID, host: 'app.example.com', enabled: true, config,
    }, 'create-key')
    await challengePoliciesApi.update('token', scopeID, policyID, 3, config, true, 'update-key')
    await challengePoliciesApi.remove('token', scopeID, policyID, 4, 'delete-key')
    await challengePoliciesApi.enable('token', scopeID, policyID, 5, 'enable-key')
    await challengePoliciesApi.disable('token', scopeID, policyID, 6, 'disable-key')

    expect(calls[0].url).toContain(`/v1/tenant-scopes/${scopeID}/challenge-policies?`)
    expect(calls[0].url).toContain('limit=20')
    expect(calls[0].url).toContain(`cursor=${encodeURIComponent(cursor)}`)
    expect(calls[0].url).toContain(`site_id=${siteID}`)
    expect(calls[0].url).toContain('host=app.example.com')
    expect(calls[0].url).toContain('enabled=true')
    expect(calls.slice(1).map((call) => call.init?.method)).toEqual(['POST', 'PATCH', 'DELETE', 'POST', 'POST'])
    expect(JSON.parse(String(calls[1].init?.body))).toEqual({ site_id: siteID, host: 'app.example.com', enabled: true, config })
    expect(JSON.parse(String(calls[2].init?.body))).toEqual({ config })
    expect(calls[3].init?.body).toBeUndefined()
    expect(calls[4].init?.body).toBe('{}')
    expect(calls[5].init?.body).toBe('{}')
    expect(calls.slice(1).map((call) => new Headers(call.init?.headers).get('Idempotency-Key')))
      .toEqual(['create-key', 'update-key', 'delete-key', 'enable-key', 'disable-key'])
    expect(calls.slice(2).map((call) => new Headers(call.init?.headers).get('If-Match')))
      .toEqual(['"3"', '"4"', '"5"', '"6"'])
    for (const call of calls) {
      const headers = new Headers(call.init?.headers)
      expect(headers.get('Authorization')).toBe('Bearer token')
      expect(headers.get('X-Request-ID')).toMatch(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/)
      expect(headers.get('X-Trace-ID')).toMatch(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/)
    }
  })

  it('strictly parses policies and opaque cursors without accepting secret references', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch')
    fetcher.mockResolvedValueOnce(json({ items: [policy], next_cursor: cursor }))
    await expect(challengePoliciesApi.list('token', scopeID, { limit: 20 })).resolves.toEqual({
      items: [policy], next_cursor: cursor,
    })

    for (const invalid of [
      { ...policy, key_reference: 'keyref:leaked' },
      { ...policy, provider: 'tencent' },
      { ...policy, revision: 0 },
      { ...policy, tenant_scope_id: siteID },
      { ...policy, bypass_routes: [{ kind: 'prefix', path: '/bad%2fpath/' }] },
    ]) {
      fetcher.mockResolvedValueOnce(json({ items: [invalid] }))
      await expect(challengePoliciesApi.list('token', scopeID, { limit: 20 }))
        .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
    }

    for (const invalidPage of [
      { items: [], next_cursor: '' },
      { items: [], next_cursor: 'x'.repeat(1025) },
      { items: [policy], next_cursor: 'not-a-signed-cursor' },
      { items: [policy], next_cursor: 'payload.bad+signature' },
      { items: [], total: 0 },
    ]) {
      fetcher.mockResolvedValueOnce(json(invalidPage))
      await expect(challengePoliciesApi.list('token', scopeID, { limit: 20 }))
        .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
    }

    fetcher.mockResolvedValueOnce(json({ items: [{ ...policy, host: 'other.example.com' }] }))
    await expect(challengePoliciesApi.list('token', scopeID, { limit: 20, host: 'app.example.com' }))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })

    fetcher.mockResolvedValueOnce(json({ items: [policy, policy] }))
    await expect(challengePoliciesApi.list('token', scopeID, { limit: 20 }))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('binds page cardinality and cursors to the requested limit', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch')
    const secondPolicy = { ...policy, id: '55555555-5555-4555-8555-555555555555' }

    fetcher.mockResolvedValueOnce(json({ items: [policy] }))
    await expect(challengePoliciesApi.list('token', scopeID, { limit: 1 }))
      .resolves.toEqual({ items: [policy] })

    fetcher.mockResolvedValueOnce(json({ items: [policy, secondPolicy] }))
    await expect(challengePoliciesApi.list('token', scopeID, { limit: 1 }))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })

    fetcher.mockResolvedValueOnce(json({ items: [], next_cursor: 'unexpected-next-page' }))
    await expect(challengePoliciesApi.list('token', scopeID, { limit: 20 }))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('rejects invalid list limits and cursors before fetch and forwards AbortSignal', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch')

    for (const limit of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 101]) {
      await expect(challengePoliciesApi.list('token', scopeID, { limit }))
        .rejects.toMatchObject({ status: 400, code: 'validation_error' })
    }
    for (const invalidCursor of ['', 'undotted', '.signature', 'payload.', 'payload.bad+signature', 'a.b.c', 'x'.repeat(1025)]) {
      await expect(challengePoliciesApi.list('token', scopeID, { limit: 20, cursor: invalidCursor }))
        .rejects.toMatchObject({ status: 400, code: 'validation_error' })
    }
    expect(fetcher).not.toHaveBeenCalled()

    const controller = new AbortController()
    fetcher.mockResolvedValueOnce(json({ items: [policy] }))
    await challengePoliciesApi.list('token', scopeID, { limit: 20, cursor }, controller.signal)
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(fetcher.mock.calls[0][1]?.signal).toBe(controller.signal)
  })

  it('accepts a 253-byte ASCII hostname and rejects 254 bytes', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch')
    fetcher.mockResolvedValueOnce(json({ items: [{ ...policy, host: host253 }] }))
    await expect(challengePoliciesApi.list('token', scopeID, { limit: 20 }))
      .resolves.toMatchObject({ items: [{ host: host253 }] })

    fetcher.mockResolvedValueOnce(json({ items: [{ ...policy, host: host254 }] }))
    await expect(challengePoliciesApi.list('token', scopeID, { limit: 20 }))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('binds every create and update success fact to the submitted configuration', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch')
    const created = { ...policy, revision: 1 }
    const mismatches: ChallengePolicy[] = [
      { ...created, priority: 101 },
      { ...created, mode: 'slider' },
      { ...created, challenge_ttl_seconds: 61 },
      { ...created, pass_ttl_seconds: 901 },
      { ...created, clock_skew_seconds: 6 },
      { ...created, failure_window_seconds: 61 },
      { ...created, max_failures_per_window: 6 },
      { ...created, ip_binding: 'none' },
      { ...created, bind_user_agent: false },
      { ...created, bypass_routes: [{ kind: 'exact', path: '/other' }] },
      { ...created, key_reference_configured: false },
      { ...created, enabled: false },
    ]
    for (const mismatch of mismatches) {
      fetcher.mockResolvedValueOnce(json(mismatch, 201))
      await expect(challengePoliciesApi.create('token', scopeID, {
        site_id: siteID, host: policy.host, enabled: true, config,
      }, 'create-key')).rejects.toMatchObject({ status: 502, code: 'invalid_response' })

      fetcher.mockResolvedValueOnce(json({ ...mismatch, revision: 4 }))
      await expect(challengePoliciesApi.update('token', scopeID, policyID, 3, config, true, 'update-key'))
        .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
    }

    fetcher.mockResolvedValueOnce(json({ ...policy, enabled: false, revision: 4 }))
    await expect(challengePoliciesApi.update('token', scopeID, policyID, 3, config, true, 'update-key'))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })

    const externalConfig: ChallengePolicyConfig = {
      ...config,
      mode: 'external',
      external_provider: { provider: 'tencent', app_reference: 'appref:tencent-primary' },
    }
    fetcher.mockResolvedValueOnce(json({
      ...created,
      mode: 'external',
      external_provider_configured: true,
    }, 201))
    await expect(challengePoliciesApi.create('token', scopeID, {
      site_id: siteID, host: policy.host, enabled: true, config: externalConfig,
    }, 'external-key')).resolves.toMatchObject({ mode: 'external', external_provider_configured: true })

    fetcher.mockResolvedValueOnce(json({
      ...policy,
      mode: 'external',
      external_provider_configured: true,
      revision: 4,
    }))
    await expect(challengePoliciesApi.update('token', scopeID, policyID, 3, externalConfig, true, 'external-update-key'))
      .resolves.toMatchObject({ mode: 'external', external_provider_configured: true })
  })

  it('independently rejects a delay-mode minimum-delay response mismatch', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch')
    const delayConfig: ChallengePolicyConfig = { ...config, mode: 'delay', min_delay_seconds: 5 }
    const mismatched = { ...policy, mode: 'delay', min_delay_seconds: 6 }

    fetcher.mockResolvedValueOnce(json({ ...mismatched, revision: 1 }, 201))
    await expect(challengePoliciesApi.create('token', scopeID, {
      site_id: siteID, host: policy.host, enabled: true, config: delayConfig,
    }, 'delay-create-key')).rejects.toMatchObject({ status: 502, code: 'invalid_response' })

    fetcher.mockResolvedValueOnce(json({ ...mismatched, revision: 4 }))
    await expect(challengePoliciesApi.update(
      'token', scopeID, policyID, 3, delayConfig, true, 'delay-update-key',
    )).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('rejects malformed JSON and resource responses that do not bind the requested scope and id', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch')
    fetcher.mockResolvedValueOnce(new Response('{', { status: 200 }))
    await expect(challengePoliciesApi.list('token', scopeID, { limit: 20 }))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })

    fetcher.mockResolvedValueOnce(json({ ...policy, id: siteID }))
    await expect(challengePoliciesApi.update('token', scopeID, policyID, 3, config, true, 'update-key'))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })

    fetcher.mockResolvedValueOnce(json(policy))
    await expect(challengePoliciesApi.update('token', scopeID, policyID, 3, config, true, 'update-key'))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })

    fetcher.mockResolvedValueOnce(json({ ...policy, tenant_scope_id: siteID }))
    await expect(challengePoliciesApi.create('token', scopeID, {
      site_id: siteID, host: 'app.example.com', enabled: true, config,
    }, 'create-key')).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('supports every frozen challenge mode while keeping provider references write-only', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      const body = JSON.parse(String(init?.body)) as { config: ChallengePolicyConfig }
      const safeConfig: Partial<ChallengePolicyConfig> = { ...body.config }
      delete safeConfig.key_reference
      delete safeConfig.external_provider
      return Promise.resolve(json({
        ...policy,
        ...safeConfig,
        key_reference_configured: true,
        external_provider_configured: Boolean(body.config.external_provider),
        revision: 1,
      }, 201))
    })
    for (const mode of ['delay', 'click', 'slider', 'captcha', 'external'] as const) {
      const nextConfig: ChallengePolicyConfig = {
        ...config,
        mode,
        min_delay_seconds: mode === 'delay' ? 5 : 0,
        ...(mode === 'external'
          ? { external_provider: { provider: 'geetest-v4', app_reference: 'appref:challenge-primary' } }
          : {}),
      }
      await challengePoliciesApi.create('token', scopeID, {
        site_id: siteID, host: 'app.example.com', enabled: true, config: nextConfig,
      }, `create-${mode}`)
      const body = JSON.parse(String(fetcher.mock.calls.at(-1)?.[1]?.body))
      expect(body.config.mode).toBe(mode)
      expect(body.config.key_reference).toBe('keyref:challenge-primary')
    }
    expect(policy).not.toHaveProperty('key_reference')
    expect(policy).not.toHaveProperty('external_provider')
  })
})
