import { vi } from 'vitest'

import { ApiError } from './auth'
import {
  cachePoliciesApi,
  type CachePolicyDocument,
  type CachePolicyView,
  type PublishCachePolicyInput,
} from './cachePolicies'

const siteID = '33333333-3333-4333-8333-333333333333'
const actorID = '44444444-4444-4444-8444-444444444444'
const cursor = 'eyJraW5kIjoicG9saWN5X2hpc3RvcnkifQ.signature'

const document: CachePolicyDocument = {
  mode: 'override',
  rules: [{
    order: 1,
    extensions: ['.css', '.js'],
    path_prefix: '/assets/',
    status_codes: [200, 206],
    ttl_seconds: 3600,
  }],
  query_mode: 'include',
  query_names: ['lang', 'version'],
  vary_headers: ['accept-encoding'],
  disk_quota_bytes: 1024 * 1024 * 1024,
}

const definitionID = '55555555-5555-4555-8555-555555555555'

const view: CachePolicyView = {
  site_id: siteID,
  revision: 7,
  binding_mode: 'override',
  definition_id: siteID,
  definition_revision: 3,
  document,
  created_by_user_id: actorID,
  request_id: 'cache-policy-publish-7',
  created_at: '2026-08-04T08:00:00Z',
}

const input: PublishCachePolicyInput = { expected_revision: 7, document }

function jsonResponse(value: unknown, status = 200): Promise<Response> {
  return Promise.resolve(new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  }))
}

function errorResponse(status: number, code: string): Promise<Response> {
  return jsonResponse({ error: { code, message: 'server detail', request_id: 'request-error-1' } }, status)
}

describe('cachePoliciesApi', () => {
  it('uses tenant-only current, history, and revision routes with read headers', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((url, init) => {
      calls.push({ url: String(url), init })
      if (String(url).includes('/revisions?')) {
        return jsonResponse({ items: [view, { ...view, revision: 6 }], next_cursor: cursor })
      }
      if (String(url).endsWith('/revisions/6')) return jsonResponse({ ...view, revision: 6 })
      return jsonResponse(view)
    })

    await expect(cachePoliciesApi.get('token', siteID)).resolves.toEqual(view)
    await expect(cachePoliciesApi.history('token', siteID, { limit: 20, cursor })).resolves.toEqual({
      items: [view, { ...view, revision: 6 }], next_cursor: cursor,
    })
    await expect(cachePoliciesApi.getRevision('token', siteID, 6)).resolves.toEqual({ ...view, revision: 6 })

    expect(calls.map((call) => new URL(call.url, 'https://control.example').pathname)).toEqual([
      `/v1/cache-policies/${siteID}`,
      `/v1/cache-policies/${siteID}/revisions`,
      `/v1/cache-policies/${siteID}/revisions/6`,
    ])
    expect(Object.fromEntries(new URL(calls[1]!.url, 'https://control.example').searchParams)).toEqual({
      limit: '20', cursor,
    })
    for (const call of calls) {
      const parsed = new URL(call.url, 'https://control.example')
      const headers = new Headers(call.init?.headers)
      expect(parsed.pathname).not.toContain('/admin/')
      expect(parsed.searchParams.has('scope_id')).toBe(false)
      expect(headers.get('Authorization')).toBe('Bearer token')
      expect(headers.get('X-Request-ID')).toMatch(/^cache-policy-(get|history|revision)-/)
      expect(headers.has('Content-Type')).toBe(false)
      expect(call.init?.credentials).toBe('include')
    }
  })

  it('site-parity3b: a platform administrator uses the admin route with the site tenant scope', async () => {
    const scopeID = '33333333-3333-4333-8333-333333333333'
    const calls: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((url, init) => {
      calls.push(String(url))
      if (String(url).includes('/revisions?')) return jsonResponse({ items: [view] })
      if (String(url).includes('/revisions/6')) return jsonResponse({ ...view, revision: 6 })
      return init?.method === 'POST' ? jsonResponse({ ...view, revision: 8 }, 201) : jsonResponse(view)
    })
    await cachePoliciesApi.get('token', siteID, scopeID)
    await cachePoliciesApi.history('token', siteID, { limit: 20 }, scopeID)
    await cachePoliciesApi.getRevision('token', siteID, 6, scopeID)
    await cachePoliciesApi.publish('token', siteID, input, 'admin-save', undefined, scopeID)
    expect(calls.map((url) => {
      const parsed = new URL(url, 'https://control.example')
      return [parsed.pathname, parsed.searchParams.get('scope_id'), parsed.searchParams.get('limit')]
    })).toEqual([
      [`/v1/admin/cache-policies/${siteID}`, scopeID, null],
      [`/v1/admin/cache-policies/${siteID}/revisions`, scopeID, '20'],
      [`/v1/admin/cache-policies/${siteID}/revisions/6`, scopeID, null],
      [`/v1/admin/cache-policies/${siteID}`, scopeID, null],
    ])
  })

  it('publishes expected_revision with one idempotency key and no invented policy fields', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation((_url, init) => {
      expect(init?.method).toBe('POST')
      return jsonResponse({ ...view, revision: 8 }, 201)
    })

    await expect(cachePoliciesApi.publish('token', siteID, input, 'policy-save-1'))
      .resolves.toEqual({ ...view, revision: 8 })

    const [url, init] = fetcher.mock.calls[0]!
    const headers = new Headers(init?.headers)
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>
    const outgoingDocument = body.document as Record<string, unknown>
    expect(new URL(String(url), 'https://control.example').pathname).toBe(`/v1/cache-policies/${siteID}`)
    expect(headers.get('Authorization')).toBe('Bearer token')
    expect(headers.get('Content-Type')).toBe('application/json')
    expect(headers.get('Idempotency-Key')).toBe('policy-save-1')
    expect([...headers.keys()].filter((name) => name === 'idempotency-key')).toHaveLength(1)
    expect(headers.get('X-Request-ID')).toMatch(/^cache-policy-publish-/)
    expect(body.expected_revision).toBe(7)
    expect(Object.keys(outgoingDocument).sort()).toEqual([
      'disk_quota_bytes', 'mode', 'query_mode', 'query_names', 'rules', 'vary_headers',
    ])
    expect(JSON.stringify(body)).not.toMatch(/browser|action|force_cache|no_cache/i)
  })

  it('replays only the canonical serialized write body byte-for-byte with the same idempotency key', async () => {
    const serializedBody = JSON.stringify(input)
    const bodies: BodyInit[] = []
    const keys: Array<string | null> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((_url, init) => {
      bodies.push(init?.body as BodyInit)
      keys.push(new Headers(init?.headers).get('Idempotency-Key'))
      return jsonResponse({ ...view, revision: 8 }, 201)
    })

    await cachePoliciesApi.publish('token', siteID, input, 'policy-replay-1', serializedBody)
    await cachePoliciesApi.publish('token', siteID, input, 'policy-replay-1', serializedBody)

    expect(bodies).toEqual([serializedBody, serializedBody])
    expect(keys).toEqual(['policy-replay-1', 'policy-replay-1'])
  })

  it('rejects non-canonical or semantically different serialized bodies before fetch', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch')
    const invalidBodies = [
      ` ${JSON.stringify(input)}`,
      JSON.stringify({ document: input.document, expected_revision: input.expected_revision }),
      JSON.stringify({
        ...input,
        document: { ...input.document, rules: [{ ...input.document.rules[0]!, ttl_seconds: 7200 }] },
      }),
      JSON.stringify({
        ...input,
        document: { ...input.document, browser_ttl_seconds: 60 },
      }),
      JSON.stringify({ ...input, expected_revision: input.expected_revision + 1 }),
    ]

    for (const serializedBody of invalidBodies) {
      await expect(cachePoliciesApi.publish(
        'token', siteID, input, 'policy-invalid-serialized', serializedBody,
      )).rejects.toMatchObject({ status: 400, code: 'invalid_request' })
    }
    expect(fetcher).not.toHaveBeenCalled()
  })

  it.each([
    [403, 'permission_denied'],
    [409, 'idempotency_conflict'],
    [412, 'revision_conflict'],
    [422, 'validation_error'],
    [503, 'service_unavailable'],
  ])('preserves %i API errors as stable ApiError values', async (status, code) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => errorResponse(status, code))

    const promise = cachePoliciesApi.publish('token', siteID, input, 'policy-error-1')
    await expect(promise).rejects.toBeInstanceOf(ApiError)
    await expect(cachePoliciesApi.publish('token', siteID, input, 'policy-error-2'))
      .rejects.toMatchObject({ status, code, requestId: 'request-error-1' })
  })

  it('maps transport failures with networkApiError', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('offline'))

    await expect(cachePoliciesApi.get('token', siteID))
      .rejects.toMatchObject({ status: 0, code: 'network_error' })
    await expect(cachePoliciesApi.history('token', siteID, {}))
      .rejects.toMatchObject({ status: 0, code: 'network_error' })
    await expect(cachePoliciesApi.publish('token', siteID, input, 'policy-offline-1'))
      .rejects.toMatchObject({ status: 0, code: 'network_error' })
  })

  it('rejects malformed and structurally invalid success responses with their response status', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch')
    fetcher.mockResolvedValueOnce(new Response('{', { status: 200 }))
    await expect(cachePoliciesApi.get('token', siteID))
      .rejects.toMatchObject({ status: 200, code: 'invalid_response' })

    for (const invalid of [
      { ...view, site_id: actorID },
      { ...view, revision: 0 },
      { ...view, created_at: 'not-a-time' },
      { ...view, binding_mode: 'shared' },
      { ...view, definition_id: 'not-a-uuid' },
      { ...view, definition_revision: 0 },
      Object.fromEntries(Object.entries(view).filter(([key]) => key !== 'binding_mode')),
      // browser_ttl_seconds is a rule key, never a document key (v1 or v2)
      { ...view, document: { ...document, browser_ttl_seconds: 60 } },
      // a v1 document (no schema_version) refuses v2 rule keys (validate.go:462)
      { ...view, document: { ...document, rules: [{ ...document.rules[0], action: 'cache' }] } },
      { ...view, document: { ...document, mode: 'enabled' } },
      { ...view, document: { ...document, query_mode: 'include', query_names: [] } },
      { ...view, document: { ...document, disk_quota_bytes: 1 } },
    ]) {
      fetcher.mockResolvedValueOnce(await jsonResponse(invalid))
      await expect(cachePoliciesApi.get('token', siteID))
        .rejects.toMatchObject({ status: 200, code: 'invalid_response' })
    }

    fetcher.mockResolvedValueOnce(await jsonResponse({ items: [view], next_cursor: 7 }))
    await expect(cachePoliciesApi.history('token', siteID, { limit: 20 }))
      .rejects.toMatchObject({ status: 200, code: 'invalid_response' })

    fetcher.mockResolvedValueOnce(await jsonResponse({ ...view, revision: 9 }, 201))
    await expect(cachePoliciesApi.publish('token', siteID, input, 'policy-invalid-success'))
      .rejects.toMatchObject({ status: 201, code: 'invalid_response' })
  })
})

describe('ge-cache policy extensions and flush', () => {
  afterEach(() => vi.restoreAllMocks())

  it('accepts and publishes the v2 extensions only when on', async () => {
    const extended: CachePolicyDocument = { ...document, stale_if_error: true, background_update: true, max_object_bytes: 1 << 30, slice_bytes: 1 << 20 }
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...view, revision: 8, document: extended }), { status: 200 }))
    const saved = await cachePoliciesApi.publish('token', siteID, { expected_revision: 7, document: extended }, 'key-1')
    expect(saved.document.slice_bytes).toBe(1 << 20)
    const body = JSON.parse(String(fetchMock.mock.calls[0]![1]!.body))
    expect(body.document).toMatchObject({ stale_if_error: true, background_update: true, max_object_bytes: 1 << 30, slice_bytes: 1 << 20 })
    expect(body.document).not.toHaveProperty('min_object_bytes')
  })

  it('refuses a response with background update but no stale-if-error', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...view, document: { ...document, background_update: true } }), { status: 200 }))
    await expect(cachePoliciesApi.get('token', siteID)).rejects.toMatchObject({ code: 'invalid_response' })
  })
})

describe('cache policy view matches cachecontrolhttp.PolicyView (N6)', () => {
  afterEach(() => vi.restoreAllMocks())

  // Exactly the JSON keys services/control-api/internal/cachecontrolhttp/model.go
  // PolicyView emits (none is omitempty), in its field order.
  const backendView = {
    site_id: siteID,
    revision: 2,
    binding_mode: 'inherit',
    definition_id: definitionID,
    definition_revision: 4,
    document: {
      mode: 'follow_origin', rules: [], query_mode: 'preserve', query_names: [], vary_headers: [],
      disk_quota_bytes: 67_108_864,
    },
    created_by_user_id: actorID,
    request_id: 'req-b1c2',
    created_at: '2026-10-23T20:17:26.123456Z',
  }

  it('parses the full backend response shape for current, revision and history', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch')
    fetcher.mockImplementation(() => jsonResponse(backendView))
    await expect(cachePoliciesApi.get('token', siteID)).resolves.toEqual(backendView)
    await expect(cachePoliciesApi.getRevision('token', siteID, 2)).resolves.toEqual(backendView)
    fetcher.mockImplementation(() => jsonResponse({ items: [backendView, { ...backendView, revision: 1, binding_mode: 'override', definition_id: siteID, definition_revision: 1 }] }))
    const page = await cachePoliciesApi.history('token', siteID, {})
    expect(page.items.map((item) => [item.binding_mode, item.definition_revision])).toEqual([['inherit', 4], ['override', 1]])
  })

  it('still rejects a field the backend does not send', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => jsonResponse({ ...backendView, tenant_id: actorID }))
    await expect(cachePoliciesApi.get('token', siteID)).rejects.toMatchObject({ code: 'invalid_response' })
  })
})

describe('schema v2 cache policy documents (n6b)', () => {
  afterEach(() => vi.restoreAllMocks())

  // Exactly what marketsupply.cacheDocument (marketsupply/cache.go:33-77)
  // stores for a market site and PolicyDocument.MarshalJSON returns
  // (captured from the Go code, 2026-10-24).
  const marketDocument = {
    schema_version: 2,
    mode: 'override',
    rules: [
      { order: 1, extensions: ['.css', '.js'], action: 'cache', ttl_seconds: 86400, browser_ttl_seconds: 3600 },
      { order: 2, path_prefix: '/api/', action: 'no_cache', ttl_seconds: 0, browser_ttl_seconds: 0 },
      { order: 3, action: 'cache', ttl_seconds: 600, browser_ttl_seconds: 0 },
    ],
    query_mode: 'ignore',
    query_names: [],
    vary_headers: [],
    disk_quota_bytes: 1_073_741_824,
  }
  const v2View = { ...view, document: marketDocument }

  it('parses the v2 document a market install writes, through get, revision and history', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch')
    fetcher.mockImplementation(() => jsonResponse(v2View))
    await expect(cachePoliciesApi.get('token', siteID)).resolves.toEqual(v2View)
    await expect(cachePoliciesApi.getRevision('token', siteID, 7)).resolves.toEqual(v2View)
    fetcher.mockImplementation(() => jsonResponse({ items: [{ ...v2View, revision: 8 }, view] }))
    const page = await cachePoliciesApi.history('token', siteID, {})
    expect(page.items.map((item) => item.document.schema_version)).toEqual([2, undefined])
  })

  it('accepts v2 with conditions and extensions', async () => {
    const extended = {
      ...marketDocument,
      rules: [{ order: 1, action: 'cache', ttl_seconds: 60, browser_ttl_seconds: 60, path_regex: '^/a', content_types: ['image/*'] }],
      stale_if_error: true,
    }
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => jsonResponse({ ...view, document: extended }))
    await expect(cachePoliciesApi.get('token', siteID)).resolves.toMatchObject({ document: extended })
  })

  it.each([
    ['schema_version 1 spelled out', { ...marketDocument, schema_version: 1 }],
    ['schema_version 3', { ...marketDocument, schema_version: 3 }],
    ['schema_version as a string', { ...marketDocument, schema_version: '2' }],
    ['a v2 rule without action', { ...marketDocument, rules: [{ order: 1, ttl_seconds: 60, browser_ttl_seconds: 0 }] }],
    ['a v2 rule without browser_ttl_seconds', { ...marketDocument, rules: [{ order: 1, action: 'cache', ttl_seconds: 60 }] }],
    ['an unknown action', { ...marketDocument, rules: [{ order: 1, action: 'force_cache', ttl_seconds: 60, browser_ttl_seconds: 0 }] }],
    ['no_cache with a TTL', { ...marketDocument, rules: [{ order: 1, action: 'no_cache', ttl_seconds: 60, browser_ttl_seconds: 0 }] }],
    ['no_cache with a browser TTL', { ...marketDocument, rules: [{ order: 1, action: 'no_cache', ttl_seconds: 0, browser_ttl_seconds: 5 }] }],
    ['cache with TTL 0', { ...marketDocument, rules: [{ order: 1, action: 'cache', ttl_seconds: 0, browser_ttl_seconds: 0 }] }],
    ['browser TTL above the edge TTL', { ...marketDocument, rules: [{ order: 1, action: 'cache', ttl_seconds: 60, browser_ttl_seconds: 61 }] }],
    ['a negative browser TTL', { ...marketDocument, rules: [{ order: 1, action: 'cache', ttl_seconds: 60, browser_ttl_seconds: -1 }] }],
  ])('rejects %s', async (_, invalid) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => jsonResponse({ ...view, document: invalid }))
    await expect(cachePoliciesApi.get('token', siteID)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('publishes a v2 document with schema_version and every rule action and browser TTL', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(() => jsonResponse({ ...v2View, revision: 8 }, 201))
    const v2Input = { expected_revision: 7, document: marketDocument as CachePolicyDocument }
    await cachePoliciesApi.publish('token', siteID, v2Input, 'policy-v2-1', JSON.stringify(v2Input))
    const body = JSON.parse(String(fetcher.mock.calls[0]![1]!.body)) as { document: typeof marketDocument }
    expect(body.document).toEqual(marketDocument)
    expect(Object.keys(body.document)[0]).toBe('schema_version')
  })
})
