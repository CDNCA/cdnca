import { vi } from 'vitest'

import {
  cacheOperationsApi,
  type CacheOperation,
  type CacheOperationSummary,
  type CreateCacheOperationInput,
} from '../api/cacheOperations'

function jsonResponse(value: unknown, status = 200): Promise<Response> {
  return Promise.resolve(new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  }))
}

const input: CreateCacheOperationInput = {
  site_id: '33333333-3333-4333-8333-333333333333',
  action: 'purge',
  target_type: 'exact_url',
  targets: ['https://www.example.com/a.js'],
  node_ids: ['44444444-4444-4444-8444-444444444444'],
  max_retries: 3,
}

const operation: CacheOperation = {
  id: '55555555-5555-4555-8555-555555555555',
  display_id: '12',
  site_id: input.site_id,
  site_display_id: '3',
  action: 'purge',
  target_type: 'exact_url',
  state: 'queued',
  max_attempts: 4,
  auto_nodes: false,
  progress: { total: 1, completed: 0, succeeded: 0, failed: 0, cancelled: 0 },
  targets: [{
    ordinal: 1,
    display_url: 'https://www.example.com/a.js',
    canonical_path: '/a.js',
    target_sha256: 'a'.repeat(64),
    query_redacted: false,
  }],
  nodes: [{
    node_id: input.node_ids[0]!,
    node_display_id: '7',
    state: 'queued',
    attempt: 0,
    progress: { total: 1, completed: 0, succeeded: 0, failed: 0, cancelled: 0 },
    targets: [{ target_ordinal: 1, state: 'queued', attempt: 0, sequence: 0 }],
    updated_at: '2026-08-06T08:00:00Z',
  }],
  created_at: '2026-08-06T08:00:00Z',
  updated_at: '2026-08-06T08:00:00Z',
}

const summary: CacheOperationSummary = {
  id: operation.id,
  display_id: operation.display_id,
  site_id: operation.site_id,
  site_display_id: operation.site_display_id,
  action: operation.action,
  target_type: operation.target_type,
  state: operation.state,
  max_attempts: operation.max_attempts,
  auto_nodes: false,
  progress: operation.progress,
  target_count: 1,
  node_count: 1,
  first_target: operation.targets[0]!,
  created_at: operation.created_at,
  updated_at: operation.updated_at,
}

describe('cacheOperationsApi', () => {
  it('uses tenant routes with Bearer authentication and stable cursor filters', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(() => jsonResponse({ items: [] }))

    await cacheOperationsApi.list('token', { kind: 'tenant' }, {
      limit: 20,
      cursor: 'cursor/value',
      site_id: input.site_id,
      action: 'purge',
      target_type: 'exact_url',
      states: ['running', 'queued', 'running'],
    })

    const [url, init] = fetch.mock.calls[0]!
    const parsed = new URL(String(url), 'https://control.example')
    expect(parsed.pathname).toBe('/v1/cache-operations')
    expect(Object.fromEntries(parsed.searchParams)).toEqual({
      limit: '20', cursor: 'cursor/value', site_id: input.site_id,
      action: 'purge', target_type: 'exact_url', state: 'queued,running',
    })
    const headers = new Headers(init?.headers)
    expect(headers.get('Authorization')).toBe('Bearer token')
    expect(headers.get('X-Request-ID')).toMatch(/^cache-list-/)
    expect(init?.credentials).toBe('include')
  })

  it('keeps admin scope explicit and preserves write idempotency keys', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((url, init) => {
      calls.push({ url: String(url), init })
      return jsonResponse(operation, init?.method === 'POST' ? 202 : 200)
    })
    const scope = { kind: 'admin' as const, scopeId: '22222222-2222-4222-8222-222222222222' }

    await cacheOperationsApi.create('token', scope, input, 'create-key')
    await cacheOperationsApi.get('token', scope, '55555555-5555-4555-8555-555555555555')
    await cacheOperationsApi.retry('token', scope, '55555555-5555-4555-8555-555555555555', 'retry-key')
    await cacheOperationsApi.cancel('token', scope, '55555555-5555-4555-8555-555555555555', 'cancel-key')
    await cacheOperationsApi.resubmit('token', scope, '55555555-5555-4555-8555-555555555555', 'resubmit-batch')

    for (const call of calls) {
      expect(new URL(call.url, 'https://control.example').searchParams.get('scope_id')).toBe(scope.scopeId)
    }
    expect(new Headers(calls[0]?.init?.headers).get('Idempotency-Key')).toBe('create-key')
    expect(new Headers(calls[2]?.init?.headers).get('Idempotency-Key')).toBe('retry-key')
    expect(new Headers(calls[3]?.init?.headers).get('Idempotency-Key')).toBe('cancel-key')
    expect(calls[0]?.init?.body).toBe(JSON.stringify(input))
    expect(calls[2]?.init?.body).toBe('{}')
    expect(calls[3]?.init?.body).toBe('{}')
    expect(new URL(calls[4]!.url, 'https://control.example').pathname)
      .toBe('/v1/admin/cache-operations/55555555-5555-4555-8555-555555555555/resubmit')
    expect(new Headers(calls[4]?.init?.headers).get('Idempotency-Key')).toBe('resubmit-batch')
    expect(calls[4]?.init?.body).toBe('{}')
  })

  it('accepts first-page state counts and rejects malformed ones', async () => {
    const counts = { queued: 1, running: 0, succeeded: 2, partial_failed: 0, failed: 0, cancelled: 0 }
    vi.spyOn(globalThis, 'fetch')
      .mockImplementationOnce(() => jsonResponse({ items: [summary], state_counts: counts }))
      .mockImplementationOnce(() => jsonResponse({ items: [summary], state_counts: { ...counts, failed: -1 } }))
      .mockImplementationOnce(() => jsonResponse({ items: [{ ...summary, first_target: { ...summary.first_target, ordinal: 2 } }] }))
    await expect(cacheOperationsApi.list('token', { kind: 'tenant' }, {})).resolves.toEqual({ items: [summary], state_counts: counts })
    await expect(cacheOperationsApi.list('token', { kind: 'tenant' }, {})).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(cacheOperationsApi.list('token', { kind: 'tenant' }, {})).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('rejects a missing admin tenant scope before making a request', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch')

    await expect(cacheOperationsApi.list('token', { kind: 'admin', scopeId: '' }, {}))
      .rejects.toMatchObject({ status: 400, code: 'validation_error' })
    expect(fetch).not.toHaveBeenCalled()
  })

  it.each([
    ['non-array items', { items: {} }],
    ['an empty cursor', { items: [summary], next_cursor: '' }],
    ['an unknown operation state', { items: [{ ...summary, state: 'unknown' }] }],
    ['an additional private field', { items: [{ ...summary, private_error: 'database host' }] }],
    ['inconsistent progress', {
      items: [{ ...summary, progress: { total: 1, completed: 2, succeeded: 2, failed: 0, cancelled: 0 } }],
    }],
  ])('rejects a successful list response with %s', async (_name, body) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => jsonResponse(body))

    await expect(cacheOperationsApi.list('token', { kind: 'tenant' }, {})).rejects.toMatchObject({
      status: 502,
      code: 'invalid_response',
    })
  })

  it.each([
    ['detail', () => cacheOperationsApi.get('token', { kind: 'tenant' }, operation.id)],
    ['create', () => cacheOperationsApi.create('token', { kind: 'tenant' }, input, 'create-key')],
    ['retry', () => cacheOperationsApi.retry('token', { kind: 'tenant' }, operation.id, 'retry-key')],
    ['cancel', () => cacheOperationsApi.cancel('token', { kind: 'tenant' }, operation.id, 'cancel-key')],
  ])('rejects a malformed successful %s operation instead of accepting a false result', async (_name, call) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => jsonResponse({
      ...operation,
      nodes: [{ ...operation.nodes[0], node_id: 'not-a-uuid' }],
    }, 202))

    await expect(call()).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('accepts a follow-up parent_operation_id and rejects a malformed one (CACHE-ADD-09b)', async () => {
    const parent = '66666666-6666-4666-8666-666666666666'
    const followUp = { ...summary, auto_nodes: true, parent_operation_id: parent }
    vi.spyOn(globalThis, 'fetch')
      .mockImplementationOnce(() => jsonResponse({ items: [followUp] }))
      .mockImplementationOnce(() => jsonResponse({ items: [{ ...followUp, parent_operation_id: 'nope' }] }))
      .mockImplementationOnce(() => jsonResponse({ items: [{ ...followUp, parent_operation_id: summary.id }] }))
      .mockImplementationOnce(() => jsonResponse({ items: [{ ...followUp, auto_nodes: false }] }))
      .mockImplementationOnce(() => jsonResponse({ ...operation, auto_nodes: true, parent_operation_id: parent }))
    await expect(cacheOperationsApi.list('token', { kind: 'tenant' }, {})).resolves.toEqual({ items: [followUp] })
    for (let index = 0; index < 3; index++) {
      await expect(cacheOperationsApi.list('token', { kind: 'tenant' }, {})).rejects.toMatchObject({ code: 'invalid_response' })
    }
    await expect(cacheOperationsApi.get('token', { kind: 'tenant' }, operation.id))
      .resolves.toMatchObject({ parent_operation_id: parent })
  })

  it('accepts a node cancel confirmation and rejects an unknown one (CACHE-ADD-07)', async () => {
    const confirmed = { ...operation, nodes: [{ ...operation.nodes[0]!, cancel_confirmation: 'unsupported' }] }
    vi.spyOn(globalThis, 'fetch')
      .mockImplementationOnce(() => jsonResponse(confirmed))
      .mockImplementationOnce(() => jsonResponse({ ...operation, nodes: [{ ...operation.nodes[0]!, cancel_confirmation: 'stopped' }] }))
    await expect(cacheOperationsApi.get('token', { kind: 'tenant' }, operation.id)).resolves.toEqual(confirmed)
    await expect(cacheOperationsApi.get('token', { kind: 'tenant' }, operation.id)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('requires the display IDs cachecontrolhttp always sends', async () => {
    const without = (value: object, key: string) => Object.fromEntries(Object.entries(value).filter(([name]) => name !== key))
    const noDisplay = without(operation, 'display_id')
    const noNodeDisplay = without(operation.nodes[0]!, 'node_display_id')
    for (const invalid of [noDisplay, { ...operation, site_display_id: '0' }, { ...operation, nodes: [noNodeDisplay] }]) {
      vi.spyOn(globalThis, 'fetch').mockImplementationOnce(() => jsonResponse(invalid))
      await expect(cacheOperationsApi.get('token', { kind: 'tenant' }, operation.id))
        .rejects.toMatchObject({ code: 'invalid_response' })
    }
  })

  it('rejects malformed JSON from a successful write as an unknown response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{', {
      status: 202,
      headers: { 'Content-Type': 'application/json' },
    }))

    await expect(cacheOperationsApi.create('token', { kind: 'tenant' }, input, 'create-key'))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  // fix-cacheflow5: the receipt of a write by its key; 404 (never received) is null, not an error.
  it('reads a write receipt by key and treats 404 as not received', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockReturnValueOnce(jsonResponse({ status: 'accepted', decided_at: '2026-08-06T08:00:00Z', operation }))
      .mockReturnValueOnce(jsonResponse({
        status: 'rejected', decided_at: '2026-08-06T08:00:00Z',
        rejection: { code: 'invalid_request', details: { field: 'targets', target_ordinal: 2, stage: 'target_validation', reason: 'target_host_not_served' } },
      }))
      .mockReturnValueOnce(jsonResponse({ error: { code: 'not_found', message: 'resource was not found', request_id: 'r' } }, 404))
      .mockReturnValueOnce(jsonResponse({ status: 'accepted', decided_at: '2026-08-06T08:00:00Z' }))

    await expect(cacheOperationsApi.writeReceipt('token', { kind: 'tenant' }, { action: 'create', key: 'cache-create-1' }))
      .resolves.toEqual({ status: 'accepted', decided_at: '2026-08-06T08:00:00Z', operation })
    const rejected = await cacheOperationsApi.writeReceipt('token', { kind: 'admin', scopeId: '11111111-1111-4111-8111-111111111111' },
      { action: 'retry', operationID: operation.id, key: 'cache-retry-1' })
    expect(rejected).toMatchObject({ status: 'rejected', rejection: { code: 'invalid_request' } })
    await expect(cacheOperationsApi.writeReceipt('token', { kind: 'tenant' }, { action: 'cancel', operationID: operation.id, key: 'cache-cancel-1' }))
      .resolves.toBeNull()
    await expect(cacheOperationsApi.writeReceipt('token', { kind: 'tenant' }, { action: 'create', key: 'cache-create-2' }))
      .rejects.toMatchObject({ code: 'invalid_response' })

    expect(String(fetchMock.mock.calls[0]![0])).toMatch(/\/v1\/cache-operation-requests\/cache-create-1\?action=create$/)
    expect(String(fetchMock.mock.calls[1]![0])).toContain(
      `/v1/admin/cache-operation-requests/cache-retry-1?action=retry&operation_id=${operation.id}&scope_id=11111111-1111-4111-8111-111111111111`)
    expect((fetchMock.mock.calls[0]![1] as RequestInit).method ?? 'GET').toBe('GET')
  })
})
