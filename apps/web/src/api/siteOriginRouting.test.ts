import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  originRoutingApi,
  ORIGIN_ROUTING_SCHEMA,
  sortOriginRoutes,
  validateOriginRoutingState,
  type OriginRoutingDocument,
} from './siteOriginRouting'

const siteId = '11111111-1111-4111-8111-111111111111'
const state = {
  site_id: siteId,
  version: 7,
  updated_at: '2026-08-06T09:00:00Z',
  document: {
    schema: ORIGIN_ROUTING_SCHEMA,
    pools: [{
      id: 'pool-a', balance_method: 'round_robin' as const,
      endpoints: [{ id: 'origin-a', host: '192.0.2.10', port: 443, weight: 100 }],
    }],
    ingress_source_enabled: false,
    default_pool_id: 'pool-a',
    routes: [],
    retry: { methods: ['GET', 'HEAD'] as Array<'GET' | 'HEAD'>, max_attempts: 2, connect_timeout_ms: 100, read_timeout_ms: 100, total_budget_ms: 300 },
  },
}

afterEach(() => vi.restoreAllMocks())

describe('originRoutingApi', () => {
  it('fetches and validates the candidate desired-state document', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(state), { status: 200 }),
    )

    await expect(originRoutingApi.get('token-a', siteId)).resolves.toEqual(state)
    expect(fetchMock).toHaveBeenCalledWith(`/v1/sites/${siteId}/origin-routing`, expect.objectContaining({
      headers: expect.objectContaining({ Authorization: 'Bearer token-a' }),
    }))
  })

  it('sends a strong quoted CAS and a fresh idempotency key for replacement', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ ...state, version: 8 }), { status: 200 }),
    )
    const document = state.document satisfies OriginRoutingDocument

    await originRoutingApi.replace('token-b', siteId, 7, document, 'idem-1')
    const [, init] = fetchMock.mock.calls[0]!
    expect(init?.method).toBe('PUT')
    expect(init?.body).toBe(JSON.stringify(document))
    expect(init?.headers).toEqual(expect.objectContaining({
      Authorization: 'Bearer token-b',
      'Content-Type': 'application/json',
      'Idempotency-Key': 'idem-1',
      'If-Match': '"7"',
    }))
  })

  it('does not expose raw server messages and preserves status/code', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: { code: 'version_conflict', message: 'private details', request_id: 'r1' } }), { status: 412 }),
    )
    await expect(originRoutingApi.get('token', siteId)).rejects.toMatchObject({ status: 412, code: 'version_conflict' })
  })
})

describe('origin routing validation and ordering', () => {
  it('accepts DNS origins while rejecting unsafe names and other invalid contracts', () => {
    expect(validateOriginRoutingState({ ...state, document: { ...state.document, pools: [{ ...state.document.pools[0]!, endpoints: [{ id: 'x', host: 'Origin.Example.', port: 443, weight: 1 }] }] } })).toBe(true)
    expect(validateOriginRoutingState({ ...state, document: { ...state.document, pools: [{ ...state.document.pools[0]!, endpoints: [{ id: 'x', host: 'localhost', port: 443, weight: 1 }] }] } })).toBe(false)
    expect(validateOriginRoutingState({ ...state, document: { ...state.document, pools: [{ ...state.document.pools[0]!, endpoints: [{ id: 'x', host: 'origin', port: 443, weight: 1 }] }] } })).toBe(false)
    expect(validateOriginRoutingState({ ...state, document: { ...state.document, routes: [{ id: 'route', priority: 1, pool_id: 'pool-a' }] } })).toBe(false)
    expect(validateOriginRoutingState({ ...state, document: { ...state.document, default_fallback_pool_id: 'missing' } })).toBe(false)
    expect(validateOriginRoutingState({ ...state, document: { ...state.document, retry: { ...state.document.retry, total_budget_ms: 100 } } })).toBe(false)
  })

  it('requires the signed ingress-source switch to be a strict boolean', () => {
    const missing = { ...state.document, ingress_source_enabled: undefined }
    expect(validateOriginRoutingState({ ...state, document: missing })).toBe(false)
    expect(validateOriginRoutingState({ ...state, document: { ...state.document, ingress_source_enabled: 'false' } })).toBe(false)
    expect(validateOriginRoutingState({ ...state, document: { ...state.document, ingress_source_enabled: true } })).toBe(true)
  })

  it('sorts routes by priority, path specificity, region, CIDR prefix, and id', () => {
    const routes = [
      { id: 'z', priority: 1, path_prefix: '/', pool_id: 'pool-a' },
      { id: 'a', priority: 1, path_prefix: '/api', pool_id: 'pool-a' },
      { id: 'b', priority: 2, path_prefix: '/a', pool_id: 'pool-a' },
      { id: 'c', priority: 1, path_prefix: '/api', node_regions: ['cn'], pool_id: 'pool-a' },
      { id: 'd', priority: 1, path_prefix: '/api', client_cidrs: ['192.0.2.0/24'], pool_id: 'pool-a' },
    ]
    expect(sortOriginRoutes(routes).map((route) => route.id)).toEqual(['b', 'c', 'd', 'a', 'z'])
  })
})
