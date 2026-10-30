import { describe, expect, it, vi } from 'vitest'

import { l4RealtimeApi, type L4RealtimeFilters } from './l4Realtime'

const tenantID = '018f0000-0000-7000-8000-000000000010'
const siteID = '018f0000-0000-7000-8000-000000000020'
const streamID = '018f0000-0000-7000-8000-000000000030'
const nodeID = '018f0000-0000-7000-8000-000000000040'
const listenerID = '018f0000-0000-7000-8000-000000000050'

const filters: L4RealtimeFilters = {
  range: 'custom',
  timezone: 'UTC',
  from: '2026-08-08T00:00:00Z',
  to: '2026-08-08T01:00:00Z',
  siteId: siteID,
  streamId: streamID,
  nodeId: nodeID,
  protocol: 'tcp',
  limit: 25,
}

function response(input: RequestInfo | URL): Response {
  const url = new URL(String(input), 'https://cdnca.test')
  return new Response(JSON.stringify({
    version: 'l4-realtime/v1',
    meta: {
      range: 'custom', timezone: 'UTC', from: filters.from, to: filters.to,
      snapshot: { at: filters.to, source_watermark: 18, finalized_through: filters.to },
    },
    totals: { sessions: 2, bytes_up: 10, bytes_down: 20, errors: 1 },
    rows: [{
      bucket: filters.from, node_id: nodeID, site_id: siteID, stream_id: streamID, listener_id: listenerID,
      protocol: 'tcp', listen_port: 443, sessions: 2, bytes_up: 10, bytes_down: 20, errors: 1,
    }],
    next_cursor: url.searchParams.has('cursor') ? undefined : 'next-page',
  }), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

describe('l4RealtimeApi', () => {
  it('uses tenant and platform routes with exact filters and keyset cursor', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(response(input)))
    const tenant = await l4RealtimeApi.read('tenant-token', 'tenant', filters)
    expect(tenant.totals.sessions).toBe(2)
    const firstURL = new URL(String(fetchSpy.mock.calls[0]?.[0]), 'https://cdnca.test')
    expect(firstURL.pathname).toBe('/v1/analytics/l4-realtime')
    expect(firstURL.searchParams.has('tenant_id')).toBe(false)
    expect(firstURL.searchParams.get('site_id')).toBe(siteID)
    expect(firstURL.searchParams.get('limit')).toBe('25')

    await l4RealtimeApi.read('platform-token', 'admin', { ...filters, cursor: 'next-page' })
    const secondURL = new URL(String(fetchSpy.mock.calls[1]?.[0]), 'https://cdnca.test')
    expect(secondURL.pathname).toBe('/v1/admin/analytics/l4-realtime')
    expect(secondURL.searchParams.has('tenant_id')).toBe(false)
    expect(secondURL.searchParams.get('cursor')).toBe('next-page')
    expect(fetchSpy.mock.calls[0]?.[1]).toMatchObject({ credentials: 'include', headers: { Authorization: 'Bearer tenant-token' } })

    await l4RealtimeApi.read('platform-token', 'admin', { ...filters, tenantId: tenantID })
    const scopedURL = new URL(String(fetchSpy.mock.calls[2]?.[0]), 'https://cdnca.test')
    expect(scopedURL.searchParams.get('tenant_id')).toBe(tenantID)
  })

  it('accepts a validated empty global snapshot', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({
      version: 'l4-realtime/v1',
      meta: {
        range: '1h', timezone: 'UTC', from: '2026-08-08T00:00:00Z', to: '2026-08-08T01:00:00Z',
        snapshot: { at: '2026-08-08T01:00:00Z', source_watermark: 0, finalized_through: '2026-08-08T01:00:00Z' },
      },
      totals: { sessions: 0, bytes_up: 0, bytes_down: 0, errors: 0 },
      rows: [],
    }), { status: 200 }))

    await expect(l4RealtimeApi.read('platform-token', 'admin', { range: '1h', timezone: 'UTC' }))
      .resolves.toMatchObject({ rows: [], totals: { sessions: 0 } })
  })

  it('rejects an unknown response version and malformed row instead of displaying it', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({ version: 'future/v2' }), { status: 200 }))
    await expect(l4RealtimeApi.read('token', 'tenant', filters)).rejects.toMatchObject({ code: 'invalid_response' })

    vi.mocked(globalThis.fetch).mockResolvedValueOnce(new Response(JSON.stringify({
      version: 'l4-realtime/v1',
      meta: { range: 'custom', timezone: 'UTC', from: filters.from, to: filters.to, snapshot: { at: filters.to, source_watermark: 1, finalized_through: filters.to } },
      totals: { sessions: 1, bytes_up: 0, bytes_down: 0, errors: 0 },
      rows: [{ bucket: filters.from, node_id: 'not-a-uuid' }],
    }), { status: 200 }))
    await expect(l4RealtimeApi.read('token', 'tenant', filters)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('maps forbidden API errors without exposing server messages', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: 'l4_analytics_forbidden', message: 'private detail' } }), { status: 403 }))
    await expect(l4RealtimeApi.read('token', 'tenant', filters)).rejects.toEqual(expect.objectContaining({ status: 403 }))
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })
})
