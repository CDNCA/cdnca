import { analyticsGeoApi } from './analyticsGeo'

const event = {
  eventId: 'event-1', occurredAt: '2026-08-08T03:00:00Z',
  siteId: '018f0000-0000-7000-8000-000000000002', nodeId: '018f0000-0000-7000-8000-000000000003',
  clientIp: '2001:db8::7',
}

describe('analyticsGeoApi', () => {
  it('validates versioned evidence without exposing a raw address', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ data: {
      event_id: 'event-1', occurred_at: event.occurredAt, site_id: event.siteId, node_id: event.nodeId,
      source_country_code: 'CN', source_carrier: 'IPv6-NET', country_code: 'CN', region: 'CN-BJ',
      city: 'Beijing', carrier: 'IPv6-NET', asn: 64512, address_family: 'ipv6', lookup_reason: 'prefix_match',
      resolution: 'matched', reconciliation: 'match', prefix_length: 32, database_provider: 'example-geo',
      database_version: 'geo-2026.08', database_sha256: 'a'.repeat(64), database_published_at: '2026-08-01T00:00:00Z',
      database_effective_at: '2026-08-02T00:00:00Z',
    } }), { status: 200, headers: { 'Content-Type': 'application/json' } }))

    const result = await analyticsGeoApi.lookup('token', 'tenant', 'access', event)

    expect(result.data.database_version).toBe('geo-2026.08')
    expect(result.data.address_family).toBe('ipv6')
    expect(result.data.lookup_reason).toBe('prefix_match')
    expect(result.data).not.toHaveProperty('client_ip')
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'https://cdnca.test')
    expect(url.pathname).toBe('/v1/analytics/logs/access/geo-evidence/event-1')
    expect(url.searchParams.get('client_ip')).toBe(event.clientIp)
  })

  it('fails closed on unknown response fields', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ data: { client_ip: event.clientIp } }), { status: 200 }))
    await expect(analyticsGeoApi.lookup('token', 'tenant', 'block', event)).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })
})
