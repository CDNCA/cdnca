import { afterEach, vi } from 'vitest'

import { dnsApi, type DNSProvider, type DNSProviderList } from '../api/dns'

const provider = (id: string, name: string, scopeID = '22222222-2222-4222-8222-222222222222'): DNSProvider => ({
  id,
  scope_id: scopeID,
  name,
  provider_type: 'cloudflare',
  credentials_configured: true,
  status: 'verified',
  version: 1,
  created_at: '2026-08-08T00:00:00Z',
  updated_at: '2026-08-08T00:00:00Z',
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('DNS provider server pagination', () => {
  it('aggregates legacy no-input calls and fails closed on duplicate cursors or provider IDs', async () => {
    const responses: DNSProviderList[] = [
      { items: [provider('11111111-1111-4111-8111-111111111111', 'first')], next_cursor: 'cursor-two' },
      { items: [provider('22222222-2222-4222-8222-222222222222', 'second')] },
    ]
    const fetchMock = vi.fn<typeof fetch>(async () => new Response(JSON.stringify(responses.shift()), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(dnsApi.list('token')).resolves.toEqual({ items: [
      expect.objectContaining({ name: 'first' }),
      expect.objectContaining({ name: 'second' }),
    ] })
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/v1/dns/providers')
    expect(fetchMock.mock.calls[1]?.[0]).toBe('/v1/dns/providers?limit=20&cursor=cursor-two')

    for (const pages of [
      [
        { items: [provider('33333333-3333-4333-8333-333333333333', 'one')], next_cursor: 'same' },
        { items: [provider('44444444-4444-4444-8444-444444444444', 'two')], next_cursor: 'same' },
      ],
      [
        { items: [provider('55555555-5555-4555-8555-555555555555', 'one')], next_cursor: 'next' },
        { items: [provider('55555555-5555-4555-8555-555555555555', 'duplicate')] },
      ],
    ]) {
      const queue = [...pages]
      fetchMock.mockImplementation(async () => new Response(JSON.stringify(queue.shift()), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
      await expect(dnsApi.list('token')).rejects.toMatchObject({ code: 'invalid_response' })
    }
  })
})
