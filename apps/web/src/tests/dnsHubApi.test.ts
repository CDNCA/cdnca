import { afterEach, vi } from 'vitest'

import { dnsHubApi, validRecordName, validRecordValue, type DNSHubRecord } from '../api/dnsHub'

const providerID = '11111111-1111-4111-8111-111111111111'
const record: DNSHubRecord = { record_ref: 'r1.cmVjLTE', name: 'www', fqdn: 'www.example.com', type: 'A', value: '192.0.2.1', ttl: 600, line: '默认', weight: 0, managed: null }
const account = { provider_id: providerID, name: 'a', provider_type: 'aliyun', status: 'verified', last_listed_at: null, list_error: '', domain_count: 1, supported_lines: ['默认'], supports_weight: false, record_types: ['A', 'AAAA', 'CNAME', 'TXT'] }

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('dnsHubApi (ADR 0020 §3.2)', () => {
  it('lists merged domains with filters and fails closed on malformed responses', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse({ accounts: [account], items: [{ provider_id: providerID, provider_name: 'a', provider_type: 'aliyun', apex: 'example.com', record_count: 3, last_listed_at: '2026-10-29T00:00:00Z', list_error: '' }], next_cursor: '' }))
    vi.stubGlobal('fetch', fetchMock)
    await expect(dnsHubApi.domains('t', { provider_id: providerID, q: 'exa' })).resolves.toMatchObject({ items: [{ apex: 'example.com' }] })
    expect(fetchMock.mock.calls[0]?.[0]).toBe(`/v1/dns/hub/domains?provider_id=${providerID}&q=exa`)
    expect((fetchMock.mock.calls[0]?.[1]?.headers as Record<string, string>).Authorization).toBe('Bearer t')

    fetchMock.mockImplementation(async () => jsonResponse({ items: [] }))
    await expect(dnsHubApi.domains('t')).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(dnsHubApi.domains('t', { provider_id: '../x' })).rejects.toMatchObject({ code: 'validation_error' })
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('reads live records on the provider/apex path', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse({ provider_id: providerID, apex: 'example.com', skipped: 0, items: [record] }))
    vi.stubGlobal('fetch', fetchMock)
    await dnsHubApi.records('t', providerID, 'example.com', { type: 'TXT' })
    expect(fetchMock.mock.calls[0]?.[0]).toBe(`/v1/dns/hub/domains/${providerID}/example.com/records?type=TXT`)
    await expect(dnsHubApi.records('t', providerID, 'Example.com')).rejects.toMatchObject({ code: 'validation_error' })
  })

  it('keeps the DNS provider short code of dns_provider_error', async () => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async () => jsonResponse({ error: { code: 'dns_provider_error', message: 'x', request_id: 'r', provider_code: 'rate_limited' } }, 502)))
    await expect(dnsHubApi.records('t', providerID, 'example.com')).rejects.toMatchObject({ status: 502, code: 'dns_provider_error', providerCode: 'rate_limited' })
  })

  it('refreshes without an Idempotency-Key', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse({ results: [] }))
    vi.stubGlobal('fetch', fetchMock)
    await dnsHubApi.refresh('t', providerID)
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('/v1/dns/hub/domains/refresh')
    expect((init?.headers as Record<string, string>)['Idempotency-Key']).toBeUndefined()
    expect(JSON.parse(String(init?.body))).toEqual({ provider_id: providerID })
  })

  it('sends Idempotency-Key, expected and confirm_managed on writes', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse({ op_id: 'op', state: 'applied', record: null }))
    vi.stubGlobal('fetch', fetchMock)

    await dnsHubApi.create('t', providerID, 'example.com', { name: '_acme-challenge', type: 'TXT', value: 'token value', ttl: 120, line: '默认', weight: 0 }, 'k1')
    let [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe(`/v1/dns/hub/domains/${providerID}/example.com/records`)
    expect(init?.method).toBe('POST')
    expect((init?.headers as Record<string, string>)['Idempotency-Key']).toBe('k1')

    await dnsHubApi.update('t', providerID, 'example.com', { ...record, managed: { kind: 'site_cname', site_id: '', site_domain: 'www.example.com' } }, { ...record, value: '192.0.2.2' }, true, 'k2')
    ;[url, init] = fetchMock.mock.calls[1]!
    expect(url).toBe(`/v1/dns/hub/domains/${providerID}/example.com/records/r1.cmVjLTE`)
    expect(init?.method).toBe('PATCH')
    expect(JSON.parse(String(init?.body))).toEqual({
      name: 'www', type: 'A', value: '192.0.2.2', ttl: 600, line: '默认', weight: 0,
      expected: { name: 'www', type: 'A', value: '192.0.2.1', ttl: 600, line: '默认', weight: 0 },
      confirm_managed: true,
    })

    await dnsHubApi.remove('t', providerID, 'example.com', record, false, 'k3')
    ;[, init] = fetchMock.mock.calls[2]!
    expect(init?.method).toBe('DELETE')
    expect(JSON.parse(String(init?.body))).toEqual({ expected: { name: 'www', type: 'A', value: '192.0.2.1', ttl: 600, line: '默认', weight: 0 } })
  })

  it('rejects invalid record input before any request', async () => {
    const fetchMock = vi.fn<typeof fetch>()
    vi.stubGlobal('fetch', fetchMock)
    await expect(dnsHubApi.create('t', providerID, 'example.com', { ...record, value: '300.0.0.1' }, 'k')).rejects.toMatchObject({ code: 'validation_error' })
    await expect(dnsHubApi.create('t', providerID, 'example.com', { ...record, ttl: 0 }, 'k')).rejects.toMatchObject({ code: 'validation_error' })
    await expect(dnsHubApi.create('t', providerID, 'example.com', { ...record, type: 'TXT', value: 'a"b' }, 'k')).rejects.toMatchObject({ code: 'validation_error' })
    await expect(dnsHubApi.batch('t', [], 'k')).rejects.toMatchObject({ code: 'validation_error' })
    await expect(dnsHubApi.batch('t', [{ provider_id: providerID, apex: 'a.com', action: 'create', ...record }], 'k'.repeat(121))).rejects.toMatchObject({ code: 'validation_error' })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('posts batch items in the contract shape', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse({ results: [] }))
    vi.stubGlobal('fetch', fetchMock)
    const { record_ref: _ref, fqdn: _fqdn, managed: _managed, ...value } = record
    const items = [
      { provider_id: providerID, apex: 'a.com', action: 'create' as const, ...value },
      { provider_id: providerID, apex: 'b.com', action: 'update' as const, record_ref: 'r1.eA', ...value, ttl: 300, expected: value },
    ]
    await dnsHubApi.batch('t', items, 'k')
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/v1/dns/hub/records/batch')
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({ items })
  })

  it('validates names and values per record type', () => {
    expect(validRecordName('@')).toBe(true)
    expect(validRecordName('*.img')).toBe(false)
    expect(validRecordName('_acme-challenge.www')).toBe(true)
    expect(validRecordName('WWW')).toBe(false)
    expect(validRecordName('a..b')).toBe(false)
    expect(validRecordValue('AAAA', '2001:db8::1')).toBe(true)
    expect(validRecordValue('AAAA', '192.0.2.1')).toBe(false)
    expect(validRecordValue('CNAME', 'edge.cdnca.com')).toBe(true)
    expect(validRecordValue('CNAME', 'not a host')).toBe(false)
    expect(validRecordValue('TXT', 'v=spf1 -all')).toBe(true)
    expect(validRecordValue('TXT', 'a\nb')).toBe(false)
    expect(validRecordValue('TXT', 'x'.repeat(256))).toBe(false)
    expect(validRecordValue('TXT', 'a\\b')).toBe(false)
  })
})
