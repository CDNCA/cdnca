import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import {
  dnsZonesApi,
  type CreateDNSRecordInput,
  type DNSRecord,
  type DNSZone,
  type DNSZoneBinding,
} from '../api/dnsZones'

const scopeID = '22222222-2222-4222-8222-222222222222'
const otherScopeID = '99999999-9999-4999-8999-999999999999'
const providerID = '33333333-3333-4333-8333-333333333333'
const zoneID = '44444444-4444-4444-8444-444444444444'
const recordID = '55555555-5555-4555-8555-555555555555'

const zone: DNSZone = {
  id: zoneID,
  scope_id: scopeID,
  provider_id: providerID,
  name: 'example.com',
  status: 'draft',
  version: 3,
  created_at: '2026-08-02T00:00:00Z',
  updated_at: '2026-08-02T00:00:00Z',
}

const record: DNSRecord = {
  id: recordID,
  scope_id: scopeID,
  zone_id: zoneID,
  name: 'www',
  type: 'A',
  content: '192.0.2.10',
  ttl: 300,
  status: 'draft',
  version: 4,
  created_at: '2026-08-02T00:00:00Z',
  updated_at: '2026-08-02T00:00:00Z',
}

const updatedRecord: DNSRecord = {
  ...record,
  type: 'AAAA',
  content: '2001:db8::10',
  ttl: 600,
  version: 5,
}

const binding: DNSZoneBinding = {
  scopeKind: 'tenant',
  scopeID,
  providers: [{ id: providerID, scope_id: scopeID }],
}

function json(value: unknown, status = 200, requestID = 'dns-test-request'): Promise<Response> {
  return Promise.resolve(new Response(status === 204 ? null : JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json', 'X-Request-ID': requestID },
  }))
}

function requestID(init?: RequestInit): string {
  return new Headers(init?.headers).get('X-Request-ID') ?? ''
}

function responseJSON(init: RequestInit | undefined, value: unknown, status = 200): Promise<Response> {
  return json(value, status, requestID(init))
}

function emptyResponse(init?: RequestInit): Promise<Response> {
  return Promise.resolve(new Response(null, { status: 204, headers: { 'X-Request-ID': requestID(init) } }))
}

describe('dnsZonesApi', () => {
  it('uses only the frozen zone/record routes and preserves exact write preconditions', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      const url = String(input)
      if (init?.method === 'DELETE') return emptyResponse(init)
      if (url.includes('/records') && init?.method === 'PATCH') return responseJSON(init, updatedRecord)
      if (url.endsWith('/records') && init?.method === 'POST') return responseJSON(init, record, 201)
      if (url.includes('/records?')) return responseJSON(init, { items: [record] })
      if (url.endsWith('/zones') && init?.method === 'POST') return responseJSON(init, zone, 201)
      return responseJSON(init, { items: [zone] })
    })
    const createRecord: CreateDNSRecordInput = {
      target_scope_id: scopeID,
      zone_id: zoneID,
      name: 'www',
      type: 'A',
      content: '192.0.2.10',
      ttl: 300,
    }

    await dnsZonesApi.listZones('token', binding)
    await dnsZonesApi.createZone('token', {
      target_scope_id: scopeID,
      provider_id: providerID,
      name: 'example.com',
    }, 'zone-create-key', binding, 'zone-create-request')
    await dnsZonesApi.deleteZone('token', zone, 'zone-delete-key', 'zone-delete-request')
    await dnsZonesApi.listRecords('token', zone)
    await dnsZonesApi.createRecord('token', createRecord, 'record-create-key', zone, 'record-create-request')
    await dnsZonesApi.updateRecord('token', record, {
      expected_version: 4,
      name: 'www',
      type: 'AAAA',
      content: '2001:db8::10',
      ttl: 600,
    }, 'record-update-key', 'record-update-request')
    await dnsZonesApi.deleteRecord('token', record, 'record-delete-key', 'record-delete-request')

    expect(calls.map(({ url, init }) => `${init?.method ?? 'GET'} ${url}`)).toEqual([
      'GET /v1/dns/zones',
      'POST /v1/dns/zones',
      `DELETE /v1/dns/zones/${zoneID}`,
      `GET /v1/dns/records?zone_id=${zoneID}`,
      'POST /v1/dns/records',
      `PATCH /v1/dns/records/${recordID}`,
      `DELETE /v1/dns/records/${recordID}`,
    ])
    expect(calls.every(({ init }) => new Headers(init?.headers).get('Authorization') === 'Bearer token')).toBe(true)
    expect(new Headers(calls[1].init?.headers).get('Idempotency-Key')).toBe('zone-create-key')
    expect(new Headers(calls[2].init?.headers).get('If-Match')).toBe('"3"')
    expect(new Headers(calls[5].init?.headers).get('Idempotency-Key')).toBe('record-update-key')
    expect(new Headers(calls[6].init?.headers).get('If-Match')).toBe('"4"')
    expect(calls.map(({ init }) => requestID(init))).toEqual([
      expect.stringMatching(/^dns-zone-list-/), 'zone-create-request', 'zone-delete-request',
      expect.stringMatching(/^dns-record-list-/), 'record-create-request', 'record-update-request',
      'record-delete-request',
    ])
    expect(calls[4].init?.body).toBe(JSON.stringify(createRecord))
  })

  it('rejects cross-tenant, provider, zone, record, duplicate, and write-response mismatches', async () => {
    const invalidPayloads: unknown[] = [
      { items: [{ ...zone, scope_id: otherScopeID }] },
      { items: [{ ...zone, provider_id: '66666666-6666-4666-8666-666666666666' }] },
      { items: [zone, zone] },
      { items: [{ ...zone, status: 'synced' }] },
      { items: [{ ...zone, version: 0 }] },
    ]
    for (const payload of invalidPayloads) {
      vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => responseJSON(init, payload))
      await expect(dnsZonesApi.listZones('token', binding)).rejects.toMatchObject({
        code: 'response_invalid',
      })
    }

    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => responseJSON(init, {
      items: [{ ...record, zone_id: '77777777-7777-4777-8777-777777777777' }],
    }))
    await expect(dnsZonesApi.listRecords('token', zone)).rejects.toMatchObject({ code: 'response_invalid' })

    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => responseJSON(init, { ...zone, name: 'wrong.example' }, 201))
    await expect(dnsZonesApi.createZone('token', {
      target_scope_id: scopeID, provider_id: providerID, name: zone.name,
    }, 'zone-key', binding, 'zone-mismatch-request')).rejects.toMatchObject({ code: 'response_invalid' })

    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => responseJSON(init, { ...record, id: zoneID }))
    await expect(dnsZonesApi.updateRecord('token', record, {
      expected_version: record.version,
      name: record.name,
      type: record.type,
      content: record.content,
      ttl: record.ttl,
    }, 'record-key', 'record-mismatch-request')).rejects.toMatchObject({ code: 'response_invalid' })
  })

  it('maps server failures without exposing their body and reports malformed success as unknown', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => responseJSON(init, {
      error: { code: 'revision_conflict', message: 'private database row', request_id: 'delete-error-request' },
    }, 409))
    await expect(dnsZonesApi.deleteRecord('token', record, 'delete-key', 'delete-error-request')).rejects.toEqual(
      expect.objectContaining({ status: 409, code: 'revision_conflict', message: 'API request failed' }),
    )

    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => responseJSON(init, { items: 'not-an-array' }))
    await expect(dnsZonesApi.listZones('token', binding)).rejects.toEqual(
      expect.objectContaining({ status: 0, code: 'response_invalid' }),
    )
    expect(ApiError).toBeDefined()
  })

  it('rejects duplicate error envelope members before JSON parsing can collapse them', async () => {
    const duplicateBodies = [
      '{"error":{"code":"revision_conflict","code":"permission_denied","message":"private","request_id":"duplicate-error-request"}}',
      '{"error":{"code":"revision_conflict","message":"private","message":"changed","request_id":"duplicate-error-request"}}',
      '{"error":{"code":"revision_conflict","message":"private","request_id":"duplicate-error-request","request_id":"other"}}',
    ]
    for (const body of duplicateBodies) {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(body, {
        status: 409,
        headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'duplicate-error-request' },
      }))
      await expect(dnsZonesApi.deleteRecord(
        'token', record, 'duplicate-error-key', 'duplicate-error-request',
      )).rejects.toMatchObject({ status: 0, code: 'response_invalid' })
    }
  })

  it('accepts only the four frozen record types and both TTL boundaries', async () => {
    const values: DNSRecord[] = [
      { ...record, type: 'A', content: '192.0.2.10', ttl: 60 },
      { ...record, id: '66666666-6666-4666-8666-666666666666', type: 'AAAA', content: '2001:db8::10', ttl: 86400 },
      { ...record, id: '77777777-7777-4777-8777-777777777777', type: 'CNAME', content: 'target.example.com' },
      { ...record, id: '88888888-8888-4888-8888-888888888888', type: 'TXT', content: 'verification=frozen' },
    ]
    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => responseJSON(init, { items: values }))
    await expect(dnsZonesApi.listRecords('token', zone)).resolves.toEqual({ items: values })

    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => responseJSON(init, {
      items: [{ ...record, type: 'MX' }],
    }))
    await expect(dnsZonesApi.listRecords('token', zone)).rejects.toMatchObject({ code: 'response_invalid' })
  })

  it('canonicalizes zone, owner, CNAME, IPv4, and IPv6 bytes before sending', async () => {
    const bodies: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((_, init) => {
      bodies.push(String(init?.body))
      if (bodies.length === 1) return responseJSON(init, zone, 201)
      if (bodies.length === 2) return responseJSON(init, {
        ...record, name: 'api', type: 'A', content: '192.0.2.10',
      }, 201)
      if (bodies.length === 3) return responseJSON(init, {
        ...record, name: 'www', type: 'AAAA', content: '2001:db8::10',
      }, 201)
      return responseJSON(init, {
        ...record, name: 'alias', type: 'CNAME', content: 'target.example.com',
      }, 201)
    })

    await expect(dnsZonesApi.createZone('token', {
      target_scope_id: scopeID, provider_id: providerID, name: ' Example.COM. ',
    }, 'zone-canonical', binding, 'zone-canonical-request')).resolves.toEqual(zone)
    await expect(dnsZonesApi.createRecord('token', {
      target_scope_id: scopeID, zone_id: zoneID, name: ' API. ', type: 'A',
      content: ' 192.0.2.10 ', ttl: 300,
    }, 'record-ipv4', zone, 'record-ipv4-request')).resolves.toMatchObject({ name: 'api', content: '192.0.2.10' })
    await expect(dnsZonesApi.createRecord('token', {
      target_scope_id: scopeID, zone_id: zoneID, name: ' WWW. ', type: 'AAAA',
      content: ' 2001:0DB8:0:0:0:0:0:10 ', ttl: 300,
    }, 'record-ipv6', zone, 'record-ipv6-request')).resolves.toMatchObject({ name: 'www', content: '2001:db8::10' })
    await expect(dnsZonesApi.createRecord('token', {
      target_scope_id: scopeID, zone_id: zoneID, name: ' ALIAS. ', type: 'CNAME',
      content: ' Target.EXAMPLE.COM. ', ttl: 300,
    }, 'record-cname', zone, 'record-cname-request')).resolves.toMatchObject({ name: 'alias', content: 'target.example.com' })

    expect(bodies.map((body) => JSON.parse(body))).toEqual([
      { target_scope_id: scopeID, provider_id: providerID, name: 'example.com' },
      { target_scope_id: scopeID, zone_id: zoneID, name: 'api', type: 'A', content: '192.0.2.10', ttl: 300 },
      { target_scope_id: scopeID, zone_id: zoneID, name: 'www', type: 'AAAA', content: '2001:db8::10', ttl: 300 },
      { target_scope_id: scopeID, zone_id: zoneID, name: 'alias', type: 'CNAME', content: 'target.example.com', ttl: 300 },
    ])
  })

  it('rejects noncanonical and type-mismatched list facts', async () => {
    const invalidZones = [{ ...zone, name: 'Example.COM.' }]
    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => responseJSON(init, { items: invalidZones }))
    await expect(dnsZonesApi.listZones('token', binding)).rejects.toMatchObject({ code: 'response_invalid' })

    const invalidRecords = [
      { ...record, name: 'WWW.' },
      { ...record, content: '2001:db8::10' },
      { ...record, type: 'AAAA', content: '2001:0DB8:0:0:0:0:0:10' },
      { ...record, type: 'CNAME', content: 'Target.EXAMPLE.COM.' },
    ]
    for (const invalid of invalidRecords) {
      vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => responseJSON(init, { items: [invalid] }))
      await expect(dnsZonesApi.listRecords('token', zone)).rejects.toMatchObject({ code: 'response_invalid' })
    }
  })

  it.each([
    '2026-08-02 00:00:00Z',
    '2026-08-02T00:00:00',
    '2026-02-30T00:00:00Z',
    '2026-08-02T24:00:00Z',
    '2026-08-02T00:00:00+24:00',
    '0000-01-01T00:00:00Z',
    '10000-01-01T00:00:00Z',
    '1900-02-29T00:00:00Z',
    '2025-02-29T00:00:00Z',
    '2026-08-02T00:60:00Z',
    '2026-08-02T00:00:60Z',
    '2026-08-02T00:00:00.1234567890Z',
    '2026-08-02T00:00:00,1Z',
    '2026-08-02T00:00:00+08:60',
  ])('rejects non-RFC3339 date-time fact %s', async (createdAt) => {
    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => responseJSON(init, {
      items: [{ ...zone, created_at: createdAt }],
    }))
    await expect(dnsZonesApi.listZones('token', binding)).rejects.toMatchObject({ code: 'response_invalid' })
  })

  it.each([
    '0001-01-01T00:00:00Z',
    '9999-12-31T23:59:59Z',
    '2000-02-29T00:00:00Z',
    '2024-02-29T23:59:59Z',
    '2026-08-02T00:00:00.1Z',
    '2026-08-02T00:00:00.123456789Z',
    '2026-08-02T08:30:00+05:30',
    '2026-08-01T17:00:00-07:00',
    '2026-08-02T00:00:00+23:59',
    '2026-08-02T00:00:00-23:59',
  ])('accepts strict RFC3339 date-time fact %s', async (createdAt) => {
    const value = { ...zone, created_at: createdAt }
    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => responseJSON(init, { items: [value] }))
    await expect(dnsZonesApi.listZones('token', binding)).resolves.toEqual({ items: [value] })
  })

  it('requires exact success status and an empty 204 delete body', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => responseJSON(init, zone, 200))
    await expect(dnsZonesApi.createZone('token', {
      target_scope_id: scopeID, provider_id: providerID, name: zone.name,
    }, 'zone-status', binding, 'zone-status-request')).rejects.toMatchObject({ code: 'response_invalid' })

    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_, init) => responseJSON(init, { deleted: true }, 200))
    await expect(dnsZonesApi.deleteZone('token', zone, 'zone-delete-body', 'zone-delete-body-request')).rejects.toMatchObject({ code: 'response_invalid' })

    vi.spyOn(globalThis, 'fetch').mockImplementationOnce(() => Promise.resolve(new Response(null, {
      status: 204,
      headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'record-delete-content-type' },
    })))
    await expect(dnsZonesApi.deleteRecord(
      'token', record, 'record-delete-content-type-key', 'record-delete-content-type',
    )).rejects.toMatchObject({ code: 'response_invalid' })
  })

  it('requires exact error envelopes and correlated request IDs', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementationOnce(() => json({
      error: { code: 'revision_conflict', message: 'private row' },
    }, 409, 'missing-error-request'))
    await expect(dnsZonesApi.deleteRecord('token', record, 'missing-error-key', 'missing-error-request')).rejects.toMatchObject({
      status: 0, code: 'response_invalid',
    })

    vi.spyOn(globalThis, 'fetch').mockImplementationOnce(() => json(zone, 201))
    await expect(dnsZonesApi.createZone('token', {
      target_scope_id: scopeID, provider_id: providerID, name: zone.name,
    }, 'mismatched-success-key', binding, 'local-success-request')).rejects.toMatchObject({ code: 'response_invalid' })
  })
})
