import { vi } from 'vitest'

import { dnsApi, type CreateDNSProviderInput, type UpdateDNSProviderInput } from '../api/dns'

function response(value: unknown, status = 200): Promise<Response> {
  return Promise.resolve(new Response(status === 204 ? null : JSON.stringify(value), {
    status, headers: { 'Content-Type': 'application/json' },
  }))
}

describe('dnsApi', () => {
  it('uses only tenant-safe provider routes and preserves write preconditions', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      return response(init?.method === 'DELETE' ? undefined : { items: [] }, init?.method === 'DELETE' ? 204 : 200)
    })
    const create: CreateDNSProviderInput = {
      name: 'Cloudflare', provider_type: 'cloudflare', credentials: { api_token: 'secret' },
    }
    const update: UpdateDNSProviderInput = { expected_version: 4, name: 'Cloudflare 2', status: 'unverified' }

    await dnsApi.list('token')
    await dnsApi.create('token', create, 'create-key')
    await dnsApi.update('token', 'provider/id', 'cloudflare', update, 'update-key')
    await dnsApi.verify('token', 'provider/id', 'cloudflare', 5, 'verify-key')
    await dnsApi.remove('token', 'provider/id', 6, 'delete-key')

    expect(calls.map((call) => call.url)).toEqual([
      '/v1/dns/providers',
      '/v1/dns/providers',
      '/v1/dns/providers/provider%2Fid',
      '/v1/dns/providers/provider%2Fid/verify',
      '/v1/dns/providers/provider%2Fid',
    ])
    expect(calls.every((call) => !call.url.includes('/v1/admin/'))).toBe(true)
    expect(calls[1].init?.body).toBe(JSON.stringify(create))
    expect(calls[2].init?.body).toBe(JSON.stringify(update))
    expect(new Headers(calls[2].init?.headers).get('Idempotency-Key')).toBe('update-key')
    expect(new Headers(calls[3].init?.headers).get('If-Match')).toBe('"5"')
    expect(new Headers(calls[4].init?.headers).get('If-Match')).toBe('"6"')
  })

  it('accepts Name.com username + API token and rejects malformed ones before fetch', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({}))
    const nameCom: CreateDNSProviderInput = {
      name: 'Name.com', provider_type: 'namecom', credentials: { username: 'fixture-user', api_token: 'fixture-token' },
    }
    await dnsApi.create('token', nameCom, 'namecom-key')
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toEqual(nameCom)
    for (const [index, credentials] of [
      { username: 'fixture:user', api_token: 'token' },
      { username: 'fixture user', api_token: 'token' },
      { username: 'fixture-user', api_token: '' },
      { username: 'fixture-user', api_token: 't'.repeat(257) },
      { username: 'fixture-user' },
      { username: 'fixture-user', api_token: 'token', extra: 'blocked' },
    ].entries()) {
      await expect(dnsApi.create('token', { name: 'Name.com', provider_type: 'namecom', credentials } as CreateDNSProviderInput,
        `invalid-namecom-${index}`)).rejects.toMatchObject({ code: 'validation_error' })
    }
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('accepts the DNS.LA 4096-byte boundary and rejects invalid creates before fetch', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({}))
    const valid4096ByteID = `${'密'.repeat(1365)}a`
    const invalid4097ByteID = `${valid4096ByteID}b`
    const dnsLA: CreateDNSProviderInput = {
      name: 'DNS.LA',
      provider_type: 'dns_la',
      credentials: { api_id: valid4096ByteID, api_secret: 's'.repeat(4096) },
    }

    await dnsApi.create('token', dnsLA, 'dns-la-key')
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toEqual(dnsLA)

    const prototypeCredentials = Object.defineProperty(
      { api_id: 'id', api_secret: 'secret' },
      'constructor',
      { value: 'blocked', enumerable: true },
    )
    const invalidInputs = [
      { name: 'DNS.LA', provider_type: 'dns_la', credentials: { api_id: invalid4097ByteID, api_secret: 'secret' } },
      { name: 'DNS.LA', provider_type: 'dns_la', credentials: { api_id: 'id', api_secret: 's'.repeat(4097) } },
      { name: 'DNS.LA', provider_type: 'dns_la', credentials: { api_id: '', api_secret: 'secret' } },
      { name: 'DNS.LA', provider_type: 'dns_la', credentials: { api_id: 'id', api_secret: '' } },
      { name: 'DNS.LA', provider_type: 'dns_la', credentials: { api_id: 'id\u0000', api_secret: 'secret' } },
      { name: 'DNS.LA', provider_type: 'dns_la', credentials: { api_id: 'id', api_secret: 'secret\u007f' } },
      { name: 'DNS.LA', provider_type: 'dns_la', credentials: { api_id: 'dns:la', api_secret: 'secret' } },
      { name: 'DNS.LA', provider_type: 'dns_la', credentials: { api_id: 'id', api_secret: 'secret', extra: 'blocked' } },
      { name: 'DNS.LA', provider_type: 'dns_la', credentials: prototypeCredentials },
      { name: 'Legacy', provider_type: 'dnsdun', credentials: { uid: 'id', api_key: 'secret' } },
      { name: 'Unknown', provider_type: 'unexpected', credentials: { token: 'secret' } },
      { name: 'Prototype provider', provider_type: 'constructor', credentials: { token: 'secret' } },
    ]
    for (const [index, input] of invalidInputs.entries()) {
      await expect(dnsApi.create(
        'token', input as unknown as CreateDNSProviderInput, `invalid-create-${index}`,
      )).rejects.toMatchObject({ code: 'validation_error' })
    }
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('accepts a custom HTTP endpoint and rejects unsafe ones before fetch', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({}))
    const custom: CreateDNSProviderInput = {
      name: 'Own DNS', provider_type: 'custom_http',
      credentials: { endpoint: 'https://dns.example.net/cdnca', secret: 'signing-secret-0123' },
    }
    await dnsApi.create('token', custom, 'custom-key')
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toEqual(custom)
    const invalid: Array<Record<string, string>> = [
      { endpoint: 'http://dns.example.net/cdnca', secret: 'signing-secret-0123' },
      { endpoint: 'https://user:pw@dns.example.net/cdnca', secret: 'signing-secret-0123' },
      { endpoint: 'https://dns.example.net/cdnca?token=1', secret: 'signing-secret-0123' },
      { endpoint: 'https://localhost/cdnca', secret: 'signing-secret-0123' },
      { endpoint: 'https://dns.example.net/cdnca', secret: 'short' },
      { endpoint: 'https://dns.example.net/cdnca', secret: 'signing-secret-0123', extra: 'x' },
    ]
    for (const [index, credentials] of invalid.entries()) {
      await expect(dnsApi.create('token', { ...custom, credentials }, `custom-invalid-${index}`))
        .rejects.toMatchObject({ code: 'validation_error' })
    }
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('validates replacement credentials by current provider while allowing a credential-free legacy rename', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      return response({})
    })
    const valid4096ByteID = `${'密'.repeat(1365)}a`
    const replacement: UpdateDNSProviderInput = {
      expected_version: 4,
      name: 'DNS.LA',
      status: 'unverified',
      credentials: { api_id: valid4096ByteID, api_secret: 's'.repeat(4096) },
    }
    const legacyRename: UpdateDNSProviderInput = {
      expected_version: 2,
      name: 'Renamed legacy',
      status: 'disabled',
    }

    await dnsApi.update('token', 'dns-la', 'dns_la', replacement, 'replace-key')
    await dnsApi.update('token', 'legacy', 'dnsdun', legacyRename, 'rename-key')
    expect(JSON.parse(String(calls[0]?.init?.body))).toEqual(replacement)
    expect(JSON.parse(String(calls[1]?.init?.body))).toEqual(legacyRename)

    const prototypeCredentials = Object.defineProperty(
      { api_id: 'id', api_secret: 'secret' },
      '__proto__',
      { value: 'blocked', enumerable: true },
    )
    const invalidReplacements: Array<[string, UpdateDNSProviderInput]> = [
      ['dns_la', { ...replacement, credentials: { api_id: `${valid4096ByteID}b`, api_secret: 'secret' } }],
      ['dns_la', { ...replacement, credentials: { api_id: 'id', api_secret: 's'.repeat(4097) } }],
      ['dns_la', { ...replacement, credentials: { api_id: '', api_secret: 'secret' } }],
      ['dns_la', { ...replacement, credentials: { api_id: 'id', api_secret: '' } }],
      ['dns_la', { ...replacement, credentials: { api_id: 'id\u001f', api_secret: 'secret' } }],
      ['dns_la', { ...replacement, credentials: { api_id: 'id', api_secret: 'secret\u007f' } }],
      ['dns_la', { ...replacement, credentials: { api_id: 'dns:la', api_secret: 'secret' } }],
      ['dns_la', { ...replacement, credentials: { api_id: 'id', api_secret: 'secret', extra: 'blocked' } }],
      ['dns_la', { ...replacement, credentials: prototypeCredentials }],
      ['dnsdun', { ...legacyRename, credentials: { uid: 'id', api_key: 'secret' } }],
      ['dnsdun', { ...legacyRename, status: 'unverified' }],
      ['unexpected', { ...legacyRename, credentials: { token: 'secret' } }],
    ]
    for (const [index, [providerType, input]] of invalidReplacements.entries()) {
      await expect(dnsApi.update(
        'token', `invalid-${index}`, providerType, input, `invalid-replace-${index}`,
      )).rejects.toMatchObject({ code: 'validation_error' })
    }
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('rejects legacy and unknown verification before fetch', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({}))

    for (const providerType of ['dnsdun', 'unexpected', 'constructor']) {
      await expect(dnsApi.verify(
        'token', 'legacy', providerType, 2, `verify-${providerType}`,
      )).rejects.toMatchObject({ code: 'provider_verification_unsupported' })
    }
    expect(fetch).not.toHaveBeenCalled()
  })
})
