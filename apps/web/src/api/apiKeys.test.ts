import { apiKeyExpired, apiKeysApi, validateAPIKeyIPAllowlist } from './apiKeys'

const record = {
  id: '33333333-3333-4333-8333-333333333333',
  key_id: 'cfk_AAAAAAAAAAAAAAAAAAAAAA',
  key_prefix: 'cfk_AAAAAAAAAAAAAAAAAAAAAA.',
  scope_id: '22222222-2222-4222-8222-222222222222',
  tenant_id: '22222222-2222-4222-8222-222222222222',
  user_id: '11111111-1111-4111-8111-111111111111',
  name: 'production reader',
  scopes: ['sites.read'],
  ip_allowlist: ['192.0.2.0/24', '2001:db8::/32'],
  status: 'active',
  revision: 3,
  created_at: '2026-07-22T12:00:00Z',
  updated_at: '2026-07-22T12:00:00Z',
}

function response(value: unknown, status = 200): Promise<Response> {
  return Promise.resolve(new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  }))
}

function page(items: unknown[] = [], nextCursor = '') {
  return { items, next_cursor: nextCursor, has_more: nextCursor !== '' }
}

describe('apiKeysApi IP allowlist contract', () => {
  it('requires canonical, non-overlapping allowlists in API key responses', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    fetchSpy.mockImplementationOnce(() => response(page([record])))
    await expect(apiKeysApi.list('token', { limit: 10 })).resolves.toEqual(page([record]))

    fetchSpy.mockImplementationOnce(() => response(page([{ ...record, ip_allowlist: undefined }])))
    await expect(apiKeysApi.list('token', { limit: 10 })).rejects.toMatchObject({ code: 'invalid_response' })

    fetchSpy.mockImplementationOnce(() => response(page([{ ...record, ip_allowlist: ['192.0.2.1/24'] }])))
    await expect(apiKeysApi.list('token', { limit: 10 })).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('accepts a complete plugin installation binding only (migration 604)', async () => {
    const binding = {
      plugin_installation_authorization_id: '018cc251-f400-7def-8000-000000000032',
      plugin_installation_id: '018cc251-f400-7def-8000-000000000033', plugin_id: 'io.cdnca.cf-optimize',
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    fetchSpy.mockImplementationOnce(() => response(page([{ ...record, ...binding }])))
    await expect(apiKeysApi.list('token', { limit: 10 })).resolves.toMatchObject({ items: [binding] })

    fetchSpy.mockImplementationOnce(() => response(page([{ ...record, plugin_id: 'io.cdnca.cf-optimize' }])))
    await expect(apiKeysApi.list('token', { limit: 10 })).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('accepts all-permission keys up to 128 scopes (migration 574)', async () => {
    const scopes = Array.from({ length: 129 }, (_, index) => `module${String(index).padStart(3, '0')}.read`)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    fetchSpy.mockImplementationOnce(() => response(page([{ ...record, scopes: scopes.slice(0, 128) }])))
    await expect(apiKeysApi.list('token', { limit: 10 })).resolves.toMatchObject({ items: [{ scopes: scopes.slice(0, 128) }] })

    fetchSpy.mockImplementationOnce(() => response(page([{ ...record, scopes }])))
    await expect(apiKeysApi.list('token', { limit: 10 })).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('encodes the complete cursor filter and strictly parses the page envelope', async () => {
    let requested = ''
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      requested = String(input)
      return response(page([record], 'opaque.cursor'))
    })

    await expect(apiKeysApi.list('token', {
      limit: 25,
      status: 'active',
      name: 'Alpha Key',
      key_id: record.key_id,
      cursor: 'first.cursor',
    })).resolves.toEqual(page([record], 'opaque.cursor'))

    expect(requested).toBe(
      `/v1/account/api-keys?limit=25&status=active&name=Alpha+Key&key_id=${record.key_id}&cursor=first.cursor`,
    )
  })

  it.each([
    { ...page([record]), has_more: true },
    { ...page([record], 'opaque.cursor'), has_more: false },
    { ...page([record]), secret: 'must-not-leak' },
    page([{ ...record, matched_prefix: '192.0.2.0/24' }]),
    { ...page([record]), next_cursor: 1 },
    { ...page([record]), total: -1 },
    { ...page([record]), total: 1.5 },
    { ...page([record]), total: '3' },
    { ...page([record]), snapshot_at: '2026-10-28T11:52:01Z' },
  ])('rejects inconsistent or sensitive list payload %#', async (payload) => {
    vi.spyOn(globalThis, 'fetch').mockImplementationOnce(() => response(payload))
    await expect(apiKeysApi.list('token', { limit: 10 })).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('sends offset for page-number access and returns the filtered total', async () => {
    let requested = ''
    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((input) => {
      const url = new URL(String(input), 'http://localhost')
      requested = `${url.pathname}${url.search}`
      return response({ ...page([record]), total: 21 })
    })
    await expect(apiKeysApi.list('token', { limit: 10, offset: 20 })).resolves.toEqual({ ...page([record]), total: 21 })
    expect(requested).toBe('/v1/account/api-keys?limit=10&offset=20')
  })

  // AA-UI02：简单区按"实际可用"查询，并带回服务端时间（Date 响应头）用于判断到期。
  it('requests usable keys and returns the server clock from the Date header', async () => {
    let requested = ''
    vi.spyOn(globalThis, 'fetch').mockImplementationOnce((input) => {
      const url = new URL(String(input), 'http://localhost')
      requested = `${url.pathname}${url.search}`
      return Promise.resolve(new Response(JSON.stringify(page([record])), {
        status: 200,
        headers: { 'Content-Type': 'application/json', Date: 'Wed, 28 Oct 2026 11:52:01 GMT' },
      }))
    })
    await expect(apiKeysApi.list('token', { limit: 2, status: 'active', usable: true }))
      .resolves.toEqual({ ...page([record]), server_time: Date.parse('2026-10-28T11:52:01Z') })
    expect(requested).toBe('/v1/account/api-keys?limit=2&status=active&usable=true')
  })

  it('treats an active key as expired from its expiry instant on', () => {
    const expiresAt = '2026-10-28T11:51:00Z'
    const at = Date.parse(expiresAt)
    expect(apiKeyExpired({ status: 'active', expires_at: expiresAt }, at - 1)).toBe(false)
    expect(apiKeyExpired({ status: 'active', expires_at: expiresAt }, at)).toBe(true)
    expect(apiKeyExpired({ status: 'active', expires_at: expiresAt }, at + 1)).toBe(true)
    expect(apiKeyExpired({ status: 'active' }, at)).toBe(false)
    expect(apiKeyExpired({ status: 'revoked', expires_at: expiresAt }, at + 1)).toBe(false)
  })

  it('serializes the exact allowlist in create and update writes', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      return init?.method === 'POST'
        ? response({ key: record, secret: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' }, 201)
        : response(record)
    })
    const fields = {
      name: record.name,
      scopes: record.scopes,
      ip_allowlist: record.ip_allowlist,
    }

    await apiKeysApi.create('token', fields, 'create-key')
    await apiKeysApi.update('token', record.id, record.revision, fields, 'update-key')

    expect(JSON.parse(String(calls[0]?.init?.body))).toEqual(fields)
    expect(JSON.parse(String(calls[1]?.init?.body))).toEqual(fields)
    expect(new Headers(calls[0]?.init?.headers).get('Idempotency-Key')).toBe('create-key')
    expect(new Headers(calls[1]?.init?.headers).get('If-Match')).toBe('"3"')
  })

  it.each(['activate', 'rotate', 'revoke'] as const)('%s binds the current exact allowlist to the guarded action', async (operation) => {
    let write: RequestInit | undefined
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      write = init
      return operation === 'revoke'
        ? response(record)
        : response({ key: record, secret: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' })
    })

    await apiKeysApi.action('token', record.id, record.revision, operation, record.ip_allowlist, 'action-key')

    expect(write?.body).toBe(JSON.stringify({ ip_allowlist: record.ip_allowlist }))
    expect(new Headers(write?.headers).get('If-Match')).toBe('"3"')
    expect(new Headers(write?.headers).get('Idempotency-Key')).toBe('action-key')
  })

  // fix-smallfu：简单版"重置密钥"要求轮换同时把权限刷新为全部；只在为 true 时写入请求体。
  it('sends grant_all_scopes only when the rotation asks for it', async () => {
    let write: RequestInit | undefined
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      write = init
      return response({ key: record, secret: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' })
    })

    await apiKeysApi.action('token', record.id, record.revision, 'rotate', record.ip_allowlist, 'reset-key', { grantAllScopes: true })

    expect(write?.body).toBe(JSON.stringify({ ip_allowlist: record.ip_allowlist, grant_all_scopes: true }))
  })

  it.each([
    [['192.0.2.0/24', '2001:db8::/32'], null],
    [['192.0.2.1/24'], 'api_key_ip_allowlist_invalid_cidr'],
    [['2001:0db8::/32'], 'api_key_ip_allowlist_invalid_cidr'],
    [['192.0.2.0/33'], 'api_key_ip_allowlist_unsupported_prefix'],
    [['192.0.2.0/24', '192.0.2.0/24'], 'api_key_ip_allowlist_duplicate'],
    [['192.0.2.0/24', '192.0.2.128/25'], 'api_key_ip_allowlist_overlap'],
    [Array.from({ length: 33 }, (_, index) => `10.${index}.0.0/16`), 'api_key_ip_allowlist_too_many'],
    [['::ffff:192.0.2.0/120'], 'api_key_ip_allowlist_invalid_cidr'],
  ] as const)('validates %j with stable result %s', (values, expected) => {
    expect(validateAPIKeyIPAllowlist([...values])).toBe(expected)
  })
})
