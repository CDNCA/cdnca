import { vi } from 'vitest'

import { usersApi } from '../api/users'

const managedUser = {
  id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  display_id: '1',
  scope_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  tenant_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  username: 'alice',
  display_name: 'Alice',
  email: 'alice@example.com',
  phone: '+8613800000000',
  status: 'active' as const,
  role: 'tenant_owner' as const,
  group_id: null,
  group_name: null,
  revision: 1,
  created_at: '2026-07-22T08:00:00Z',
  updated_at: '2026-07-22T08:00:00Z',
}

const userGroup = {
  id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  scope_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  name: 'Operations',
  revision: 1,
  member_count: 0,
  created_at: '2026-07-22T08:00:00Z',
  updated_at: '2026-07-22T08:00:00Z',
}

const writeMetadata = {
  idempotencyKey: 'update-user-1',
  requestId: 'update-user-request-1',
  traceparent: '00-11111111111111111111111111111111-2222222222222222-01',
}

describe('usersApi', () => {
  it('requests verification only for the managed-user list and preserves each authoritative flag', async () => {
    const verification = { personal_verified: false, company_verified: true }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      items: [{ ...managedUser, verification }], page: 1, limit: 10, total: 1,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    const result = await usersApi.list('token', { page: 1, limit: 10, include_verification: true, real_name_status: 'verified', username: 'alice' })
    expect(result.items[0].verification).toEqual(verification)
    const query = new URL(String(fetchSpy.mock.calls[0][0]), 'https://example.invalid').searchParams
    expect(query.get('include')).toBe('user_metadata,user_verification')
    expect(query.get('real_name_status')).toBe('verified')
    expect(query.get('username')).toBe('alice')
    expect(query.has('include_verification')).toBe(false)
  })

  it('opts the management list into platform administrators and parses tenant-less administrator rows', async () => {
    const admin = { ...managedUser, id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', username: 'admin', tenant_id: null, role: 'platform_owner' }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      items: [managedUser, admin], page: 1, limit: 10, total: 2,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    const result = await usersApi.list('token', { page: 1, limit: 10, include_platform_admins: true })
    expect(result.total).toBe(2)
    expect(result.items[1]).toMatchObject({ role: 'platform_owner', tenant_id: null })
    const query = new URL(String(fetchSpy.mock.calls[0][0]), 'https://example.invalid').searchParams
    expect(query.get('include')).toBe('user_metadata,platform_admins')
    expect(query.has('include_platform_admins')).toBe(false)
  })

  it.each([
    ['owner pickers', { role: 'platform_owner', tenant_id: null }, false],
    ['platform role with a tenant', { role: 'platform_owner' }, true],
    ['tenant role without a tenant', { role: 'tenant_owner', tenant_id: null }, true],
    ['grouped platform administrator', { role: 'platform_admin', tenant_id: null, group_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', group_name: 'Ops' }, true],
  ])('rejects platform administrator rows for %s', async (_name, row, platformAdmins) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      items: [{ ...managedUser, ...row }], page: 1, limit: 10, total: 1,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    await expect(usersApi.list('token', { page: 1, limit: 10, include_platform_admins: platformAdmins }))
      .rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each([undefined, null, {}, { personal_verified: false }, { personal_verified: 'true', company_verified: false },
    { personal_verified: true, company_verified: false, identity_number: 'must-not-leak' },
  ])('rejects missing, malformed or sensitive verification projections %j', async (verification) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      items: [{ ...managedUser, verification }], page: 1, limit: 10, total: 1,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    await expect(usersApi.list('token', { page: 1, limit: 10, include_verification: true })).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('keeps remark and QQ literal filters separate from the general search and requests metadata', async () => {
    const metadata = { remark: '备注\n第二行', qq: '001a' }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      items: [{ ...managedUser, metadata }], page: 1, limit: 20, total: 1,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    const result = await usersApi.list('access-token', { page: 1, limit: 20, search: 'alice', username: '  ali  ', display_name: '  中文  ', email: '  %_@example  ', phone: '  +86001  ', remark: '  50%_  ', qq: '  001a  ' })
    const query = new URL(String(fetchSpy.mock.calls[0][0]), 'https://example.invalid').searchParams
    expect(Object.fromEntries(query)).toEqual({ page: '1', limit: '20', include: 'user_metadata', search: 'alice', username: 'ali', display_name: '中文', email: '%_@example', phone: '+86001', remark: '50%_', qq: '001a' })
    expect(result.items[0].metadata).toEqual(metadata)
  })

  it('reads an authoritative item without filling omitted historical metadata with empty values', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(managedUser), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }))
    expect(await usersApi.get('access-token', managedUser.id)).not.toHaveProperty('metadata')
    expect(fetchSpy.mock.calls[0][0]).toBe(`/v1/admin/users/${managedUser.id}?include=user_metadata`)
  })

  it.each([
    null, {}, { remark: null }, { remark: null, qq: null, unexpected: true },
    { remark: 1, qq: null }, { remark: 'x'.repeat(513), qq: null },
    { remark: null, qq: 'x'.repeat(33) }, { remark: 'bad\u0000value', qq: null },
    { remark: null, qq: '001\n2' }, { remark: null, qq: '001\t2' },
  ])('rejects malformed or non-exact user metadata %j', async (metadata) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...managedUser, metadata }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }))
    await expect(usersApi.get('access-token', managedUser.id)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('counts Unicode code points and allows tabs and line breaks inside remarks', async () => {
    const metadata = { remark: '😀'.repeat(508) + '\t\n\rX', qq: '😀'.repeat(32) }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...managedUser, metadata }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }))
    await expect(usersApi.get('access-token', managedUser.id)).resolves.toMatchObject({ metadata })
  })

  it('preserves the difference between omitted and explicitly cleared write metadata', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify(managedUser), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }))
    const input = { expected_revision: 1, display_name: managedUser.display_name, email: managedUser.email,
      phone: managedUser.phone, status: managedUser.status, role: managedUser.role, group_id: null }
    await usersApi.update('access-token', managedUser.id, input, writeMetadata)
    await usersApi.update('access-token', managedUser.id, { ...input, remark: null, qq: '001X' }, writeMetadata)
    expect(JSON.parse(String(fetchSpy.mock.calls[0][1]?.body))).not.toHaveProperty('remark')
    expect(JSON.parse(String(fetchSpy.mock.calls[0][1]?.body))).not.toHaveProperty('qq')
    expect(JSON.parse(String(fetchSpy.mock.calls[1][1]?.body))).toMatchObject({ remark: null, qq: '001X' })
    expect(fetchSpy.mock.calls[1][0]).toBe(`/v1/admin/users/${managedUser.id}?include=user_metadata`)
  })

  it('serializes administrator filters and authenticates the request', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ items: [], page: 2, limit: 20, total: 0 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await usersApi.list('access-token', {
      page: 2,
      limit: 20,
      display_id: '42',
      search: 'alice',
      status: 'active',
      role: 'tenant_owner',
    })

    expect(fetchSpy).toHaveBeenCalledWith(
      '/v1/admin/users?page=2&limit=20&include=user_metadata&display_id=42&search=alice&status=active&role=tenant_owner',
      expect.objectContaining({
        credentials: 'include',
        headers: expect.objectContaining({ Authorization: 'Bearer access-token' }),
      }),
    )
  })

  it('parses and preserves the public display id from administrator responses', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      items: [managedUser], page: 1, limit: 20, total: 1,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))

    await expect(usersApi.list('access-token', { page: 1, limit: 20 })).resolves.toEqual({
      items: [managedUser], page: 1, limit: 20, total: 1,
    })
  })

  it('sends the idempotency key on profile updates', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          id: 'user-1',
          username: 'alice',
          display_name: 'Alice',
          email: null,
          phone: null,
          revision: 2,
          created_at: '2026-07-22T08:00:00Z',
          updated_at: '2026-07-22T09:00:00Z',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )

    await usersApi.updateProfile(
      'access-token',
      { expected_revision: 1, display_name: 'Alice', email: null, phone: null },
      'profile-key',
    )

    expect(globalThis.fetch).toHaveBeenCalledWith(
      '/v1/account/profile',
      expect.objectContaining({
        method: 'PATCH',
        headers: expect.objectContaining({ 'Idempotency-Key': 'profile-key' }),
      }),
    )
  })

  it.each([
    ['an unknown field', { items: [], page: 1, limit: 20, total: 0, private_note: 'internal' }],
    ['a malformed user', { items: [{ ...managedUser, tenant_id: 'not-a-uuid' }], page: 1, limit: 20, total: 1 }],
    ['a mismatched page', { items: [], page: 2, limit: 20, total: 0 }],
    ['an invalid total', { items: [], page: 1, limit: 20, total: -1 }],
  ])('rejects %s in a successful administrator list response', async (_label, body) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))

    await expect(usersApi.list('access-token', { page: 1, limit: 20 })).rejects.toMatchObject({
      status: 502,
      code: 'invalid_response',
    })
  })

  it.each([
    ['a missing display id', undefined],
    ['a numeric display id', 1],
    ['zero', '0'],
    ['a leading zero', '01'],
    ['more than 19 digits', '12345678901234567890'],
  ])('rejects %s in a successful administrator response', async (_label, displayID) => {
    const item = { ...managedUser, display_id: displayID }
    if (displayID === undefined) delete (item as Partial<typeof managedUser>).display_id
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      items: [item], page: 1, limit: 20, total: 1,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))

    await expect(usersApi.list('access-token', { page: 1, limit: 20 })).rejects.toMatchObject({
      status: 502,
      code: 'invalid_response',
    })
  })

  it('rejects malformed JSON, media type, and success status without exposing the payload', async () => {
    const responses = [
      new Response('{"items":', { status: 200, headers: { 'Content-Type': 'application/json' } }),
      new Response(JSON.stringify({ items: [], page: 1, limit: 20, total: 0 }), {
        status: 200,
        headers: { 'Content-Type': 'text/plain' },
      }),
      new Response(JSON.stringify({ items: [], page: 1, limit: 20, total: 0 }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }),
    ]
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => responses.shift()!)

    for (let index = 0; index < 3; index += 1) {
      await expect(usersApi.list('access-token', { page: 1, limit: 20 })).rejects.toMatchObject({
        status: 502,
        code: 'invalid_response',
        message: expect.not.stringContaining('items'),
      })
    }
  })

  it('sends the complete caller-provided identity and validates an update response', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      ...managedUser,
      status: 'disabled',
      revision: 2,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))

    await usersApi.update('access-token', managedUser.id, {
      expected_revision: 1,
      display_name: managedUser.display_name,
      email: managedUser.email,
      phone: managedUser.phone,
      status: 'disabled',
      role: managedUser.role,
      group_id: null,
    }, writeMetadata)

    const headers = new Headers(fetchSpy.mock.calls[0][1]?.headers)
    expect(headers.get('Idempotency-Key')).toBe(writeMetadata.idempotencyKey)
    expect(headers.get('X-Request-ID')).toBe(writeMetadata.requestId)
    expect(headers.get('Traceparent')).toBe(writeMetadata.traceparent)
  })

  it('deletes one managed user with its revision and write identity', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 204 }))

    await expect(usersApi.deleteUser('access-token', managedUser.id, managedUser.revision, writeMetadata)).resolves.toBeUndefined()

    const [url, init] = fetchSpy.mock.calls[0]
    expect(url).toBe(`/v1/admin/users/${managedUser.id}`)
    expect(init?.method).toBe('DELETE')
    expect(JSON.parse(String(init?.body))).toEqual({ expected_revision: managedUser.revision })
    const headers = new Headers(init?.headers)
    expect(headers.get('Authorization')).toBe('Bearer access-token')
    expect(headers.get('Idempotency-Key')).toBe(writeMetadata.idempotencyKey)
    expect(headers.get('X-Request-ID')).toBe(writeMetadata.requestId)
    expect(headers.get('Traceparent')).toBe(writeMetadata.traceparent)
  })

  it('binds an administrator password reset to the original target and keeps secrets out of the URL', async () => {
    const updated = { ...managedUser, revision: 2, updated_at: '2026-07-22T09:00:00Z' }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(updated), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    const input = {
      user_id: managedUser.id,
      tenant_id: managedUser.tenant_id,
      tenant_scope_id: managedUser.scope_id,
      expected_revision: managedUser.revision,
      new_password: 'replacement-password-long-enough',
      step_up_token: 'opaque-step-up-proof',
    }

    await expect(usersApi.resetPassword('access-token', input, writeMetadata)).resolves.toEqual(updated)

    const [url, init] = fetchSpy.mock.calls[0]
    expect(url).toBe(`/v1/admin/users/${managedUser.id}?include=user_metadata`)
    expect(String(url)).not.toContain(input.new_password)
    expect(String(url)).not.toContain(input.step_up_token)
    expect(JSON.parse(String(init?.body))).toEqual({
      expected_revision: 1,
      password_reset: {
        tenant_scope_id: managedUser.scope_id,
        new_password: input.new_password,
        step_up_token: input.step_up_token,
      },
    })
    expect(new Headers(init?.headers).get('Idempotency-Key')).toBe(writeMetadata.idempotencyKey)

    fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ ...updated, scope_id: userGroup.id }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    await expect(usersApi.resetPassword('access-token', input, writeMetadata)).rejects.toMatchObject({
      status: 502,
      code: 'invalid_response',
    })
  })

  it('serializes batch updates as an array and validates every returned user', async () => {
    const updated = { ...managedUser, status: 'disabled' as const, revision: 2 }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [updated] }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    const input = [{
      id: managedUser.id,
      expected_revision: 1,
      display_name: managedUser.display_name,
      email: managedUser.email,
      phone: managedUser.phone,
      status: 'disabled' as const,
      role: managedUser.role,
      group_id: null,
    }]

    await expect(usersApi.batchUpdate('access-token', input, writeMetadata)).resolves.toEqual({ items: [updated] })
    expect(fetchSpy.mock.calls[0][0]).toBe('/v1/admin/users?include=user_metadata')
    expect(fetchSpy.mock.calls[0][1]?.method).toBe('PATCH')
    expect(JSON.parse(String(fetchSpy.mock.calls[0][1]?.body))).toEqual(input)

    fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ items: [{ ...updated, private_note: 'raw' }] }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    await expect(usersApi.batchUpdate('access-token', input, writeMetadata)).rejects.toMatchObject({
      status: 502,
      code: 'invalid_response',
    })
  })

  it('strictly parses paginated user groups and rejects malformed successful payloads', async () => {
    const responses = [
      new Response(JSON.stringify({ items: [userGroup], page: 2, limit: 20, total: 21 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
      new Response(JSON.stringify({ items: [{ ...userGroup, member_count: -1 }], page: 2, limit: 20, total: 21 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    ]
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => responses.shift()!)

    await expect(usersApi.listGroups('access-token', 2, 20, 'ops')).resolves.toEqual({
      items: [userGroup], page: 2, limit: 20, total: 21,
    })
    expect(fetchSpy.mock.calls[0][0]).toBe('/v1/admin/user-groups?page=2&limit=20&search=ops')
    await expect(usersApi.listGroups('access-token', 2, 20, 'ops')).rejects.toMatchObject({
      status: 502,
      code: 'invalid_response',
    })
  })

  it('preserves complete caller-provided identity across user group writes', async () => {
    const responses = [
      new Response(JSON.stringify(userGroup), { status: 201, headers: { 'Content-Type': 'application/json' } }),
      new Response(JSON.stringify({ ...userGroup, name: 'Support', revision: 2 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
      new Response(null, { status: 204 }),
    ]
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => responses.shift()!)

    await usersApi.createGroup('access-token', userGroup.name, writeMetadata)
    await usersApi.updateGroup('access-token', { id: userGroup.id, revision: 1, name: 'Support' }, writeMetadata)
    await usersApi.deleteGroup('access-token', { id: userGroup.id, revision: 2 }, writeMetadata)

    expect(JSON.parse(String(fetchSpy.mock.calls[0][1]?.body))).toEqual({ name: userGroup.name })
    expect(JSON.parse(String(fetchSpy.mock.calls[1][1]?.body))).toEqual({ expected_revision: 1, name: 'Support' })
    expect(JSON.parse(String(fetchSpy.mock.calls[2][1]?.body))).toEqual({ expected_revision: 2 })
    for (const [, init] of fetchSpy.mock.calls) {
      const headers = new Headers(init?.headers)
      expect(headers.get('Idempotency-Key')).toBe(writeMetadata.idempotencyKey)
      expect(headers.get('X-Request-ID')).toBe(writeMetadata.requestId)
      expect(headers.get('Traceparent')).toBe(writeMetadata.traceparent)
    }
  })

  it('rejects a successful group write whose identity does not match the request', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      ...userGroup,
      id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
      revision: 2,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))

    await expect(usersApi.updateGroup(
      'access-token',
      { id: userGroup.id, revision: 1, name: 'Support' },
      writeMetadata,
    )).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })
})
