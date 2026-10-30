import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from './auth'
import { customRbacApi } from './customRbac'

const roleID = '11111111-1111-4111-8111-111111111111'
const grantID = '22222222-2222-4222-8222-222222222222'
const subjectUserID = '33333333-3333-4333-8333-333333333333'
const actorUserID = '44444444-4444-4444-8444-444444444444'
const traceparent = `00-${'a'.repeat(32)}-${'b'.repeat(16)}-01`
const stepUpProof = 'c'.repeat(43)

const role = {
  id: roleID,
  name: '站点只读员',
  current_revision: 1,
  permissions: ['sites.read', 'certificates.read'],
  created_at: '2026-08-08T01:00:00Z',
}
const permissionCatalog = {
  data: [
    { name: 'sites.read', step_up_required: false },
    { name: 'identity.roles.manage', step_up_required: true },
  ],
}
const grant = {
  id: grantID,
  role_id: roleID,
  role_revision: 1,
  subject_user_id: subjectUserID,
  granted_by_user_id: actorUserID,
  granted_at: '2026-08-08T02:00:00Z',
}
const revocation = {
  id: '55555555-5555-4555-8555-555555555555',
  grant_id: grantID,
  revoked_by_user_id: actorUserID,
  revoked_at: '2026-08-08T03:00:00Z',
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

function metadata(suffix: string, withStepUp = false) {
  return {
    idempotencyKey: `custom-rbac-${suffix}`,
    requestId: `custom-rbac-request-${suffix}`,
    traceparent,
    ...(withStepUp ? { stepUpProof } : {}),
  }
}

describe('customRbacApi', () => {
  afterEach(() => vi.restoreAllMocks())

  it('lists strict role pages with a stable cursor and include_deactivated and reads the permission catalog', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ data: [role], page: { next_cursor: 'role-next' } }))
      .mockResolvedValueOnce(json({ data: [], page: {} }))
      .mockResolvedValueOnce(json(permissionCatalog))

    await expect(customRbacApi.listRoles('token', {
      limit: 25, cursor: 'role-current', includeDeactivated: true,
    })).resolves.toEqual({ data: [role], page: { next_cursor: 'role-next' } })
    await expect(customRbacApi.listRoles('token', { includeDeactivated: false }))
      .resolves.toEqual({ data: [], page: {} })
    await expect(customRbacApi.listPermissions('token')).resolves.toEqual(permissionCatalog)

    expect(fetchSpy.mock.calls.map(([url]) => String(url))).toEqual([
      '/v1/custom-rbac/roles?limit=25&cursor=role-current&include_deactivated=true',
      '/v1/custom-rbac/roles?include_deactivated=false',
      '/v1/custom-rbac/permissions',
    ])
    for (const [, init] of fetchSpy.mock.calls) {
      expect(init?.credentials).toBe('include')
      expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer token')
      expect(init?.method).toBeUndefined()
    }
  })

  it('gets, creates, renames, publishes, and deactivates roles on the exact mounted routes', async () => {
    const renamed = { ...role, name: '站点审计员', current_revision: 2 }
    const published = { ...renamed, current_revision: 3, permissions: ['sites.read'] }
    const deactivated = { ...published, deactivated_at: '2026-08-08T04:00:00Z' }
    const createMetadata = metadata('create', true)
    const renameMetadata = metadata('rename')
    const publishMetadata = metadata('publish', true)
    const deactivateMetadata = metadata('deactivate')
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ data: role }))
      .mockResolvedValueOnce(json({ data: { ...role, replayed: false } }, 201))
      .mockResolvedValueOnce(json({ data: renamed }))
      .mockResolvedValueOnce(json({ data: published }))
      .mockResolvedValueOnce(json({ data: deactivated }))

    await expect(customRbacApi.getRole('token', roleID)).resolves.toEqual(role)
    await expect(customRbacApi.createRole('token', {
      name: role.name, permissions: role.permissions,
    }, createMetadata)).resolves.toEqual({ ...role, replayed: false })
    await expect(customRbacApi.renameRole('token', roleID, 1, { name: renamed.name }, renameMetadata))
      .resolves.toEqual(renamed)
    await expect(customRbacApi.publishRole('token', roleID, 2, { permissions: published.permissions }, publishMetadata))
      .resolves.toEqual(published)
    await expect(customRbacApi.deactivateRole('token', roleID, 3, deactivateMetadata))
      .resolves.toEqual(deactivated)

    expect(fetchSpy.mock.calls.map(([url]) => String(url))).toEqual([
      `/v1/custom-rbac/roles/${roleID}`,
      '/v1/custom-rbac/roles',
      `/v1/custom-rbac/roles/${roleID}/rename`,
      `/v1/custom-rbac/roles/${roleID}/publish`,
      `/v1/custom-rbac/roles/${roleID}/deactivate`,
    ])
    const expected = [
      [1, createMetadata, undefined, { name: role.name, permissions: role.permissions }],
      [2, renameMetadata, '"1"', { name: renamed.name }],
      [3, publishMetadata, '"2"', { permissions: published.permissions }],
      [4, deactivateMetadata, '"3"', undefined],
    ] as const
    for (const [index, writeMetadata, revision, body] of expected) {
      const init = fetchSpy.mock.calls[index]?.[1]
      const headers = new Headers(init?.headers)
      expect(init?.method).toBe('POST')
      expect(headers.get('Idempotency-Key')).toBe(writeMetadata.idempotencyKey)
      expect(headers.get('X-Request-ID')).toBe(writeMetadata.requestId)
      expect(headers.get('Traceparent')).toBe(writeMetadata.traceparent)
      expect(headers.get('If-Match')).toBe(revision ?? null)
      expect(headers.get('X-Step-Up-Proof')).toBe('stepUpProof' in writeMetadata ? writeMetadata.stepUpProof : null)
      expect(body === undefined ? init?.body : JSON.parse(String(init?.body))).toEqual(body)
      expect(headers.get('Content-Type')).toBe(body === undefined ? null : 'application/json')
    }
  })

  it('lists filtered grants and assigns and revokes them with the canonical contracts', async () => {
    const assignMetadata = metadata('assign', true)
    const revokeMetadata = metadata('revoke')
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ data: [grant], page: { next_cursor: 'grant-next' } }))
      .mockResolvedValueOnce(json({ data: { ...grant, replayed: false } }, 201))
      .mockResolvedValueOnce(json({ data: { ...revocation, replayed: false } }))

    await expect(customRbacApi.listGrants('token', {
      limit: 20, cursor: 'grant-current', roleId: roleID, subjectUserId: subjectUserID, state: 'all',
    })).resolves.toEqual({ data: [grant], page: { next_cursor: 'grant-next' } })
    await expect(customRbacApi.assignGrant('token', 1, {
      role_id: roleID, subject_user_id: subjectUserID,
    }, assignMetadata)).resolves.toEqual({ ...grant, replayed: false })
    await expect(customRbacApi.revokeGrant('token', grantID, revokeMetadata))
      .resolves.toEqual({ ...revocation, replayed: false })

    expect(fetchSpy.mock.calls.map(([url]) => String(url))).toEqual([
      `/v1/custom-rbac/grants?limit=20&cursor=grant-current&role_id=${roleID}&subject_user_id=${subjectUserID}&state=all`,
      '/v1/custom-rbac/grants',
      `/v1/custom-rbac/grants/${grantID}/revoke`,
    ])
    const assignInit = fetchSpy.mock.calls[1]?.[1]
    const assignHeaders = new Headers(assignInit?.headers)
    expect(assignInit?.method).toBe('POST')
    expect(JSON.parse(String(assignInit?.body))).toEqual({ role_id: roleID, subject_user_id: subjectUserID })
    expect(assignHeaders.get('If-Match')).toBe('"1"')
    expect(assignHeaders.get('Idempotency-Key')).toBe(assignMetadata.idempotencyKey)
    expect(assignHeaders.get('X-Request-ID')).toBe(assignMetadata.requestId)
    expect(assignHeaders.get('Traceparent')).toBe(assignMetadata.traceparent)
    expect(assignHeaders.get('X-Step-Up-Proof')).toBe(stepUpProof)

    const revokeInit = fetchSpy.mock.calls[2]?.[1]
    const revokeHeaders = new Headers(revokeInit?.headers)
    expect(revokeInit?.method).toBe('POST')
    expect(revokeInit?.body).toBeUndefined()
    expect(revokeHeaders.get('If-Match')).toBeNull()
    expect(revokeHeaders.get('Idempotency-Key')).toBe(revokeMetadata.idempotencyKey)
    expect(revokeHeaders.get('X-Request-ID')).toBe(revokeMetadata.requestId)
    expect(revokeHeaders.get('Traceparent')).toBe(revokeMetadata.traceparent)
    expect(revokeHeaders.get('X-Step-Up-Proof')).toBeNull()
  })

  it('rejects malformed pagination, filters, revisions, payloads, and write metadata before fetch', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const invalidRequests = [
      customRbacApi.listRoles('token', { limit: 0 }),
      customRbacApi.listRoles('token', { cursor: '' }),
      customRbacApi.listRoles('token', { includeDeactivated: 'yes' } as never),
      customRbacApi.listGrants('token', { state: 'pending' } as never),
      customRbacApi.listGrants('token', { roleId: 'not-a-uuid' }),
      customRbacApi.createRole('token', { name: '', permissions: [] }, metadata('invalid-create')),
      customRbacApi.renameRole('token', roleID, 0, { name: 'name' }, metadata('invalid-revision')),
      customRbacApi.publishRole('token', roleID, 1, { permissions: ['sites.read', 'sites.read'] }, metadata('duplicate')),
      customRbacApi.assignGrant('token', 1, { role_id: roleID, subject_user_id: 'invalid' }, metadata('invalid-subject')),
      customRbacApi.revokeGrant('token', grantID, { ...metadata('invalid-proof'), stepUpProof: 'short' }),
    ]

    for (const request of invalidRequests) {
      await expect(request).rejects.toMatchObject({ status: 400, code: 'custom_rbac_validation_error' })
    }
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['role envelope extra field', { data: { ...role, internal_scope_id: actorUserID } }, 'role'],
    ['role revision zero', { data: { ...role, current_revision: 0 } }, 'role'],
    ['duplicate role permissions', { data: { ...role, permissions: ['sites.read', 'sites.read'] } }, 'role'],
    ['role page extra field', { data: [role], page: { count: 1 } }, 'roles'],
    ['permission extra field', { data: [{ ...permissionCatalog.data[0], description: 'private' }] }, 'permissions'],
    ['permission invalid name', { data: [{ name: 'Sites Read', step_up_required: false }] }, 'permissions'],
    ['grant invalid identity', { data: [{ ...grant, subject_user_id: 'not-a-uuid' }], page: {} }, 'grants'],
    ['grant invalid timestamp', { data: [{ ...grant, granted_at: 'not-a-date' }], page: {} }, 'grants'],
  ])('rejects a malformed successful response: %s', async (_scenario, body, requestKind) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(body))
    const request = requestKind === 'role'
      ? customRbacApi.getRole('token', roleID)
      : requestKind === 'roles'
        ? customRbacApi.listRoles('token')
        : requestKind === 'permissions'
          ? customRbacApi.listPermissions('token')
          : customRbacApi.listGrants('token')
    await expect(request).rejects.toMatchObject({ status: 502, code: 'custom_rbac_invalid_response' })
  })

  it('validates write envelopes and treats malformed committed responses as unknown outcomes', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ data: { ...role, replayed: 'yes' } }, 201))
      .mockResolvedValueOnce(json({ data: { ...revocation, grant_id: 'invalid' } }))

    await expect(customRbacApi.createRole('token', {
      name: role.name, permissions: role.permissions,
    }, metadata('bad-role-envelope'))).rejects.toMatchObject({ code: 'custom_rbac_write_unknown' })
    await expect(customRbacApi.revokeGrant('token', grantID, metadata('bad-revocation-envelope')))
      .rejects.toMatchObject({ code: 'custom_rbac_write_unknown' })
  })

  it('binds successful write responses to the original target, revision, and payload', async () => {
    const otherRoleID = '66666666-6666-4666-8666-666666666666'
    const otherGrantID = '77777777-7777-4777-8777-777777777777'
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ data: { ...role, name: 'wrong-create-result' } }, 201))
      .mockResolvedValueOnce(json({ data: { ...role, id: otherRoleID, name: 'renamed', current_revision: 2 } }))
      .mockResolvedValueOnce(json({ data: { ...role, current_revision: 2, permissions: ['sites.manage'] } }))
      .mockResolvedValueOnce(json({ data: { ...role, current_revision: 2 } }))
      .mockResolvedValueOnce(json({ data: { ...grant, role_id: otherRoleID } }, 201))
      .mockResolvedValueOnce(json({ data: { ...revocation, grant_id: otherGrantID } }))

    const writes = [
      customRbacApi.createRole('token', { name: role.name, permissions: role.permissions }, metadata('bound-create')),
      customRbacApi.renameRole('token', roleID, 1, { name: 'renamed' }, metadata('bound-rename')),
      customRbacApi.publishRole('token', roleID, 1, { permissions: ['sites.read'] }, metadata('bound-publish')),
      customRbacApi.deactivateRole('token', roleID, 1, metadata('bound-deactivate')),
      customRbacApi.assignGrant('token', 1, {
        role_id: roleID, subject_user_id: subjectUserID,
      }, metadata('bound-assign')),
      customRbacApi.revokeGrant('token', grantID, metadata('bound-revoke')),
    ]
    for (const request of writes) {
      await expect(request).rejects.toMatchObject({ status: 502, code: 'custom_rbac_write_unknown' })
    }
  })

  it('preserves stable custom_rbac errors without exposing raw server messages', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ error: {
        code: 'custom_rbac_revision_conflict',
        message: 'private database revision and tenant details',
        request_id: 'custom-rbac-safe-request',
      } }, 409))
      .mockResolvedValueOnce(json({ error: {
        code: 'permission_denied', message: 'private policy topology', request_id: 'unsafe request id',
      } }, 403))

    const conflict = await customRbacApi.getRole('token', roleID).catch((error: unknown) => error)
    expect(conflict).toBeInstanceOf(ApiError)
    expect(conflict).toMatchObject({
      status: 409,
      code: 'custom_rbac_revision_conflict',
      requestId: 'custom-rbac-safe-request',
      message: 'API request failed',
    })
    expect(String(conflict)).not.toContain('private database')

    const unsafe = await customRbacApi.listPermissions('token').catch((error: unknown) => error)
    expect(unsafe).toBeInstanceOf(ApiError)
    expect(unsafe).toMatchObject({ status: 403, code: 'request_failed', requestId: undefined })
    expect(String(unsafe)).not.toContain('private policy')
  })

  it('keeps unknown writes caller-owned for exact explicit retry or abandonment', async () => {
    const retryAttempt = Object.freeze({
      input: Object.freeze({ name: role.name, permissions: Object.freeze([...role.permissions]) }),
      metadata: Object.freeze(metadata('exact-retry', true)),
    })
    const abandonAttempt = Object.freeze({
      input: Object.freeze({ name: '可放弃角色', permissions: Object.freeze(['sites.read']) }),
      metadata: Object.freeze(metadata('abandon')),
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(new TypeError('response lost after commit'))
      .mockResolvedValueOnce(json({ data: { ...role, replayed: true } }, 201))
      .mockResolvedValueOnce(json({ error: {
        code: 'custom_rbac_request_timeout', message: 'private timeout detail', request_id: 'timeout-request',
      } }, 504))

    await expect(customRbacApi.createRole('token', retryAttempt.input, retryAttempt.metadata))
      .rejects.toMatchObject({ status: 0, code: 'custom_rbac_write_unknown' })
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    await expect(customRbacApi.createRole('token', retryAttempt.input, retryAttempt.metadata))
      .resolves.toEqual({ ...role, replayed: true })

    const first = fetchSpy.mock.calls[0]!
    const retry = fetchSpy.mock.calls[1]!
    expect(retry[0]).toBe(first[0])
    expect(retry[1]?.method).toBe(first[1]?.method)
    expect(retry[1]?.body).toBe(first[1]?.body)
    expect(Object.fromEntries(new Headers(retry[1]?.headers))).toEqual(Object.fromEntries(new Headers(first[1]?.headers)))

    let pendingAttempt: typeof abandonAttempt | undefined = abandonAttempt
    await expect(customRbacApi.createRole('token', pendingAttempt.input, pendingAttempt.metadata))
      .rejects.toMatchObject({ status: 504, code: 'custom_rbac_write_unknown' })
    expect(fetchSpy).toHaveBeenCalledTimes(3)
    pendingAttempt = undefined
    await Promise.resolve()
    expect(pendingAttempt).toBeUndefined()
    expect(fetchSpy).toHaveBeenCalledTimes(3)
  })
})
