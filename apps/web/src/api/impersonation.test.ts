import { ApiError } from './auth'
import {
  createImpersonationWriteMetadata,
  impersonationApi,
  type ImpersonationWriteMetadata,
} from './impersonation'

const tenantID = '11111111-1111-4111-8111-111111111111'
const scopeID = '22222222-2222-4222-8222-222222222222'
const subjectID = '33333333-3333-4333-8333-333333333333'
const actorID = '44444444-4444-4444-8444-444444444444'
const actorScopeID = '55555555-5555-4555-8555-555555555555'
const grantID = '66666666-6666-4666-8666-666666666666'
const revocationID = '77777777-7777-4777-8777-777777777777'
const otherTenantID = '88888888-8888-4888-8888-888888888888'
const otherScopeID = '99999999-9999-4999-8999-999999999999'
const otherSubjectID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const metadata: ImpersonationWriteMetadata = {
  requestId: 'impersonation-create-1',
  idempotencyKey: 'impersonation-create-1',
  traceparent: '00-11111111111111111111111111111111-2222222222222222-01',
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  })
}

describe('impersonation API', () => {
  it('creates and exactly replays a short one-time grant without persisting its code', async () => {
    const response = {
      grant: {
        id: grantID, tenant_id: tenantID, tenant_scope_id: scopeID, actor_user_id: actorID,
        actor_scope_id: actorScopeID, subject_user_id: subjectID,
        created_at: '2026-08-07T08:00:00Z', expires_at: '2026-08-07T08:02:00Z',
      },
      authorization_code: 'one-time-secret',
      replayed: false,
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response, 201))
    const input = {
      tenant_id: tenantID, tenant_scope_id: scopeID, subject_user_id: subjectID,
    }

    await expect(impersonationApi.createGrant('primary-token', input, metadata)).resolves.toEqual(response)
    expect(fetchSpy).toHaveBeenCalledWith('/v1/admin/impersonation/grants', {
      method: 'POST',
      credentials: 'include',
      cache: 'no-store',
      headers: {
        Authorization: 'Bearer primary-token', 'Content-Type': 'application/json',
        'Idempotency-Key': metadata.idempotencyKey, 'X-Request-ID': metadata.requestId,
        Traceparent: metadata.traceparent,
      },
      body: JSON.stringify(input),
    })
  })

  it('exchanges without a bearer token and returns only safe session facts', async () => {
    const response = {
      principal: {
        user_id: subjectID, scope_id: scopeID, scope_kind: 'tenant', tenant_id: tenantID,
        username: 'tenant-user', display_name: 'Tenant User', roles: ['tenant_viewer'],
        permissions: ['sites.read'],
      },
      banner: {
        grant_id: grantID, actor_user_id: actorID, actor_display_name: 'Support Admin',
        subject_user_id: subjectID, subject_display_name: 'Tenant User', tenant_id: tenantID,
        expires_at: '2099-08-07T08:15:00Z',
      },
      expires_at: '2099-08-07T08:15:00Z', refreshable: false, replayed: false,
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response, 201))
    const input = { tenant_id: tenantID, tenant_scope_id: scopeID, authorization_code: 'one-time-secret' }

    const result = await impersonationApi.exchange(input, metadata)
    expect(result).toEqual(response)
    const init = fetchSpy.mock.calls[0][1]!
    expect(new Headers(init.headers).has('Authorization')).toBe(false)
    expect(init.credentials).toBe('include')
    expect(JSON.stringify(result)).not.toContain('one-time-secret')
  })

  // fix-overview：后端代登录 principal 带 display_id（用户概览「账号 ID」），解析不能把整个响应拒掉。
  it('accepts the subject display_id in the exchanged principal', async () => {
    const response = {
      principal: {
        user_id: subjectID, display_id: '100023', scope_id: scopeID, scope_kind: 'tenant', tenant_id: tenantID,
        username: 'tenant-user', display_name: 'Tenant User', roles: ['tenant_viewer'], permissions: ['sites.read'],
      },
      banner: {
        grant_id: grantID, actor_user_id: actorID, actor_display_name: 'Support Admin',
        subject_user_id: subjectID, subject_display_name: 'Tenant User', tenant_id: tenantID,
        expires_at: '2099-08-07T08:15:00Z',
      },
      expires_at: '2099-08-07T08:15:00Z', refreshable: false, replayed: false,
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response, 201))
    const result = await impersonationApi.exchange({ tenant_id: tenantID, tenant_scope_id: scopeID, authorization_code: 'code' }, metadata)
    expect(result.principal.display_id).toBe('100023')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ ...response, principal: { ...response.principal, display_id: '0' } }, 201))
    await expect(impersonationApi.exchange({ tenant_id: tenantID, tenant_scope_id: scopeID, authorization_code: 'code' }, metadata)).rejects.toThrow()
  })

  it('rejects create and exchange responses that are not bound to the exact request target', async () => {
    const createInput = {
      tenant_id: tenantID, tenant_scope_id: scopeID, subject_user_id: subjectID,
    }
    const grant = {
      id: grantID, tenant_id: tenantID, tenant_scope_id: scopeID, actor_user_id: actorID,
      actor_scope_id: actorScopeID, subject_user_id: subjectID,
      created_at: '2026-08-07T08:00:00Z', expires_at: '2026-08-07T08:02:00Z',
    }
    const session = {
      principal: {
        user_id: subjectID, scope_id: scopeID, scope_kind: 'tenant', tenant_id: tenantID,
        username: 'tenant-user', display_name: 'Tenant User', roles: ['tenant_viewer'], permissions: ['sites.read'],
      },
      banner: {
        grant_id: grantID, actor_user_id: actorID, actor_display_name: 'Support Admin',
        subject_user_id: subjectID, subject_display_name: 'Tenant User', tenant_id: tenantID,
        expires_at: '2099-08-07T08:15:00Z',
      },
      expires_at: '2099-08-07T08:15:00Z', refreshable: false, replayed: false,
    }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ grant: { ...grant, tenant_id: otherTenantID }, authorization_code: 'secret', replayed: false }, 201))
      .mockResolvedValueOnce(json({ grant: { ...grant, tenant_scope_id: otherScopeID }, authorization_code: 'secret', replayed: false }, 201))
      .mockResolvedValueOnce(json({ grant: { ...grant, subject_user_id: otherSubjectID }, authorization_code: 'secret', replayed: false }, 201))
      .mockResolvedValueOnce(json({
        ...session,
        principal: { ...session.principal, tenant_id: otherTenantID },
        banner: { ...session.banner, tenant_id: otherTenantID },
      }, 201))
      .mockResolvedValueOnce(json({
        ...session,
        principal: { ...session.principal, scope_id: otherScopeID },
      }, 201))

    for (let attempt = 0; attempt < 3; attempt += 1) {
      await expect(impersonationApi.createGrant('primary-token', createInput, metadata))
        .rejects.toMatchObject({ code: 'invalid_response' })
    }
    const exchangeInput = { tenant_id: tenantID, tenant_scope_id: scopeID, authorization_code: 'one-time-secret' }
    await expect(impersonationApi.exchange(exchangeInput, metadata)).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(impersonationApi.exchange(exchangeInput, metadata)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('revokes with the primary session and rejects unknown response fields and stable errors', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({
        id: revocationID, grant_id: grantID, revoked_by: actorID, reason: 'support complete',
        revoked_at: '2026-08-07T08:10:00Z', replayed: false,
      }))
      .mockResolvedValueOnce(json({
        id: revocationID, grant_id: grantID, revoked_by: actorID, reason: 'support complete',
        revoked_at: '2026-08-07T08:10:00Z', replayed: false, private_note: 'secret',
      }))
      .mockResolvedValueOnce(json({ error: { code: 'impersonation_principal_changed', request_id: 'request-9' } }, 403))

    await expect(impersonationApi.revoke('primary-token', grantID, {
      tenant_id: tenantID, tenant_scope_id: scopeID, reason: 'support complete',
    }, metadata)).resolves.toMatchObject({ id: revocationID })
    await expect(impersonationApi.revoke('primary-token', grantID, {
      tenant_id: tenantID, tenant_scope_id: scopeID, reason: 'support complete',
    }, metadata)).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(impersonationApi.revoke('primary-token', grantID, {
      tenant_id: tenantID, tenant_scope_id: scopeID, reason: 'support complete',
    }, metadata)).rejects.toEqual(expect.objectContaining<ApiError>({
      name: 'ApiError', message: 'API request failed', status: 403,
      code: 'impersonation_principal_changed', requestId: 'request-9',
    }))
    expect(String(fetchSpy.mock.calls[0][0])).toBe(`/v1/admin/impersonation/grants/${grantID}/revocations`)
  })

  it('generates canonical nonzero request, idempotency, and trace metadata', () => {
    const value = createImpersonationWriteMetadata('exchange')
    expect(value.requestId).toMatch(/^impersonation-exchange-[0-9a-f-]{16,}$/)
    expect(value.idempotencyKey).toMatch(/^impersonation-exchange-[0-9a-f-]{16,}$/)
    expect(value.traceparent).toMatch(/^00-(?!0{32}-)[0-9a-f]{32}-(?!0{16}-)[0-9a-f]{16}-01$/)
  })
})
