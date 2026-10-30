import { vi } from 'vitest'

import { logoutSession, refreshSession, useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'

describe('session refresh', () => {
  it('uses the HttpOnly cookie flow and refreshes account data from me', async () => {
    const user = principal()
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        new Response(JSON.stringify(authResponse(user)), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify(user), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )

    await refreshSession()

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      '/v1/auth/refresh',
      expect.objectContaining({ method: 'POST', credentials: 'include' }),
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      '/v1/auth/me',
      expect.objectContaining({
        credentials: 'include',
        headers: expect.objectContaining({ Authorization: 'Bearer memory-only-access-token' }),
      }),
    )
    expect(useSessionStore.getState()).toMatchObject({
      status: 'authenticated',
      accessToken: 'memory-only-access-token',
      principal: user,
    })
    expect(localStorage).toHaveLength(0)
    expect(sessionStorage).toHaveLength(0)
  })

  it('keeps the target identity and rehydrates only a non-sensitive impersonation marker', async () => {
    const localStorageBefore = JSON.stringify(localStorage)
    const sessionStorageBefore = JSON.stringify(sessionStorage)
    const tenantId = '11111111-1111-4111-8111-111111111111'
    const target = {
      ...principal({
        user_id: '22222222-2222-4222-8222-222222222222',
        scope_id: '33333333-3333-4333-8333-333333333333',
        scope_kind: 'tenant',
        tenant_id: tenantId,
        permissions: ['identity.self.read'],
      }),
      impersonation: {
        grant_id: '44444444-4444-4444-8444-444444444444',
        actor_user_id: '55555555-5555-4555-8555-555555555555',
        actor_display_name: 'Support Admin',
        subject_user_id: '22222222-2222-4222-8222-222222222222',
        subject_display_name: 'Tenant User',
        tenant_id: tenantId,
        expires_at: '2099-08-07T08:15:00Z',
      },
    }
    useSessionStore.getState().setSession(authResponse(target), target)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const response = { ...authResponse(target), impersonation: target.impersonation }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(response), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify(target), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      }))

    await refreshSession()

    expect(useSessionStore.getState()).toMatchObject({
      status: 'authenticated',
      sessionEpoch,
      principal: target,
    })
    expect(JSON.stringify(localStorage)).toBe(localStorageBefore)
    expect(JSON.stringify(sessionStorage)).toBe(sessionStorageBefore)
    expect(JSON.stringify([localStorage, sessionStorage])).not.toContain(target.impersonation.grant_id)
  })

  it('updates current display name without replacing authentication data', () => {
    const user = principal()
    useSessionStore.getState().setSession(authResponse(user), user)

    useSessionStore.getState().updatePrincipal({ display_name: 'Jason Chen' })

    expect(useSessionStore.getState()).toMatchObject({
      status: 'authenticated',
      accessToken: 'memory-only-access-token',
      principal: { ...user, display_name: 'Jason Chen' },
    })
  })
})

// 退出即清本机会话；服务端注销在后台尽力完成，失败不报错、不提示。
describe('session sign-out', () => {
  it('clears the local session before the server answers and swallows a failed revoke', async () => {
    const user = principal()
    useSessionStore.getState().setSession(authResponse(user), user)
    let fail: (reason: unknown) => void = () => undefined
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockReturnValueOnce(new Promise<Response>((_, reject) => { fail = reject }))
    const done = logoutSession()
    expect(useSessionStore.getState()).toMatchObject({ status: 'anonymous', principal: null, accessToken: null })
    expect(fetchMock).toHaveBeenCalledWith('/v1/auth/logout', expect.objectContaining({ method: 'POST', credentials: 'include' }))
    fail(new TypeError('offline'))
    await expect(done).resolves.toBeUndefined()
    fetchMock.mockRestore()
  })
})
