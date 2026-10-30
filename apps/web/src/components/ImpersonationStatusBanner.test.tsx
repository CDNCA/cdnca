import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ApiError, authApi } from '../api/auth'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { ImpersonationStatusBanner } from './ImpersonationStatusBanner'

const revoke = vi.hoisted(() => vi.fn())
const createMetadata = vi.hoisted(() => vi.fn())
vi.mock('../api/impersonation', async () => {
  const actual = await vi.importActual<typeof import('../api/impersonation')>('../api/impersonation')
  return {
    ...actual,
    impersonationApi: { ...actual.impersonationApi, revoke },
    createImpersonationWriteMetadata: createMetadata,
  }
})

const grantID = '44444444-4444-4444-8444-444444444444'
const tenantID = '11111111-1111-4111-8111-111111111111'
const scopeID = '22222222-2222-4222-8222-222222222222'

describe('ImpersonationStatusBanner', () => {
  beforeEach(() => {
    revoke.mockReset()
    createMetadata.mockReset()
    let sequence = 0
    createMetadata.mockImplementation(() => {
      sequence += 1
      return {
        requestId: `revoke-request-${sequence}`, idempotencyKey: `revoke-key-${sequence}`,
        traceparent: `00-11111111111111111111111111111111-${String(sequence).padStart(16, '2')}-01`,
      }
    })
    vi.restoreAllMocks()
    const actor = principal({ scope_kind: 'platform', tenant_id: null, permissions: ['identity.impersonation.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
  })

  it('is non-dismissible, identifies both actors, and revokes before exit', async () => {
    revoke.mockResolvedValue({})
    const actor = useSessionStore.getState().principal!
    vi.spyOn(authApi, 'me').mockResolvedValue(actor)
    useSessionStore.setState({
      principal: {
        user_id: '33333333-3333-4333-8333-333333333333', scope_id: scopeID,
        scope_kind: 'tenant', tenant_id: tenantID, username: 'tenant-user',
        display_name: 'Tenant User', roles: ['tenant_viewer'], permissions: ['sites.read'],
        impersonation: {
        grant_id: grantID, actor_user_id: actor.user_id,
        actor_display_name: 'Support Admin', subject_user_id: '33333333-3333-4333-8333-333333333333',
        subject_display_name: 'Tenant User', tenant_id: tenantID, expires_at: '2099-08-07T08:15:00Z',
        },
      },
    })
    renderWithProviders(<ImpersonationStatusBanner />)

    // P2-15: inside .app-main > * (margin 12px on mobile) width:100% made the
    // 390px page 402px wide; the block takes the remaining width by itself.
    expect(screen.getByRole('status')).not.toHaveStyle({ width: '100%' })
    expect(screen.getByRole('status')).toHaveStyle({ minWidth: '0' })
    expect(screen.getByRole('status')).toHaveTextContent('正在代登录')
    expect(screen.getByRole('status')).toHaveTextContent('Support Admin')
    expect(screen.getByRole('status')).toHaveTextContent('Tenant User')
    expect(screen.queryByRole('button', { name: /关闭/ })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '退出代登录' }))
    await waitFor(() => expect(revoke).toHaveBeenCalledTimes(1))
    expect(revoke.mock.calls[0][1]).toBe(grantID)
    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument())
    expect(useSessionStore.getState().principal?.scope_kind).toBe('platform')
    expect(useSessionStore.getState().principal?.impersonation).toBeUndefined()
    expect(authApi.me).toHaveBeenCalledTimes(1)
  })

  it('freezes an unknown revoke for exact retry and restores only after revoke and me are confirmed', async () => {
    const actor = useSessionStore.getState().principal!
    let confirmRevoke!: () => void
    let confirmMe!: (value: typeof actor) => void
    revoke
      .mockRejectedValueOnce(new Error('network outcome unknown'))
      .mockReturnValueOnce(new Promise<void>((resolve) => { confirmRevoke = resolve }))
    vi.spyOn(authApi, 'me').mockReturnValue(new Promise((resolve) => { confirmMe = resolve }))
    useSessionStore.setState({ principal: {
      user_id: '33333333-3333-4333-8333-333333333333', scope_id: scopeID,
      scope_kind: 'tenant', tenant_id: tenantID, username: 'tenant-user', display_name: 'Tenant User',
      roles: ['tenant_viewer'], permissions: ['sites.read'], impersonation: {
        grant_id: grantID, actor_user_id: actor.user_id, actor_display_name: 'Support Admin',
        subject_user_id: '33333333-3333-4333-8333-333333333333', subject_display_name: 'Tenant User',
        tenant_id: tenantID, expires_at: '2099-08-07T08:15:00Z',
      },
    } })
    renderWithProviders(<ImpersonationStatusBanner />)

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: '退出代登录' }))
    expect(await screen.findByText('操作结果尚不确定。', { selector: '.ant-alert-banner .ant-alert-message' })).toBeInTheDocument()
    const firstInput = revoke.mock.calls[0][2]
    const firstMetadata = revoke.mock.calls[0][3]
    expect(createMetadata).toHaveBeenCalledTimes(1)
    expect(useSessionStore.getState().principal?.scope_kind).toBe('tenant')
    expect(authApi.me).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: '使用完全相同的请求重试' }))
    expect(revoke).toHaveBeenCalledTimes(2)
    expect(revoke.mock.calls[1][2]).toEqual(firstInput)
    expect(revoke.mock.calls[1][3]).toEqual(firstMetadata)
    expect(createMetadata).toHaveBeenCalledTimes(1)
    expect(useSessionStore.getState().principal?.scope_kind).toBe('tenant')
    expect(authApi.me).not.toHaveBeenCalled()

    await act(async () => { confirmRevoke() })
    expect(authApi.me).toHaveBeenCalledTimes(1)
    expect(useSessionStore.getState().principal?.scope_kind).toBe('tenant')
    await act(async () => { confirmMe(actor) })
    await waitFor(() => expect(useSessionStore.getState().principal?.scope_kind).toBe('platform'))
  })

  it('explicitly abandons an unknown revoke without dropping the impersonation marker', async () => {
    revoke.mockRejectedValue(new ApiError('unknown', 503, 'impersonation_unavailable'))
    const actor = useSessionStore.getState().principal!
    vi.spyOn(authApi, 'me').mockResolvedValue(actor)
    useSessionStore.setState({ principal: {
      user_id: '33333333-3333-4333-8333-333333333333', scope_id: scopeID,
      scope_kind: 'tenant', tenant_id: tenantID, username: 'tenant-user', display_name: 'Tenant User',
      roles: ['tenant_viewer'], permissions: ['sites.read'], impersonation: {
        grant_id: grantID, actor_user_id: actor.user_id, actor_display_name: 'Support Admin',
        subject_user_id: '33333333-3333-4333-8333-333333333333', subject_display_name: 'Tenant User',
        tenant_id: tenantID, expires_at: '2099-08-07T08:15:00Z',
      },
    } })
    renderWithProviders(<ImpersonationStatusBanner />)

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: '退出代登录' }))
    expect(await screen.findByText('操作结果尚不确定。', { selector: '.ant-alert-banner .ant-alert-message' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '放弃本次尝试' }))
    expect(screen.getByRole('status')).toHaveTextContent('正在代登录')
    expect(useSessionStore.getState().principal?.scope_kind).toBe('tenant')
    expect(useSessionStore.getState().principal?.impersonation?.grant_id).toBe(grantID)
    expect(revoke).toHaveBeenCalledTimes(1)
    expect(authApi.me).not.toHaveBeenCalled()
  })
})
