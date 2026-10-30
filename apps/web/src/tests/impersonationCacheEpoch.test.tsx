import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CdncaProvider } from '@cdnca/ui'
import { MemoryRouter } from 'react-router-dom'

import { authApi } from '../api/auth'
import { SessionQueryBoundary } from '../auth/SessionQueryBoundary'
import { useSessionStore } from '../auth/session'
import { ImpersonationStatusBanner } from '../components/ImpersonationStatusBanner'
import { authResponse, principal } from '../test/fixtures'

// A14 (Codex 审测 跨端角色卡三): leaving impersonation (operator exit or
// expiry) swapped the principal without a new sessionEpoch, so
// SessionQueryBoundary kept the tenant's cached queries for the restored
// platform admin. Each identity transition must start a new epoch.

const revoke = vi.hoisted(() => vi.fn())
vi.mock('../api/impersonation', async () => {
  const actual = await vi.importActual<typeof import('../api/impersonation')>('../api/impersonation')
  return { ...actual, impersonationApi: { ...actual.impersonationApi, revoke } }
})

const grantID = '44444444-4444-4444-8444-444444444444'
const tenantID = '11111111-1111-4111-8111-111111111111'
const scopeID = '22222222-2222-4222-8222-222222222222'
const subjectID = '33333333-3333-4333-8333-333333333333'

function enterImpersonation(expiresAt: string) {
  const admin = useSessionStore.getState().principal!
  const epoch = useSessionStore.getState().sessionEpoch
  const applied = useSessionStore.getState().transitionPrincipal(epoch, {
    user_id: subjectID, scope_id: scopeID, scope_kind: 'tenant', tenant_id: tenantID,
    username: 'tenant-user', display_name: 'Tenant User', roles: ['tenant_owner'], permissions: ['sites.read'],
    impersonation: {
      grant_id: grantID, actor_user_id: admin.user_id, actor_display_name: 'Support Admin',
      subject_user_id: subjectID, subject_display_name: 'Tenant User', tenant_id: tenantID, expires_at: expiresAt,
    },
  })
  expect(applied).toBe(true)
  return admin
}

function renderBanner(queryClient: QueryClient) {
  return render(
    <CdncaProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <SessionQueryBoundary><ImpersonationStatusBanner /></SessionQueryBoundary>
        </MemoryRouter>
      </QueryClientProvider>
    </CdncaProvider>,
  )
}

describe('impersonation identity transitions start a new session epoch', () => {
  beforeEach(() => {
    revoke.mockReset()
    vi.restoreAllMocks()
    const admin = principal({ scope_kind: 'platform', tenant_id: null, permissions: ['identity.impersonation.manage'] })
    useSessionStore.getState().setSession(authResponse(admin), admin)
  })

  it('entering clears the admin cache; operator exit clears the tenant cache', async () => {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
    queryClient.setQueryData(['plugin-menu'], { owner: 'admin' })
    renderBanner(queryClient)

    const epochAdmin = useSessionStore.getState().sessionEpoch
    let admin!: ReturnType<typeof enterImpersonation>
    act(() => { admin = enterImpersonation('2099-08-07T08:15:00Z') })
    expect(useSessionStore.getState().sessionEpoch).toBeGreaterThan(epochAdmin)
    expect(queryClient.getQueryData(['plugin-menu'])).toBeUndefined()

    queryClient.setQueryData(['plugin-menu'], { owner: 'tenant' })
    const epochTenant = useSessionStore.getState().sessionEpoch
    revoke.mockResolvedValue({})
    vi.spyOn(authApi, 'me').mockResolvedValue(admin)
    await userEvent.click(await screen.findByRole('button', { name: '退出代登录' }))
    await waitFor(() => expect(useSessionStore.getState().principal?.scope_kind).toBe('platform'))
    expect(useSessionStore.getState().sessionEpoch).toBeGreaterThan(epochTenant)
    expect(queryClient.getQueryData(['plugin-menu'])).toBeUndefined()
  })

  it('expiry restore clears the tenant cache', async () => {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
    const admin = enterImpersonation(new Date(Date.now() - 1_000).toISOString())
    queryClient.setQueryData(['plugin-menu'], { owner: 'tenant' })
    const epochTenant = useSessionStore.getState().sessionEpoch
    vi.spyOn(authApi, 'me').mockResolvedValue(admin)
    renderBanner(queryClient)

    await waitFor(() => expect(useSessionStore.getState().principal?.scope_kind).toBe('platform'))
    expect(useSessionStore.getState().sessionEpoch).toBeGreaterThan(epochTenant)
    expect(queryClient.getQueryData(['plugin-menu'])).toBeUndefined()
  })

  it('a transition from a stale epoch is refused (late revoke after a new sign-in)', () => {
    const stale = useSessionStore.getState().sessionEpoch
    const other = principal({ user_id: '55555555-5555-4555-8555-555555555555' })
    useSessionStore.getState().setSession(authResponse(other), other)
    expect(useSessionStore.getState().transitionPrincipal(stale, principal())).toBe(false)
    expect(useSessionStore.getState().principal?.user_id).toBe(other.user_id)
  })
})
