import { fireEvent, screen, waitFor, within } from '@testing-library/react'

import { useSessionStore } from '../auth/session'
import { getBreadcrumbLabels, isImplementedPath } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import AdminIdentityReviewPage from './AdminIdentityReviewPage'

const tenantScope = '44444444-4444-4444-8444-444444444444'
const caseID = '55555555-5555-4555-8555-555555555555'
const adminID = '11111111-1111-4111-8111-111111111111'

function summary(status: string) {
  return {
    id: caseID, applicant_user_id: '66666666-6666-4666-8666-666666666666', kind: 'personal_initial', status,
    revision: 2, created_at: '2026-10-27T01:00:00Z', state_changed_at: '2026-10-27T01:00:00Z',
    submitted_at: '2026-10-27T01:00:00Z', tenant_scope_id: tenantScope, tenant_name: '甲租户', applicant_username: 'alice',
  }
}

function detail(status: string, revision: number, reviewer?: string) {
  return {
    id: caseID, applicant_user_id: '66666666-6666-4666-8666-666666666666', kind: 'personal_initial', status,
    ...(reviewer ? { reviewer_user_id: reviewer } : {}), revision,
    created_at: '2026-10-27T01:00:00Z', state_changed_at: '2026-10-27T01:00:00Z', submitted_at: '2026-10-27T01:00:00Z',
    retention: { eligible: false, eligible_at: '2026-11-27T01:00:00Z', reason_code: 'case_not_terminal' },
    materials: [], replayed: false,
  }
}

function json(body: unknown, revision?: number) {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (revision !== undefined) headers.ETag = `"${revision}"`
  return new Response(JSON.stringify(body), { status: 200, headers })
}

function authenticate() {
  const actor = principal({ user_id: adminID, scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
    permissions: ['platform.admin'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

describe('admin identity review page', () => {
  it('is an admin system route for platform administrators', () => {
    expect(isImplementedPath('admin', '/sys/identity-review', ['platform.admin'])).toBe(true)
    expect(isImplementedPath('admin', '/sys/identity-review', ['sites.read'])).toBe(false)
    expect(getBreadcrumbLabels('admin', '/sys/identity-review').at(-1)).toBe('实名审核')
  })

  it('lists every tenant\'s cases by status and claims then approves one as the administrator', async () => {
    authenticate()
    const calls: Array<{ method: string; url: string; body?: unknown }> = []
    let state = detail('submitted', 2)
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      calls.push({ method, url, body: init?.body ? JSON.parse(String(init.body)) : undefined })
      if (url.includes('/v1/identity-verification/admin/cases')) {
        return json({ items: new URL(url, 'http://x').searchParams.get('status') === 'approved' ? [] : [summary(state.status)] })
      }
      if (url.includes(`/reviewer/cases/${caseID}/claim`)) {
        state = detail('reviewing', 3, adminID)
        return json(state, 3)
      }
      if (url.includes(`/reviewer/cases/${caseID}/decision`)) {
        state = { ...detail('approved', 4, adminID), decision_reason_code: 'evidence_verified' } as typeof state
        return json(state, 4)
      }
      if (url.includes(`/reviewer/cases/${caseID}`)) return json(state, state.revision)
      return new Response('{}', { status: 404 })
    })
    renderWithProviders(<AdminIdentityReviewPage />)
    expect(await screen.findByText('甲租户')).toBeInTheDocument()
    expect(screen.getByText('alice')).toBeInTheDocument()
    expect(calls[0].url).toContain('/v1/identity-verification/admin/cases?status=submitted')

    fireEvent.click(screen.getByRole('button', { name: '审核' }))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('待审核')).toBeInTheDocument()
    expect(calls.at(-1)?.url).toContain(`/reviewer/cases/${caseID}?tenant_scope_id=${tenantScope}`)

    fireEvent.click(within(drawer).getByRole('button', { name: '开始审核' }))
    await waitFor(() => expect(within(drawer).getByRole('button', { name: '通过' })).toBeEnabled())
    expect(calls.find((call) => call.url.includes('/claim'))?.url).toContain(`tenant_scope_id=${tenantScope}`)

    fireEvent.click(within(drawer).getByRole('button', { name: '通过' }))
    await waitFor(() => expect(calls.some((call) => call.url.includes('/decision'))).toBe(true))
    const decision = calls.find((call) => call.url.includes('/decision'))!
    expect(decision.url).toContain(`tenant_scope_id=${tenantScope}`)
    expect(decision.body).toEqual({ decision: 'approved', reason_code: 'evidence_verified' })
    expect(await within(drawer).findByText('已通过')).toBeInTheDocument()
  })

  it('rejects with a reason', async () => {
    authenticate()
    const bodies: unknown[] = []
    let state = detail('reviewing', 3, adminID)
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (url.includes('/admin/cases')) return json({ items: [summary('reviewing')] })
      if (url.includes('/decision')) {
        bodies.push(JSON.parse(String(init?.body)))
        state = { ...detail('rejected', 4, adminID), decision_reason_code: 'evidence_incomplete' } as typeof state
        return json(state, 4)
      }
      return json(state, state.revision)
    })
    renderWithProviders(<AdminIdentityReviewPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '审核中' }))
    fireEvent.click(await screen.findByRole('button', { name: '审核' }))
    const drawer = await screen.findByRole('dialog')
    await waitFor(() => expect(within(drawer).getByRole('button', { name: '驳回' })).toBeEnabled())
    fireEvent.click(within(drawer).getByRole('button', { name: '驳回' }))
    await waitFor(() => expect(bodies).toEqual([{ decision: 'rejected', reason_code: 'evidence_incomplete' }]))
    expect(await within(drawer).findByText('已驳回')).toBeInTheDocument()
  })

  it('refuses non-administrators', () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    renderWithProviders(<AdminIdentityReviewPage />)
    expect(screen.getByText('只有平台管理员可以审核实名认证。')).toBeInTheDocument()
  })
})
