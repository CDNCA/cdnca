import { screen } from '@testing-library/react'
import { useLocation } from 'react-router-dom'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import { getNavigation } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { pageRequests } from '../test/shellRequests'

const route = '/monitor/site/analysis/ja4-blocks?tenant_scope_id=22222222-2222-4222-8222-222222222222&site_id=33333333-3333-4333-8333-333333333333&ja4=t13d1516h2_8daaf6152771&snapshot_at=2026-08-08T00%3A00%3A00Z&filter_dimension=ja4#ja4-ranking'

function LocationProbe() {
  const location = useLocation()
  return <output aria-label="location">{`${location.pathname}${location.search}${location.hash}`}</output>
}

function authenticate(scope: 'tenant' | 'platform', permissions: string[]) {
  const actor = principal({
    scope_kind: scope,
    scope_id: scope === 'platform' ? 'platform' : '22222222-2222-4222-8222-222222222222',
    tenant_id: scope === 'platform' ? null : '22222222-2222-4222-8222-222222222222',
    roles: scope === 'platform' ? ['platform_admin'] : ['tenant_owner'],
    permissions,
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

describe('SEC-10 JA4 block workflow route', () => {
  it('mounts for an authorized tenant and preserves direct query/hash identity', async () => {
    authenticate('tenant', [
      'sites.read',
      'security_policies.read',
      'security_policies.manage',
    ])
    renderWithProviders(<><AppRoutes /><LocationProbe /></>, [route])

    expect(await screen.findByRole('heading', { name: 'JA4 封禁工作流' })).toBeInTheDocument()
    expect(screen.getByLabelText('location')).toHaveTextContent(route)
  })

  it('keeps the tenant workflow hidden from a platform administrator without issuing requests', async () => {
    authenticate('platform', [
      'platform.admin',
      'sites.read',
      'security_policies.read',
      'security_policies.manage',
    ])
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<><AppRoutes /><LocationProbe /></>, [route])

    expect(await screen.findByText('页面不存在')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'JA4 封禁工作流' })).not.toBeInTheDocument()
    expect(pageRequests(fetchSpy)).toEqual([])
  })

  it.each([
    ['analytics permission', ['security_policies.read', 'security_policies.manage']],
    ['security read permission', ['sites.read', 'security_policies.manage']],
    ['security manage permission', ['sites.read', 'security_policies.read']],
  ])('does not mount or request the page without %s', async (_label, permissions) => {
    authenticate('tenant', permissions)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<><AppRoutes /><LocationProbe /></>, [route])

    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'JA4 封禁工作流' })).not.toBeInTheDocument()
    expect(pageRequests(fetchSpy)).toEqual([])
  })

  it('does not add the workflow route as an independent menu item', () => {
    const keys = getNavigation('user', undefined, [
      'sites.read', 'security_policies.read', 'security_policies.manage',
    ]).flatMap((group) => [group.key, ...(group.children ?? []).map((item) => item.key)])
    expect(keys).not.toContain('/monitor/site/analysis/ja4-blocks')
  })
})
