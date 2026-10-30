import { useEffect } from 'react'
import { screen } from '@testing-library/react'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { pageRequests } from '../test/shellRequests'

// Page mocks count mounts (useEffect), not renders: the shell's background
// requests (test/shellRequests.ts) re-render the route element, so a render
// count depended on their timing and toHaveBeenCalledOnce failed at random.
const mounted = vi.hoisted(() => ({
  siteProtocols: vi.fn(),
}))

vi.mock('../pages/site-protocols/SiteProtocolBatchPage', () => ({
  default: function MockPage1() {
    useEffect(() => {
      mounted.siteProtocols()
    }, [])
    return <h1>site-protocols-page</h1>
  },
}))

function authenticate(
  scope: 'platform' | 'tenant',
  permissions: string[],
) {
  const actor = principal({
    scope_kind: scope,
    scope_id: scope === 'platform' ? 'platform' : '22222222-2222-4222-8222-222222222222',
    tenant_id: scope === 'platform' ? null : '22222222-2222-4222-8222-222222222222',
    roles: scope === 'platform' ? ['platform_admin'] : ['tenant_owner'],
    permissions,
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

describe('full-surface route guards', () => {
  it.each([
    '/site/list',
    '/monitor/site/realtime',
    '/monitor/site/analysis',
    '/site/site-1/edit',
    '/site/publications',
    '/site/cc-rule',
    '/site/waf-rule',
    '/site/acl',
  ])('rejects %s before mounting a page or issuing a request when its read permission is absent', async (path) => {
    authenticate('tenant', [])
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<AppRoutes />, [path])

    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(screen.queryByLabelText('页面加载中')).not.toBeInTheDocument()
    expect(pageRequests(fetchSpy)).toEqual([])
  })

  it.each([
    ['tenant publication', 'tenant', ['edge_publications.read'], '/site/publications'],
    ['platform publication', 'platform', ['sites.read'], '/site/publications'],
  ] as const)('uses the audience-specific permission for %s', async (_label, scope, permissions, path) => {
    authenticate(scope, [...permissions])
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<AppRoutes />, [path])

    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(pageRequests(fetchSpy)).toEqual([])
  })

  it('keeps site protocol batches administrator-only even when a tenant has the underlying permission', async () => {
    authenticate('tenant', ['sites.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<AppRoutes />, ['/site/protocols'])

    expect(await screen.findByText('页面不存在')).toBeInTheDocument()
    expect(mounted.siteProtocols).not.toHaveBeenCalled()
    expect(pageRequests(fetchSpy)).toEqual([])
  })

  it('mounts site protocol batches for an administrator with the exact permission', async () => {
    authenticate('platform', ['sites.manage'])

    renderWithProviders(<AppRoutes />, ['/site/protocols'])

    expect(await screen.findByRole('heading', { name: 'site-protocols-page' })).toBeInTheDocument()
    expect(mounted.siteProtocols).toHaveBeenCalledOnce()
  })
})
