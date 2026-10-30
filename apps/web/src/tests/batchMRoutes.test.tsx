import { screen } from '@testing-library/react'
import { vi } from 'vitest'

import { AppRoutes } from '../App'
import { errorPagesApi } from '../api/errorPages'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const siteID = '44444444-4444-4444-8444-444444444444'

function setSession(scopeKind: 'platform' | 'tenant', permissions: string[]) {
  const actor = principal({
    scope_kind: scopeKind,
    tenant_id: scopeKind === 'tenant' ? '22222222-2222-4222-8222-222222222222' : null,
    permissions,
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

describe('Batch M routes', () => {
  it('mounts the platform error-page route behind system configuration read', async () => {
    setSession('platform', ['error_pages.read'])
    vi.spyOn(errorPagesApi, 'listAssets').mockImplementation(() => new Promise<never>(() => undefined))
    vi.spyOn(errorPagesApi, 'listRules').mockImplementation(() => new Promise<never>(() => undefined))

    renderWithProviders(<AppRoutes />, ['/config/error'])

    expect(await screen.findByRole('heading', { name: '错误页面' })).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/全局配置/错误页面')
  })

  it('mounts tenant DNS reconciliation detail only with dns.read', async () => {
    setSession('tenant', ['dns.read'])

    renderWithProviders(<AppRoutes />, [`/site/${siteID}/dns-reconcile`])

    expect(await screen.findByRole('heading', { name: 'DNS 对账' })).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/网站管理/DNS 对账')
  })

  it('denies the error-page route locally before any read request', async () => {
    setSession('platform', [])
    const listAssets = vi.spyOn(errorPagesApi, 'listAssets')
    const listRules = vi.spyOn(errorPagesApi, 'listRules')

    renderWithProviders(<AppRoutes />, ['/config/error'])

    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(listAssets).not.toHaveBeenCalled()
    expect(listRules).not.toHaveBeenCalled()
  })
})
