import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'
import { vi } from 'vitest'

import { challengePoliciesApi } from '../api/challengePolicies'
import { securityPoliciesApi } from '../api/securityPolicies'
import { securitySystemRulesApi } from '../api/securitySystemRules'
import { SiteCCTab } from '../pages/site-edit/SiteProtectionTabs'
import { renderWithProviders } from '../test/render'

const siteID = '55555555-5555-4555-8555-555555555555'
const tenantScope = '22222222-2222-4222-8222-222222222222'

function Location() {
  const location = useLocation()
  return <output aria-label="location">{location.pathname + location.search}</output>
}

function renderTab(scopeKind: 'platform' | 'tenant', permissions: string[]) {
  renderWithProviders(<Routes>
    <Route path="/site/edit" element={<SiteCCTab siteId={siteID} host="shop.example.com" scopeKind={scopeKind} scopeId="s1"
      accessToken="token" permissions={permissions} locked={false} siteScopeId={tenantScope} />} />
    <Route path="/site/cc-rule" element={<Location />} />
  </Routes>, ['/site/edit'])
}

describe('站点 CC 防护页跳转 CC 统计', () => {
  beforeEach(() => {
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 100 })
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({ binding: null, latest_candidate: null, operation: null } as never)
  })
  afterEach(() => vi.restoreAllMocks())

  // tp-b1: CC rule statistics moved to the administrator console.
  it('tenants do not get the statistics entry', async () => {
    renderTab('tenant', ['security_policies.read'])
    expect(await screen.findByRole('heading', { name: 'CC防护' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '查看规则统计' })).not.toBeInTheDocument()
  })

  it('administrators also name the site tenant', async () => {
    renderTab('platform', ['security_policies.read'])
    await userEvent.click(await screen.findByRole('button', { name: '查看规则统计' }))
    // s4 A11：子流程跳转统一带 site_id 与管理员 tenant_scope_id，参数顺序不作契约。
    const url = new URL(screen.getByLabelText('location').textContent ?? '', 'http://x')
    expect(url.pathname).toBe('/site/cc-rule')
    expect(Object.fromEntries(url.searchParams)).toEqual({ site_id: siteID, tenant_scope_id: tenantScope, view: 'stats' })
  })

  it('is hidden without the CC rule read permission', async () => {
    vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 1 } as never)
    renderTab('tenant', ['challenge_policies.read'])
    expect(await screen.findByRole('heading', { name: 'CC防护' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '查看规则统计' })).not.toBeInTheDocument()
  })

  it('administrators read the site activation directly, no tenant-only note', async () => {
    // W7 曾让平台会话不调租户专用激活接口并显示说明；现在管理员按站点租户作用域直接读取。
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([] as never)
    renderTab('platform', ['security_policies.read'])
    expect(await screen.findByRole('heading', { name: 'CC防护' })).toBeInTheDocument()
    expect(screen.queryByText(/管理员视角无法读取发布绑定/)).not.toBeInTheDocument()
  })

  it('W7: tenants still read the activation binding', async () => {
    renderTab('tenant', ['security_policies.read'])
    expect(await screen.findByRole('heading', { name: 'CC防护' })).toBeInTheDocument()
    expect(securityPoliciesApi.getActivationStatus).toHaveBeenCalled()
    expect(screen.queryByText(/管理员视角无法读取发布绑定/)).not.toBeInTheDocument()
  })
})
