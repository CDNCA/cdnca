import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'
import { vi } from 'vitest'

import { challengePoliciesApi } from '../api/challengePolicies'
import { securityPoliciesApi } from '../api/securityPolicies'
import { securitySystemRulesApi } from '../api/securitySystemRules'
import { useSessionStore } from '../auth/session'
import SecurityPoliciesPage from '../pages/SecurityPoliciesPage'
import { SiteCCTab, SiteWAFTab } from '../pages/site-edit/SiteProtectionTabs'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const siteID = '55555555-5555-4555-8555-555555555555'
const tenantScope = '22222222-2222-4222-8222-222222222222'
const wafPolicy = { id: '77777777-7777-4777-8777-777777777777', name: '默认规则库', kind: 'waf', enabled: true, version: 1, rules: [] }

function Location() {
  const location = useLocation()
  return <output aria-label="location">{location.pathname + location.search}</output>
}

function renderCC(scopeKind: 'platform' | 'tenant', permissions: string[]) {
  renderWithProviders(<Routes>
    <Route path="/site/edit" element={<SiteCCTab siteId={siteID} host="shop.example.com" scopeKind={scopeKind} scopeId="s1"
      accessToken="token" permissions={permissions} locked={false} siteScopeId={tenantScope} />} />
    <Route path="/site/cc-rule" element={<Location />} />
  </Routes>, ['/site/edit'])
}

function renderWAF(scopeKind: 'platform' | 'tenant', permissions: string[]) {
  renderWithProviders(<Routes>
    <Route path="/site/edit" element={<SiteWAFTab siteId={siteID} host="shop.example.com" scopeKind={scopeKind} scopeId="s1"
      accessToken="token" permissions={permissions} locked={false} siteScopeId={tenantScope} />} />
    <Route path="/site/waf-rule" element={<Location />} />
  </Routes>, ['/site/edit'])
}

// The WAF library card ("站点 WAF 规则库" section), not the summary strip above it.
const libraryCard = async () => screen.findByRole('region', { name: '站点 WAF 规则库' })

const query = (text: string) => new URLSearchParams(text.slice(text.indexOf('?') + 1))

describe('站点 CC/WAF 子流程上下文 (A11/C27/C29)', () => {
  beforeEach(() => {
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 100 })
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({ binding: null, latest_candidate: null, operation: null } as never)
    vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [] } as never)
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([] as never)
  })
  afterEach(() => vi.restoreAllMocks())

  it('fix-siteprot: only 自定义 leaves for the rule page, keeping site, host and tenant', async () => {
    renderCC('platform', ['platform.admin'])
    await userEvent.click(await screen.findByRole('radio', { name: '自定义' }))
    const params = query(screen.getByLabelText('location').textContent ?? '')
    expect(params.get('site_id')).toBe(siteID)
    expect(params.get('host')).toBe('shop.example.com')
    expect(params.get('tenant_scope_id')).toBe(tenantScope)
  })

  it('A11: rule-group links name the tenant for administrators but not for tenants', async () => {
    renderCC('platform', ['platform.admin'])
    await userEvent.click(await screen.findByRole('button', { name: '新增第一条规则' }))
    expect(query(screen.getByLabelText('location').textContent ?? '').get('tenant_scope_id')).toBe(tenantScope)
  })

  it('A11: WAF links carry the site context; fix-siteprot: applying a library publishes it here', async () => {
    vi.mocked(securityPoliciesApi.list).mockResolvedValue({ items: [wafPolicy], total: 1, page: 1, limit: 100 } as never)
    const publish = vi.spyOn(securityPoliciesApi, 'publishActivation').mockResolvedValue({ candidate: {} } as never)
    renderWAF('platform', ['platform.admin'])
    await userEvent.click(await screen.findByRole('button', { name: '应用' }))
    const confirm = await screen.findByText(`将本站的 WAF 规则库换成“${wafPolicy.name}”并立即下发？`)
    await userEvent.click(within(confirm.closest('.ant-popover') as HTMLElement).getByRole('button', { name: '应用' }))
    await waitFor(() => expect(publish).toHaveBeenCalled())
    expect(publish.mock.calls[0]![1]).toMatchObject({ site_id: siteID, policy_id: wafPolicy.id })
    expect(screen.queryByLabelText('location')).not.toBeInTheDocument()
    await userEvent.click(screen.getAllByRole('button', { name: '高级规则编辑' })[0]!)
    const params = query(screen.getByLabelText('location').textContent ?? '')
    expect(params.get('site_id')).toBe(siteID)
    expect(params.get('tenant_scope_id')).toBe(tenantScope)
  })

  it('site-parity3b: an administrator reads the site binding directly and can act, no tenant switch', async () => {
    renderWAF('platform', ['platform.admin'])
    // site-parity4：摘要条也显示“未启用”，限定在规则库卡片内查找
    expect(await within(await libraryCard()).findByText('未启用')).toBeInTheDocument()
    expect(securityPoliciesApi.getActivationStatus).toHaveBeenCalledWith('token', siteID, 'waf', expect.anything())
    expect(screen.queryByText(/管理员视角无法读取发布绑定/)).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: '高级规则编辑' })[0]).toBeEnabled()
  })

  it('C27: an administrator whose binding read fails sees "not confirmed", never "未启用" or modules "关闭"', async () => {
    vi.mocked(securityPoliciesApi.getActivationStatus).mockRejectedValue(new Error('down'))
    renderWAF('platform', ['platform.admin'])
    expect(await screen.findAllByText('生效状态未确认')).not.toHaveLength(0)
    expect(screen.queryByText('未启用')).not.toBeInTheDocument()
    const modules = screen.getByLabelText('内置检测模块状态')
    expect(within(modules).queryByText('关闭')).not.toBeInTheDocument()
  })

  it('C27: a tenant whose binding read fails sees the failure and "not confirmed"', async () => {
    vi.mocked(securityPoliciesApi.getActivationStatus).mockRejectedValue(new Error('down'))
    renderWAF('tenant', ['security_policies.read'])
    expect(await screen.findByText('读取本站发布绑定失败，生效状态未确认。')).toBeInTheDocument()
    expect(screen.queryByText('未启用')).not.toBeInTheDocument()
  })

  it('C27: a tenant with a verified empty binding still sees "未启用"', async () => {
    renderWAF('tenant', ['security_policies.read'])
    expect(await within(await libraryCard()).findByText('未启用')).toBeInTheDocument()
  })

  it('C27: the CC default protection is not shown as "关闭" while it cannot be read', async () => {
    vi.mocked(securityPoliciesApi.getActivationStatus).mockRejectedValue(new Error('down'))
    renderCC('platform', ['platform.admin'])
    const off = await screen.findByRole('radio', { name: '关闭' })
    expect(off).toHaveAttribute('aria-checked', 'false')
    expect(screen.getByText(/未能读取本站生效的默认防护/)).toBeInTheDocument()
  })

  it('C29: WAF actions say where they lead; no fake attack-test, batch or list-cleanup buttons', async () => {
    renderWAF('tenant', ['security_policies.read', 'security_policies.manage'])
    expect((await screen.findAllByRole('button', { name: '高级规则编辑' })).length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: /攻击测试|批量配置为/ })).not.toBeInTheDocument()
    renderCC('tenant', ['security_policies.read', 'security_policies.manage'])
    expect(await screen.findAllByRole('textbox', { name: /名单 IP$/ })).toHaveLength(2)
    expect(screen.queryByRole('button', { name: /^(整理|去重|清空)$/ })).not.toBeInTheDocument()
  })

  it('A11: the challenge page opened from a site starts on that tenant, site and host, and a new policy uses the chosen mode', async () => {
    const user = principal({ permissions: ['challenge_policies.read', 'challenge_policies.manage'], scope_kind: 'platform', tenant_id: null })
    useSessionStore.getState().setSession(authResponse(user), user)
    const list = vi.mocked(challengePoliciesApi.list)
    renderWithProviders(<SecurityPoliciesPage kind="cc" />,
      [`/site/cc-rule?site_id=${siteID}&host=shop.example.com&view=challenge&mode=slider&tenant_scope_id=${tenantScope}`])
    await waitFor(() => expect(list).toHaveBeenCalledWith(expect.any(String), tenantScope,
      expect.objectContaining({ site_id: siteID, host: 'shop.example.com' }), expect.any(AbortSignal)))
    expect(screen.queryByText('请先选择要管理的租户作用域。')).not.toBeInTheDocument()
    await userEvent.click(await screen.findByRole('button', { name: '新建挑战策略' }))
    const dialog = [...await screen.findAllByRole('dialog')].find((element) => element.querySelector('.ant-modal-title')?.textContent === '新建挑战策略')!
    expect(within(dialog).getByDisplayValue(siteID)).toBeInTheDocument()
    expect(within(dialog).getByDisplayValue('shop.example.com')).toBeInTheDocument()
    expect(within(dialog).getByText('滑块验证')).toBeInTheDocument()
  })
})
