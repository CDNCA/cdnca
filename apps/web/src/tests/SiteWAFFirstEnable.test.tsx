import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'
import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import { challengePoliciesApi } from '../api/challengePolicies'
import { firewallActionApi } from '../api/firewallAction'
import { rulePacksApi } from '../api/rulePacks'
import { securityPoliciesApi, type SecurityPolicy } from '../api/securityPolicies'
import { securitySystemRulesApi } from '../api/securitySystemRules'
import { SiteWAFTab } from '../pages/site-edit/SiteProtectionTabs'
import { renderWithProviders } from '../test/render'

// CU-SITE-04（Codex 双角色审测 10-27）：WAF 首次启用继承有效系统默认、只应用显式修改；系统默认无规则时
// 不发必败请求并给引导；首次发布被拒不吞错、不承诺自动重试，可原位重新下发；新增放行规则带上本站规则库与 allow 意图。

const siteID = '55555555-5555-4555-8555-555555555555'
const tenantScope = '22222222-2222-4222-8222-222222222222'
const ownerID = '33333333-3333-4333-8333-333333333333'
const sqliRule = { name: 'SQL注入 · 请求体检测', priority: 1, enabled: true, conditions: [{ field: 'path' as const, operator: 'prefix', values: ['/'] }],
  action: 'block' as const, flow: 'stop' as const, action_config: {} }
const xssRule = { ...sqliRule, name: 'XSS · 参数检测' }
const unbound = { binding: null, latest_candidate: null, operation: null }
const created = (input: Partial<SecurityPolicy>): SecurityPolicy => ({ id: 'w-new', scope_id: tenantScope, kind: 'waf', name: '', description: '', enabled: true,
  default_action: 'allow', rules: [], version: 1, created_at: '', updated_at: '', ...input })

function Location() {
  const location = useLocation()
  return <output aria-label="location">{location.pathname + location.search}</output>
}

function render(scopeKind: 'platform' | 'tenant' = 'tenant') {
  renderWithProviders(<Routes>
    <Route path="/site/edit" element={<SiteWAFTab siteId={siteID} host="shop.example.com" scopeKind={scopeKind} scopeId={scopeKind === 'tenant' ? tenantScope : 'p1'}
      accessToken="token" permissions={['security_policies.read', 'security_policies.manage']} locked={false} siteScopeId={tenantScope} siteOwnerId={ownerID} />} />
    <Route path="/site/*" element={<Location />} />
  </Routes>, ['/site/edit'])
}

describe('CU-SITE-04 WAF 首次启用与发布反馈', () => {
  beforeEach(() => {
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 100 })
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue(unbound as never)
    vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [] } as never)
    vi.spyOn(firewallActionApi, 'get').mockResolvedValue(null as never)
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([
      { system_key: 'waf_set:sqli', kind: 'waf_rule_set', legacy_id: '', name: 'SQL注入', description: '', sort: 1, revision: 1, status: 'active', selectable: true, enabled: true, updated_at: '', body: {} },
      { system_key: 'waf_set:xss', kind: 'waf_rule_set', legacy_id: '', name: 'XSS', description: '', sort: 2, revision: 1, status: 'active', selectable: true, enabled: true, updated_at: '', body: {} },
    ] as never)
    vi.spyOn(securityPoliciesApi, 'getSiteCRS').mockRejectedValue(new Error('n/a'))
    vi.spyOn(securityPoliciesApi, 'listCRSProfiles').mockResolvedValue({ items: [] })
    vi.spyOn(rulePacksApi, 'view').mockResolvedValue({ level: { level: 'site', object_id: siteID }, overrides: [], packs: [] } as never)
    vi.spyOn(securityPoliciesApi, 'catalogRules').mockImplementation(async (_token, _kind, keys) => (keys[0] === '@system-default'
      ? { rules: [sqliRule], default: { enabled: true, rules: [sqliRule] } }
      : keys[0] === 'waf_set:xss' ? { rules: [xssRule] } : { rules: [sqliRule] }) as never)
    vi.spyOn(securityPoliciesApi, 'create').mockImplementation(async (_token, input) => created(input))
    vi.spyOn(securityPoliciesApi, 'update').mockImplementation(async (_token, id, version, input) => created({ ...input, id, version: version + 1 }))
    vi.spyOn(securityPoliciesApi, 'publishActivation').mockResolvedValue({ candidate: {} } as never)
  })
  afterEach(() => vi.restoreAllMocks())

  async function switchOn() {
    const card = await screen.findByRole('region', { name: '站点 WAF 规则库' })
    const toggle = within(card).getByRole('switch', { name: '站点 WAF 规则库' })
    await waitFor(() => expect(toggle).not.toBeDisabled())
    await userEvent.click(toggle)
  }

  it('the first switch-on keeps the system default\'s rules (unbound modules are no choice to remove them)', async () => {
    render()
    await switchOn()
    await waitFor(() => expect(securityPoliciesApi.create).toHaveBeenCalled())
    expect(vi.mocked(securityPoliciesApi.create).mock.calls[0]![1].rules.map((rule) => rule.name)).toEqual(['SQL注入 · 请求体检测'])
    await waitFor(() => expect(securityPoliciesApi.publishActivation).toHaveBeenCalled())
  })

  it('with no default rule nothing is sent; the switch stays off and the next step is shown (tenant / administrator)', async () => {
    vi.mocked(securityPoliciesApi.catalogRules).mockResolvedValue({ rules: [], default: { enabled: false, rules: [] } } as never)
    render()
    await switchOn()
    expect(await screen.findByText('尚未配置默认 WAF 规则，本站 WAF 未开启。')).toBeInTheDocument()
    expect(screen.getByText(/联系管理员配置默认 WAF 规则/)).toBeInTheDocument()
    expect(securityPoliciesApi.create).not.toHaveBeenCalled()
    expect(securityPoliciesApi.publishActivation).not.toHaveBeenCalled()
    expect(screen.getByRole('switch', { name: '站点 WAF 规则库' })).not.toBeChecked()
  })

  it('a refused first publish shows the reason, promises no automatic retry and publishes the saved library again', async () => {
    vi.mocked(securityPoliciesApi.publishActivation)
      .mockRejectedValueOnce(new ApiError('forbidden', 403, 'package_feature_denied', 'req-waf-1'))
      .mockResolvedValueOnce({ candidate: {} } as never)
    render()
    await switchOn()
    const status = await screen.findByText(/已保存到规则库，但未生效/)
    const alert = status.closest('[role="status"]') as HTMLElement
    expect(within(alert).getByText(/当前套餐未开通该防护功能/)).toBeInTheDocument()
    expect(within(alert).getByText(/req-waf-1/)).toBeInTheDocument()
    expect(screen.queryByText(/自动重试/)).not.toBeInTheDocument()
    expect(screen.queryByText('操作成功')).not.toBeInTheDocument()
    await userEvent.click(within(alert).getByRole('button', { name: '重新下发' }))
    await waitFor(() => expect(securityPoliciesApi.publishActivation).toHaveBeenCalledTimes(2))
    expect(vi.mocked(securityPoliciesApi.publishActivation).mock.calls[1]![1]).toMatchObject({ site_id: siteID, policy_id: 'w-new', policy_version: 1 })
    expect(securityPoliciesApi.create).toHaveBeenCalledTimes(1)
  })

  // fix-secflow SF-SECURITY-ENTRY-01：本站 WAF 标签有“访问控制 (ACL)”与“URL 鉴权”的自然入口，带本站上下文，按各自权限显示。
  it('links the site\'s ACL and URL authentication pages with the site context, by permission', async () => {
    renderWithProviders(<Routes>
      <Route path="/site/edit" element={<SiteWAFTab siteId={siteID} host="shop.example.com" scopeKind="tenant" scopeId={tenantScope}
        accessToken="token" permissions={['security_policies.read', 'security_policies.manage', 'url_auth_policies.read']} locked={false} siteScopeId={tenantScope} siteOwnerId={ownerID} />} />
      <Route path="/site/*" element={<Location />} />
    </Routes>, ['/site/edit'])
    const entry = await screen.findByRole('navigation', { name: '更多访问规则' })
    await userEvent.click(within(entry).getByRole('link', { name: '访问控制 (ACL)' }))
    const params = new URLSearchParams((await screen.findByLabelText('location')).textContent!.split('?')[1])
    expect((await screen.findByLabelText('location')).textContent).toMatch(/^\/site\/acl\?/)
    expect(Object.fromEntries(params)).toEqual({ site_id: siteID, host: 'shop.example.com' })
  })

  it('hides the URL authentication link without its read permission', async () => {
    renderWithProviders(<Routes>
      <Route path="/site/edit" element={<SiteWAFTab siteId={siteID} host="shop.example.com" scopeKind="tenant" scopeId={tenantScope}
        accessToken="token" permissions={['security_policies.read']} locked={false} siteScopeId={tenantScope} siteOwnerId={ownerID} />} />
    </Routes>, ['/site/edit'])
    const entry = await screen.findByRole('navigation', { name: '更多访问规则' })
    expect(within(entry).getByRole('link', { name: '访问控制 (ACL)' })).toBeInTheDocument()
    expect(within(entry).queryByRole('link', { name: 'URL 鉴权（签名链接）' })).not.toBeInTheDocument()
  })

  it('新增放行规则 opens the rule editor with the site, its library and the allow intent', async () => {
    const bound = created({ id: 'w1', version: 3, name: '本站 WAF', rules: [sqliRule] })
    vi.mocked(securityPoliciesApi.list).mockResolvedValue({ items: [bound], total: 1, page: 1, limit: 100 })
    vi.mocked(securityPoliciesApi.getActivationStatus).mockResolvedValue({ binding: { id: 'b', policy_id: 'w1', binding_revision: 7,
      active_policy_version: 3, last_claimed_policy_version: 3 }, latest_candidate: null, operation: null } as never)
    render('platform')
    await userEvent.click(await screen.findByRole('button', { name: '新增放行规则' }))
    const params = new URLSearchParams((await screen.findByLabelText('location')).textContent!.split('?')[1])
    expect(Object.fromEntries(params)).toEqual({ site_id: siteID, host: 'shop.example.com', tenant_scope_id: tenantScope,
      new_rule: 'allow', policy_id: 'w1', owner_id: ownerID })
  })
})

describe('CU-SITE-04 规则页接收新增放行规则意图', () => {
  afterEach(() => vi.restoreAllMocks())

  it('?new_rule=allow&policy_id opens that library\'s editor with an allow rule appended', async () => {
    const { default: SecurityPoliciesPage } = await import('../pages/SecurityPoliciesPage')
    const { wafRuleSubscriptionsApi } = await import('../api/wafRuleSubscriptions')
    vi.spyOn(wafRuleSubscriptionsApi, 'pendingPublications').mockResolvedValue([])
    vi.spyOn(wafRuleSubscriptionsApi, 'libraries').mockResolvedValue([] as never)
    const { useSessionStore } = await import('../auth/session')
    const { authResponse, principal } = await import('../test/fixtures')
    const actor = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const bound = created({ id: '88888888-8888-4888-8888-888888888888', version: 3, name: '本站 WAF', rules: [{ ...sqliRule, id: 'r1' }] })
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [bound], total: 1, page: 1, limit: 20 })
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue(unbound as never)
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([])
    vi.spyOn(securityPoliciesApi, 'listCRSProfiles').mockResolvedValue({ items: [] })
    renderWithProviders(<SecurityPoliciesPage kind="waf" referenceLayout />,
      [`/site/waf-rule?site_id=${siteID}&host=shop.example.com&new_rule=allow&policy_id=${bound.id}`])
    const dialog = within(await screen.findByRole('dialog', { name: '编辑安全规则集' }))
    expect(dialog.getByDisplayValue('本站 WAF')).toBeInTheDocument()
    // the library's rule and the new allow rule (动作 放行)
    await waitFor(() => expect(dialog.getAllByText('放行').length).toBeGreaterThan(0))
    expect(dialog.getByDisplayValue('SQL注入 · 请求体检测')).toBeInTheDocument()
  })

  // fix-secflow D1（Codex 安全防护审测 10-27）：放行追加在 block+stop 之后会被遮蔽，必须排在本库已有规则之前，
  // 其它规则相对顺序不变，并在编辑器内说明顺序。
  it('the appended allow rule runs before the library\'s rules (a block+stop no longer shadows it)', async () => {
    const { default: SecurityPoliciesPage } = await import('../pages/SecurityPoliciesPage')
    const { wafRuleSubscriptionsApi } = await import('../api/wafRuleSubscriptions')
    vi.spyOn(wafRuleSubscriptionsApi, 'pendingPublications').mockResolvedValue([])
    vi.spyOn(wafRuleSubscriptionsApi, 'libraries').mockResolvedValue([] as never)
    const { useSessionStore } = await import('../auth/session')
    const { authResponse, principal } = await import('../test/fixtures')
    const actor = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const bound = created({ id: '88888888-8888-4888-8888-888888888888', version: 7, name: '本站 WAF',
      rules: [{ ...sqliRule, id: 'r1', priority: 1 }, { ...xssRule, id: 'r2', priority: 5, flow: 'continue' as const, action: 'log' as const }] })
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [bound], total: 1, page: 1, limit: 20 })
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue(unbound as never)
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([])
    vi.spyOn(securityPoliciesApi, 'listCRSProfiles').mockResolvedValue({ items: [] })
    renderWithProviders(<SecurityPoliciesPage kind="waf" referenceLayout />,
      [`/site/waf-rule?site_id=${siteID}&host=shop.example.com&new_rule=allow&policy_id=${bound.id}`])
    const dialog = within(await screen.findByRole('dialog', { name: '编辑安全规则集' }))
    const first = within(await dialog.findByTestId('rule-0'))
    expect(first.getAllByText('放行').length).toBeGreaterThan(0)
    // existing distinct priorities are reused (reorderedPriorities): allow 1, then 5, 6 in the old order
    expect(first.getByLabelText('优先级')).toHaveValue('1')
    expect(within(dialog.getByTestId('rule-1')).getByDisplayValue('SQL注入 · 请求体检测')).toBeInTheDocument()
    expect(within(dialog.getByTestId('rule-1')).getByLabelText('优先级')).toHaveValue('5')
    expect(within(dialog.getByTestId('rule-2')).getByDisplayValue('XSS · 参数检测')).toBeInTheDocument()
    expect(within(dialog.getByTestId('rule-2')).getByLabelText('优先级')).toHaveValue('6')
    expect(dialog.getByText(/新增的放行规则已排在本规则库其它规则之前/)).toBeInTheDocument()
  })

  async function renderIntent(list: (input: { id?: string }) => Promise<unknown>) {
    const { default: SecurityPoliciesPage } = await import('../pages/SecurityPoliciesPage')
    const { wafRuleSubscriptionsApi } = await import('../api/wafRuleSubscriptions')
    vi.spyOn(wafRuleSubscriptionsApi, 'pendingPublications').mockResolvedValue([])
    vi.spyOn(wafRuleSubscriptionsApi, 'libraries').mockResolvedValue([] as never)
    const { useSessionStore } = await import('../auth/session')
    const { authResponse, principal } = await import('../test/fixtures')
    const actor = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(securityPoliciesApi, 'list').mockImplementation(((_token: string, input: { id?: string }) => list(input)) as never)
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue(unbound as never)
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([])
    vi.spyOn(securityPoliciesApi, 'listCRSProfiles').mockResolvedValue({ items: [] })
    renderWithProviders(<Routes>
      <Route path="/site/waf-rule" element={<SecurityPoliciesPage kind="waf" referenceLayout />} />
      <Route path="*" element={<Location />} />
    </Routes>, [`/site/waf-rule?site_id=${siteID}&host=shop.example.com&new_rule=allow&policy_id=88888888-8888-4888-8888-888888888888`])
  }
  const boundLibrary = () => created({ id: '88888888-8888-4888-8888-888888888888', version: 7, name: '本站 WAF', rules: [{ ...sqliRule, id: 'r1' }] })

  // fix-secflow D2：按 policy_id 读取目标库失败时不能退成新建、不消费意图；原地重试成功后只打开正确目标一次。
  it('a failed read of the target library opens no editor, keeps the intent and retries in place', async () => {
    let fail = true
    await renderIntent(async (input) => {
      if (input.id) {
        if (fail) throw new ApiError('unavailable', 503, 'service_unavailable', 'req-intent-1')
        return { items: [boundLibrary()], total: 1, page: 1, limit: 1 }
      }
      return { items: [boundLibrary()], total: 1, page: 1, limit: 20 }
    })
    const alert = (await screen.findByText(/未能读取本站的 WAF 规则库/)).closest('[role="alert"]') as HTMLElement
    expect(within(alert).getByText(/req-intent-1/)).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    fail = false
    await userEvent.click(within(alert).getByRole('button', { name: '重试' }))
    const dialog = within(await screen.findByRole('dialog', { name: '编辑安全规则集' }))
    expect(dialog.getByDisplayValue('本站 WAF')).toBeInTheDocument()
    expect(screen.queryByText(/未能读取本站的 WAF 规则库/)).not.toBeInTheDocument()
  })

  // fix-secflow D3：从本站发起的放行，取消后回到该网站的 WAF 标签。
  it('cancelling the site\'s allow rule returns to the site\'s WAF tab', async () => {
    await renderIntent(async (input) => ({ items: [boundLibrary()], total: 1, page: 1, limit: input.id ? 1 : 20 }))
    const dialog = await screen.findByRole('dialog', { name: '编辑安全规则集' })
    await userEvent.click(within(dialog).getByRole('button', { name: /取\s*消/ }))
    expect(await screen.findByLabelText('location')).toHaveTextContent(`/site/${siteID}/edit?tab=waf`)
  })
})
