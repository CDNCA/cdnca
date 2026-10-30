import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import { openrestySecurityApi } from '../api/openrestySecurity'
import { securityPoliciesApi } from '../api/securityPolicies'
import { securitySystemRulesApi, type SystemRule } from '../api/securitySystemRules'
import { listTenantScopes } from '../api/tenantScopes'
import { useSessionStore } from '../auth/session'
import SecurityPoliciesPage from '../pages/SecurityPoliciesPage'
import { SystemRuleCatalogSection } from '../pages/security/SystemRuleCatalogTable'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

vi.mock('../api/tenantScopes', () => ({ listTenantScopes: vi.fn().mockResolvedValue([]) }))

// CCWAF-09: the catalog is folded by default; ?system_rules=open opens it.
const opened = ['/?system_rules=open']

function rule(overrides: Partial<SystemRule>): SystemRule {
  return {
    system_key: 'cc_rule:1', kind: 'cc_rule_group', legacy_id: '1', name: 'JS验证', description: '', sort: 3, revision: 1,
    body: {}, status: 'active', selectable: true, enabled: true, updated_at: '2026-10-13T00:00:00Z', ...overrides,
  }
}

const group = rule({ body: { cc_rule_group: { entries: [{ matcher_key: 'cc_matcher:3', filter1_key: 'cc_filter:1', filter2_key: '', action: 'block', mode: 'break', enabled: true }] } } })
const withdrawn = rule({ system_key: 'cc_rule:10003', legacy_id: '10003', name: '旋转图片', sort: 8, status: 'withdrawn', selectable: false, enabled: false,
  body: { cc_rule_group: { entries: [] } } })
const matcher = rule({ system_key: 'cc_matcher:3', kind: 'cc_matcher', legacy_id: '3', name: '匹配所有资源', body: { cc_matcher: { conditions: [] } } })
const filter = rule({ system_key: 'cc_filter:1', kind: 'cc_filter', legacy_id: '1', name: 'JS验证过滤器',
  body: { cc_filter: { type: 'browser_verify_auto', within_second: 60, max_req: 5, max_req_per_uri: 0, extra: {} } } })

function mockCatalog() {
  return vi.spyOn(securitySystemRulesApi, 'list').mockImplementation((_token, kind) => Promise.resolve(
    kind === 'cc_rule_group' ? [withdrawn, group] : kind === 'cc_matcher' ? [matcher] : kind === 'cc_filter' ? [filter] : []))
}

describe('SystemRuleCatalogSection', () => {
  afterEach(() => vi.restoreAllMocks())

  it('renders rule groups as a two-level table with read-only entries resolved by key', async () => {
    mockCatalog()
    const user = userEvent.setup()
    renderWithProviders(<SystemRuleCatalogSection accessToken="t" kind="cc_rule_group" cacheKey="s:1" isAdmin={false} canManage />, opened)
    const groupRow = (await screen.findByText('JS验证')).closest('tr')!
    expect(within(groupRow).getByText('系统规则 · 排序 3')).toBeInTheDocument()
    await user.click(within(groupRow).getByRole('button', { name: /展开|expand/i }))
    expect(await screen.findByText('匹配所有资源')).toBeInTheDocument()
    expect(screen.getByText('JS验证过滤器')).toBeInTheDocument()
    expect(screen.getByText('拉黑')).toBeInTheDocument()
    expect(screen.getByText('停止匹配')).toBeInTheDocument()
    // Sorted by catalog sort: the active group (3) comes before the withdrawn one (8).
    const names = screen.getAllByRole('row').map((row) => row.textContent ?? '')
    expect(names.findIndex((text) => text.includes('JS验证')) < names.findIndex((text) => text.includes('旋转图片'))).toBe(true)
  })

  it('lets tenants only switch rules, and blocks newly enabling a withdrawn rule', async () => {
    mockCatalog()
    const setEnabled = vi.spyOn(securitySystemRulesApi, 'setEnabled').mockResolvedValue({ ...group, enabled: false })
    const user = userEvent.setup()
    renderWithProviders(<SystemRuleCatalogSection accessToken="t" kind="cc_rule_group" cacheKey="s:2" isAdmin={false} canManage />, opened)
    const withdrawnRow = (await screen.findByText('旋转图片')).closest('tr')!
    expect(within(withdrawnRow).getByText('已下线')).toBeInTheDocument()
    expect(within(withdrawnRow).getByRole('switch')).toBeDisabled()
    expect(screen.queryByRole('button', { name: /编辑|删除|管理/ })).not.toBeInTheDocument()
    await user.click(within(screen.getByText('JS验证').closest('tr')!).getByRole('switch'))
    await waitFor(() => expect(setEnabled).toHaveBeenCalledWith('t', 'cc_rule:1', false))
  })

  it('hides the block for tenants when nothing is delivered, but shows platform admins the empty state', async () => {
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([])
    const view = renderWithProviders(<SystemRuleCatalogSection accessToken="t" kind="waf_rule_set" cacheKey="s:3" isAdmin={false} canManage />)
    await waitFor(() => expect(securitySystemRulesApi.list).toHaveBeenCalled())
    expect(screen.queryByText('暂未同步到系统规则')).not.toBeInTheDocument()
    view.unmount()
    renderWithProviders(<SystemRuleCatalogSection accessToken="t" kind="waf_rule_set" cacheKey="s:4" isAdmin canManage />)
    expect(await screen.findByText('暂未同步到系统规则')).toBeInTheDocument()
    // Notice tells admins built-in rules only log first and where to switch to block.
    expect(screen.getByText(/编码变形的攻击/)).toBeInTheDocument()
    expect(screen.queryByRole('switch', { name: /启用/ })).not.toBeInTheDocument()
  })

  // fix-secflow SEC-ACCOUNT-03：系统目录读取失败不能当作空数据整块消失；保留区域、说明原因并可原地重试（两种角色）。
  it('keeps the block with the reason and an in-place retry when the catalog cannot be read', async () => {
    for (const [isAdmin, cacheKey] of [[false, 's:err1'], [true, 's:err2']] as const) {
      const list = vi.spyOn(securitySystemRulesApi, 'list')
        .mockRejectedValueOnce(new ApiError('unavailable', 503, 'service_unavailable', 'req-cat-1'))
        .mockResolvedValue([])
      const view = renderWithProviders(<SystemRuleCatalogSection accessToken="t" kind="waf_rule_set" cacheKey={cacheKey} isAdmin={isAdmin} canManage />)
      const alert = (await screen.findByText(/系统规则暂时读取失败/)).closest('[role="alert"]') as HTMLElement
      const region = screen.getByRole('region', { name: '系统规则' })
      expect(region).toContainElement(alert)
      expect(within(alert).getByText(/req-cat-1/)).toBeInTheDocument()
      expect(within(region).queryByText('暂未同步到系统规则')).not.toBeInTheDocument()
      await userEvent.click(within(alert).getByRole('button', { name: '重试' }))
      await waitFor(() => expect(list.mock.calls.length).toBeGreaterThanOrEqual(2))
      await waitFor(() => expect(screen.queryByText(/系统规则暂时读取失败/)).not.toBeInTheDocument())
      view.unmount()
      list.mockRestore()
    }
  })

  it('replaces the legacy per-tenant system copies on the CC page once the catalog has synced', async () => {
    const user = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    mockCatalog()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [{
      id: '33333333-3333-4333-8333-333333333333', scope_id: user.scope_id, kind: 'cc', name: '我的登录保护', description: '', enabled: true,
      default_action: 'allow', version: 1, created_at: '2026-10-13T00:00:00Z', updated_at: '2026-10-13T00:00:00Z', rules: [],
    }], total: 1, page: 1, limit: 10 })
    vi.spyOn(openrestySecurityApi, 'listRuleGroups').mockResolvedValue([{ id: 'legacy', system_rule_key: 'cc.legacy', system_rule_id: '9', name: '旧系统组', enabled: true, kind: 'system', system_rule: true, sort: 1 }])
    renderWithProviders(<SecurityPoliciesPage kind="cc" referenceLayout />, ['/site/cc-rule?system_rules=open'])
    expect(await screen.findByText('JS验证')).toBeInTheDocument()
    expect(await screen.findByText('我的登录保护')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('旧系统组')).not.toBeInTheDocument())
  })

  // CCWAF-09（fix-tails1028b）：目录默认收起，标题条给条数与展开按钮；展开状态在 URL（刷新/深链保持）。
  it('folds the catalog by default and opens it from the title bar, keeping the state in the URL', async () => {
    mockCatalog()
    const user = userEvent.setup()
    const view = renderWithProviders(<SystemRuleCatalogSection accessToken="t" kind="cc_rule_group" cacheKey="f:1" isAdmin={false} canManage />)
    const region = await screen.findByRole('region', { name: '系统规则' })
    expect(await within(region).findByText(/系统规则 2 条/)).toBeInTheDocument()
    expect(within(region).queryByText('JS验证')).not.toBeInTheDocument()
    expect(within(region).queryByRole('table')).not.toBeInTheDocument()
    const toggle = within(region).getByRole('button', { name: '展开系统规则' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    await user.click(toggle)
    expect(await within(region).findByText('JS验证')).toBeInTheDocument()
    expect(within(region).getByRole('button', { name: '收起系统规则' })).toHaveAttribute('aria-expanded', 'true')
    await user.click(within(region).getByRole('button', { name: '收起系统规则' }))
    expect(within(region).queryByText('JS验证')).not.toBeInTheDocument()
    view.unmount()
    renderWithProviders(<SystemRuleCatalogSection accessToken="t" kind="cc_rule_group" cacheKey="f:2" isAdmin={false} canManage />, opened)
    expect(await screen.findByText('JS验证')).toBeInTheDocument()
  })

  // CCWAF-09：效果列只留一行白话，不再同格重复技术摘要；技术摘要在行展开里。
  it('shows one plain-language line per rule and keeps the technical summary in the expanded row', async () => {
    const rate = rule({ system_key: 'cc_rule:6', legacy_id: '6', name: '频率限制', sort: 1,
      body: { cc_filter: { type: 'req_rate', within_second: 5, max_req: 300, max_req_per_uri: 50, extra: {}, params: { ban_seconds: 360 } } } as never })
    vi.spyOn(securitySystemRulesApi, 'list').mockImplementation((_token, kind) => Promise.resolve(kind === 'cc_rule_group' ? [rate] : []))
    const user = userEvent.setup()
    renderWithProviders(<SystemRuleCatalogSection accessToken="t" kind="cc_rule_group" cacheKey="f:3" isAdmin={false} canManage />, opened)
    const row = (await screen.findByText('频率限制')).closest('tr')!
    const effect = row.querySelector('.system-rule-effect')!
    expect(effect).toHaveTextContent('同一 IP 在 5 秒内请求超过 300 次')
    expect(effect.querySelector('small')).toBeNull()
    expect(row).not.toHaveTextContent('请求频率 · 5 秒内 300 次')
    await user.click(within(row).getByRole('button', { name: /展开|expand/i }))
    const detail = await screen.findByText('请求频率 · 5 秒内 300 次，单 URL 50 次')
    expect(detail.closest('.system-rule-detail')).not.toBeNull()
  })

  // CCWAF-09：本地分页（每页 10 条）+ 按名称/ID 搜索。
  it('pages the catalog locally and filters it by name or ID', async () => {
    const many = Array.from({ length: 12 }, (_, index) => rule({ system_key: `waf_set:r${index + 1}`, kind: 'waf_rule_set', legacy_id: String(100 + index),
      name: `规则${index + 1}`, sort: index + 1, body: { waf_rule_set: { rules: [] } } as never }))
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue(many)
    const user = userEvent.setup()
    renderWithProviders(<SystemRuleCatalogSection accessToken="t" kind="waf_rule_set" cacheKey="f:4" isAdmin={false} canManage />, opened)
    expect(await screen.findByText('规则1')).toBeInTheDocument()
    expect(screen.queryByText('规则11')).not.toBeInTheDocument()
    expect(document.querySelector('.system-rule-catalog .ant-pagination')).not.toBeNull()
    const search = screen.getByRole('searchbox', { name: '搜索系统规则' })
    await user.type(search, '规则11')
    expect(await screen.findByText('规则11')).toBeInTheDocument()
    expect(screen.queryByText('规则1')).not.toBeInTheDocument()
    await user.clear(search)
    await user.type(search, '103')
    expect(await screen.findByText('规则4')).toBeInTheDocument()
    expect(screen.queryByText('规则2')).not.toBeInTheDocument()
    await user.clear(search)
    await user.type(search, '没有这条')
    expect(await screen.findByText('没有匹配的系统规则')).toBeInTheDocument()
  })

  // 顺带：管理员「仅对以下用户显示」按名称搜索选用户，已选显示名称，提交仍为作用域 ID。
  it('lets admins pick show-to users by name while still submitting scope IDs', async () => {
    const known = '11111111-1111-4111-8111-111111111111'
    const picked = '22222222-2222-4222-8222-222222222222'
    const shown = rule({ system_key: 'waf_set:sqli', kind: 'waf_rule_set', legacy_id: '1', name: 'SQL 注入', body: { waf_rule_set: { rules: [] } } as never,
      visibility: { visible: true, show_to_scope_ids: [known], revision: 1 } })
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([shown])
    const scopes = vi.mocked(listTenantScopes).mockImplementation(async (_token, params = {}) => [
      { scope_id: known, tenant_id: 't1', tenant_name: '甲公司', status: 'active', display_id: '1001' },
      ...(params.search ? [{ scope_id: picked, tenant_id: 't2', tenant_name: '乙公司', status: 'active', display_id: '1002' }] : []),
    ])
    const setVisibility = vi.spyOn(securitySystemRulesApi, 'setVisibility').mockResolvedValue(shown)
    const user = userEvent.setup()
    renderWithProviders(<SystemRuleCatalogSection accessToken="t" kind="waf_rule_set" cacheKey="f:5" isAdmin canManage />, opened)
    const select = await screen.findByRole('combobox', { name: '仅对以下用户显示 SQL 注入' })
    const cell = select.closest('.ant-select')!
    expect(await within(cell as HTMLElement).findByText('甲公司（1001）')).toBeInTheDocument()
    expect(cell).not.toHaveTextContent(known)
    await user.type(select, '乙')
    await waitFor(() => expect(scopes).toHaveBeenCalledWith('t', expect.objectContaining({ search: '乙' })))
    await user.click(await screen.findByTitle('乙公司（1002）'))
    await waitFor(() => expect(setVisibility).toHaveBeenCalledWith('t', 'waf_set:sqli', true, [known, picked]))
  })
})

describe('plain-language rule effect', () => {
  // fix-secflow SF-CC-EFFECT-01：超频转验证（filter1 频率 + filter2 验证）与节点执行一致：超频才验证，连续失败才临时封禁，
  // 不能说成超频即拉黑；组合不合法时明说无法说明。
  it('explains a rate-then-challenge pair as the node runs it (rate only triggers the challenge)', async () => {
    const { explainRule } = await import('../pages/security/ruleExplain')
    const filters: Record<string, object> = {
      'cc_matcher:3': { cc_matcher: { conditions: [] } },
      'cc_filter:rate': { cc_filter: { type: 'req_rate', within_second: 5, max_req: 100, max_req_per_uri: 0, params: { ban_seconds: 360 } } },
      'cc_filter:js': { cc_filter: { type: 'browser_verify_auto', within_second: 60, max_req: 5, max_req_per_uri: 0,
        params: { ban_seconds: 360, pass_seconds: 3600 } } },
    }
    const group = { cc_rule_group: { entries: [{ matcher_key: 'cc_matcher:3', filter1_key: 'cc_filter:rate', filter2_key: 'cc_filter:js', action: 'block', enabled: true }] } }
    const text = explainRule('cc_rule:rate_then_js', group, (key) => filters[key])
    expect(text).toContain('同一 IP 在 5 秒内请求超过 100 次后')
    expect(text).toContain('JS 验证')
    expect(text).toContain('60 秒内超过 5 次没通过验证时，该 IP 被拉黑 360 秒')
    expect(text).not.toMatch(/超过 100 次[^后]*拉黑/)
    // filter2 that is itself a rate filter (the backend refuses the pair): no guess.
    filters['cc_filter:js'] = filters['cc_filter:rate']
    expect(explainRule('cc_rule:rate_then_js', group, (key) => filters[key])).toContain('无法说明')
  })

  it('explains when a catalog rule triggers and what happens, from the catalog values', async () => {
    const { explainRule } = await import('../pages/security/ruleExplain')
    const params = { ban_seconds: 360, pass_seconds: 21600, pow_bits: 18, delay_seconds: 5, bind_ipv4_prefix: 24, bind_ipv6_prefix: 64 }
    const filters: Record<string, object> = {
      'cc_matcher:3': { cc_matcher: { conditions: [] } },
      'cc_filter:10001': { cc_filter: { type: 'delay_jump_filter', within_second: 60, max_req: 5, max_req_per_uri: 0, params } },
      'cc_filter:11': { cc_filter: { type: 'req_rate', within_second: 5, max_req: 300, max_req_per_uri: 50, params: { ban_seconds: 360 } } },
    }
    const group = { cc_rule_group: { entries: [{ matcher_key: 'cc_matcher:3', filter1_key: 'cc_filter:10001', action: 'block', enabled: true }] } }
    const text = explainRule('cc_rule:10001', group, (key) => filters[key])
    expect(text).toContain('5 秒等待页')
    expect(text).toContain('18 位 SHA-256 工作量证明')
    expect(text).toContain('6 小时内放行')
    expect(text).toContain('IPv4 /24')
    expect(text).toContain('5 秒超过 300 次或同一网址超过 50 次会要求重新验证')
    expect(text).toContain('60 秒内超过 5 次没通过验证')
    expect(text).toContain('拉黑 360 秒')
    // Changed catalog values change the text: nothing is assumed.
    filters['cc_filter:10001'] = { cc_filter: { type: 'delay_jump_filter', within_second: 30, max_req: 2, max_req_per_uri: 0,
      params: { ...params, ban_seconds: 90, pow_bits: 20, delay_seconds: 2 } } }
    const changed = explainRule('cc_rule:10001', group, (key) => filters[key])
    expect(changed).toContain('2 秒等待页')
    expect(changed).toContain('20 位')
    expect(changed).toContain('拉黑 90 秒')
    expect(changed).toContain('30 秒内超过 2 次')
    expect(explainRule('cc_rule:6', { cc_filter: { type: 'req_rate', within_second: 5, max_req: 300, max_req_per_uri: 50, params: { ban_seconds: 360 } } }, () => undefined))
      .toBe('同一 IP 在 5 秒内请求超过 300 次，或同一个网址超过 50 次时，该 IP 被拉黑 360 秒（返回 403）。')
    expect(explainRule('cc_rule:9', { cc_filter: { type: 'req_rate', within_second: 5, max_req: 300, max_req_per_uri: 0 } }, () => undefined))
      .toContain('缺少执行参数')
    expect(explainRule('cc_rule:10002', { cc_rule_group: { entries: [] } }, () => undefined)).toContain('直接放行')
    expect(explainRule('waf_set:sqli', { waf_rule_set: { engine: { action: 'block', paranoia: 1, threshold: 5 } } }, () => undefined))
      .toContain('Paranoia 1，命中规则分数之和达到 5 时拦截')
    expect(explainRule('waf_set:crs_settings', { waf_rule_set: { settings: { request_body_limit: 13107200,
      request_body_no_files_limit: 131072, request_body_limit_action: 'reject' } } }, () => undefined)).toContain('13107200 字节')
  })
})
