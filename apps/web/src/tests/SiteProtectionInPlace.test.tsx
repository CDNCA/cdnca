import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'
import { vi } from 'vitest'

import { challengePoliciesApi } from '../api/challengePolicies'
import { firewallActionApi } from '../api/firewallAction'
import { rulePacksApi } from '../api/rulePacks'
import { securityPoliciesApi, type SecurityPolicy } from '../api/securityPolicies'
import { securitySystemRulesApi } from '../api/securitySystemRules'
import { SiteCCTab, SiteWAFTab } from '../pages/site-edit/SiteProtectionTabs'
import { editCCRules, editWAFSourceRules, managedRuleNames } from '../pages/site-edit/sitePolicyEdits'
import { renderWithProviders } from '../test/render'

// 网站管理 CC/WAF 标签页就地开关、选防护等级，保存即下发，不跳规则页。

const siteID = '55555555-5555-4555-8555-555555555555'
const tenantScope = '22222222-2222-4222-8222-222222222222'
const ownerID = '33333333-3333-4333-8333-333333333333'
const ccPolicy: SecurityPolicy = { id: 'c1', scope_id: tenantScope, kind: 'cc', name: '本站 CC', description: '', enabled: true, default_action: 'allow',
  version: 4, created_at: '', updated_at: '', cc_settings: { ban_seconds: { mode: 'custom', seconds: 600 } },
  rules: [
    { id: 'u1', name: '我的规则', priority: 1, enabled: true, conditions: [{ field: 'path', operator: 'prefix', values: ['/api'] }], action: 'block', flow: 'stop', action_config: {} },
    { id: 'g1', name: '宽松 · 请求速率5-300-50', priority: 2, enabled: true, conditions: [{ field: 'path', operator: 'prefix', values: ['/'] }], action: 'rate_limit', flow: 'stop',
      action_config: { rate_limit: { window_seconds: 5, max_requests: 300 } } },
  ] }
const binding = (policyID: string, version: number) => ({ binding: { id: 'b', policy_id: policyID, binding_revision: 7, active_policy_version: version, last_claimed_policy_version: version },
  latest_candidate: null, operation: null })
const group = (key: string, name: string) => ({ system_key: key, kind: 'cc_rule_group', legacy_id: '', name, description: '', sort: 1, revision: 1, status: 'active', selectable: true,
  enabled: true, updated_at: '', body: { cc_rule_group: { entries: [] } } })
const sliderRule = { name: '滑块验证 · 滑动过滤60-5', priority: 1, enabled: true, conditions: [{ field: 'path' as const, operator: 'prefix', values: ['/'] }],
  action: 'challenge' as const, flow: 'stop' as const, action_config: { challenge: { type: 'slider' } } }

function Location() {
  const location = useLocation()
  return <output aria-label="location">{location.pathname}</output>
}

function render(tab: 'cc' | 'waf', scopeKind: 'platform' | 'tenant' = 'tenant') {
  const Tab = tab === 'cc' ? SiteCCTab : SiteWAFTab
  renderWithProviders(<Routes>
    <Route path="/site/edit" element={<Tab siteId={siteID} host="shop.example.com" scopeKind={scopeKind} scopeId={scopeKind === 'tenant' ? tenantScope : 'p1'}
      accessToken="token" permissions={['security_policies.read', 'security_policies.manage']} locked={false} siteScopeId={tenantScope} siteOwnerId={ownerID} />} />
    <Route path="/site/*" element={<Location />} />
  </Routes>, ['/site/edit'])
}

describe('站点 CC/WAF 就地修改', () => {
  beforeEach(() => {
    vi.spyOn(securityPoliciesApi, 'list').mockImplementation(async (_token, filters) =>
      ({ items: filters.kind === 'cc' ? [ccPolicy] : [], total: 1, page: 1, limit: 100 }))
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockImplementation(async (_token, _site, kind) =>
      (kind === 'cc' ? binding('c1', 4) : { binding: null, latest_candidate: null, operation: null }) as never)
    vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [] } as never)
    vi.spyOn(firewallActionApi, 'get').mockResolvedValue(null as never)
    // The attack escalation card is not under test (its failure dialog would take focus).
    vi.spyOn(securitySystemRulesApi, 'list').mockImplementation(async (_token, kind) => (kind === 'cc_rule_group'
      ? [group('cc_rule:10002', '关闭'), group('cc_rule:6', '宽松'), group('cc_rule:2', '滑块验证')]
      : [{ ...group('waf_set:sqli', 'SQL注入'), kind: 'waf_rule_set' }]) as never)
    vi.spyOn(securitySystemRulesApi, 'defaultCrawlers').mockResolvedValue([{ name: 'Baidu', members: [], categories: [], user_agent_tokens: ['Baiduspider'],
      networks: [], rdns_suffixes: ['.baidu.com'], ready: true }])
    vi.spyOn(securityPoliciesApi, 'getSiteCRS').mockRejectedValue(new Error('n/a'))
    vi.spyOn(securityPoliciesApi, 'listCRSProfiles').mockResolvedValue({ items: [] })
    const rulePack = (packID: string, name: string, layer: 'system' | 'user', enabled: boolean) => ({ pack_id: packID, layer, name, description: '',
      engine: 'waf_v2', effect: { enabled, enabled_at: { level: 'platform' }, adjustable: [], priority: 500, params: {}, rule_states: {}, rule_source: {}, ignored_overrides: 0 } })
    vi.spyOn(rulePacksApi, 'view').mockResolvedValue({ level: { level: 'site', object_id: siteID }, overrides: [], packs: [
      rulePack('system/scanner-signatures', '扫描器特征', 'system', true), rulePack('system/sqli-strict', '未启用的包', 'system', false),
      rulePack('user/x', '租户自己的包', 'user', true)] } as never)
    vi.spyOn(securityPoliciesApi, 'catalogRules').mockImplementation(async (_token, kind) => (kind === 'cc'
      ? { rules: [sliderRule] }
      : { rules: [{ ...sliderRule, name: 'SQL注入 · 语义检测', action: 'block', action_config: {} }],
        default: { enabled: true, rules: [{ ...sliderRule, name: 'SQL注入 · 语义检测', action: 'block', action_config: {} }], waf_settings: { auto_block: { window_seconds: 60, hit_threshold: 5, block_seconds: 600 } } } }) as never)
    vi.spyOn(securityPoliciesApi, 'update').mockImplementation(async (_token, id, version, input) => ({ ...ccPolicy, ...input, id, version: version + 1 }) as never)
    vi.spyOn(securityPoliciesApi, 'create').mockImplementation(async (_token, input) => ({ ...ccPolicy, ...input, id: 'w-new', version: 1 }) as never)
    vi.spyOn(securityPoliciesApi, 'publishActivation').mockResolvedValue({ candidate: {} } as never)
  })
  afterEach(() => vi.restoreAllMocks())

  it('CC: the stored default protection is the bound library\'s catalog group', async () => {
    render('cc')
    expect(await screen.findByRole('radio', { name: '宽松' })).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByText('以下设置写入本站使用的 CC 规则库：本站 CC')).toBeInTheDocument()
  })

  it('CC: choosing 滑块验证 stays on the page; saving replaces the preset rules, keeps own rules and settings, publishes to the site', async () => {
    render('cc')
    await userEvent.click(await screen.findByRole('radio', { name: '滑块验证' }))
    expect(screen.queryByLabelText('location')).not.toBeInTheDocument()
    expect(screen.getByRole('radio', { name: '滑块验证' })).toHaveAttribute('aria-checked', 'true')
    // Choosing saves at once; no save bar
    expect(screen.queryByRole('button', { name: '保存更改' })).toBeNull()
    await waitFor(() => expect(securityPoliciesApi.publishActivation).toHaveBeenCalled())
    expect(securityPoliciesApi.catalogRules).toHaveBeenCalledWith('token', 'cc', ['cc_rule:2'])
    const [, id, version, fields] = vi.mocked(securityPoliciesApi.update).mock.calls[0]!
    expect([id, version]).toEqual(['c1', 4])
    expect(fields.rules.map((rule) => [rule.name, rule.priority])).toEqual([['我的规则', 1], ['滑块验证 · 滑动过滤60-5', 2]])
    expect(fields.cc_settings).toEqual(ccPolicy.cc_settings)
    expect(vi.mocked(securityPoliciesApi.publishActivation).mock.calls[0]![1]).toMatchObject({ site_id: siteID, policy_id: 'c1', policy_version: 5,
      expected_binding_revision: 7, expected_active_policy_version: 4 })
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
  })

  it('CC: blacklist / whitelist are edited here and saved as the site\'s own IP rules', async () => {
    render('cc')
    expect(await screen.findByRole('radio', { name: '宽松' })).toHaveAttribute('aria-checked', 'true')
    const list = await screen.findByRole('textbox', { name: '黑名单 IP' })
    await waitFor(() => expect(list).not.toHaveAttribute('readonly'))
    await userEvent.type(list, '203.0.113.9 # bad')
    // typing does not save; leaving the list does
    expect(securityPoliciesApi.update).not.toHaveBeenCalled()
    fireEvent.blur(list)
    await waitFor(() => expect(securityPoliciesApi.update).toHaveBeenCalled())
    const rules = vi.mocked(securityPoliciesApi.update).mock.calls[0]![3].rules
    expect(rules.find((rule) => rule.name === managedRuleNames.blacklist)).toMatchObject({ action: 'block',
      conditions: [{ field: 'client_ip', operator: 'ip_in_cidr', values: ['203.0.113.9'] }] })
  })

  it('CC: crawler 放行 writes the platform default crawlers as the library\'s trusted crawlers', async () => {
    render('cc')
    await userEvent.click(await screen.findByRole('radio', { name: '放行' }))
    await waitFor(() => expect(securityPoliciesApi.update).toHaveBeenCalled())
    expect(vi.mocked(securityPoliciesApi.update).mock.calls[0]![3].cc_settings?.trusted_crawlers).toEqual([
      { name: 'Baidu', user_agent_tokens: ['Baiduspider'], rdns_suffixes: ['.baidu.com'] }])
  })

  it('CC: region blocking without a WAF library creates the site\'s own WAF library (administrator names tenant and owner)', async () => {
    render('cc', 'platform')
    await userEvent.click(await screen.findByRole('radio', { name: /仅屏蔽中国大陆/ }))
    await waitFor(() => expect(securityPoliciesApi.create).toHaveBeenCalled())
    const input = vi.mocked(securityPoliciesApi.create).mock.calls[0]![1]
    expect(input).toMatchObject({ kind: 'waf', target_scope_id: tenantScope, owner_id: ownerID })
    expect(input.rules).toEqual([expect.objectContaining({ name: '区域屏蔽 屏蔽境内（不含港澳台）',
      conditions: [{ field: 'country', operator: 'in', values: ['CN'] }] })])
    expect(securityPoliciesApi.update).not.toHaveBeenCalled()
  })

  it('WAF: the library switch enables the system default library for the site in place', async () => {
    render('waf')
    const card = await screen.findByRole('region', { name: '站点 WAF 规则库' })
    // The switch saves at once with the system default library (modules are switched after it)
    await userEvent.click(within(card).getByRole('switch', { name: '站点 WAF 规则库' }))
    expect(screen.queryByLabelText('location')).not.toBeInTheDocument()
    await waitFor(() => expect(securityPoliciesApi.publishActivation).toHaveBeenCalled())
    expect(securityPoliciesApi.catalogRules).toHaveBeenCalledWith('token', 'waf', ['@system-default'])
    const input = vi.mocked(securityPoliciesApi.create).mock.calls[0]![1]
    // CU-SITE-04: the default's rules are kept (an empty library is refused before sending)
    expect(input.rules.map((rule) => rule.name)).toEqual(['SQL注入 · 语义检测'])
    expect(input.waf_settings).toEqual({ auto_block: { window_seconds: 60, hit_threshold: 5, block_seconds: 600 } })
    expect(vi.mocked(securityPoliciesApi.publishActivation).mock.calls[0]![1]).toMatchObject({ policy_id: 'w-new', policy_version: 1, expected_binding_revision: 0 })
  })

  it('WAF: switching a bound library off withdraws it from the site (detach)', async () => {
    vi.mocked(securityPoliciesApi.list).mockResolvedValue({ items: [{ ...ccPolicy, id: 'w1', kind: 'waf', name: '本站 WAF', rules: [] }], total: 1, page: 1, limit: 100 })
    vi.mocked(securityPoliciesApi.getActivationStatus).mockResolvedValue(binding('w1', 3) as never)
    render('waf')
    await userEvent.click(await screen.findByRole('switch', { name: '站点 WAF 规则库' }))
    await waitFor(() => expect(securityPoliciesApi.publishActivation).toHaveBeenCalled())
    expect(vi.mocked(securityPoliciesApi.publishActivation).mock.calls[0]![1]).toMatchObject({ site_id: siteID, policy_id: 'w1', policy_version: 3, detach: true })
    expect(securityPoliciesApi.update).not.toHaveBeenCalled()
  })

  // 名单保留整理/去重/清空；保存失败回滚到服务端值。
  it('CC: 整理 / 去重 / 清空 edit the IP list and save at once', async () => {
    // the stored library follows each save (as the server does)
    let stored: SecurityPolicy = { ...ccPolicy, rules: editCCRules(ccPolicy.rules, { blacklist: ['203.0.113.9'] }) }
    vi.mocked(securityPoliciesApi.list).mockImplementation(async (_token, filters) => ({ items: filters.kind === 'cc' ? [stored] : [], total: 1, page: 1, limit: 100 }))
    vi.mocked(securityPoliciesApi.update).mockImplementation(async (_token, id, version, input) => {
      stored = { ...stored, ...input, id, version: version + 1 } as SecurityPolicy
      return stored as never
    })
    vi.mocked(securityPoliciesApi.getActivationStatus).mockImplementation(async (_token, _site, kind) =>
      (kind === 'cc' ? binding('c1', stored.version) : { binding: null, latest_candidate: null, operation: null }) as never)
    render('cc')
    const list = await screen.findByRole('textbox', { name: '黑名单 IP' })
    await waitFor(() => expect(list).toHaveValue('203.0.113.9'))
    // the buttons work on the text as typed (fireEvent keeps focus in the list, so nothing is saved before them)
    fireEvent.change(list, { target: { value: '203.0.113.9\n\n 203.0.113.9 # again\n198.51.100.1' } })
    fireEvent.click(screen.getByRole('button', { name: '去重 黑名单 IP' }))
    expect(list).toHaveValue('203.0.113.9\n\n198.51.100.1')
    fireEvent.click(screen.getByRole('button', { name: '整理 黑名单 IP' }))
    expect(list).toHaveValue('203.0.113.9\n198.51.100.1')
    await waitFor(() => expect(securityPoliciesApi.update).toHaveBeenCalled())
    const rules = vi.mocked(securityPoliciesApi.update).mock.calls.at(-1)![3].rules
    expect(rules.find((rule) => rule.name === managedRuleNames.blacklist)?.conditions[0]?.values).toEqual(['203.0.113.9', '198.51.100.1'])
    await userEvent.click(screen.getByRole('button', { name: '清空 黑名单 IP' }))
    await waitFor(() => expect(vi.mocked(securityPoliciesApi.update).mock.calls.at(-1)![3].rules.some((rule) => rule.name === managedRuleNames.blacklist)).toBe(false))
  })

  it('CC: a refused save puts the choice back to the stored value', async () => {
    vi.mocked(securityPoliciesApi.update).mockRejectedValue(new Error('refused'))
    render('cc')
    expect(await screen.findByRole('radio', { name: '宽松' })).toHaveAttribute('aria-checked', 'true')
    await userEvent.click(screen.getByRole('radio', { name: '滑块验证' }))
    await waitFor(() => expect(securityPoliciesApi.update).toHaveBeenCalled())
    await waitFor(() => expect(screen.getByRole('radio', { name: '宽松' })).toHaveAttribute('aria-checked', 'true'))
    expect(await screen.findByText(/保存失败/)).toBeInTheDocument()
  })

  describe('防御级别、自动封禁、应用规则库、设置区保存即下发', () => {
    const wafPolicy: SecurityPolicy = { ...ccPolicy, id: 'w1', kind: 'waf', name: '本站 WAF', version: 3, rules: [], cc_settings: undefined }
    beforeEach(() => {
      vi.mocked(securityPoliciesApi.list).mockImplementation(async (_token, filters) =>
        ({ items: filters.kind === 'cc' ? [ccPolicy] : [wafPolicy, { ...wafPolicy, id: 'w2', name: '电商严格' }], total: 2, page: 1, limit: 100 }))
      vi.mocked(securityPoliciesApi.getActivationStatus).mockImplementation(async (_token, _site, kind) =>
        (kind === 'cc' ? binding('c1', 4) : binding('w1', 3)) as never)
    })

    function renderWAF(permissions = ['security_policies.read', 'security_policies.manage', 'firewall.read', 'firewall.manage']) {
      renderWithProviders(<Routes>
        <Route path="/site/edit" element={<SiteWAFTab siteId={siteID} host="shop.example.com" scopeKind="tenant" scopeId={tenantScope}
          accessToken="token" permissions={permissions} locked={false} siteScopeId={tenantScope} siteOwnerId={ownerID} />} />
        <Route path="/site/*" element={<Location />} />
      </Routes>, ['/site/edit'])
    }

    it('WAF: 防御级别 (observe mode) is saved into the bound library and published', async () => {
      renderWAF()
      const level = await screen.findByRole('region', { name: '防御级别' })
      // Each choice saves at once (命中自动封禁 moved to the 自动防御 tab)
      await userEvent.click(within(level).getByRole('radio', { name: '观察（只记录不拦截）' }))
      await waitFor(() => expect(securityPoliciesApi.update).toHaveBeenCalledTimes(1))
      const [, id, version, fields] = vi.mocked(securityPoliciesApi.update).mock.calls[0]!
      expect([id, version]).toEqual(['w1', 3])
      expect(fields.waf_settings).toEqual({ mode: 'observe' })
      expect(screen.queryByLabelText('location')).not.toBeInTheDocument()
      await waitFor(() => expect(securityPoliciesApi.publishActivation).toHaveBeenCalled())
      expect(vi.mocked(securityPoliciesApi.publishActivation).mock.calls[0]![1]).toMatchObject({ site_id: siteID, policy_id: 'w1', policy_version: 4 })
    })

    // 攻击自动封禁阈值与命中自动封禁的就地修改测试随卡片移到 SiteAutoDefenseTab.test.tsx。
    it('WAF: switching the mode keeps the stored hit auto ban of the library', async () => {
      vi.mocked(securityPoliciesApi.list).mockImplementation(async (_token, filters) => ({ items: filters.kind === 'cc' ? [ccPolicy]
        : [{ ...wafPolicy, waf_settings: { auto_block: { window_seconds: 30, hit_threshold: 8, block_seconds: 900 } } }], total: 1, page: 1, limit: 100 }))
      renderWAF()
      const level = await screen.findByRole('region', { name: '防御级别' })
      await userEvent.click(within(level).getByRole('radio', { name: '观察（只记录不拦截）' }))
      await waitFor(() => expect(securityPoliciesApi.update).toHaveBeenCalled())
      expect(vi.mocked(securityPoliciesApi.update).mock.calls[0]![3].waf_settings).toEqual({ mode: 'observe',
        auto_block: { window_seconds: 30, hit_threshold: 8, block_seconds: 900 } })
    })

    it('WAF: 应用 another library publishes it to the site in place', async () => {
      renderWAF()
      const card = (await screen.findByText('电商严格')).closest('article')!
      await userEvent.click(within(card as HTMLElement).getByRole('button', { name: '应用' }))
      const confirm = await screen.findByText('将本站的 WAF 规则库换成“电商严格”并立即下发？')
      await userEvent.click(within(confirm.closest('.ant-popover') as HTMLElement).getByRole('button', { name: '应用' }))
      await waitFor(() => expect(securityPoliciesApi.publishActivation).toHaveBeenCalled())
      expect(vi.mocked(securityPoliciesApi.publishActivation).mock.calls[0]![1]).toMatchObject({ site_id: siteID, policy_id: 'w2', policy_version: 3,
        expected_binding_revision: 7, expected_active_policy_version: 3 })
      expect(screen.queryByLabelText('location')).not.toBeInTheDocument()
    })

    it('WAF: a subscribed library\'s new version is published here, not on the rules page', async () => {
      vi.mocked(securityPoliciesApi.list).mockResolvedValue({ items: [{ ...wafPolicy, protected: true, version: 5 }], total: 1, page: 1, limit: 100 })
      renderWAF()
      await userEvent.click(await screen.findByRole('button', { name: '立即下发新版本' }))
      await waitFor(() => expect(securityPoliciesApi.publishActivation).toHaveBeenCalled())
      expect(vi.mocked(securityPoliciesApi.publishActivation).mock.calls[0]![1]).toMatchObject({ site_id: siteID, policy_id: 'w1', policy_version: 5,
        expected_active_policy_version: 3 })
      expect(screen.queryByLabelText('location')).not.toBeInTheDocument()
    })

    describe('托管 WAF 防护档位 + 官方系统规则包', () => {
      const engine = { request_body_limit: 13107200, request_body_no_files_limit: 131072, request_body_limit_action: 'reject' as const,
        arguments_limit: 1000, json_depth_limit: 512, pcre_match_limit: 100000 }
      const crsRule = { name: '托管规则集 (OWASP CRS)', priority: 1, enabled: true, conditions: [], action: 'managed_waf' as const, flow: 'continue' as const,
        action_config: { managed_waf: { ...engine, profile: 'system/crs-pl1' } } }
      beforeEach(() => {
        vi.mocked(securityPoliciesApi.listCRSProfiles).mockResolvedValue({ items: [
          { pack_id: 'system/crs-pl2', version: '1', name: 'PL2', description: '', exports: [941100] },
          { pack_id: 'system/crs-pl1', version: '1', name: 'PL1', description: '', exports: [941100, 942100] },
        ] })
        vi.mocked(securityPoliciesApi.catalogRules).mockImplementation(async (_token, _kind, keys) =>
          (keys[0] === 'waf_set:crs_sqli' ? { rules: [crsRule] } : { rules: [] }) as never)
      })

      it('choosing 严格防护 appends the managed_waf rule to the bound library (rules page interface) and publishes', async () => {
        vi.mocked(securityPoliciesApi.list).mockResolvedValue({ items: [{ ...wafPolicy, rules: [{ ...sliderRule, id: 'own', name: '我的规则', action: 'block', action_config: {} }] }],
          total: 1, page: 1, limit: 100 })
        renderWAF()
        const tier = await screen.findByRole('region', { name: '托管 WAF 防护档位' })
        expect(within(tier).getByRole('radio', { name: '关闭' })).toHaveAttribute('aria-checked', 'true')
        await waitFor(() => expect(within(tier).getByRole('radio', { name: '严格防护' })).not.toBeDisabled())
        await userEvent.click(within(tier).getByRole('radio', { name: '严格防护' }))
        await waitFor(() => expect(securityPoliciesApi.publishActivation).toHaveBeenCalled())
        expect(securityPoliciesApi.catalogRules).toHaveBeenCalledWith('token', 'waf', ['waf_set:crs_sqli'])
        const [, id, version, fields] = vi.mocked(securityPoliciesApi.update).mock.calls[0]!
        expect([id, version]).toEqual(['w1', 3])
        expect(fields.rules.map((rule) => [rule.name, rule.priority, rule.action])).toEqual([['我的规则', 1, 'block'], ['托管 WAF（由网站页设置）', 2, 'managed_waf']])
        expect(fields.rules[1]).toMatchObject({ flow: 'continue', conditions: [], action_config: { managed_waf: { ...engine, profile: 'system/crs-pl2' } } })
        expect(screen.queryByLabelText('location')).not.toBeInTheDocument()
      })

      it('the rules page\'s managed_waf rule shows as the current tier; 关闭 removes it', async () => {
        vi.mocked(securityPoliciesApi.list).mockResolvedValue({ items: [{ ...wafPolicy, rules: [{ ...crsRule, id: 'm1', action_config: { managed_waf: { ...engine, profile: 'system/crs-pl2', exclusions: [941100] } } }] }],
          total: 1, page: 1, limit: 100 })
        renderWAF()
        const tier = await screen.findByRole('region', { name: '托管 WAF 防护档位' })
        await waitFor(() => expect(within(tier).getByRole('radio', { name: '严格防护' })).toHaveAttribute('aria-checked', 'true'))
        await userEvent.click(within(tier).getByRole('radio', { name: '关闭' }))
        await waitFor(() => expect(securityPoliciesApi.update).toHaveBeenCalled())
        expect(vi.mocked(securityPoliciesApi.update).mock.calls[0]![3].rules).toEqual([])
      })

      it('without a bound library the tier creates the system default library with the managed_waf rule', async () => {
        vi.mocked(securityPoliciesApi.list).mockResolvedValue({ items: [], total: 0, page: 1, limit: 100 })
        vi.mocked(securityPoliciesApi.getActivationStatus).mockResolvedValue({ binding: null, latest_candidate: null, operation: null } as never)
        renderWAF()
        const tier = await screen.findByRole('region', { name: '托管 WAF 防护档位' })
        await waitFor(() => expect(within(tier).getByRole('radio', { name: '标准防护' })).not.toBeDisabled())
        await userEvent.click(within(tier).getByRole('radio', { name: '标准防护' }))
        await waitFor(() => expect(securityPoliciesApi.create).toHaveBeenCalled())
        expect(securityPoliciesApi.catalogRules).toHaveBeenCalledWith('token', 'waf', ['@system-default'])
        expect(vi.mocked(securityPoliciesApi.create).mock.calls[0]![1].rules).toEqual([expect.objectContaining({ name: '托管 WAF（由网站页设置）',
          action_config: { managed_waf: { ...engine, profile: 'system/crs-pl1' } } })])
      })

      it('lists every official system rule pack with its real effective state (read only)', async () => {
        const view = vi.mocked(rulePacksApi.view)
        renderWAF()
        const packs = await screen.findByRole('region', { name: '官方系统规则包' })
        const active = (await within(packs).findByText('扫描器特征')).closest('li')!
        expect(within(active as HTMLElement).getByText('已生效')).toBeInTheDocument()
        // 平台层 14/15 个系统包为 inherit（系统默认关闭）：按真实状态显示未生效，不写死已生效。
        const inactive = within(packs).getByText('未启用的包').closest('li')!
        expect(within(inactive as HTMLElement).getByText('未生效')).toBeInTheDocument()
        expect(within(inactive as HTMLElement).queryByText('已生效')).not.toBeInTheDocument()
        expect(within(packs).getAllByText('已生效')).toHaveLength(1)
        expect(within(packs).queryByText('租户自己的包')).not.toBeInTheDocument()
        expect(view).toHaveBeenCalledWith('token', 'site', siteID)
      })
    })

    it('CC: 黑白名单时间 saved in the tab are published to the site (no 去发布 link)', async () => {
      render('cc')
      const ban = await screen.findByRole('combobox', { name: '黑名单时间' })
      await userEvent.click(ban)
      // Choosing saves and publishes at once
      await userEvent.click(await screen.findByTitle('系统默认'))
      await waitFor(() => expect(securityPoliciesApi.publishActivation).toHaveBeenCalled())
      expect(vi.mocked(securityPoliciesApi.publishActivation).mock.calls[0]![1]).toMatchObject({ site_id: siteID, policy_id: 'c1', policy_version: 5 })
      expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '去发布' })).not.toBeInTheDocument()
    })
  })
})

describe('规则编辑纯函数', () => {
  it('editCCRules orders whitelist, crawler block, blacklist, own rules, then the default protection', () => {
    const rules = editCCRules(ccPolicy.rules, { presetNames: ['宽松', '滑块验证'], presetRules: [sliderRule], whitelist: ['10.0.0.1'], blacklist: ['10.0.0.2'],
      crawler: { mode: 'block', tokens: ['Baiduspider'] } })
    expect(rules.map((rule) => rule.name)).toEqual([managedRuleNames.whitelist, managedRuleNames.crawlerBlock, managedRuleNames.blacklist, '我的规则', sliderRule.name])
    expect(rules.map((rule) => rule.priority)).toEqual([1, 2, 3, 4, 5])
  })

  it('editCCRules: 关闭 removes the preset rules; empty lists remove their rules', () => {
    const rules = editCCRules(ccPolicy.rules, { presetNames: ['宽松'], presetRules: [], blacklist: [] })
    expect(rules.map((rule) => rule.name)).toEqual(['我的规则'])
  })

  it('editWAFSourceRules matches the site defaults\' proxy rules and replaces the region preset', () => {
    const on = editWAFSourceRules([], { proxy: true, region: 'abroad' })
    expect(on.map((rule) => rule.name)).toEqual(['屏蔽透明代理 via', '屏蔽透明代理 x-forwarded-for', '屏蔽透明代理 forwarded', '区域屏蔽 屏蔽境外（不含港澳台）'])
    expect(editWAFSourceRules(on, { region: 'none' }).map((rule) => rule.name)).toHaveLength(3)
    expect(editWAFSourceRules(on, { proxy: false })).toHaveLength(1)
  })
})
