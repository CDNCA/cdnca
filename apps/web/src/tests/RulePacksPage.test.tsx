import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { rulePacksApi, type RulePack, type SiteMounts } from '../api/rulePacks'
import { sitesApi, type SiteListResponse } from '../api/sites'
import { wafRuleSubscriptionsApi, type TenantWAFRuleSubscription } from '../api/wafRuleSubscriptions'
import { useSessionStore } from '../auth/session'
import RulePacksPage from '../pages/RulePacksPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const tenantScope = '22222222-2222-4222-8222-222222222222'
const siteID = '55555555-5555-4555-8555-555555555555'

function pack(overrides: Partial<RulePack> = {}): RulePack {
  return {
    pack_id: 'system/sqli-basic', layer: 'system', owner_scope_id: null, current_version: '1.0.0', update_policy: 'auto',
    name: 'SQL 注入基础防护', description: '', engine: 'waf_v2', exports: [{ rule_id: 'r020', name: '后台路径' }],
    params_schema: {}, defaults: { exclusions: [] }, requires: [], cost: { rules: 2, regexes: 0, units: 12 },
    versions: [], updated_at: '',
    effect: { enabled: false, enabled_at: { level: 'default' }, inherited: false, adjustable: [{ level: 'platform' }], priority: 500,
      params: {}, rule_states: {}, rule_source: {}, ignored_overrides: 0 },
    ...overrides,
  }
}

describe('规则包页面 (PA-11)', () => {
  afterEach(() => vi.restoreAllMocks())

  it('platform operator enables a downloaded pack at the platform level', async () => {
    const user = principal({ scope_kind: 'platform', permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    vi.spyOn(rulePacksApi, 'view').mockResolvedValue({ level: { level: 'platform' }, packs: [pack()], overrides: [] })
    const put = vi.spyOn(rulePacksApi, 'putOverride').mockResolvedValue(undefined)
    const actor = userEvent.setup()
    renderWithProviders(<RulePacksPage />, ['/site/rule-packs'])

    const row = (await screen.findByText('SQL 注入基础防护')).closest('tr')!
    expect(within(row).getByText('不生效')).toBeInTheDocument()
    expect(within(row).getByText('来自系统默认')).toBeInTheDocument()
    // Platform level: "inherit" is the system default, which is off.
    expect(within(row).getByText('系统默认（关闭）')).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: /允许下层调整/ })).toBeInTheDocument()
    await actor.click(within(row).getByText('启用'))
    await waitFor(() => expect(put).toHaveBeenCalledWith(expect.any(String), {
      level: 'platform', level_object_id: null, pack_id: 'system/sqli-basic', rule_id: '', state: 'enabled',
      allow_lower: false, priority: null, params: null,
    }))
  })

  it('a tenant cannot set a pack the platform has not opened', async () => {
    const user = principal({ scope_kind: 'tenant', scope_id: tenantScope, permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    const view = vi.spyOn(rulePacksApi, 'view').mockResolvedValue({ level: { level: 'tenant', object_id: tenantScope }, overrides: [],
      packs: [pack({ effect: { ...pack().effect!, enabled: true, enabled_at: { level: 'platform' } } })] })
    renderWithProviders(<RulePacksPage />, ['/site/rule-packs'])

    const row = (await screen.findByText('SQL 注入基础防护')).closest('tr')!
    expect(view).toHaveBeenCalledWith(expect.any(String), 'tenant', tenantScope)
    expect(within(row).getByText('来自平台')).toBeInTheDocument()
    expect(row.querySelector('.ant-segmented-disabled')).not.toBeNull()
  })

  it('an end user sees "my account / single site", no 租户, and settings explained', async () => {
    const user = principal({ scope_kind: 'tenant', scope_id: tenantScope, permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    const official = pack({ effect: { ...pack().effect!, enabled: true, enabled_at: { level: 'platform' }, inherited: true,
      adjustable: [{ level: 'tenant', object_id: tenantScope }] } })
    vi.spyOn(rulePacksApi, 'view').mockImplementation(async (_token, level) => level === 'site'
      ? { level: { level: 'site', object_id: siteID }, overrides: [], packs: [{ ...official, effect: { ...official.effect!,
        adjustable: [{ level: 'site', object_id: siteID }] } }] }
      : { level: { level: 'tenant', object_id: tenantScope }, overrides: [], packs: [official] })
    vi.spyOn(sitesApi, 'list').mockResolvedValue({ items: [{ id: siteID, domain: 'shop.example.com' }], total: 1, page: 1, limit: 100 } as unknown as SiteListResponse)
    vi.spyOn(rulePacksApi, 'site').mockResolvedValue({ site_id: siteID, published: null, up_to_date: true,
      resolution: { security: { mounts: [], resolved_sha256: 'a'.repeat(64) }, rules: [], conflicts: [], warnings: [], requires: [], cost: { rules: 0, regexes: 0, units: 0 } } })
    vi.spyOn(wafRuleSubscriptionsApi, 'available').mockResolvedValue([])
    const put = vi.spyOn(rulePacksApi, 'putOverride').mockResolvedValue(undefined)
    const actor = userEvent.setup()
    const { container } = renderWithProviders(<RulePacksPage />, ['/site/rule-packs'])

    const row = (await screen.findByText('SQL 注入基础防护')).closest('tr')!
    expect(screen.getByText('我的账号（全部网站）')).toBeInTheDocument()
    expect(screen.getByText('单个网站')).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: /我的设置/ })).toBeInTheDocument()
    expect(within(row).getByText('跟随平台（当前：启用）')).toBeInTheDocument()
    expect(within(row).getByText('关闭')).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: /允许单个网站单独设置/ })).toBeInTheDocument()
    const priorityHeader = screen.getByRole('columnheader', { name: /优先级/ })
    expect(priorityHeader.textContent).not.toContain('数字越小越先匹配')
    await actor.hover(within(priorityHeader).getByText('优先级'))
    expect(await screen.findByText(/数字越小越先匹配，默认 500/)).toBeInTheDocument()
    expect(container.textContent).not.toContain('租户')
    await actor.click(within(row).getByText('关闭'))
    await waitFor(() => expect(put).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({
      level: 'tenant', level_object_id: tenantScope, state: 'disabled' })))

    await actor.click(screen.getByText('单个网站'))
    await actor.click(screen.getByRole('combobox', { name: '选择网站' }))
    await actor.click(await screen.findByText('shop.example.com'))
    const siteRow = (await screen.findAllByText('SQL 注入基础防护')).at(-1)!.closest('tr')!
    expect(within(siteRow).getByText('跟随我的账号（当前：启用）')).toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: /允许单个网站单独设置|允许下层调整/ })).not.toBeInTheDocument()
    expect(container.textContent).not.toContain('租户')
  })

  it('a site shows the final order and conflicts with "disable at level" remedies; publishing waits', async () => {
    const user = principal({ scope_kind: 'tenant', scope_id: tenantScope, permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    vi.spyOn(sitesApi, 'list').mockResolvedValue({ items: [{ id: siteID, domain: 'shop.example.com' }], total: 1, page: 1, limit: 100 } as unknown as SiteListResponse)
    vi.spyOn(rulePacksApi, 'view').mockResolvedValue({ level: { level: 'site', object_id: siteID }, packs: [pack()], overrides: [] })
    const mounts: SiteMounts = {
      site_id: siteID, published: null, up_to_date: false,
      resolution: {
        security: null, requires: [], cost: { rules: 2, regexes: 0, units: 10 }, warnings: [],
        rules: [{ layer: 'system', pack_id: 'system/sqli-basic', version: '1.0.0', rule_id: 'r020', node_id: 'n1', engine: 'waf_v2',
          priority: 500, name: '后台路径', waf: { action: 'block', flow: 'stop' } }],
        conflicts: [{ code: 'opposite_action', message: '', sides: [
          { layer: 'system', pack_id: 'system/sqli-basic', version: '1.0.0', rule_id: 'r020', enabled_at: { level: 'platform' } },
          { layer: 'system', pack_id: 'system/sqli-strict', version: '1.0.0', rule_id: 'r020', enabled_at: { level: 'tenant', object_id: tenantScope } },
        ], remedies: [{ action: 'disable_pack', at: { level: 'tenant', object_id: tenantScope }, pack_id: 'system/sqli-strict' }] }],
      },
    }
    vi.spyOn(rulePacksApi, 'site').mockResolvedValue(mounts)
    const put = vi.spyOn(rulePacksApi, 'putOverride').mockResolvedValue(undefined)
    const actor = userEvent.setup()
    renderWithProviders(<RulePacksPage />, ['/site/rule-packs'])

    await actor.click(await screen.findByText('单个网站'))
    await actor.click(screen.getByRole('combobox', { name: '选择网站' }))
    await actor.click(await screen.findByText('shop.example.com'))

    expect(await screen.findByText('冲突（1），不能发布')).toBeInTheDocument()
    expect(screen.getByText('同层同优先级、相同条件上动作相反')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '发布' })).toBeDisabled()
    expect(screen.getByText('block / stop')).toBeInTheDocument()
    await actor.click(screen.getByRole('button', { name: '在我的账号关闭 system/sqli-strict' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith(expect.any(String), {
      level: 'tenant', level_object_id: tenantScope, pack_id: 'system/sqli-strict', rule_id: '', state: 'disabled',
      allow_lower: false, priority: null, params: null,
    }))
  })

  it('a tenant subscribes to a WAF rule library subscription and opens a site waiting to publish (PA-25)', async () => {
    const user = principal({ scope_kind: 'tenant', scope_id: tenantScope, permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    const packID = `user/${tenantScope}/waf-sub-11111111111141118111111111111111`
    vi.spyOn(rulePacksApi, 'view').mockResolvedValue({ level: { level: 'tenant', object_id: tenantScope }, packs: [], overrides: [] })
    const fresh: TenantWAFRuleSubscription = { id: '11111111-1111-4111-8111-111111111111', name: '已知漏洞防护', description: '',
      revision: 2, feed_version: '20261017', rule_count: 3, synced_at: '2026-10-17T00:00:00Z', deleted: false, subscribed: false, pack: null }
    const mine: TenantWAFRuleSubscription = { ...fresh, id: '33333333-3333-4333-8333-333333333333', name: '爬虫拦截', subscribed: true,
      pack: { subscription_id: '33333333-3333-4333-8333-333333333333', tenant_scope_id: tenantScope, tenant_name: '', pack_id: packID,
        current_version: '2.0.0', latest_version: '2.0.0', update_policy: 'auto', subscribed_at: '',
        pending_sites: [{ site_id: siteID, domain: 'shop.example.com', published_version: '1.0.0' }] } }
    vi.spyOn(wafRuleSubscriptionsApi, 'available').mockResolvedValue([fresh, mine])
    const subscribe = vi.spyOn(wafRuleSubscriptionsApi, 'subscribe').mockResolvedValue({ ...fresh, subscribed: true })
    const site = vi.spyOn(rulePacksApi, 'site').mockResolvedValue({ site_id: siteID, published: null, up_to_date: false,
      resolution: { security: null, rules: [], conflicts: [], warnings: [], requires: [], cost: { rules: 0, regexes: 0, units: 0 } } })
    vi.spyOn(sitesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 100 } as unknown as SiteListResponse)
    const actor = userEvent.setup()
    renderWithProviders(<RulePacksPage />, ['/site/rule-packs'])

    const freshRow = (await screen.findByText('已知漏洞防护')).closest('tr')!
    expect(within(freshRow).getByText('未订阅')).toBeInTheDocument()
    await actor.click(within(freshRow).getByRole('button', { name: '订阅' }))
    await waitFor(() => expect(subscribe).toHaveBeenCalledWith(expect.any(String), fresh.id))

    const mineRow = screen.getByText('爬虫拦截').closest('tr')!
    expect(within(mineRow).getByText(packID)).toBeInTheDocument()
    expect(within(mineRow).getByText('2.0.0（最新 2.0.0）')).toBeInTheDocument()
    expect(within(mineRow).getByText('待发布：shop.example.com')).toBeInTheDocument()
    await actor.click(within(mineRow).getByRole('button', { name: '去发布 shop.example.com' }))
    await waitFor(() => expect(site).toHaveBeenCalledWith(expect.any(String), siteID))
    expect(screen.queryByText('爬虫拦截')).not.toBeInTheDocument()
  })

  it('parameter enum actions show localized labels and save the raw value (A7)', async () => {
    const user = principal({ scope_kind: 'platform', permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    const withParams = pack({
      params_schema: {
        action: { type: 'string', enum: ['allow', 'block', 'challenge', 'log'], bind: { target: 'waf.action', rules: ['r020'] } },
        cc_action: { type: 'string', enum: ['challenge', 'log', 'reject_429'], bind: { target: 'cc.action.kind', rules: ['r020'] } },
        mode: { type: 'string', enum: ['delay', 'slider'], bind: { target: 'cc.challenge.mode', rules: ['r020'] } },
      },
      defaults: { exclusions: [], action: 'block', cc_action: 'reject_429', mode: 'delay' },
    })
    vi.spyOn(rulePacksApi, 'view').mockResolvedValue({ level: { level: 'platform' }, packs: [withParams], overrides: [] })
    const put = vi.spyOn(rulePacksApi, 'putOverride').mockResolvedValue(undefined)
    const actor = userEvent.setup()
    renderWithProviders(<RulePacksPage />, ['/site/rule-packs'])

    const row = (await screen.findByText('SQL 注入基础防护')).closest('tr')!
    await actor.click(within(row).getByRole('button', { name: /展开|Expand row/ }))
    expect(await screen.findByTitle('拦截')).toBeInTheDocument()
    expect(screen.getByTitle('返回 429')).toBeInTheDocument()
    expect(screen.getByTitle('5 秒盾')).toBeInTheDocument()
    expect(screen.queryByTitle('block')).not.toBeInTheDocument()
    await actor.click(screen.getByRole('combobox', { name: 'action' }))
    await actor.click(await screen.findByText('仅记录'))
    await actor.click(screen.getByRole('button', { name: '保存参数' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ params: { action: 'log' } })))
  })

  it('?site_id= opens that site level', async () => {
    const user = principal({ scope_kind: 'tenant', scope_id: tenantScope, permissions: ['security_policies.read'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    const view = vi.spyOn(rulePacksApi, 'view').mockResolvedValue({ level: { level: 'site', object_id: siteID }, packs: [], overrides: [] })
    vi.spyOn(rulePacksApi, 'site').mockResolvedValue({ site_id: siteID, published: null, up_to_date: true,
      resolution: { security: { mounts: [], resolved_sha256: 'a'.repeat(64) }, rules: [], conflicts: [], warnings: [], requires: [], cost: { rules: 0, regexes: 0, units: 0 } } })
    vi.spyOn(sitesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 100 } as unknown as SiteListResponse)
    renderWithProviders(<RulePacksPage />, [`/site/rule-packs?site_id=${siteID}`])
    await waitFor(() => expect(view).toHaveBeenCalledWith(expect.any(String), 'site', siteID))
    expect(await screen.findByText('最终执行顺序')).toBeInTheDocument()
  })
})
