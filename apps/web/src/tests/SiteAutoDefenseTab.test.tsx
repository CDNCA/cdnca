import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'
import { vi } from 'vitest'

import { challengePoliciesApi } from '../api/challengePolicies'
import { firewallActionApi } from '../api/firewallAction'
import { rulePacksApi } from '../api/rulePacks'
import { securityPoliciesApi, type SecurityPolicy } from '../api/securityPolicies'
import { securitySystemRulesApi } from '../api/securitySystemRules'
import { useSessionStore } from '../auth/session'
import * as granted from '../components/useGrantedModules'
import i18n from '../i18n'
import { SiteAutoDefenseTab } from '../pages/site-edit/SiteAutoDefenseTab'
import { SiteCCTab, SiteWAFTab } from '../pages/site-edit/SiteProtectionTabs'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// CC/WAF 页里的自动类功能集中到网站编辑「自动防御」标签。

const siteID = '55555555-5555-4555-8555-555555555555'
const tenantScope = '22222222-2222-4222-8222-222222222222'
const ownerID = '33333333-3333-4333-8333-333333333333'
const ccPolicy: SecurityPolicy = { id: 'c1', scope_id: tenantScope, kind: 'cc', name: '本站 CC', description: '', enabled: true, default_action: 'allow',
  version: 4, created_at: '', updated_at: '', rules: [], cc_settings: { auto_switch: { mode: 'system', qps_total: 300, qps_5xx: 20, recover_seconds: 300,
    rule_groups: ['cc_rule:2'], rules: [] } } }
const wafPolicy: SecurityPolicy = { ...ccPolicy, id: 'w1', kind: 'waf', name: '本站 WAF', version: 3, cc_settings: undefined,
  waf_settings: { auto_block: { window_seconds: 60, hit_threshold: 10, block_seconds: 600 } } }
const binding = (policyID: string, version: number) => ({ binding: { id: 'b', policy_id: policyID, binding_revision: 7, active_policy_version: version,
  last_claimed_policy_version: version }, latest_candidate: null, operation: null })
const firewall = { id: '66666666-6666-4666-8666-666666666666', tenant_scope_id: tenantScope, site_id: siteID, normal_action: 'return_page', escalated_action: 'nftables',
  engage_threshold: 100, recover_threshold: 20, recovery_windows: 3, block_networks: ['198.51.100.0/24'], trusted_proxies: [], trusted_crawlers: [],
  return_page: { status: 429, content_type: 'text/plain; charset=utf-8', body: 'x' }, revision: 2, active_revision: 2, lkg_revision: 1,
  deployment_state: 'active', host_escalation: 'owned', document_sha256: 'a'.repeat(64), created_at: '', updated_at: '' }
// The current URL, outside the routes (a same-path ?tab= change keeps the tab route).
function CurrentURL() {
  const location = useLocation()
  return <output aria-label="current-url">{`${location.pathname}${location.search}`}</output>
}

const allPermissions = ['security_policies.read', 'security_policies.manage', 'firewall.read', 'firewall.manage']

function renderTab(Tab: typeof SiteAutoDefenseTab, options: { permissions?: string[]; scopeKind?: 'tenant' | 'platform' } = {}) {
  const scopeKind = options.scopeKind ?? 'tenant'
  renderWithProviders(<><Routes>
    <Route path="/site/edit" element={<Tab siteId={siteID} host="shop.example.com" scopeKind={scopeKind} scopeId={scopeKind === 'tenant' ? tenantScope : 'p1'}
      accessToken="token" permissions={options.permissions ?? allPermissions} locked={false} siteScopeId={tenantScope} siteOwnerId={ownerID} cname="x.cdn.test" />} />
    <Route path="*" element={null} />
  </Routes><CurrentURL /></>, ['/site/edit'])
}

interface Call { method: string; path: string; body?: unknown }

/** GET /v1/modules and the auto defense endpoints (fetch based APIs). */
function stubFetch(modules: string[]) {
  const calls: Call[] = []
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://test')
    const method = init?.method ?? 'GET'
    calls.push({ method, path: url.pathname, body: init?.body ? JSON.parse(String(init.body)) : undefined })
    const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
    if (url.pathname === '/v1/modules') return json({ status: 'active', lease_serial: 1, modules })
    if (url.pathname.endsWith('/modules')) return json({ auto_mitigation_granted: true, overlay: 'active', items: [] })
    return json({ items: [] })
  }))
  return calls
}

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
  const actor = principal({ permissions: allPermissions })
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'token' }, actor)
  vi.spyOn(granted, 'useGrantedModules').mockReturnValue(['module.escalate', 'module.autodefense', 'module.autodefense.auto'])
  vi.spyOn(securityPoliciesApi, 'list').mockImplementation(async (_token, filters) =>
    ({ items: filters.kind === 'cc' ? [ccPolicy] : [wafPolicy], total: 1, page: 1, limit: 100 }))
  vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockImplementation(async (_token, _site, kind) =>
    (kind === 'cc' ? binding('c1', 4) : binding('w1', 3)) as never)
  vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [] } as never)
  vi.spyOn(firewallActionApi, 'get').mockResolvedValue(firewall as never)
  vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([] as never)
  vi.spyOn(securitySystemRulesApi, 'defaultCrawlers').mockResolvedValue([])
  vi.spyOn(securityPoliciesApi, 'getSiteCRS').mockRejectedValue(new Error('n/a'))
  vi.spyOn(securityPoliciesApi, 'listCRSProfiles').mockResolvedValue({ items: [] })
  vi.spyOn(rulePacksApi, 'view').mockResolvedValue({ level: { level: 'site', object_id: siteID }, overrides: [], packs: [] } as never)
  vi.spyOn(securityPoliciesApi, 'update').mockImplementation(async (_token, id, version, input) => ({ ...wafPolicy, ...input, id, version: version + 1 }) as never)
  vi.spyOn(securityPoliciesApi, 'publishActivation').mockResolvedValue({ candidate: {} } as never)
})
afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('自动防御标签', () => {
  // 社区版：攻击自动升级属于商业版，只剩三个分区。
  it('shows the status overview and the three sections in order', async () => {
    stubFetch(['module.escalate', 'module.autodefense', 'module.autodefense.auto'])
    renderTab(SiteAutoDefenseTab)
    const overview = await screen.findByRole('region', { name: '本页摘要' })
    for (const label of ['CC 自动切换', 'WAF 攻击自动封禁', 'WAF 命中自动封禁']) {
      expect(await within(overview).findByText(label)).toBeInTheDocument()
    }
    // 状态取自服务端值：自动切换（跟随全局）开、命中自动封禁开
    await waitFor(() => expect(within(overview).getByRole('button', { name: /WAF 攻击自动封禁/ })).toHaveTextContent('已开启'))
    expect(within(overview).getByRole('button', { name: /CC 自动切换/ })).toHaveTextContent('已开启')
    expect(within(overview).getByRole('button', { name: /WAF 命中自动封禁/ })).toHaveTextContent('已开启')
    expect(within(overview).queryByText('攻击自动升级')).toBeNull()
    const headings = screen.getAllByRole('heading', { level: 2 }).filter((heading) => !heading.classList.contains('visually-hidden')).map((heading) => heading.textContent)
    expect(headings).toEqual(['CC 自动切换', 'WAF 攻击自动封禁', 'WAF 命中自动封禁'])
  })

  it('① CC auto switch saves at once and publishes to the site; the CC v5 note stays', async () => {
    stubFetch([])
    renderTab(SiteAutoDefenseTab)
    const section = await screen.findByRole('region', { name: 'CC 自动切换' })
    expect(await within(section).findByText(/节点需升级到支持自动切换的版本（CC v5）/)).toBeInTheDocument()
    await userEvent.click(within(section).getByRole('switch', { name: '自动切换' }))
    await waitFor(() => expect(securityPoliciesApi.update).toHaveBeenCalled())
    const [, id, version, fields] = vi.mocked(securityPoliciesApi.update).mock.calls[0]!
    expect([id, version]).toEqual(['c1', 4])
    expect(fields.cc_settings?.auto_switch).toBeUndefined()
    await waitFor(() => expect(securityPoliciesApi.publishActivation).toHaveBeenCalled())
    expect(vi.mocked(securityPoliciesApi.publishActivation).mock.calls[0]![1]).toMatchObject({ site_id: siteID, policy_id: 'c1', policy_version: 5 })
  })

  it('② WAF attack auto ban thresholds save on blur through the firewall action PUT', async () => {
    stubFetch([])
    const put = vi.spyOn(firewallActionApi, 'put').mockResolvedValue(firewall as never)
    renderTab(SiteAutoDefenseTab)
    const section = await screen.findByRole('region', { name: 'WAF 攻击自动封禁' })
    const engage = within(section).getByRole('spinbutton', { name: '触发阈值' })
    await waitFor(() => expect(engage).toHaveValue('100'))
    await waitFor(() => expect(engage).not.toBeDisabled())
    act(() => engage.focus())
    fireEvent.change(engage, { target: { value: '150' } })
    expect(put).not.toHaveBeenCalled()
    fireEvent.blur(engage)
    await waitFor(() => expect(put).toHaveBeenCalled())
    expect(put.mock.calls[0]![1]).toMatchObject({ scopeId: tenantScope, siteId: siteID, expectedRevision: 2,
      policy: { engage_threshold: 150, recover_threshold: 20, recovery_windows: 3, block_networks: ['198.51.100.0/24'], normal_action: 'return_page' } })
    expect(securityPoliciesApi.update).not.toHaveBeenCalled()
  })

  it('② thresholds stay read only without firewall.manage', async () => {
    stubFetch([])
    renderTab(SiteAutoDefenseTab, { permissions: ['security_policies.read', 'security_policies.manage', 'firewall.read'] })
    const section = await screen.findByRole('region', { name: 'WAF 攻击自动封禁' })
    await waitFor(() => expect(within(section).getByRole('spinbutton', { name: '触发阈值' })).toHaveValue('100'))
    expect(within(section).getByRole('spinbutton', { name: '触发阈值' })).toBeDisabled()
  })

  it('③ WAF hit auto ban writes waf_settings of the bound library and keeps its rules', async () => {
    stubFetch([])
    renderTab(SiteAutoDefenseTab)
    const section = await screen.findByRole('region', { name: 'WAF 命中自动封禁' })
    const toggle = within(section).getByRole('switch', { name: 'WAF 命中自动封禁' })
    await waitFor(() => expect(toggle).not.toBeDisabled())
    expect(toggle).toBeChecked()
    await userEvent.click(toggle)
    await waitFor(() => expect(securityPoliciesApi.update).toHaveBeenCalled())
    const [, id, version, fields] = vi.mocked(securityPoliciesApi.update).mock.calls[0]!
    expect([id, version]).toEqual(['w1', 3])
    expect(fields.waf_settings).toBeUndefined()
    expect(fields.rules).toEqual(wafPolicy.rules)
    await waitFor(() => expect(securityPoliciesApi.publishActivation).toHaveBeenCalled())
    expect(vi.mocked(securityPoliciesApi.publishActivation).mock.calls[0]![1]).toMatchObject({ site_id: siteID, policy_id: 'w1', policy_version: 4 })
  })

  it('③ the window and hit count save on blur', async () => {
    stubFetch([])
    renderTab(SiteAutoDefenseTab)
    const section = await screen.findByRole('region', { name: 'WAF 命中自动封禁' })
    const hits = await within(section).findByRole('spinbutton', { name: '命中次数' })
    await waitFor(() => expect(hits).not.toBeDisabled())
    act(() => hits.focus())
    fireEvent.change(hits, { target: { value: '25' } })
    expect(securityPoliciesApi.update).not.toHaveBeenCalled()
    fireEvent.blur(hits)
    await waitFor(() => expect(securityPoliciesApi.update).toHaveBeenCalled())
    expect(vi.mocked(securityPoliciesApi.update).mock.calls[0]![3].waf_settings).toEqual({ mode: '', auto_block: { window_seconds: 60, hit_threshold: 25, block_seconds: 600 } })
  })

  it('has no smart auto defense or fallback chain section (commercial edition only)', async () => {
    const calls = stubFetch(['module.escalate', 'module.autodefense', 'module.autodefense.auto'])
    renderTab(SiteAutoDefenseTab, { scopeKind: 'platform' })
    await screen.findByRole('region', { name: 'CC 自动切换' })
    expect(screen.queryByRole('region', { name: '智能自动防御' })).toBeNull()
    expect(screen.queryByText('保底链')).toBeNull()
    expect(calls.some((call) => call.path.startsWith('/v1/security/autodefense') || call.path.includes('fallback-chain'))).toBe(false)
  })

  it('② an administrator reads the site firewall action with the site tenant scope', async () => {
    stubFetch([])
    renderTab(SiteAutoDefenseTab, { scopeKind: 'platform', permissions: ['platform.admin'] })
    await screen.findByRole('region', { name: 'WAF 攻击自动封禁' })
    await waitFor(() => expect(firewallActionApi.get).toHaveBeenCalledWith('token', tenantScope, siteID))
  })

  it('without firewall.read the attack auto ban section is not shown', async () => {
    stubFetch([])
    renderTab(SiteAutoDefenseTab, { permissions: ['security_policies.read', 'security_policies.manage'] })
    await screen.findByRole('region', { name: 'CC 自动切换' })
    expect(screen.queryByRole('region', { name: 'WAF 攻击自动封禁' })).toBeNull()
    expect(firewallActionApi.get).not.toHaveBeenCalled()
  })
})

describe('CC/WAF 页只留规则本身', () => {
  it('the CC tab no longer has the auto switch, attack escalation or smart auto sections', async () => {
    stubFetch(['module.escalate', 'module.autodefense', 'module.autodefense.auto'])
    renderTab(SiteCCTab)
    expect(await screen.findByRole('combobox', { name: '黑名单时间' })).toBeInTheDocument()
    expect(screen.queryByRole('switch', { name: '自动切换' })).toBeNull()
    expect(screen.queryByText('攻击自动升级')).toBeNull()
    expect(screen.queryByText(/^(CC|Bot) 智能自动$/)).toBeNull()
    // The relocated items say where they went.
    await userEvent.click(screen.getByRole('button', { name: '到自动防御标签设置' }))
    expect(screen.getByLabelText('current-url').textContent).toBe('/site/edit?tab=autodefense')
  })

  it('the WAF tab keeps the defense mode but no longer has the auto bans or smart auto sections', async () => {
    stubFetch(['module.autodefense', 'module.autodefense.auto'])
    renderTab(SiteWAFTab)
    const level = await screen.findByRole('region', { name: '防御级别' })
    expect(within(level).getByRole('radio', { name: '观察（只记录不拦截）' })).toBeInTheDocument()
    expect(screen.queryByRole('switch', { name: 'WAF 命中自动封禁' })).toBeNull()
    expect(screen.queryByText('WAF 攻击自动封禁')).toBeNull()
    expect(screen.queryByRole('spinbutton', { name: '触发阈值' })).toBeNull()
    expect(screen.queryByText(/^(WAF|扫描与撞库) 智能自动$/)).toBeNull()
    expect(firewallActionApi.get).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: '到自动防御标签设置' }))
    expect(screen.getByLabelText('current-url').textContent).toBe('/site/edit?tab=autodefense')
  })
})
