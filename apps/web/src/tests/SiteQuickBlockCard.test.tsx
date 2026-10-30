import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import { isQuickBlockRuleID, securityPoliciesApi, type SecurityPolicy } from '../api/securityPolicies'
import { securitySystemRulesApi } from '../api/securitySystemRules'
import { SiteQuickBlockCard } from '../pages/site-edit/SiteQuickBlockCard'
import { SiteWAFTab } from '../pages/site-edit/SiteProtectionTabs'
import { crawlersToText, parseCrawlers } from '../pages/site-edit/quickBlock'
import { renderWithProviders } from '../test/render'

const siteID = '55555555-5555-4555-8555-555555555555'
const systemRule = '00000000-0001-5abc-8def-0123456789ab'
const policy = {
  id: '88888888-8888-4888-8888-888888888888', scope_id: '22222222-2222-4222-8222-222222222222', kind: 'waf',
  name: '站点规则库', description: '', enabled: true, default_action: 'allow', version: 4, created_at: '', updated_at: '',
  origin: 'custom', protected: false,
  rules: [
    { id: systemRule, name: 'quick-block:idc', priority: 1, enabled: true, action: 'block', flow: 'continue', action_config: {},
      conditions: [{ field: 'ip_tag', operator: 'in', values: ['idc:global'] }] },
    { id: '00000000-0002-5abc-8def-0123456789ab', name: 'quick-block:crawler', priority: 1, enabled: true, action: 'allow',
      flow: 'continue', action_config: {}, conditions: [{ field: 'client_ip', operator: 'ip_in_cidr', values: ['66.249.64.0/19'] }] },
    { id: '018f7a5e-0000-7000-8000-00000000b001', name: '放行办公网', priority: 5, enabled: true, action: 'allow', flow: 'stop',
      action_config: {}, conditions: [{ field: 'client_ip', operator: 'ip_in_cidr', values: ['192.0.2.0/24'] }] },
  ],
  quick_block: { block_idc_cn: false, block_idc_global: true, carriers: [],
    allowed_crawlers: [{ networks: ['66.249.64.0/19'], user_agent_prefixes: ['Googlebot'] }] },
} as unknown as SecurityPolicy

function renderCard(overrides: Partial<Parameters<typeof SiteQuickBlockCard>[0]> = {}) {
  const onPublish = vi.fn()
  renderWithProviders(<SiteQuickBlockCard policy={policy} activeVersion={4} accessToken="token" canManage
    onPublish={onPublish} onOpenLibraries={vi.fn()} {...overrides} />)
  return { onPublish }
}

describe('快速屏蔽卡片 (G3-d #13)', () => {
  afterEach(() => vi.restoreAllMocks())

  it('recognizes the reserved system rule IDs only', () => {
    expect(isQuickBlockRuleID(systemRule)).toBe(true)
    expect(isQuickBlockRuleID('00000000-0023-5abc-8def-0123456789ab')).toBe(false) // slot 35
    expect(isQuickBlockRuleID('018f7a5e-0000-7000-8000-00000000b001')).toBe(false)
    expect(isQuickBlockRuleID(undefined)).toBe(false)
  })

  it('parses crawler lines per network, keeping commas inside the User-Agent prefix', () => {
    const parsed = parseCrawlers('66.249.64.0/19,Mozilla/5.0 (compatible; Googlebot/2.1\n\n66.249.64.0/19,Googlebot-Image\n40.77.167.0/24, bingbot')
    expect(parsed).toEqual({ networks: 2, crawlers: [
      { networks: ['66.249.64.0/19'], user_agent_prefixes: ['Mozilla/5.0 (compatible; Googlebot/2.1', 'Googlebot-Image'] },
      { networks: ['40.77.167.0/24'], user_agent_prefixes: ['bingbot'] },
    ] })
    expect(parseCrawlers('66.249.64.0/19\n')).toEqual({ invalidLine: 1 })
    expect(crawlersToText([{ networks: ['a', 'b'], user_agent_prefixes: ['x'] }])).toBe('a,x\nb,x')
  })

  it('saves the switches as a new version and links to publishing', async () => {
    vi.spyOn(securityPoliciesApi, 'ipIntelStatus').mockResolvedValue({ ready: true, revision: 7 })
    const save = vi.spyOn(securityPoliciesApi, 'setQuickBlock').mockResolvedValue({ ...policy, version: 5 })
    const { onPublish } = renderCard()
    const actor = userEvent.setup()
    expect(await screen.findByText('已开启')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: '屏蔽境外 IDC' })).toBeChecked()
    // fix-siteinstant: the switch saves at once
    await actor.click(screen.getByRole('switch', { name: '屏蔽国内 IDC' }))
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1))
    expect(save.mock.calls[0]!.slice(0, 4)).toEqual(['token', policy.id, 4, {
      block_idc_cn: true, block_idc_global: true, carriers: [],
      allowed_crawlers: [{ networks: ['66.249.64.0/19'], user_agent_prefixes: ['Googlebot'] }],
    }])
    expect(save.mock.calls[0]![4]).toMatch(/^site-quick-block-[0-9a-f-]+-4-[0-9a-f-]+$/)
    expect(await screen.findByText('已保存为规则库新版本 v5，发布后在节点生效。')).toBeInTheDocument()
    await actor.click(screen.getByRole('button', { name: '去发布' }))
    expect(onPublish).toHaveBeenCalledWith(policy.id)
  })

  it('refuses turning a block on while the control plane has no IP intelligence library, but allows turning off', async () => {
    vi.spyOn(securityPoliciesApi, 'ipIntelStatus').mockResolvedValue({ ready: false, revision: 0 })
    renderCard()
    expect(await screen.findByText('主控还没有同步到 IP 情报库，暂时不能开启快速屏蔽（关闭不受影响）。')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: '屏蔽国内 IDC' })).toBeDisabled()
    // The block that is on can still be switched off.
    const global = screen.getByRole('switch', { name: '屏蔽境外 IDC' })
    expect(global).toBeEnabled()
    // Turning the last block off is sent even without the library.
    const save = vi.spyOn(securityPoliciesApi, 'setQuickBlock').mockResolvedValue({ ...policy, version: 5 })
    await userEvent.setup().click(global)
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1))
    expect(save.mock.calls[0]![3]).toMatchObject({ block_idc_global: false })
  })

  it('maps server refusals to messages and validates crawler lines', async () => {
    vi.spyOn(securityPoliciesApi, 'ipIntelStatus').mockResolvedValue({ ready: true, revision: 7 })
    vi.spyOn(securityPoliciesApi, 'setQuickBlock').mockRejectedValue(new ApiError('x', 422, 'quick_block_last_rules'))
    renderCard()
    const actor = userEvent.setup()
    const crawlers = await screen.findByRole('textbox', { name: '放行搜索引擎蜘蛛' })
    await actor.clear(crawlers)
    await actor.type(crawlers, '66.249.64.0/19')
    expect(screen.getByText('第 1 行格式应为“网段,User-Agent 前缀”')).toBeInTheDocument()
    // an invalid line is marked and not sent on blur
    fireEvent.blur(crawlers)
    expect(securityPoliciesApi.setQuickBlock).not.toHaveBeenCalled()
    await actor.clear(crawlers)
    fireEvent.blur(crawlers)
    expect(await screen.findByText('规则库只剩快速屏蔽规则，关闭前请先在规则库里添加一条规则。')).toBeInTheDocument()
  })

  it('shows the pending release and explains unsupported libraries', async () => {
    vi.spyOn(securityPoliciesApi, 'ipIntelStatus').mockResolvedValue({ ready: true, revision: 7 })
    const { onPublish } = renderCard({ activeVersion: 3 })
    expect(await screen.findByText('快速屏蔽有未发布的修改（当前生效 v3，最新 v4）。')).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: '去发布' }))
    expect(onPublish).toHaveBeenCalledWith(policy.id)
  })

  it('explains whitelist libraries cannot carry it', () => {
    renderCard({ policy: { ...policy, default_action: 'block' } })
    expect(screen.getByText(/默认动作为“拦截”的白名单规则库也不能开启/)).toBeInTheDocument()
  })

  it('the WAF tab shows the card and keeps quick block crawler rules out of the allow rules list', async () => {
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 100 })
    vi.spyOn(securityPoliciesApi, 'ipIntelStatus').mockResolvedValue({ ready: true, revision: 7 })
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([])
    vi.spyOn(securityPoliciesApi, 'getSiteQuickBlock').mockResolvedValue({
      site_id: siteID, version: 9, override: { block_idc_cn: null, block_idc_global: null, carriers: null, allowed_crawlers: null },
      library: { policy_id: policy.id, version: 4, active_version: 4, supported: true, quick_block: policy.quick_block! },
      effective: policy.quick_block!, updated_at: null,
    })
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({
      binding: { id: 'b1', policy_id: policy.id, binding_revision: 2, active_policy_version: 4, last_claimed_policy_version: 4 },
      latest_candidate: null, operation: null,
    })
    renderWithProviders(<SiteWAFTab siteId={siteID} host="shop.example.com" scopeKind="tenant" scopeId="s1" accessToken="token"
      permissions={['security_policies.read', 'security_policies.manage']} locked={false} />)
    // This site's own setting first, then the library's defaults.
    expect(await screen.findByRole('heading', { name: /本站快速屏蔽/ })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /规则库快速屏蔽（默认值）/ })).toBeInTheDocument()
    expect(screen.getByText('放行办公网')).toBeInTheDocument()
    expect(screen.queryByText('quick-block:crawler')).not.toBeInTheDocument()
  })
})
