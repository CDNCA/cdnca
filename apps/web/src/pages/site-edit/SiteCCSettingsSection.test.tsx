import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { vi } from 'vitest'

import { ApiError } from '../../api/auth'
import { securityPoliciesApi, type SecurityPolicy, type SecurityPolicyRule } from '../../api/securityPolicies'
import { securitySystemRulesApi, type SystemRule } from '../../api/securitySystemRules'
import { SiteCCSettingsSection } from './SiteCCSettingsSection'

const relaxed: SecurityPolicyRule = {
  id: '44444444-4444-4444-8444-444444444444', name: 'relaxed', priority: 10, enabled: true,
  conditions: [{ field: 'path', operator: 'prefix', values: ['/'] }], action: 'rate_limit', flow: 'stop',
  action_config: { rate_limit: { window_seconds: 5, max_requests: 300, algorithm: 'fixed_window', response_action: 'temporary_ban', ban_seconds: 360 } },
}
const policy: SecurityPolicy = {
  id: '33333333-3333-4333-8333-333333333333', scope_id: '22222222-2222-4222-8222-222222222222', kind: 'cc', name: 'site cc',
  description: '', enabled: true, default_action: 'allow', version: 4, created_at: '2026-10-17T00:00:00Z',
  updated_at: '2026-10-17T00:00:00Z', rules: [relaxed],
}
const rotateGroup = {
  system_key: 'cc_rule:10003', kind: 'cc_rule_group', legacy_id: '10003', name: '旋转图片', description: '', sort: 8, revision: 1,
  status: 'active', selectable: true, enabled: true, updated_at: '2026-10-17T00:00:00Z',
  body: { cc_rule_group: { entries: [{ matcher_key: 'cc_matcher:3', filter1_key: 'cc_filter:10002', filter2_key: '', action: 'block', mode: 'break', enabled: true }] } },
} as SystemRule
const offGroup = { ...rotateGroup, system_key: 'cc_rule:10002', legacy_id: '10002', name: '关闭', sort: 1, body: { cc_rule_group: { entries: [] } } } as SystemRule
const rotateRule: SecurityPolicyRule = { ...relaxed, id: undefined, name: '旋转图片 · 旋转图片60-5', action: 'challenge', priority: 1,
  action_config: { challenge: { type: 'rotate_image', failure_window_seconds: 60, max_failures: 5, pass_seconds: 21600, ban_seconds: 360 } } }

function renderSection(item: SecurityPolicy | undefined, onPublish = vi.fn()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<ConfigProvider><AntApp><QueryClientProvider client={client}>
    <SiteCCSettingsSection policy={item} accessToken="token" isAdmin={false} canManage onPublish={onPublish} />
  </QueryClientProvider></AntApp></ConfigProvider>)
  return onPublish
}

describe('SiteCCSettingsSection', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([offGroup, rotateGroup])
    vi.spyOn(securitySystemRulesApi, 'defaultCrawlers').mockResolvedValue([
      { name: 'baidu', members: ['baidu'], categories: ['search-engine'], user_agent_tokens: ['Baiduspider'], networks: [],
        rdns_suffixes: ['baidu.com', 'baidu.jp'], ready: true },
      { name: 'google', members: ['google-crawler'], categories: ['search-engine'], user_agent_tokens: ['Googlebot'],
        networks: [], rdns_suffixes: ['geo.googlebot.com', 'googlebot.com'], ready: true },
      { name: 'openai', members: ['openai-crawler'], categories: ['ai'], user_agent_tokens: ['GPTBot'],
        networks: ['20.171.206.0/24'], rdns_suffixes: [], ready: true },
      // Only verifiable by ranges not fetched yet: not offered.
      { name: 'perplexity-crawler', members: ['perplexity-crawler'], categories: ['ai'], user_agent_tokens: ['PerplexityBot/'],
        networks: [], rdns_suffixes: [], ready: false },
    ])
  })

  it('asks for a CC rule set before the settings can be edited', () => {
    renderSection(undefined)
    expect(screen.getByText(/站点还没有已发布的 CC 规则集/)).toBeInTheDocument()
  })

  it('shows the stored switch state instead of guessing it from the rules', async () => {
    renderSection({ ...policy, cc_settings: { auto_switch: { mode: 'system', qps_total: 300, qps_5xx: 20, recover_seconds: 300,
      rule_groups: ['cc_rule:10003'], rules: [{ ...rotateRule, id: '55555555-5555-4555-8555-555555555555' }] } } })
    expect(screen.getByRole('switch', { name: '自动切换' })).toBeChecked()
    expect(await screen.findByText('跟随全局配置：每秒请求 300、每秒 5xx 20，切换到 旋转图片，300 秒后恢复')).toBeInTheDocument()
  })

  it('saves a custom auto switch with the chosen group expanded from the catalog and custom durations', async () => {
    const catalog = vi.spyOn(securityPoliciesApi, 'catalogRules').mockResolvedValue({ rules: [rotateRule] })
    // a save that does not answer keeps the draft as edited; the first complete change is what is sent
    let release!: () => void
    const update = vi.spyOn(securityPoliciesApi, 'update').mockImplementation(() => new Promise((resolve) => { release = () => resolve({ ...policy, version: 5 }) }))
    const onPublish = renderSection(policy)
    const user = userEvent.setup()
    expect(screen.getByRole('switch', { name: '自动切换' })).not.toBeChecked()
    expect(screen.queryByRole('button', { name: '保存设置' })).toBeNull()
    await user.click(screen.getByRole('switch', { name: '自动切换' }))
    // 跟随全局配置 is complete and saves at once
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1))
    await user.click(screen.getByRole('radio', { name: '自定义' }))
    // Only groups with entries can be switched to (关闭 has none).
    await user.click(screen.getByRole('combobox', { name: '切换到' }))
    expect(screen.queryByTitle('关闭')).not.toBeInTheDocument()
    await user.click(await screen.findByTitle('旋转图片'))
    await user.click(screen.getByRole('combobox', { name: '黑名单时间' }))
    await user.click(await screen.findByTitle('自定义'))
    const ban = screen.getByRole('spinbutton', { name: '黑名单时间 自定义' })
    await user.clear(ban)
    await user.type(ban, '900')
    fireEvent.blur(ban)
    await act(async () => release())
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2))
    expect(catalog).toHaveBeenCalledWith('token', 'cc', ['cc_rule:10003'])
    const [, id, version, fields] = update.mock.calls[1]
    expect([id, version]).toEqual([policy.id, policy.version])
    expect(fields.rules).toEqual(policy.rules)
    expect(fields.cc_settings).toEqual({
      ban_seconds: { mode: 'custom', seconds: 900 },
      auto_switch: { mode: 'custom', qps_total: 20, qps_5xx: 0, recover_seconds: 300, rule_groups: ['cc_rule:10003'], rules: [rotateRule] },
    })
    const saved = await screen.findByText('已保存为规则集新版本 v5，发布后在节点生效。')
    await user.click(within(saved.closest('.ant-alert')!).getByRole('button', { name: '去发布' }))
    expect(onPublish).toHaveBeenCalled()
  })

  // fix-cfl-b (10-27 #8 修复自动切换无法选择QPS): choosing 自定义 in the
  // requests-per-second select opens the number box and keeps it open; the
  // stored value is unchanged, so nothing is saved until a value is entered.
  it('keeps the custom requests-per-second box open after choosing 自定义 and saves the typed value', async () => {
    const stored = { mode: 'custom' as const, qps_total: 100, qps_5xx: 0, recover_seconds: 300, rule_groups: ['cc_rule:10003'],
      rules: [{ ...rotateRule, id: '55555555-5555-4555-8555-555555555555' }] }
    const update = vi.spyOn(securityPoliciesApi, 'update').mockResolvedValue({ ...policy, version: 5,
      cc_settings: { auto_switch: { ...stored, qps_total: 300 } } })
    renderSection({ ...policy, cc_settings: { auto_switch: stored } })
    const user = userEvent.setup()
    await user.click(screen.getByRole('combobox', { name: '每秒请求' }))
    await user.click(await screen.findByTitle('自定义'))
    const box = await screen.findByRole('spinbutton', { name: '每秒请求 自定义' })
    // choosing 自定义 alone changes no stored value: no save, the box stays
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(update).not.toHaveBeenCalled()
    expect(screen.getByRole('spinbutton', { name: '每秒请求 自定义' })).toBe(box)
    await user.clear(box)
    await user.type(box, '300')
    fireEvent.blur(box)
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1))
    expect(update.mock.calls[0][3].cc_settings?.auto_switch).toMatchObject({ mode: 'custom', qps_total: 300 })
  })

  it('saves the system default and turning the switch off clears it', async () => {
    const update = vi.spyOn(securityPoliciesApi, 'update').mockResolvedValue({ ...policy, version: 5 })
    renderSection({ ...policy, cc_settings: { pass_seconds: { mode: 'system', seconds: 21600 },
      auto_switch: { mode: 'custom', qps_total: 100, qps_5xx: 0, recover_seconds: 300, rule_groups: ['cc_rule:10003'], rules: [rotateRule] } } })
    const user = userEvent.setup()
    expect(screen.getByRole('combobox', { name: '白名单时间' }).closest('.ant-select')).toHaveTextContent('系统默认（当前 21600 秒）')
    await user.click(screen.getByRole('switch', { name: '自动切换' }))
    await waitFor(() => expect(update).toHaveBeenCalled())
    expect(update.mock.calls[0][3].cc_settings).toEqual({ pass_seconds: { mode: 'system', seconds: 0 } })
  })

  // FX47 / NF28 (CC v6).
  it('adds the default crawlers and a cookie domain, and keeps them when other settings are saved', async () => {
    const update = vi.spyOn(securityPoliciesApi, 'update').mockResolvedValue({ ...policy, version: 5 })
    renderSection(policy)
    const user = userEvent.setup()
    expect(screen.getByText('未设置，蜘蛛按普通访客处理。')).toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: '添加常见爬虫' }))
    expect(screen.getByRole('textbox', { name: '名称 1' })).toHaveValue('baidu')
    await user.type(screen.getByRole('textbox', { name: '验证 Cookie 域名' }), 'example.com')
    fireEvent.blur(screen.getByRole('textbox', { name: '验证 Cookie 域名' }))
    await waitFor(() => expect(update.mock.calls.at(-1)?.[3].cc_settings?.challenge_cookie_domain).toBe('example.com'))
    const settings = update.mock.calls.at(-1)![3].cc_settings!
    expect(settings.challenge_cookie_domain).toBe('example.com')
    expect(settings.trusted_crawlers?.map((crawler) => crawler.name)).toEqual(['baidu', 'google', 'openai'])
    expect(settings.trusted_crawlers?.find((crawler) => crawler.name === 'google')).toEqual({
      name: 'google', user_agent_tokens: ['Googlebot'], rdns_suffixes: ['geo.googlebot.com', 'googlebot.com'],
    })
    expect(settings.trusted_crawlers?.find((crawler) => crawler.name === 'openai')).toEqual({
      name: 'openai', user_agent_tokens: ['GPTBot'], networks: ['20.171.206.0/24'],
    })
    expect(screen.getByText(/蜘蛛白名单和验证 Cookie 域名需要节点支持 CC v6/)).toBeInTheDocument()
  })

  // fix-fielderr-be4：服务端拒绝 Cookie 域名时标在该输入框下，保留所填内容、不弹窗；再编辑即清
  it('marks a refused cookie domain under its box and keeps the typed value', async () => {
    vi.spyOn(securityPoliciesApi, 'update').mockRejectedValueOnce(Object.assign(
      new ApiError('API request failed', 400, 'validation_error', 'req-cc'), { field: 'cc_settings.challenge_cookie_domain', reason: 'invalid_format' }))
    renderSection(policy)
    const user = userEvent.setup()
    const box = screen.getByRole('textbox', { name: '验证 Cookie 域名' })
    await user.type(box, 'bad_domain')
    fireEvent.blur(box)
    expect(await screen.findByText('格式不正确')).toBeInTheDocument()
    expect(box).toHaveValue('bad_domain')
    expect(box).toHaveClass('ant-input-status-error')
    expect(screen.getByText('格式不正确').closest('.site-protection-control')).toContainElement(box)
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
    await user.type(box, 'x')
    expect(screen.queryByText('格式不正确')).not.toBeInTheDocument()
  })

  it('marks a refused crawler network on its row', async () => {
    vi.spyOn(securityPoliciesApi, 'update').mockRejectedValueOnce(Object.assign(
      new ApiError('API request failed', 400, 'validation_error', 'req-cc'), { field: 'cc_settings.trusted_crawlers[0].networks', reason: 'invalid_format' }))
    renderSection({ ...policy, cc_settings: { trusted_crawlers: [{ name: 'netbot', user_agent_tokens: ['NetBot'], networks: ['198.51.100.0/24'] }] } })
    const user = userEvent.setup()
    const networks = screen.getByRole('textbox', { name: '可信网段（每行一个，可选） 1' })
    await user.clear(networks)
    await user.type(networks, '198.51.100.999/24')
    fireEvent.blur(networks)
    expect(await screen.findByText('可信网段（每行一个，可选）：格式不正确')).toBeInTheDocument()
    expect(networks).toHaveValue('198.51.100.999/24')
    expect(networks).toHaveClass('ant-input-status-error')
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
  })

  it('keeps stored crawlers and refuses a crawler without verification', async () => {
    const update = vi.spyOn(securityPoliciesApi, 'update').mockResolvedValue({ ...policy, version: 5 })
    const crawlers = [{ name: 'netbot', user_agent_tokens: ['NetBot'], networks: ['198.51.100.0/24'] }]
    renderSection({ ...policy, cc_settings: { trusted_crawlers: crawlers, challenge_cookie_domain: 'example.test' } })
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: '添加蜘蛛' }))
    await user.type(screen.getByRole('textbox', { name: '名称 2' }), 'bare')
    await user.type(screen.getByRole('textbox', { name: 'User-Agent 关键字（每行一个） 2' }), 'BareBot')
    expect(screen.getByText('“bare”需要填写可信网段或反查域名后缀，至少一项')).toBeInTheDocument()
    // an incomplete crawler is marked and not sent
    fireEvent.blur(screen.getByRole('textbox', { name: 'User-Agent 关键字（每行一个） 2' }))
    expect(update).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: '删除 2' }))
    // deleting it leaves the stored list, so there is nothing to save
    expect(update).not.toHaveBeenCalled()
    await user.clear(screen.getByRole('textbox', { name: '验证 Cookie 域名' }))
    await user.type(screen.getByRole('textbox', { name: '验证 Cookie 域名' }), 'example.org')
    fireEvent.blur(screen.getByRole('textbox', { name: '验证 Cookie 域名' }))
    await waitFor(() => expect(update).toHaveBeenCalled())
    expect(update.mock.calls[0][3].cc_settings).toEqual({ trusted_crawlers: crawlers, challenge_cookie_domain: 'example.org' })
  })
})
