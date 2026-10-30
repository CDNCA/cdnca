import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import { securityPoliciesApi, type SiteCRSState } from '../api/securityPolicies'
import { SiteCRSOverrideCard } from '../pages/site-edit/SiteCRSOverrideCard'
import { renderWithProviders } from '../test/render'

const siteID = '55555555-5555-4555-8555-555555555555'
const library = { policy_id: '88888888-8888-4888-8888-888888888888', version: 4, profile: 'system/crs-pl1', exclusions: [942100] }
// Tiers as the server counts them (rulepack.CRSTiers), trimmed to two classes.
const sqli = { key: 'waf_set:crs_sqli', name: 'SQL注入', paranoia: 1, rules_by_paranoia: { 1: 2 }, rules: [942100, 942101] }
const ssti = { key: 'waf_set:crs_ssti', name: 'SSTI模板注入', paranoia: 2, rules_by_paranoia: { 1: 1, 2: 1 }, rules: [934180, 934200] }
const tiered: SiteCRSState['profiles'] = [
  { pack_id: 'system/crs-pl1', version: '1.1.0', name: '标准防护', description: '5 类', exports: [942100, 942101],
    tier: { pack_id: 'system/crs-pl1', name: '标准防护', order: 1, action: 'block', paranoia: 1, sets: [sqli],
      previous: 'system/crs-pl1-log', added: [{ kind: 'block', rules: 2 }] } },
  { pack_id: 'system/crs-pl1-log', version: '1.1.0', name: '仅记录', description: '只记录', exports: [942100, 942101],
    tier: { pack_id: 'system/crs-pl1-log', name: '仅记录', order: 0, action: 'log', paranoia: 1, sets: [sqli], previous: '', added: [] } },
  { pack_id: 'system/crs-pl3', version: '1.1.0', name: '极严格防护', description: '10 类', exports: [934180, 934200, 942100, 942101],
    tier: { pack_id: 'system/crs-pl3', name: '极严格防护', order: 2, action: 'block', paranoia: 3, sets: [sqli, ssti],
      previous: 'system/crs-pl1', added: [{ kind: 'set', key: 'waf_set:crs_ssti', name: 'SSTI模板注入', rules: 2 }] } },
]

const inherited: SiteCRSState = {
  site_id: siteID, version: 9, override: { profile: null, exclusions: null }, library, effective: library,
  profiles: [
    { pack_id: 'system/crs-pl1', version: '1.0.0', name: 'CRS 标准（PL1）', description: '误报最少', exports: [941100, 942100] },
    { pack_id: 'system/crs-pl2', version: '1.0.0', name: 'CRS 增强（PL2）', description: '覆盖更多绕过', exports: [941100, 942100, 942180] },
  ],
  apps: [],
  updated_at: null,
  rule_pack_suspensions: [],
}

const appTypes: SiteCRSState['apps'] = [
  { pack_id: 'system/app-drupal', key: 'drupal', name: 'Drupal', version: '1.0.0', description: 'Drupal 内容管理系统' },
  { pack_id: 'system/app-wordpress', key: 'wordpress', name: 'WordPress', version: '1.2.0', description: 'WordPress（原版）' },
]

function renderCard(state: SiteCRSState = inherited, canManage = true) {
  vi.spyOn(securityPoliciesApi, 'getSiteCRS').mockResolvedValue(state)
  renderWithProviders(<SiteCRSOverrideCard siteId={siteID} accessToken="token" canManage={canManage} onOpenLibraries={vi.fn()} />)
}

const option = (groupName: string, label: RegExp) =>
  [...screen.getByRole('radiogroup', { name: groupName }).querySelectorAll('label')].find((item) => label.test(item.textContent ?? ''))!

describe('本站 OWASP CRS 档位 (PA-12)', () => {
  afterEach(() => vi.restoreAllMocks())

  it('shows the library profile and exclusions as inherited', async () => {
    renderCard()
    expect(await screen.findByRole('heading', { name: '本站 OWASP CRS 档位' })).toBeInTheDocument()
    expect(option('CRS 档位', /^跟随规则库/)).toHaveTextContent('跟随规则库（标准防护）')
    expect(option('CRS 档位', /^跟随规则库/).querySelector('input')).toBeChecked()
    expect(option('排除规则 ID', /^跟随规则库（1 条）$/).querySelector('input')).toBeChecked()
    expect(screen.getByRole('status')).toHaveTextContent('本站生效：标准防护，排除 942100')
  })

  it('saves a site profile and exclusions, refusing rules the profile does not export', async () => {
    renderCard()
    const save = vi.spyOn(securityPoliciesApi, 'setSiteCRS').mockResolvedValue({ ...inherited, version: 10 })
    const actor = userEvent.setup()
    await screen.findByRole('heading', { name: '本站 OWASP CRS 档位' })
    // fix-siteinstant: no save button; 本站单独设置 of the exclusions saves the library's list at once
    expect(screen.queryByRole('button', { name: '保存' })).toBeNull()
    await actor.click(option('排除规则 ID', /本站单独设置/))
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1))
    expect(save.mock.calls[0][2]).toBe(9)
    const input = screen.getByRole('textbox', { name: '排除规则 ID' })
    await actor.clear(input)
    await actor.type(input, '942180')
    expect(screen.getByText('所选档位不允许排除：942180')).toBeInTheDocument()
    // an exclusion the profile does not export is marked and not sent
    fireEvent.blur(input)
    expect(save).toHaveBeenCalledTimes(1)
    await actor.click(option('CRS 档位', /本站单独设置/))
    await actor.click(screen.getByRole('combobox', { name: 'CRS 档位' }))
    await actor.click(await screen.findByText('严格防护', { selector: '.ant-select-item-option-content' }))
    expect(screen.queryByText('所选档位不允许排除：942180')).not.toBeInTheDocument()
    await waitFor(() => expect(save.mock.calls.at(-1)![3]).toEqual({ profile: 'system/crs-pl2', exclusions: [942180], apps: [] }))
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
  })

  it('names the server refusal and explains a library without CRS', async () => {
    renderCard()
    vi.spyOn(securityPoliciesApi, 'setSiteCRS').mockRejectedValue(new ApiError('x', 422, 'crs_profile_unavailable'))
    const actor = userEvent.setup()
    await screen.findByRole('heading', { name: '本站 OWASP CRS 档位' })
    await actor.click(option('排除规则 ID', /本站单独设置/))
    expect(await screen.findByText('所选档位尚未下载到主控')).toBeInTheDocument()
    // the refused choice goes back to the stored value
    await waitFor(() => expect(option('排除规则 ID', /^跟随规则库/).querySelector('input')).toBeChecked())
  })

  it('lists the tiers in order with their attack types and additions, and turns a rule group off', async () => {
    renderCard({ ...inherited, library: { ...library, exclusions: [] }, effective: { ...library, exclusions: [] }, profiles: tiered })
    // the server keeps what it was sent; each choice is a save against the returned version
    const tieredState = { ...inherited, library: { ...library, exclusions: [] }, effective: { ...library, exclusions: [] }, profiles: tiered }
    let current: SiteCRSState = tieredState
    vi.mocked(securityPoliciesApi.getSiteCRS).mockImplementation(async () => current)
    const save = vi.spyOn(securityPoliciesApi, 'setSiteCRS').mockImplementation(async (_token, _site, version, override) => {
      current = { ...tieredState, version: version + 1, override }
      return current
    })
    const actor = userEvent.setup()
    await screen.findByRole('heading', { name: '本站 OWASP CRS 档位' })
    expect(screen.getByText('拦截 · 防护等级 1 · 1 类攻击')).toBeInTheDocument()
    expect(screen.getByText('比「仅记录」新增')).toBeInTheDocument()
    expect(screen.getByText('命中后拦截（「仅记录」只记录，2 条规则相同）')).toBeInTheDocument()
    await actor.click(option('CRS 档位', /本站单独设置/))
    await actor.click(screen.getByRole('combobox', { name: 'CRS 档位' }))
    const options = [...document.querySelectorAll('.ant-select-item-option-content')].map((item) => item.textContent)
    expect(options).toEqual(['仅记录', '标准防护', '极严格防护'])
    await actor.click(await screen.findByText('极严格防护', { selector: '.ant-select-item-option-content' }))
    expect(screen.getByText('新增攻击类型「SSTI模板注入」（2 条规则）')).toBeInTheDocument()
    expect(screen.getByText(/极严格防护会明显增加误报/)).toBeInTheDocument()
    await actor.click(screen.getByRole('switch', { name: 'SSTI模板注入：开启' }))
    expect(screen.getByRole('switch', { name: 'SSTI模板注入：关闭' })).not.toBeChecked()
    // the last save holds the tier and the exclusions the switched-off group adds
    await waitFor(() => expect(save.mock.calls.at(-1)![3]).toEqual({ profile: 'system/crs-pl3', exclusions: [934180, 934200], apps: [] }))
  })

  it('names attack types from the waf_set:* translation, not the server fallback (key contains ":")', async () => {
    const raw = { ...sqli, name: 'crs_sqli raw' }
    const profiles = tiered.map((item) => ({ ...item, tier: item.tier && { ...item.tier, sets: [raw] } }))
    renderCard({ ...inherited, library: { ...library, exclusions: [] }, effective: { ...library, exclusions: [] }, profiles })
    await screen.findByRole('heading', { name: '本站 OWASP CRS 档位' })
    expect(screen.getAllByText(/SQL注入 · 2 条规则/).length).toBeGreaterThan(0)
    expect(screen.queryByText(/crs_sqli raw/)).toBeNull()
  })

  it('selects application types (none by default) and saves them with the site override', async () => {
    renderCard({ ...inherited, apps: appTypes })
    const save = vi.spyOn(securityPoliciesApi, 'setSiteCRS').mockResolvedValue({ ...inherited, version: 10 })
    const actor = userEvent.setup()
    await screen.findByRole('heading', { name: '本站 OWASP CRS 档位' })
    expect(screen.getByText(/不确定就不选/)).toBeInTheDocument()
    expect(screen.getByRole('status')).not.toHaveTextContent('应用类型')
    await actor.click(screen.getByRole('combobox', { name: '应用类型' }))
    await actor.click(await screen.findByText('WordPress', { selector: '.ant-select-item-option-content' }))
    expect(screen.getByRole('status')).toHaveTextContent('应用类型：WordPress')
    await waitFor(() => expect(save).toHaveBeenCalled())
    expect(save.mock.calls[0][3]).toEqual({ profile: null, exclusions: null, apps: ['system/app-wordpress'] })
  })

  it('says when no application exclusion pack is downloaded', async () => {
    renderCard()
    expect(await screen.findByText('主控尚未下载应用排除包，暂无可选应用类型。')).toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: '应用类型' })).not.toBeInTheDocument()
  })

  it('without a managed WAF on the library there is nothing to set', async () => {
    renderCard({ ...inherited, library: null, effective: null })
    expect(await screen.findByText(/没有启用 OWASP CRS 托管规则/)).toBeInTheDocument()
  })
})
