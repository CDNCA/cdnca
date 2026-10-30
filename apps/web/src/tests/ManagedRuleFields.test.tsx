import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, vi } from 'vitest'

import { securityPoliciesApi, type CRSProfilePack, type SecurityPolicyRule } from '../api/securityPolicies'
import { securitySystemRulesApi, type SystemRule } from '../api/securitySystemRules'
import { wafRuleSubscriptionsApi } from '../api/wafRuleSubscriptions'
import { useSessionStore } from '../auth/session'
import SecurityPoliciesPage from '../pages/SecurityPoliciesPage'
import { challengeFieldsFor, managedWAFFromForm, managedWAFToForm } from '../pages/security/ManagedRuleFields'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const now = '2026-10-15T00:00:00Z'
function selfSet(key: string, name: string): SystemRule {
  return { system_key: key, kind: 'waf_rule_set', legacy_id: '', name, description: '', sort: 1, revision: 1, status: 'active',
    selectable: true, enabled: true, updated_at: now,
    body: { waf_rule_set: { rules: [{ id: 'r1', name: 'x', enabled: true, action: 'log', matcher_groups: [] }] } } }
}
function catalogSet(key: string, name: string, files: string[], paranoia: number): SystemRule {
  return { system_key: key, kind: 'waf_rule_set', legacy_id: '', name, description: '', sort: 1, revision: 2, status: 'active',
    selectable: true, enabled: true, updated_at: now,
    body: { waf_rule_set: { engine: { engine: 'owasp_crs', files, include_ids: [], exclude_ids: [], action: 'block', paranoia, threshold: 5 } } } }
}

// What the server returns for the catalog defaults (securitypolicy.CatalogRules).
const managedRule: SecurityPolicyRule = {
  name: '托管规则集 (OWASP CRS)', priority: 1, enabled: true, action: 'managed_waf', flow: 'continue', conditions: [],
  action_config: { managed_waf: { request_body_limit: 13107200, request_body_no_files_limit: 131072, request_body_limit_action: 'reject',
    arguments_limit: 1000, json_depth_limit: 512, pcre_match_limit: 100000, profile: 'system/crs-pl1' } },
}

const profiles: CRSProfilePack[] = [
  { pack_id: 'system/crs-pl1', version: '1.0.0', name: 'CRS 标准（PL1）', description: '误报最少', exports: [941100, 941160, 941310, 942100] },
  { pack_id: 'system/crs-pl2', version: '1.0.0', name: 'CRS 增强（PL2）', description: '覆盖更多绕过', exports: [941100, 941160, 941310, 942100, 942180] },
]

// SEC-ACCOUNT-03: WAF pages now report failed platform-library and pending-publication
// reads, so tests that do not care about them stub both as empty.
beforeEach(() => {
  vi.spyOn(wafRuleSubscriptionsApi, 'libraries').mockResolvedValue([])
  vi.spyOn(wafRuleSubscriptionsApi, 'pendingPublications').mockResolvedValue([])
})

describe('managed WAF rule sets in the site WAF policy editor', () => {
  afterEach(() => vi.restoreAllMocks())

  it('converts exclusion rule IDs between form text and API numbers', () => {
    const config = managedRule.action_config.managed_waf!
    const form = managedWAFToForm({ ...config, exclusions: [941160, 941310] })
    expect(form.exclusions).toBe('941160, 941310')
    expect(managedWAFFromForm({ ...form, exclusions: '941310 941160,941160' as unknown as number[] }).exclusions).toEqual([941160, 941310])
    expect(managedWAFFromForm({ ...form, exclusions: '' as unknown as number[] }).exclusions).toBeUndefined()
    // FX12: inspection limit hits are recorded only unless the site chooses block.
    expect(form.inspection_limit_action).toBe('log')
    expect(managedWAFToForm({ ...config, inspection_limit_action: 'block' }).inspection_limit_action).toBe('block')
    expect(challengeFieldsFor('five_second', false).map(([field]) => field)).toContain('delay_seconds')
    expect(challengeFieldsFor('redirect', false).map(([field]) => field)).not.toContain('pow_bits')
    expect(challengeFieldsFor('js', true).map(([field]) => field)).not.toContain('ban_seconds')
  })

  it('imports catalog CRS sets as the default profile, lets the admin pick a profile and exclusions, and saves them', async () => {
    const user = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    vi.spyOn(securitySystemRulesApi, 'list').mockImplementation(async (_token, kind) =>
      kind === 'waf_rule_set' ? [catalogSet('waf_set:crs_sqli', 'CRS·SQL注入', ['REQUEST-942'], 1), catalogSet('waf_set:crs_xss', 'CRS·XSS', ['REQUEST-941'], 1)] : [])
    const catalogRules = vi.spyOn(securityPoliciesApi, 'catalogRules').mockResolvedValue({ rules: [managedRule] })
    vi.spyOn(securityPoliciesApi, 'listCRSProfiles').mockResolvedValue({ items: profiles })
    const create = vi.spyOn(securityPoliciesApi, 'create').mockImplementation(async (_token, input) => ({
      ...input, id: '33333333-3333-4333-8333-333333333333', scope_id: '22222222-2222-4222-8222-222222222222', version: 1,
      created_at: now, updated_at: now, rules: input.rules }))
    const actor = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="waf" />, ['/site/waf-rule'])
    await actor.click(await screen.findByRole('button', { name: '添加规则集' }))
    const editor = await screen.findByRole('dialog')
    await actor.type(within(editor).getByLabelText('名称'), 'CRS 站点策略')
    await actor.click(within(editor).getByRole('combobox', { name: '选择要导入的系统规则' }))
    await actor.click(await screen.findByText('CRS·SQL注入', { selector: '.ant-select-item-option-content' }))
    await actor.click(await screen.findByText('CRS·XSS', { selector: '.ant-select-item-option-content' }))
    await actor.click(within(editor).getByRole('button', { name: '从系统规则导入' }))
    await waitFor(() => expect(catalogRules).toHaveBeenCalledWith(expect.any(String), 'waf', ['waf_set:crs_sqli', 'waf_set:crs_xss']))
    await actor.click(await within(editor).findByRole('combobox', { name: 'CRS 档位' }))
    await actor.click(await screen.findByText('严格防护', { selector: '.ant-select-item-option-content' }))
    expect(await within(editor).findByText('覆盖更多绕过')).toBeInTheDocument()
    await actor.type(within(editor).getByLabelText('排除规则 ID'), '942180, 941160')
    await actor.click(within(editor).getByRole('combobox', { name: '触发检查上限' }))
    await actor.click(await screen.findByText('拦截(403)', { selector: '.ant-select-item-option-content' }))
    // the empty starter rule is replaced by the imported one
    await actor.click(within(editor).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(create).toHaveBeenCalled())
    const rules = create.mock.calls[0][1].rules
    expect(rules).toHaveLength(1)
    expect(rules[0]).toMatchObject({ action: 'managed_waf', conditions: [], action_config: { managed_waf: {
      pcre_match_limit: 100000, inspection_limit_action: 'block', profile: 'system/crs-pl2', exclusions: [941160, 942180] } } })
  })

  it('refuses an exclusion the selected profile does not export', async () => {
    const user = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    vi.spyOn(securitySystemRulesApi, 'list').mockImplementation(async (_token, kind) =>
      kind === 'waf_rule_set' ? [catalogSet('waf_set:crs_sqli', 'CRS·SQL注入', ['REQUEST-942'], 1)] : [])
    vi.spyOn(securityPoliciesApi, 'catalogRules').mockResolvedValue({ rules: [managedRule] })
    vi.spyOn(securityPoliciesApi, 'listCRSProfiles').mockResolvedValue({ items: profiles })
    const create = vi.spyOn(securityPoliciesApi, 'create')
    const actor = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="waf" />, ['/site/waf-rule'])
    await actor.click(await screen.findByRole('button', { name: '添加规则集' }))
    const editor = await screen.findByRole('dialog')
    await actor.type(within(editor).getByLabelText('名称'), 'CRS 排除')
    await actor.click(within(editor).getByRole('combobox', { name: '选择要导入的系统规则' }))
    await actor.click(await screen.findByText('CRS·SQL注入', { selector: '.ant-select-item-option-content' }))
    await actor.click(within(editor).getByRole('button', { name: '从系统规则导入' }))
    // 942180 is a PL2 rule: the default PL1 profile does not run it.
    await actor.type(await within(editor).findByLabelText('排除规则 ID'), '942180')
    await actor.click(within(editor).getByRole('button', { name: '保存' }))
    expect(await within(editor).findByText('当前档位不允许排除：942180')).toBeInTheDocument()
    expect(create).not.toHaveBeenCalled()
  })

  it('lists self-developed detection and OWASP CRS as two groups and imports both together', async () => {
    const user = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    const hidden: SystemRule = { ...catalogSet('waf_set:crs_rules', 'OWASP CRS 规则文本', [], 1),
      body: { waf_rule_set: { bundle: { engine: 'owasp_crs', version: '4.30.0', files: [] } } } }
    vi.spyOn(securitySystemRulesApi, 'list').mockImplementation(async (_token, kind) => kind === 'waf_rule_set'
      ? [selfSet('waf_set:sqli', 'SQL注入'), catalogSet('waf_set:crs_sqli', 'CRS·SQL注入', ['REQUEST-942'], 1), hidden] : [])
    const selfRule: SecurityPolicyRule = { name: 'SQL注入 · 语义检测', priority: 1, enabled: true, action: 'log', flow: 'continue',
      conditions: [{ field: 'args', operator: 'detect', values: ['sqli'] }], action_config: {} }
    const catalogRules = vi.spyOn(securityPoliciesApi, 'catalogRules').mockResolvedValue({ rules: [selfRule, { ...managedRule, priority: 2 }] })
    vi.spyOn(securityPoliciesApi, 'listCRSProfiles').mockResolvedValue({ items: profiles })
    const create = vi.spyOn(securityPoliciesApi, 'create').mockImplementation(async (_token, input) => ({
      ...input, id: '33333333-3333-4333-8333-333333333333', scope_id: '22222222-2222-4222-8222-222222222222', version: 1,
      created_at: now, updated_at: now, rules: input.rules }))
    const actor = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="waf" />, ['/site/waf-rule'])
    await actor.click(await screen.findByRole('button', { name: '添加规则集' }))
    const editor = await screen.findByRole('dialog')
    await actor.click(within(editor).getByRole('combobox', { name: '选择要导入的系统规则' }))
    expect(await screen.findByText('自研检测（默认）')).toBeInTheDocument()
    expect(screen.getByText('OWASP CRS（需节点引擎扩展，按需下载）')).toBeInTheDocument()
    expect(screen.queryByText('OWASP CRS 规则文本', { selector: '.ant-select-item-option-content' })).toBeNull()
    await actor.click(await screen.findByText('SQL注入', { selector: '.ant-select-item-option-content' }))
    await actor.click(await screen.findByText('CRS·SQL注入', { selector: '.ant-select-item-option-content' }))
    await actor.click(within(editor).getByRole('button', { name: '从系统规则导入' }))
    await waitFor(() => expect(catalogRules).toHaveBeenCalledWith(expect.any(String), 'waf', ['waf_set:sqli', 'waf_set:crs_sqli']))
    await actor.type(within(editor).getByLabelText('名称'), '双引擎')
    await actor.click(within(editor).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(create).toHaveBeenCalled())
    const rules = create.mock.calls[0][1].rules
    expect(rules).toHaveLength(2)
    expect(rules[0]).toMatchObject({ action: 'log', conditions: [{ field: 'args', operator: 'detect', values: ['sqli'] }] })
    expect(rules[1]).toMatchObject({ action: 'managed_waf', conditions: [], action_config: { managed_waf: { inspection_limit_action: 'log' } } })
  })
})
