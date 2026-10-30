import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CdncaProvider } from '@cdnca/ui'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { openrestySecurityApi } from '../api/openrestySecurity'
import { securityPoliciesApi, type SecurityPolicy, type SecurityPolicyFields } from '../api/securityPolicies'
import { wafRuleSubscriptionsApi } from '../api/wafRuleSubscriptions'
import { usersApi } from '../api/users'
import { useSessionStore } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import { enUS, pseudoCN, zhCN } from '../i18n/resources'
import SecurityPoliciesPage from '../pages/SecurityPoliciesPage'
import securityPoliciesCSS from '../pages/SecurityPoliciesPage.css?raw'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// antd 在 jsdom 下所有弹窗共用 aria-labelledby="test-id"，常驻的反馈弹窗（useFeedback/OutcomeUnknown）
// 挂在前面时会抢走其他弹窗的可访问名；按可见标题找当前可见的弹窗/抽屉。
const dialogsNamed = (name: string | RegExp) => screen.queryAllByRole('dialog').filter((node) => {
  const title = node.querySelector('.ant-modal-title, .ant-modal-confirm-title, .ant-drawer-title')?.textContent?.trim() ?? ''
  return typeof name === 'string' ? title === name : name.test(title)
})
const queryDialog = (name: string | RegExp) => {
  const found = dialogsNamed(name)
  if (found.length > 1) throw new Error(`multiple dialogs named ${String(name)}`)
  return found[0] ?? null
}
const getDialog = (name: string | RegExp) => {
  const found = queryDialog(name)
  if (!found) throw new Error(`no dialog named ${String(name)}`)
  return found
}
const findDialog = (name: string | RegExp, options?: { timeout?: number }) => waitFor(() => getDialog(name), options)

const policy: SecurityPolicy = {
  id: '33333333-3333-4333-8333-333333333333', scope_id: '22222222-2222-4222-8222-222222222222',
  kind: 'cc', name: 'Login protection', description: '', enabled: true, default_action: 'allow', version: 1,
  created_at: '2026-07-22T12:00:00Z', updated_at: '2026-07-22T12:00:00Z',
  rules: [{
    id: '44444444-4444-4444-8444-444444444444', name: 'Block login', priority: 100, enabled: true,
    conditions: [{ field: 'path', operator: 'prefix', values: ['/login'] }],
    action: 'block', flow: 'stop', action_config: {},
  }],
}

function authenticate(permissions = ['security_policies.read', 'security_policies.manage']) {
  const user = principal({ permissions })
  useSessionStore.getState().setSession(authResponse(user), user)
}

function renderPoliciesWithQueryClient(
  queryClient: QueryClient,
  kind: 'cc' | 'acl' | 'waf' = 'cc',
  initialEntry = '/site/cc-rule',
) {
  return render(
    <CdncaProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={[initialEntry]}>
          <SecurityPoliciesPage kind={kind} />
        </MemoryRouter>
      </QueryClientProvider>
    </CdncaProvider>,
  )
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((next) => { resolve = next })
  return { promise, resolve }
}

async function openChallengePolicies(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: '批量操作' }))
  await user.click(await screen.findByRole('menuitem', { name: '挑战策略' }))
}

// SEC-ACCOUNT-03: WAF pages now report failed platform-library and pending-publication
// reads, so tests that do not care about them stub both as empty.
beforeEach(() => {
  vi.spyOn(wafRuleSubscriptionsApi, 'libraries').mockResolvedValue([])
  vi.spyOn(wafRuleSubscriptionsApi, 'pendingPublications').mockResolvedValue([])
  for (const key of ['cc-rule-groups', 'cc-matcher', 'cc-filter']) localStorage.removeItem(`cdnca.advancedFilters.${key}`)
})

describe('SecurityPoliciesPage', () => {
  it('CC 规则组 keeps name + status in the row and folds type, display, ID and user into 高级筛选', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const list = vi.spyOn(securityPoliciesApi, 'list').mockImplementation((_token, filters) => Promise.resolve({ items: [policy], total: 1, page: filters.page, limit: filters.limit }))
    const user = userEvent.setup()
    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))
    await screen.findByText(policy.name)

    const toggle = screen.getByRole('button', { name: '高级筛选' })
    const panel = document.getElementById(toggle.getAttribute('aria-controls')!)!
    expect(panel).not.toBeVisible()
    for (const label of ['规则类型', '显示', '规则组ID', '用户ID']) expect(within(panel).getByText(label)).toBeInTheDocument()
    expect(screen.getByLabelText('规则组名称').closest('[hidden]')).toBeNull()

    await user.type(screen.getByLabelText('规则组名称'), 'stable')
    await user.click(toggle)
    await user.type(within(panel).getByLabelText('规则组ID'), 'policy-7')
    await user.click(within(panel).getByRole('button', { name: '应用' }))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ name: 'stable', id: 'policy-7' })))
    expect(screen.getByRole('button', { name: '高级筛选 · 1' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '移除条件 规则组ID' }))
    await waitFor(() => expect(list.mock.lastCall?.[1]).not.toHaveProperty('id', 'policy-7'))
    expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ name: 'stable' }))
    expect(within(panel).getByLabelText('规则组ID')).toHaveValue('')
  })

  it('CC 规则组 名称与用户 边输入边生效，用户可输入用户名并按联想选中的 ID 过滤', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const list = vi.spyOn(securityPoliciesApi, 'list').mockImplementation((_token, filters) => Promise.resolve({ items: [policy], total: 1, page: filters.page, limit: filters.limit }))
    const owners = vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [{ id: '7d1f0a52-5c8e-4f6b-9a3d-1e2b3c4d5e6f', display_id: '10086', username: 'alice', display_name: 'alice' }], page: 1, limit: 10, total: 1 } as never)
    const user = userEvent.setup()
    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))
    await screen.findByText(policy.name)

    await user.type(screen.getByLabelText('规则组名称'), 'stable')
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ name: 'stable' })), { timeout: 2000 })
    const calls = list.mock.calls.length
    await new Promise((resolve) => setTimeout(resolve, 500))
    expect(list.mock.calls.length).toBe(calls)

    await user.click(screen.getByRole('button', { name: '高级筛选' }))
    await user.type(screen.getByRole('combobox', { name: '用户ID' }), 'ali')
    await waitFor(() => expect(owners).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ search: 'ali' })))
    await user.click(await screen.findByText('alice（10086）'))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ name: 'stable', owner: '7d1f0a52-5c8e-4f6b-9a3d-1e2b3c4d5e6f' })), { timeout: 2000 })
  })

  it('keeps security rule cards, tables, empty states, and dialogs compact', () => {
    expect(securityPoliciesCSS).toContain('height: 40px;')
    expect(securityPoliciesCSS).toContain('height: 48px;')
    expect(securityPoliciesCSS).toContain('.ant-table-placeholder .ant-empty-image')
    expect(securityPoliciesCSS).toContain('.security-policy-modal')
    expect(securityPoliciesCSS).toContain('.security-policies-generic-page')
    expect(securityPoliciesCSS).toContain('.challenge-policy-page')
    expect(securityPoliciesCSS).toContain('.challenge-policy-modal')
    expect(securityPoliciesCSS).toContain('height: 32px !important;')
    expect(securityPoliciesCSS).toContain('margin: 24px;')
    expect(securityPoliciesCSS).toContain('max-height: min(68vh, 820px);')
    expect(securityPoliciesCSS).toContain('max-width: calc(100vw - 48px);')
  })
  it('loads real matcher and filter projections with reference pagination and filters', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    const listReferences = vi.spyOn(securityPoliciesApi, 'listReferences').mockImplementation((_token, kind, filters) => Promise.resolve({
      items: kind === 'matcher' ? [{
        id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', scope_id: policy.scope_id, name: '阻止登录 · path', system_rule: false,
        status: 'enabled', created_at: policy.created_at, policy_id: policy.id, rule_id: policy.rules[0]!.id!, field: 'path', operator: 'prefix', values: ['/login'],
      }] : [{
        id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', scope_id: policy.scope_id, name: '请求频率', system_rule: false,
        status: 'disabled', type: 'req_rate', created_at: policy.created_at, policy_id: policy.id, rule_id: policy.rules[0]!.id!,
      }],
      total: 1, page: filters.page, limit: filters.limit,
    }))
    const user = userEvent.setup()

    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))

    await user.click(screen.getByRole('tab', { name: '匹配器' }))
    expect(await screen.findByText('阻止登录 · path')).toBeInTheDocument()
    expect(listReferences).toHaveBeenCalledWith(expect.any(String), 'matcher', expect.objectContaining({ page: 1, limit: 10 }))
    await user.type(screen.getByLabelText('匹配器名称'), '登录{enter}')
    expect(listReferences).toHaveBeenLastCalledWith(expect.any(String), 'matcher', expect.objectContaining({ name: '登录' }))

    await user.click(screen.getByRole('tab', { name: '过滤器' }))
    expect((await screen.findAllByText('请求频率')).length).toBeGreaterThan(0)
    expect(screen.getByText('已禁用')).toBeInTheDocument()
    expect(listReferences).toHaveBeenLastCalledWith(expect.any(String), 'filter', expect.objectContaining({ page: 1, limit: 10 }))
  })

  it('keeps CC reference row actions compact and puts destructive actions in more', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    vi.spyOn(securityPoliciesApi, 'listReferences').mockResolvedValue({
      items: [{
        id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', scope_id: policy.scope_id, name: '阻止登录 · path', system_rule: false,
        status: 'enabled', created_at: policy.created_at, policy_id: policy.id, rule_id: policy.rules[0]!.id!, field: 'path', operator: 'prefix', values: ['/login'],
      }],
      total: 1, page: 1, limit: 10,
    })
    const user = userEvent.setup()

    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))

    await user.click(screen.getByRole('tab', { name: '匹配器' }))
    const row = (await screen.findByText('阻止登录 · path')).closest('tr')
    expect(row).not.toBeNull()
    expect(within(row!).getByRole('button', { name: '编辑阻止登录 · path' })).toBeInTheDocument()
    expect(within(row!).getByRole('button', { name: '更多' })).toBeInTheDocument()
    expect(within(row!).queryByText('评估')).not.toBeInTheDocument()
    expect(within(row!).queryByText('删除')).not.toBeInTheDocument()
  })

  // 结果未知（503）时，更多菜单的启停/删除与添加同守一个写锁，不发第二个新 key 的写请求；
  // 只能按原请求重试一次。
  it('an unknown CC reference write locks the row more menu too; only the same request is retried', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    vi.spyOn(securityPoliciesApi, 'listReferences').mockResolvedValue({
      items: [{
        id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', scope_id: policy.scope_id, name: '阻止登录 · path', system_rule: false,
        status: 'enabled', created_at: policy.created_at, policy_id: policy.id, rule_id: policy.rules[0]!.id!, field: 'path', operator: 'prefix', values: ['/login'],
      }],
      total: 1, page: 1, limit: 10,
    })
    const setEnabled = vi.spyOn(securityPoliciesApi, 'setReferenceEnabled')
      .mockRejectedValueOnce(new ApiError('unavailable', 503, 'service_unavailable', 'req-cc-1'))
      .mockResolvedValue({} as never)
    const user = userEvent.setup()
    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))
    await user.click(screen.getByRole('tab', { name: '匹配器' }))
    const row = (await screen.findByText('阻止登录 · path')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '更多' }))
    await user.click(await screen.findByRole('menuitem', { name: '禁用' }))
    await waitFor(() => expect(setEnabled).toHaveBeenCalledTimes(1))
    const firstKey = setEnabled.mock.calls[0]![5]
    await waitFor(() => expect(within(row).getByRole('button', { name: '更多' })).toBeDisabled())
    expect(screen.getByRole('button', { name: /添加匹配器/ })).toBeDisabled()
    await user.click(await screen.findByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(setEnabled).toHaveBeenCalledTimes(2))
    expect(setEnabled.mock.calls[1]![5]).toBe(firstKey)
  })

  it('counts and filters rule groups by the competitor pills 全部/系统/自定义/显示/禁用 (tp-b4)', async () => {
    authenticate()
    const list = vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({
      items: [{ ...policy, name: '自定义甲', enabled: true }, { ...policy, id: '55555555-5555-4555-8555-555555555555', name: '自定义乙', enabled: false }],
      total: 2, page: 1, limit: 10,
    })
    vi.spyOn(openrestySecurityApi, 'listRuleGroups').mockResolvedValue([{ id: 'cc.system.10002', system_rule_key: 'cc.system.10002', system_rule_id: '10002', name: '系统组', enabled: true, kind: 'system', system_rule: true, sort: 1 }])
    // Counts come from the server over every group, not the loaded page.
    const summary = vi.spyOn(openrestySecurityApi, 'ruleGroupSummary').mockResolvedValue({ all: 31, system: 9, custom: 22, visible: 25, disabled: 6 })
    const user = userEvent.setup()
    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))

    expect(await screen.findByText('自定义甲')).toBeInTheDocument()
    expect(await screen.findByText('系统组')).toBeInTheDocument()
    const pills = screen.getByRole('group', { name: '规则组统计' })
    await waitFor(() => expect(pills).toHaveTextContent('全部 31系统 9自定义 22显示 25禁用 6'))
    expect(summary).toHaveBeenCalledTimes(1)
    expect(within(pills).getByRole('button', { name: /全部/ })).toHaveAttribute('aria-pressed', 'true')

    await user.click(within(pills).getByRole('button', { name: /系统/ }))
    expect(screen.getByText('系统组')).toBeInTheDocument()
    expect(screen.queryByText('自定义甲')).not.toBeInTheDocument()
    await user.click(within(pills).getByRole('button', { name: /自定义/ }))
    expect(screen.queryByText('系统组')).not.toBeInTheDocument()
    expect(screen.getByText('自定义甲')).toBeInTheDocument()
    await user.click(within(pills).getByRole('button', { name: /禁用/ }))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ status: 'disabled' })))
    expect(screen.queryByRole('tab', { name: '统计' })).not.toBeInTheDocument()
  })

  it('keeps the system-rule manage switch in sync for disable and re-enable', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin', 'security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    vi.spyOn(openrestySecurityApi, 'listRuleGroups').mockResolvedValue([{ id: 'cc.system.10002', system_rule_key: 'cc.system.10002', system_rule_id: '10002', name: '关闭', enabled: true, kind: 'system', system_rule: true, sort: 1 }])
    const setEnabled = vi.spyOn(openrestySecurityApi, 'setRuleGroupEnabled').mockResolvedValue({ id: 'cc.system.10002', enabled: false })
    const user = userEvent.setup()

    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))

    await user.click(await screen.findByRole('button', { name: '管理' }))
    const toggle = screen.getByRole('switch')
    expect(toggle).toBeChecked()
    await user.click(toggle)
    await waitFor(() => expect(setEnabled).toHaveBeenCalledWith(expect.any(String), 'cc.system.10002', false))
    await waitFor(() => expect(screen.getByRole('switch')).not.toBeChecked())

    setEnabled.mockResolvedValue({ id: 'cc.system.10002', enabled: true })
    await user.click(screen.getByRole('switch'))
    await waitFor(() => expect(setEnabled).toHaveBeenLastCalledWith(expect.any(String), 'cc.system.10002', true))
    await waitFor(() => expect(screen.getByRole('switch')).toBeChecked())
  })

  // SEC-ACCOUNT-02: tenants and read-only admins view system groups but cannot toggle them.
  it.each([
    ['tenant', principal({ permissions: ['security_policies.read', 'security_policies.manage'] })],
    ['read-only admin', principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_viewer'], permissions: ['security_policies.read', 'security_policies.manage', 'openresty_security.read'] })],
  ])('SEC-ACCOUNT-02: %s cannot toggle a system rule group', async (_label, actor) => {
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    vi.spyOn(openrestySecurityApi, 'listRuleGroups').mockResolvedValue([{ id: 'cc.system.10002', system_rule_key: 'cc.system.10002', system_rule_id: '10002', name: '关闭', enabled: true, kind: 'system', system_rule: true, sort: 1 }])
    const setEnabled = vi.spyOn(openrestySecurityApi, 'setRuleGroupEnabled').mockResolvedValue({ id: 'cc.system.10002', enabled: false })
    const user = userEvent.setup()

    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))
    const row = (await screen.findByText('关闭')).closest('tr')!
    expect(within(row).queryByRole('button', { name: '更多' })).not.toBeInTheDocument()
    await user.click(within(row).getByRole('button', { name: '管理' }))
    const toggle = await screen.findByRole('switch', { name: '正常' })
    expect(toggle).toBeDisabled()
    expect(screen.getByText('系统规则组由平台统一启停，当前账号只能查看和在网站中选用。')).toBeInTheDocument()
    await user.click(toggle)
    expect(setEnabled).not.toHaveBeenCalled()
  })

  it('SEC-ACCOUNT-02: a refused toggle shows the reason and re-reads the real state', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin', 'security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    const groups = vi.spyOn(openrestySecurityApi, 'listRuleGroups').mockResolvedValue([{ id: 'cc.system.10002', system_rule_key: 'cc.system.10002', system_rule_id: '10002', name: '关闭', enabled: true, kind: 'system', system_rule: true, sort: 1 }])
    const setEnabled = vi.spyOn(openrestySecurityApi, 'setRuleGroupEnabled').mockRejectedValue(new ApiError('forbidden', 403, 'permission_denied'))
    const user = userEvent.setup()

    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))
    await user.click(await screen.findByRole('button', { name: '管理' }))
    const before = groups.mock.calls.length
    await user.click(screen.getByRole('switch', { name: '正常' }))
    await waitFor(() => expect(setEnabled).toHaveBeenCalledTimes(1))
    expect(await screen.findByText(/当前账号缺少/)).toBeInTheDocument()
    await waitFor(() => expect(groups.mock.calls.length).toBeGreaterThan(before))
    expect(screen.getByRole('switch', { name: '正常' })).toBeChecked()
  })

  it('renders the competitor system-rule manage dialog metadata and state label', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin', 'security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    vi.spyOn(openrestySecurityApi, 'listRuleGroups').mockResolvedValue([{ id: 'cc.system.10002', system_rule_key: 'cc.system.10002', system_rule_id: '10002', name: '关闭', enabled: true, kind: 'system', system_rule: true, sort: 1 }])
    const user = userEvent.setup()

    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))
    const row = (await screen.findByText('关闭')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '管理' }))

    expect(await screen.findByText('cc.system.10002 · 关闭')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: '正常' })).toBeChecked()
    expect(within(row).getByRole('button', { name: '更多' })).toBeInTheDocument()
  })

  it('renders real system references in the competitor rule editor and opens the add-rule form', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin', 'security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    vi.spyOn(openrestySecurityApi, 'listRuleGroups').mockResolvedValue([{ id: 'cc.challenge.5s', system_rule_key: 'cc.challenge.5s', system_rule_id: '10005', name: '5秒盾', enabled: true, kind: 'system', system_rule: true, sort: 1 }])
    vi.spyOn(securityPoliciesApi, 'listReferences').mockImplementation((_token, kind) => Promise.resolve({
      items: kind === 'matcher' ? [{
        id: 'matcher-5s', scope_id: 'platform', name: '5秒盾60-5', system_rule: true, status: 'enabled', created_at: policy.created_at,
        system_rule_key: 'cc.challenge.5s.60-5', field: 'path', operator: 'prefix', values: ['/'], sort: 1,
      }] : [{
        id: 'filter-5s', scope_id: 'platform', name: '5秒盾60-5', system_rule: true, status: 'enabled', created_at: policy.created_at,
        system_rule_key: 'cc.challenge.5s.60-5', type: 'challenge_5s', sort: 1,
      }, {
        id: 'filter-5s-duplicate', scope_id: 'platform', name: '5秒盾60-5', system_rule: true, status: 'enabled', created_at: policy.created_at,
        system_rule_key: 'cc.challenge.5s.60-5', type: 'challenge_5s', sort: 1,
      }],
      total: kind === 'matcher' ? 1 : 2, page: 1, limit: 100,
    }))
    const user = userEvent.setup()

    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))
    const row = (await screen.findByText('5秒盾')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '管理' }))

    const editor = await findDialog('编辑规则组')
    expect(within(editor).getByText('基础信息')).toBeInTheDocument()
    expect(within(editor).getByText('规则列表')).toBeInTheDocument()
    expect(within(editor).getAllByText('5秒盾60-5')).toHaveLength(2)
    expect(within(editor).getByRole('button', { name: '新增规则' })).toBeInTheDocument()

    fireEvent.click(within(editor).getByRole('button', { name: '新增规则' }))
    await screen.findByText('匹配模式')
    const addDialog = document.querySelector<HTMLElement>('.cc-system-rule-add-modal')!
    expect(within(addDialog).getByText('匹配器')).toBeInTheDocument()
    expect(within(addDialog).getByText('匹配模式')).toBeInTheDocument()
    const matcherSelect = within(addDialog).getAllByRole('combobox')[0]!
    fireEvent.mouseDown(matcherSelect.closest('.ant-select')!.querySelector('.ant-select-selector')!)
    expect(await screen.findByText('匹配内置资源', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    expect(screen.getByText('匹配静态资源', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    expect(screen.getByText('匹配所有资源', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    await user.keyboard('{Escape}')
    const filterSelect = within(addDialog).getAllByRole('combobox')[1]!
    fireEvent.mouseDown(filterSelect.closest('.ant-select')!.querySelector('.ant-select-selector')!)
    const filterDropdown = document.querySelector<HTMLElement>('.ant-select-dropdown:not(.ant-select-dropdown-hidden)')!
    expect(within(filterDropdown).getAllByText('5秒盾60-5', { selector: '.ant-select-item-option-content' })).toHaveLength(1)
  })

  it('limits filter editor types to the observed CC enum', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    vi.spyOn(securityPoliciesApi, 'listReferences').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    const user = userEvent.setup()

    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))

    await user.click(screen.getByRole('tab', { name: '过滤器' }))
    await user.click(screen.getByRole('button', { name: '添加过滤器' }))
    const editor = await findDialog('添加过滤器')
    const type = within(editor).getByRole('combobox', { name: '类型' })
    fireEvent.mouseDown(type.closest('.ant-select')!.querySelector('.ant-select-selector')!)
    for (const label of ['请求频率', '无感验证', '5 秒盾', '点击验证', '点击验证（简单）', '滑动验证', '滑动验证（简单）', '验证码', '旋转图片', '302 跳转', 'URL 鉴权']) {
      expect(await screen.findByText(label, { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    }
    expect(screen.getByText('请求频率', { selector: '.ant-select-item-option-selected .ant-select-item-option-content' })).toBeInTheDocument()
    await user.keyboard('{Escape}')
  })

  // SEC-ACCOUNT-05: the backend accepts only a JSON object for filter parameters.
  it('SEC-ACCOUNT-05: rejects non-object filter parameters before saving and keeps the draft', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    vi.spyOn(securityPoliciesApi, 'listReferences').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    const create = vi.spyOn(securityPoliciesApi, 'createReference')
    const user = userEvent.setup()

    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))
    await user.click(screen.getByRole('tab', { name: '过滤器' }))
    await user.click(screen.getByRole('button', { name: '添加过滤器' }))
    const editor = await findDialog('添加过滤器')
    await user.type(within(editor).getByRole('textbox', { name: '名称' }), '频率')
    const parameters = within(editor).getByRole('textbox', { name: '高级参数（JSON）' })
    for (const value of ['42', 'true', '"text"', 'null', '[1]', '{bad']) {
      await user.clear(parameters)
      fireEvent.change(parameters, { target: { value } })
      await user.click(within(editor).getByRole('button', { name: /保\s*存/ }))
      await waitFor(() => expect(within(editor).getByText('请输入有效的 JSON 对象'), value).toBeInTheDocument())
      expect(parameters).toHaveValue(value)
    }
    expect(create).not.toHaveBeenCalled()
  })

  // SEC-05 增强：常用计数参数用数字表单编辑，其余字段留在高级 JSON，提交时合并。
  it('SEC-05: edits common filter parameters as numbers and keeps other JSON fields', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    vi.spyOn(securityPoliciesApi, 'listReferences').mockResolvedValue({ items: [{
      id: 'filter-1', name: '频率', description: '', status: 'enabled', version: 3, type: 'req_rate',
      parameters: { within_second: 5, max_req: 100, max_req_per_uri: 10, extra: { note: 'keep' } },
    }], total: 1, page: 1, limit: 10 } as never)
    const update = vi.spyOn(securityPoliciesApi, 'updateReference').mockResolvedValue({} as never)
    const user = userEvent.setup()

    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))
    await user.click(screen.getByRole('tab', { name: '过滤器' }))
    await user.click(await screen.findByRole('button', { name: /编辑\s*频率/ }))
    const editor = await findDialog('编辑过滤器')
    expect(within(editor).getByRole('spinbutton', { name: '统计周期（秒）' })).toHaveValue('5')
    expect(within(editor).getByRole('spinbutton', { name: '最大请求次数' })).toHaveValue('100')
    expect(within(editor).getByRole('spinbutton', { name: '单个网址最大请求次数' })).toHaveValue('10')
    const advanced = within(editor).getByRole('textbox', { name: '高级参数（JSON）' })
    expect(JSON.parse((advanced as HTMLTextAreaElement).value)).toEqual({ extra: { note: 'keep' } })

    const maxReq = within(editor).getByRole('spinbutton', { name: '最大请求次数' })
    await user.clear(maxReq)
    await user.type(maxReq, '200')
    await user.click(within(editor).getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(update).toHaveBeenCalled())
    expect(update.mock.calls[0][4]).toMatchObject({
      type: 'req_rate',
      parameters: { within_second: 5, max_req: 200, max_req_per_uri: 10, extra: { note: 'keep' } },
    })
  })

  it('renders a localized forbidden result when CC reference reads are denied', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    const listReferences = vi.spyOn(securityPoliciesApi, 'listReferences').mockRejectedValue(
      new ApiError('private matcher list', 403, 'permission_denied'),
    )
    const user = userEvent.setup()

    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))

    await user.click(screen.getByRole('tab', { name: '匹配器' }))
    expect(await screen.findByText('无权查看安全规则')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少安全策略权限')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '添加匹配器' })).not.toBeInTheDocument()
    expect(listReferences).toHaveBeenCalledWith(expect.any(String), 'matcher', expect.objectContaining({ page: 1, limit: 10 }))
  })

  it('renders the observed WAF rule-library projection from the real policy contract', async () => {
    authenticate()
    const list = vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({
      items: [{
        ...policy,
        kind: 'waf',
        name: '边缘 WAF 规则',
        description: '拦截高风险请求',
        enabled: true,
        updated_at: '2026-08-22T01:02:03Z',
      }],
      total: 1,
      page: 1,
      limit: 10,
    })
    const user = userEvent.setup()

    renderWithProviders(<SecurityPoliciesPage kind="waf" referenceLayout />, ['/site/waf-rule'])

    expect(await screen.findByRole('heading', { name: 'WAF 规则库' })).toBeInTheDocument()
    expect(await screen.findByText('边缘 WAF 规则')).toBeInTheDocument()
    expect(screen.getByText('1 个')).toBeInTheDocument()
    expect(screen.getByText('拦截高风险请求')).toBeInTheDocument()
    // 范围 is the caller's (用户); an own library has no subscription (—).
    expect(screen.getByText('用户')).toBeInTheDocument()
    expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('启用')).toBeInTheDocument()
    expect(screen.getByText('2026-08-22 09:02:03')).toBeInTheDocument()
    expect(screen.queryByText(/规则库订阅、系统规则和全局范围字段尚未/)).not.toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '规则范围' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '查询' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '清除' })).not.toBeInTheDocument()
    expect(document.querySelector('.ant-pagination-options')).not.toBeInTheDocument()
    expect(list).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ kind: 'waf', page: 1, limit: 10 }))

    const row = screen.getByText('边缘 WAF 规则').closest('tr')!
    expect(within(row).getByRole('button', { name: '编辑' })).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: '删除' })).toBeInTheDocument()
    expect(within(row).queryByRole('button', { name: /评估/ })).not.toBeInTheDocument()

    await user.type(screen.getByLabelText('规则库名称'), '边缘')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ name: '边缘' })))

    await user.click(screen.getByRole('button', { name: '新增规则库' }))
    expect(await findDialog('添加安全规则集')).toBeInTheDocument()
  })

  // SEC-ACCOUNT-04：规则范围（全局/站点/系统）由服务端筛选并回第 1 页；批量启用/停用/删除走批量接口，
  // 带每行版本，逐项回执，系统库不可勾选。
  it('filters WAF libraries by scope on the server and reports batch results item by item', async () => {
    authenticate()
    const own = { ...policy, kind: 'waf' as const, id: '11111111-1111-4111-8111-111111111111', name: '自建库甲', version: 3 }
    const stale = { ...policy, kind: 'waf' as const, id: '22222222-2222-4222-8222-222222222222', name: '自建库乙', version: 5 }
    const system = { ...policy, kind: 'waf' as const, id: '33333333-3333-4333-8333-333333333333', name: '平台库', protected: true }
    const list = vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [own, stale, system], total: 3, page: 1, limit: 10 })
    const batch = vi.spyOn(securityPoliciesApi, 'batch').mockResolvedValue({ items: [
      { id: own.id, status: 'ok', version: 4 }, { id: stale.id, status: 'version_conflict' },
    ] })
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="waf" referenceLayout />, ['/site/waf-rule'])
    expect(await screen.findByText('自建库甲')).toBeInTheDocument()

    await user.click(screen.getByRole('combobox', { name: '规则范围' }))
    await user.click(await screen.findByTitle('站点'))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ kind: 'waf', scope: 'site', page: 1 })))

    const systemRow = screen.getByText('平台库').closest('tr')!
    expect(within(systemRow).getByRole('checkbox')).toBeDisabled()
    for (const name of ['自建库甲', '自建库乙']) await user.click(within(screen.getByText(name).closest('tr')!).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '批量操作' }))
    await user.click(await screen.findByRole('menuitem', { name: '停用选中（2）' }))
    await user.click(within(await findDialog('停用选中的 2 个规则库？')).getByRole('button', { name: '确定' }))

    await waitFor(() => expect(batch).toHaveBeenCalledWith(expect.any(String), 'disable',
      [{ id: own.id, version: 3 }, { id: stale.id, version: 5 }], expect.stringMatching(/^security-policy-disable-/)))
    const results = await findDialog('批量操作结果')
    expect(within(within(results).getByText('自建库甲').closest('tr')!).getByText('成功')).toBeInTheDocument()
    expect(within(within(results).getByText('自建库乙').closest('tr')!).getByText('版本已变化，请刷新后重试')).toBeInTheDocument()
  })

  it('opens the administrator rule library subscriptions (NF37); 批量操作 is a menu (tp-b4)', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin', 'security_policies.read', 'security_policies.manage'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })

    renderWithProviders(<SecurityPoliciesPage kind="waf" referenceLayout />, ['/site/waf-rule'])

    vi.spyOn(wafRuleSubscriptionsApi, 'list').mockResolvedValue([])
    const open = await screen.findByRole('button', { name: '规则库订阅' })
    expect(open).toBeEnabled()
    await userEvent.setup().click(open)
    expect(await screen.findByRole('button', { name: /新增订阅/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '批量操作' })).toBeEnabled()
  })

  it('keeps matcher operators aligned with the selected field', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    vi.spyOn(securityPoliciesApi, 'listReferences').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    const user = userEvent.setup()

    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))

    await user.click(screen.getByRole('tab', { name: '匹配器' }))
    await user.click(screen.getByRole('button', { name: '添加匹配器' }))
    const editor = await findDialog('添加匹配器')
    const field = within(editor).getByRole('combobox', { name: '匹配字段' })
    const operator = within(editor).getByRole('combobox', { name: '运算符' })

    fireEvent.mouseDown(field.closest('.ant-select')!.querySelector('.ant-select-selector')!)
    await user.click(await screen.findByText('客户端IP', { selector: '.ant-select-item-option-content' }))
    fireEvent.mouseDown(operator.closest('.ant-select')!.querySelector('.ant-select-selector')!)
    expect(await screen.findByText('属于 IP/网段', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    expect(screen.queryByText('前缀匹配', { selector: '.ant-select-item-option-content' })).not.toBeInTheDocument()
    expect(screen.queryByText('ip_in_cidr', { selector: '.ant-select-item-option-content' })).not.toBeInTheDocument()
  })

  it('only offers the ACL contract accepted by signed Edge publication', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    const user = userEvent.setup()

    renderWithProviders(<SecurityPoliciesPage kind="acl" />, ['/site/acl'])

    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '添加ACL' }))
    const editor = await findDialog('添加ACL')
    const actionSelect = within(editor).getByRole('combobox', { name: '行为 1' })
    expect(actionSelect.closest('.ant-select')).toHaveTextContent('允许')
    fireEvent.mouseDown(actionSelect.closest('.ant-select')!.querySelector('.ant-select-selector')!)
    expect(await screen.findByText('允许', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    expect(screen.getByText('拒绝', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    expect(screen.queryByText('仅记录', { selector: '.ant-select-item-option-content' })).not.toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(within(editor).getByLabelText('匹配 1')).toHaveAttribute('placeholder', '请输入 IP 或 CIDR，例如 192.0.2.0/24')
    expect(within(editor).getByText('规则列表')).toBeInTheDocument()
    expect(within(editor).queryByText('高级设置')).not.toBeInTheDocument()
  })

  it('W4: an empty ACL rule shows a readable validation message, not a field path', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    const create = vi.spyOn(securityPoliciesApi, 'create')
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="acl" />, ['/site/acl'])
    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '添加ACL' }))
    const editor = await findDialog('添加ACL')
    await user.type(within(editor).getByLabelText('名称'), 'office')
    await user.click(within(editor).getByRole('button', { name: '保存' }))
    expect(await within(editor).findByText('请输入 IP 或 CIDR')).toBeInTheDocument()
    expect(editor).not.toHaveTextContent(/conditions|0,/)
    expect(create).not.toHaveBeenCalled()
  })

  it('W5: administrators pick the target tenant in the main ACL form and it fills the user', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['security_policies.read', 'security_policies.manage', 'identity.users.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    const tenantScope = '22222222-2222-4222-8222-222222222222'
    const tenantUser = '55555555-5555-4555-8555-555555555555'
    vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [{
      id: tenantUser, display_id: '27', scope_id: tenantScope, tenant_id: tenantScope, username: 'tenant-a', display_name: 'A',
      email: null, phone: null, status: 'active', role: 'tenant_owner', group_id: null, group_name: null, revision: 1,
      created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
    }], page: 1, limit: 20, total: 1 })
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="acl" />, ['/site/acl'])
    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '添加ACL' }))
    const editor = await findDialog('添加ACL')
    await user.click(within(editor).getByRole('button', { name: '保存' }))
    expect(await within(editor).findByText('请选择目标租户')).toBeVisible()
    const target = within(editor).getByRole('combobox', { name: '目标租户' })
    expect(target.closest('details')).toBeNull()
    await user.click(target)
    await user.click(await screen.findByText('tenant-a（27）'))
    expect(within(editor).getByLabelText('用户')).toHaveValue(tenantUser)
  })

  it('keeps the administrator ACL projection in reference order and sends the user filter', async () => {
    authenticate(['security_policies.read', 'security_policies.manage'])
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const list = vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 10 })
    const user = userEvent.setup()

    renderWithProviders(<SecurityPoliciesPage kind="acl" />, ['/site/acl'])

    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    const headers = screen.getAllByRole('columnheader').map((header) => header.textContent?.trim())
    expect(headers.slice(0, 3)).toEqual(['', 'ID', '用户'])
    // 用户 边输入边生效（防抖后自动查询）。
    vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [], page: 1, limit: 10, total: 0 } as never)
    await user.type(screen.getByLabelText('用户'), 'alice')
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ kind: 'acl', owner: 'alice' })))
  })

  it('matches the observed ACL list projection and sends real filters', async () => {
    authenticate()
    const list = vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({
      items: [{ ...policy, kind: 'acl', name: '办公网白名单', description: '办公室出口', enabled: false }],
      total: 1,
      page: 1,
      limit: 10,
    })
    const user = userEvent.setup()

    renderWithProviders(<SecurityPoliciesPage kind="acl" />, ['/site/acl'])

    expect(await screen.findByText('办公网白名单')).toBeInTheDocument()
    expect(screen.getByText('办公室出口')).toBeInTheDocument()
    expect(screen.getByText('停用')).toBeInTheDocument()
    expect(screen.getByText('共 1 条')).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '备注' })).toBeInTheDocument()
    expect(list).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ kind: 'acl', page: 1, limit: 10 }))

    await user.type(screen.getByLabelText('ACL名称'), '办公{enter}')
    expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ kind: 'acl', name: '办公' }))

    const status = screen.getByRole('combobox', { name: '所有状态' })
    fireEvent.mouseDown(status.closest('.ant-select')!.querySelector('.ant-select-selector')!)
    await user.click(await screen.findByText('启用', { selector: '.ant-select-item-option-content' }))
    expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ kind: 'acl', status: 'enabled' }))
  })

  it.each([
    ['tenant', 'waf' as const, principal({ permissions: ['security_policies.manage'] })],
    ['platform', 'cc' as const, principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['security_policies.manage'],
    })],
  ])('renders a local rules 403 without a list read for a %s principal lacking read access', async (_role, kind, actor) => {
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const list = vi.spyOn(securityPoliciesApi, 'list')
    const user = userEvent.setup()

    renderWithProviders(<SecurityPoliciesPage kind={kind} />, [kind === 'cc' ? '/site/cc-rule' : '/config/waf'])

    expect(await screen.findByText('无权查看安全规则')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少安全策略权限')).toBeInTheDocument()
    expect(list).not.toHaveBeenCalled()
    expect(screen.queryByTestId('security-policy-table-scroll')).not.toBeInTheDocument()

    if (kind === 'cc') {
      await openChallengePolicies(user)
      expect(await screen.findByText('无权访问挑战策略')).toBeInTheDocument()
      expect(list).not.toHaveBeenCalled()
    }
  })

  it('keeps filters, page two, editor, and token-free cache identity across a same-epoch token refresh', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'],
    })
    const oldToken = 'old-security-policy-token'
    const newToken = 'new-security-policy-token'
    const stablePolicy = { ...policy, name: 'Stable security policy' }
    const list = vi.spyOn(securityPoliciesApi, 'list').mockImplementation((_token, filters) => Promise.resolve({
      items: [stablePolicy], total: 45, page: filters.page, limit: filters.limit,
    }))
    const update = vi.spyOn(securityPoliciesApi, 'update').mockResolvedValue(stablePolicy)
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    useSessionStore.getState().setSession({ ...authResponse(actor), access_token: oldToken }, actor)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const user = userEvent.setup()

    renderPoliciesWithQueryClient(queryClient)

    expect(await screen.findByText(stablePolicy.name)).toBeInTheDocument()
    await user.type(screen.getByLabelText('规则组名称'), 'stable{enter}')
    await user.click(screen.getByRole('combobox', { name: '状态' }))
    await user.click(await screen.findByText('已启用', { selector: '.ant-select-item-option-content' }))
    // 用户ID 在「高级筛选」里，「应用」后生效。
    await user.click(screen.getByRole('button', { name: /^高级筛选/ }))
    await user.type(screen.getByRole('combobox', { name: '用户ID' }), 'owner-a')
    await user.click(screen.getByRole('button', { name: '应用' }))
    expect(within(screen.getByRole('list', { name: '已启用的高级条件' })).getByText('用户ID：owner-a')).toBeInTheDocument()
    await user.click(screen.getByTitle('2'))
    await waitFor(() => expect(document.querySelector('.ant-pagination-item-active')).toHaveAttribute('title', '2'))
    await user.click(screen.getByRole('button', { name: `编辑${stablePolicy.name}` }))
    const editor = await findDialog('编辑安全规则集')
    expect(within(editor).getByLabelText('名称')).toHaveValue(stablePolicy.name)
    const readsBeforeRefresh = list.mock.calls.length

    await act(async () => {
      useSessionStore.getState().setSession({ ...authResponse(actor), access_token: newToken }, actor, 'refresh')
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(list).toHaveBeenCalledTimes(readsBeforeRefresh)
    expect(getDialog('编辑安全规则集')).toBe(editor)
    expect(screen.getByLabelText('规则组名称')).toHaveValue('stable')
    expect(screen.getByRole('combobox', { name: '状态' }).closest('.ant-select')).toHaveTextContent('已启用')
    expect(screen.getByLabelText('用户ID')).toHaveValue('owner-a')
    expect(document.querySelector('.ant-pagination-item-active')).toHaveAttribute('title', '2')

    const activeKey = [
      'security-policies', actor.scope_id, sessionEpoch, 'cc', 2, 10, 'stable', '', 'enabled', 'all', 'owner-a', '',
    ] as const
    const policyKeys = queryClient.getQueryCache().getAll()
      .map((query) => query.queryKey)
      .filter((queryKey) => queryKey[0] === 'security-policies')
    expect(policyKeys).toContainEqual(activeKey)
    for (const queryKey of policyKeys) {
      expect(JSON.stringify(queryKey)).not.toContain(oldToken)
      expect(JSON.stringify(queryKey)).not.toContain(newToken)
    }
    expect(document.body.textContent).not.toContain(oldToken)
    expect(document.body.textContent).not.toContain(newToken)

    await queryClient.refetchQueries({ queryKey: activeKey, type: 'active' })
    await waitFor(() => expect(list).toHaveBeenCalledTimes(readsBeforeRefresh + 1))
    expect(list.mock.calls.at(-1)?.[0]).toBe(newToken)

    await user.click(within(editor).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1))
    expect(update.mock.calls[0]?.[0]).toBe(newToken)
    expect(update.mock.calls[0]?.[1]).toBe(stablePolicy.id)
    expect(update.mock.calls[0]?.[2]).toBe(stablePolicy.version)
    expect(update.mock.calls[0]?.[4]).toMatch(/^security-policy-update-/)
  }, 20_000)

  it('keeps evaluation state across a token refresh and clears it for a new session', async () => {
    const tenantA = principal({ permissions: ['security_policies.read'] })
    const tenantB = principal({
      user_id: '88888888-8888-4888-8888-888888888888',
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
      permissions: ['security_policies.read'],
    })
    const oldToken = 'old-evaluation-token'
    const newToken = 'new-evaluation-token'
    const tenantBToken = 'tenant-b-evaluation-token'
    const list = vi.spyOn(securityPoliciesApi, 'list').mockImplementation((token) => Promise.resolve({
      items: token === tenantBToken ? [] : [policy],
      total: token === tenantBToken ? 0 : 1,
      page: 1,
      limit: 20,
    }))
    const evaluate = vi.spyOn(securityPoliciesApi, 'evaluate').mockResolvedValue({
      policy_id: policy.id,
      policy_version: policy.version,
      action: 'block',
      matched_rule_ids: ['44444444-4444-4444-8444-444444444444'],
      terminal_rule_id: '44444444-4444-4444-8444-444444444444',
      used_default: false,
    })
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: oldToken }, tenantA,
    )
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const user = userEvent.setup()

    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    expect(await screen.findByText(policy.name)).toBeInTheDocument()
    const policyRow = screen.getByText(policy.name).closest('tr')!
    await user.click(within(policyRow).getByRole('button', { name: '更多' }))
    await user.click(await screen.findByRole('menuitem', { name: '评估' }))
    const evaluationDialog = await findDialog('策略评估预览')
    const pathInput = within(evaluationDialog).getByLabelText('路径')
    await user.clear(pathInput)
    await user.type(pathInput, '/preserved-evaluation')
    const readsBeforeRefresh = list.mock.calls.length

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantA), access_token: newToken }, tenantA, 'refresh',
      )
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(list).toHaveBeenCalledTimes(readsBeforeRefresh)
    expect(getDialog('策略评估预览')).toBe(evaluationDialog)
    expect(within(evaluationDialog).getByLabelText('路径')).toHaveValue('/preserved-evaluation')

    await user.click(within(evaluationDialog).getByRole('button', { name: '评估' }))
    expect(await within(evaluationDialog).findByText('结果：拦截，命中 1 条规则')).toBeInTheDocument()
    expect(evaluate).toHaveBeenCalledWith(
      newToken,
      policy.id,
      policy.version,
      expect.objectContaining({ path: '/preserved-evaluation', headers: {} }),
    )

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantB), access_token: tenantBToken }, tenantB,
      )
      await Promise.resolve()
    })

    expect(await screen.findByText('暂无安全规则集')).toBeInTheDocument()
    await waitFor(() => {
      expect(queryDialog('策略评估预览')).not.toBeInTheDocument()
      expect(screen.queryByText('结果：拦截，命中 1 条规则')).not.toBeInTheDocument()
    })
  }, 20_000)

  it('keeps an unknown create retry across token refresh and clears the lock for a new session', async () => {
    const tenantA = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    const tenantB = principal({
      user_id: '88888888-8888-4888-8888-888888888888',
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
      permissions: ['security_policies.read', 'security_policies.manage'],
    })
    const oldToken = 'old-unknown-create-token'
    const newToken = 'new-unknown-create-token'
    const list = vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({
      items: [], total: 0, page: 1, limit: 20,
    })
    const create = vi.spyOn(securityPoliciesApi, 'create').mockRejectedValue(
      new ApiError('private lost create response', 503, 'request_failed'),
    )
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: oldToken }, tenantA,
    )
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const user = userEvent.setup()

    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    expect(await screen.findByText('暂无安全规则集')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '添加规则组' }))
    const editor = await findDialog('添加安全规则集')
    await user.type(within(editor).getByLabelText('名称'), 'Unknown create')
    await user.type(within(editor).getByLabelText('规则名称'), 'Unknown create rule')
    await user.type(within(editor).getByLabelText('匹配值'), '/unknown')
    await user.click(within(editor).getByRole('button', { name: '保存' }))

    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.queryByText('private lost create response')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '添加规则组' })).toBeDisabled()
    const firstCall = create.mock.calls[0]!
    const readsBeforeRefresh = list.mock.calls.length

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantA), access_token: newToken }, tenantA, 'refresh',
      )
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(list).toHaveBeenCalledTimes(readsBeforeRefresh)
    expect(getDialog('添加安全规则集')).toBe(editor)
    expect(screen.getByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '添加规则组' })).toBeDisabled()

    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    const secondCall = create.mock.calls[1]!
    expect(firstCall[0]).toBe(oldToken)
    expect(secondCall[0]).toBe(newToken)
    expect(secondCall[1]).toEqual(firstCall[1])
    expect(secondCall[2]).toBe(firstCall[2])
    expect(firstCall[2]).toMatch(/^security-policy-create-/)
    expect(screen.getByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantB), access_token: 'tenant-b-unknown-create-token' }, tenantB,
      )
      await Promise.resolve()
    })

    await waitFor(() => expect(list.mock.calls.some(([token]) => (
      token === 'tenant-b-unknown-create-token'
    ))).toBe(true))
    expect(await screen.findByText('暂无安全规则集')).toBeInTheDocument()
    await waitFor(() => expect(queryDialog('添加安全规则集')).not.toBeInTheDocument())
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '添加规则组' })).toBeEnabled()
  }, 20_000)

  it('uses the refreshed token with the selected policy version and idempotency key when deleting', async () => {
    const actor = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    const oldToken = 'old-delete-token'
    const newToken = 'new-delete-token'
    const list = vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({
      items: [policy], total: 1, page: 1, limit: 20,
    })
    const remove = vi.spyOn(securityPoliciesApi, 'remove').mockResolvedValue(undefined)
    useSessionStore.getState().setSession(
      { ...authResponse(actor), access_token: oldToken }, actor,
    )
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const user = userEvent.setup()

    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    expect(await screen.findByText(policy.name)).toBeInTheDocument()
    const readsBeforeRefresh = list.mock.calls.length

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(actor), access_token: newToken }, actor, 'refresh',
      )
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(list).toHaveBeenCalledTimes(readsBeforeRefresh)
    const policyRow = screen.getByText(policy.name).closest('tr')!
    await user.click(within(policyRow).getByRole('button', { name: '更多' }))
    await user.click(await screen.findByRole('menuitem', { name: '删除' }))
    await user.click(await screen.findByRole('button', { name: /^删除$/ }))

    expect(await screen.findByText('安全规则集已删除')).toBeInTheDocument()
    expect(remove).toHaveBeenCalledTimes(1)
    expect(remove).toHaveBeenCalledWith(
      newToken,
      policy.id,
      policy.version,
      expect.stringMatching(/^security-policy-delete-/),
    )
  }, 20_000)

  it('D3: explains that a policy active on a site cannot be deleted', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    vi.spyOn(securityPoliciesApi, 'remove').mockRejectedValue(
      new ApiError('API request failed', 409, 'security_policy_in_use'))
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    const policyRow = (await screen.findByText(policy.name)).closest('tr')!
    await user.click(within(policyRow).getByRole('button', { name: '更多' }))
    await user.click(await screen.findByRole('menuitem', { name: '删除' }))
    await user.click(await screen.findByRole('button', { name: /^删除$/ }))

    expect(await screen.findByText('规则集仍在站点上生效，不能删除')).toBeInTheDocument()
    expect(screen.getByText('请先在这些站点「换用其他规则库」或「撤下」，生效后再删除。')).toBeInTheDocument()
    expect(screen.queryByText('安全规则集已删除')).not.toBeInTheDocument()
  }, 20_000)

  it('sec-ui-polish D3: lists the sites still using the policy, each linked to its publish panel', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    const refused = new ApiError('API request failed', 409, 'security_policy_in_use')
    refused.inUseSites = [
      { id: '11111111-1111-4111-8111-111111111111', domain: 'a.example.com' },
      { id: '22222222-2222-4222-8222-222222222222', domain: 'b.example.com' },
    ]
    vi.spyOn(securityPoliciesApi, 'remove').mockRejectedValue(refused)
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    const policyRow = (await screen.findByText(policy.name)).closest('tr')!
    await user.click(within(policyRow).getByRole('button', { name: '更多' }))
    await user.click(await screen.findByRole('menuitem', { name: '删除' }))
    await user.click(await screen.findByRole('button', { name: /^删除$/ }))

    // jsdom 下 antd 弹窗的 aria-labelledby 都是 test-id，按可见标题找到所在 dialog。
    const dialogTitle = await screen.findByText(/规则集仍在站点上生效/, { selector: '.ant-modal-title, .ant-modal-title *, .cdnca-feedback-title *, .ant-modal-confirm-title' })
    const dialog = dialogTitle.closest('[role="dialog"]') as HTMLElement
    expect(within(dialog).getByRole('link', { name: 'a.example.com' })).toHaveAttribute('href', '/site/cc-rule?site_id=11111111-1111-4111-8111-111111111111')
    expect(within(dialog).getByRole('link', { name: 'b.example.com' })).toHaveAttribute('href', '/site/cc-rule?site_id=22222222-2222-4222-8222-222222222222')
    expect(within(dialog).getByText(/换用其他规则库」或「撤下」/)).toBeInTheDocument()
    // Following a link closes the dialog (same route, only ?site_id changes).
    await user.click(within(dialog).getByRole('link', { name: 'a.example.com' }))
    await waitFor(() => expect(screen.queryByText(/规则集仍在站点上生效/)).not.toBeInTheDocument())
  }, 20_000)

  it('resets rules state for a new session and isolates a delayed old-session list result', async () => {
    const tenantA = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    const tenantB = principal({
      user_id: '88888888-8888-4888-8888-888888888888',
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
      permissions: ['security_policies.read', 'security_policies.manage'],
    })
    const tenantAPolicy = { ...policy, name: 'Tenant A security policy' }
    const lateTenantAPolicy = {
      ...policy, id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', name: 'Late tenant A security policy',
    }
    const tenantBPolicy = {
      ...policy, id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', scope_id: tenantB.scope_id,
      name: 'Tenant B security policy',
    }
    const lateTenantA = deferred<{ items: SecurityPolicy[]; total: number; page: number; limit: number }>()
    const pendingTenantB = deferred<{ items: SecurityPolicy[]; total: number; page: number; limit: number }>()
    let delayTenantA = false
    const list = vi.spyOn(securityPoliciesApi, 'list').mockImplementation((token, filters) => {
      if (token === 'tenant-a-security-token') {
        if (delayTenantA && filters.page === 2) return lateTenantA.promise
        return Promise.resolve({ items: [tenantAPolicy], total: 45, page: filters.page, limit: filters.limit })
      }
      if (token === 'tenant-b-security-token') return pendingTenantB.promise
      throw new Error(`unexpected security policy token ${token}`)
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: 'tenant-a-security-token' }, tenantA,
    )
    const tenantAEpoch = useSessionStore.getState().sessionEpoch
    const user = userEvent.setup()

    renderPoliciesWithQueryClient(queryClient)

    expect(await screen.findByText(tenantAPolicy.name)).toBeInTheDocument()
    await user.type(screen.getByLabelText('规则组名称'), 'tenant-a{enter}')
    await user.click(screen.getByRole('combobox', { name: '状态' }))
    await user.click(await screen.findByText('已启用', { selector: '.ant-select-item-option-content' }))
    await user.click(screen.getByTitle('2'))
    await waitFor(() => expect(document.querySelector('.ant-pagination-item-active')).toHaveAttribute('title', '2'))
    await user.click(screen.getByRole('button', { name: `编辑${tenantAPolicy.name}` }))
    expect(await findDialog('编辑安全规则集')).toBeInTheDocument()

    const tenantAKey = [
      'security-policies', tenantA.scope_id, tenantAEpoch, 'cc', 2, 10, 'tenant-a', '', 'enabled', 'all', '', '',
    ] as const
    delayTenantA = true
    void queryClient.invalidateQueries({ queryKey: tenantAKey })
    await waitFor(() => expect(list.mock.calls.filter(([token, filters]) => (
      token === 'tenant-a-security-token' && filters.page === 2
    )).length).toBeGreaterThanOrEqual(2))

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantB), access_token: 'tenant-b-security-token' }, tenantB,
      )
      await Promise.resolve()
    })
    const tenantBEpoch = useSessionStore.getState().sessionEpoch
    await waitFor(() => expect(list.mock.calls.some(([token]) => token === 'tenant-b-security-token')).toBe(true))

    expect(tenantBEpoch).not.toBe(tenantAEpoch)
    expect(screen.queryByText(tenantAPolicy.name)).not.toBeInTheDocument()
    expect(queryDialog('编辑安全规则集')).not.toBeInTheDocument()
    expect(screen.getByLabelText('规则组名称')).toHaveValue('')
    expect(screen.getByRole('combobox', { name: '状态' }).closest('.ant-select')).not.toHaveTextContent('已启用')
    expect(screen.getByTestId('security-policy-table-scroll')).toHaveAttribute('aria-busy', 'true')
    expect(list.mock.calls.find(([token]) => token === 'tenant-b-security-token')?.[1]).toEqual({
      page: 1, limit: 10, kind: 'cc', name: undefined, id: undefined, status: undefined, owner: undefined,
    })

    const tenantBData = { items: [tenantBPolicy], total: 1, page: 1, limit: 20 }
    await act(async () => pendingTenantB.resolve(tenantBData))
    expect(await screen.findByText(tenantBPolicy.name)).toBeInTheDocument()

    const lateTenantAData = { items: [lateTenantAPolicy], total: 45, page: 2, limit: 20 }
    await act(async () => lateTenantA.resolve(lateTenantAData))
    const tenantBKey = [
      'security-policies', tenantB.scope_id, tenantBEpoch, 'cc', 1, 10, '', '', undefined, 'all', '', '',
    ] as const
    expect(queryClient.getQueryData(tenantAKey)).toEqual(lateTenantAData)
    expect(queryClient.getQueryData(tenantBKey)).toEqual(tenantBData)
    expect(screen.getByText(tenantBPolicy.name)).toBeInTheDocument()
    expect(screen.queryByText(lateTenantAPolicy.name)).not.toBeInTheDocument()
  }, 20_000)

  it('returns to the CC rules tab when the session identity changes', async () => {
    const tenantA = principal({ permissions: ['security_policies.read'] })
    const tenantB = principal({
      user_id: '88888888-8888-4888-8888-888888888888',
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
      permissions: ['security_policies.read'],
    })
    const list = vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({
      items: [], total: 0, page: 1, limit: 20,
    })
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: 'tenant-a-tab-token' }, tenantA,
    )
    const user = userEvent.setup()

    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    expect(await screen.findByText('暂无安全规则集')).toBeInTheDocument()
    await openChallengePolicies(user)
    expect(await screen.findByText('无权访问挑战策略')).toBeInTheDocument()

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantB), access_token: 'tenant-b-tab-token' }, tenantB,
      )
      await Promise.resolve()
    })

    expect(screen.getByRole('tab', { name: '规则组' })).toHaveAttribute('aria-selected', 'true')
    expect(await screen.findByText('暂无安全规则集')).toBeInTheDocument()
    expect(list.mock.calls.some(([token]) => token === 'tenant-b-tab-token')).toBe(true)
  })

  it.each(['successful update', 'version conflict'] as const)(
    'invalidates only the current identity prefix after a %s',
    async (outcome) => {
      const actor = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
      useSessionStore.getState().setSession(authResponse(actor), actor)
      const sessionEpoch = useSessionStore.getState().sessionEpoch
      const currentPrefix = ['security-policies', actor.scope_id, sessionEpoch] as const
      const foreignKey = [
        'security-policies', '99999999-9999-4999-8999-999999999999', 999,
        'cc', 1, 20, '', undefined, '',
      ] as const
      const foreignData = {
        items: [{ ...policy, name: 'Foreign security policy' }], total: 1, page: 1, limit: 20,
      }
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
      })
      queryClient.setQueryData(foreignKey, foreignData)
      vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
      const update = vi.spyOn(securityPoliciesApi, 'update')
      if (outcome === 'successful update') {
        update.mockResolvedValue(policy)
      } else {
        update.mockRejectedValue(new ApiError('private stale security policy version', 409, 'version_conflict'))
      }
      const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
      const user = userEvent.setup()

      renderPoliciesWithQueryClient(queryClient)
      expect(await screen.findByText(policy.name)).toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: `编辑${policy.name}` }))
      const editor = await findDialog('编辑安全规则集')
      await user.click(within(editor).getByRole('button', { name: '保存' }))

      expect(await screen.findByText(outcome === 'successful update'
        ? '安全规则集已更新'
        : '规则集已被其他操作修改，列表已刷新')).toBeInTheDocument()
      expect(screen.queryByText('private stale security policy version')).not.toBeInTheDocument()
      expect(update).toHaveBeenCalledWith(
        expect.any(String), policy.id, policy.version,
        expect.objectContaining({ kind: policy.kind, name: policy.name, default_action: policy.default_action }),
        expect.stringMatching(/^security-policy-update-/),
      )

      const policyInvalidations = invalidate.mock.calls
        .map(([filters]) => filters?.queryKey)
        .filter((queryKey) => queryKey?.[0] === 'security-policies')
      expect(policyInvalidations).toEqual([currentPrefix])
      expect(queryClient.getQueryData(foreignKey)).toEqual(foreignData)
      expect(queryClient.getQueryState(foreignKey)?.isInvalidated).toBe(false)
    },
    20_000,
  )

  it.each([
    ['en-US', enUS.securityPolicies],
    ['qps-ploc', (pseudoCN as unknown as typeof zhCN).securityPolicies],
  ] as const)('localizes WAF empty, error, retry, and local 403 states in %s', async (locale, copy) => {
    await changeLocale(locale)
    const actor = principal({ permissions: ['security_policies.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const list = vi.spyOn(securityPoliciesApi, 'list')
      .mockRejectedValueOnce(new ApiError('private security policy topology', 503, 'request_failed'))
      .mockResolvedValueOnce({ items: [], total: 0, page: 1, limit: 20 })
    const user = userEvent.setup()

    renderWithProviders(<SecurityPoliciesPage kind="waf" />, ['/config/waf'])

    expect(await screen.findByRole('heading', { name: copy.titles.waf })).toBeInTheDocument()
    expect(screen.getByLabelText(copy.filters.name)).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: copy.filters.status })).toBeInTheDocument()
    expect(await screen.findByText(copy.errors.loadFailed)).toBeInTheDocument()
    expect(screen.getByText(copy.errors.request_failed)).toBeInTheDocument()
    expect(screen.queryByText('private security policy topology')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: copy.actions.retry }))
    expect(await screen.findByText(copy.values.empty)).toBeInTheDocument()
    expect(list).toHaveBeenCalledTimes(2)

    const forbidden = principal({ permissions: ['security_policies.manage'] })
    await act(async () => {
      useSessionStore.getState().setSession(authResponse(forbidden), forbidden)
      await Promise.resolve()
    })

    expect(await screen.findByText(copy.errors.forbiddenTitle)).toBeInTheDocument()
    expect(screen.getByText(copy.errors.permission_denied)).toBeInTheDocument()
    expect(list).toHaveBeenCalledTimes(2)
  })

  it('renders the global WAF title and scopes the list request to WAF policies', async () => {
    authenticate(['security_policies.read'])
    const list = vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })

    renderWithProviders(<SecurityPoliciesPage kind="waf" />, ['/config/waf'])

    expect(await screen.findByRole('heading', { name: 'WAF规则' })).toBeInTheDocument()
    expect(list).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ kind: 'waf' }))
  })

  // wafgeo-check：独立地区策略面板（从未下发到节点）已删，WAF 规则页改为指向规则库的 country 条件。
  it('points region blocking at WAF rule library country conditions instead of a geo policy panel', async () => {
    authenticate(['security_policies.read', 'firewall.manage'])
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<SecurityPoliciesPage kind="waf" />, ['/config/waf'])

    expect(await screen.findByText(/按国家\/地区屏蔽：在下方 WAF 规则库里新增规则，条件字段选「国家」/)).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: /地区访问控制/ })).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('/v1/site-security/geo-policy'))).toBe(false)
  })

  it('keeps the table mounted while loading and when the policy list is empty', async () => {
    authenticate(['security_policies.read'])
    let resolveList!: (value: { items: SecurityPolicy[]; total: number; page: number; limit: number }) => void
    vi.spyOn(securityPoliciesApi, 'list').mockReturnValue(new Promise((resolve) => { resolveList = resolve }))

    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    const table = screen.getByTestId('security-policy-table-scroll')
    expect(table).toHaveAttribute('aria-busy', 'true')
    await act(async () => { resolveList({ items: [], total: 0, page: 1, limit: 20 }) })
    expect(await screen.findByText('暂无安全规则集')).toBeInTheDocument()
    expect(table).toBeInTheDocument()
    expect(table).toHaveAttribute('aria-busy', 'false')
  })

  it('localizes list failures, hides server messages, and retries without replacing the table', async () => {
    authenticate(['security_policies.read'])
    const list = vi.spyOn(securityPoliciesApi, 'list')
      .mockRejectedValueOnce(new ApiError('private policy store', 503, 'request_failed'))
      .mockResolvedValueOnce({ items: [], total: 0, page: 1, limit: 20 })
    // The system catalog reads fine (its own failure now shows its own notice, SEC-ACCOUNT-03).
    const { securitySystemRulesApi } = await import('../api/securitySystemRules')
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([])
    const user = userEvent.setup()

    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    expect(await screen.findByText('安全规则加载失败')).toBeInTheDocument()
    expect(screen.getByText('请求失败，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('private policy store')).not.toBeInTheDocument()
    expect(screen.getByTestId('security-policy-table-scroll')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无安全规则集')).toBeInTheDocument()
    expect(list).toHaveBeenCalledTimes(2)
  })

  it('renders a compact tenant table without owner metadata and honors read-only RBAC', async () => {
    authenticate(['security_policies.read'])
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    expect(await screen.findByRole('heading', { name: 'CC规则' })).toBeInTheDocument()
    expect(await screen.findByText('Login protection')).toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: '用户' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '添加规则组' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '编辑Login protection' })).not.toBeInTheDocument()
    const policyRow = screen.getByText('Login protection').closest('tr')!
    await userEvent.setup().click(within(policyRow).getByRole('button', { name: '更多' }))
    expect(await screen.findByRole('menuitem', { name: '评估' })).toBeInTheDocument()
    expect(screen.getByTestId('security-policy-table-scroll')).toHaveAttribute('aria-busy', 'false')
  })

  it('locks unknown creates and retries the exact input and idempotency key', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    const create = vi.spyOn(securityPoliciesApi, 'create')
      .mockRejectedValueOnce(new ApiError('private upstream failure', 500, 'internal_error'))
      .mockResolvedValue(policy)
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    expect(await screen.findByText('暂无安全规则集')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '添加规则组' }))
    const dialog = getDialog('添加安全规则集')
    await user.type(within(dialog).getByLabelText('名称'), 'Login protection')
    await user.type(within(dialog).getByLabelText('规则名称'), 'Block login')
    await user.type(within(dialog).getByLabelText('匹配值'), '/login')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))

    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.queryByText('private upstream failure')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '添加规则组' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]).toEqual(create.mock.calls[0])
  }, 20_000)

  it('maps permission denial locally without exposing the server message', async () => {
    authenticate(['security_policies.read'])
    vi.spyOn(securityPoliciesApi, 'list').mockRejectedValue(new ApiError('internal role row', 403, 'permission_denied'))
    renderWithProviders(<SecurityPoliciesPage kind="acl" />, ['/site/acl'])

    expect(await screen.findByText('无权查看安全规则')).toBeInTheDocument()
    expect(screen.queryByText('internal role row')).not.toBeInTheDocument()
  })

  it('mounts activation operations with the current policy kind and URL site', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    const status = vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({
      binding: null, latest_candidate: null, operation: null,
    })

    renderWithProviders(
      <SecurityPoliciesPage kind="cc" />,
      ['/site/cc-rule?site_id=55555555-5555-4555-8555-555555555555'],
    )

    expect(await screen.findByRole('heading', { name: '安全规则发布' })).toBeInTheDocument()
    expect(status).toHaveBeenCalledWith(
      expect.any(String), '55555555-5555-4555-8555-555555555555', 'cc', expect.any(AbortSignal),
    )
  })
})

describe('SecurityPoliciesPage CC site settings', () => {
  it('keeps a CC policy\'s site settings (durations, auto switch) when its rules are saved', async () => {
    const actor = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const settings = {
      ban_seconds: { mode: 'custom' as const, seconds: 900 },
      auto_switch: { mode: 'system' as const, qps_total: 0, qps_5xx: 0, recover_seconds: 0, rule_groups: [], rules: [] },
    }
    const withSettings: SecurityPolicy = { ...policy, cc_settings: settings }
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [withSettings], total: 1, page: 1, limit: 20 })
    const update = vi.spyOn(securityPoliciesApi, 'update').mockResolvedValue(withSettings)
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    const user = userEvent.setup()
    renderPoliciesWithQueryClient(queryClient)
    expect(await screen.findByText(policy.name)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: `编辑${policy.name}` }))
    const editor = await findDialog('编辑安全规则集')
    await user.click(within(editor).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(update).toHaveBeenCalled())
    expect(update.mock.calls[0][3]).toEqual(expect.objectContaining({ cc_settings: settings }))
  }, 20_000)

  it('sends 全部客户端 as the path prefix "/" condition and shows it back as the switch', async () => {
    authenticate()
    const rule: SecurityPolicy['rules'][number] = { ...policy.rules[0], action: 'rate_limit',
      action_config: { rate_limit: { window_seconds: 10, max_requests: 20 } },
      conditions: [{ field: 'client_ip', operator: 'ip_in_cidr', values: ['10.0.0.0/24'] }] }
    const item: SecurityPolicy = { ...policy, rules: [rule] }
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [item], total: 1, page: 1, limit: 20 })
    const update = vi.spyOn(securityPoliciesApi, 'update').mockResolvedValue(item)
    const user = userEvent.setup()
    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }))
    expect(await screen.findByText(policy.name)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: `编辑${policy.name}` }))
    const editor = await findDialog('编辑安全规则集')
    const all = within(editor).getByRole('switch', { name: '全部客户端' })
    expect(all).not.toBeChecked()
    await user.click(all)
    expect(within(editor).queryByRole('combobox', { name: '匹配字段' })).not.toBeInTheDocument()
    await user.click(within(editor).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(update).toHaveBeenCalled())
    const sent = update.mock.calls[0][3] as SecurityPolicyFields
    expect(sent.rules[0].conditions).toEqual([{ field: 'path', operator: 'prefix', values: ['/'] }])
    expect(sent.rules[0]).not.toHaveProperty('match_all')
  }, 20_000)

  // NF27 / NF32 (CC v6): User-Agent / Referer / header matches and repeated
  // client IP conditions (exclusions, ranges) round-trip through the editor.
  it('offers User-Agent, Referer and header matches and IP exclusions on CC rules', async () => {
    authenticate()
    const rule: SecurityPolicy['rules'][number] = {
      ...policy.rules[0], action: 'rate_limit',
      action_config: { rate_limit: { window_seconds: 10, max_requests: 30 } },
      conditions: [
        { field: 'client_ip', operator: 'ip_in_cidr', values: ['10.0.0.0/24'] },
        { field: 'client_ip', operator: 'ip_not_in_cidr', values: ['10.0.0.7/32'] },
        { field: 'user_agent', operator: 'regex', values: ['(?i)python'] },
      ],
    }
    const withConditions: SecurityPolicy = { ...policy, rules: [rule] }
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [withConditions], total: 1, page: 1, limit: 20 })
    const update = vi.spyOn(securityPoliciesApi, 'update').mockResolvedValue(withConditions)
    const user = userEvent.setup()
    renderPoliciesWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }))
    expect(await screen.findByText(policy.name)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: `编辑${policy.name}` }))
    const editor = await findDialog('编辑安全规则集')
    expect(within(editor).getByText(/点分掩码/)).toBeInTheDocument()
    const fields = within(editor).getAllByRole('combobox', { name: '匹配字段' })
    fireEvent.mouseDown(fields[0]!.closest('.ant-select')!.querySelector('.ant-select-selector')!)
    for (const label of ['User-Agent', 'Referer', '请求头']) {
      expect(await screen.findByText(label, { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    }
    fireEvent.keyDown(fields[0]!, { key: 'Escape' })
    // Only the first condition row is labelled; it is a client IP condition.
    const operator = within(editor).getByRole('combobox', { name: '运算符' })
    fireEvent.mouseDown(operator.closest('.ant-select')!.querySelector('.ant-select-selector')!)
    expect(await screen.findByText('不属于 IP/网段', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    fireEvent.keyDown(operator, { key: 'Escape' })
    await user.click(within(editor).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(update).toHaveBeenCalled())
    expect(update.mock.calls[0][3].rules[0].conditions).toEqual([
      { field: 'client_ip', operator: 'ip_in_cidr', values: ['10.0.0.0/24'] },
      { field: 'client_ip', operator: 'ip_not_in_cidr', values: ['10.0.0.7/32'] },
      { field: 'user_agent', operator: 'regex', values: ['(?i)python'] },
    ])
  }, 20_000)
})

describe('SecurityPoliciesPage WAF quick block (G3-d #13)', () => {
  it('hides the system-managed quick block rules in the editor and does not send them back', async () => {
    const actor = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const waf: SecurityPolicy = {
      ...policy, kind: 'waf', name: 'Site WAF', version: 3,
      rules: [
        { id: '00000000-0001-5abc-8def-0123456789ab', name: 'quick-block:idc', priority: 1, enabled: true,
          conditions: [{ field: 'ip_tag', operator: 'in', values: ['idc:global'] }], action: 'block', flow: 'continue', action_config: {} },
        ...policy.rules,
      ],
      quick_block: { block_idc_cn: false, block_idc_global: true, carriers: [], allowed_crawlers: [] },
    }
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [waf], total: 1, page: 1, limit: 20 })
    const update = vi.spyOn(securityPoliciesApi, 'update').mockResolvedValue(waf)
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="waf" referenceLayout />, ['/site/waf-rule'])
    const row = (await screen.findByText(waf.name)).closest('tr')!
    // The list is not left loading by the CC-only rule group query (disabled here).
    await waitFor(() => expect(document.querySelector('.ant-spin-blur')).toBeNull())
    await user.click(within(row).getByRole('button', { name: '编辑' }))
    const editor = await screen.findByRole('dialog')
    expect(within(editor).getByText(/本规则库开启了快速屏蔽/)).toBeInTheDocument()
    expect(within(editor).queryByDisplayValue('quick-block:idc')).not.toBeInTheDocument()
    await user.click(within(editor).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(update).toHaveBeenCalled())
    const sent = update.mock.calls[0][3] as { rules: Array<{ id?: string }> }
    expect(sent.rules.map((rule) => rule.id)).toEqual([policy.rules[0]!.id])
  }, 20_000)
})

describe('SecurityPoliciesPage WAF editor', () => {
  it('drafts a new WAF policy from the system default and sends ban, filters and waf_settings', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    const defaultRule = {
      name: 'SQL 注入', priority: 1, enabled: true, action: 'block' as const, flow: 'stop' as const, action_config: {},
      conditions: [{ field: 'args' as const, operator: 'detect', values: ['sqli'], filters: ['lowercase' as const] }],
    }
    const catalog = vi.spyOn(securityPoliciesApi, 'catalogRules').mockResolvedValue({
      rules: [defaultRule],
      default: { enabled: true, rules: [defaultRule], waf_settings: { auto_block: { window_seconds: 60, hit_threshold: 5, block_seconds: 300 } } },
    })
    const create = vi.spyOn(securityPoliciesApi, 'create').mockResolvedValue({ ...policy, kind: 'waf' })
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="waf" />, ['/site/waf'])

    expect(await screen.findByText('暂无安全规则集')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '添加规则集' }))
    const dialog = getDialog('添加安全规则集')
    await user.click(within(dialog).getByRole('button', { name: '使用系统默认 WAF' }))
    await waitFor(() => expect(catalog).toHaveBeenCalledWith(expect.any(String), 'waf', ['@system-default']))
    expect(await within(dialog).findByDisplayValue('SQL 注入')).toBeInTheDocument()
    expect(within(dialog).getByRole('switch', { name: 'WAF 命中自动封禁' })).toBeChecked()
    await user.type(within(dialog).getByLabelText('名称'), 'Default WAF')
    // Remove the empty starter rule; the imported rule replaces it.
    await waitFor(() => expect(within(dialog).queryByTestId('rule-1')).toBeNull())
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(create).toHaveBeenCalled())
    const sent = create.mock.calls[0][1]
    expect(sent.waf_settings).toEqual({ mode: '', auto_block: { window_seconds: 60, hit_threshold: 5, block_seconds: 300 } })
    expect(sent.rules).toHaveLength(1)
    expect(sent.rules[0]!.conditions[0]).toMatchObject({ field: 'args', operator: 'detect', values: ['sqli'], filters: ['lowercase'] })
    expect(sent.rules[0]!.conditions[0]!.key).toBeUndefined()
  }, 20_000)

  it('offers the temporary ban action, length fields and observe mode on WAF rules', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    const create = vi.spyOn(securityPoliciesApi, 'create').mockResolvedValue({ ...policy, kind: 'waf' })
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="waf" />, ['/site/waf'])

    expect(await screen.findByText('暂无安全规则集')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '添加规则集' }))
    const dialog = getDialog('添加安全规则集')
    await user.type(within(dialog).getByLabelText('名称'), 'Ban long bodies')
    await user.type(within(dialog).getByLabelText('规则名称'), 'Long body')
    const selects = within(dialog).getAllByRole('combobox')
    const pick = async (combobox: HTMLElement, label: string) => {
      fireEvent.mouseDown(combobox)
      await user.click((await screen.findAllByText(label)).at(-1)!)
    }
    await pick(selects.find((element) => element.closest('.ant-form-item')?.textContent?.includes('运行模式'))!, '观察（只记录不拦截）')
    await pick(within(dialog).getByRole('combobox', { name: '动作' }), '临时封禁')
    expect(await within(dialog).findByLabelText('封禁时长（秒）')).toHaveValue('600')
    await pick(within(dialog).getByRole('combobox', { name: '匹配字段' }), '请求体长度')
    await waitFor(() => expect(within(dialog).getByRole('switch', { name: '请求体超过 64KB 时视为命中' })).toBeInTheDocument())
    await user.click(within(dialog).getByRole('switch', { name: '请求体超过 64KB 时视为命中' }))
    await user.type(within(dialog).getByLabelText('匹配值'), '1000')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(create).toHaveBeenCalled())
    const sent = create.mock.calls[0][1]
    expect(sent.waf_settings).toEqual({ mode: 'observe', auto_block: undefined })
    expect(sent.rules[0]).toMatchObject({ action: 'ban', action_config: { waf_ban: { ban_seconds: 600 } } })
    expect(sent.rules[0]!.conditions[0]).toMatchObject({ field: 'body_length', operator: 'number_gt', values: ['1000'], body_overflow: 'match' })
  }, 20_000)

  it('picks an IP list for an "IP list" condition', async () => {
    authenticate()
    const listID = '55555555-5555-4555-8555-555555555555'
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    const create = vi.spyOn(securityPoliciesApi, 'create').mockResolvedValue({ ...policy, kind: 'waf' })
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ items: [{
      id: listID, name: 'scanners', description: '', entries: ['192.0.2.0/24'], revision: 1, platform: true,
      updated_at: '2026-10-21T00:00:00Z' }] }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="waf" />, ['/site/waf'])

    expect(await screen.findByText('暂无安全规则集')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '添加规则集' }))
    const dialog = getDialog('添加安全规则集')
    expect(within(dialog).getByText(/IP 名单条件需要节点支持 WAF v4/)).toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('名称'), 'Block scanners')
    await user.type(within(dialog).getByLabelText('规则名称'), 'Scanners')
    const pick = async (combobox: HTMLElement, label: string) => {
      fireEvent.mouseDown(combobox)
      await user.click((await screen.findAllByText(label)).at(-1)!)
    }
    await pick(within(dialog).getByRole('combobox', { name: '匹配字段' }), 'IP 名单')
    await pick(within(dialog).getByRole('combobox', { name: '运算符' }), '不在 IP 名单中')
    await pick(await within(dialog).findByRole('combobox', { name: 'IP 名单' }), 'scanners (1)')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(create).toHaveBeenCalled())
    expect(create.mock.calls[0][1].rules[0]!.conditions[0]).toMatchObject({ field: 'ip_list', operator: 'not_in_ip_list', values: [listID] })
    expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith('/v1/security-ip-lists'))).toBe(true)
  }, 20_000)
  it.each([
    { label: '内容类型 (Content-Type)', operator: 'prefix', value: 'application/json', field: 'content_type' },
    { label: 'HTTP 版本', operator: 'not_equals', value: '2', field: 'http_version' },
    // Node WAF v5
    { label: 'Multipart 表单字段名', operator: 'equals', value: 'PHP_SESSION_UPLOAD_PROGRESS', field: 'multipart_field_names' },
    { label: 'Multipart 分段数', operator: 'number_gt', value: '1000', field: 'multipart_part_count' },
    { label: 'Multipart 最长字段长度', operator: 'number_gt', value: '1048576', field: 'multipart_field_max_length' },
  ])('sends a $field condition', async ({ label, operator, value, field }) => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    const create = vi.spyOn(securityPoliciesApi, 'create').mockResolvedValue({ ...policy, kind: 'waf' })
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ items: [] }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }))
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="waf" />, ['/site/waf'])

    expect(await screen.findByText('暂无安全规则集')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '添加规则集' }))
    const dialog = getDialog('添加安全规则集')
    await user.type(within(dialog).getByLabelText('名称'), `By ${field}`)
    await user.type(within(dialog).getByLabelText('规则名称'), field)
    const pick = async (combobox: HTMLElement, text: string) => {
      fireEvent.mouseDown(combobox)
      await user.click((await screen.findAllByText(text)).at(-1)!)
    }
    await pick(within(dialog).getByRole('combobox', { name: '匹配字段' }), label)
    // ui-errmsg-1024: operators are listed by their Chinese label.
    await pick(within(dialog).getByRole('combobox', { name: '运算符' }), i18n.t(`securityPolicies:operatorsMap.${operator}`))
    // Pasted: typing a 27-character field name key by key outran the timeout under load.
    await user.click(within(dialog).getByLabelText('匹配值'))
    await user.paste(value)
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(create).toHaveBeenCalled())
    expect(create.mock.calls[0][1].rules[0]!.conditions[0]).toMatchObject({ field, operator, values: [value] })
  }, 20_000)
})

describe('security policy modal validation failures (ui-click F2)', () => {
  it('keeps a failed evaluation validation local without an unhandled rejection or request', async () => {
    const tenant = principal({ permissions: ['security_policies.read'] })
    useSessionStore.getState().setSession(authResponse(tenant), tenant)
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    const evaluate = vi.spyOn(securityPoliciesApi, 'evaluate')
    const rejections: unknown[] = []
    const onRejection = (reason: unknown) => { rejections.push(reason) }
    process.on('unhandledRejection', onRejection)
    try {
      const user = userEvent.setup()
      renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])
      expect(await screen.findByText(policy.name)).toBeInTheDocument()
      await user.click(within(screen.getByText(policy.name).closest('tr')!).getByRole('button', { name: '更多' }))
      await user.click(await screen.findByRole('menuitem', { name: '评估' }))
      const dialog = await findDialog('策略评估预览')
      await user.clear(within(dialog).getByLabelText('路径'))
      await user.click(within(dialog).getByRole('button', { name: '评估' }))
      await waitFor(() => expect(dialog.querySelector('.ant-form-item-explain-error')).not.toBeNull())
      await new Promise((resolve) => setTimeout(resolve, 0))
      expect(rejections).toEqual([])
      expect(evaluate).not.toHaveBeenCalled()
    } finally {
      process.off('unhandledRejection', onRejection)
    }
  })
})
