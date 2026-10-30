import { useEffect } from 'react'
import { type QueryClient, useQueryClient } from '@tanstack/react-query'
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import { challengePoliciesApi, type ChallengePolicy } from '../api/challengePolicies'
import { securityPoliciesApi } from '../api/securityPolicies'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import SecurityPoliciesPage from '../pages/SecurityPoliciesPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// antd 测试环境所有 Modal 的 aria-labelledby 都是 test-id，可访问名取的是 DOM 里第一个 test-id（常是反馈弹窗标题）；
// 业务弹窗按自身标题匹配，并排除反馈弹窗（.cdnca-feedback）
const pageDialogs = (name?: string) => screen.queryAllByRole('dialog')
  .filter((element) => !element.classList.contains('cdnca-feedback'))
  .filter((element) => name === undefined || element.querySelector('.ant-modal-title, .ant-drawer-title')?.textContent?.trim() === name)
const pageDialog = (name: string) => { const [element] = pageDialogs(name); if (!element) throw new Error(`no dialog ${name}`); return element }

// 结果未知改为 OutcomeUnknown 后，弹窗标题与原位恢复条（或表单内 Alert）同文案；断言原位提示
const OUTCOME_BAR = '.ant-alert-message'

const scopeID = '22222222-2222-4222-8222-222222222222'
const otherScopeID = '66666666-6666-4666-8666-666666666666'
const host253 = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`
const host254 = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(62)}`
const policy: ChallengePolicy = {
  id: '44444444-4444-4444-8444-444444444444',
  tenant_scope_id: scopeID,
  site_id: '33333333-3333-4333-8333-333333333333',
  host: 'app.example.com',
  priority: 100,
  mode: 'click',
  min_delay_seconds: 0,
  challenge_ttl_seconds: 60,
  pass_ttl_seconds: 900,
  clock_skew_seconds: 5,
  attempts_per_nonce: 1,
  failure_window_seconds: 60,
  max_failures_per_window: 5,
  ip_binding: 'exact',
  bind_user_agent: true,
  bypass_routes: [{ kind: 'prefix', path: '/health/' }],
  key_reference_configured: true,
  external_provider_configured: false,
  enabled: true,
  deleted: false,
  revision: 3,
  created_at: '2026-08-01T08:00:00Z',
  updated_at: '2026-08-01T09:00:00Z',
}

function authenticate(permissions: string[], scopeKind: 'tenant' | 'platform' = 'tenant') {
  const user = principal({
    permissions,
    scope_kind: scopeKind,
    tenant_id: scopeKind === 'tenant' ? scopeID : null,
  })
  useSessionStore.getState().setSession(authResponse(user), user)
}

function QueryClientCapture({ onCapture }: { onCapture: (client: QueryClient) => void }) {
  const client = useQueryClient()
  useEffect(() => onCapture(client), [client, onCapture])
  return null
}

function serializedMutationCache(queryClient: QueryClient): string {
  return JSON.stringify(queryClient.getMutationCache().getAll().map((mutation) => mutation.state))
}

function flattenedStrings(value: unknown, prefix = ''): Array<[string, string]> {
  if (typeof value === 'string') return [[prefix, value]]
  if (!value || typeof value !== 'object') return []
  return Object.entries(value).flatMap(([key, item]) => flattenedStrings(item, prefix ? `${prefix}.${key}` : key))
}

// 规则组页「更多」下拉（参考布局为“批量操作”，无权限视图为“更多”）里的「挑战策略」。
async function openChallengeView(user: ReturnType<typeof userEvent.setup>) {
  const more = await screen.findByRole('button', { name: /^(更多|批量操作)/ })
  await user.click(more)
  await user.click(await screen.findByRole('menuitem', { name: '挑战策略' }))
}

describe('ChallengePoliciesPanel', () => {
  it('keeps the original CC tab and isolates each read permission and query', async () => {
    authenticate(['challenge_policies.read'])
    const securityList = vi.spyOn(securityPoliciesApi, 'list')
    const challengeList = vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [policy] })
    const user = userEvent.setup()

    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    // 2026-08 起挑战策略不再是 CC 页的标签，而是「更多 > 挑战策略」打开的子视图（?view=challenge）。
    expect(screen.getByRole('tab', { name: '规则组' })).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: '挑战策略' })).not.toBeInTheDocument()
    expect(securityList).not.toHaveBeenCalled()
    await openChallengeView(user)
    expect(await screen.findByText('app.example.com')).toBeInTheDocument()
    expect(challengeList).toHaveBeenCalledWith(expect.any(String), scopeID, expect.objectContaining({ limit: 20 }), expect.any(AbortSignal))
    expect(securityList).not.toHaveBeenCalled()
  })

  it('does not query either protected resource without its corresponding read permission', async () => {
    authenticate([])
    const securityList = vi.spyOn(securityPoliciesApi, 'list')
    const challengeList = vi.spyOn(challengePoliciesApi, 'list')
    const user = userEvent.setup()

    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    expect(await screen.findByText(i18n.t('securityPolicies:errors.permission_denied'))).toBeInTheDocument()
    expect(securityList).not.toHaveBeenCalled()
    await openChallengeView(user)
    expect(await screen.findByText('当前账号缺少挑战策略查看权限。')).toBeInTheDocument()
    expect(challengeList).not.toHaveBeenCalled()
  })

  it('requires an explicit platform target and never substitutes the platform scope', async () => {
    authenticate(['challenge_policies.read'], 'platform')
    const list = vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [] })
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    await openChallengeView(user)
    expect(await screen.findByText('请先选择要管理的租户作用域。')).toBeInTheDocument()
    expect(list).not.toHaveBeenCalled()
    await user.type(screen.getByLabelText('目标租户作用域'), scopeID)
    await user.click(screen.getByRole('button', { name: '应用目标' }))
    await waitFor(() => expect(list).toHaveBeenCalledWith(expect.any(String), scopeID, expect.any(Object), expect.any(AbortSignal)))
  })

  it('aborts an in-flight list on live read revocation, drops its late result, and refetches after restore', async () => {
    authenticate(['challenge_policies.read'])
    let queryClient!: QueryClient
    let firstSignal: AbortSignal | undefined
    let resolveFirst!: (value: { items: ChallengePolicy[] }) => void
    let resolveRestored!: (value: { items: ChallengePolicy[] }) => void
    const list = vi.spyOn(challengePoliciesApi, 'list').mockImplementation((_token, _scope, _filters, signal) => {
      if (!firstSignal) {
        firstSignal = signal
        return new Promise((resolve) => { resolveFirst = resolve })
      }
      return new Promise((resolve) => { resolveRestored = resolve })
    })
    const capture = (client: QueryClient) => { queryClient = client }
    const user = userEvent.setup()
    renderWithProviders(<>
      <SecurityPoliciesPage kind="cc" />
      <QueryClientCapture onCapture={capture} />
    </>, ['/site/cc-rule'])
    await openChallengeView(user)
    await waitFor(() => expect(firstSignal).toBeInstanceOf(AbortSignal))

    act(() => useSessionStore.setState((state) => ({
      principal: state.principal ? { ...state.principal, permissions: [] } : null,
    })))
    await waitFor(() => expect(firstSignal?.aborted).toBe(true))
    await act(async () => resolveFirst({ items: [{ ...policy, host: 'revoked.example.com' }] }))
    expect(queryClient.getQueryCache().findAll({ queryKey: ['challenge-policies'] })
      .every((entry) => entry.state.data === undefined)).toBe(true)
    expect(screen.queryByText('revoked.example.com')).not.toBeInTheDocument()

    act(() => useSessionStore.setState((state) => ({
      principal: state.principal ? { ...state.principal, permissions: ['challenge_policies.read'] } : null,
    })))
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2))
    await act(async () => resolveRestored({ items: [policy] }))
    expect(await screen.findByText('app.example.com')).toBeInTheDocument()
    expect(list.mock.calls[1][3]).not.toBe(firstSignal)
  })

  it('renders compact policy facts, cursor navigation, and no secret/provider reference values', async () => {
    authenticate(['challenge_policies.read'])
    const list = vi.spyOn(challengePoliciesApi, 'list')
      .mockResolvedValueOnce({ items: [policy], next_cursor: 'next-opaque' })
      .mockResolvedValueOnce({ items: [{ ...policy, id: '55555555-5555-4555-8555-555555555555', host: 'next.example.com' }] })
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])
    await openChallengeView(user)

    expect(await screen.findByText('app.example.com')).toBeInTheDocument()
    expect(screen.getByText('点击验证')).toBeInTheDocument()
    expect(screen.getByText('IP + User-Agent')).toBeInTheDocument()
    expect(screen.queryByText('keyref:challenge-primary')).not.toBeInTheDocument()
    expect(screen.queryByText('geetest-v4')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('next.example.com')).toBeInTheDocument()
    expect(list.mock.calls[1][2]).toEqual(expect.objectContaining({ cursor: 'next-opaque' }))
    await user.click(screen.getByRole('button', { name: '上一页' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[2].cursor).toBeUndefined())
  })

  it('keeps manage controls absent and makes zero write calls when manage is missing', async () => {
    authenticate(['challenge_policies.read'])
    vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [policy] })
    const create = vi.spyOn(challengePoliciesApi, 'create')
    const update = vi.spyOn(challengePoliciesApi, 'update')
    const remove = vi.spyOn(challengePoliciesApi, 'remove')
    const enable = vi.spyOn(challengePoliciesApi, 'enable')
    const disable = vi.spyOn(challengePoliciesApi, 'disable')
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])
    await openChallengeView(user)

    expect(await screen.findByText('app.example.com')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新建挑战策略' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '编辑 app.example.com' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '停用 app.example.com' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '删除 app.example.com' })).not.toBeInTheDocument()
    expect([create, update, remove, enable, disable].every((spy) => spy.mock.calls.length === 0)).toBe(true)
  })

  it('rechecks live manage permission before submit and makes zero writes after revocation', async () => {
    authenticate(['challenge_policies.read', 'challenge_policies.manage'])
    vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [] })
    const create = vi.spyOn(challengePoliciesApi, 'create')
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])
    await openChallengeView(user)
    await user.click(await screen.findByRole('button', { name: '新建挑战策略' }))
    const dialog = screen.getByRole('dialog', { name: '新建挑战策略' })
    await user.type(within(dialog).getByLabelText('站点 ID'), policy.site_id)
    await user.type(within(dialog).getByLabelText('主机名'), policy.host)
    await user.type(within(dialog).getByLabelText('密钥引用'), 'keyref:challenge-primary')

    act(() => {
      useSessionStore.setState((state) => ({
        principal: state.principal ? { ...state.principal, permissions: ['challenge_policies.read'] } : null,
      }))
    })
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(create).not.toHaveBeenCalled()
  })

  it('requires write-only external references again when editing an external policy', async () => {
    authenticate(['challenge_policies.read', 'challenge_policies.manage'])
    const externalPolicy: ChallengePolicy = {
      ...policy,
      mode: 'external',
      external_provider_configured: true,
    }
    vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [externalPolicy] })
    const update = vi.spyOn(challengePoliciesApi, 'update').mockResolvedValue({ ...externalPolicy, revision: 4 })
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])
    await openChallengeView(user)
    await user.click(await screen.findByRole('button', { name: '编辑 app.example.com' }))
    const dialog = screen.getByRole('dialog', { name: '编辑挑战策略' })

    expect(within(dialog).queryByText('极验 v4')).not.toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('密钥引用'), 'keyref:challenge-primary')
    const ttl = within(dialog).getByLabelText('挑战有效期（秒）')
    await user.clear(ttl)
    await user.type(ttl, '61')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(update).not.toHaveBeenCalled()

    await user.click(within(dialog).getByLabelText('外部提供商'))
    await user.click(await screen.findByText('腾讯云验证码'))
    await user.type(within(dialog).getByLabelText('应用引用'), 'appref:tencent-primary')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))

    await waitFor(() => expect(update).toHaveBeenCalledTimes(1))
    expect(update.mock.calls[0][4]).toMatchObject({
      mode: 'external',
      challenge_ttl_seconds: 61,
      external_provider: { provider: 'tencent', app_reference: 'appref:tencent-primary' },
    })
  })

  it('accepts a 253-byte ASCII hostname and blocks 254 bytes before create', async () => {
    authenticate(['challenge_policies.read', 'challenge_policies.manage'])
    vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [] })
    const create = vi.spyOn(challengePoliciesApi, 'create').mockResolvedValue({ ...policy, host: host253, revision: 1 })
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])
    await openChallengeView(user)
    await user.click(await screen.findByRole('button', { name: '新建挑战策略' }))
    const dialog = screen.getByRole('dialog', { name: '新建挑战策略' })
    await user.type(within(dialog).getByLabelText('站点 ID'), policy.site_id)
    await user.type(within(dialog).getByLabelText('主机名'), host254)
    await user.type(within(dialog).getByLabelText('密钥引用'), 'keyref:challenge-primary')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(await within(dialog).findByText('请输入规范的小写主机名')).toBeInTheDocument()
    expect(create).not.toHaveBeenCalled()

    const host = within(dialog).getByLabelText('主机名')
    await user.clear(host)
    await user.type(host, host253)
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(create.mock.calls[0][2].host).toBe(host253)
  })

  it('enforces exact TTL, key-reference, bypass-count, uniqueness, and path-length boundaries locally', async () => {
    authenticate(['challenge_policies.read', 'challenge_policies.manage'])
    vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [] })
    const create = vi.spyOn(challengePoliciesApi, 'create').mockResolvedValue({ ...policy, revision: 1 })
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])
    await openChallengeView(user)
    await user.click(await screen.findByRole('button', { name: '新建挑战策略' }))
    const dialog = screen.getByRole('dialog', { name: '新建挑战策略' })
    await user.type(within(dialog).getByLabelText('站点 ID'), policy.site_id)
    await user.type(within(dialog).getByLabelText('主机名'), policy.host)
    await user.type(within(dialog).getByLabelText('密钥引用'), 'kms:a')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(await within(dialog).findByText('请输入有效的密钥引用')).toBeInTheDocument()
    expect(create).not.toHaveBeenCalled()

    const keyReference = within(dialog).getByLabelText('密钥引用')
    await user.clear(keyReference)
    await user.type(keyReference, 'keyref:a')
    const challengeTTL = within(dialog).getByLabelText('挑战有效期（秒）')
    const clockSkew = within(dialog).getByLabelText('时钟偏差（秒）')
    await user.clear(challengeTTL)
    await user.type(challengeTTL, '10')
    await user.clear(clockSkew)
    await user.type(clockSkew, '10')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(await within(dialog).findByText('挑战有效期必须大于最短延迟与时钟偏差之和')).toBeInTheDocument()
    expect(create).not.toHaveBeenCalled()

    await user.clear(challengeTTL)
    await user.type(challengeTTL, '11')
    const bypass = within(dialog).getByLabelText('绕过路径')
    fireEvent.change(bypass, { target: { value: Array.from({ length: 33 }, (_, index) => `exact /route-${index}`).join('\n') } })
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(await within(dialog).findByText('绕过路径必须使用“exact /path”或“prefix /path/”格式')).toBeInTheDocument()
    expect(create).not.toHaveBeenCalled()

    fireEvent.change(bypass, { target: { value: 'exact /same/\nprefix /same/' } })
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(create).not.toHaveBeenCalled()

    fireEvent.change(bypass, { target: { value: `exact /${'a'.repeat(512)}` } })
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(create).not.toHaveBeenCalled()

    const longestValidPath = `/${'a'.repeat(511)}`
    const validRoutes = [
      `exact ${longestValidPath}`,
      ...Array.from({ length: 31 }, (_, index) => `exact /valid-${index}`),
    ].join('\n')
    fireEvent.change(bypass, { target: { value: validRoutes } })
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(create.mock.calls[0][2].config).toMatchObject({
      challenge_ttl_seconds: 11,
      clock_skew_seconds: 10,
      key_reference: 'keyref:a',
    })
    expect(create.mock.calls[0][2].config.bypass_routes).toHaveLength(32)
  })

  it('keeps target, filters, cursor, editor, and token-free cache identity across a same-epoch token refresh', async () => {
    const platform = principal({
      user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      scope_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      scope_kind: 'platform',
      tenant_id: null,
      permissions: ['challenge_policies.read', 'challenge_policies.manage'],
      roles: ['platform_admin'],
    })
    useSessionStore.getState().setSession({ ...authResponse(platform), access_token: 'challenge-token-a' }, platform)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const ownerKey = JSON.stringify([
      platform.scope_kind, platform.scope_id, platform.tenant_id, platform.user_id, sessionEpoch,
    ])
    const list = vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [policy], next_cursor: 'opaque-next' })
    let queryClient!: QueryClient
    const capture = (client: QueryClient) => { queryClient = client }
    const user = userEvent.setup()
    renderWithProviders(<>
      <SecurityPoliciesPage kind="cc" />
      <QueryClientCapture onCapture={capture} />
    </>, ['/site/cc-rule'])
    await openChallengeView(user)
    await user.type(screen.getByLabelText('目标租户作用域'), scopeID)
    await user.click(screen.getByRole('button', { name: '应用目标' }))
    await waitFor(() => expect(list).toHaveBeenCalled())
    const siteFilter = screen.getByPlaceholderText('站点 ID')
    await user.type(siteFilter, policy.site_id)
    await user.click(screen.getByRole('button', { name: '筛选' }))
    await user.click(await screen.findByRole('button', { name: '下一页' }))
    await user.click(screen.getByRole('button', { name: '新建挑战策略' }))
    const dialog = screen.getByRole('dialog', { name: '新建挑战策略' })
    await user.type(within(dialog).getByLabelText('密钥引用'), 'keyref:must-stay')
    const readsBeforeRefresh = list.mock.calls.length

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(platform), access_token: 'challenge-token-b' },
        platform,
        'refresh',
      )
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(list).toHaveBeenCalledTimes(readsBeforeRefresh)
    expect(screen.getByLabelText('目标租户作用域')).toHaveValue(scopeID)
    expect(siteFilter).toHaveValue(policy.site_id)
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    expect(screen.getByRole('dialog', { name: '新建挑战策略' })).toBe(dialog)
    expect(within(dialog).getByLabelText('密钥引用')).toHaveValue('keyref:must-stay')

    const queryKeys = queryClient.getQueryCache().getAll().map((entry) => entry.queryKey)
    expect(queryKeys).toContainEqual([
      'challenge-policies', ownerKey, scopeID, 20, 'opaque-next', { site_id: policy.site_id },
    ])
    const serializedKeys = queryKeys.map((key) => JSON.stringify(key)).join('\n')
    expect(serializedKeys).not.toContain('challenge-token-a')
    expect(serializedKeys).not.toContain('challenge-token-b')
  })

  it('clears every scope-bound state when a platform operator switches targets', async () => {
    authenticate(['challenge_policies.read', 'challenge_policies.manage'], 'platform')
    const list = vi.spyOn(challengePoliciesApi, 'list').mockImplementation(async (_token, target) => ({
      items: [{
        ...policy,
        tenant_scope_id: target,
        host: target === scopeID ? 'scope-a.example.com' : 'scope-b.example.com',
      }],
      ...(target === scopeID ? { next_cursor: 'next-opaque' } : {}),
    }))
    const create = vi.spyOn(challengePoliciesApi, 'create')
      .mockRejectedValue(new ApiError('invalid response', 502, 'invalid_response'))
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])
    await openChallengeView(user)
    await user.type(screen.getByLabelText('目标租户作用域'), scopeID)
    await user.click(screen.getByRole('button', { name: '应用目标' }))
    expect(await screen.findByText('scope-a.example.com')).toBeInTheDocument()
    await user.type(screen.getByLabelText('站点 ID'), policy.site_id)
    await user.type(screen.getByLabelText('主机名'), policy.host)
    await user.click(screen.getByRole('button', { name: '筛选' }))
    await user.click(await screen.findByRole('button', { name: '下一页' }))
    await user.click(screen.getByRole('button', { name: '新建挑战策略' }))
    const dialog = screen.getByRole('dialog', { name: '新建挑战策略' })
    await user.type(within(dialog).getByLabelText('站点 ID'), policy.site_id)
    await user.type(within(dialog).getByLabelText('主机名'), policy.host)
    await user.type(within(dialog).getByLabelText('密钥引用'), 'keyref:scope-a-secret')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeInTheDocument()
    // 结果待确认的说明弹窗在进场动画结束时才抢焦点；负载高时会落在下面 type 的点击之后把按键吞掉，先等它拿到焦点。
    await waitFor(() => expect(document.activeElement?.closest('.cdnca-feedback')).not.toBeNull())

    const target = screen.getByLabelText('目标租户作用域')
    await user.clear(target)
    await user.type(target, otherScopeID)
    await user.click(screen.getByRole('button', { name: '应用目标' }))

    expect(await screen.findByText('scope-b.example.com')).toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.getByLabelText('站点 ID')).toHaveValue('')
    expect(screen.getByLabelText('主机名')).toHaveValue('')
    expect(screen.getByText('第 1 页')).toBeInTheDocument()
    expect(list.mock.calls.at(-1)?.[1]).toBe(otherScopeID)
    expect(list.mock.calls.at(-1)?.[2]).toEqual({ limit: 20, cursor: undefined })
    expect(create).toHaveBeenCalledTimes(1)
    expect(create.mock.calls[0][1]).toBe(scopeID)

    await user.click(screen.getByRole('button', { name: '新建挑战策略' }))
    expect(within(screen.getByRole('dialog', { name: '新建挑战策略' })).getByLabelText('密钥引用')).toHaveValue('')
  })

  it('keeps write-only references out of MutationCache and clears a pending write on unmount', async () => {
    authenticate(['challenge_policies.read', 'challenge_policies.manage'])
    vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [] })
    let resolveCreate!: (value: ChallengePolicy) => void
    const pendingCreate = new Promise<ChallengePolicy>((resolve) => { resolveCreate = resolve })
    const create = vi.spyOn(challengePoliciesApi, 'create').mockReturnValue(pendingCreate)
    let queryClient!: QueryClient
    const capture = (client: QueryClient) => { queryClient = client }
    const user = userEvent.setup()
    const rendered = renderWithProviders(<>
      <SecurityPoliciesPage kind="cc" />
      <QueryClientCapture onCapture={capture} />
    </>, ['/site/cc-rule'])
    await openChallengeView(user)
    await user.click(await screen.findByRole('button', { name: '新建挑战策略' }))
    const dialog = screen.getByRole('dialog', { name: '新建挑战策略' })
    await user.type(within(dialog).getByLabelText('站点 ID'), policy.site_id)
    await user.type(within(dialog).getByLabelText('主机名'), policy.host)
    await user.type(within(dialog).getByLabelText('密钥引用'), 'keyref:mutation-cache-secret')
    await user.click(within(dialog).getByLabelText('挑战模式'))
    await user.click(await screen.findByText('外部验证'))
    await user.click(within(dialog).getByLabelText('外部提供商'))
    await user.click(await screen.findByText('腾讯云验证码'))
    await user.type(within(dialog).getByLabelText('应用引用'), 'appref:mutation-cache-secret')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))

    expect(serializedMutationCache(queryClient)).not.toContain('keyref:mutation-cache-secret')
    expect(serializedMutationCache(queryClient)).not.toContain('appref:mutation-cache-secret')
    rendered.unmount()
    await act(async () => {
      resolveCreate({ ...policy, mode: 'external', external_provider_configured: true, revision: 1 })
      await pendingCreate
    })
    await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0))
  })

  it.each([
    ['success', null],
    ['error', new ApiError('old target failed', 502, 'invalid_response')],
  ])('ignores a delayed old-target %s callback after switching A to B', async (outcome, oldError) => {
    authenticate(['challenge_policies.read', 'challenge_policies.manage'], 'platform')
    vi.spyOn(challengePoliciesApi, 'list').mockImplementation(async (_token, target) => ({
      items: [{
        ...policy,
        tenant_scope_id: target,
        host: target === scopeID ? 'scope-a.example.com' : 'scope-b.example.com',
      }],
    }))
    let resolveCreate!: (value: ChallengePolicy) => void
    let rejectCreate!: (reason: unknown) => void
    const pendingCreate = new Promise<ChallengePolicy>((resolve, reject) => {
      resolveCreate = resolve
      rejectCreate = reject
    })
    const create = vi.spyOn(challengePoliciesApi, 'create').mockReturnValue(pendingCreate)
    let queryClient!: QueryClient
    const capture = (client: QueryClient) => { queryClient = client }
    const user = userEvent.setup()
    renderWithProviders(<>
      <SecurityPoliciesPage kind="cc" />
      <QueryClientCapture onCapture={capture} />
    </>, ['/site/cc-rule'])
    await openChallengeView(user)
    await user.type(screen.getByLabelText('目标租户作用域'), scopeID)
    await user.click(screen.getByRole('button', { name: '应用目标' }))
    expect(await screen.findByText('scope-a.example.com')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '新建挑战策略' }))
    const dialog = screen.getByRole('dialog', { name: '新建挑战策略' })
    await user.type(within(dialog).getByLabelText('站点 ID'), policy.site_id)
    await user.type(within(dialog).getByLabelText('主机名'), policy.host)
    await user.type(within(dialog).getByLabelText('密钥引用'), 'keyref:old-target-secret')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    const oldMutation = queryClient.getMutationCache().getAll().find((entry) => entry.state.status === 'pending')
    expect(oldMutation).toBeDefined()
    expect(serializedMutationCache(queryClient)).not.toContain('keyref:old-target-secret')

    const target = screen.getByLabelText('目标租户作用域')
    await user.clear(target)
    await user.type(target, otherScopeID)
    expect(screen.getByRole('button', { name: '应用目标' })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: '应用目标' }))
    expect(await screen.findByText('scope-b.example.com')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新建挑战策略' })).toBeEnabled()
    expect(serializedMutationCache(queryClient)).not.toContain('keyref:old-target-secret')

    await act(async () => {
      if (oldError) rejectCreate(oldError)
      else resolveCreate({ ...policy, revision: 1 })
      await pendingCreate.catch(() => undefined)
    })
    await waitFor(() => expect(oldMutation?.state.status).toBe(outcome))
    expect(screen.getByText('scope-b.example.com')).toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(create).toHaveBeenCalledTimes(1)
  })

  it('cannot carry an unknown retry into another tenant session', async () => {
    const tenantA = principal({
      user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      scope_id: scopeID,
      tenant_id: scopeID,
      permissions: ['challenge_policies.read', 'challenge_policies.manage'],
    })
    const tenantBScope = '66666666-6666-4666-8666-666666666666'
    const tenantB = principal({
      user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      scope_id: tenantBScope,
      tenant_id: tenantBScope,
      permissions: ['challenge_policies.read', 'challenge_policies.manage'],
    })
    useSessionStore.getState().setSession({ ...authResponse(tenantA), access_token: 'tenant-a-token' }, tenantA)
    const tenantAEpoch = useSessionStore.getState().sessionEpoch
    const tenantAOwnerKey = JSON.stringify([
      tenantA.scope_kind, tenantA.scope_id, tenantA.tenant_id, tenantA.user_id, tenantAEpoch,
    ])
    let tenantAReads = 0
    let resolveLateTenantA!: (value: { items: ChallengePolicy[] }) => void
    const lateTenantA = new Promise<{ items: ChallengePolicy[] }>((resolve) => { resolveLateTenantA = resolve })
    vi.spyOn(challengePoliciesApi, 'list').mockImplementation(async (_token, requestedScope) => {
      if (requestedScope === scopeID) {
        tenantAReads += 1
        return tenantAReads === 1 ? { items: [] } : lateTenantA
      }
      return { items: [{ ...policy, tenant_scope_id: tenantBScope, host: 'tenant-b.example.com' }] }
    })
    const create = vi.spyOn(challengePoliciesApi, 'create').mockRejectedValue(new ApiError('unknown', 503, 'request_failed'))
    let queryClient!: QueryClient
    const capture = (client: QueryClient) => { queryClient = client }
    const user = userEvent.setup()
    renderWithProviders(<>
      <SecurityPoliciesPage kind="cc" />
      <QueryClientCapture onCapture={capture} />
    </>, ['/site/cc-rule'])
    await openChallengeView(user)
    await user.click(await screen.findByRole('button', { name: '新建挑战策略' }))
    const dialog = screen.getByRole('dialog', { name: '新建挑战策略' })
    await user.type(within(dialog).getByLabelText('站点 ID'), policy.site_id)
    await user.type(within(dialog).getByLabelText('主机名'), policy.host)
    await user.type(within(dialog).getByLabelText('密钥引用'), 'keyref:challenge-primary')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    const oldMutation = queryClient.getMutationCache().getAll().find((entry) => entry.state.status === 'error')
    expect(oldMutation).toBeDefined()
    expect(queryClient.getQueryCache().getAll().map((entry) => entry.queryKey))
      .toEqual(expect.arrayContaining([expect.arrayContaining(['challenge-policies', tenantAOwnerKey])]))
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(tenantAReads).toBe(2))

    act(() => useSessionStore.getState().setSession({ ...authResponse(tenantB), access_token: 'tenant-b-token' }, tenantB))

    await openChallengeView(user)
    expect(await screen.findByText('tenant-b.example.com')).toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(create).toHaveBeenCalledTimes(1)
    expect(queryClient.getMutationCache().getAll()).not.toContain(oldMutation)
    await waitFor(() => expect(queryClient.getQueryCache().getAll()
      .some((entry) => JSON.stringify(entry.queryKey).includes(tenantAOwnerKey))).toBe(false))

    await act(async () => {
      resolveLateTenantA({ items: [{ ...policy, host: 'late-tenant-a.example.com' }] })
      await lateTenantA
    })
    expect(screen.getByText('tenant-b.example.com')).toBeInTheDocument()
    expect(screen.queryByText('late-tenant-a.example.com')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '新建挑战策略' }))
    expect(within(screen.getByRole('dialog', { name: '新建挑战策略' })).getByLabelText('密钥引用')).toHaveValue('')
  })

  it('supports all modes and preserves an unknown write body and idempotency key for retry', async () => {
    const actor = principal({ permissions: ['challenge_policies.read', 'challenge_policies.manage'] })
    const oldToken = 'challenge-write-token-a'
    const newToken = 'challenge-write-token-b'
    useSessionStore.getState().setSession({ ...authResponse(actor), access_token: oldToken }, actor)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const ownerKey = JSON.stringify([
      actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, sessionEpoch,
    ])
    const list = vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [] })
    const create = vi.spyOn(challengePoliciesApi, 'create')
      .mockRejectedValueOnce(new ApiError('private upstream', 503, 'request_failed'))
      .mockResolvedValue(policy)
    let queryClient!: QueryClient
    const capture = (client: QueryClient) => { queryClient = client }
    const user = userEvent.setup()
    renderWithProviders(<>
      <SecurityPoliciesPage kind="cc" />
      <QueryClientCapture onCapture={capture} />
    </>, ['/site/cc-rule'])
    await openChallengeView(user)
    await user.click(await screen.findByRole('button', { name: '新建挑战策略' }))
    const dialog = screen.getByRole('dialog', { name: '新建挑战策略' })

    expect(within(dialog).getByText('点击验证')).toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('站点 ID'), policy.site_id)
    await user.type(within(dialog).getByLabelText('主机名'), policy.host)
    await user.type(within(dialog).getByLabelText('密钥引用'), 'keyref:challenge-primary')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))

    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(screen.queryByText('private upstream')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新建挑战策略' })).toBeDisabled()

    act(() => useSessionStore.setState((state) => ({
      principal: state.principal ? { ...state.principal, permissions: ['challenge_policies.read'] } : null,
    })))
    expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeDisabled()
    expect(create).toHaveBeenCalledTimes(1)

    act(() => useSessionStore.setState((state) => ({
      principal: state.principal ? { ...state.principal, permissions: ['challenge_policies.read', 'challenge_policies.manage'] } : null,
    })))
    expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeEnabled()
    const firstAttempt = create.mock.calls[0]
    const readsBeforeRefresh = list.mock.calls.length

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(actor), access_token: newToken },
        actor,
        'refresh',
      )
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(list).toHaveBeenCalledTimes(readsBeforeRefresh)
    expect(screen.getByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(pageDialog('新建挑战策略')).toBe(dialog)
    expect(within(dialog).getByLabelText('密钥引用')).toHaveValue('keyref:challenge-primary')
    expect(queryClient.getMutationCache().getAll().map((entry) => entry.options.mutationKey))
      .toContainEqual(['challenge-policies-write', ownerKey, scopeID])
    const serializedMutationKeys = JSON.stringify(
      queryClient.getMutationCache().getAll().map((entry) => entry.options.mutationKey),
    )
    expect(serializedMutationKeys).not.toContain(oldToken)
    expect(serializedMutationKeys).not.toContain(newToken)

    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[0][0]).toBe(oldToken)
    expect(create.mock.calls[1][0]).toBe(newToken)
    expect(create.mock.calls[1].slice(1)).toEqual(firstAttempt.slice(1))
  })

  it('removes every create, update, delete, enable, and disable entry point while manage is revoked, then restores them', async () => {
    authenticate(['challenge_policies.read', 'challenge_policies.manage'])
    const disabled = { ...policy, id: '55555555-5555-4555-8555-555555555555', host: 'off.example.com', enabled: false }
    vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [policy, disabled] })
    const writes = [
      vi.spyOn(challengePoliciesApi, 'create'),
      vi.spyOn(challengePoliciesApi, 'update'),
      vi.spyOn(challengePoliciesApi, 'remove'),
      vi.spyOn(challengePoliciesApi, 'enable'),
      vi.spyOn(challengePoliciesApi, 'disable'),
      vi.spyOn(challengePoliciesApi, 'publish'),
    ]
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])
    await openChallengeView(user)
    expect(await screen.findByText('off.example.com')).toBeInTheDocument()

    act(() => useSessionStore.setState((state) => ({
      principal: state.principal ? { ...state.principal, permissions: ['challenge_policies.read'] } : null,
    })))
    expect(screen.queryByRole('button', { name: '新建挑战策略' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '编辑 app.example.com' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '停用 app.example.com' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '启用 off.example.com' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '删除 app.example.com' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '发布 app.example.com' })).not.toBeInTheDocument()
    expect(writes.every((spy) => spy.mock.calls.length === 0)).toBe(true)

    act(() => useSessionStore.setState((state) => ({
      principal: state.principal ? { ...state.principal, permissions: ['challenge_policies.read', 'challenge_policies.manage'] } : null,
    })))
    expect(screen.getByRole('button', { name: '新建挑战策略' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '编辑 app.example.com' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '停用 app.example.com' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '启用 off.example.com' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '删除 app.example.com' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '发布 app.example.com' })).toBeInTheDocument()
    expect(writes.every((spy) => spy.mock.calls.length === 0)).toBe(true)
  })

  it('publishes an enabled policy and renders bounded node rollout state in Chinese', async () => {
    authenticate(['challenge_policies.read', 'challenge_policies.manage'])
    vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [policy] })
    const publish = vi.spyOn(challengePoliciesApi, 'publish').mockResolvedValue({
      policy_id: policy.id, policy_revision: policy.revision,
      rollout_id: '77777777-7777-4777-8777-777777777777',
      config_version_id: '88888888-8888-4888-8888-888888888888',
      state: 'running', reason: 'waiting_for_nodes', total: 2, pending: 1, running: 0,
      healthy: 1, failed: 0, cancelled: 0, superseded: 0,
    })
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])
    await openChallengeView(user)
    await user.click(await screen.findByRole('button', { name: '发布 app.example.com' }))
    await waitFor(() => expect(publish).toHaveBeenCalledWith(
      expect.any(String), scopeID, policy.id, policy.revision, expect.stringContaining('challenge-policy-update-'),
    ))
    expect(await screen.findByText('节点应用中')).toBeInTheDocument()
    expect(screen.getByText('1 / 2 节点健康')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '刷新 app.example.com 的发布状态' })).toBeInTheDocument()
  })

  it('shows nodes that ignored the secret as an old release apart from failures', async () => {
    authenticate(['challenge_policies.read', 'challenge_policies.manage'])
    vi.spyOn(challengePoliciesApi, 'list').mockResolvedValue({ items: [policy] })
    vi.spyOn(challengePoliciesApi, 'publish').mockResolvedValue({
      policy_id: policy.id, policy_revision: policy.revision,
      rollout_id: '77777777-7777-4777-8777-777777777777',
      config_version_id: '88888888-8888-4888-8888-888888888888',
      state: 'healthy', reason: '-', total: 3, pending: 0, running: 0,
      healthy: 2, failed: 0, cancelled: 0, superseded: 1,
    })
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])
    await openChallengeView(user)
    await user.click(await screen.findByRole('button', { name: '发布 app.example.com' }))
    expect(await screen.findByText('密钥已就绪')).toBeInTheDocument()
    expect(screen.getByText('2 / 3 节点健康')).toBeInTheDocument()
    expect(screen.getByText('已忽略旧发布 1')).toBeInTheDocument()
  })

  it('ships complete English and expanded pseudo-locale challenge-policy resources', () => {
    const zh = flattenedStrings(i18n.getResourceBundle('zh-CN', 'challengePolicies'))
    const en = flattenedStrings(i18n.getResourceBundle('en-US', 'challengePolicies'))
    const pseudo = flattenedStrings(i18n.getResourceBundle('qps-ploc', 'challengePolicies'))
    expect(en.map(([key]) => key)).toEqual(zh.map(([key]) => key))
    expect(pseudo.map(([key]) => key)).toEqual(zh.map(([key]) => key))
    expect(en.every(([, value]) => !/[\u3400-\u9fff]/u.test(value))).toBe(true)
    const enByKey = new Map(en)
    expect(pseudo.every(([key, value]) => value.length > (enByKey.get(key)?.length ?? 0))).toBe(true)
  })

  it('uses revision CAS for state changes and confines a server 403 to this panel', async () => {
    authenticate(['security_policies.read', 'challenge_policies.read', 'challenge_policies.manage'])
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    vi.spyOn(challengePoliciesApi, 'list').mockRejectedValue(new ApiError('raw denial', 403, 'permission_denied'))
    const disable = vi.spyOn(challengePoliciesApi, 'disable').mockResolvedValue({ ...policy, enabled: false, revision: 4 })
    const user = userEvent.setup()
    renderWithProviders(<SecurityPoliciesPage kind="cc" />, ['/site/cc-rule'])

    await openChallengeView(user)
    expect(await screen.findByText('当前账号缺少挑战策略查看权限。')).toBeInTheDocument()
    expect(screen.queryByText('raw denial')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '返回规则组' }))
    expect(await screen.findByText('暂无安全规则集')).toBeInTheDocument()
    expect(disable).not.toHaveBeenCalled()
  })
})
