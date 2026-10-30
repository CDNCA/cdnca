import { onlineManager, QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import { sitesApi, type SiteListItem } from '../api/sites'
import { urlAuthPoliciesApi, type URLAuthPolicy } from '../api/urlAuthPolicies'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import { enUS, pseudoCN, zhCN } from '../i18n/resources'
import UrlAuthPoliciesPage from '../pages/UrlAuthPoliciesPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// OutcomeUnknown 的标题同时出现在恢复条和说明弹窗里，这里只认原位的恢复条。
const OUTCOME_BAR = { selector: '.cdnca-outcome-bar .ant-alert-message' }

const site: SiteListItem = {
  id: '33333333-3333-4333-8333-333333333333', display_id: '31', version: 1, owner: null, domain: 'download.example',
  listen_ports: ['80'], origins: ['192.0.2.10:80'], cname: '', https_enabled: false,
  package: null, group_name: null, region: null, status: 'active',
  listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' },
  lock: { locked: false, reason: null, locked_at: null, operator: null }, created_at: '2026-07-22T12:00:00Z',
}

const policy: URLAuthPolicy = {
  id: '44444444-4444-4444-8444-444444444444', scope_id: '22222222-2222-4222-8222-222222222222',
  site: { id: site.id, domain: site.domain }, name: 'Protected downloads', enabled: true,
  algorithm: 'hmac-sha256', signature_parameter: 'sig', expiration_parameter: 'exp', key_id_parameter: 'kid',
  bind_client_ip: true, max_clock_skew_seconds: 30, max_validity_seconds: 600, max_signature_uses: 1,
  excluded_query_parameters: ['utm_source'], trusted_proxy_cidrs: ['10.0.0.0/8'],
  current_key: { key_id: 'k-current', created_at: '2026-07-22T12:00:00Z' },
  previous_key: { key_id: 'k-previous', created_at: '2026-07-21T12:00:00Z' },
  version: 2, created_at: '2026-07-22T12:00:00Z', updated_at: '2026-07-22T12:00:00Z',
}

function authenticate(permissions = ['url_auth_policies.read', 'url_auth_policies.manage']) {
  const user = principal({ permissions })
  useSessionStore.getState().setSession(authResponse(user), user)
}

function mockSites() {
  return vi.spyOn(sitesApi, 'list').mockResolvedValue({ items: [site], total: 1, page: 1, limit: 100 })
}

function renderUrlAuthWithQueryClient(queryClient: QueryClient) {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/site/url-auth']}>
            <UrlAuthPoliciesPage />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((release) => { resolve = release })
  return { promise, resolve }
}

function expectSecretAbsentFromMutationData(queryClient: QueryClient, secret: string) {
  const mutations = queryClient.getMutationCache().getAll()
  for (const mutation of mutations) expect(mutation.state.data).toBeUndefined()
  expect(JSON.stringify(mutations.map((mutation) => mutation.state.data))).not.toContain(secret)
}

const validationKeys = [
  'targetScopeRequired',
  'targetScopeInvalid',
  'ownerRequired',
  'ownerInvalid',
  'siteRequired',
  'nameRequired',
  'nameTooLong',
  'parameterRequired',
  'parameterInvalid',
  'clockSkewRequired',
  'clockSkewRange',
  'validityRequired',
  'validityRange',
  'signatureUsesRequired',
  'signatureUsesRange',
] as const

const pseudoUrlAuthPolicies = (pseudoCN as unknown as typeof zhCN).urlAuthPolicies

// W2: the target tenant is a searchable picker; a pasted scope UUID is offered as an option.
async function pickTargetScope(user: ReturnType<typeof userEvent.setup>, editor: HTMLElement, scope: string) {
  await user.type(within(editor).getByRole('combobox', { name: '目标租户作用域' }), scope)
  const option = await waitFor(() => {
    const found = [...document.querySelectorAll<HTMLElement>('.ant-select-item-option')]
      .find((item) => item.textContent === scope)
    if (!found) throw new Error(`scope option not found: ${scope}`)
    return found
  })
  await user.click(option)
}

describe('UrlAuthPoliciesPage', () => {
  it('renders a compact read-only table and all key metadata without owner leakage', async () => {
    authenticate(['url_auth_policies.read'])
    vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])

    expect(await screen.findByRole('heading', { name: 'URL鉴权策略' })).toBeInTheDocument()
    expect(await screen.findByText('Protected downloads')).toBeInTheDocument()
    expect(screen.getByText(/k-current/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '创建策略' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '编辑Protected downloads' })).not.toBeInTheDocument()
    expect(screen.getByTestId('url-auth-policy-table-scroll')).toHaveAttribute('aria-busy', 'false')
  })

  it('creates HMAC-SHA256 policy and requires acknowledgement of the one-time secret', async () => {
    authenticate()
    vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    mockSites()
    const create = vi.spyOn(urlAuthPoliciesApi, 'create').mockResolvedValue({ policy, secret: 'one-time-secret', replayed: false })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()
    renderUrlAuthWithQueryClient(queryClient)

    expect(await screen.findByText('暂无URL鉴权策略')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '创建策略' }))
    const dialog = screen.getByRole('dialog', { name: '创建URL鉴权策略' })
    await user.click(within(dialog).getByLabelText('绑定网站'))
    await user.click(await screen.findByText(site.domain))
    await user.type(within(dialog).getByLabelText('名称'), 'Protected downloads')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(create.mock.calls[0][1]).toMatchObject({ algorithm: 'hmac-sha256', site_id: site.id, name: 'Protected downloads' })
    const secretDialog = await screen.findByRole('dialog', { name: 'URL鉴权密钥（仅显示一次）' })
    expect(within(secretDialog).getByLabelText('一次性URL鉴权密钥')).toHaveValue('one-time-secret')
    expectSecretAbsentFromMutationData(queryClient, 'one-time-secret')
    expect(screen.getByRole('button', { name: '创建策略' })).toBeDisabled()
    await user.click(within(secretDialog).getByRole('button', { name: '我已安全保存' }))
    expect(screen.getByRole('button', { name: '创建策略' })).toBeEnabled()
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'URL鉴权密钥（仅显示一次）' })).not.toBeInTheDocument())
    expect(screen.queryByText('one-time-secret')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '创建策略' }))
    expect(await screen.findByRole('dialog', { name: '创建URL鉴权策略' })).toBeInTheDocument()
    expect(screen.queryByText('one-time-secret')).not.toBeInTheDocument()
  }, 60_000)

  // fix-fielderr-be4：服务端拒绝某个可信代理网段时标在该文本框下并写出是哪一项，弹窗不关、不弹错误窗
  it('marks a refused trusted proxy entry under its box with the entry value', async () => {
    authenticate()
    vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    mockSites()
    const update = vi.spyOn(urlAuthPoliciesApi, 'update').mockRejectedValueOnce(Object.assign(
      new ApiError('API request failed', 400, 'validation_error', 'req-url-auth'), { field: 'trusted_proxy_cidrs[1]', reason: 'invalid_format' }))
    const user = userEvent.setup()
    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])
    await user.click(await screen.findByRole('button', { name: '编辑Protected downloads' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑URL鉴权策略' })
    const proxies = within(dialog).getByLabelText('可信代理CIDR（每行一个）')
    await user.clear(proxies)
    await user.type(proxies, '10.0.0.0/8{enter}10.0.0.999/24')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1))
    const help = await within(dialog).findByText('10.0.0.999/24：格式不正确')
    expect(help.closest('.ant-form-item')).toHaveClass('ant-form-item-has-error')
    expect(help.closest('.ant-form-item')).toContainElement(proxies)
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
    expect(screen.getByRole('dialog', { name: '编辑URL鉴权策略' })).toBeInTheDocument()
  })

  it('confirms rotation and disable before sending versioned writes', async () => {
    authenticate()
    vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    const rotate = vi.spyOn(urlAuthPoliciesApi, 'rotate').mockResolvedValue({ policy: { ...policy, version: 3 }, secret: 'rotated-secret', replayed: false })
    const disable = vi.spyOn(urlAuthPoliciesApi, 'disable').mockResolvedValue({ policy: { ...policy, enabled: false, version: 3 }, replayed: false })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()
    renderUrlAuthWithQueryClient(queryClient)
    await screen.findByText('Protected downloads')

    await user.click(screen.getByRole('button', { name: '轮换Protected downloads的密钥' }))
    expect(await screen.findByText('确认轮换当前密钥？')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '确认' }))
    await waitFor(() => expect(rotate).toHaveBeenCalledWith('memory-only-access-token', policy.id, 2, expect.stringMatching(/^url-auth-rotate-/)))
    const secretInput = await screen.findByLabelText('一次性URL鉴权密钥')
    expect(secretInput).toHaveValue('rotated-secret')
    expectSecretAbsentFromMutationData(queryClient, 'rotated-secret')
    const secretDialog = secretInput.closest<HTMLElement>('[role="dialog"]')
    expect(secretDialog).not.toBeNull()
    if (!secretDialog) throw new Error('secret dialog missing')
    await user.click(within(secretDialog).getByRole('button', { name: '我已安全保存' }))

    await user.click(screen.getByRole('button', { name: '禁用Protected downloads' }))
    expect(await screen.findByText('确认禁用该URL鉴权策略？')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '确认' }))
    await waitFor(() => expect(disable).toHaveBeenCalledWith('memory-only-access-token', policy.id, 2, expect.stringMatching(/^url-auth-disable-/)))
  }, 60_000)

  it('fails closed locally without issuing a URL authentication request', async () => {
    authenticate([])
    const list = vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    const sites = vi.spyOn(sitesApi, 'list')
    const create = vi.spyOn(urlAuthPoliciesApi, 'create')
    const update = vi.spyOn(urlAuthPoliciesApi, 'update')
    const rotate = vi.spyOn(urlAuthPoliciesApi, 'rotate')
    const revoke = vi.spyOn(urlAuthPoliciesApi, 'revoke')
    const enable = vi.spyOn(urlAuthPoliciesApi, 'enable')
    const disable = vi.spyOn(urlAuthPoliciesApi, 'disable')
    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])

    expect(await screen.findByText('无权查看URL鉴权策略')).toBeInTheDocument()
    expect(list).not.toHaveBeenCalled()
    expect(sites).not.toHaveBeenCalled()
    expect(create).not.toHaveBeenCalled()
    expect(update).not.toHaveBeenCalled()
    expect(rotate).not.toHaveBeenCalled()
    expect(revoke).not.toHaveBeenCalled()
    expect(enable).not.toHaveBeenCalled()
    expect(disable).not.toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: '创建策略' })).not.toBeInTheDocument()
    expect(screen.queryByTestId('url-auth-policy-table-scroll')).not.toBeInTheDocument()
  })

  it('keeps filters, page two, editor, and token-free cache identity across a same-epoch token refresh', async () => {
    const actor = principal({ permissions: ['url_auth_policies.read', 'url_auth_policies.manage'] })
    const oldToken = 'old-url-auth-access-token'
    const newToken = 'new-url-auth-access-token'
    const stablePolicy = { ...policy, name: 'stable URL auth policy' }
    const list = vi.spyOn(urlAuthPoliciesApi, 'list').mockImplementation((_token, filters) => Promise.resolve({
      items: [stablePolicy], total: 45, page: filters.page, limit: filters.limit,
    }))
    const sites = mockSites()
    const update = vi.spyOn(urlAuthPoliciesApi, 'update').mockResolvedValue({
      policy: { ...stablePolicy, name: 'updated with fresh token', version: 3 }, replayed: false,
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    useSessionStore.getState().setSession({ ...authResponse(actor), access_token: oldToken }, actor)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const user = userEvent.setup()

    renderUrlAuthWithQueryClient(queryClient)

    expect(await screen.findByText(stablePolicy.name)).toBeInTheDocument()
    await user.type(screen.getByPlaceholderText('搜索名称'), 'stable')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await user.click(screen.getAllByRole('combobox')[0])
    await user.click(await screen.findByText('已禁用', { selector: '.ant-select-item-option-content' }))
    await user.click(screen.getByTitle('2'))
    await waitFor(() => expect(document.querySelector('.ant-pagination-item-active')).toHaveAttribute('title', '2'))
    await user.click(screen.getByRole('button', { name: `编辑${stablePolicy.name}` }))
    const editor = await screen.findByRole('dialog', { name: '编辑URL鉴权策略' })
    await waitFor(() => expect(sites).toHaveBeenCalled())
    const listReadsBeforeRefresh = list.mock.calls.length
    const siteReadsBeforeRefresh = sites.mock.calls.length

    await act(async () => {
      useSessionStore.getState().setSession({ ...authResponse(actor), access_token: newToken }, actor, 'refresh')
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(screen.getByText(stablePolicy.name)).toBeInTheDocument()
    expect(screen.getByRole('dialog', { name: '编辑URL鉴权策略' })).toBeInTheDocument()
    expect(screen.getByPlaceholderText('搜索名称')).toHaveValue('stable')
    expect(screen.getAllByRole('combobox')[0].closest('.ant-select')).toHaveTextContent('已禁用')
    expect(document.querySelector('.ant-pagination-item-active')).toHaveAttribute('title', '2')
    expect(list).toHaveBeenCalledTimes(listReadsBeforeRefresh)
    expect(sites).toHaveBeenCalledTimes(siteReadsBeforeRefresh)

    const listKey = [
      'url-auth-policies', actor.scope_kind, actor.scope_id, actor.user_id, sessionEpoch,
      2, 20, 'stable', 'disabled',
    ] as const
    const sitesKey = [
      'url-auth-policy-sites', actor.scope_kind, actor.scope_id, actor.user_id, sessionEpoch,
      actor.scope_id, actor.user_id, '',
    ] as const
    const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    expect(queryKeys).toContainEqual(listKey)
    expect(queryKeys).toContainEqual(sitesKey)
    for (const queryKey of queryKeys) {
      const serializedKey = JSON.stringify(queryKey)
      expect(serializedKey).not.toContain(oldToken)
      expect(serializedKey).not.toContain(newToken)
    }
    expect(document.body.textContent).not.toContain(oldToken)
    expect(document.body.textContent).not.toContain(newToken)

    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(list).toHaveBeenCalledTimes(listReadsBeforeRefresh + 1))
    expect(list.mock.calls.at(-1)?.[0]).toBe(newToken)

    const name = within(editor).getByLabelText('名称')
    await user.clear(name)
    await user.type(name, 'updated with fresh token')
    await user.click(within(editor).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(update).toHaveBeenCalled())
    expect(update.mock.calls[0][0]).toBe(newToken)
  }, 60_000)

  it('resets tenant editor, filters, and pagination while isolating a late old-session list', async () => {
    const tenantA = principal({ permissions: ['url_auth_policies.read', 'url_auth_policies.manage'] })
    const tenantB = principal({
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
      user_id: '88888888-8888-4888-8888-888888888888',
      permissions: ['url_auth_policies.read', 'url_auth_policies.manage'],
    })
    const tenantAPolicy = { ...policy, name: 'tenant A URL policy', scope_id: tenantA.scope_id }
    const lateTenantAPolicy = {
      ...tenantAPolicy, id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', name: 'late tenant A URL policy',
    }
    const tenantBPolicy = {
      ...policy, id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', scope_id: tenantB.scope_id,
      name: 'tenant B first page policy',
    }
    const lateTenantA = deferred<{ items: URLAuthPolicy[]; total: number; page: number; limit: number }>()
    const pendingTenantB = deferred<{ items: URLAuthPolicy[]; total: number; page: number; limit: number }>()
    let tenantAPageTwoReads = 0
    const list = vi.spyOn(urlAuthPoliciesApi, 'list').mockImplementation((token, filters) => {
      if (token === 'tenant-a-url-auth-token') {
        if (filters.page === 2) {
          tenantAPageTwoReads += 1
          return tenantAPageTwoReads === 1
            ? Promise.resolve({ items: [tenantAPolicy], total: 40, page: 2, limit: 20 })
            : lateTenantA.promise
        }
        return Promise.resolve({ items: [tenantAPolicy], total: 40, page: 1, limit: 20 })
      }
      if (token === 'tenant-b-url-auth-token') return pendingTenantB.promise
      throw new Error(`unexpected URL auth list token ${token}`)
    })
    mockSites()
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: 'tenant-a-url-auth-token' }, tenantA,
    )
    const tenantAEpoch = useSessionStore.getState().sessionEpoch
    const user = userEvent.setup()

    renderUrlAuthWithQueryClient(queryClient)

    expect(await screen.findByText(tenantAPolicy.name)).toBeInTheDocument()
    await user.type(screen.getByPlaceholderText('搜索名称'), 'tenant-a')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await user.click(screen.getAllByRole('combobox')[0])
    await user.click(await screen.findByText('已禁用', { selector: '.ant-select-item-option-content' }))
    await user.click(screen.getByTitle('2'))
    await waitFor(() => expect(document.querySelector('.ant-pagination-item-active')).toHaveAttribute('title', '2'))
    await user.click(screen.getByRole('button', { name: `编辑${tenantAPolicy.name}` }))
    expect(await screen.findByRole('dialog', { name: '编辑URL鉴权策略' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(tenantAPageTwoReads).toBe(2))

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantB), access_token: 'tenant-b-url-auth-token' }, tenantB,
      )
      await Promise.resolve()
    })
    const tenantBEpoch = useSessionStore.getState().sessionEpoch
    await waitFor(() => expect(list.mock.calls.some(([token]) => token === 'tenant-b-url-auth-token')).toBe(true))

    expect(tenantBEpoch).not.toBe(tenantAEpoch)
    expect(screen.queryByText(tenantAPolicy.name)).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '编辑URL鉴权策略' })).not.toBeInTheDocument()
    expect(screen.getByPlaceholderText('搜索名称')).toHaveValue('')
    expect(screen.getAllByRole('combobox')[0].closest('.ant-select')).toHaveTextContent('筛选状态')
    expect(screen.getByTestId('url-auth-policy-table-scroll')).toHaveAttribute('aria-busy', 'true')
    expect(list.mock.calls.find(([token]) => token === 'tenant-b-url-auth-token')?.[1]).toEqual({
      page: 1, limit: 20, name: undefined, status: undefined,
    })

    await act(async () => {
      pendingTenantB.resolve({ items: [tenantBPolicy], total: 1, page: 1, limit: 20 })
    })
    expect(await screen.findByText(tenantBPolicy.name)).toBeInTheDocument()

    await act(async () => {
      lateTenantA.resolve({ items: [lateTenantAPolicy], total: 40, page: 2, limit: 20 })
      await Promise.resolve()
    })

    const tenantBKey = [
      'url-auth-policies', tenantB.scope_kind, tenantB.scope_id, tenantB.user_id, tenantBEpoch,
      1, 20, '', undefined,
    ] as const
    expect(screen.getByText(tenantBPolicy.name)).toBeInTheDocument()
    expect(screen.queryByText(lateTenantAPolicy.name)).not.toBeInTheDocument()
    expect(queryClient.getQueryData(tenantBKey)).toEqual({
      items: [tenantBPolicy], total: 1, page: 1, limit: 20,
    })
  }, 60_000)

  it('clears a one-time secret when a new session starts', async () => {
    const tenantA = principal({ permissions: ['url_auth_policies.read', 'url_auth_policies.manage'] })
    const tenantB = principal({
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
      user_id: '88888888-8888-4888-8888-888888888888',
      permissions: ['url_auth_policies.read', 'url_auth_policies.manage'],
    })
    vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    mockSites()
    vi.spyOn(urlAuthPoliciesApi, 'create').mockResolvedValue({
      policy, secret: 'tenant-a-one-time-secret', replayed: false,
    })
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: 'tenant-a-secret-token' }, tenantA,
    )
    const user = userEvent.setup()

    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])
    expect(await screen.findByText('暂无URL鉴权策略')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '创建策略' }))
    const editor = screen.getByRole('dialog', { name: '创建URL鉴权策略' })
    await user.click(within(editor).getByLabelText('绑定网站'))
    await user.click(await screen.findByText(site.domain))
    await user.type(within(editor).getByLabelText('名称'), 'tenant A secret policy')
    await user.click(within(editor).getByRole('button', { name: '保存' }))
    expect(await screen.findByLabelText('一次性URL鉴权密钥')).toHaveValue('tenant-a-one-time-secret')

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantB), access_token: 'tenant-b-secret-token' }, tenantB,
      )
      await Promise.resolve()
    })

    expect(screen.queryByRole('dialog', { name: 'URL鉴权密钥（仅显示一次）' })).not.toBeInTheDocument()
    expect(screen.queryByText('tenant-a-one-time-secret')).not.toBeInTheDocument()
    expect(await screen.findByText('暂无URL鉴权策略')).toBeInTheDocument()
  }, 60_000)

  it('clears an unknown write outcome when a new session starts', async () => {
    const tenantA = principal({ permissions: ['url_auth_policies.read', 'url_auth_policies.manage'] })
    const tenantB = principal({
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
      user_id: '88888888-8888-4888-8888-888888888888',
      permissions: ['url_auth_policies.read', 'url_auth_policies.manage'],
    })
    vi.spyOn(urlAuthPoliciesApi, 'list').mockImplementation((token) => Promise.resolve({
      items: token === 'tenant-a-unknown-token' ? [policy] : [], total: token === 'tenant-a-unknown-token' ? 1 : 0,
      page: 1, limit: 20,
    }))
    vi.spyOn(urlAuthPoliciesApi, 'disable').mockRejectedValue(
      new ApiError('private tenant A write route', 503, 'request_failed'),
    )
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: 'tenant-a-unknown-token' }, tenantA,
    )
    const user = userEvent.setup()

    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])
    expect(await screen.findByText(policy.name)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: `禁用${policy.name}` }))
    await user.click(await screen.findByRole('button', { name: '确认' }))
    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantB), access_token: 'tenant-b-unknown-token' }, tenantB,
      )
      await Promise.resolve()
    })

    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(screen.queryByText('private tenant A write route')).not.toBeInTheDocument()
    expect(await screen.findByText('暂无URL鉴权策略')).toBeInTheDocument()
  }, 60_000)

  it('ignores a late secret mutation from an old session without invalidating the new session cache', async () => {
    const tenantA = principal({ permissions: ['url_auth_policies.read', 'url_auth_policies.manage'] })
    const tenantB = principal({
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
      user_id: '88888888-8888-4888-8888-888888888888',
      permissions: ['url_auth_policies.read', 'url_auth_policies.manage'],
    })
    const tenantBPolicy = {
      ...policy, id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', scope_id: tenantB.scope_id,
      name: 'tenant B stable URL policy',
    }
    const rotateResult = deferred<{ policy: URLAuthPolicy; secret?: string; replayed: boolean }>()
    const list = vi.spyOn(urlAuthPoliciesApi, 'list').mockImplementation((token) => Promise.resolve({
      items: token === 'tenant-a-late-write-token' ? [policy] : [tenantBPolicy],
      total: 1, page: 1, limit: 20,
    }))
    vi.spyOn(urlAuthPoliciesApi, 'rotate').mockReturnValue(rotateResult.promise)
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: 'tenant-a-late-write-token' }, tenantA,
    )
    const user = userEvent.setup()

    renderUrlAuthWithQueryClient(queryClient)
    expect(await screen.findByText(policy.name)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: `轮换${policy.name}的密钥` }))
    await user.click(await screen.findByRole('button', { name: '确认' }))

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantB), access_token: 'tenant-b-late-write-token' }, tenantB,
      )
      await Promise.resolve()
    })
    const tenantBEpoch = useSessionStore.getState().sessionEpoch
    expect(await screen.findByText(tenantBPolicy.name)).toBeInTheDocument()
    const tenantBReads = list.mock.calls.filter(([token]) => token === 'tenant-b-late-write-token').length

    await act(async () => {
      rotateResult.resolve({
        policy: { ...policy, version: 3 }, secret: 'late-tenant-a-secret', replayed: false,
      })
      await Promise.resolve()
    })

    const tenantBKey = [
      'url-auth-policies', tenantB.scope_kind, tenantB.scope_id, tenantB.user_id, tenantBEpoch,
      1, 20, '', undefined,
    ] as const
    expect(screen.getByText(tenantBPolicy.name)).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: 'URL鉴权密钥（仅显示一次）' })).not.toBeInTheDocument()
    expect(screen.queryByText('late-tenant-a-secret')).not.toBeInTheDocument()
    expectSecretAbsentFromMutationData(queryClient, 'late-tenant-a-secret')
    expect(list.mock.calls.filter(([token]) => token === 'tenant-b-late-write-token')).toHaveLength(tenantBReads)
    expect(queryClient.getQueryState(tenantBKey)?.isInvalidated).toBe(false)
  }, 60_000)

  it.each(['success', 'version conflict'] as const)(
    'invalidates only the current identity list after a %s mutation',
    async (outcome) => {
      const actor = principal({ permissions: ['url_auth_policies.read', 'url_auth_policies.manage'] })
      useSessionStore.getState().setSession(authResponse(actor), actor)
      const sessionEpoch = useSessionStore.getState().sessionEpoch
      const currentKey = [
        'url-auth-policies', actor.scope_kind, actor.scope_id, actor.user_id, sessionEpoch,
        1, 20, '', undefined,
      ] as const
      const foreignKey = [
        'url-auth-policies', 'tenant', '99999999-9999-4999-8999-999999999999',
        'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 999, 1, 20, '', undefined,
      ] as const
      const foreignData = { items: [], total: 0, page: 1, limit: 20 }
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
      })
      queryClient.setQueryData(foreignKey, foreignData)
      const list = vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({
        items: [policy], total: 1, page: 1, limit: 20,
      })
      const disable = vi.spyOn(urlAuthPoliciesApi, 'disable')
      if (outcome === 'success') {
        disable.mockResolvedValue({ policy: { ...policy, enabled: false, version: 3 }, replayed: false })
      } else {
        disable.mockRejectedValue(new ApiError('private revision owner', 409, 'version_conflict'))
      }
      const user = userEvent.setup()

      renderUrlAuthWithQueryClient(queryClient)
      expect(await screen.findByText(policy.name)).toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: `禁用${policy.name}` }))
      await user.click(await screen.findByRole('button', { name: '确认' }))

      await waitFor(() => expect(disable).toHaveBeenCalledOnce())
      await waitFor(() => expect(list).toHaveBeenCalledTimes(2))
      expect(queryClient.getQueryData(currentKey)).toEqual({ items: [policy], total: 1, page: 1, limit: 20 })
      expect(queryClient.getQueryState(currentKey)?.isInvalidated).toBe(false)
      expect(queryClient.getQueryData(foreignKey)).toEqual(foreignData)
      expect(queryClient.getQueryState(foreignKey)?.isInvalidated).toBe(false)
      expect(screen.queryByText('private revision owner')).not.toBeInTheDocument()
    },
    60_000,
  )

  it('keeps the table mounted with aria-busy while loading, then renders the empty state', async () => {
    authenticate(['url_auth_policies.read'])
    const pending = deferred<{ items: URLAuthPolicy[]; total: number; page: number; limit: number }>()
    vi.spyOn(urlAuthPoliciesApi, 'list').mockReturnValue(pending.promise)

    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])

    const table = screen.getByTestId('url-auth-policy-table-scroll')
    expect(table).toHaveAttribute('aria-busy', 'true')
    await act(async () => {
      pending.resolve({ items: [], total: 0, page: 1, limit: 20 })
    })
    expect(await screen.findByText('暂无URL鉴权策略')).toBeInTheDocument()
    expect(table).toHaveAttribute('aria-busy', 'false')
  })

  it('localizes an ordinary load failure and recovers through retry without exposing the server message', async () => {
    authenticate(['url_auth_policies.read'])
    const list = vi.spyOn(urlAuthPoliciesApi, 'list')
      .mockRejectedValueOnce(new ApiError('private URL auth shard', 503, 'request_failed'))
      .mockResolvedValueOnce({ items: [], total: 0, page: 1, limit: 20 })
    const user = userEvent.setup()

    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])

    expect(await screen.findByText('URL鉴权策略加载失败')).toBeInTheDocument()
    expect(screen.getByText('请求失败，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('private URL auth shard')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无URL鉴权策略')).toBeInTheDocument()
    expect(list).toHaveBeenCalledTimes(2)
  })

  it('turns an API 403 into a terminal local boundary with no follow-up requests or raw message', async () => {
    authenticate()
    const list = vi.spyOn(urlAuthPoliciesApi, 'list').mockRejectedValue(
      new ApiError('private URL auth role row', 403, 'permission_denied'),
    )
    const sites = vi.spyOn(sitesApi, 'list')
    const create = vi.spyOn(urlAuthPoliciesApi, 'create')
    const update = vi.spyOn(urlAuthPoliciesApi, 'update')
    const rotate = vi.spyOn(urlAuthPoliciesApi, 'rotate')
    const revoke = vi.spyOn(urlAuthPoliciesApi, 'revoke')
    const enable = vi.spyOn(urlAuthPoliciesApi, 'enable')
    const disable = vi.spyOn(urlAuthPoliciesApi, 'disable')

    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])

    expect(await screen.findByText('无权查看URL鉴权策略')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少URL鉴权策略权限')).toBeInTheDocument()
    expect(screen.queryByText('private URL auth role row')).not.toBeInTheDocument()
    expect(list).toHaveBeenCalledOnce()
    expect(sites).not.toHaveBeenCalled()
    expect(create).not.toHaveBeenCalled()
    expect(update).not.toHaveBeenCalled()
    expect(rotate).not.toHaveBeenCalled()
    expect(revoke).not.toHaveBeenCalled()
    expect(enable).not.toHaveBeenCalled()
    expect(disable).not.toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: '创建策略' })).not.toBeInTheDocument()
    expect(screen.queryByTestId('url-auth-policy-table-scroll')).not.toBeInTheDocument()
  })

  it('terminally disables open list and site observers after a list refetch returns 403', async () => {
    const actor = principal({ permissions: ['url_auth_policies.read', 'url_auth_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const listPrefix = ['url-auth-policies', actor.scope_kind, actor.scope_id, actor.user_id, sessionEpoch] as const
    const sitesPrefix = ['url-auth-policy-sites', actor.scope_kind, actor.scope_id, actor.user_id, sessionEpoch] as const
    const list = vi.spyOn(urlAuthPoliciesApi, 'list')
      .mockResolvedValueOnce({ items: [policy], total: 1, page: 1, limit: 20 })
      .mockRejectedValueOnce(new ApiError('private refetch role row', 403, 'permission_denied'))
      .mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    const sites = mockSites()
    const create = vi.spyOn(urlAuthPoliciesApi, 'create')
    const update = vi.spyOn(urlAuthPoliciesApi, 'update')
    const rotate = vi.spyOn(urlAuthPoliciesApi, 'rotate')
    const revoke = vi.spyOn(urlAuthPoliciesApi, 'revoke')
    const enable = vi.spyOn(urlAuthPoliciesApi, 'enable')
    const disable = vi.spyOn(urlAuthPoliciesApi, 'disable')
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()
    onlineManager.setOnline(true)

    renderUrlAuthWithQueryClient(queryClient)
    expect(await screen.findByText(policy.name)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: `编辑${policy.name}` }))
    expect(await screen.findByRole('dialog', { name: '编辑URL鉴权策略' })).toBeInTheDocument()
    await waitFor(() => expect(sites).toHaveBeenCalledOnce())

    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('无权查看URL鉴权策略')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少URL鉴权策略权限')).toBeInTheDocument()
    expect(screen.queryByText('private refetch role row')).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '编辑URL鉴权策略' })).not.toBeInTheDocument()
    const listReads = list.mock.calls.length
    const siteReads = sites.mock.calls.length

    const terminalQueries = [
      ...queryClient.getQueryCache().findAll({ queryKey: listPrefix }),
      ...queryClient.getQueryCache().findAll({ queryKey: sitesPrefix }),
    ]
    for (const terminalQuery of terminalQueries) expect(terminalQuery.isDisabled()).toBe(true)

    await act(async () => {
      await queryClient.invalidateQueries({ queryKey: listPrefix })
      await queryClient.refetchQueries({ queryKey: listPrefix, type: 'active' })
      await queryClient.invalidateQueries({ queryKey: sitesPrefix })
      await queryClient.refetchQueries({ queryKey: sitesPrefix, type: 'active' })
      onlineManager.setOnline(false)
      onlineManager.setOnline(true)
      await Promise.resolve()
    })

    expect(screen.getByText('无权查看URL鉴权策略')).toBeInTheDocument()
    expect(list).toHaveBeenCalledTimes(listReads)
    expect(sites).toHaveBeenCalledTimes(siteReads)
    expect(create).not.toHaveBeenCalled()
    expect(update).not.toHaveBeenCalled()
    expect(rotate).not.toHaveBeenCalled()
    expect(revoke).not.toHaveBeenCalled()
    expect(enable).not.toHaveBeenCalled()
    expect(disable).not.toHaveBeenCalled()
  }, 60_000)

  it('terminally disables list and site observers after a platform site lookup returns 403', async () => {
    const admin = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'],
    })
    useSessionStore.getState().setSession(authResponse(admin), admin)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const listPrefix = ['url-auth-policies', admin.scope_kind, admin.scope_id, admin.user_id, sessionEpoch] as const
    const sitesPrefix = ['url-auth-policy-sites', admin.scope_kind, admin.scope_id, admin.user_id, sessionEpoch] as const
    const list = vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({
      items: [policy], total: 1, page: 1, limit: 20,
    })
    const sites = vi.spyOn(sitesApi, 'list')
      .mockRejectedValueOnce(new ApiError('private site role row', 403, 'permission_denied'))
      .mockResolvedValue({ items: [site], total: 1, page: 1, limit: 100 })
    const create = vi.spyOn(urlAuthPoliciesApi, 'create')
    const update = vi.spyOn(urlAuthPoliciesApi, 'update')
    const rotate = vi.spyOn(urlAuthPoliciesApi, 'rotate')
    const revoke = vi.spyOn(urlAuthPoliciesApi, 'revoke')
    const enable = vi.spyOn(urlAuthPoliciesApi, 'enable')
    const disable = vi.spyOn(urlAuthPoliciesApi, 'disable')
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()
    onlineManager.setOnline(true)

    renderUrlAuthWithQueryClient(queryClient)
    expect(await screen.findByText(policy.name)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '创建策略' }))
    const editor = await screen.findByRole('dialog', { name: '创建URL鉴权策略' })
    await pickTargetScope(user, editor, '22222222-2222-4222-8222-222222222222')
    await user.type(
      within(editor).getByLabelText('所属用户'),
      '11111111-1111-4111-8111-111111111111',
    )

    expect(await screen.findByText('无权查看URL鉴权策略')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少URL鉴权策略权限')).toBeInTheDocument()
    expect(screen.queryByText('private site role row')).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '创建URL鉴权策略' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '创建策略' })).not.toBeInTheDocument()
    const listReads = list.mock.calls.length
    const siteReads = sites.mock.calls.length

    const terminalQueries = [
      ...queryClient.getQueryCache().findAll({ queryKey: listPrefix }),
      ...queryClient.getQueryCache().findAll({ queryKey: sitesPrefix }),
    ]
    await waitFor(() => {
      for (const terminalQuery of terminalQueries) expect(terminalQuery.isActive()).toBe(false)
    })

    await act(async () => {
      await queryClient.invalidateQueries({ queryKey: listPrefix })
      await queryClient.refetchQueries({ queryKey: listPrefix, type: 'active' })
      await queryClient.invalidateQueries({ queryKey: sitesPrefix })
      await queryClient.refetchQueries({ queryKey: sitesPrefix, type: 'active' })
      onlineManager.setOnline(false)
      onlineManager.setOnline(true)
      await Promise.resolve()
    })

    expect(screen.getByText('无权查看URL鉴权策略')).toBeInTheDocument()
    expect(list).toHaveBeenCalledTimes(listReads)
    expect(sites).toHaveBeenCalledTimes(siteReads)
    expect(create).not.toHaveBeenCalled()
    expect(update).not.toHaveBeenCalled()
    expect(rotate).not.toHaveBeenCalled()
    expect(revoke).not.toHaveBeenCalled()
    expect(enable).not.toHaveBeenCalled()
    expect(disable).not.toHaveBeenCalled()
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0)
  }, 60_000)

  it('edits and revokes with current revisions, then refreshes the list', async () => {
    authenticate()
    const list = vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    mockSites()
    const update = vi.spyOn(urlAuthPoliciesApi, 'update').mockResolvedValue({ policy: { ...policy, name: 'Updated downloads', version: 3 }, replayed: false })
    const revoke = vi.spyOn(urlAuthPoliciesApi, 'revoke').mockResolvedValue({ policy: { ...policy, previous_key: undefined, version: 3 }, replayed: false })
    const user = userEvent.setup()
    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])
    await screen.findByText('Protected downloads')

    await user.click(screen.getByRole('button', { name: '编辑Protected downloads' }))
    const editor = await screen.findByRole('dialog', { name: '编辑URL鉴权策略' })
    const name = within(editor).getByLabelText('名称')
    await user.clear(name)
    await user.type(name, 'Updated downloads')
    await user.click(within(editor).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(update).toHaveBeenCalledWith(
      'memory-only-access-token', policy.id, policy.version,
      expect.objectContaining({ name: 'Updated downloads', algorithm: 'hmac-sha256' }),
      expect.stringMatching(/^url-auth-update-/),
    ))
    await waitFor(() => expect(list.mock.calls.length).toBeGreaterThan(1))

    await user.click(screen.getByRole('button', { name: '撤销Protected downloads的前一密钥' }))
    expect(await screen.findByText('确认撤销前一密钥？')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '确认' }))
    await waitFor(() => expect(revoke).toHaveBeenCalledWith(
      'memory-only-access-token', policy.id, policy.version, policy.previous_key?.key_id,
      expect.stringMatching(/^url-auth-revoke-/),
    ))
  }, 60_000)

  it('sends name, status, page, and page-size filters', async () => {
    authenticate(['url_auth_policies.read'])
    const list = vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 45, page: 1, limit: 20 })
    const user = userEvent.setup()
    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])
    await screen.findByText('Protected downloads')

    await user.type(screen.getByPlaceholderText('搜索名称'), 'down')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith('memory-only-access-token', expect.objectContaining({ page: 1, limit: 20, name: 'down' })))

    await user.click(screen.getAllByRole('combobox')[0])
    await user.click(await screen.findByText('已禁用'))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith('memory-only-access-token', expect.objectContaining({ page: 1, status: 'disabled' })))

    fireEvent.click(screen.getByTitle('2'))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith('memory-only-access-token', expect.objectContaining({ page: 2, limit: 20 })))
    expect(screen.getByTestId('url-auth-policy-pagination-scroll')).toHaveStyle({ overflowX: 'auto' })
  }, 60_000)

  it('renders the complete English surface and keeps MD5 as migration provenance only', async () => {
    await changeLocale('en-US')
    authenticate(['url_auth_policies.read'])
    vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({
      items: [{ ...policy, migration_marker: 'cdnfly_type_a_md5' }], total: 1, page: 1, limit: 20,
    })
    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])

    expect(await screen.findByRole('heading', { name: 'URL authentication policies' })).toBeInTheDocument()
    await screen.findByText('Protected downloads')
    expect(screen.getByRole('columnheader', { name: 'Algorithm' })).toBeInTheDocument()
    expect(screen.getByText('HMAC-SHA256')).toBeInTheDocument()
    expect(screen.getByText('Migration source')).toBeInTheDocument()
    expect(screen.queryByText('MD5')).not.toBeInTheDocument()
  })

  it('retries an unknown write with the exact revision and idempotency key', async () => {
    authenticate()
    vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    const disable = vi.spyOn(urlAuthPoliciesApi, 'disable')
      .mockRejectedValueOnce(new ApiError('private upstream', 503, 'request_failed'))
      .mockResolvedValueOnce({ policy: { ...policy, enabled: false, version: 3 }, replayed: true })
    const user = userEvent.setup()
    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])
    await screen.findByText('Protected downloads')

    await user.click(screen.getByRole('button', { name: '禁用Protected downloads' }))
    await user.click(await screen.findByRole('button', { name: '确认' }))
    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(disable).toHaveBeenCalledTimes(2))
    expect(disable.mock.calls[0]).toEqual(disable.mock.calls[1])
    expect(screen.queryByText('private upstream')).not.toBeInTheDocument()
  }, 60_000)

  it('keeps writes locked until close-and-refresh really succeeds', async () => {
    authenticate()
    const list = vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({ items: [policy], total: 1, page: 1, limit: 20 })
    vi.spyOn(urlAuthPoliciesApi, 'disable').mockRejectedValue(new ApiError('private upstream', 503, 'request_failed'))
    const user = userEvent.setup()
    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])
    await screen.findByText('Protected downloads')

    await user.click(screen.getByRole('button', { name: '禁用Protected downloads' }))
    await user.click(await screen.findByRole('button', { name: '确认' }))
    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    list.mockRejectedValueOnce(new ApiError('private read', 503, 'request_failed'))
    await user.click(screen.getByRole('button', { name: '关闭并刷新' }))
    await waitFor(() => expect(screen.getByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument())
    expect(screen.getByRole('button', { name: '创建策略' })).toBeDisabled()

    list.mockResolvedValueOnce({ items: [policy], total: 1, page: 1, limit: 20 })
    await user.click(screen.getByRole('button', { name: '关闭并刷新' }))
    await waitFor(() => expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument())
    expect(screen.getByRole('button', { name: '创建策略' })).toBeEnabled()
  }, 60_000)

  it('keys platform site lookup by target scope, owner, and search and resets selection when target changes', async () => {
    const admin = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'],
    })
    useSessionStore.getState().setSession(
      { ...authResponse(admin), access_token: 'platform-url-auth-token' }, admin,
    )
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const targetScopeA = '22222222-2222-4222-8222-222222222222'
    const targetScopeB = '77777777-7777-4777-8777-777777777777'
    const targetOwner = '11111111-1111-4111-8111-111111111111'
    vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    const sites = mockSites()
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()

    renderUrlAuthWithQueryClient(queryClient)
    expect(await screen.findByText('暂无URL鉴权策略')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '创建策略' }))
    const editor = await screen.findByRole('dialog', { name: '创建URL鉴权策略' })
    await pickTargetScope(user, editor, targetScopeA)
    await user.type(within(editor).getByLabelText('所属用户'), targetOwner)
    await waitFor(() => expect(sites).toHaveBeenCalledOnce())

    const siteSelect = within(editor).getByLabelText('绑定网站')
    await user.click(siteSelect)
    await user.type(siteSelect, 'download')
    await waitFor(() => expect(sites).toHaveBeenLastCalledWith(
      'platform-url-auth-token',
      expect.objectContaining({ owner: targetOwner, domain: 'download', page: 1, limit: 100 }),
    ))
    const searchKey = [
      'url-auth-policy-sites', admin.scope_kind, admin.scope_id, admin.user_id, sessionEpoch,
      targetScopeA, targetOwner, 'download',
    ] as const
    expect(queryClient.getQueryCache().getAll().map((query) => query.queryKey)).toContainEqual(searchKey)

    await user.click(await screen.findByText(site.domain, { selector: '.ant-select-item-option-content' }))
    expect(siteSelect.closest('.ant-select')).toHaveTextContent(site.domain)
    const readsBeforeTargetChange = sites.mock.calls.length
    await pickTargetScope(user, editor, targetScopeB)

    await waitFor(() => expect(sites.mock.calls.length).toBe(readsBeforeTargetChange + 1))
    expect(siteSelect.closest('.ant-select')).not.toHaveTextContent(site.domain)
    expect(sites).toHaveBeenLastCalledWith('platform-url-auth-token', {
      page: 1, limit: 100, owner: targetOwner,
    })
    const resetKey = [
      'url-auth-policy-sites', admin.scope_kind, admin.scope_id, admin.user_id, sessionEpoch,
      targetScopeB, targetOwner, '',
    ] as const
    expect(queryClient.getQueryCache().getAll().map((query) => query.queryKey)).toContainEqual(resetKey)
  }, 60_000)

  it('rejects non-canonical platform target and owner UUIDs without site reads or writes', async () => {
    const admin = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'],
    })
    useSessionStore.getState().setSession(authResponse(admin), admin)
    vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    const sites = mockSites()
    const create = vi.spyOn(urlAuthPoliciesApi, 'create')
    const user = userEvent.setup()

    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])
    expect(await screen.findByText('暂无URL鉴权策略')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '创建策略' }))
    const editor = await screen.findByRole('dialog', { name: '创建URL鉴权策略' })
    // The tenant picker never offers the zero UUID; free text cannot become the target.
    await user.type(within(editor).getByRole('combobox', { name: '目标租户作用域' }), '00000000-0000-0000-0000-000000000000')
    expect(document.querySelector('.ant-select-item-option')).toBeNull()
    await user.type(within(editor).getByLabelText('所属用户'), 'ffffffff-ffff-ffff-ffff-ffffffffffff')
    await act(async () => { await Promise.resolve() })
    expect(sites).not.toHaveBeenCalled()

    await user.click(within(editor).getByRole('button', { name: '保存' }))
    expect(await within(editor).findByText(zhCN.urlAuthPolicies.validation.targetScopeRequired)).toBeInTheDocument()
    expect(await within(editor).findByText('请输入规范UUID格式的所属用户')).toBeInTheDocument()
    expect(create).not.toHaveBeenCalled()
  }, 60_000)

  it('provides complete namespaced validation copy with an expanded pseudo locale', () => {
    for (const key of validationKeys) {
      const chinese = zhCN.urlAuthPolicies.validation[key]
      const english = enUS.urlAuthPolicies.validation[key]
      const pseudo = pseudoUrlAuthPolicies.validation[key]
      expect(chinese).toBeTruthy()
      expect(english).toBeTruthy()
      expect(pseudo).toBeTruthy()
      expect(pseudo).not.toBe(chinese)
      expect(pseudo.length).toBeGreaterThan(chinese.length)
    }
  })

  it.each([
    ['zh-CN', zhCN.urlAuthPolicies],
    ['en-US', enUS.urlAuthPolicies],
    ['qps-ploc', pseudoUrlAuthPolicies],
  ] as const)('renders every form-rule family from the %s URL-auth namespace', async (locale, copy) => {
    await changeLocale(locale)
    const admin = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'],
    })
    useSessionStore.getState().setSession(authResponse(admin), admin)
    vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    const sites = vi.spyOn(sitesApi, 'list')
    const create = vi.spyOn(urlAuthPoliciesApi, 'create')
    const user = userEvent.setup()

    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])
    await screen.findByText(copy.values.empty)
    await user.click(screen.getByRole('button', { name: copy.actions.create }))
    const editor = await screen.findByRole('dialog', { name: copy.editor.createTitle })
    const save = within(editor).getByRole('button', { name: copy.actions.save })

    await user.click(save)
    for (const message of [
      copy.validation.targetScopeRequired,
      copy.validation.ownerRequired,
      copy.validation.siteRequired,
      copy.validation.nameRequired,
    ]) {
      expect(await within(editor).findByText(message)).toBeInTheDocument()
    }

    // The tenant picker never offers the zero UUID, so free text cannot become an invalid target.
    await user.type(within(editor).getByRole('combobox', { name: copy.editor.targetScope }), '00000000-0000-0000-0000-000000000000')
    expect(document.querySelector('.ant-select-item-option')).toBeNull()
    await user.type(within(editor).getByLabelText(copy.editor.owner), 'ffffffff-ffff-ffff-ffff-ffffffffffff')
    await user.type(within(editor).getByLabelText(copy.editor.name), 'x'.repeat(129))
    await user.clear(within(editor).getByLabelText(copy.editor.signatureParameter))
    await user.clear(within(editor).getByLabelText(copy.editor.expirationParameter))
    await user.type(within(editor).getByLabelText(copy.editor.expirationParameter), 'bad value')
    await user.clear(within(editor).getByLabelText(copy.editor.clockSkew))
    await user.click(save)

    expect(within(editor).getByText(copy.validation.targetScopeRequired)).toBeInTheDocument()
    for (const message of [
      copy.validation.ownerInvalid,
      copy.validation.nameTooLong,
      copy.validation.parameterRequired,
      copy.validation.parameterInvalid,
      copy.validation.clockSkewRequired,
    ]) {
      expect(await within(editor).findByText(message)).toBeInTheDocument()
    }

    await user.type(within(editor).getByLabelText(copy.editor.signatureParameter), 'sig')
    await user.clear(within(editor).getByLabelText(copy.editor.expirationParameter))
    await user.type(within(editor).getByLabelText(copy.editor.expirationParameter), 'exp')
    await user.clear(within(editor).getByLabelText(copy.editor.validity))
    await user.clear(within(editor).getByLabelText(copy.editor.signatureUses))
    await user.click(save)

    for (const message of [
      copy.validation.validityRequired,
      copy.validation.signatureUsesRequired,
    ]) {
      expect(await within(editor).findByText(message)).toBeInTheDocument()
    }
    const allowed = new Set(Object.values(copy.validation))
    for (const node of editor.querySelectorAll('.ant-form-item-explain-error')) {
      expect(allowed.has(node.textContent ?? '')).toBe(true)
    }
    expect(sites).not.toHaveBeenCalled()
    expect(create).not.toHaveBeenCalled()
  }, 30_000)

  it('filters platform site lookup by the selected owner and shows scope ownership columns', async () => {
    authenticate(['platform.admin'])
    const current = useSessionStore.getState().principal!
    useSessionStore.getState().setSession(authResponse({ ...current, scope_kind: 'platform', tenant_id: null }), { ...current, scope_kind: 'platform', tenant_id: null })
    vi.spyOn(urlAuthPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
    const sites = mockSites()
    const user = userEvent.setup()
    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])

    expect(await screen.findByRole('columnheader', { name: '租户作用域' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '所属用户' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '创建策略' }))
    const editor = await screen.findByRole('dialog', { name: '创建URL鉴权策略' })
    await pickTargetScope(user, editor, '22222222-2222-4222-8222-222222222222')
    await user.type(within(editor).getByLabelText('所属用户'), '11111111-1111-4111-8111-111111111111')
    await waitFor(() => expect(sites).toHaveBeenLastCalledWith('memory-only-access-token', expect.objectContaining({
      owner: '11111111-1111-4111-8111-111111111111', page: 1, limit: 100,
    })))
  }, 60_000)

  it('maps permission denial and server failures locally', async () => {
    authenticate(['url_auth_policies.read'])
    vi.spyOn(urlAuthPoliciesApi, 'list').mockRejectedValue(new ApiError('private role row', 403, 'permission_denied'))
    const { unmount } = renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])
    expect(await screen.findByText('无权查看URL鉴权策略')).toBeInTheDocument()
    expect(screen.queryByText('private role row')).not.toBeInTheDocument()
    unmount()

    authenticate()
    vi.spyOn(urlAuthPoliciesApi, 'list').mockRejectedValue(new ApiError('private SQL', 500, 'internal_error'))
    renderWithProviders(<UrlAuthPoliciesPage />, ['/site/url-auth'])
    expect(await screen.findByText('URL鉴权策略加载失败')).toBeInTheDocument()
    expect(screen.queryByText('private SQL')).not.toBeInTheDocument()
    expect(screen.queryByText('暂无URL鉴权策略')).not.toBeInTheDocument()
  })
})
