import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CdncaProvider } from '@cdnca/ui'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import { ApiError } from '../api/auth'
import { apiKeysApi } from '../api/apiKeys'
import AccountApiKeysPage from '../pages/AccountApiKeysPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// antd 测试环境里所有弹窗的 aria-labelledby 都是 test-id；编辑器内的 OutcomeUnknown 也会弹出说明弹窗，按 name 查会同时命中两个；按标题文字找所属弹窗。
async function findDialogTitled(title: string): Promise<HTMLElement> {
  return (await screen.findByText(title, { selector: '.ant-modal-title' })).closest('[role="dialog"]') as HTMLElement
}

// OutcomeUnknown keeps its recovery buttons in the outcome dialog while it is
// open (a separate modal, not inside the editor), and in the bar once closed.
async function findOutcomeRetry(): Promise<HTMLElement> {
  const dialog = (await screen.findByText('使用同一请求重试', { selector: '.cdnca-feedback button span, .cdnca-feedback button' }))
    .closest('.cdnca-feedback') as HTMLElement
  return within(dialog).getByRole('button', { name: '使用同一请求重试' })
}

const activeKey = {
  id: '33333333-3333-4333-8333-333333333333',
  key_id: 'cfk_AAAAAAAAAAAAAAAAAAAAAA',
  key_prefix: 'cfk_AAAAAAAAAAAAAAAAAAAAAA.',
  scope_id: '22222222-2222-4222-8222-222222222222',
  tenant_id: '22222222-2222-4222-8222-222222222222',
  user_id: '11111111-1111-4111-8111-111111111111',
  name: 'production reader',
  scopes: ['sites.read'],
  ip_allowlist: ['192.0.2.0/24', '2001:db8::/32'],
  status: 'active' as const,
  expires_at: '2026-08-22T12:00:00Z',
  revision: 1,
  created_at: '2026-07-22T12:00:00Z',
  updated_at: '2026-07-22T12:00:00Z',
}

const issued = {
  key: { ...activeKey, id: '44444444-4444-4444-8444-444444444444', name: 'new reader' },
  secret: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
}

const pendingKey = {
  ...activeKey,
  id: '55555555-5555-4555-8555-555555555555',
  key_id: 'cfk_CCCCCCCCCCCCCCCCCCCCCC',
  key_prefix: 'cfk_CCCCCCCCCCCCCCCCCCCCCC.',
  name: 'pending reader',
  status: 'pending_activation',
  revision: 1,
}

const secondActiveKey = {
  ...activeKey,
  id: '66666666-6666-4666-8666-666666666666',
  key_id: 'cfk_DDDDDDDDDDDDDDDDDDDDDD',
  key_prefix: 'cfk_DDDDDDDDDDDDDDDDDDDDDD.',
  name: 'automation writer',
  scopes: ['sites.manage'],
  ip_allowlist: ['198.51.100.0/24'],
}

function authenticate(overrides: Parameters<typeof principal>[0] = {}) {
  const user = principal({
    permissions: ['identity.self.read', 'api_keys.self.manage', 'sites.read', 'sites.manage'],
    ...overrides,
  })
  useSessionStore.getState().setSession(authResponse(user), user)
}

function jsonResponse(value: unknown, status = 200): Promise<Response> {
  return Promise.resolve(new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  }))
}

function apiPage<T>(items: T[], nextCursor = '', total?: number) {
  return { items, next_cursor: nextCursor, has_more: nextCursor !== '', ...(total === undefined ? {} : { total }) }
}

function renderApiKeysWithQueryClient(queryClient: QueryClient) {
  return render(
    // CdncaProvider mounts the FeedbackProvider that renders useFeedback() dialogs.
    <CdncaProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/account/api-key']}>
          <AccountApiKeysPage />
        </MemoryRouter>
      </QueryClientProvider>
    </CdncaProvider>,
  )
}

function apiKeyItems(namePrefix: string, scopeID = activeKey.scope_id) {
  return Array.from({ length: 12 }, (_, index) => ({
    ...activeKey,
    id: `33333333-3333-4333-8333-${String(index + 1).padStart(12, '0')}`,
    key_id: `cfk_${String(index + 1).padStart(22, 'A')}`,
    key_prefix: `cfk_${String(index + 1).padStart(22, 'A')}.`,
    scope_id: scopeID,
    tenant_id: scopeID,
    name: `${namePrefix} ${String(index + 1).padStart(2, '0')}`,
    status: 'active' as const,
  }))
}

// 高级密钥管理默认收起（fix-apikeysimple）；需要表格/创建按钮的用例先展开。
async function openAdvanced() {
  const header = await screen.findByRole('button', { name: /高级密钥管理|Advanced key management/ })
  if (header.getAttribute('aria-expanded') !== 'true') fireEvent.click(header)
  await screen.findByTestId('api-key-table-scroll')
}

async function fillCreateForm(
  user: ReturnType<typeof userEvent.setup>,
  ipAllowlist = '',
  directAllowlistInput = false,
) {
  await openAdvanced()
  await user.click(screen.getByRole('button', { name: '创建密钥' }))
  const dialog = screen.getByRole('dialog', { name: '创建API密钥' })
  await user.type(within(dialog).getByLabelText('名称'), 'new reader')
  const scopes = within(dialog).getByRole('combobox', { name: '最小权限范围' })
  await user.click(scopes)
  await user.click(await screen.findByRole('option', { name: '查看网站' }))
  if (ipAllowlist) {
    const input = within(dialog).getByLabelText('IP 允许列表')
    if (directAllowlistInput) fireEvent.change(input, { target: { value: ipAllowlist } })
    else await user.type(input, ipAllowlist)
  }
  await user.click(within(dialog).getByRole('button', { name: /^创建密钥$/ }))
}

describe('AccountApiKeysPage', () => {
  it.each([
    ['a tenant missing api_keys.self.manage', principal({ permissions: ['sites.read'] })],
    ['a platform principal', principal({
      scope_kind: 'platform',
      tenant_id: null,
      roles: ['platform_admin'],
      permissions: ['api_keys.self.manage'],
    })],
  ])('renders a local 403 and performs no API requests for %s', async (_case, actor) => {
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const listSpy = vi.spyOn(apiKeysApi, 'list')
    const getSpy = vi.spyOn(apiKeysApi, 'get')
    const createSpy = vi.spyOn(apiKeysApi, 'create')
    const updateSpy = vi.spyOn(apiKeysApi, 'update')
    const actionSpy = vi.spyOn(apiKeysApi, 'action')

    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    expect(await screen.findByText('无权管理API密钥')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少API密钥管理权限')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(listSpy).not.toHaveBeenCalled()
    expect(getSpy).not.toHaveBeenCalled()
    expect(createSpy).not.toHaveBeenCalled()
    expect(updateSpy).not.toHaveBeenCalled()
    expect(actionSpy).not.toHaveBeenCalled()
    expect(screen.queryByTestId('api-key-table-scroll')).not.toBeInTheDocument()
  })

  it('keeps advanced key management collapsed by default and expands it on demand', async () => {
    authenticate()
    vi.spyOn(apiKeysApi, 'list').mockResolvedValue(apiPage([]))

    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    const header = await screen.findByRole('button', { name: /高级密钥管理/ })
    expect(header).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByTestId('api-key-table-scroll')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '创建密钥' })).not.toBeInTheDocument()

    fireEvent.click(header)
    expect(await screen.findByTestId('api-key-table-scroll')).toBeInTheDocument()
    expect(screen.getByTestId('api-key-advanced')).toContainElement(screen.getByTestId('api-key-table-scroll'))
    expect(header).toHaveAttribute('aria-expanded', 'true')
  })

  it('creates an all-permission, non-expiring default key from the switch and shows api_secret once', async () => {
    authenticate({
      permissions: ['identity.self.read', 'api_keys.self.manage', 'sites.read', 'sites.manage', 'dns.read'],
    })
    let keys: typeof activeKey[] = []
    const list = vi.spyOn(apiKeysApi, 'list').mockImplementation(() => Promise.resolve(apiPage(keys)))
    const simpleIssued = { key: { ...activeKey, name: '默认密钥', scopes: ['dns.read', 'sites.manage', 'sites.read'], ip_allowlist: [] }, secret: issued.secret }
    const create = vi.spyOn(apiKeysApi, 'create').mockImplementation(() => {
      keys = [simpleIssued.key]
      return Promise.resolve(simpleIssued)
    })
    const user = userEvent.setup()
    // userEvent.setup() 会换掉 navigator.clipboard，桩要在它之后挂。
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })

    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    const compatibility = await screen.findByTestId('api-key-compatibility')
    expect(await within(compatibility).findByText('未开启')).toBeInTheDocument()
    expect(within(compatibility).getByText('开启 API 后可配置 IP 白名单。')).toBeInTheDocument()
    expect(within(compatibility).getByText('API 未开启，暂无可用密钥。')).toBeInTheDocument()
    expect(list).toHaveBeenCalledWith(expect.any(String), { limit: 2, status: 'active' }, expect.any(AbortSignal))
    const toggle = within(compatibility).getByRole('switch', { name: 'API 密钥状态' })
    expect(toggle).not.toBeChecked()

    await user.click(toggle)

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(create).toHaveBeenCalledWith(
      expect.any(String),
      { name: '默认密钥', scopes: ['dns.read', 'sites.manage', 'sites.read'], ip_allowlist: [] },
      expect.stringMatching(/^api-key-create-/),
    )
    expect(screen.queryByRole('dialog', { name: '创建API密钥' })).not.toBeInTheDocument()
    const dialog = await findDialogTitled('API 密钥已生成')
    expect(within(dialog).getByText('api_secret 只显示这一次，请立即保存。关闭后无法再次查看，遗失只能重置。')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('api_key')).toHaveValue(simpleIssued.key.key_id)
    expect(within(dialog).getByLabelText('api_secret')).toHaveValue(issued.secret)
    await user.click(within(dialog).getByRole('button', { name: '复制 api_secret' }))
    expect(writeText).toHaveBeenCalledWith(issued.secret)
    await user.click(within(dialog).getByRole('button', { name: '复制 api_key' }))
    expect(writeText).toHaveBeenLastCalledWith(simpleIssued.key.key_id)

    await user.click(within(dialog).getByRole('button', { name: '我已安全保存' }))
    await waitFor(() => expect(screen.queryByLabelText('api_secret')).not.toBeInTheDocument())
    expect(document.body.textContent).not.toContain(issued.secret)
    expect(await within(compatibility).findByText('已开启')).toBeInTheDocument()
    expect(within(compatibility).getByText(simpleIssued.key.key_id)).toBeInTheDocument()
    expect(within(compatibility).getByText('已隐藏，仅在开启或重置时显示一次')).toBeInTheDocument()
  })

  it('disables the switch when the session has no grantable permission', async () => {
    authenticate({ permissions: ['identity.self.read', 'api_keys.self.manage'] })
    vi.spyOn(apiKeysApi, 'list').mockResolvedValue(apiPage([]))
    const create = vi.spyOn(apiKeysApi, 'create')

    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    const compatibility = await screen.findByTestId('api-key-compatibility')
    expect(await within(compatibility).findByText('当前账号没有可授予 API 的权限，无法开启。')).toBeInTheDocument()
    expect(within(compatibility).getByRole('switch', { name: 'API 密钥状态' })).toBeDisabled()
    expect(create).not.toHaveBeenCalled()
  })

  it('shows one active key in the compatibility surface and revokes it through the status switch', async () => {
    authenticate()
    vi.spyOn(apiKeysApi, 'list').mockImplementation((_token, input) => Promise.resolve(
      input.limit === 2 ? apiPage([activeKey]) : apiPage([activeKey]),
    ))
    const action = vi.spyOn(apiKeysApi, 'action').mockReturnValue(new Promise(() => undefined))
    const user = userEvent.setup()

    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    const compatibility = await screen.findByTestId('api-key-compatibility')
    expect(await within(compatibility).findByText('已开启')).toBeInTheDocument()
    expect(within(compatibility).getByText(activeKey.key_id)).toBeInTheDocument()
    expect(within(compatibility).getByRole('textbox', { name: 'IP 白名单' })).toHaveValue('192.0.2.0/24 | 2001:db8::/32')
    const toggle = within(compatibility).getByRole('switch', { name: 'API 密钥状态' })
    expect(toggle).toBeChecked()

    await user.click(toggle)
    await user.click(await screen.findByRole('button', { name: /^撤销$/ }))

    await waitFor(() => expect(action).toHaveBeenCalledWith(
      expect.any(String),
      activeKey.id,
      activeKey.revision,
      'revoke',
      activeKey.ip_allowlist,
      expect.stringMatching(/^api-key-revoke-/),
    ))
  })

  it('resets the default key by rotation, refreshes it to all permissions, and shows the new api_secret once', async () => {
    authenticate()
    vi.spyOn(apiKeysApi, 'list').mockResolvedValue(apiPage([activeKey]))
    const rotated = { key: { ...activeKey, revision: 2 }, secret: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC' }
    const action = vi.spyOn(apiKeysApi, 'action').mockResolvedValue(rotated)
    const user = userEvent.setup()

    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    const compatibility = await screen.findByTestId('api-key-compatibility')
    await user.click(await within(compatibility).findByRole('button', { name: '重置密钥' }))
    expect(await screen.findByText('旧密钥立即失效，权限同步为当前账号的全部权限，新的 api_secret 只显示一次。')).toBeInTheDocument()
    expect(action).not.toHaveBeenCalled()
    const popover = screen.getByText('确认重置密钥？').closest('.ant-popover') as HTMLElement
    await user.click(within(popover).getByRole('button', { name: /^重置密钥$/ }))

    await waitFor(() => expect(action).toHaveBeenCalledWith(
      expect.any(String), activeKey.id, activeKey.revision, 'rotate', activeKey.ip_allowlist,
      expect.stringMatching(/^api-key-rotate-/), { grantAllScopes: true },
    ))
    const dialog = await findDialogTitled('API 密钥已生成')
    expect(within(dialog).getByLabelText('api_key')).toHaveValue(activeKey.key_id)
    expect(within(dialog).getByLabelText('api_secret')).toHaveValue(rotated.secret)
    expect(screen.queryByRole('dialog', { name: 'API密钥（仅显示一次）' })).not.toBeInTheDocument()
  })

  it('saves the simple IP allowlist on blur and Enter, accepting bare IPs and pipe separators', async () => {
    authenticate()
    const key = { ...activeKey, ip_allowlist: [] as string[], expires_at: undefined }
    vi.spyOn(apiKeysApi, 'list').mockResolvedValue(apiPage([key]))
    const update = vi.spyOn(apiKeysApi, 'update').mockImplementation((_token, _id, revision, input) =>
      Promise.resolve({ ...key, ip_allowlist: input.ip_allowlist, revision: revision + 1 }))
    const user = userEvent.setup()

    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    const input = await screen.findByRole('textbox', { name: 'IP 白名单' })
    expect(input).toHaveValue('')
    fireEvent.blur(input)
    expect(update).not.toHaveBeenCalled()

    await user.type(input, '192.0.2.10 | 198.51.100.0/24,2001:db8::1')
    fireEvent.blur(input)
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1))
    expect(update).toHaveBeenCalledWith(
      expect.any(String), key.id, key.revision,
      { name: key.name, scopes: key.scopes, ip_allowlist: ['192.0.2.10/32', '198.51.100.0/24', '2001:db8::1/128'] },
      expect.stringMatching(/^api-key-update-/),
    )

    await user.clear(input)
    await user.type(input, '192.0.2.300{Enter}')
    expect(await screen.findByRole('alert')).toHaveTextContent('请输入规范网络 CIDR')
    expect(update).toHaveBeenCalledTimes(1)

    await user.clear(input)
    await user.type(input, '203.0.113.0/24{Enter}')
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2))
    expect(update.mock.calls[1][3]).toMatchObject({ ip_allowlist: ['203.0.113.0/24'] })
  })

  it('keeps the compatibility switch safe for multiple active keys while retaining advanced actions', async () => {
    authenticate()
    vi.spyOn(apiKeysApi, 'list').mockImplementation((_token, input) => Promise.resolve(
      input.limit === 2
        ? apiPage([activeKey, secondActiveKey], 'more-active-keys')
        : apiPage([activeKey, secondActiveKey]),
    ))

    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    const compatibility = await screen.findByTestId('api-key-compatibility')
    expect(await within(compatibility).findByText('已开启')).toBeInTheDocument()
    expect(within(compatibility).getAllByText('至少 2 个有效密钥')).toHaveLength(2)
    expect(within(compatibility).getByRole('switch', { name: 'API 密钥状态' })).toBeDisabled()
    expect(within(compatibility).getAllByText('你有多个密钥，请在高级密钥管理里操作。').length).toBeGreaterThan(0)
    expect(within(compatibility).queryByRole('button', { name: '重置密钥' })).not.toBeInTheDocument()
    await openAdvanced()
    const advanced = screen.getByTestId('api-key-advanced')
    expect(within(advanced).getByText('production reader')).toBeInTheDocument()
    expect(within(advanced).getByText('automation writer')).toBeInTheDocument()
    expect(within(advanced).getByRole('button', { name: '轮换production reader' })).toBeInTheDocument()
    expect(within(advanced).getByRole('button', { name: '撤销automation writer' })).toBeInTheDocument()
  })

  it('keeps filters, page two, and token-free cache identity across a same-epoch token refresh', async () => {
    const actor = principal({
      permissions: ['identity.self.read', 'api_keys.self.manage', 'sites.read'],
    })
    const oldToken = 'old-api-key-access-token'
    const newToken = 'new-api-key-access-token'
    const items = apiKeyItems('stable active key')
    const listSpy = vi.spyOn(apiKeysApi, 'list').mockImplementation((_token, input) => Promise.resolve(
      input?.offset === 10
        ? apiPage(items.slice(10), '', items.length)
        : apiPage(items.slice(0, 10), 'stable-page-2', items.length),
    ))
    const queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false, gcTime: Infinity },
        mutations: { retry: false },
      },
    })
    useSessionStore.getState().setSession(
      { ...authResponse(actor), access_token: oldToken },
      actor,
    )
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const user = userEvent.setup()

    renderApiKeysWithQueryClient(queryClient)

    await openAdvanced()

    expect(await screen.findByText('stable active key 01')).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: '筛选状态' }))
    await user.click(await screen.findByText('有效', { selector: '.ant-select-item-option-content' }))
    fireEvent.change(screen.getByRole('textbox', { name: '搜索API密钥' }), { target: { value: 'stable' } })
    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith(
      oldToken,
      { limit: 10, status: 'active', name: 'stable' },
      expect.any(AbortSignal),
    ))
    await user.click(await screen.findByTitle('2'))
    expect(await screen.findByText('stable active key 12')).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: '搜索API密钥' })).toHaveValue('stable')
    expect(screen.getByRole('combobox', { name: '筛选状态' }).closest('.ant-select')).toHaveTextContent('有效')
    expect(document.querySelector('.ant-pagination-item-active')).toHaveAttribute('title', '2')
    const readsBeforeRefresh = listSpy.mock.calls.length

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(actor), access_token: newToken },
        actor,
        'refresh',
      )
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(screen.getByText('stable active key 12')).toBeInTheDocument()
    expect(screen.queryByText('stable active key 01')).not.toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: '搜索API密钥' })).toHaveValue('stable')
    expect(screen.getByRole('combobox', { name: '筛选状态' }).closest('.ant-select')).toHaveTextContent('有效')
    expect(document.querySelector('.ant-pagination-item-active')).toHaveAttribute('title', '2')
    expect(screen.getByTestId('api-key-table-scroll')).toHaveAttribute('aria-busy', 'false')
    expect(listSpy).toHaveBeenCalledTimes(readsBeforeRefresh)

    const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    expect(queryKeys).toContainEqual([
      'account-api-keys', actor.user_id, sessionEpoch, 10, 'active', 'stable', '', 10,
    ])
    for (const queryKey of queryKeys) {
      const serializedKey = JSON.stringify(queryKey)
      expect(serializedKey).not.toContain(oldToken)
      expect(serializedKey).not.toContain(newToken)
    }
    expect(document.body.textContent).not.toContain(oldToken)
    expect(document.body.textContent).not.toContain(newToken)

    await queryClient.invalidateQueries({
      queryKey: ['account-api-keys', actor.user_id, sessionEpoch],
    })
    await waitFor(() => expect(listSpy).toHaveBeenCalledTimes(readsBeforeRefresh + 1))
    expect(listSpy).toHaveBeenLastCalledWith(
      newToken,
      { limit: 10, status: 'active', name: 'stable', offset: 10 },
      expect.any(AbortSignal),
    )
    expect(screen.getByText('stable active key 12')).toBeInTheDocument()
  })

  it('invalidates only the current scoped list after success and clears an issued secret for a new tenant', async () => {
    const tenantA = principal({ permissions: ['api_keys.self.manage', 'sites.read'] })
    const tenantB = principal({
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
      permissions: ['api_keys.self.manage', 'sites.read'],
    })
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: 'tenant-a-success-token' }, tenantA,
    )
    const tenantAEpoch = useSessionStore.getState().sessionEpoch
    const foreignKey = ['account-api-keys', '99999999-9999-4999-8999-999999999999', 999] as const
    const foreignData = apiPage([pendingKey])
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    queryClient.setQueryData(foreignKey, foreignData)
    let resolveTenantB!: (value: ReturnType<typeof apiPage<never>>) => void
    const tenantBList = new Promise<ReturnType<typeof apiPage<never>>>((resolve) => { resolveTenantB = resolve })
    const listSpy = vi.spyOn(apiKeysApi, 'list').mockImplementation((token) => {
      if (token === 'tenant-a-success-token') return Promise.resolve(apiPage([]))
      if (token === 'tenant-b-success-token') return tenantBList
      throw new Error(`unexpected API key list token ${token}`)
    })
    vi.spyOn(apiKeysApi, 'create').mockResolvedValue(issued)
    const user = userEvent.setup()

    renderApiKeysWithQueryClient(queryClient)

    await openAdvanced()
    expect(await screen.findByText('暂无API密钥')).toBeInTheDocument()
    await fillCreateForm(user)

    const secretDialog = await screen.findByRole('dialog', { name: 'API密钥（仅显示一次）' })
    expect(within(secretDialog).getByLabelText('一次性API密钥')).toHaveValue(`${issued.key.key_id}.${issued.secret}`)
    await waitFor(() => expect(listSpy).toHaveBeenCalledTimes(4))
    expect(queryClient.getQueryState([
      'account-api-keys', tenantA.user_id, tenantAEpoch, 10, '', '', '', 0,
    ])?.isInvalidated).toBe(false)
    expect(queryClient.getQueryData(foreignKey)).toEqual(foreignData)
    expect(queryClient.getQueryState(foreignKey)?.isInvalidated).toBe(false)

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantB), access_token: 'tenant-b-success-token' }, tenantB,
      )
      await Promise.resolve()
    })

    expect(screen.queryByRole('dialog', { name: 'API密钥（仅显示一次）' })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('一次性API密钥')).not.toBeInTheDocument()
    expect(screen.queryByText('关闭后无法再次查看。请立即保存到安全的凭据管理器。')).not.toBeInTheDocument()
    expect(screen.queryByText(issued.secret)).not.toBeInTheDocument()
    expect(screen.getByTestId('api-key-table-scroll')).toHaveAttribute('aria-busy', 'true')
    expect(queryClient.getQueryData(foreignKey)).toEqual(foreignData)
    expect(queryClient.getQueryState(foreignKey)?.isInvalidated).toBe(false)
    await act(async () => { resolveTenantB(apiPage([])) })
    expect(await screen.findByText('暂无API密钥')).toBeInTheDocument()
  })

  it('clears an uncertain editor and write attempt while the next tenant list is pending', async () => {
    const tenantA = principal({ permissions: ['api_keys.self.manage', 'sites.read'] })
    const tenantB = principal({
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
      permissions: ['api_keys.self.manage', 'sites.read'],
    })
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: 'tenant-a-unknown-token' }, tenantA,
    )
    let resolveTenantB!: (value: ReturnType<typeof apiPage<never>>) => void
    const tenantBList = new Promise<ReturnType<typeof apiPage<never>>>((resolve) => { resolveTenantB = resolve })
    vi.spyOn(apiKeysApi, 'list').mockImplementation((token) => {
      if (token === 'tenant-a-unknown-token') return Promise.resolve(apiPage([]))
      if (token === 'tenant-b-unknown-token') return tenantBList
      throw new Error(`unexpected API key list token ${token}`)
    })
    vi.spyOn(apiKeysApi, 'create').mockRejectedValue(new ApiError('private write topology', 503, 'request_failed'))
    const user = userEvent.setup()

    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    await openAdvanced()
    expect(await screen.findByText('暂无API密钥')).toBeInTheDocument()
    await fillCreateForm(user)
    const editor = await findDialogTitled('创建API密钥')
    expect(within(editor).getByText('操作结果待确认')).toBeInTheDocument()
    expect(await findOutcomeRetry()).toBeInTheDocument()

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantB), access_token: 'tenant-b-unknown-token' }, tenantB,
      )
      await Promise.resolve()
    })

    expect(screen.queryByRole('dialog', { name: '创建API密钥' })).not.toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByText('使用同一请求重试')).not.toBeInTheDocument()
    expect(screen.queryByText('private write topology')).not.toBeInTheDocument()
    expect(screen.getByTestId('api-key-table-scroll')).toHaveAttribute('aria-busy', 'true')
    await act(async () => { resolveTenantB(apiPage([])) })
    expect(await screen.findByText('暂无API密钥')).toBeInTheDocument()
  })

  it('invalidates only the current scoped list after a version conflict', async () => {
    const actor = principal({ permissions: ['api_keys.self.manage', 'sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const currentKey = ['account-api-keys', actor.user_id, sessionEpoch, 10, '', '', '', 0] as const
    const foreignKey = ['account-api-keys', '99999999-9999-4999-8999-999999999999', 999] as const
    const foreignData = apiPage([pendingKey])
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    queryClient.setQueryData(foreignKey, foreignData)
    const listSpy = vi.spyOn(apiKeysApi, 'list').mockResolvedValue(apiPage([activeKey]))
    vi.spyOn(apiKeysApi, 'update').mockRejectedValue(
      new ApiError('private revision owner', 409, 'version_conflict'),
    )
    const user = userEvent.setup()

    renderApiKeysWithQueryClient(queryClient)

    await openAdvanced()
    expect(await screen.findByText('production reader')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '编辑production reader' }))
    await user.click(within(screen.getByRole('dialog', { name: '编辑API密钥' })).getByRole('button', { name: '保存' }))

    expect(await screen.findByText('密钥已被其他操作修改，列表已刷新')).toBeInTheDocument()
    await waitFor(() => expect(listSpy).toHaveBeenCalledTimes(4))
    expect(queryClient.getQueryData(currentKey)).toEqual(apiPage([activeKey]))
    expect(queryClient.getQueryState(currentKey)?.isInvalidated).toBe(false)
    expect(queryClient.getQueryData(foreignKey)).toEqual(foreignData)
    expect(queryClient.getQueryState(foreignKey)?.isInvalidated).toBe(false)
    expect(screen.queryByText('private revision owner')).not.toBeInTheDocument()
  })

  it('clears filters and old caches while isolating late list and detail responses for a new session', async () => {
    const tenantA = principal({
      permissions: ['identity.self.read', 'api_keys.self.manage', 'sites.read'],
    })
    const tenantB = principal({
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
      user_id: '88888888-8888-4888-8888-888888888888',
      permissions: ['identity.self.read', 'api_keys.self.manage', 'sites.read'],
    })
    const tenantAItem = { ...activeKey, name: 'tenant A key' }
    const tenantBItem = {
      ...activeKey,
      id: '77777777-7777-4777-8777-777777777777',
      scope_id: tenantB.scope_id,
      tenant_id: tenantB.scope_id,
      user_id: tenantB.user_id,
      name: 'tenant B key',
      status: 'revoked' as const,
    }
    let resolveTenantB!: (value: ReturnType<typeof apiPage<typeof tenantBItem>>) => void
    const tenantBList = new Promise<ReturnType<typeof apiPage<typeof tenantBItem>>>((resolve) => { resolveTenantB = resolve })
    const tenantALateItem = { ...tenantAItem, name: 'tenant A late list key' }
    let resolveTenantAList!: (value: ReturnType<typeof apiPage<typeof tenantALateItem>>) => void
    const tenantAList = new Promise<ReturnType<typeof apiPage<typeof tenantALateItem>>>((resolve) => { resolveTenantAList = resolve })
    let resolveTenantADetail!: (value: typeof tenantAItem) => void
    const tenantADetail = new Promise<typeof tenantAItem>((resolve) => { resolveTenantADetail = resolve })
    let tenantAReads = 0
    const listSpy = vi.spyOn(apiKeysApi, 'list').mockImplementation((token, input) => {
      if (token === 'tenant-a-api-key-token') {
        tenantAReads += 1
        return input?.name ? tenantAList : Promise.resolve(apiPage([tenantAItem]))
      }
      if (token === 'tenant-b-api-key-token') return tenantBList
      throw new Error(`unexpected API key list token ${token}`)
    })
    const getSpy = vi.spyOn(apiKeysApi, 'get').mockImplementation((token, id) => {
      if (token === 'tenant-a-api-key-token' && id === tenantAItem.id) return tenantADetail
      throw new Error(`unexpected API key detail ${token} ${id}`)
    })
    const queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false, gcTime: Infinity },
        mutations: { retry: false },
      },
    })
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: 'tenant-a-api-key-token' },
      tenantA,
    )
    const tenantAEpoch = useSessionStore.getState().sessionEpoch
    const user = userEvent.setup()

    renderApiKeysWithQueryClient(queryClient)

    await openAdvanced()

    expect(await screen.findByText('tenant A key')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '查看tenant A key' }))
    expect(await screen.findByRole('dialog', { name: 'API密钥详情' })).toBeInTheDocument()
    expect(getSpy).toHaveBeenCalledWith('tenant-a-api-key-token', tenantAItem.id)
    fireEvent.change(screen.getByRole('textbox', { name: '搜索API密钥' }), { target: { value: 'late' } })
    await waitFor(() => expect(tenantAReads).toBe(3))

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantB), access_token: 'tenant-b-api-key-token' },
        tenantB,
      )
      await Promise.resolve()
    })
    const tenantBEpoch = useSessionStore.getState().sessionEpoch

    expect(tenantBEpoch).not.toBe(tenantAEpoch)
    expect(screen.queryByText('tenant A key')).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: 'API密钥详情' })).not.toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: '搜索API密钥' })).toHaveValue('')
    expect(screen.getByRole('combobox', { name: '筛选状态' }).closest('.ant-select')).toHaveTextContent('全部状态')
    expect(screen.getByTestId('api-key-table-scroll')).toHaveAttribute('aria-busy', 'true')
    expect(listSpy).toHaveBeenLastCalledWith(
      'tenant-b-api-key-token', { limit: 10 }, expect.any(AbortSignal),
    )

    await act(async () => { resolveTenantB(apiPage([tenantBItem])) })
    expect(await screen.findByText('tenant B key')).toBeInTheDocument()
    expect(screen.getByText('已撤销')).toBeInTheDocument()

    await act(async () => {
      resolveTenantAList(apiPage([tenantALateItem]))
      resolveTenantADetail(tenantAItem)
    })
    expect(screen.getByText('tenant B key')).toBeInTheDocument()
    expect(screen.queryByText('tenant A key')).not.toBeInTheDocument()
    expect(screen.queryByText('tenant A late list key')).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: 'API密钥详情' })).not.toBeInTheDocument()
    const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    expect(queryKeys.some((key) => key[1] === tenantA.user_id && key[2] === tenantAEpoch)).toBe(false)
    expect(queryKeys).toContainEqual([
      'account-api-keys', tenantB.user_id, tenantBEpoch, 10, '', '', '', 0,
    ])
  })

  it('keeps the table mounted while loading and when the key list is empty', async () => {
    authenticate()
    let resolveList!: (value: ReturnType<typeof apiPage<never>>) => void
    vi.spyOn(apiKeysApi, 'list').mockReturnValue(new Promise((resolve) => { resolveList = resolve }))

    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    await openAdvanced()

    const table = screen.getByTestId('api-key-table-scroll')
    expect(table).toHaveAttribute('aria-busy', 'true')
    await act(async () => { resolveList(apiPage([])) })
    expect(await screen.findByText('暂无API密钥')).toBeInTheDocument()
    expect(table).toBeInTheDocument()
    expect(table).toHaveAttribute('aria-busy', 'false')
  })

  it('localizes list failures, hides server messages, and retries without replacing the table', async () => {
    authenticate()
    let mainReads = 0
    const list = vi.spyOn(apiKeysApi, 'list').mockImplementation((_token, input) => {
      if (input.limit === 2) return Promise.resolve(apiPage([]))
      mainReads += 1
      return mainReads === 1
        ? Promise.reject(new ApiError('private key vault', 503, 'request_failed'))
        : Promise.resolve(apiPage([]))
    })
    const user = userEvent.setup()

    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    await openAdvanced()

    expect(await screen.findByText('API密钥加载失败')).toBeInTheDocument()
    expect(screen.getByText('请求失败，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('private key vault')).not.toBeInTheDocument()
    expect(screen.getByTestId('api-key-table-scroll')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无API密钥')).toBeInTheDocument()
    expect(list).toHaveBeenCalledTimes(3)
    expect(mainReads).toBe(2)
  })

  it('rejects unknown fields in the list envelope', async () => {
    authenticate()
    let mainListCount = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'http://localhost')
      if (url.searchParams.get('limit') === '2') return jsonResponse(apiPage([]))
      mainListCount += 1
      return jsonResponse(mainListCount === 1 ? { ...apiPage([]), unexpected: true } : apiPage([]))
    })
    const user = userEvent.setup()

    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    await openAdvanced()

    expect(await screen.findByText('API密钥加载失败')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无API密钥')).toBeInTheDocument()
    expect(mainListCount).toBe(2)
  })

  it('renders a compact key table and shows a created secret only until dismissal', async () => {
    authenticate()
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      return init?.method === 'POST' ? jsonResponse(issued, 201) : jsonResponse(apiPage([activeKey]))
    })
    const storage = vi.spyOn(Storage.prototype, 'setItem')
    const user = userEvent.setup()
    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])
    await openAdvanced()

    expect(await screen.findByText('production reader')).toBeInTheDocument()
    expect(screen.getByText('cfk_AAAAAAAAAAAAAAAAAAAAAA.********')).toBeInTheDocument()
    expect(screen.getByTestId('api-key-table-scroll')).toHaveAttribute('aria-busy', 'false')

    await fillCreateForm(user, '198.51.100.0/24|2001:db8:1::/48')
    const oneTime = await screen.findByRole('dialog', { name: 'API密钥（仅显示一次）' })
    expect(within(oneTime).getByLabelText('一次性API密钥')).toHaveValue(`${issued.key.key_id}.${issued.secret}`)
    const write = calls.find((call) => call.init?.method === 'POST')
    expect(write?.url).toContain('/v1/account/api-keys')
    expect(new Headers(write?.init?.headers).get('If-Match')).toBe('"0"')
    expect(new Headers(write?.init?.headers).get('Idempotency-Key')).toMatch(/^api-key-create-/)
    expect(write?.init?.body).toBe(JSON.stringify({
      name: 'new reader',
      scopes: ['sites.read'],
      ip_allowlist: ['198.51.100.0/24', '2001:db8:1::/48'],
    }))
    expect(storage).not.toHaveBeenCalled()

    await user.click(within(oneTime).getByRole('button', { name: '我已安全保存' }))
    expect(screen.queryByText(issued.secret)).not.toBeInTheDocument()
    await waitFor(() => expect(screen.queryByLabelText('一次性API密钥')).not.toBeInTheDocument())
  })

  it('freezes an unknown write and retries the exact body and idempotency key', async () => {
    authenticate()
    const writes: Array<{ body?: BodyInit | null; key: string | null; match: string | null }> = []
    let writeCount = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method !== 'POST') return jsonResponse(apiPage([]))
      writeCount += 1
      writes.push({
        body: init?.body,
        key: new Headers(init?.headers).get('Idempotency-Key'),
        match: new Headers(init?.headers).get('If-Match'),
      })
      if (writeCount === 1) return Promise.reject(new TypeError('connection reset'))
      return jsonResponse(issued, 201)
    })
    const user = userEvent.setup()
    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])
    await openAdvanced()

    expect(await screen.findByText('暂无API密钥')).toBeInTheDocument()
    await fillCreateForm(user)
    const editor = await findDialogTitled('创建API密钥')
    expect(within(editor).getByText('操作结果待确认')).toBeInTheDocument()
    for (const button of screen.getAllByRole('button', { name: '创建密钥' })) {
      expect(button).toBeDisabled()
    }

    await user.click(await findOutcomeRetry())
    expect(await screen.findByRole('dialog', { name: 'API密钥（仅显示一次）' })).toBeInTheDocument()
    expect(writes).toHaveLength(2)
    expect(writes[1]).toEqual(writes[0])
  })

  it('treats a malformed successful issuance as unknown and retries the exact request', async () => {
    authenticate()
    const writes: Array<{ body?: BodyInit | null; key: string | null; match: string | null }> = []
    let writeCount = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method !== 'POST') return jsonResponse(apiPage([]))
      writeCount += 1
      writes.push({
        body: init.body,
        key: new Headers(init.headers).get('Idempotency-Key'),
        match: new Headers(init.headers).get('If-Match'),
      })
      if (writeCount === 1) return jsonResponse({ key: issued.key }, 201)
      if (writeCount === 2) return jsonResponse({ ...issued, unexpected: true }, 201)
      return jsonResponse(issued, 201)
    })
    const user = userEvent.setup()
    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])
    await openAdvanced()

    expect(await screen.findByText('暂无API密钥')).toBeInTheDocument()
    await fillCreateForm(user)
    const editor = await findDialogTitled('创建API密钥')
    expect(within(editor).getByText('操作结果待确认')).toBeInTheDocument()
    expect(screen.queryByText('API密钥已创建')).not.toBeInTheDocument()

    await user.click(await findOutcomeRetry())
    expect(within(editor).getByText('操作结果待确认')).toBeInTheDocument()
    await waitFor(() => expect(writes).toHaveLength(2))
    await user.click(await findOutcomeRetry())
    expect(await screen.findByRole('dialog', { name: 'API密钥（仅显示一次）' })).toBeInTheDocument()
    expect(writes).toHaveLength(3)
    expect(writes[1]).toEqual(writes[0])
    expect(writes[2]).toEqual(writes[0])
  })

  it('edits metadata with a revision guard', async () => {
    authenticate()
    const writes: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (!init?.method) return jsonResponse(apiPage([pendingKey, activeKey]))
      writes.push({ url, init })
      return jsonResponse({ ...activeKey, name: 'renamed reader', revision: 2 })
    })
    const user = userEvent.setup()
    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])
    await openAdvanced()

    expect(await screen.findByText('pending reader')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '编辑production reader' }))
    const editor = screen.getByRole('dialog', { name: '编辑API密钥' })
    const name = within(editor).getByLabelText('名称')
    await user.clear(name)
    await user.type(name, 'renamed reader')
    const allowlist = within(editor).getByLabelText('IP 允许列表')
    expect(allowlist).toHaveValue('192.0.2.0/24\n2001:db8::/32')
    await user.clear(allowlist)
    await user.type(allowlist, '203.0.113.0/24')
    await user.click(within(editor).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(writes).toHaveLength(1))
    await waitFor(() => expect(screen.getByRole('button', { name: '创建密钥' })).toBeEnabled())

    expect(new URL(writes[0].url, 'http://localhost').pathname).toBe(`/v1/account/api-keys/${activeKey.id}`)
    expect(writes[0].init?.method).toBe('PATCH')
    expect(new Headers(writes[0].init?.headers).get('If-Match')).toBe('"1"')
    expect(new Headers(writes[0].init?.headers).get('Idempotency-Key')).toMatch(/^api-key-update-/)
    expect(JSON.parse(String(writes[0].init?.body))).toEqual({
      name: 'renamed reader',
      scopes: ['sites.read'],
      ip_allowlist: ['203.0.113.0/24'],
      expires_at: new Date(activeKey.expires_at).toISOString(),
    })
  })

  it.each([
    { label: '激活', namedLabel: '激活pending reader', operation: 'activate', item: pendingKey },
    { label: '轮换', namedLabel: '轮换production reader', operation: 'rotate', item: activeKey },
    { label: '撤销', namedLabel: '撤销production reader', operation: 'revoke', item: activeKey },
  ])('$label dispatches the item revision and a unique idempotency key', async ({ label, namedLabel, operation, item }) => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => jsonResponse(apiPage([item])))
    const action = vi.spyOn(apiKeysApi, 'action').mockReturnValue(new Promise(() => undefined))
    const user = userEvent.setup()
    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])
    await openAdvanced()

    expect(await screen.findByText(item.name)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: namedLabel }))
    await user.click(await screen.findByRole('button', { name: new RegExp(`^${label}$`) }))
    await waitFor(() => expect(action).toHaveBeenCalledTimes(1))
    for (const button of screen.getAllByRole('button', { name: '创建密钥' })) expect(button).toBeDisabled()

    expect(action).toHaveBeenCalledWith(
      expect.any(String),
      item.id,
      item.revision,
      operation,
      item.ip_allowlist,
      expect.stringMatching(new RegExp(`^api-key-${operation}-`)),
    )
  })

  it('renders exact CIDR chips in the table and detail while naming an empty allowlist as unrestricted', async () => {
    authenticate()
    const unrestricted = {
      ...activeKey,
      id: '66666666-6666-4666-8666-666666666666',
      key_id: 'cfk_DDDDDDDDDDDDDDDDDDDDDD',
      key_prefix: 'cfk_DDDDDDDDDDDDDDDDDDDDDD.',
      name: 'unrestricted key',
      ip_allowlist: [],
    }
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const path = new URL(String(input), 'http://localhost').pathname
      if (path === '/v1/account/api-keys') return jsonResponse(apiPage([activeKey, unrestricted]))
      return jsonResponse(activeKey)
    })
    const user = userEvent.setup()

    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    await openAdvanced()

    expect(await screen.findByText('192.0.2.0/24')).toBeInTheDocument()
    expect(screen.getByText('2001:db8::/32')).toBeInTheDocument()
    expect(screen.getByText('不限制来源 IP')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '查看production reader' }))
    const detail = await screen.findByRole('dialog', { name: 'API密钥详情' })
    expect(within(detail).getByText('192.0.2.0/24')).toBeInTheDocument()
    expect(within(detail).getByText('2001:db8::/32')).toBeInTheDocument()
  })

  it.each<[string, string, string, boolean]>([
    ['api_key_ip_allowlist_invalid_cidr', '192.0.2.1/24', '请输入规范网络 CIDR（不允许主机位、地址区或非规范写法）', false],
    ['api_key_ip_allowlist_unsupported_prefix', '192.0.2.0/33', 'CIDR 前缀长度超出地址范围', false],
    ['api_key_ip_allowlist_duplicate', '192.0.2.0/24{enter}192.0.2.0/24', 'IP 允许列表不能包含重复网段', false],
    ['api_key_ip_allowlist_overlap', '192.0.2.0/24{enter}192.0.2.128/25', 'IP 允许列表不能包含重叠网段', false],
    ['api_key_ip_allowlist_too_many', Array.from({ length: 33 }, (_, index) => `10.${index}.0.0/16`).join('\n'), 'IP 允许列表最多 32 个网段', true],
  ])('blocks invalid allowlists with localized stable code %s', async (_code, value, expected, directInput) => {
    authenticate()
    vi.spyOn(apiKeysApi, 'list').mockResolvedValue(apiPage([]))
    const create = vi.spyOn(apiKeysApi, 'create')
    const user = userEvent.setup()

    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])
    await openAdvanced()
    expect(await screen.findByText('暂无API密钥')).toBeInTheDocument()
    await fillCreateForm(user, value, directInput)

    expect(await screen.findByText(expected)).toBeInTheDocument()
    expect(create).not.toHaveBeenCalled()
  })

  it('maps a server allowlist error without exposing the raw matching prefix', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (!init?.method) return jsonResponse(apiPage([]))
      return jsonResponse({
        error: {
          code: 'api_key_ip_allowlist_overlap',
          message: 'matching prefix 10.0.0.0/8',
          request_id: 'api-key-allowlist-request-1',
          params: { field: 'ip_allowlist', index: 1, overlaps: 0 },
        },
      }, 422)
    })
    const user = userEvent.setup()

    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    await openAdvanced()
    expect(await screen.findByText('暂无API密钥')).toBeInTheDocument()
    await fillCreateForm(user, '10.0.0.0/8\n192.0.2.0/24', true)

    expect(await screen.findByText('IP 允许列表不能包含重叠网段')).toBeInTheDocument()
    expect(screen.queryByText('matching prefix')).not.toBeInTheDocument()
    // fix-feedbackui2: under the allowlist field (the editor stays open), not a dialog.
    expect(screen.getByText('IP 允许列表不能包含重叠网段').closest('.ant-form-item')).toHaveClass('ant-form-item-has-error')
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
  })

  it('renders permission denial without leaking the server message', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      error: { code: 'permission_denied', message: 'internal RBAC rule name' },
    }), { status: 403, headers: { 'Content-Type': 'application/json' } }))
    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    expect(await screen.findByText('无权管理API密钥')).toBeInTheDocument()
    expect(screen.queryByText('internal RBAC rule name')).not.toBeInTheDocument()
  })

  it('filters, paginates, and reopens metadata-only details without recovering a secret', async () => {
    authenticate()
    const items = Array.from({ length: 12 }, (_, index) => ({
      ...activeKey,
      id: `33333333-3333-4333-8333-${String(index + 1).padStart(12, '0')}`,
      key_id: `cfk_${String(index + 1).padStart(22, 'A')}`,
      key_prefix: `cfk_${String(index + 1).padStart(22, 'A')}.`,
      name: index === 11 ? 'production twelfth' : `reader ${String(index + 1).padStart(2, '0')}`,
      status: index === 10 ? 'revoked' : 'active',
    }))
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'http://localhost')
      if (url.pathname === '/v1/account/api-keys' && url.searchParams.get('name') === 'production') {
        return jsonResponse(apiPage([items[11]], '', 1))
      }
      if (url.pathname === '/v1/account/api-keys' && url.searchParams.get('offset') === '10') {
        return jsonResponse(apiPage(items.slice(10), '', items.length))
      }
      if (url.pathname === '/v1/account/api-keys') return jsonResponse(apiPage(items.slice(0, 10), 'page-2', items.length))
      return jsonResponse(items[11])
    })
    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])
    await openAdvanced()

    expect(await screen.findByText('reader 01')).toBeInTheDocument()
    expect(screen.queryByText('production twelfth')).not.toBeInTheDocument()
    expect(await screen.findByText('共 12 条')).toBeInTheDocument()
    fireEvent.click(screen.getByTitle('2'))
    expect(await screen.findByText('production twelfth')).toBeInTheDocument()

    fireEvent.change(screen.getByRole('textbox', { name: '搜索API密钥' }), {
      target: { value: 'production' },
    })
    expect(await screen.findByText('production twelfth')).toBeInTheDocument()
    expect(screen.queryByText('reader 01')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '查看production twelfth' }))
    const detail = await screen.findByRole('dialog', { name: 'API密钥详情' })
    expect(await within(detail).findByText('production twelfth')).toBeInTheDocument()
    expect(within(detail).queryByText(issued.secret)).not.toBeInTheDocument()
    expect(within(detail).queryByLabelText('一次性API密钥')).not.toBeInTheDocument()
    fireEvent.click(within(detail).getByRole('button', { name: '关闭' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'API密钥详情' })).not.toBeInTheDocument())
    await waitFor(() => expect(document.querySelector('.ant-modal-wrap')).not.toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: '查看production twelfth' }))
    const reopened = await screen.findByRole('dialog', { name: 'API密钥详情' })
    expect(await within(reopened).findByText('production twelfth')).toBeInTheDocument()
    expect(screen.queryByText(issued.secret)).not.toBeInTheDocument()
  })

  it('renders complete English metadata and keeps the 390px table scroll boundary', async () => {
    await changeLocale('en-US')
    authenticate()
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    window.dispatchEvent(new Event('resize'))
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => jsonResponse(apiPage([activeKey])))
    renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])
    await openAdvanced()

    expect(await screen.findByRole('heading', { name: 'API access configuration' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Advanced key management' })).toBeInTheDocument()
    expect(await screen.findByText('production reader')).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Key identifier' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Scopes' })).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByTestId('api-key-table-scroll')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByTestId('api-key-table-scroll')).toHaveAttribute('aria-busy', 'false'))
  })

  it('keeps the API key panel scoped for the compact account layout', async () => {
    authenticate()
    vi.spyOn(apiKeysApi, 'list').mockResolvedValue(apiPage([]))

    const { container } = renderWithProviders(<AccountApiKeysPage />, ['/account/api-key'])

    await openAdvanced()

    expect(await screen.findByText('暂无API密钥')).toBeInTheDocument()
    const panel = container.querySelector('.account-api-keys-page')
    expect(panel).toBeInTheDocument()
    expect(panel).toContainElement(screen.getByTestId('api-key-table-scroll'))
    expect(panel?.querySelector('.identity-toolbar')).toBeInTheDocument()
  })
})
