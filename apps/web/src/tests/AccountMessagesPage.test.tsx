import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import AccountMessagesPage from '../pages/AccountMessagesPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

function json(value: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }))
}

async function flushUi() {
  await act(async () => {
    await Promise.resolve()
    await new Promise((resolve) => setTimeout(resolve, 50))
  })
}

const item = {
  id: '11111111-1111-4111-8111-111111111111', announcement_id: '22222222-2222-4222-8222-222222222222',
  announcement_version: 1, title: '维护通知', body: '## 窗口\n\n**今晚**维护。', published_at: '2026-07-22T02:00:00Z', state_revision: 1,
}

function authenticate() {
  const actor = principal({ permissions: ['announcements.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function renderMessagesWithQueryClient(queryClient: QueryClient) {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/account/message']}>
            <AccountMessagesPage />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

describe('AccountMessagesPage', () => {
  it.each([
    ['a tenant missing announcements.read', principal({ permissions: [] })],
    ['a platform scope carrying a tenant lineage', principal({
      scope_kind: 'platform',
      tenant_id: '33333333-3333-4333-8333-333333333333',
      roles: ['platform_admin'],
      permissions: ['announcements.read'],
    })],
  ])('renders a local 403 and performs no reads for %s', async (_case, actor) => {
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<AccountMessagesPage />, ['/account/message'])

    expect(await screen.findByText('当前账号没有站内消息读取权限')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(screen.queryByTestId('account-messages-scroll')).not.toBeInTheDocument()
  })

  // 账户消息页对管理员展示的是他自己的收件箱，
  // 所以平台作用域读自身作用域而不是被本地拒绝。
  it('reads its own scope for a platform principal', async () => {
    const actor = principal({
      scope_id: '01a0859f-e949-7d00-9c85-cc02f6332fde',
      scope_kind: 'platform',
      tenant_id: null,
      roles: ['platform_owner'],
      permissions: ['platform.admin', 'announcements.read'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ items: [], total: 0, unread_total: 0 }))

    renderWithProviders(<AccountMessagesPage />, ['/account/message'])

    expect(await screen.findByTestId('account-messages-scroll')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(String(fetchSpy.mock.calls[0]?.[0])).toContain('/v1/account/messages')
  })

  it('keeps the unread cursor page and token-free cache identity across a same-epoch token refresh', async () => {
    const actor = principal({ permissions: ['announcements.read'] })
    const oldToken = 'old-message-access-token'
    const newToken = 'new-message-access-token'
    const unreadItem = { ...item, title: '未读第一页消息' }
    const secondPageItem = {
      ...item,
      id: '55555555-5555-4555-8555-555555555555',
      announcement_id: '66666666-6666-4666-8666-666666666666',
      title: '未读第二页消息',
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.includes('filter=unread') && url.includes('offset=10')) return json({ items: [secondPageItem], total: 11 })
      if (url.includes('filter=unread')) return json({ items: [unreadItem], next_cursor: 'unread-next', total: 11 })
      return json({ items: [item], total: 1 })
    })
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

    renderMessagesWithQueryClient(queryClient)

    expect(await screen.findByText('维护通知')).toBeInTheDocument()
    // tp-b7：后端没有的用户ID/用户套餐ID/网站ID 不做禁用占位，"发布时间""状态"列去掉。
    expect(screen.queryByPlaceholderText('请输入用户ID')).not.toBeInTheDocument()
    expect(screen.queryByPlaceholderText('请输入用户套餐ID')).not.toBeInTheDocument()
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: '所属用户ID' })).not.toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: '发布时间' })).not.toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: '状态' })).not.toBeInTheDocument()
    expect(screen.getAllByRole('columnheader').map((cell) => cell.textContent)).toEqual(['标题', '创建时间', '操作'])
    await user.click(screen.getByRole('combobox', { name: '消息状态' }))
    await user.click(await screen.findByText('未读', { selector: '.ant-select-item-option-content' }))
    expect(await screen.findByText('未读第一页消息')).toBeInTheDocument()
    expect(screen.getByText('共 11 条')).toBeInTheDocument()
    await user.click(screen.getByTitle('2'))
    expect(await screen.findByText('未读第二页消息')).toBeInTheDocument()
    const readsBeforeRefresh = fetchSpy.mock.calls.length

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(actor), access_token: newToken },
        actor,
        'refresh',
      )
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(screen.getByText('未读第二页消息')).toBeInTheDocument()
    expect(screen.queryByText('未读第一页消息')).not.toBeInTheDocument()
    expect(screen.getByTestId('account-messages-scroll')).toHaveAttribute('aria-busy', 'false')
    expect(fetchSpy).toHaveBeenCalledTimes(readsBeforeRefresh)
    const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    expect(queryKeys).toEqual(expect.arrayContaining([
      ['account-messages', actor.scope_id, sessionEpoch, 'all', 10, 1],
      ['account-messages', actor.scope_id, sessionEpoch, 'unread', 10, 1],
      ['account-messages', actor.scope_id, sessionEpoch, 'unread', 10, 2],
    ]))
    for (const queryKey of queryKeys) {
      const serializedKey = JSON.stringify(queryKey)
      expect(serializedKey).not.toContain(oldToken)
      expect(serializedKey).not.toContain(newToken)
    }
    expect(document.body.textContent).not.toContain(oldToken)
    expect(document.body.textContent).not.toContain(newToken)
  })

  it('clears the old cursor page and restarts an unfiltered first page for a new tenant session', async () => {
    const tenantA = principal({ permissions: ['announcements.read'] })
    const tenantB = principal({
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
      user_id: '88888888-8888-4888-8888-888888888888',
      permissions: ['announcements.read'],
    })
    const tenantAPage = {
      ...item,
      id: '99999999-9999-4999-8999-999999999999',
      title: '租户 A 第二页消息',
    }
    const tenantBItem = {
      ...item,
      id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      title: '租户 B 第一页消息',
    }
    let resolveTenantB!: (response: Response) => void
    const tenantBResponse = new Promise<Response>((resolve) => { resolveTenantB = resolve })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      const authorization = new Headers(init?.headers).get('Authorization')
      if (authorization === 'Bearer tenant-a-message-token') {
        if (url.includes('filter=unread') && url.includes('offset=10')) return json({ items: [tenantAPage], total: 11 })
        if (url.includes('filter=unread')) return json({ items: [item], total: 11 })
        return json({ items: [item], total: 1 })
      }
      if (authorization === 'Bearer tenant-b-message-token') return tenantBResponse
      throw new Error(`unexpected message read ${authorization ?? 'without authorization'} ${url}`)
    })
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: 'tenant-a-message-token' },
      tenantA,
    )
    const user = userEvent.setup()

    renderWithProviders(<AccountMessagesPage />, ['/account/message'])

    expect(await screen.findByText('维护通知')).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: '消息状态' }))
    await user.click(await screen.findByText('未读', { selector: '.ant-select-item-option-content' }))
    await user.click(await screen.findByTitle('2'))
    expect(await screen.findByText('租户 A 第二页消息')).toBeInTheDocument()

    act(() => useSessionStore.getState().setSession(
      { ...authResponse(tenantB), access_token: 'tenant-b-message-token' },
      tenantB,
    ))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => (
      new Headers(init?.headers).get('Authorization') === 'Bearer tenant-b-message-token'
    ))).toBe(true))

    expect(screen.queryByText('租户 A 第二页消息')).not.toBeInTheDocument()
    expect(screen.getByTestId('account-messages-scroll')).toHaveAttribute('aria-busy', 'true')
    const tenantBCall = fetchSpy.mock.calls.find(([, init]) => (
      new Headers(init?.headers).get('Authorization') === 'Bearer tenant-b-message-token'
    ))
    expect(tenantBCall?.[0]).toBe('/v1/account/messages?limit=10')

    await act(async () => resolveTenantB(await json({ items: [tenantBItem] })))
    expect(await screen.findByText('租户 B 第一页消息')).toBeInTheDocument()
  })

  it('loads the inbox, marks detail delivered, then marks it read', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (!init?.method) return json({ items: [item], next_cursor: 'next-cursor' })
      if (url.endsWith('/delivered')) return json({ event_id: item.id, delivered_at: '2026-07-22T02:01:00Z', revision: 2 })
      if (url.endsWith('/read')) return json({ event_id: item.id, delivered_at: '2026-07-22T02:01:00Z', read_at: '2026-07-22T02:02:00Z', revision: 3 })
      throw new Error(`unexpected request ${url}`)
    })
    const user = userEvent.setup()

    renderWithProviders(<AccountMessagesPage />, ['/account/message'])
    await flushUi()
    const title = await screen.findByText('维护通知')
    expect(within(title.closest('tr')!).getByRole('img', { name: '未读' })).toBeInTheDocument()
    await user.click(within(title.closest('tr')!).getByRole('button', { name: '查看' }))
    await flushUi()

    expect(await screen.findByText('今晚')).toBeInTheDocument()
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).endsWith('/delivered'))).toBe(true))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: '标记已读' }))
    await flushUi()
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).endsWith('/read'))).toBe(true))

    const delivered = fetchSpy.mock.calls.find(([url]) => String(url).endsWith('/delivered'))!
    const read = fetchSpy.mock.calls.find(([url]) => String(url).endsWith('/read'))!
    expect(new Headers(delivered[1]?.headers).get('If-Match')).toBe('"1"')
    expect(new Headers(read[1]?.headers).get('If-Match')).toBe('"2"')
  })

  it('keeps an unknown read locked to the same revision, body, and key', async () => {
    authenticate()
    let reads = 0
    const deliveredItem = { ...item, delivered_at: '2026-07-22T02:01:00Z' }
    const otherItem = {
      ...deliveredItem,
      id: '33333333-3333-4333-8333-333333333333',
      announcement_id: '44444444-4444-4444-8444-444444444444',
      title: '另一条通知',
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (!init?.method) return json({ items: [deliveredItem, otherItem] })
      if (String(input).endsWith('/read')) {
        reads += 1
        if (reads === 1) return Promise.reject(new TypeError('connection closed'))
        return json({ event_id: item.id, delivered_at: deliveredItem.delivered_at, read_at: '2026-07-22T02:02:00Z', revision: 2 })
      }
      throw new Error(`unexpected request ${String(input)}`)
    })
    const user = userEvent.setup()

    renderWithProviders(<AccountMessagesPage />, ['/account/message'])
    await flushUi()
    const originalRow = (await screen.findByText('维护通知')).closest('tr')!
    await user.click(within(originalRow).getByRole('button', { name: '标记已读' }))
    await flushUi()
    expect(await screen.findByText('操作结果待确认')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: '使用同一请求重试' })).toHaveLength(1)
    const otherRow = screen.getByText('另一条通知').closest('tr')!
    expect(otherRow).toHaveAttribute('aria-disabled', 'true')
    expect(otherRow).toHaveStyle({ cursor: 'default' })
    fireEvent.click(otherRow)
    expect(within(screen.getByRole('dialog')).getByText('维护通知')).toBeInTheDocument()
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: '使用同一请求重试' }))
    await flushUi()
    await waitFor(() => expect(reads).toBe(2))

    const calls = fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/read'))
    expect(calls.map(([url]) => String(url))).toEqual([
      `/v1/account/messages/${item.id}/read`,
      `/v1/account/messages/${item.id}/read`,
    ])
    expect(calls[0][1]?.body).toBe(calls[1][1]?.body)
    expect(new Headers(calls[0][1]?.headers).get('Idempotency-Key')).toBe(
      new Headers(calls[1][1]?.headers).get('Idempotency-Key'),
    )
  })

  it('keeps an unknown delivered write locked to the same revision, body, and key', async () => {
    authenticate()
    let deliveries = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (!init?.method) return json({ items: [item] })
      if (String(input).endsWith('/delivered')) {
        deliveries += 1
        if (deliveries === 1) return Promise.reject(new TypeError('response lost'))
        return json({ event_id: item.id, delivered_at: '2026-07-22T02:01:00Z', revision: 2 })
      }
      throw new Error(`unexpected request ${String(input)}`)
    })
    const user = userEvent.setup()

    renderWithProviders(<AccountMessagesPage />, ['/account/message'])
    await flushUi()
    const row = (await screen.findByText('维护通知')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '查看' }))
    await flushUi()

    expect(await screen.findByText('操作结果待确认')).toBeInTheDocument()
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: '使用同一请求重试' }))
    await flushUi()
    await waitFor(() => expect(deliveries).toBe(2))

    const calls = fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/delivered'))
    expect(calls[0][1]?.body).toBe(calls[1][1]?.body)
    expect(new Headers(calls[0][1]?.headers).get('Idempotency-Key')).toBe(
      new Headers(calls[1][1]?.headers).get('Idempotency-Key'),
    )
  })

  it('renders the loading state while the inbox is pending', () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise<Response>(() => undefined))

    renderWithProviders(<AccountMessagesPage />, ['/account/message'])

    expect(screen.getByTestId('account-messages-scroll')).toHaveAttribute('aria-busy', 'true')
  })

  it('renders a localized list error and retries into the empty state', async () => {
    authenticate()
    let reads = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      reads += 1
      return reads === 1
        ? json({ error: { code: 'store_unavailable', message: 'postgres connection detail' } }, 500)
        : json({ items: [] })
    })
    const user = userEvent.setup()

    renderWithProviders(<AccountMessagesPage />, ['/account/message'])
    await flushUi()

    expect((await screen.findAllByText('消息加载失败，请稍后重试')).length).toBeGreaterThan(0)
    expect(screen.queryByText('postgres connection detail')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    await flushUi()
    expect(await screen.findByText('暂无站内消息')).toBeInTheDocument()
    expect(reads).toBe(2)
  })

  it('falls back to a localized stable message when a conflict key is not yet integrated', async () => {
    authenticate()
    const deliveredItem = { ...item, delivered_at: '2026-07-22T02:01:00Z' }
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => init?.method
      ? json({ error: { code: 'version_conflict', message: 'internal revision detail' } }, 409)
      : json({ items: [deliveredItem] }))
    const user = userEvent.setup()

    renderWithProviders(<AccountMessagesPage />, ['/account/message'])
    await flushUi()
    const row = (await screen.findByText('维护通知')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '标记已读' }))
    await flushUi()

    expect((await screen.findAllByText('消息加载失败，请稍后重试')).length).toBeGreaterThan(0)
    expect(screen.queryByText('internal revision detail')).not.toBeInTheDocument()
  })

  it('filters, shows the total and jumps to a page by offset', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ items: [], total: 35 }))

    renderWithProviders(<AccountMessagesPage />, ['/account/message'])
    await flushUi()
    await screen.findByText('暂无站内消息')
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '消息状态' }))
    fireEvent.click(await screen.findByText('未读', { selector: '.ant-select-item-option-content' }))
    await flushUi()
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).includes('filter=unread'))).toBe(true))
    expect(await screen.findByText('共 35 条')).toBeInTheDocument()
    await userEvent.setup().click(screen.getByTitle('4'))
    await flushUi()
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url) === '/v1/account/messages?filter=unread&limit=10&offset=30')).toBe(true))
  })

  it('renders permission denial without exposing server text', async () => {
    const actor = principal({ permissions: ['announcements.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ error: { code: 'permission_denied', message: 'internal detail' } }, 403))

    renderWithProviders(<AccountMessagesPage />, ['/account/message'])
    await flushUi()

    expect(await screen.findByText('当前账号没有站内消息读取权限')).toBeInTheDocument()
    expect(screen.queryByText('internal detail')).not.toBeInTheDocument()
  })

  it('keeps the compact reference surface and detail state labels', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ items: [item] }))
    const user = userEvent.setup()

    const view = renderWithProviders(<AccountMessagesPage />, ['/account/message'])
    // 页内标题只留给读屏（顶部条显示标题）。
    expect(await screen.findByRole('heading', { name: '消息查询' })).toHaveClass('visually-hidden')
    expect(await screen.findByText('维护通知')).toBeInTheDocument()
    expect(view.container.querySelector('.account-messages-page')).toBeInTheDocument()
    expect(view.container.querySelector('.account-messages-toolbar')).toBeInTheDocument()
    expect(view.container.querySelector('.account-messages-table-scroll')).toBeInTheDocument()
    expect(screen.getByRole('img', { name: '未读' })).toHaveClass('account-message-unread-dot')

    await user.click(within(screen.getByText('维护通知').closest('tr')!).getByRole('button', { name: '查看' }))
    expect(await screen.findByRole('dialog')).toHaveClass('account-messages-detail-modal')
    expect(screen.getByRole('dialog')).toHaveTextContent('今晚')
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: '标记已读' }))
    await flushUi()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it.each([
    ['en-US', 'No in-app messages', 'Created at'],
    ['qps-ploc', '［暂~无~站~内~消~息~］', '［创~建~时~间~］'],
  ] as const)('has a complete %s state surface', async (locale, empty, createdAt) => {
    await changeLocale(locale)
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ items: [] }))

    renderWithProviders(<AccountMessagesPage />, ['/account/message'])
    await flushUi()

    expect(await screen.findByText(empty)).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: createdAt })).toBeInTheDocument()
  })

  // SEC-ACCOUNT-07：事件提醒走本人通知事件投影，按类型/网站 ID 过滤，显示事件时的网站与用户套餐 ID。
  it('SEC-ACCOUNT-07: lists own event alerts with event-time site and package IDs and filters by them', async () => {
    authenticate()
    const siteID = '44444444-4444-4444-8444-444444444444'
    const packageID = '55555555-5555-4555-8555-555555555555'
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).startsWith('/v1/account/notification-messages')
      ? json({ schema: 'cdnca.notification-own-messages/v1', total: 2, items: [
        { id: '66666666-6666-4666-8666-666666666666', type: 'security.attack.detected', title: '网站遭受攻击', site_id: siteID, package_id: null, created_at: '2026-10-25T02:00:00Z', content: '<b>a.example.com</b> 5 分钟内拦截 1200 次' },
        { id: '77777777-7777-4777-8777-777777777777', type: 'package.monitor.traffic.triggered', title: null, site_id: null, package_id: packageID, created_at: '2026-10-25T01:00:00Z', content: null },
      ] })
      : json({ items: [], total: 0 }))
    const user = userEvent.setup()

    renderWithProviders(<AccountMessagesPage />, ['/account/message'])
    await flushUi()
    await user.click(screen.getByText('事件提醒'))
    expect(await screen.findByText('网站遭受攻击')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([url]) => String(url) === '/v1/account/notification-messages?limit=10')).toBe(true)
    expect(fetchSpy.mock.calls.some(([url]) => String(url).includes('/v1/admin/'))).toBe(false)
    expect(screen.getByText(siteID)).toBeInTheDocument()
    expect(screen.getByText(packageID)).toBeInTheDocument()
    expect(screen.getByText('流量超限')).toBeInTheDocument()
    expect(screen.getByText('（无标题）')).toBeInTheDocument()
    expect(screen.getByText('共 2 条')).toBeInTheDocument()

    // 网站/用户套餐可输名称或展示 ID，边输入边生效；完整 ID 按 ID 过滤。
    await user.type(screen.getByRole('textbox', { name: '用户套餐ID' }), '基础套餐')
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url) === `/v1/account/notification-messages?package=${encodeURIComponent('基础套餐')}&limit=10`)).toBe(true))
    await user.clear(screen.getByRole('textbox', { name: '用户套餐ID' }))
    await user.type(screen.getByRole('combobox', { name: '网站ID' }), siteID)
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url) === `/v1/account/notification-messages?site_id=${siteID}&limit=10`)).toBe(true))
    // 超长关键字就地标错（不弹窗），不发请求。
    const calls = fetchSpy.mock.calls.length
    await user.clear(screen.getByRole('combobox', { name: '网站ID' }))
    await user.click(screen.getByRole('combobox', { name: '网站ID' }))
    await user.paste('a'.repeat(129))
    expect(await screen.findByText('最多 128 个字符，不能含控制字符', { selector: '.account-messages-filter-error' })).toBeInTheDocument()
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
    await new Promise((resolve) => setTimeout(resolve, 500))
    expect(fetchSpy.mock.calls.slice(calls).some(([url]) => String(url).startsWith('/v1/account/notification-messages') && String(url).includes('a'.repeat(129)))).toBe(false)
    await user.clear(screen.getByRole('combobox', { name: '网站ID' }))

    const row = screen.getByText('网站遭受攻击').closest('tr')!
    await user.click(within(row).getByRole('button', { name: /查看/ }))
    // 正文按纯文本显示，不渲染 HTML。
    const body = await screen.findByText('<b>a.example.com</b> 5 分钟内拦截 1200 次')
    expect(body.closest('.ant-modal')).not.toBeNull()
    expect(screen.getByText(`网站ID: ${siteID}`)).toBeInTheDocument()
  })
})
