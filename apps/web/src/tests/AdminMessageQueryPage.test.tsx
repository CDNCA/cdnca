import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'

import { notificationsApi, type NotificationDeliveryPolicy } from '../api/notifications'
import { sitesApi, type SiteListResponse } from '../api/sites'
import { usersApi, type UserListResponse } from '../api/users'
import { useSessionStore } from '../auth/session'
import AdminMessageQueryPage from '../pages/AdminMessageQueryPage'
import type { AdminMessage, AdminMessagePage } from '../pages/AdminMessageQueryPage.adapter'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'


const scopeID = '22222222-2222-4222-8222-222222222222'
const userID = '33333333-3333-4333-8333-333333333333'
const messageID = '44444444-4444-4444-8444-444444444444'
const nextCursor = '55555555-5555-4555-8555-555555555555'

const message: AdminMessage = {
  id: messageID,
  user_id: userID,
  type: 'announcement.published',
  title: null,
  package_id: null,
  site_id: null,
  created_at: '2026-09-06T02:00:00Z',
  email_content: 'redacted email content',
  sms_content: null,
  email_state: 'delivered',
  sms_state: null,
  user_display_id: 7,
  username: 'alice',
  user_display_name: 'Alice Shop',
  site_domain: null,
  package_name: null,
}

const catalogEvent = { enabled: true, sms_enabled: true, email_enabled: true, repeat_count: 1, interval_hours: 24, supported: true }
const policy: NotificationDeliveryPolicy = {
  schema: 'cdnca.notification-delivery-policy/v1', window_mode: 'all_day', window_start: '00:00', window_end: '23:59',
  timezone: 'Asia/Shanghai', revision: 1, changed: false,
  events: [
    { ...catalogEvent, event_type: 'site.origin.failover' },
    { ...catalogEvent, event_type: 'node.availability.offline' },
    { ...catalogEvent, event_type: 'brand.new.event' },
  ],
}

function page(items: AdminMessage[], overrides: Partial<AdminMessagePage> = {}): AdminMessagePage {
  return { schema: 'cdnca.notification-message-query/v1', items, total: items.length, ...overrides }
}

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

function authenticate(overrides: Parameters<typeof principal>[0] = {}, update: 'new' | 'refresh' = 'new') {
  const actor = principal({
    scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'],
    permissions: ['system_configuration.read'],
    ...overrides,
  })
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: `${update}-message-token` }, actor, update)
  return actor
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((next) => { resolve = next })
  return { promise, resolve }
}

function renderWithClient(queryClient: QueryClient) {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/sys/message']}>
            <AdminMessageQueryPage />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

describe('AdminMessageQueryPage', () => {
  beforeEach(() => {
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue(policy)
  })

  it.each([
    ['a platform actor without read permission', { permissions: [] }],
    ['a tenant actor carrying the permission', { scope_kind: 'tenant' as const, tenant_id: scopeID }],
  ])('renders a local 403 with zero message requests for %s', async (_case, overrides) => {
    authenticate(overrides)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])

    expect(await screen.findByText('无权查询消息')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('matches the observed seven-column empty surface and filter availability', async () => {
    authenticate()
    const pending = deferred<Response>()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockReturnValue(pending.promise)

    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])

    expect(screen.getByTestId('admin-message-deliveries')).toHaveAttribute('aria-busy', 'true')
    await act(async () => pending.resolve(response(page([]))))
    expect(await screen.findByText('暂无消息')).toBeInTheDocument()

    const table = screen.getByTestId('admin-message-deliveries')
    expect(within(table).getAllByRole('columnheader').map((header) => header.textContent?.trim())).toEqual([
      '所属用户', '类型', '标题', '网站', '创建时间', '操作',
    ])
    expect(screen.getByText('所有类型')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '用户' })).not.toBeDisabled()
    expect(screen.queryByRole('combobox', { name: '用户套餐' })).not.toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '网站' })).not.toBeDisabled()
    expect(screen.getByText('共 0 条')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '1' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByText('10 条/页')).toBeInTheDocument()
    expect(String(fetchSpy.mock.calls[0]?.[0])).toBe('/v1/admin/notifications/messages?limit=10')
  })

  it('renders contract-backed facts and opens a detail view for the message content', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(page([message])))

    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])

    // L1：显示用户名称（可点进用户），标题为空时用消息类型兜底，未关联的套餐/网站写明而不是「未知」。
    const userLink = await screen.findByRole('link', { name: 'Alice Shop（alice）' })
    expect(userLink).toHaveAttribute('href', '/sys/user?display_id=7')
    expect(screen.queryByText(userID)).not.toBeInTheDocument()
    expect(screen.getByText('公告')).toBeInTheDocument()
    expect(screen.getByText('公告（无邮件标题）')).toBeInTheDocument()
    expect(screen.queryByText('未知')).not.toBeInTheDocument()
    // An unlinked site cell is a dash; the tooltip says why (社区版无套餐列).
    expect(screen.getAllByText('—')).toHaveLength(1)
    expect(screen.getByLabelText('该消息未关联网站')).toHaveTextContent('—')
    await userEvent.setup().hover(screen.getByLabelText('该消息未关联网站'))
    expect(await screen.findByRole('tooltip')).toHaveTextContent('该消息未关联网站')
    expect(screen.getByText('2026/09/06 10:00:00')).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('redacted email content')
    await userEvent.setup().click(screen.getByRole('button', { name: '详情' }))
    expect(await screen.findByText('消息详情')).toBeInTheDocument()
    expect(screen.getByText('redacted email content')).toBeInTheDocument()
    const detail = screen.getByTestId('admin-message-detail')
    expect(within(detail).getByText('已送达')).toBeInTheDocument()
    expect(within(detail).getByText('未生成')).toBeInTheDocument()
    expect(within(detail).getByText(/不是发送失败/)).toBeInTheDocument()
    expect(within(detail).getByText(messageID)).toBeInTheDocument()
    expect(within(detail).getAllByText('事件未关联')).toHaveLength(1)
  })

  it('names the site and links it to its edit page', async () => {
    authenticate()
    const siteID = '66666666-6666-4666-8666-666666666666'
    const packageID = '77777777-7777-4777-8777-777777777777'
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(page([{
      ...message, title: '流量告警', site_id: siteID, site_domain: 'www.example.com',
      package_id: packageID, package_name: '企业版', user_display_name: 'alice',
    }])))

    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])

    expect(await screen.findByRole('link', { name: 'www.example.com' })).toHaveAttribute('href', `/site/${siteID}/edit`)
    expect(screen.getByRole('link', { name: 'alice' })).toBeInTheDocument()
    expect(screen.queryByText('企业版')).not.toBeInTheDocument()
    expect(screen.getByText('流量告警')).toBeInTheDocument()
  })

  it('rejects a message without the readable name fields', async () => {
    authenticate()
    const legacy: Partial<AdminMessage> = { ...message }
    delete legacy.site_domain
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(page([legacy as AdminMessage])))

    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])

    expect(await screen.findByText('消息加载失败')).toBeInTheDocument()
  })

  // C23 / MSG-M01: the filter lists the current event catalog only
  // (no legacy group), every name in Chinese, and queries the exact value.
  it('lists only current catalog events in Chinese and queries the exact value', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(page([])))
    const user = userEvent.setup()

    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])
    await screen.findByText('暂无消息')
    await user.click(screen.getByRole('combobox', { name: '类型' }))
    expect(await screen.findByTitle('节点离线告警')).toBeInTheDocument()
    expect(screen.getByTitle('其他消息（brand.new.event）')).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('旧版')
    expect(screen.queryByTitle('套餐即将到期（旧版）')).not.toBeInTheDocument()
    await user.click(screen.getByTitle('回源级别自动切换'))

    await waitFor(() => {
      const url = new URL(String(fetchSpy.mock.calls.at(-1)?.[0]), 'http://localhost')
      expect(url.searchParams.get('type')).toBe('site.origin.failover')
    })
    expect(screen.getByRole('button', { name: '1' })).toHaveAttribute('aria-current', 'page')
  })

  it('says so when the event catalog cannot be read and offers no legacy types', async () => {
    authenticate()
    vi.mocked(notificationsApi.getDeliveryPolicy).mockRejectedValue(new Error('down'))
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(page([])))
    const user = userEvent.setup()

    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])
    expect(await screen.findByText(/事件目录读取失败/)).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: '类型' }))
    await waitFor(() => expect(document.querySelectorAll('.ant-select-item-option')).toHaveLength(1))
    expect(document.querySelector('.ant-select-item-option')).toHaveAttribute('title', '所有类型')
    expect(document.body).not.toHaveTextContent('旧版')
  })

  it('rejects a message whose channel state is outside the delivery contract', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(page([{ ...message, email_state: 'sent' as never }])))

    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])
    expect(await screen.findByText('消息加载失败')).toBeInTheDocument()
  })

  // User / site filters search by name or ID and query
  // with the picked object's UUID (the message API only takes UUIDs).
  it('finds the user and site by name, then pages with the stable cursor', async () => {
    authenticate({ permissions: ['system_configuration.read', 'identity.users.manage', 'sites.read'] })
    const siteID = '66666666-6666-4666-8666-666666666666'
    const usersSpy = vi.spyOn(usersApi, 'list').mockResolvedValue({
      items: [{ id: userID, username: 'alice', display_id: 7 }], page: 1, limit: 20, total: 1,
    } as unknown as UserListResponse)
    const sitesSpy = vi.spyOn(sitesApi, 'list').mockResolvedValue({
      items: [{ id: siteID, domain: 'www.example.com', display_id: '9' }], page: 1, limit: 20, total: 1,
    } as unknown as SiteListResponse)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = new URL(String(input), 'http://localhost')
      return response(url.searchParams.has('cursor')
        ? page([{ ...message, id: nextCursor }], { total: 2 })
        : page([message], { total: 2, next_cursor: nextCursor }))
    })
    const user = userEvent.setup()

    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])
    await screen.findByRole('link', { name: 'Alice Shop（alice）' })

    await user.type(screen.getByRole('combobox', { name: '用户' }), 'alice')
    await user.click(await screen.findByText('alice（7）'))
    expect(usersSpy).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ search: 'alice' }))
    expect(screen.queryByRole('combobox', { name: '用户套餐' })).not.toBeInTheDocument()
    await user.type(screen.getByRole('combobox', { name: '网站' }), 'example')
    await user.click(await screen.findByText('www.example.com（9）'))
    expect(sitesSpy).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ domain: 'example' }))

    await waitFor(() => {
      const url = new URL(String(fetchSpy.mock.calls.at(-1)?.[0]), 'http://localhost')
      expect(Object.fromEntries(url.searchParams)).toEqual({
        limit: '10', user_id: userID, site_id: siteID,
      })
    })
    await user.click(screen.getByRole('button', { name: '下一页' }))
    await waitFor(() => {
      const url = new URL(String(fetchSpy.mock.calls.at(-1)?.[0]), 'http://localhost')
      expect(url.searchParams.get('cursor')).toBe(nextCursor)
    })
    expect(screen.getByRole('button', { name: '2' })).toHaveAttribute('aria-current', 'page')

    await user.click(screen.getByRole('button', { name: '上一页' }))
    await waitFor(() => {
      const url = new URL(String(fetchSpy.mock.calls.at(-1)?.[0]), 'http://localhost')
      expect(url.searchParams.has('cursor')).toBe(false)
    })
  })

  it('searches users by numeric user ID', async () => {
    authenticate({ permissions: ['system_configuration.read', 'identity.users.manage'] })
    const usersSpy = vi.spyOn(usersApi, 'list').mockResolvedValue({
      items: [{ id: userID, username: 'alice', display_id: 7 }], page: 1, limit: 20, total: 1,
    } as unknown as UserListResponse)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(page([])))
    const user = userEvent.setup()

    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])
    await screen.findByText('暂无消息')
    await user.type(screen.getByRole('combobox', { name: '用户' }), '7')
    expect(await screen.findByText('alice（7）')).toBeInTheDocument()
    expect(usersSpy).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ display_id: '7' }))
  })

  // The site domain search matches the numeric display ID on the
  // server, so a typed number is sent as-is.
  it('searches sites by numeric display ID', async () => {
    authenticate({ permissions: ['system_configuration.read', 'sites.read'] })
    const sitesSpy = vi.spyOn(sitesApi, 'list').mockResolvedValue({
      items: [{ id: '66666666-6666-4666-8666-666666666666', domain: 'www.example.com', display_id: '9' }], page: 1, limit: 20, total: 1,
    } as unknown as SiteListResponse)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(page([])))
    const user = userEvent.setup()

    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])
    await screen.findByText('暂无消息')
    await user.type(screen.getByRole('combobox', { name: '网站' }), '9')
    expect(await screen.findByText('www.example.com（9）')).toBeInTheDocument()
    expect(sitesSpy).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ domain: '9' }))
  })

  it('accepts a pasted UUID without list permission and sends no list request', async () => {
    authenticate()
    const usersSpy = vi.spyOn(usersApi, 'list')
    const sitesSpy = vi.spyOn(sitesApi, 'list')
    const siteID = '66666666-6666-4666-8666-666666666666'
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(page([])))
    const user = userEvent.setup()

    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])
    await screen.findByText('暂无消息')
    await user.type(screen.getByRole('combobox', { name: '网站' }), siteID.toUpperCase())

    await waitFor(() => {
      const url = new URL(String(fetchSpy.mock.calls.at(-1)?.[0]), 'http://localhost')
      expect(url.searchParams.get('site_id')).toBe(siteID)
    })
    expect(usersSpy).not.toHaveBeenCalled()
    expect(sitesSpy).not.toHaveBeenCalled()
  })

  // 未选联想项时按名称参数过滤，边输入边生效，防抖只发一次。
  it('filters by typed names without picking a suggestion, once per pause', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(page([])))
    const user = userEvent.setup()

    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])
    await screen.findByText('暂无消息')
    const before = fetchSpy.mock.calls.length
    await user.type(screen.getByRole('combobox', { name: '用户' }), 'alice')
    await waitFor(() => {
      const url = new URL(String(fetchSpy.mock.calls.at(-1)?.[0]), 'http://localhost')
      expect(Object.fromEntries(url.searchParams)).toEqual({ limit: '10', user: 'alice' })
    })
    const messageCalls = fetchSpy.mock.calls.slice(before).filter(([url]) => String(url).includes('/v1/admin/notifications/messages'))
    expect(messageCalls).toHaveLength(1)
  })

  it('localizes request failures, retries, and renders an API 403 without leaking raw messages', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(response({ error: { code: 'message_unavailable', message: 'private topology', request_id: 'request-1' } }, 503))
      .mockResolvedValueOnce(response(page([])))

    const view = renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])
    expect(await screen.findByText('消息加载失败')).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private topology')
    await userEvent.setup().click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无消息')).toBeInTheDocument()

    view.unmount()
    fetchSpy.mockResolvedValueOnce(response({ error: { code: 'permission_denied', message: 'private policy', request_id: 'request-2' } }, 403))
    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])
    expect(await screen.findByText('无权查询消息')).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private policy')
  })

  it('keeps the cursor and cache owner stable across token refresh without storing tokens in query keys', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(page([message], { total: 2, next_cursor: nextCursor })))
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
    const user = userEvent.setup()

    renderWithClient(queryClient)
    await screen.findByRole('link', { name: 'Alice Shop（alice）' })
    await user.click(screen.getByRole('button', { name: '下一页' }))
    await screen.findByRole('button', { name: '2' })

    const calls = fetchSpy.mock.calls.length
    await act(async () => { authenticate({}, 'refresh') })
    expect(screen.getByRole('button', { name: '2' })).toBeInTheDocument()
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(calls))
    expect(JSON.stringify(queryClient.getQueryCache().getAll().map((item) => item.queryKey))).not.toContain('message-token')
  })

  it('names aggregated edge schedule alerts and dnspup probe pauses instead of other messages', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(page([
      { ...message, type: 'aggregated_edge.schedule.alert' },
      { ...message, id: '66666666-6666-4666-8666-666666666666', type: 'probe.dnspup.degraded' },
      { ...message, id: '77777777-7777-4777-8777-777777777777', type: 'node.security.waf_ban' },
    ])))

    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])

    expect(await screen.findByText('聚合边缘调度告警')).toBeInTheDocument()
    expect(screen.getByText('dnspup 拨测暂停')).toBeInTheDocument()
    expect(screen.getByText('WAF 自动封禁')).toBeInTheDocument()
    expect(screen.queryByText('其他消息')).not.toBeInTheDocument()
  })

  it('names every node market notice kind instead of other messages', async () => {
    authenticate()
    const kinds = [
      'market.downstream.attacked',
      'market.complaint.resolved',
      'market.complaint.actioned',
      'market.node.action',
      'market.site.paused',
      'market.site.resumed',
      'market.commission.low',
      'market.commission.exhausted',
      'market.commission.restored',
      'market.supply.outage',
      'market.supply.restored',
      'market.supply.cancel_available',
      'market.direct_topup.paid',
      'market.direct_topup.received',
      'market.seller.deposit_mode',
      'market.seller.deposit_shortfall',
      'market.seller.default_compensated',
      'market.seller.defaulted',
    ]
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(page(kinds.map((type, i) => (
      { ...message, id: `77777777-7777-4777-8777-${String(i).padStart(12, '0')}`, type })))))
    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])
    expect(await screen.findByText('节点市场：保证金不足')).toBeInTheDocument()
    expect(screen.getByText('节点市场：供给无在线可用节点')).toBeInTheDocument()
    expect(screen.queryByText('其他消息')).not.toBeInTheDocument()
  })

  it('names origin failover, ticket, top-up rejection and migration events instead of other messages', async () => {
    authenticate()
    const kinds = [
      'site.origin.failover', 'site.origin.recovered', 'payment.market_topup.rejected', 'identity.migrated_account',
      'identity.secondary_verification', 'package.monitor.traffic.warning', 'package.monitor.bandwidth_over_limit',
      'package.monitor.connections_over_limit', 'ticket.created', 'ticket.replied', 'ticket.status_changed',
      'ticket.staff.created', 'ticket.staff.replied',
    ]
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(page(kinds.map((type, i) => (
      { ...message, id: `88888888-8888-4888-8888-${String(i).padStart(12, '0')}`, type })))))
    renderWithProviders(<AdminMessageQueryPage />, ['/sys/message'])
    expect(await screen.findByText('回源级别自动切换')).toBeInTheDocument()
    expect(screen.getByText('直结充值到账报告被市场拒收')).toBeInTheDocument()
    expect(screen.getByText('账号已迁移到新平台')).toBeInTheDocument()
    expect(screen.getByText('工单用户回复（运营）')).toBeInTheDocument()
    expect(screen.queryByText('其他消息')).not.toBeInTheDocument()
  })
})
