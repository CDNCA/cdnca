import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, vi } from 'vitest'

import { sitesApi } from '../api/sites'
import { usersApi, type ManagedUser } from '../api/users'
import type { Stream, StreamListResponse } from '../api/streams'
import type { StreamGroup } from '../api/streamGroups'
import { useSessionStore } from '../auth/session'
import StreamListPage from '../pages/StreamListPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

import { stream } from './streamFixture'

function listResponse(items: Stream[] = [stream], page = 1, total = items.length, limit = 10): Response {
  const body: StreamListResponse = { items, total, page, limit }
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

const streamGroup: StreamGroup = {
  id: '88888888-8888-4888-8888-888888888888',
  display_id: '1',
  scope_id: stream.scope_id,
  owner: stream.owner,
  name: '现有分组',
  remark: '',
  stream_count: 1,
  revision: 1,
  created_at: stream.created_at,
  updated_at: stream.updated_at,
}

function groupResponse(items: StreamGroup[], page = 1, total = items.length): Response {
  return new Response(JSON.stringify({ items, total, page, limit: 100 }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function deferredJsonResponse() {
  let releaseFetch: (response: Response) => void = () => undefined
  let releaseJson: (body: unknown) => void = () => undefined
  const fetchPromise = new Promise<Response>((resolve) => { releaseFetch = resolve })
  const jsonPromise = new Promise<unknown>((resolve) => { releaseJson = resolve })
  const response = new Response(null, { status: 200, headers: { 'Content-Type': 'application/json' } })
  const jsonSpy = vi.spyOn(response, 'json').mockReturnValue(jsonPromise)
  return {
    fetchPromise,
    jsonSpy,
    resolveFetch: () => releaseFetch(response),
    resolveJson: releaseJson,
  }
}

function renderStreamsWithQueryClient(queryClient: QueryClient) {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/stream/list']}>
            <StreamListPage />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

function authenticate(role: 'admin' | 'user', permissions?: string[]) {
  const user = principal(role === 'admin' ? {
    scope_kind: 'platform', tenant_id: null, username: 'admin', display_name: 'admin', roles: ['platform_admin'],
    permissions: permissions ?? ['platform.admin'],
  } : { permissions: permissions ?? ['streams.read', 'streams.manage'] })
  useSessionStore.getState().setSession(authResponse(user), user)
}

type TestUser = ReturnType<typeof userEvent.setup>

async function openAdvancedFilters(user: TestUser) {
  await user.click(screen.getByRole('button', { name: /^高级筛选/ }))
}

async function openRowMenu(user: TestUser) {
  await user.click(screen.getByRole('button', { name: '转发操作菜单' }))
}

async function chooseRowAction(user: TestUser, action: '启用' | '停用' | '删除' | '发布详情') {
  await openRowMenu(user)
  await user.click(await screen.findByRole('menuitem', { name: action }))
}

// 弹窗：「展开更多」默认收起，展开后我方附加字段在折叠组里（默认全收起）。
async function showAdvancedFields(user: TestUser, dialog: HTMLElement) {
  const trigger = within(dialog).getByRole('button', { name: '展开更多' })
  if (trigger.getAttribute('aria-expanded') === 'false') await user.click(trigger)
  for (const header of Array.from(dialog.querySelectorAll<HTMLElement>('.ant-collapse-header[aria-expanded="false"]'))) await user.click(header)
}


async function pickOption(user: ReturnType<typeof userEvent.setup>, dialog: HTMLElement, label: string, text: RegExp) {
  await user.click(within(dialog).getByRole('combobox', { name: label }))
  await user.click(await screen.findByText(text, { selector: '.ant-select-item-option-content' }))
}

// fix-advfilter2：高级筛选展开状态记在 localStorage，各用例从收起开始。
beforeEach(() => { localStorage.removeItem('cdnca.advancedFilters.stream-list') })

describe('StreamListPage', () => {
  it('picks the user (tenant + owner) from the user selector, clears groups on a user change and finds group options beyond the first page', async () => {
    authenticate('admin')
    const otherScope = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
    const otherGroup = { ...streamGroup, id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', scope_id: otherScope, name: '目标租户分组' }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'http://localhost')
      if (url.pathname === '/v1/stream-groups') {
        const page = Number(url.searchParams.get('page'))
        return Promise.resolve(groupResponse(page === 1 ? Array.from({ length: 100 }, (_, index) => ({
          ...streamGroup,
          id: `10000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
          display_id: String(index + 1),
          name: `其他分组 ${index + 1}`,
        })) : [otherGroup], page, 101))
      }
      if (init?.method === 'POST') return Promise.resolve(new Response(JSON.stringify(stream), { status: 201 }))
      return Promise.resolve(listResponse())
    })
    const userBase = { tenant_id: '', display_name: '', phone: null, status: 'active', role: 'owner', group_id: null, group_name: null, revision: 1, created_at: stream.created_at }
    const users = vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [
      { ...userBase, id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', display_id: '9', scope_id: otherScope, username: 'other', email: 'other@example.com' },
      { ...userBase, id: stream.owner!.id, display_id: '2', scope_id: stream.scope_id, username: 'jason', email: null },
    ] as unknown as ManagedUser[], total: 2, page: 1, limit: 20 } as Awaited<ReturnType<typeof usersApi.list>>)
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: '添加转发' }))
    const dialog = await screen.findByRole('dialog', { name: '添加转发' })
    expect(within(dialog).queryByLabelText('租户作用域 ID')).not.toBeInTheDocument()
    await showAdvancedFields(user, dialog)
    const select = within(dialog).getByRole('combobox', { name: '所属分组' })
    expect(select).toBeDisabled()
    await pickOption(user, dialog, '用户选择', /other（9）/)
    await user.click(select)
    await user.click(await screen.findByText('目标租户分组', { selector: '.ant-select-item-option-content' }))
    expect(screen.queryByText('其他分组 1', { selector: '.ant-select-item-option-content' })).not.toBeInTheDocument()
    expect(select.closest('.ant-select')).toHaveTextContent('目标租户分组')
    await pickOption(user, dialog, '用户选择', /jason（2）/)
    expect(select.closest('.ant-select')).not.toHaveTextContent('目标租户分组')
    await user.type(within(dialog).getByRole('combobox', { name: '用户选择' }), 'jason@')
    await waitFor(() => expect(users).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ search: 'jason@' })))
    expect(within(dialog).queryByRole('combobox', { name: '用户套餐' })).not.toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('监听端口'), '18101')
    await user.type(within(dialog).getByLabelText('源地址:端口'), '192.0.2.11:9001')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
    const post = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')
    expect(JSON.parse(String(post?.[1]?.body))).toEqual(expect.objectContaining({ target_scope_id: stream.scope_id, owner_id: stream.owner!.id, group_ids: [],
      listen_port: 18101, upstream_address: '192.0.2.11', upstream_port: 9001 }))
    expect(JSON.parse(String(post?.[1]?.body))).not.toHaveProperty('site_id')
    expect(JSON.parse(String(post?.[1]?.body))).not.toHaveProperty('package_subscription_id')
  })

  // 社区版：转发不绑定套餐，添加时不选套餐，也不选网站（不读网站列表）。
  it('creates a stream without a package or a website', async () => {
    authenticate('user', ['streams.read', 'streams.manage', 'sites.read'])
    useSessionStore.setState((state) => ({ principal: { ...state.principal!, scope_id: stream.scope_id, tenant_id: stream.scope_id, user_id: stream.owner!.id } }))
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => init?.method === 'POST'
      ? Promise.resolve(new Response(JSON.stringify(stream), { status: 201, headers: { 'Content-Type': 'application/json' } }))
      : Promise.resolve(listResponse()))
    const siteList = vi.spyOn(sitesApi, 'list')
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: '添加转发' }))
    const dialog = await screen.findByRole('dialog', { name: '添加转发' })
    expect(within(dialog).queryByLabelText('套餐订阅 ID')).not.toBeInTheDocument()
    expect(within(dialog).queryByRole('combobox', { name: '所属站点' })).not.toBeInTheDocument()
    expect(within(dialog).queryByRole('combobox', { name: '用户套餐' })).not.toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('监听端口'), '18101')
    await user.type(within(dialog).getByLabelText('源地址:端口'), '192.0.2.11:9001')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
    const post = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')
    const body = JSON.parse(String(post?.[1]?.body))
    expect(body).not.toHaveProperty('package_subscription_id')
    expect(body).not.toHaveProperty('site_id')
    expect(siteList).not.toHaveBeenCalled()
  })

  it('keeps publication links inside the dashboard router basename', async () => {
    authenticate('admin')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup({ delay: null })
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
    render(<QueryClientProvider client={queryClient}>
      <MemoryRouter basename="/dashboard" initialEntries={['/dashboard/stream/list']}>
        <StreamListPage />
      </MemoryRouter>
    </QueryClientProvider>)
    await screen.findByText('TCP gateway')
    await openRowMenu(user)
    const link = await screen.findByRole('link', { name: '发布配置' })
    expect(link).toHaveAttribute('href', `/dashboard/site/publications?target_scope_id=${stream.scope_id}&stream_id=${stream.id}&stream_revision=1`)
  })

  // 线路列「区域 (线路分组)」只在管理员端；源站列逐个源站「端口 · 权重 · 上线/下线」；状态列显示设置状态与同步状态。
  it('renders the line, every origin with weight and state, the admin status and the sync state', async () => {
    authenticate('admin')
    const pooled = {
      ...stream, admin_status: 'locked' as const, sync_state: 'failed' as const,
      origins: [{ address: '192.0.2.10', weight: 3, down: false }, { address: '192.0.2.11', weight: 1, down: true }],
      publish_intent: { ...stream.publish_intent, runtime_spec: { ...stream.publish_intent.runtime_spec, endpoint: { ...stream.publish_intent.runtime_spec.endpoint,
        origins: [{ address: '192.0.2.10', weight: 3 }, { address: '192.0.2.11', weight: 1, down: true as const }] } } },
      line: { ...stream.line, region_id: '77777777-7777-4777-8777-777777777777', region_name: '默认', node_group_id: '88888888-8888-4888-8888-888888888888', node_group_name: 'test' },
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse([pooled]))
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    const row = (await screen.findByText('TCP gateway')).closest('tr')!
    const cells = within(row).getAllByRole('cell')
    expect(cells[4]).toHaveTextContent(`192.0.2.10端口 ${stream.upstream_port} · 权重 3 · 上线`)
    expect(cells[4]).toHaveTextContent(`192.0.2.11端口 ${stream.upstream_port} · 权重 1 · 下线`)
    // fix-weighthint：上线源站按权重占比（下线不计），下线的不分流量
    expect(cells[4]).toHaveTextContent('权重 3 · 上线 · 约 100%')
    expect(cells[4]).toHaveTextContent('权重 1 · 下线 · 不分流量')
    expect(cells[6]).toHaveTextContent('默认 (test)')
    expect(cells[7]).toHaveTextContent('锁定')
    expect(cells[7]).toHaveTextContent('同步失败')
  })

  it.each([
    ['a tenant missing streams.read', principal({ permissions: ['streams.manage'] })],
    ['a platform principal without a stream or publication read permission', principal({
      scope_kind: 'platform',
      tenant_id: null,
      roles: ['platform_admin'],
      permissions: ['billing.account.read'],
    })],
  ])('renders a local 403 and performs no reads for %s', async (_case, actor) => {
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())

    renderWithProviders(<StreamListPage />, ['/stream/list'])

    expect(await screen.findByText('无权查看转发列表')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少四层转发权限')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(screen.queryByTestId('stream-table-scroll')).not.toBeInTheDocument()
  })

  it('keeps the observed forwarding sub-navigation above the table shell', async () => {
    authenticate('user')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())

    renderWithProviders(<StreamListPage />, ['/stream/list'])

    expect(await screen.findByText('TCP gateway')).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: '四层转发栏目' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '转发列表' })).toHaveClass('is-active')
    expect(screen.getByRole('button', { name: '分组管理' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '默认设置' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '向前查看更多栏目' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '向后查看更多栏目' })).toBeInTheDocument()
    // 用户端没有线路列。
    expect(screen.queryByRole('columnheader', { name: '线路' })).not.toBeInTheDocument()
  })

  // 转发列表表头：ID / 监听端口 / CNAME / 源站 / 套餐·分组 / 线路 / 状态 / 操作。
  // 没有「备注」「添加时间」两列，备注只作为编辑表单字段存在（见 remark 用例）。
  it('matches the observed header set exactly', async () => {
    authenticate('user')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())

    renderWithProviders(<StreamListPage />, ['/stream/list'])

    expect(await screen.findByText('TCP gateway')).toBeInTheDocument()
    const headers = screen
      .getAllByRole('columnheader')
      .map((item) => item.textContent?.trim() ?? '')
      .filter((label) => label !== '')
    expect(headers).toEqual(['ID', '监听端口', 'CNAME', '源站', '分组', '状态', '操作'])
  })

  it('shows the 线路 column to the platform', async () => {
    authenticate('admin')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    expect(await screen.findByText('TCP gateway')).toBeInTheDocument()
    const headers = screen.getAllByRole('columnheader').map((item) => item.textContent?.trim() ?? '').filter((label) => label !== '')
    expect(headers).toEqual(['ID', '监听端口', 'CNAME', '源站', '分组', '线路', '状态', '操作'])
  })

  it('keeps filters, page two, and token-free cache identity across a same-epoch token refresh', async () => {
    const actor = principal({ permissions: ['streams.read', 'streams.manage'] })
    const oldToken = 'old-stream-access-token'
    const newToken = 'new-stream-access-token'
    const stableStream = { ...stream, name: 'stable filtered stream' }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'http://localhost')
      const page = Number(url.searchParams.get('page'))
      return Promise.resolve(listResponse([stableStream], page, 40))
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
    const user = userEvent.setup({ delay: null })

    renderStreamsWithQueryClient(queryClient)

    expect(await screen.findByText('stable filtered stream')).toBeInTheDocument()
    await user.type(screen.getByLabelText('搜索转发'), '18100')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await openAdvancedFilters(user)
    await user.click(screen.getByRole('combobox', { name: '筛选协议' }))
    await user.click(await screen.findByText('TCP', { selector: '.ant-select-item-option-content' }))
    await user.click(screen.getByRole('combobox', { name: '筛选状态' }))
    await user.click(await screen.findByText('已启用', { selector: '.ant-select-item-option-content' }))
    await user.click(screen.getByRole('button', { name: '应用' }))
    await user.click(await screen.findByTitle('2'))
    await waitFor(() => expect(document.querySelector('.ant-pagination-item-active')).toHaveAttribute('title', '2'))
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
    expect(screen.getByText('stable filtered stream')).toBeInTheDocument()
    expect(screen.getByLabelText('搜索转发')).toHaveValue('18100')
    expect(screen.getByRole('combobox', { name: '筛选协议' }).closest('.ant-select')).toHaveTextContent('TCP')
    expect(screen.getByRole('combobox', { name: '筛选状态' }).closest('.ant-select')).toHaveTextContent('已启用')
    expect(document.querySelector('.ant-pagination-item-active')).toHaveAttribute('title', '2')
    expect(fetchSpy).toHaveBeenCalledTimes(readsBeforeRefresh)

    const finalKey = [
      'streams', actor.scope_kind, actor.scope_id, sessionEpoch, 2, 10, { listen_port: 18100, protocol: 'tcp', enabled: true },
    ] as const
    const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    expect(queryKeys).toContainEqual(finalKey)
    for (const queryKey of queryKeys) {
      const serializedKey = JSON.stringify(queryKey)
      expect(serializedKey).not.toContain(oldToken)
      expect(serializedKey).not.toContain(newToken)
    }
    expect(document.body.textContent).not.toContain(oldToken)
    expect(document.body.textContent).not.toContain(newToken)

    await queryClient.invalidateQueries({
      queryKey: ['streams', actor.scope_kind, actor.scope_id, sessionEpoch],
    })
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(readsBeforeRefresh + 1))
    expect(new Headers(fetchSpy.mock.calls.at(-1)?.[1]?.headers).get('Authorization')).toBe(`Bearer ${newToken}`)
  })

  it('resets tenant state and isolates a late list response when a new session starts', async () => {
    const tenantA = principal({ permissions: ['streams.read', 'streams.manage'] })
    const tenantB = principal({
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
      user_id: '88888888-8888-4888-8888-888888888888',
      permissions: ['streams.read', 'streams.manage'],
    })
    const tenantAStream = { ...stream, name: 'tenant A filtered page two', scope_id: tenantA.scope_id }
    const lateTenantAStream = {
      ...tenantAStream,
      id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      name: 'late tenant A stream',
      publish_intent: {
        ...tenantAStream.publish_intent,
        runtime_spec: {
          ...tenantAStream.publish_intent.runtime_spec,
          stream_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
          geo: { ...tenantAStream.publish_intent.runtime_spec.geo, stream_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' },
        },
      },
    }
    const tenantBStream = {
      ...stream,
      id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      scope_id: tenantB.scope_id,
      name: 'tenant B first page',
      publish_intent: {
        ...stream.publish_intent,
        runtime_spec: {
          ...stream.publish_intent.runtime_spec,
          tenant_id: tenantB.scope_id,
          stream_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
          geo: { ...stream.publish_intent.runtime_spec.geo, tenant_id: tenantB.scope_id, stream_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' },
        },
      },
    }
    const lateTenantA = deferredJsonResponse()
    const pendingTenantB = deferredJsonResponse()
    let tenantAPageTwoReads = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      const authorization = new Headers(init?.headers).get('Authorization')
      if (authorization === 'Bearer tenant-a-stream-token') {
        if (url.includes('page=2')) {
          tenantAPageTwoReads += 1
          return tenantAPageTwoReads === 1
            ? Promise.resolve(listResponse([tenantAStream], 2, 40))
            : lateTenantA.fetchPromise
        }
        return Promise.resolve(listResponse([{ ...tenantAStream, name: 'tenant A first page' }], 1, 40))
      }
      if (authorization === 'Bearer tenant-b-stream-token') return pendingTenantB.fetchPromise
      throw new Error(`unexpected stream read ${authorization ?? 'without authorization'} ${url}`)
    })
    const queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false, gcTime: Infinity },
        mutations: { retry: false },
      },
    })
    const foreignKey = [
      'streams', 'tenant', '99999999-9999-4999-8999-999999999999', 999, 1, 10, {},
    ] as const
    const foreignData: StreamListResponse = { items: [], total: 0, page: 1, limit: 10 }
    queryClient.setQueryData(foreignKey, foreignData)
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: 'tenant-a-stream-token' },
      tenantA,
    )
    const tenantAEpoch = useSessionStore.getState().sessionEpoch
    const user = userEvent.setup({ delay: null })

    renderStreamsWithQueryClient(queryClient)

    expect(await screen.findByText('tenant A first page')).toBeInTheDocument()
    await user.type(screen.getByLabelText('搜索转发'), '18100')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await openAdvancedFilters(user)
    await user.click(screen.getByRole('combobox', { name: '筛选协议' }))
    await user.click(await screen.findByText('TCP', { selector: '.ant-select-item-option-content' }))
    await user.click(screen.getByRole('combobox', { name: '筛选状态' }))
    await user.click(await screen.findByText('已启用', { selector: '.ant-select-item-option-content' }))
    await user.click(screen.getByRole('button', { name: '应用' }))
    await user.click(await screen.findByTitle('2'))
    expect(await screen.findByText('tenant A filtered page two')).toBeInTheDocument()

    void queryClient.refetchQueries({ type: 'active' })
    await waitFor(() => expect(tenantAPageTwoReads).toBe(2))

    act(() => useSessionStore.getState().setSession(
      { ...authResponse(tenantB), access_token: 'tenant-b-stream-token' },
      tenantB,
    ))
    const tenantBEpoch = useSessionStore.getState().sessionEpoch
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => (
      new Headers(init?.headers).get('Authorization') === 'Bearer tenant-b-stream-token'
    ))).toBe(true))

    expect(tenantBEpoch).not.toBe(tenantAEpoch)
    expect(screen.queryByText('tenant A filtered page two')).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '编辑转发' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('搜索转发')).toHaveValue('')
    // fix-advfilter2：高级筛选面板的展开状态按浏览器记住，新会话里可以仍是展开的；但上一租户的条件全部清空。
    expect(screen.getByRole('combobox', { name: '筛选协议' }).closest('.ant-select')).not.toHaveTextContent('TCP')
    expect(screen.getByRole('combobox', { name: '筛选状态' }).closest('.ant-select')).not.toHaveTextContent('已启用')
    expect(screen.queryByRole('list', { name: '已启用的高级条件' })).not.toBeInTheDocument()
    expect(screen.getByTestId('stream-table-scroll')).toHaveAttribute('aria-busy', 'true')
    const tenantBCall = fetchSpy.mock.calls.find(([, init]) => (
      new Headers(init?.headers).get('Authorization') === 'Bearer tenant-b-stream-token'
    ))
    expect(tenantBCall?.[0]).toBe('/v1/streams?page=1&limit=10')
    expect(queryClient.getQueryData(foreignKey)).toEqual(foreignData)
    expect(queryClient.getQueryState(foreignKey)?.isInvalidated).toBe(false)

    pendingTenantB.resolveFetch()
    await waitFor(() => expect(pendingTenantB.jsonSpy).toHaveBeenCalledOnce())
    pendingTenantB.resolveJson({ items: [tenantBStream], total: 1, page: 1, limit: 10 })
    expect(await screen.findByText('tenant B first page')).toBeInTheDocument()

    lateTenantA.resolveFetch()
    await waitFor(() => expect(lateTenantA.jsonSpy).toHaveBeenCalledOnce())
    await act(async () => {
      lateTenantA.resolveJson({ items: [lateTenantAStream], total: 40, page: 2, limit: 10 })
      await new Promise((resolve) => setTimeout(resolve, 0))
    })

    const tenantAKey = [
      'streams', tenantA.scope_kind, tenantA.scope_id, tenantAEpoch, 2, 10, { listen_port: 18100, protocol: 'tcp', enabled: true },
    ] as const
    const tenantBKey = [
      'streams', tenantB.scope_kind, tenantB.scope_id, tenantBEpoch, 1, 10, {},
    ] as const
    expect(screen.getByText('tenant B first page')).toBeInTheDocument()
    expect(screen.queryByText('late tenant A stream')).not.toBeInTheDocument()
    expect(queryClient.getQueryData(tenantAKey)).toBeUndefined()
    expect(queryClient.getQueryData(tenantBKey)).toEqual({
      items: [tenantBStream], total: 1, page: 1, limit: 10,
    })
    expect(queryClient.getQueryData(foreignKey)).toEqual(foreignData)
    expect(queryClient.getQueryState(foreignKey)?.isInvalidated).toBe(false)
  })

  it('invalidates only the current scoped list after a successful mutation', async () => {
    const actor = principal({ permissions: ['streams.read', 'streams.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const currentKey = [
      'streams', actor.scope_kind, actor.scope_id, sessionEpoch, 1, 10, {},
    ] as const
    const foreignKey = [
      'streams', 'tenant', '99999999-9999-4999-8999-999999999999', 999, 1, 10, {},
    ] as const
    const foreignData: StreamListResponse = { items: [], total: 0, page: 1, limit: 10 }
    let reads = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'PATCH') {
        return Promise.resolve(new Response(JSON.stringify({
          ...stream,
          enabled: false,
          revision: 2,
          publish_intent: { ...stream.publish_intent, resource_revision: 2, runtime_spec: { ...stream.publish_intent.runtime_spec, revision: 2,
            geo: { ...stream.publish_intent.runtime_spec.geo, revision: 2 } } },
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }))
      }
      reads += 1
      return Promise.resolve(listResponse())
    })
    const queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false, gcTime: Infinity },
        mutations: { retry: false },
      },
    })
    queryClient.setQueryData(foreignKey, foreignData)
    const user = userEvent.setup({ delay: null })

    renderStreamsWithQueryClient(queryClient)

    expect(await screen.findByText('TCP gateway')).toBeInTheDocument()
    await chooseRowAction(user, '停用')
    await user.click(await screen.findByRole('button', { name: '确认' }))

    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(true))
    await waitFor(() => expect(reads).toBe(2))
    expect(queryClient.getQueryData(currentKey)).toEqual({ items: [stream], total: 1, page: 1, limit: 10 })
    expect(queryClient.getQueryState(currentKey)?.isInvalidated).toBe(false)
    expect(queryClient.getQueryData(foreignKey)).toEqual(foreignData)
    expect(queryClient.getQueryState(foreignKey)?.isInvalidated).toBe(false)
  })

  it('keeps the table mounted while loading and after the response settles', async () => {
    authenticate('user')
    let resolveList!: (response: Response) => void
    vi.spyOn(globalThis, 'fetch').mockReturnValue(new Promise((resolve) => { resolveList = resolve }))

    renderWithProviders(<StreamListPage />, ['/stream/list'])

    const table = screen.getByTestId('stream-table-scroll')
    expect(table).toHaveAttribute('aria-busy', 'true')
    await act(async () => { resolveList(listResponse()) })
    expect(await screen.findByText('TCP gateway')).toBeInTheDocument()
    expect(table).toBeInTheDocument()
    expect(table).toHaveAttribute('aria-busy', 'false')
  })

  it('localizes list failures, hides server messages, and retries without replacing the table', async () => {
    authenticate('user')
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: 'request_failed', message: 'private stream shard' } }), { status: 503, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(listResponse([]))
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<StreamListPage />, ['/stream/list'])

    expect(await screen.findByText('转发列表加载失败')).toBeInTheDocument()
    expect(screen.getByText('操作失败，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('private stream shard')).not.toBeInTheDocument()
    expect(screen.getByTestId('stream-table-scroll')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('renders tenant data without administrator ownership and marks publication as unknown', async () => {
    authenticate('user')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])

    expect(await screen.findByText('TCP gateway')).toBeInTheDocument()
    const publishState = screen.getByText('v1 下发状态待确认')
    expect(publishState).toBeInTheDocument()
    expect(publishState).toHaveClass('visually-hidden')
    expect(screen.getAllByRole('columnheader').map((item) => item.textContent)).not.toContain('用户')
    expect(screen.getByTestId('stream-table-scroll')).toHaveAttribute('aria-busy', 'false')
    await user.click(screen.getByRole('button', { name: '添加转发' }))
    const drawer = await screen.findByRole('dialog', { name: '添加转发' })
    expect(within(drawer).getByRole('tab', { name: '批量' })).toBeInTheDocument()
  })

  it('renders an exact succeeded publication state', async () => {
    authenticate('user')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse([{
      ...stream,
      publish_intent: { ...stream.publish_intent, state: 'succeeded' },
    }]))
    renderWithProviders(<StreamListPage />, ['/stream/list'])

    const publishState = await screen.findByText('v1 已生效')
    expect(publishState).toHaveClass('visually-hidden')
  })

  it('keeps a streams.read viewer read-only without issuing writes', async () => {
    authenticate('user', ['streams.read'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])

    expect(await screen.findByText('TCP gateway')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '添加转发' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '批量修改' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '更多操作' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: '管理' })).toBeInTheDocument()
    await openRowMenu(user)
    expect(screen.queryByRole('menuitem', { name: '停用' })).not.toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: '删除' })).not.toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: '发布详情' })).toBeInTheDocument()
    expect(fetchSpy.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true)
  })

  it('closes an open write form when streams.manage is revoked', async () => {
    authenticate('user')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')

    await user.click(screen.getByRole('button', { name: '添加转发' }))
    expect(await screen.findByRole('dialog', { name: '添加转发' })).toBeInTheDocument()
    const viewer = principal({ permissions: ['streams.read'] })
    act(() => useSessionStore.getState().setSession(authResponse(viewer), viewer, 'refresh'))

    expect(screen.queryByRole('dialog', { name: '添加转发' })).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([, init]) => ['POST', 'PATCH', 'DELETE'].includes(init?.method ?? ''))).toBe(false)
  })

  it('disables an already-open confirmation during a list refetch and restores one successful update afterwards', async () => {
    const actor = principal({ permissions: ['streams.read', 'streams.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false, gcTime: Infinity },
        mutations: { retry: false },
      },
    })
    let reads = 0
    let resolveRefetch!: (response: Response) => void
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'PATCH') {
        return Promise.resolve(new Response(JSON.stringify({
          ...stream,
          enabled: false,
          revision: 2,
          publish_intent: { ...stream.publish_intent, resource_revision: 2, runtime_spec: { ...stream.publish_intent.runtime_spec, revision: 2,
            geo: { ...stream.publish_intent.runtime_spec.geo, revision: 2 } } },
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }))
      }
      reads += 1
      if (reads === 2) return new Promise((resolve) => { resolveRefetch = resolve })
      return Promise.resolve(listResponse())
    })
    const user = userEvent.setup({ delay: null })

    renderStreamsWithQueryClient(queryClient)
    expect(await screen.findByText('TCP gateway')).toBeInTheDocument()
    await chooseRowAction(user, '停用')
    const confirmation = await screen.findByRole('dialog', { name: '停用转发' })
    const confirm = within(confirmation).getByRole('button', { name: '确认' })

    const refetch = queryClient.refetchQueries({ type: 'active' })
    await waitFor(() => expect(reads).toBe(2))
    await waitFor(() => {
      expect(confirm).toBeDisabled()
      expect(confirm).toHaveClass('ant-btn-loading')
    })
    fireEvent.click(confirm)
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(false)

    await act(async () => {
      resolveRefetch(listResponse())
      await refetch
    })
    await waitFor(() => {
      expect(confirm).toBeEnabled()
      expect(confirm).not.toHaveClass('ant-btn-loading')
    })

    await user.click(confirm)

    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1))
    const patch = JSON.parse(String(fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')?.[1]?.body))
    expect(patch).toEqual(expect.objectContaining({
      remark: stream.remark,
      upstream_host: stream.upstream_host,
      dns_policy: stream.dns_policy,
      geo_policy: stream.geo_policy,
      max_connections_per_client: stream.max_connections_per_client,
      proxy_protocol_inbound: stream.proxy_protocol_inbound,
      expected_revision: stream.revision,
    }))
    expect(await screen.findByText('转发规则已更新，发布意图下发状态待确认')).toBeInTheDocument()
  })

  it('renders administrator ownership and sends filters', async () => {
    authenticate('admin')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')

    expect(screen.getAllByRole('columnheader').map((item) => item.textContent)).not.toContain('用户')
    expect(screen.getByTitle('所属用户：jason')).toBeInTheDocument()
    await user.type(screen.getByLabelText('搜索转发'), '18100')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(String(fetchSpy.mock.calls.at(-1)?.[0])).toContain('listen_port=18100'))
  })

  it('fix-advfilter2: quick search stays in the row, other conditions fold into 高级筛选 with count, tags, clear and conflict check', async () => {
    authenticate('admin')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const lastQuery = () => new URL(String(fetchSpy.mock.calls.filter(([url]) => String(url).startsWith('/v1/streams?')).at(-1)?.[0]), 'https://control.example').searchParams
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')

    const toggle = screen.getByRole('button', { name: '高级筛选' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.getByRole('button', { name: '重置' })).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: '筛选条件' })).not.toBeInTheDocument()

    await user.type(screen.getByLabelText('搜索转发'), '18100')
    await user.click(toggle)
    const advanced = screen.getByRole('group', { name: '高级筛选' })
    await user.click(within(advanced).getByRole('combobox', { name: '筛选协议' }))
    await user.click(await screen.findByText('TCP', { selector: '.ant-select-item-option-content' }))
    await user.type(within(advanced).getByLabelText('CNAME域名'), 'edge.example.net')
    await user.click(within(advanced).getByRole('button', { name: '应用' }))
    await waitFor(() => {
      expect(lastQuery().get('listen_port')).toBe('18100')
      expect(lastQuery().get('protocol')).toBe('tcp')
      expect(lastQuery().get('cname_domain')).toBe('edge.example.net')
    })
    expect(screen.getByRole('button', { name: '高级筛选 · 2' })).toBeInTheDocument()
    const tags = screen.getByRole('list', { name: '已启用的高级条件' })
    expect(within(tags).getByText('监听协议：TCP')).toBeInTheDocument()

    await user.click(within(tags).getByRole('button', { name: '移除条件 监听协议' }))
    await waitFor(() => expect(lastQuery().get('protocol')).toBeNull())
    expect(lastQuery().get('cname_domain')).toBe('edge.example.net')
    expect(lastQuery().get('listen_port')).toBe('18100')

    // 行内端口与高级里的端口取值不同：不生效并提示冲突。
    const reads = fetchSpy.mock.calls.length
    await user.type(within(advanced).getByLabelText('监听端口'), '18200')
    await user.click(within(advanced).getByRole('button', { name: '应用' }))
    expect(await screen.findByText('快捷查询与筛选条件中的同一字段取值不同，请统一取值或清空其中一项后重试')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.length).toBe(reads)

    await user.click(within(advanced).getByRole('button', { name: '清空高级条件' }))
    await waitFor(() => expect(lastQuery().get('cname_domain')).toBeNull())
    expect(screen.queryByText('快捷查询与筛选条件中的同一字段取值不同，请统一取值或清空其中一项后重试')).not.toBeInTheDocument()
    expect(lastQuery().get('listen_port')).toBe('18100')

    await user.click(screen.getByRole('button', { name: '重置' }))
    await waitFor(() => expect(lastQuery().get('listen_port')).toBeNull())
    expect(screen.getByLabelText('搜索转发')).toHaveValue('')
  })

  it.each([
    ['edge publication manager', ['edge_publications.manage']],
    ['platform administrator', ['platform.admin']],
  ])('links each row tenant to the publication workflow for a %s', async (_case, permissions) => {
    authenticate('admin', permissions)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<StreamListPage />, ['/stream/list'])

    await screen.findByText('TCP gateway')
    await openRowMenu(user)
    const link = await screen.findByRole('link', { name: '发布配置' })
    expect(link).toHaveAttribute(
      'href',
      '/site/publications?target_scope_id=22222222-2222-4222-8222-222222222222&stream_id=11111111-1111-4111-8111-111111111111&stream_revision=1',
    )
    expect(screen.getByText('v1 下发状态待确认')).toBeInTheDocument()
    expect(screen.queryByText(/已生效|已激活/)).not.toBeInTheDocument()
  })

  it.each([
    ['read-only platform principal', 'admin' as const, ['edge_publications.read']],
    ['tenant principal with the platform permission string', 'user' as const, ['streams.read', 'edge_publications.manage']],
  ])('hides the publication command from a %s', async (_case, role, permissions) => {
    authenticate(role, permissions)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<StreamListPage />, ['/stream/list'])

    await screen.findByText('TCP gateway')
    await openRowMenu(user)
    expect(screen.queryByRole('link', { name: '发布配置' })).not.toBeInTheDocument()
  })

  it('shows empty, error, and forbidden states distinctly', async () => {
    authenticate('user')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse([]))
    const first = renderWithProviders(<StreamListPage />, ['/stream/list'])
    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    first.unmount()

    vi.restoreAllMocks()
    authenticate('user')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ error: { code: 'permission_denied', message: 'permission is required' } }), { status: 403, headers: { 'Content-Type': 'application/json' } }))
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    expect(await screen.findByText('无权查看转发列表')).toBeInTheDocument()
    expect(screen.queryByText('转发列表加载失败')).not.toBeInTheDocument()
    expect(screen.queryByText('permission is required')).not.toBeInTheDocument()
  })

  it.each([
    '::::',
    '2001:db8:00000::1',
  ])('rejects malformed IPv6 %s without issuing a write', async (upstreamAddress) => {
    authenticate('user')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'POST') {
        return Promise.resolve(new Response(JSON.stringify(stream), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        }))
      }
      return Promise.resolve(listResponse())
    })
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: '添加转发' }))
    await user.type(within(screen.getByRole('dialog', { name: '添加转发' })).getByLabelText('监听端口'), '18101')
    fireEvent.change(screen.getByLabelText('源地址:端口'), { target: { value: `[${upstreamAddress}]:9001` } })
    await user.click(screen.getByRole('button', { name: '确定' }))

    expect(await screen.findByText('请输入有效的 IPv4 或 IPv6 地址')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
  })

  it('falls back to tenant/owner UUID inputs without a user-list permission and rejects malformed UUIDs without issuing a write', async () => {
    authenticate('admin', ['streams.read', 'streams.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'POST') {
        return Promise.resolve(new Response(JSON.stringify(stream), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        }))
      }
      return Promise.resolve(listResponse())
    })
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: '添加转发' }))
    await user.type(screen.getByLabelText('租户作用域 ID'), 'not-a-tenant-uuid')
    await user.type(screen.getByLabelText('归属用户 ID'), 'not-an-owner-uuid')
    await user.type(within(screen.getByRole('dialog', { name: '添加转发' })).getByLabelText('监听端口'), '18101')
    await user.type(screen.getByLabelText('源地址:端口'), '192.0.2.11:9001')
    await user.click(screen.getByRole('button', { name: '确定' }))

    expect(await screen.findByText('请输入有效的租户作用域 UUID')).toBeInTheDocument()
    expect(screen.getByText('请输入有效的归属用户 UUID')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
  })

  it('freezes an unknown create and retries the exact body and idempotency key', async () => {
    authenticate('user')
    let writes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'POST') {
        writes += 1
        return writes === 1
          ? Promise.reject(new TypeError('connection reset'))
          : Promise.resolve(new Response(JSON.stringify(stream), { status: 201, headers: { 'Content-Type': 'application/json' } }))
      }
      return Promise.resolve(listResponse())
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')

    await user.click(screen.getByRole('button', { name: '添加转发' }))
    await user.type(within(screen.getByRole('dialog', { name: '添加转发' })).getByLabelText('监听端口'), '18101')
    await user.type(screen.getByLabelText('源地址:端口'), '192.0.2.11:9001')
    await user.click(screen.getByRole('button', { name: '确定' }))

    expect(await screen.findByText('操作失败，请稍后重试', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '添加转发' })).toBeDisabled()
    expect(screen.getByRole('link', { name: '管理' })).toHaveAttribute('href', `/stream/list/${stream.id}`)
    expect(screen.queryByRole('dialog', { name: '添加转发' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('转发规则已保存，发布意图下发状态待确认')).toBeInTheDocument()

    const calls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')
    expect(calls).toHaveLength(2)
    expect(calls[1][1]?.body).toBe(calls[0][1]?.body)
    expect(new Headers(calls[1][1]?.headers).get('Idempotency-Key')).toBe(new Headers(calls[0][1]?.headers).get('Idempotency-Key'))
  })

  it('creates a UDP rule and keeps Proxy Protocol disabled', async () => {
    authenticate('user')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_, init) => {
      if (init?.method === 'POST') {
        return Promise.resolve(new Response(JSON.stringify({
          ...stream,
          name: 'UDP gateway',
          protocol: 'udp',
          proxy_protocol_v1: false,
          publish_intent: {
            ...stream.publish_intent,
            runtime_spec: { ...stream.publish_intent.runtime_spec, listener: { protocol: 'udp', address: '*', port: 18100 }, proxy_protocol_outbound: false },
          },
        }), { status: 201, headers: { 'Content-Type': 'application/json' } }))
      }
      return Promise.resolve(listResponse())
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')

    await user.click(screen.getByRole('button', { name: '添加转发' }))
    const drawer = screen.getByRole('dialog', { name: '添加转发' })
    await showAdvancedFields(user, drawer)
    await user.type(screen.getByLabelText('转发名称'), 'UDP gateway')
    // 端口写法：88/udp。
    await user.type(within(screen.getByRole('dialog', { name: '添加转发' })).getByLabelText('监听端口'), '18101/udp')
    await waitFor(() => expect(within(drawer).getByRole('radio', { name: 'Proxy Protocol v1' })).toBeDisabled())
    fireEvent.change(screen.getByLabelText('源地址:端口'), { target: { value: '[::ffff:192.0.2.128]:9001' } })
    await user.click(screen.getByRole('button', { name: '确定' }))

    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
    const post = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')
    expect(JSON.parse(String(post?.[1]?.body))).toEqual(expect.objectContaining({
      name: 'UDP gateway', protocol: 'udp', listen_port: 18101, upstream_address: '::ffff:192.0.2.128', proxy_protocol_v1: false,
    }))
  })

  it('forces TCP for TLS passthrough, rejects bad SNI and posts normalized server names', async () => {
    authenticate('user')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_, init) => {
      if (init?.method === 'POST') return Promise.resolve(new Response(JSON.stringify(stream), { status: 201, headers: { 'Content-Type': 'application/json' } }))
      return Promise.resolve(listResponse())
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')

    await user.click(screen.getByRole('button', { name: '添加转发' }))
    const drawer = screen.getByRole('dialog', { name: '添加转发' })
    await showAdvancedFields(user, drawer)
    expect(within(drawer).queryByRole('combobox', { name: 'SNI 列表' })).not.toBeInTheDocument()
    await user.click(within(drawer).getByRole('switch', { name: 'TLS 透传（按 SNI 分流）' }))
    expect(within(drawer).getByText(/SNI 未命中任何规则的连接会被关闭/)).toBeInTheDocument()

    // TLS 透传只用于 TCP：UDP 端口被拒绝。
    await user.type(within(drawer).getByLabelText('监听端口'), '443/udp')
    await user.type(within(drawer).getByLabelText('源地址:端口'), '192.0.2.11:443')
    await user.click(within(drawer).getByRole('button', { name: '确定' }))
    expect(await within(drawer).findByText('TLS 透传仅支持 TCP，主监听和附加监听都必须为 TCP')).toBeInTheDocument()
    await user.clear(within(drawer).getByLabelText('监听端口'))
    await user.type(within(drawer).getByLabelText('监听端口'), '443')
    await user.click(within(drawer).getByRole('button', { name: '确定' }))
    expect(await within(drawer).findByText('开启 TLS 透传时至少填写 1 个 SNI')).toBeInTheDocument()

    const names = within(drawer).getByRole('combobox', { name: 'SNI 列表' })
    await user.type(names, '*.com,')
    expect(await within(drawer).findByText('SNI *.com 无效：需为至少两级的域名，通配仅支持开头的 *.')).toBeInTheDocument()
    await user.click(within(drawer).getByRole('button', { name: '确定' }))
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)

    await user.click(drawer.querySelector('.ant-select-selection-item-remove')!)
    await user.type(names, ' App.Example.COM ,*.example.com,')
    await user.click(within(drawer).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
    const post = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')
    expect(JSON.parse(String(post?.[1]?.body))).toEqual(expect.objectContaining({
      protocol: 'tcp', listen_port: 443, tls_passthrough: true, server_names: ['app.example.com', '*.example.com'],
    }))
  })

  it('explains shared-port TCP limits, warns on PROXY with passthrough and maps the shared-port 409', async () => {
    authenticate('user')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_, init) => {
      if (init?.method === 'POST') {
        return Promise.resolve(new Response(JSON.stringify({ error: { code: 'stream_shared_port_proxy_protocol', message: 'raw backend text' } }), { status: 409, headers: { 'Content-Type': 'application/json' } }))
      }
      return Promise.resolve(listResponse())
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: '添加转发' }))
    const drawer = screen.getByRole('dialog', { name: '添加转发' })
    await showAdvancedFields(user, drawer)
    const notice = /服务端先发数据的协议在共享端口上会被断开/
    expect(within(drawer).getByText(notice)).toBeInTheDocument()
    await user.type(within(drawer).getByLabelText('监听端口'), '443/udp')
    await waitFor(() => expect(within(drawer).queryByText(notice)).not.toBeInTheDocument())
    await user.clear(within(drawer).getByLabelText('监听端口'))
    await user.type(within(drawer).getByLabelText('监听端口'), '443')
    await waitFor(() => expect(within(drawer).getByText(notice)).toBeInTheDocument())
    await user.click(within(drawer).getByRole('switch', { name: 'TLS 透传（按 SNI 分流）' }))
    expect(within(drawer).queryByText(notice)).not.toBeInTheDocument()

    const warning = /端口有多个使用方时不能开启 PROXY 协议/
    expect(within(drawer).queryByText(warning)).not.toBeInTheDocument()
    await user.click(within(drawer).getByRole('radio', { name: 'Proxy Protocol v1' }).closest('label')!)
    expect(await within(drawer).findByText(warning)).toBeInTheDocument()
    // 收起「展开更多」后字段仍保留在表单里（折叠只是隐藏）。
    await user.click(within(drawer).getByRole('button', { name: '展开更多' }))
    expect(within(drawer).getByText(warning)).toBeInTheDocument()
    await showAdvancedFields(user, drawer)

    await user.type(within(drawer).getByRole('combobox', { name: 'SNI 列表' }), 'app.example.com,')
    await user.type(within(drawer).getByLabelText('源地址:端口'), '192.0.2.11:443')
    await user.click(within(drawer).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
    const post = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')
    expect(JSON.parse(String(post?.[1]?.body))).toEqual(expect.objectContaining({ tls_passthrough: true, proxy_protocol_v1: true }))
    expect(await screen.findByText('这个端口有多个使用方（转发或网站），不能开启 PROXY 协议（入站或出站）')).toBeInTheDocument()
    expect(screen.queryByText('raw backend text')).not.toBeInTheDocument()
  })

  it('reports duplicate SNI after normalization instead of dropping it', async () => {
    authenticate('user')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: '添加转发' }))
    const drawer = screen.getByRole('dialog', { name: '添加转发' })
    await showAdvancedFields(user, drawer)
    await user.click(within(drawer).getByRole('switch', { name: 'TLS 透传（按 SNI 分流）' }))
    await user.type(within(drawer).getByRole('combobox', { name: 'SNI 列表' }), 'a.example.com,A.example.com,')
    expect(await within(drawer).findByText('SNI a.example.com 重复')).toBeInTheDocument()
    await user.click(within(drawer).getByRole('button', { name: '确定' }))
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
  })

  it('drops a late list response when the live read permission is revoked', async () => {
    const actor = principal({ permissions: ['streams.read', 'streams.manage'] })
    useSessionStore.getState().setSession(
      { ...authResponse(actor), access_token: 'live-read-token' },
      actor,
    )
    let resolveResponse!: (response: Response) => void
    const pendingResponse = new Promise<Response>((resolve) => { resolveResponse = resolve })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockReturnValue(pendingResponse)
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: true, gcTime: Infinity }, mutations: { retry: false } },
    })

    renderStreamsWithQueryClient(queryClient)
    expect(await screen.findByTestId('stream-table-scroll')).toHaveAttribute('aria-busy', 'true')

    const viewer = { ...actor, permissions: ['streams.manage'] }
    act(() => useSessionStore.getState().setSession(
      { ...authResponse(viewer), access_token: 'live-read-token' },
      viewer,
      'refresh',
    ))
    expect(await screen.findByText('无权查看转发列表')).toBeInTheDocument()

    resolveResponse(listResponse([{ ...stream, name: 'late revoked stream' }]))
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)) })

    const epoch = useSessionStore.getState().sessionEpoch
    const key = ['streams', actor.scope_kind, actor.scope_id, epoch, 1, 10, {}] as const
    expect(screen.queryByText('late revoked stream')).not.toBeInTheDocument()
    expect(queryClient.getQueryData(key)).toBeUndefined()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  // 10-25 stream-parity：「添加转发」是居中弹窗，展开更多默认收起，展开区内我方字段分组折叠（默认全收起）。
  it('opens add forwarding as a centered modal with reference fields, collapsed groups and closes on cancel', async () => {
    authenticate('user')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: '添加转发' }))
    const dialog = await screen.findByRole('dialog', { name: '添加转发' })
    expect(dialog.closest('.ant-modal')).not.toBeNull()
    expect(document.querySelector('.ant-drawer')).toBeNull()
    expect(within(dialog).getByRole('tab', { name: '单个' })).toHaveAttribute('aria-selected', 'true')
    expect(within(dialog).getByLabelText('监听端口')).toHaveAttribute('placeholder', '88、99/udp或88/tcp,多个端口空格分隔')
    expect(within(dialog).getByLabelText('源地址:端口')).toHaveAttribute('placeholder', '1.1.1.1:99或www.abc.com:99')
    const more = within(dialog).getByRole('button', { name: '展开更多' })
    expect(more).toHaveAttribute('aria-expanded', 'false')
    expect(within(dialog).getByLabelText('所属分组').closest('[hidden]')).not.toBeNull()
    await user.click(more)
    expect(within(dialog).getByLabelText('所属分组').closest('[hidden]')).toBeNull()
    // 弹窗 ant-zoom 入场动画期间 .ant-modal 的 opacity 为 0，等动画结束再断言可见。
    await waitFor(() => expect(within(dialog).getByLabelText('备注')).toBeVisible())
    const headers = Array.from(dialog.querySelectorAll('.ant-collapse-header')).map((header) => header.textContent)
    expect(headers).toEqual(['基本设置', '监听设置', '源站设置', '访问控制', '连接限制'])
    expect(dialog.querySelectorAll('.ant-collapse-item-active')).toHaveLength(0)
    await user.click(within(dialog).getByText('源站设置'))
    expect(dialog.querySelectorAll('.ant-collapse-item-active')).toHaveLength(1)
    expect(within(dialog).getByText('负载方式')).toBeVisible()
    await user.click(within(dialog).getByRole('button', { name: '取消' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '添加转发' })).not.toBeInTheDocument())
  })

  // fp-role L4-005：域名源在「源地址:端口」里输入即显示 DNS 区（不是等提交后的 upstream_mode）。
  it('shows the DNS fields as soon as the origin input is a domain and keeps the draft', async () => {
    authenticate('user')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: '添加转发' }))
    const dialog = await screen.findByRole('dialog', { name: '添加转发' })
    await showAdvancedFields(user, dialog)
    const origin = within(dialog).getByLabelText('源地址:端口')
    expect(within(dialog).queryByLabelText('DNS 最小正缓存 TTL（秒）')).not.toBeInTheDocument()
    await user.type(origin, 'origin.example.com:8080')
    const minTTL = await within(dialog).findByLabelText('DNS 最小正缓存 TTL（秒）')
    await user.clear(minTTL)
    await user.type(minTTL, '45')
    await user.clear(origin)
    await user.type(origin, '192.0.2.10:8080')
    await waitFor(() => expect(within(dialog).queryByLabelText('DNS 最小正缓存 TTL（秒）')).not.toBeInTheDocument())
    await user.clear(origin)
    await user.type(origin, 'origin.example.com:8080')
    expect(await within(dialog).findByLabelText('DNS 最小正缓存 TTL（秒）')).toHaveValue('45')
  })

  // fp-role L4-006/L4-007：确定失败显示在弹窗内，服务端指出的字段定位到对应输入框，输入保留。
  it('keeps a definite create failure inside the dialog and points at the refused field', async () => {
    authenticate('user')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => init?.method === 'POST'
      ? Promise.resolve(new Response(JSON.stringify({ error: { code: 'validation_error', message: 'raw', request_id: 'req-9', details: { field: 'upstream_host', reason: 'invalid' } } }), { status: 400, headers: { 'Content-Type': 'application/json' } }))
      : Promise.resolve(listResponse()))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: '添加转发' }))
    const dialog = await screen.findByRole('dialog', { name: '添加转发' })
    await user.type(within(dialog).getByLabelText('监听端口'), '20000')
    await user.type(within(dialog).getByLabelText('源地址:端口'), 'origin.example.com:8080')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
    const alert = await within(dialog).findByRole('alert')
    expect(alert).toHaveTextContent('源站域名无效，请检查拼写')
    expect(alert).toHaveTextContent('请求 ID：req-9')
    expect(within(dialog).getAllByText('源站域名无效，请检查拼写')).toHaveLength(2)
    expect(within(dialog).getByLabelText('源地址:端口')).toHaveValue('origin.example.com:8080')
    expect(screen.queryByText('raw')).not.toBeInTheDocument()
  })

  it('expands multi-port and host:port input into the existing create body', async () => {
    authenticate('user')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => init?.method === 'POST'
      ? Promise.resolve(new Response(JSON.stringify(stream), { status: 201, headers: { 'Content-Type': 'application/json' } }))
      : Promise.resolve(listResponse()))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: '添加转发' }))
    const dialog = await screen.findByRole('dialog', { name: '添加转发' })
    await user.type(within(dialog).getByLabelText('监听端口'), '88 abc')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('端口格式不正确，示例：88、99/udp、20000-20010/tcp')).toBeInTheDocument()
    await user.clear(within(dialog).getByLabelText('监听端口'))
    await user.type(within(dialog).getByLabelText('监听端口'), '20000-20010 99/udp')
    await user.type(within(dialog).getByLabelText('源地址:端口'), 'origin.example.com')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('请在源地址后写上端口，例如 1.1.1.1:99')).toBeInTheDocument()
    await user.clear(within(dialog).getByLabelText('源地址:端口'))
    await user.type(within(dialog).getByLabelText('源地址:端口'), 'origin.example.com:8080')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
    const body = JSON.parse(String(fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')?.[1]?.body))
    expect(body).toEqual(expect.objectContaining({
      protocol: 'tcp', listen_port: 20000, listen_port_end: 20010, upstream_address: '', upstream_host: 'origin.example.com', upstream_port: 8080,
      balance_way: 'rr', proxy_protocol_v1: false, toa: false, name: 'TCP 20000',
      additional_listeners: [expect.objectContaining({ protocol: 'udp', address: '*', port: 99 })],
    }))
    expect(body).not.toHaveProperty('listen_ports_text')
    expect(body).not.toHaveProperty('origin_text')
  })

  it('keeps the single-port create body identical to the pre-modal shape', async () => {
    authenticate('user')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => init?.method === 'POST'
      ? Promise.resolve(new Response(JSON.stringify(stream), { status: 201, headers: { 'Content-Type': 'application/json' } }))
      : Promise.resolve(listResponse()))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: '添加转发' }))
    const dialog = await screen.findByRole('dialog', { name: '添加转发' })
    await user.type(within(dialog).getByLabelText('监听端口'), '18101')
    await user.type(within(dialog).getByLabelText('源地址:端口'), '192.0.2.11:9001')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
    const body = JSON.parse(String(fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')?.[1]?.body))
    expect(Object.keys(body).sort()).toEqual([
      'balance_way', 'connect_timeout_ms', 'dns_policy', 'enabled', 'geo_policy', 'group_ids', 'listen_address', 'listen_port',
      'max_connections_per_client', 'max_new_connections_per_client_per_second', 'name', 'new_connection_ban_seconds', 'new_connection_burst',
      'protocol', 'proxy_protocol_inbound', 'proxy_protocol_v1', 'remark', 'response_timeout_ms',
      'server_names', 'session_log_enabled', 'tls_passthrough', 'toa', 'upstream_address', 'upstream_host', 'upstream_port',
    ])
    expect(body).toEqual(expect.objectContaining({ name: 'TCP 18101', protocol: 'tcp', listen_port: 18101, upstream_address: '192.0.2.11', upstream_port: 9001, group_ids: [] }))
  })

  // 「批量修改转发」：弹窗 + 目标转发卡片 + 折叠组默认收起，勾选的项才覆盖。
  it('batch-edits checked fields in a modal and patches each selected stream with its own revision', async () => {
    authenticate('user')
    const secondID = '99999999-9999-4999-8999-999999999999'
    const second = { ...stream, id: secondID, display_id: '2', name: 'TCP second', listen_port: 18102, revision: 4,
      publish_intent: { ...stream.publish_intent, id: '77777777-7777-4777-8777-777777777777', resource_revision: 4,
        runtime_spec: { ...stream.publish_intent.runtime_spec, stream_id: secondID, revision: 4, listener: { protocol: 'tcp', address: '*', port: 18102 },
          geo: { ...stream.publish_intent.runtime_spec.geo, stream_id: secondID, revision: 4 } } } } as Stream
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => init?.method === 'PATCH'
      ? Promise.resolve(new Response(JSON.stringify(stream), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      : Promise.resolve(listResponse([stream, second])))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findAllByText('TCP second')
    for (const row of screen.getAllByRole('row').slice(1)) await user.click(within(row).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '批量修改' }))
    const dialog = await screen.findByRole('dialog', { name: '批量修改转发' })
    expect(dialog.closest('.ant-modal')).not.toBeNull()
    expect(within(dialog).getByText('正在修改的转发：2')).toBeInTheDocument()
    expect(Array.from(dialog.querySelectorAll('.ant-collapse-header')).map((header) => header.textContent)).toEqual(['基本设置', '源站设置', '访问控制'])
    expect(dialog.querySelectorAll('.ant-collapse-item-active')).toHaveLength(0)
    await user.click(within(dialog).getByText('源站设置'))
    const originPanel = dialog.querySelector('.ant-collapse-item-active') as HTMLElement
    await user.click(within(originPanel).getByRole('button', { name: '批量修改' }))
    expect(await within(dialog).findByText('请至少勾选一项')).toBeInTheDocument()
    await user.click(within(originPanel).getByRole('checkbox', { name: '负载方式' }))
    await user.click(within(originPanel).getByText('定源'))
    await user.click(within(originPanel).getByRole('checkbox', { name: '回源端口' }))
    await user.type(within(originPanel).getByRole('spinbutton', { name: '回源端口' }), '7000')
    await user.click(within(originPanel).getByRole('button', { name: '批量修改' }))
    const confirmation = await screen.findByRole('dialog', { name: '批量修改选中的 2 条转发' })
    await user.click(within(confirmation).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(2))
    const patches = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')
    const bodies = patches.map(([, init]) => JSON.parse(String(init?.body)))
    expect(bodies[0]).toEqual(expect.objectContaining({ balance_way: 'ip_hash', upstream_port: 7000, listen_port: 18100, expected_revision: 1, enabled: true }))
    expect(bodies[1]).toEqual(expect.objectContaining({ balance_way: 'ip_hash', upstream_port: 7000, listen_port: 18102, expected_revision: 4 }))
    expect(bodies[0]).not.toHaveProperty('group_ids')
    expect(String(patches[1]?.[0])).toContain(second.id)
    expect(await screen.findByText('已提交 2 条批量修改，下发状态需另行确认')).toBeInTheDocument()
  })

  // fix-weighthint：批量修改源站列表时每行按上线源站实时显示占比，并说明负载方式
  it('shows each origin share live in the batch origin list', async () => {
    authenticate('user')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse([stream]))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    const row = (await screen.findByText('TCP gateway')).closest('tr')!
    await user.click(within(row).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '批量修改' }))
    const dialog = await screen.findByRole('dialog', { name: '批量修改转发' })
    await user.click(within(dialog).getByText('源站设置'))
    const originPanel = dialog.querySelector('.ant-collapse-item-active') as HTMLElement
    await user.click(within(originPanel).getByRole('checkbox', { name: '源站列表' }))
    expect(within(originPanel).getByText(/权重合计不必等于 100/)).toBeInTheDocument()
    expect(within(originPanel).queryByText(/轮询：按权重轮流转发/)).toBeNull()
    await user.click(within(originPanel).getByRole('checkbox', { name: '负载方式' }))
    expect(within(originPanel).getByText(/轮询：按权重轮流转发/)).toBeInTheDocument()
    expect(within(originPanel).getByText('约 100%')).toBeInTheDocument()
    await user.click(within(originPanel).getByRole('button', { name: '新增源站' }))
    const weights = within(originPanel).getAllByRole('spinbutton', { name: '权重' })
    await user.clear(weights[1]!)
    await user.type(weights[1]!, '3')
    expect(within(originPanel).getByText('约 25%')).toBeInTheDocument()
    expect(within(originPanel).getByText('约 75%')).toBeInTheDocument()
    await user.click(within(originPanel).getByText('定源'))
    expect(within(originPanel).getByText(/定源：同一客户端 IP 固定到一个源站/)).toBeInTheDocument()
  })

  it('does not retry or refetch a terminal list 403 on window focus', async () => {
    authenticate('user')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      error: { code: 'permission_denied', message: 'permission is required' },
    }), { status: 403, headers: { 'Content-Type': 'application/json' } }))
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: true, gcTime: Infinity }, mutations: { retry: false } },
    })

    renderStreamsWithQueryClient(queryClient)
    expect(await screen.findByText('无权查看转发列表')).toBeInTheDocument()
    fireEvent.focus(window)
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 150)) })

    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })
})
