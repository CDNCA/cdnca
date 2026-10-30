import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'

import { announcementsApi, type Announcement, type AudienceInput } from '../api/announcements'
import { ApiError } from '../api/auth'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import AnnouncementManagementPage from '../pages/AnnouncementManagementPage'

function json(value: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }))
}

async function flushUi() {
  await act(async () => {
    await Promise.resolve()
    await new Promise((resolve) => setTimeout(resolve, 50))
  })
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((next) => { resolve = next })
  return { promise, resolve }
}

const draft = {
  id: '11111111-1111-4111-8111-111111111111', scope_id: '22222222-2222-4222-8222-222222222222', version: 1, head_version: 1, revision: 1,
  status: 'draft', title: '维护通知', body: '详细维护窗口', format: 'content', sort_order: 100, visible: true, popup: false, red: false, bold: false, audience: { all: true, user_ids: [], group_ids: [] }, withdrawal_visibility: 'retain', created_at: '2026-07-22T02:00:00Z', state_changed_at: '2026-07-22T02:00:00Z', archived: false, lifecycle_revision: 1,
} satisfies Announcement
const published = {
  ...draft,
  id: '33333333-3333-4333-8333-333333333333',
  status: 'published',
  title: '已发布通知',
  published_at: '2026-07-22T03:00:00Z',
} satisfies Announcement
const publishedWithoutAudienceArrays = {
  ...published,
  audience: { all: true },
} satisfies Announcement

// @ts-expect-error Request audiences must include explicit user and group arrays.
const incompleteRequestAudience: AudienceInput = { all: true }
void incompleteRequestAudience

function authenticate() {
  const actor = principal({ permissions: ['announcements.manage'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function renderAnnouncementsWithQueryClient(queryClient: QueryClient) {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/sys/anno']}>
            <AnnouncementManagementPage />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

describe('AnnouncementManagementPage', () => {
  it.each([
    ['scope_id 为空', { scope_id: '' }],
    ['tenant_id 缺失', { tenant_id: null }],
    ['user_id 为空', { user_id: '' }],
  ] as const)('rejects malformed tenant lineage locally without requests for %s', async (_case, overrides) => {
    const actor = principal({ permissions: ['announcements.manage'], ...overrides })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ items: [] }))

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])

    expect(await screen.findByText('无权管理公告')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('rejects a zero session epoch locally without requests', async () => {
    const actor = principal({ permissions: ['announcements.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    useSessionStore.setState({ sessionEpoch: 0 })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ items: [] }))

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])

    expect(await screen.findByText('无权管理公告')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('rejects list results outside the current tenant owner', async () => {
    authenticate()
    const foreign = { ...draft, scope_id: '99999999-9999-4999-8999-999999999999', title: '越权公告' }
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ items: [foreign] }))

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])

    expect(await screen.findByText('公告请求失败，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('越权公告')).not.toBeInTheDocument()
  })

  it('rejects detail results outside the current tenant owner', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      return url === `/v1/admin/announcements/${draft.id}`
        ? json({ ...draft, scope_id: '99999999-9999-4999-8999-999999999999', body: '越权详情' })
        : json({ items: [draft] })
    })
    const user = userEvent.setup()

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    const row = (await screen.findByText(draft.title)).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '详情' }))

    expect(await screen.findByText('公告请求失败，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('越权详情')).not.toBeInTheDocument()
  })

  it('uses the complete token-free owner tuple for query and mutation identities', async () => {
    const actor = principal({ permissions: ['announcements.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false, gcTime: Infinity } },
    })
    vi.spyOn(announcementsApi, 'list').mockResolvedValue({ items: [draft] })
    vi.spyOn(announcementsApi, 'get').mockResolvedValue(draft)
    const update = vi.spyOn(announcementsApi, 'update').mockResolvedValue(draft)
    const user = userEvent.setup()

    renderAnnouncementsWithQueryClient(queryClient)
    const title = await screen.findByText(draft.title)
    const owner = [actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, sessionEpoch]
    expect(queryClient.getQueryCache().getAll().map((query) => query.queryKey)).toEqual(expect.arrayContaining([
      ['announcements', ...owner, 'all', 20, undefined],
    ]))

    await user.click(within(title.closest('tr')!).getByRole('button', { name: '编辑' }))
    await screen.findByText('编辑草稿', { selector: '.ant-modal-title' })
    await user.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(queryClient.getMutationCache().getAll().some((mutation) => (
      JSON.stringify(mutation.options.mutationKey) === JSON.stringify(['announcement-mutation', ...owner])
    ))).toBe(true)
  }, 20_000)

  it('does not cache a foreign-scope write result', async () => {
    const actor = principal({ permissions: ['announcements.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false, gcTime: Infinity } },
    })
    vi.spyOn(announcementsApi, 'list').mockResolvedValue({ items: [draft] })
    vi.spyOn(announcementsApi, 'get').mockResolvedValue(draft)
    vi.spyOn(announcementsApi, 'update').mockResolvedValue({
      ...draft,
      scope_id: '99999999-9999-4999-8999-999999999999',
      title: '越权写入结果',
    })
    const user = userEvent.setup()

    renderAnnouncementsWithQueryClient(queryClient)
    const title = await screen.findByText(draft.title)
    await user.click(within(title.closest('tr')!).getByRole('button', { name: '编辑' }))
    await screen.findByText('编辑草稿', { selector: '.ant-modal-title' })
    await user.click(screen.getByRole('button', { name: '保存' }))

    expect(await screen.findByText('操作结果待确认')).toBeInTheDocument()
    expect(queryClient.getQueryData(['announcement-detail', actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, sessionEpoch, draft.id])).toEqual(draft)
    expect(screen.queryByText('越权写入结果')).not.toBeInTheDocument()
  }, 20_000)

  it.each([
    ['a tenant missing announcements.manage', principal({ permissions: [] })],
  ])('renders a local 403 and performs no reads or writes for %s', async (_case, actor) => {
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ items: [] }))

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])

    expect(await screen.findByText('无权管理公告')).toBeInTheDocument()
    expect(screen.getByText('当前账号没有公告管理权限')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(screen.queryByTestId('announcement-table-scroll')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新建公告' })).not.toBeInTheDocument()
  })

  it('routes a platform principal with announcements.manage to global announcement management', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['announcements.manage'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ items: [] }))

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])

    expect(await screen.findByRole('heading', { name: '公告管理' })).toBeInTheDocument()
    expect(screen.getByTestId('global-announcement-table')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增公告' })).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalled()
    expect(screen.queryByText('无权管理公告')).not.toBeInTheDocument()
  })

  it.each(['detail', 'editor'] as const)(
    'keeps the draft cursor page and open %s state across a same-epoch token refresh',
    async (openState) => {
      const actor = principal({ permissions: ['announcements.manage'] })
      const oldToken = 'old-announcement-access-token'
      const newToken = 'new-announcement-access-token'
      const firstPage = { ...draft, title: '稳定草稿第一页' }
      const secondPage = {
        ...draft,
        id: '44444444-4444-4444-8444-444444444444',
        title: '稳定草稿第二页',
      }
      const detail = { ...secondPage, body: '稳定详情正文' }
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
        const url = String(input)
        if (url === `/v1/admin/announcements/${secondPage.id}`) return json(detail)
        if (url.includes('cursor=draft-next')) return json({ items: [secondPage] })
        if (url.includes('status=draft')) return json({ items: [firstPage], next_cursor: 'draft-next' })
        return json({ items: [draft] })
      })
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
      })
      useSessionStore.getState().setSession(
        { ...authResponse(actor), access_token: oldToken }, actor,
      )
      const sessionEpoch = useSessionStore.getState().sessionEpoch
      const user = userEvent.setup()

      renderAnnouncementsWithQueryClient(queryClient)

      expect(await screen.findByText('维护通知')).toBeInTheDocument()
      await user.click(screen.getByRole('combobox', { name: '公告状态' }))
      await user.click(await screen.findByText('草稿', { selector: '.ant-select-item-option-content' }))
      expect(await screen.findByText(firstPage.title)).toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: '下一页' }))
      expect(await screen.findByText(secondPage.title)).toBeInTheDocument()
      const row = screen.getByText(secondPage.title).closest('tr')!
      await user.click(within(row).getByRole('button', { name: openState === 'detail' ? '详情' : '编辑' }))
      if (openState === 'detail') expect(await screen.findByText(detail.body)).toBeInTheDocument()
      else expect(await screen.findByText('编辑草稿', { selector: '.ant-modal-title' })).toBeInTheDocument()
      const readsBeforeRefresh = fetchSpy.mock.calls.length

      await act(async () => {
        useSessionStore.getState().setSession(
          { ...authResponse(actor), access_token: newToken }, actor, 'refresh',
        )
        await Promise.resolve()
      })

      expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
      expect(within(screen.getByTestId('announcement-table-scroll')).getByText(secondPage.title)).toBeInTheDocument()
      expect(screen.queryByText(firstPage.title)).not.toBeInTheDocument()
      expect(screen.getByRole('combobox', { name: '公告状态' }).closest('.ant-select')).toHaveTextContent('草稿')
      expect(screen.getByRole('button', { name: '上一页' })).toBeEnabled()
      if (openState === 'detail') expect(screen.getByText(detail.body)).toBeInTheDocument()
      else expect(screen.getByText('编辑草稿', { selector: '.ant-modal-title' })).toBeInTheDocument()
      expect(fetchSpy).toHaveBeenCalledTimes(readsBeforeRefresh)

      const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
      expect(queryKeys).toEqual(expect.arrayContaining([
        ['announcements', actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, sessionEpoch, 'all', 20, undefined],
        ['announcements', actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, sessionEpoch, 'draft', 20, undefined],
        ['announcements', actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, sessionEpoch, 'draft', 20, 'draft-next'],
        ['announcement-detail', actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, sessionEpoch, secondPage.id],
      ]))
      for (const queryKey of queryKeys) {
        const serializedKey = JSON.stringify(queryKey)
        expect(serializedKey).not.toContain(oldToken)
        expect(serializedKey).not.toContain(newToken)
      }
      expect(document.body.textContent).not.toContain(oldToken)
      expect(document.body.textContent).not.toContain(newToken)

      await user.click(screen.getByRole('button', { name: '刷新' }))
      await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(readsBeforeRefresh + 1))
      expect(new Headers(fetchSpy.mock.calls.at(-1)?.[1]?.headers).get('Authorization')).toBe(`Bearer ${newToken}`)
    },
    20_000,
  )

  it('resets filters, cursor, detail, editor, and an unknown write for a new tenant session', async () => {
    const tenantA = principal({ permissions: ['announcements.manage'] })
    const tenantB = principal({
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
      user_id: '88888888-8888-4888-8888-888888888888',
      permissions: ['announcements.manage'],
    })
    const tenantAPage = {
      ...draft,
      id: '99999999-9999-4999-8999-999999999999',
      scope_id: tenantA.scope_id,
      title: '租户 A 第二页草稿',
      body: '租户 A 详情正文',
    }
    const tenantBItem = {
      ...draft,
      id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      scope_id: tenantB.scope_id,
      title: '租户 B 第一页公告',
    }
    const tenantBList = deferred<Response>()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      const authorization = new Headers(init?.headers).get('Authorization')
      if (authorization === 'Bearer tenant-a-announcement-token') {
        if (init?.method === 'PATCH') return Promise.reject(new TypeError('connection closed'))
        if (url === `/v1/admin/announcements/${tenantAPage.id}`) return json(tenantAPage)
        if (url.includes('cursor=tenant-a-next')) return json({ items: [tenantAPage] })
        if (url.includes('status=draft')) return json({ items: [draft], next_cursor: 'tenant-a-next' })
        return json({ items: [draft] })
      }
      if (authorization === 'Bearer tenant-b-announcement-token') return tenantBList.promise
      throw new Error(`unexpected announcement request ${authorization ?? 'without authorization'} ${url}`)
    })
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: 'tenant-a-announcement-token' }, tenantA,
    )
    const user = userEvent.setup()

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])

    expect(await screen.findByText('维护通知')).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: '公告状态' }))
    await user.click(await screen.findByText('草稿', { selector: '.ant-select-item-option-content' }))
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText(tenantAPage.title)).toBeInTheDocument()
    let row = screen.getByText(tenantAPage.title).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '详情' }))
    expect(await screen.findByText(tenantAPage.body)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '关闭' }))
    row = screen.getByText(tenantAPage.title).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '编辑' }))
    expect(await screen.findByText('编辑草稿', { selector: '.ant-modal-title' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '保存' }))
    expect(await screen.findByText('操作结果待确认')).toBeInTheDocument()

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantB), access_token: 'tenant-b-announcement-token' }, tenantB,
      )
      await Promise.resolve()
    })
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => (
      new Headers(init?.headers).get('Authorization') === 'Bearer tenant-b-announcement-token'
    ))).toBe(true))

    expect(screen.queryByText(tenantAPage.title)).not.toBeInTheDocument()
    expect(screen.queryByText(tenantAPage.body)).not.toBeInTheDocument()
    expect(screen.queryByText('编辑草稿', { selector: '.ant-modal-title' })).not.toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByText('使用同一请求重试')).not.toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '公告状态' }).closest('.ant-select')).toHaveTextContent('全部状态')
    expect(screen.getByRole('button', { name: '上一页' })).toBeDisabled()
    expect(screen.getByTestId('announcement-table-scroll')).toHaveAttribute('aria-busy', 'true')
    const tenantBCall = fetchSpy.mock.calls.find(([, init]) => (
      new Headers(init?.headers).get('Authorization') === 'Bearer tenant-b-announcement-token'
    ))
    expect(tenantBCall?.[0]).toBe('/v1/admin/announcements?limit=20')

    await act(async () => tenantBList.resolve(await json({ items: [tenantBItem] })))
    expect(await screen.findByText(tenantBItem.title)).toBeInTheDocument()
  }, 20_000)

  it('isolates delayed old-session list and detail results after the new tenant completes', async () => {
    const tenantA = principal({ permissions: ['announcements.manage'] })
    const tenantB = principal({
      scope_id: '77777777-7777-4777-8777-777777777777',
      tenant_id: '77777777-7777-4777-8777-777777777777',
      user_id: '88888888-8888-4888-8888-888888888888',
      permissions: ['announcements.manage'],
    })
    const tenantAItem = { ...draft, scope_id: tenantA.scope_id, title: '租户 A 初始公告' }
    const lateTenantAItem = {
      ...tenantAItem,
      id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      title: '租户 A 迟到公告',
    }
    const lateTenantADetail = { ...tenantAItem, body: '租户 A 迟到详情' }
    const tenantBItem = {
      ...draft,
      id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      scope_id: tenantB.scope_id,
      title: '租户 B 当前公告',
    }
    const lateList = deferred<{ items: Announcement[] }>()
    const lateDetail = deferred<Announcement>()
    const tenantBList = deferred<{ items: Announcement[] }>()
    let tenantAReads = 0
    const list = vi.spyOn(announcementsApi, 'list').mockImplementation((token) => {
      if (token === 'tenant-a-late-announcement-token') {
        tenantAReads += 1
        return tenantAReads === 1 ? Promise.resolve({ items: [tenantAItem] }) : lateList.promise
      }
      if (token === 'tenant-b-current-announcement-token') return tenantBList.promise
      throw new Error(`unexpected announcement list token ${token}`)
    })
    vi.spyOn(announcementsApi, 'get').mockImplementation((token) => {
      if (token === 'tenant-a-late-announcement-token') return lateDetail.promise
      if (token === 'tenant-b-current-announcement-token') return Promise.resolve(tenantBItem)
      throw new Error(`unexpected announcement detail token ${token}`)
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    useSessionStore.getState().setSession(
      { ...authResponse(tenantA), access_token: 'tenant-a-late-announcement-token' }, tenantA,
    )
    const tenantAEpoch = useSessionStore.getState().sessionEpoch
    const user = userEvent.setup()

    renderAnnouncementsWithQueryClient(queryClient)

    const title = await screen.findByText(tenantAItem.title)
    await user.click(within(title.closest('tr')!).getByRole('button', { name: '详情' }))
    expect(await screen.findByLabelText('公告详情加载中')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2))

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(tenantB), access_token: 'tenant-b-current-announcement-token' }, tenantB,
      )
      await Promise.resolve()
    })
    const tenantBEpoch = useSessionStore.getState().sessionEpoch
    await act(async () => tenantBList.resolve({ items: [tenantBItem] }))
    expect(await screen.findByText(tenantBItem.title)).toBeInTheDocument()

    await act(async () => {
      lateList.resolve({ items: [lateTenantAItem] })
      lateDetail.resolve(lateTenantADetail)
      await Promise.resolve()
    })

    const tenantAListKey = ['announcements', tenantA.scope_kind, tenantA.scope_id, tenantA.tenant_id, tenantA.user_id, tenantAEpoch, 'all', 20, undefined] as const
    const tenantADetailKey = ['announcement-detail', tenantA.scope_kind, tenantA.scope_id, tenantA.tenant_id, tenantA.user_id, tenantAEpoch, tenantAItem.id] as const
    const tenantBListKey = ['announcements', tenantB.scope_kind, tenantB.scope_id, tenantB.tenant_id, tenantB.user_id, tenantBEpoch, 'all', 20, undefined] as const
    expect(screen.getByText(tenantBItem.title)).toBeInTheDocument()
    expect(screen.queryByText(lateTenantAItem.title)).not.toBeInTheDocument()
    expect(screen.queryByText(lateTenantADetail.body)).not.toBeInTheDocument()
    expect(queryClient.getQueryData(tenantAListKey)).toBeUndefined()
    expect(queryClient.getQueryData(tenantADetailKey)).toBeUndefined()
    expect(queryClient.getQueryData(tenantBListKey)).toEqual({ items: [tenantBItem] })
  }, 20_000)

  it.each(['success', 'version conflict'] as const)(
    'keeps list and detail cache effects scoped after a mutation %s',
    async (outcome) => {
      const actor = principal({ permissions: ['announcements.manage'] })
      useSessionStore.getState().setSession(authResponse(actor), actor)
      const sessionEpoch = useSessionStore.getState().sessionEpoch
      const owner = [actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, sessionEpoch] as const
      const currentListKey = ['announcements', ...owner, 'all', 20, undefined] as const
      const currentDetailKey = ['announcement-detail', ...owner, draft.id] as const
      const foreignListKey = [
        'announcements', '99999999-9999-4999-8999-999999999999', 999, 'all', 20, undefined,
      ] as const
      const foreignDetailKey = [
        'announcement-detail', '99999999-9999-4999-8999-999999999999', 999, draft.id,
      ] as const
      const foreignListData = { items: [{ ...draft, title: 'foreign announcement' }] }
      const foreignDetailData = { ...draft, title: 'foreign detail' }
      const latest = { ...draft, revision: 2, title: outcome === 'success' ? 'saved detail' : 'conflict detail' }
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
      })
      queryClient.setQueryData(foreignListKey, foreignListData)
      queryClient.setQueryData(foreignDetailKey, foreignDetailData)
      const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
      const fetchDetail = vi.spyOn(queryClient, 'fetchQuery')
      const setDetail = vi.spyOn(queryClient, 'setQueryData')
      const list = vi.spyOn(announcementsApi, 'list').mockResolvedValue({ items: [draft] })
      const get = vi.spyOn(announcementsApi, 'get')
      if (outcome === 'success') get.mockResolvedValue(draft)
      else get.mockResolvedValueOnce(draft).mockResolvedValue(latest)
      const update = vi.spyOn(announcementsApi, 'update')
      if (outcome === 'success') update.mockResolvedValue(latest)
      else update.mockRejectedValue(new ApiError('private stale revision owner', 409, 'version_conflict'))
      const user = userEvent.setup()

      renderAnnouncementsWithQueryClient(queryClient)

      const title = await screen.findByText(draft.title)
      await user.click(within(title.closest('tr')!).getByRole('button', { name: '编辑' }))
      expect(await screen.findByText('编辑草稿', { selector: '.ant-modal-title' })).toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: '保存' }))

      await waitFor(() => expect(update).toHaveBeenCalledOnce())
      await waitFor(() => expect(list).toHaveBeenCalledTimes(2))
      expect(update).toHaveBeenCalledWith(
        'memory-only-access-token',
        draft.id,
        expect.objectContaining({ version: draft.version, expected_revision: draft.revision }),
        expect.stringMatching(`^announcement-update-${draft.id}-`),
      )
      expect(invalidate.mock.calls.some(([filters]) => (
        JSON.stringify(filters?.queryKey) === JSON.stringify(['announcements', ...owner])
      ))).toBe(true)
      expect(fetchDetail.mock.calls.some(([options]) => (
        JSON.stringify(options.queryKey) === JSON.stringify(currentDetailKey)
      ))).toBe(true)
      if (outcome === 'success') {
        expect(setDetail.mock.calls.some(([queryKey, value]) => (
          JSON.stringify(queryKey) === JSON.stringify(currentDetailKey) && value === latest
        ))).toBe(true)
      } else {
        expect(await screen.findByText('公告已被其他操作修改，请刷新后重试')).toBeInTheDocument()
        expect(screen.queryByText('private stale revision owner')).not.toBeInTheDocument()
        expect(invalidate.mock.calls.some(([filters]) => (
          JSON.stringify(filters?.queryKey) === JSON.stringify(currentDetailKey)
        ))).toBe(true)
      }
      expect(queryClient.getQueryData(currentListKey)).toEqual({ items: [draft] })
      expect(queryClient.getQueryData(currentDetailKey)).toEqual(latest)
      expect(queryClient.getQueryData(foreignListKey)).toEqual(foreignListData)
      expect(queryClient.getQueryState(foreignListKey)?.isInvalidated).toBe(false)
      expect(queryClient.getQueryData(foreignDetailKey)).toEqual(foreignDetailData)
      expect(queryClient.getQueryState(foreignDetailKey)?.isInvalidated).toBe(false)
    },
    20_000,
  )

  it('lists, filters, paginates, and loads detail from the detail endpoint', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url === `/v1/admin/announcements/${draft.id}`) return json({ ...draft, body: '详情接口返回的正文' })
      if (url.includes('cursor=next-cursor')) return json({ items: [published] })
      if (url.includes('status=published')) return json({ items: [published] })
      return json({ items: [draft], next_cursor: 'next-cursor' })
    })

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    await flushUi()

    const title = await screen.findByText('维护通知')
    fireEvent.click(within(title.closest('tr')!).getByRole('button', { name: '详情' }))
    await flushUi()
    expect(await screen.findByText('详情接口返回的正文')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([url]) => String(url) === `/v1/admin/announcements/${draft.id}`)).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: '关闭' }))
    await flushUi()

    fireEvent.mouseDown(screen.getByRole('combobox', { name: '公告状态' }))
    fireEvent.click(await screen.findByText('已发布', { selector: '.ant-select-item-option-content' }))
    await flushUi()
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).includes('status=published'))).toBe(true))
    expect(await screen.findByText('已发布通知')).toBeInTheDocument()

    fireEvent.mouseDown(screen.getByRole('combobox', { name: '公告状态' }))
    fireEvent.click(await screen.findByText('全部状态', { selector: '.ant-select-item-option-content' }))
    await flushUi()
    await screen.findByText('维护通知')
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    await flushUi()
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).includes('cursor=next-cursor'))).toBe(true))
  })

  it('keeps an unknown create locked to the exact body and idempotency key', async () => {
    authenticate()
    let creates = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'POST') {
        creates += 1
        if (creates === 1) return Promise.reject(new TypeError('connection closed'))
        return json({ ...draft, title: '新公告' }, 201)
      }
      return json({ items: [] })
    })
    const user = userEvent.setup()

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    await flushUi()
    await screen.findByText('暂无公告')
    await user.click(screen.getByRole('button', { name: '新建公告' }))
    fireEvent.change(screen.getByLabelText('标题'), { target: { value: '😀'.repeat(161) } })
    fireEvent.change(screen.getByLabelText('正文'), { target: { value: '发布内容' } })
    await user.click(screen.getByRole('button', { name: '保存' }))

    expect(await screen.findByText('标题不能超过 160 个字符')).toBeInTheDocument()
    expect(creates).toBe(0)

    fireEvent.change(screen.getByLabelText('标题'), { target: { value: '😀'.repeat(160) } })
    fireEvent.change(screen.getByLabelText('正文'), { target: { value: '中'.repeat(21846) } })
    await user.click(screen.getByRole('button', { name: '保存' }))

    expect(await screen.findByText('正文不能超过 65536 字节')).toBeInTheDocument()
    expect(screen.queryByText('标题不能超过 160 个字符')).not.toBeInTheDocument()
    expect(creates).toBe(0)

    fireEvent.change(screen.getByLabelText('标题'), { target: { value: '新公告' } })
    fireEvent.change(screen.getByLabelText('正文'), { target: { value: '发布内容' } })
    await user.click(screen.getByRole('combobox', { name: '受众范围' }))
    await user.click(await screen.findByText('指定用户或角色', { selector: '.ant-select-item-option-content' }))
    await user.click(screen.getByRole('button', { name: '保存' }))

    expect(await screen.findByText('请至少选择一个受众')).toBeInTheDocument()
    expect(creates).toBe(0)

    await user.click(screen.getByRole('combobox', { name: '受众范围' }))
    await user.click(await screen.findByText('全部租户用户', { selector: '.ant-select-item-option-content' }))
    await user.click(screen.getByRole('button', { name: '保存' }))
    await flushUi()

    expect(await screen.findByText('操作结果待确认')).toBeInTheDocument()
    expect(screen.getByLabelText('标题')).toBeDisabled()
    expect(screen.getAllByRole('button', { name: '使用同一请求重试' })).toHaveLength(1)
    const modal = screen.getByText('新增公告', { selector: '.ant-modal-title' }).closest('.ant-modal-content') as HTMLElement
    expect(screen.queryByText('新建公告', { selector: '.ant-drawer-title' })).not.toBeInTheDocument()
    expect(document.querySelector('.ant-drawer-content')).not.toBeInTheDocument()
    await user.click(within(modal).getByRole('button', { name: '使用同一请求重试' }))
    await flushUi()
    await waitFor(() => expect(creates).toBe(2))

    const posts = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')
    expect(posts[0][1]?.body).toBe(posts[1][1]?.body)
    expect(new Headers(posts[0][1]?.headers).get('Idempotency-Key')).toBe(
      new Headers(posts[1][1]?.headers).get('Idempotency-Key'),
    )
  })

  // fix-fielderr-be4：服务端拒绝正文时标在正文框下，编辑弹窗不关、不弹错误窗
  it('marks a server-refused body under its field and keeps the editor open', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'POST') {
        return json({ error: { code: 'validation_error', message: 'request fields are invalid', request_id: 'r', details: { field: 'body', reason: 'invalid' } } }, 400)
      }
      return json({ items: [] })
    })
    const user = userEvent.setup()
    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    await flushUi()
    await screen.findByText('暂无公告')
    await user.click(screen.getByRole('button', { name: '新建公告' }))
    fireEvent.change(screen.getByLabelText('标题'), { target: { value: '新公告' } })
    fireEvent.change(screen.getByLabelText('正文'), { target: { value: '见 www 链接' } })
    await user.click(screen.getByRole('button', { name: '保存' }))
    const help = await screen.findByText('填写的内容不符合要求')
    expect(help.closest('.ant-form-item')).toHaveClass('ant-form-item-has-error')
    expect(help.closest('.ant-form-item')).toContainElement(screen.getByLabelText('正文'))
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
    expect(screen.getByText('新增公告', { selector: '.ant-modal-title' })).toBeInTheDocument()
    expect(screen.getByLabelText('标题')).not.toBeDisabled()
  })

  it('exposes edit, schedule, publish, revise, and withdraw as real writes', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (!init?.method && url === `/v1/admin/announcements/${draft.id}`) return json(draft)
      if (!init?.method && url === `/v1/admin/announcements/${published.id}`) {
        return json(publishedWithoutAudienceArrays)
      }
      if (!init?.method && url.endsWith('/audience/count')) return json({ announcement_id: draft.id, version: 1, recipient_count: 3 })
      if (init?.method && init.method !== 'GET') {
        if (url.includes('/revise')) return json({ ...published, version: 2, head_version: 2 })
        if (url.includes(`/${published.id}/`)) return json(published)
        return json(draft)
      }
      return json({ items: [draft, published] })
    })
    const user = userEvent.setup()

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    await flushUi()
    const draftRow = (await screen.findByText('维护通知')).closest('tr')!

    await user.click(within(draftRow).getByRole('button', { name: '编辑' }))
    await screen.findByText('编辑草稿', { selector: '.ant-modal-title' })
    await user.clear(screen.getByLabelText('标题'))
    await user.type(screen.getByLabelText('标题'), '已编辑通知')
    await user.click(screen.getByRole('button', { name: '保存' }))
    await flushUi()
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(true))

    await waitFor(() => {
      const scheduleRow = screen.getByText('维护通知').closest('tr')!
      expect(within(scheduleRow).getByRole('button', { name: '定时发布' })).toBeEnabled()
    })
    fireEvent.click(within(screen.getByText('维护通知').closest('tr')!).getByRole('button', { name: '定时发布' }))
    const scheduleDialog = (await screen.findByText('定时发布', { selector: '.ant-modal-title' })).closest('.ant-modal-content') as HTMLElement
    fireEvent.change(within(scheduleDialog).getByLabelText('发布时间'), { target: { value: '2026-07-25T10:30' } })
    const dateNow = vi.spyOn(Date, 'now').mockReturnValue(Date.parse('2026-07-24T00:00:00Z'))
    await user.click(within(scheduleDialog).getByRole('button', { name: '定时发布' }))
    dateNow.mockRestore()
    await flushUi()
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).endsWith('/schedule'))).toBe(true))

    await waitFor(() => {
      const publishRow = screen.getByText('维护通知').closest('tr')!
      expect(within(publishRow).getByRole('button', { name: '立即发布' })).toBeEnabled()
    })
    fireEvent.click(within(screen.getByText('维护通知').closest('tr')!).getByRole('button', { name: '立即发布' }))
    const publishDialog = (await screen.findByText('确认发布公告', { selector: '.ant-modal-title' })).closest('.ant-modal-content') as HTMLElement
    expect(await within(publishDialog).findByText('将发送给 3 人')).toBeInTheDocument()
    await user.click(within(publishDialog).getByRole('button', { name: '确认' }))
    await flushUi()
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).endsWith('/publish'))).toBe(true))

    await waitFor(() => {
      const reviseRow = screen.getByText('已发布通知').closest('tr')!
      expect(within(reviseRow).getByRole('button', { name: '创建修订' })).toBeEnabled()
    })
    fireEvent.click(within(screen.getByText('已发布通知').closest('tr')!).getByRole('button', { name: '创建修订' }))
    await screen.findByText('创建修订草稿', { selector: '.ant-modal-title' })
    await user.click(screen.getByRole('button', { name: '保存' }))
    await flushUi()
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).endsWith('/revise'))).toBe(true))

    await waitFor(() => {
      const withdrawRow = screen.getByText('已发布通知').closest('tr')!
      expect(within(withdrawRow).getByRole('button', { name: '撤回' })).toBeEnabled()
    })
    fireEvent.click(within(screen.getByText('已发布通知').closest('tr')!).getByRole('button', { name: '撤回' }))
    const withdrawDialog = (await screen.findByText('确认撤回公告', { selector: '.ant-modal-title' })).closest('.ant-modal-content') as HTMLElement
    await user.click(within(withdrawDialog).getByRole('button', { name: '确认' }))
    await flushUi()
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).endsWith('/withdraw'))).toBe(true))
  })

  it('renders the loading state while the first page is pending', () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise<Response>(() => undefined))

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])

    expect(screen.getByTestId('announcement-table-scroll')).toHaveAttribute('aria-busy', 'true')
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

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    await flushUi()

    expect(await screen.findByText('公告请求失败，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('postgres connection detail')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    await flushUi()
    expect(await screen.findByText('暂无公告')).toBeInTheDocument()
    expect(reads).toBe(2)
  })

  it('renders permission denial without exposing server text', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({
      error: { code: 'permission_denied', message: 'internal authorization detail' },
    }, 403))

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    await flushUi()

    expect(await screen.findByText('当前账号没有公告管理权限')).toBeInTheDocument()
    expect(screen.queryByText('internal authorization detail')).not.toBeInTheDocument()
  })

  it.each([
    ['en-US', 'No announcements', 'Changed at'],
    ['qps-ploc', '［暂~无~公~告~］', '［状~态~变~更~时~间~］'],
  ] as const)('has a complete %s state surface', async (locale, empty, changedAt) => {
    await changeLocale(locale)
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ items: [] }))

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    await flushUi()

    expect(await screen.findByText(empty)).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: changedAt })).toBeInTheDocument()
  })

  it('refreshes detail and clears the stale editor after a 409', async () => {
    authenticate()
    const latest = { ...draft, revision: 2, state_changed_at: '2026-07-22T04:00:00Z' }
    let detailReads = 0
    let patches = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (!init?.method && url === `/v1/admin/announcements/${draft.id}`) {
        detailReads += 1
        return json(detailReads === 1 ? draft : latest)
      }
      if (init?.method === 'PATCH') {
        patches += 1
        if (patches === 1) return json({ error: { code: 'version_conflict', message: 'internal stale revision' } }, 409)
        return json(latest)
      }
      return json({ items: [detailReads > 1 ? latest : draft] })
    })
    const user = userEvent.setup()

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    await flushUi()
    const row = (await screen.findByText('维护通知')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '编辑' }))
    await screen.findByText('编辑草稿', { selector: '.ant-modal-title' })
    await user.click(screen.getByRole('button', { name: '保存' }))
    await flushUi()

    expect(await screen.findByText('公告已被其他操作修改，请刷新后重试')).toBeInTheDocument()
    expect(screen.queryByText('internal stale revision')).not.toBeInTheDocument()
    await waitFor(() => expect(detailReads).toBeGreaterThanOrEqual(2))
    expect(screen.queryByText('编辑草稿', { selector: '.ant-modal-title' })).not.toBeInTheDocument()

    const refreshedRow = (await screen.findByText('维护通知')).closest('tr')!
    await user.click(within(refreshedRow).getByRole('button', { name: '编辑' }))
    await screen.findByText('编辑草稿', { selector: '.ant-modal-title' })
    await user.click(screen.getByRole('button', { name: '保存' }))
    await flushUi()
    await waitFor(() => expect(patches).toBe(2))
    const patchCalls = vi.mocked(globalThis.fetch).mock.calls.filter(([, init]) => init?.method === 'PATCH')
    expect(new Headers(patchCalls[1][1]?.headers).get('If-Match')).toBe('"2"')
    expect(JSON.parse(String(patchCalls[1][1]?.body))).toMatchObject({ expected_revision: 2 })
  })

  it('matches the competitor announcement editor and submits presentation settings', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (init?.method === 'POST') return json({ ...draft, title: '新公告', format: 'content', sort_order: 100, visible: true, popup: false, red: true, bold: true })
      if (url.includes('/v1/admin/announcements')) return json({ items: [] })
      return json({})
    })
    const user = userEvent.setup()
    renderAnnouncementsWithQueryClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }))
    await flushUi()
    await user.click(screen.getByRole('button', { name: '新建公告' }))
    expect(screen.getByText('基础信息')).toBeInTheDocument()
    expect(screen.getByText('展示状态')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('请输入标题')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('请输入html内容')).toBeInTheDocument()
    expect(screen.getByRole('spinbutton', { name: '排序' })).toHaveValue('100')
    expect(screen.getByRole('checkbox', { name: '加红' })).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: '加粗' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '跳转链接' }))
    expect(screen.getByPlaceholderText('请输入链接')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '显示内容' }))
    await user.type(screen.getByLabelText('标题'), '新公告')
    await user.type(screen.getByLabelText('正文'), '正文')
    await user.click(screen.getByRole('checkbox', { name: '加红' }))
    await user.click(screen.getByRole('checkbox', { name: '加粗' }))
    await user.click(screen.getByRole('button', { name: '保存' }))
    await flushUi()
    const post = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')
    expect(JSON.parse(String(post?.[1]?.body))).toMatchObject({ format: 'content', sort_order: 100, visible: true, popup: false, red: true, bold: true })
  })

  it('archives and restores a tenant announcement through the confirmation flow', async () => {
    authenticate()
    let current: Announcement = { ...draft }
    let archiveCalls = 0
    let restoreCalls = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (init?.method === 'POST' && url.endsWith(`/v1/admin/announcements/${draft.id}/archive`)) {
        archiveCalls += 1
        current = { ...current, archived: true, lifecycle_revision: 2, archived_at: '2026-07-22T05:00:00Z' }
        return json(current)
      }
      if (init?.method === 'POST' && url.endsWith(`/v1/admin/announcements/${draft.id}/restore`)) {
        restoreCalls += 1
        current = { ...current, archived: false, lifecycle_revision: 3, archived_at: undefined }
        return json(current)
      }
      if (!init?.method && url === '/v1/admin/announcements?limit=20') return json({ items: [current] })
      return json({ items: [] })
    })
    const user = userEvent.setup()

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    const initialRow = (await screen.findByText(draft.title)).closest('tr')!
    await user.click(within(initialRow).getByRole('button', { name: '归档' }))
    expect(await screen.findByText('确认归档公告', { selector: '.ant-modal-title' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '确认' }))
    await waitFor(() => expect(archiveCalls).toBe(1))
    const archivedRow = await screen.findByText(draft.title)
    expect(within(archivedRow.closest('tr')!).getByText('已归档')).toBeInTheDocument()

    await user.click(within(archivedRow.closest('tr')!).getByRole('button', { name: '恢复' }))
    expect(await screen.findByText('确认恢复公告', { selector: '.ant-modal-title' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '确认' }))
    await waitFor(() => expect(restoreCalls).toBe(1))
    expect(await screen.findByText('草稿')).toBeInTheDocument()
  })

  it('requires confirmation before archiving selected announcements', async () => {
    authenticate()
    const second = { ...published, id: '55555555-5555-4555-8555-555555555555' }
    const archivedIDs = new Set<string>()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (init?.method === 'POST' && url.endsWith('/archive')) {
        const id = decodeURIComponent(url.split('/').at(-2)!)
        archivedIDs.add(id)
        return json({ ...(id === draft.id ? draft : second), archived: true, lifecycle_revision: 2 })
      }
      return json({ items: [draft, second] })
    })
    const user = userEvent.setup()

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    const firstRow = (await screen.findByText(draft.title)).closest('tr')!
    const secondRow = screen.getByText(second.title).closest('tr')!
    await user.click(within(firstRow).getByRole('checkbox'))
    await user.click(within(secondRow).getByRole('checkbox'))
    const bulkArchive = screen.getByRole('button', { name: '批量归档' })
    expect(bulkArchive).toHaveClass('ant-btn-default', 'ant-btn-dangerous')
    expect(bulkArchive).not.toHaveClass('ant-btn-primary')
    await user.click(bulkArchive)

    expect(await screen.findByText('确认归档公告', { selector: '.ant-modal-title' })).toBeInTheDocument()
    expect(archivedIDs.size).toBe(0)
    await user.click(screen.getByRole('button', { name: '确认' }))
    await waitFor(() => expect(archivedIDs).toEqual(new Set([draft.id, second.id])))
  })

  it.each([
    [400, 'validation_error'],
    [409, 'announcement_state_conflict'],
  ])('refreshes a partially archived batch after a %s error and reports confirmed progress', async (status, code) => {
    authenticate()
    let firstArchived = false
    let listReads = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (init?.method === 'POST' && url.endsWith(`/${draft.id}/archive`)) {
        firstArchived = true
        return json({ ...draft, archived: true, lifecycle_revision: 2 })
      }
      if (init?.method === 'POST' && url.endsWith(`/${published.id}/archive`)) {
        return json({ error: { code, message: 'internal archive failure' } }, status)
      }
      listReads += 1
      return json({ items: firstArchived ? [published] : [draft, published] })
    })
    const user = userEvent.setup()
    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    await user.click(within((await screen.findByText(draft.title)).closest('tr')!).getByRole('checkbox'))
    await user.click(within(screen.getByText(published.title).closest('tr')!).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '批量归档' }))
    await user.click(await screen.findByRole('button', { name: '确认' }))

    expect(await screen.findByText('已归档: 1 / 2')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText(draft.title)).not.toBeInTheDocument())
    expect(screen.getByText(published.title)).toBeInTheDocument()
    expect(listReads).toBeGreaterThanOrEqual(2)
    expect(screen.queryByText('internal archive failure')).not.toBeInTheDocument()
    expect(screen.queryByText('所选公告已归档')).not.toBeInTheDocument()
  })

  it('refreshes an unknown batch outcome and retries only the unfinished item with the same key', async () => {
    authenticate()
    const requests: { id: string; key: string | null; body: unknown }[] = []
    let firstArchived = false
    let secondArchived = false
    let listReads = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (init?.method === 'POST' && url.endsWith('/archive')) {
        const id = url.split('/').at(-2)!
        requests.push({ id, key: new Headers(init.headers).get('Idempotency-Key'), body: JSON.parse(String(init.body)) })
        if (id === draft.id) {
          firstArchived = true
          return json({ ...draft, archived: true, lifecycle_revision: 2 })
        }
        if (!secondArchived) {
          secondArchived = true
          return Promise.reject(new Error('response lost after commit'))
        }
        return json({ ...published, archived: true, lifecycle_revision: 2, replayed: true })
      }
      listReads += 1
      return json({ items: [draft, published].filter((item) => item.id === draft.id ? !firstArchived : !secondArchived) })
    })
    const user = userEvent.setup()
    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    await user.click(within((await screen.findByText(draft.title)).closest('tr')!).getByRole('checkbox'))
    await user.click(within(screen.getByText(published.title).closest('tr')!).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '批量归档' }))
    await user.click(await screen.findByRole('button', { name: '确认' }))

    expect(await screen.findByText('已归档: 1 / 2')).toBeInTheDocument()
    await waitFor(() => expect(listReads).toBeGreaterThanOrEqual(2))
    await user.click(await screen.findByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('所选公告已归档')).toBeInTheDocument()
    expect(requests.map(({ id }) => id)).toEqual([draft.id, published.id, published.id])
    expect(requests[2]).toEqual(requests[1])
  })

  // C32 (Codex ADM01): audience members are picked by name, stored IDs are
  // shown by name (or as deleted), and publishing previews the recipient count.
  describe('C32 audience by name and recipient count', () => {
    const userID = '44444444-4444-4444-8444-444444444444'
    const roleID = '55555555-5555-4555-8555-555555555555'
    const goneID = '66666666-6666-4666-8666-666666666666'
    const selectedDraft = { ...draft, audience: { all: false, user_ids: [userID, goneID], group_ids: [roleID] } } satisfies Announcement

    it('searches users and roles by name and submits their IDs without showing them', async () => {
      authenticate()
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const url = String(input)
        if (url.startsWith('/v1/admin/announcements/audience-directory?')) {
          const params = new URL(url, 'http://local').searchParams
          return json({ items: params.get('kind') === 'user'
            ? [{ id: userID, name: '张三', detail: 'zhangsan' }]
            : [{ id: roleID, name: 'tenant_owner', system: true }] })
        }
        if (init?.method === 'POST') return json(draft, 201)
        return json({ items: [] })
      })
      const user = userEvent.setup()
      renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
      await user.click(await screen.findByRole('button', { name: '新建公告' }))
      fireEvent.change(screen.getByLabelText('标题'), { target: { value: '新公告' } })
      fireEvent.change(screen.getByLabelText('正文'), { target: { value: '发布内容' } })
      await user.click(screen.getByRole('combobox', { name: '受众范围' }))
      await user.click(await screen.findByText('指定用户或角色', { selector: '.ant-select-item-option-content' }))

      await user.type(screen.getByRole('combobox', { name: '用户' }), '张')
      await user.click(await screen.findByText('张三（zhangsan）', { selector: '.ant-select-item-option-content' }))
      await user.click(screen.getByRole('combobox', { name: '角色' }))
      await user.click(await screen.findByText('主账号', { selector: '.ant-select-item-option-content' }))
      const dialog = screen.getByRole('dialog')
      expect(dialog.textContent).not.toContain(userID)
      expect(dialog.textContent).not.toContain(roleID)
      await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).includes('kind=user&search=%E5%BC%A0'))).toBe(true))

      await user.click(screen.getByRole('button', { name: '保存' }))
      await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
      const body = JSON.parse(String(fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')![1]!.body))
      expect(body).toMatchObject({ all: false, user_ids: [userID], group_ids: [roleID] })
    })

    it('shows stored audience members by name and missing ones as deleted', async () => {
      authenticate()
      vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
        const url = String(input)
        if (url === `/v1/admin/announcements/${draft.id}`) return json(selectedDraft)
        if (url.startsWith('/v1/admin/announcements/audience-directory?')) {
          const params = new URL(url, 'http://local').searchParams
          return json({ items: params.get('kind') === 'user'
            ? [{ id: userID, name: '张三', detail: 'zhangsan' }]
            : [{ id: roleID, name: 'ops' }] })
        }
        return json({ items: [selectedDraft] })
      })
      const user = userEvent.setup()
      renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
      await user.click(within((await screen.findByText('维护通知')).closest('tr')!).getByRole('button', { name: '编辑' }))
      const dialog = await screen.findByRole('dialog')
      expect(await within(dialog).findByText('张三（zhangsan）')).toBeInTheDocument()
      expect(within(dialog).getByText('已删除的对象')).toBeInTheDocument()
      expect(within(dialog).getByText('ops')).toBeInTheDocument()
      expect(dialog.textContent).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-/)
    })

    it('disables publishing when the audience resolves to nobody', async () => {
      authenticate()
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
        const url = String(input)
        if (url.endsWith('/audience/count')) return json({ announcement_id: draft.id, version: 1, recipient_count: 0 })
        return json({ items: [draft] })
      })
      renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
      fireEvent.click(within((await screen.findByText('维护通知')).closest('tr')!).getByRole('button', { name: '立即发布' }))
      const dialog = (await screen.findByText('确认发布公告', { selector: '.ant-modal-title' })).closest('.ant-modal-content') as HTMLElement
      expect(await within(dialog).findByText('当前受众中没有活跃用户，无法发布。请先调整受众。')).toBeInTheDocument()
      expect(within(dialog).getByRole('button', { name: '确认' })).toBeDisabled()
      expect(fetchSpy.mock.calls.some(([url]) => String(url) === `/v1/admin/announcements/${draft.id}/audience/count`)).toBe(true)
      expect(fetchSpy.mock.calls.some(([url]) => String(url).endsWith('/publish'))).toBe(false)
    })
  })
})
