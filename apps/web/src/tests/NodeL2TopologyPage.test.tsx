import { act, screen, waitFor, within } from '@testing-library/react'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import userEvent from '@testing-library/user-event'
import { useLocation } from 'react-router-dom'

import type { L2Config } from '../api/nodeScheduling'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import NodeL2TopologyPage from '../pages/NodeL2TopologyPage'
import nodeL2TopologyRawCSS from '../pages/NodeL2TopologyPage.css?raw'
import { pseudoNodeScheduling, zhCNNodeScheduling } from '../pages/node-scheduling/messages'
import { principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { defaultLookCSS } from '../test/defaultLookCSS'

// OutcomeUnknown 的标题同时出现在恢复条和说明弹窗里，这里只认原位的恢复条。
const OUTCOME_BAR = { selector: '.cdnca-outcome-bar .ant-alert-message' }

const nodeL2TopologyCSS = defaultLookCSS(nodeL2TopologyRawCSS)

const tenantA = '22222222-2222-4222-8222-222222222222'
const tenantB = '66666666-6666-4666-8666-666666666666'
const userA = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'

const group: L2Config = {
  id: '11111111-1111-4111-8111-111111111111',
  display_id: '1',
  tenant_scope_id: tenantA,
  revision: 7,
  name: '华东 L2 线路',
  region: 'cn-east',
  remark: '',
  mode: 'cache',
  load_method: 'rr',
  created_at: '2026-07-28T08:00:00Z',
  updated_at: '2026-07-28T08:00:01Z',
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise
  })
  return { promise, resolve }
}

function authenticate({
  scopeKind = 'tenant',
  permissions = ['node_scheduling.read', 'node_scheduling.manage'],
  token = 'access-token',
  userID = userA,
  overrides = {},
}: {
  scopeKind?: 'tenant' | 'platform'
  permissions?: string[]
  token?: string
  userID?: string
  overrides?: Parameters<typeof principal>[0]
} = {}) {
  useSessionStore.setState({
    accessToken: token,
    expiresAt: Date.now() + 60_000,
    principal: principal({
      scope_kind: scopeKind,
      scope_id: tenantA,
      tenant_id: scopeKind === 'tenant' ? tenantA : null,
      user_id: userID,
      permissions,
      roles: [scopeKind === 'tenant' ? 'tenant_owner' : 'platform_admin'],
      ...overrides,
    }),
    status: 'authenticated',
  })
}

function QueryClientCapture({ onCapture }: { onCapture: (client: QueryClient) => void }) {
  onCapture(useQueryClient())
  return null
}

function LocationCapture() {
  const location = useLocation()
  return <span data-testid="location">{location.pathname}{location.search}</span>
}

async function submitValidCreate(user: ReturnType<typeof userEvent.setup>, name: string) {
  await user.click(screen.getByRole('button', { name: '新增配置' }))
  const dialog = await screen.findByRole('dialog', { name: '新增L2配置' })
  await user.click(within(dialog).getByRole('combobox', { name: '区域' }))
  await user.click(screen.getByText('默认', { selector: '.ant-select-item-option-content' }))
  await user.type(within(dialog).getByLabelText('名称'), name)
  await user.click(within(dialog).getByRole('button', { name: '确定' }))
}

beforeAll(() => {
  i18n.addResourceBundle('zh-CN', 'nodeScheduling', zhCNNodeScheduling, true, true)
  i18n.addResourceBundle('qps-ploc', 'nodeScheduling', pseudoNodeScheduling, true, true)
  i18n.addResourceBundle('qps-Ploc', 'nodeScheduling', pseudoNodeScheduling, true, true)
})

beforeEach(() => sessionStorage.clear())

describe('NodeL2TopologyPage', () => {
  it.each([
    ['missing read permission', ['node_scheduling.manage']],
    ['missing all scheduling permissions', []],
  ])('denies %s locally without querying', async (_caseName, permissions) => {
    authenticate({ permissions })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<NodeL2TopologyPage />)

    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新增配置' })).not.toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['tenant missing scope ID', {
      scope_kind: 'tenant' as const,
      scope_id: '',
      tenant_id: tenantA,
    }],
    ['tenant missing user ID', {
      scope_kind: 'tenant' as const,
      scope_id: tenantA,
      tenant_id: tenantA,
      user_id: '',
    }],
    ['platform carrying tenant ID', {
      scope_kind: 'platform' as const,
      scope_id: 'platform',
      tenant_id: tenantA,
    }],
    ['platform missing scope ID', {
      scope_kind: 'platform' as const,
      scope_id: '',
      tenant_id: null,
    }],
  ])('fails closed with zero requests for %s', async (_caseName, overrides) => {
    authenticate({ overrides })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<NodeL2TopologyPage />)

    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('fails closed with zero requests for a zero session epoch', async () => {
    authenticate()
    useSessionStore.setState({ sessionEpoch: 0 })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<NodeL2TopologyPage />)

    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('keeps loading, pagination, localized error, and retry states natural', async () => {
    authenticate({ permissions: ['node_scheduling.read'] })
    const firstRead = deferred<Response>()
    let reads = 0
    const groups = Array.from({ length: 11 }, (_, index) => ({
      ...group,
      id: `${String(index + 1).padStart(8, '0')}-1111-4111-8111-111111111111`,
      name: `L2 分页线路 ${index + 1}`,
    }))
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      reads += 1
      return reads === 1 ? firstRead.promise : Promise.resolve(json({ items: groups }))
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeL2TopologyPage />)
    const table = screen.getByTestId('node-l2-topology-table')
    expect(table).toHaveAttribute('aria-busy', 'true')
    await act(async () => firstRead.resolve(json({
      error: { code: 'private_code', message: 'private server detail' },
    }, 500)))
    expect(await screen.findByText('节点调度配置加载失败')).toBeInTheDocument()
    expect(table).toHaveAttribute('aria-busy', 'false')
    expect(screen.getByText('请求失败，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('private server detail')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('L2 分页线路 1')).toBeInTheDocument()
    expect(screen.getByText('第 1 / 2 页')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('L2 分页线路 11')).toBeInTheDocument()
    expect(screen.getByText('第 2 / 2 页')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('renders the empty L2 state without replacing the table shell', async () => {
    authenticate({ permissions: ['node_scheduling.read'] })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))

    renderWithProviders(<NodeL2TopologyPage />)

    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getByTestId('node-l2-topology-table')).toHaveAttribute('aria-busy', 'false')
    })
  })

  // 页顶说明卡，首次展开、之后记住收起。
  it('explains L2 once expanded, then remembers it collapsed', async () => {
    localStorage.clear()
    authenticate({ permissions: ['node_scheduling.read'] })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))
    const user = userEvent.setup()

    const first = renderWithProviders(<NodeL2TopologyPage />)
    const intro = await screen.findByRole('region', { name: 'L2 是什么、怎么用' })
    const toggle = within(intro).getByRole('button', { name: '收起说明' })
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    const flow = within(intro).getByRole('img', { name: '用户 → L1 边缘节点 → L2 中间节点 → 源站' })
    expect(within(flow).getAllByText(/^(用户|L1 边缘节点|L2 中间节点|源站)$/)).toHaveLength(4)
    expect(intro).toHaveTextContent('L1 回源时先向 L2 请求')
    expect(intro).toHaveTextContent('缓存模式')
    expect(intro).toHaveTextContent('URL哈希')
    expect(intro).toHaveTextContent('L2条件')
    expect(intro).toHaveTextContent('直接回源站')
    expect(intro).toHaveTextContent('线路分组 > 编辑 > L2回源配置')
    // 代码事实：节点类型只是标识；自动发布按网站线路分组的 L2 配置走 L2
    expect(intro).toHaveTextContent('节点类型只是标识')
    expect(intro).toHaveTextContent('保存后自动发布会按网站所用线路分组的 L2 配置走 L2')
    expect(intro).toHaveTextContent('L1 按访客进来的协议和端口连 L2，L2 按网站回源设置回源站')
    expect(intro).not.toHaveTextContent('线路分组快照')
    expect(within(intro).getByRole('link', { name: '线路分组' })).toHaveAttribute('href', '/node/line-group')
    first.unmount()

    renderWithProviders(<NodeL2TopologyPage />)
    const again = await screen.findByRole('region', { name: 'L2 是什么、怎么用' })
    const expand = within(again).getByRole('button', { name: '展开说明' })
    expect(expand).toHaveAttribute('aria-expanded', 'false')
    expect(within(again).queryByRole('img')).not.toBeInTheDocument()
    await user.click(expand)
    expect(within(again).getByRole('button', { name: '收起说明' })).toHaveAttribute('aria-expanded', 'true')
    await user.click(within(again).getByRole('button', { name: '收起说明' }))
    expect(localStorage.getItem('cdnca.nodeL2Intro')).toBe('collapsed')
    // 说明卡样式只读共享变量，不写回退色
    const introCSS = nodeL2TopologyRawCSS.slice(nodeL2TopologyRawCSS.indexOf('.node-l2-intro'))
    expect(introCSS).toContain('var(--cdnca-color-info-bg)')
    expect(introCSS).not.toMatch(/var\(--[\w-]+,/)
    expect(introCSS).not.toMatch(/#[0-9a-f]{3,8}\b/i)
  })

  // 新增/删除/区域放在 L2配置/L2条件 标签行右侧，同一行。
  it('puts the L2 toolbar on the tab row, outside the tablist', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))

    renderWithProviders(<NodeL2TopologyPage />)

    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    const tablist = screen.getAllByRole('tablist').find((list) => within(list).queryByRole('tab', { name: 'L2配置' }))!
    const row = tablist.closest('.node-l2-topology-tab-row') as HTMLElement
    expect(row).not.toBeNull()
    const toolbar = within(row).getByRole('toolbar')
    expect(within(toolbar).getByRole('button', { name: '新增配置' })).toBeInTheDocument()
    expect(within(toolbar).getByRole('combobox', { name: '区域' })).toBeInTheDocument()
    expect(tablist).not.toContainElement(toolbar)
  })

  it('keeps the observed compact L2 inventory shell and conditions tab', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))

    renderWithProviders(<NodeL2TopologyPage />)

    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增配置' }).querySelector('svg')).not.toBeNull()
    expect(screen.getByRole('button', { name: '删除' })).toBeEnabled()
    expect(screen.getByRole('tab', { name: 'L2配置' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: 'L2条件' })).toBeEnabled()
    expect(screen.getByRole('combobox', { name: '区域' })).toBeInTheDocument()
    expect(screen.getAllByRole('columnheader')
      .map((heading) => heading.textContent?.trim())
      .filter(Boolean)).toEqual(['ID', '名称', '区域', '模式', '负载方式', '操作'])
    expect(nodeL2TopologyCSS).toContain('height: 40px;')
    expect(nodeL2TopologyCSS).toContain('height: 48px;')
    expect(nodeL2TopologyCSS).toContain('.ant-table-placeholder .ant-empty-image')
    expect(nodeL2TopologyCSS).toContain('background: #f8fbff;')
    expect(nodeL2TopologyCSS).toContain('background: rgb(45 140 240 / 12%);')
    expect(nodeL2TopologyCSS).not.toContain('.node-l2-topology-tab.is-active::after')
    expect(nodeL2TopologyCSS).toContain('.node-l2-topology-tab:hover:not(:disabled)')
    expect(nodeL2TopologyCSS).toContain('.node-l2-topology-tab:focus-visible')
    expect(nodeL2TopologyCSS).toContain('outline: 2px solid var(--cdnca-color-primary);')
    expect(nodeL2TopologyCSS).toContain('cursor: not-allowed;')
    expect(nodeL2TopologyCSS).toContain('overflow-x: auto !important;')
    expect(nodeL2TopologyCSS).toContain('width: 60px;')
    expect(nodeL2TopologyCSS).toContain('padding: 18px 20px 20px;')
    expect(nodeL2TopologyCSS).toContain('width: 90px;')
    expect(nodeL2TopologyCSS).toContain('margin: 24px !important;')
    expect(nodeL2TopologyCSS).not.toContain('ant-table-cell-fix-right')
  })

  it('uses a default danger delete that confirms before DELETE and a cancel-first editor footer', async () => {
    authenticate()
    let items: L2Config[] = [group]
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'DELETE') {
        items = []
        return Promise.resolve(new Response(null, { status: 204 }))
      }
      return Promise.resolve(json({ items }))
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeL2TopologyPage />)
    const row = (await screen.findByText('华东 L2 线路')).closest('tr')!
    const deleteButton = within(screen.getByRole('toolbar')).getByRole('button', { name: '删除' })
    expect(deleteButton).toHaveClass('ant-btn-default', 'ant-btn-dangerous')
    expect(deleteButton).not.toHaveClass('ant-btn-primary')

    await user.click(screen.getByRole('button', { name: '新增配置' }))
    const editor = await screen.findByRole('dialog', { name: '新增L2配置' })
    expect(Array.from(editor.querySelectorAll('.ant-modal-footer .ant-btn')).map((button) => button.textContent?.trim()))
      .toEqual(['取消', '确定'])
    await user.click(within(editor).getByRole('button', { name: '取消' }))

    await user.click(within(row).getByRole('checkbox'))
    await user.click(deleteButton)
    const confirmation = await screen.findByRole('dialog', { name: '删除确认' })
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false)
    await user.click(within(confirmation).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'DELETE')).toHaveLength(1))
  })

  it('allows platform.admin to manage its own control scope without a UUID prompt', async () => {
    authenticate({ scopeKind: 'platform', permissions: ['platform.admin'] })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [group] }))
    renderWithProviders(<NodeL2TopologyPage />)
    expect(await screen.findByText('华东 L2 线路')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledWith(
      '/v1/l2-configs',
      expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer access-token' }) }),
    )
    expect(screen.getByRole('button', { name: '新增配置' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: '读取租户' })).not.toBeInTheDocument()
  })

  it('keeps token-free owner cache identity and an exact unknown create across same-epoch token refresh', async () => {
    authenticate({ token: 'token-before-refresh' })
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const groups = Array.from({ length: 11 }, (_, index) => ({
      ...group,
      id: `${String(index + 1).padStart(8, '0')}-1111-4111-8111-111111111111`,
      name: `轮换 L2 线路 ${index + 1}`,
    }))
    let writes = 0
    let queryClient!: QueryClient
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'POST') {
        writes += 1
        return writes === 1
          ? Promise.reject(new TypeError('connection reset'))
          : Promise.resolve(json({ ...group, name: '轮换新线路' }))
      }
      return Promise.resolve(json({ items: groups }))
    })
    const user = userEvent.setup()

    renderWithProviders(<>
      <NodeL2TopologyPage />
      <QueryClientCapture onCapture={(client) => { queryClient = client }} />
    </>, ['/node/l2-config?mode=advanced'])
    expect(await screen.findByText('轮换 L2 线路 1')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    await submitValidCreate(user, '轮换新线路')
    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()

    const owner = ['tenant', tenantA, tenantA, userA, sessionEpoch]
    const queryKey = ['node-l2-topology', ...owner, 'configuration']
    const mutationKey = ['node-l2-topology-write', ...owner]
    expect(queryClient.getQueryCache().find({ queryKey, exact: true })).toBeDefined()
    expect(queryClient.getMutationCache().find({ mutationKey, exact: true })).toBeDefined()
    expect(JSON.stringify({
      queries: queryClient.getQueryCache().getAll().map((entry) => ({ key: entry.queryKey, state: entry.state })),
      mutations: queryClient.getMutationCache().getAll().map((entry) => ({ key: entry.options.mutationKey, state: entry.state })),
    })).not.toContain('token-before-refresh')

    act(() => useSessionStore.setState({
      accessToken: 'token-after-refresh',
      expiresAt: Date.now() + 60_000,
    }))
    expect(screen.getByText('第 2 / 2 页')).toBeInTheDocument()
    expect(screen.getByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '刷新并对账' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => !init?.method)).toHaveLength(3))
    expect(new Headers(fetchSpy.mock.calls.filter(([, init]) => !init?.method).at(-1)![1]?.headers).get('Authorization'))
      .toBe('Bearer token-after-refresh')
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('L2 配置已保存')).toBeInTheDocument()

    const calls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')
    expect(calls).toHaveLength(2)
    expect(calls[0][1]?.body).toBe(calls[1][1]?.body)
    const firstHeaders = new Headers(calls[0][1]?.headers)
    const retryHeaders = new Headers(calls[1][1]?.headers)
    expect(firstHeaders.get('Authorization')).toBe('Bearer token-before-refresh')
    expect(retryHeaders.get('Authorization')).toBe('Bearer token-after-refresh')
    for (const name of ['If-Match', 'Idempotency-Key', 'X-Request-ID']) {
      expect(retryHeaders.get(name)).toBe(firstHeaders.get(name))
    }
    expect(firstHeaders.get('If-Match')).toBe('"0"')
    expect(firstHeaders.get('X-Request-ID')).toBe(firstHeaders.get('Idempotency-Key'))
  })

  it('resets local state and removes old cache on a new session epoch', async () => {
    authenticate({ scopeKind: 'platform', permissions: ['node_scheduling.read'], token: 'old-platform-token' })
    const oldEpoch = useSessionStore.getState().sessionEpoch
    const groups = Array.from({ length: 11 }, (_, index) => ({
      ...group,
      id: `${String(index + 1).padStart(8, '0')}-1111-4111-8111-111111111111`,
      name: `平台旧线路 ${index + 1}`,
    }))
    let queryClient!: QueryClient
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: groups }))
    const user = userEvent.setup()

    renderWithProviders(<>
      <NodeL2TopologyPage />
      <QueryClientCapture onCapture={(client) => { queryClient = client }} />
    </>, ['/node/l2-config?mode=advanced'])
    expect(await screen.findByText('平台旧线路 1')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))

    act(() => useSessionStore.setState({
      accessToken: 'new-platform-token',
      expiresAt: Date.now() + 60_000,
      sessionEpoch: oldEpoch + 1,
    }))

    expect(await screen.findByText('平台旧线路 1')).toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: '目标租户作用域 ID' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '读取租户' })).not.toBeInTheDocument()
    expect(screen.getByText('第 1 / 2 页')).toBeInTheDocument()
    expect(screen.queryByText('平台旧线路 11')).not.toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(2)
    await waitFor(() => {
      expect(queryClient.getQueryCache().getAll().some((entry) => entry.queryKey.includes(oldEpoch))).toBe(false)
    })
  })

  it.each(['success', 'error', 'forbidden'] as const)(
    'ignores a delayed old-owner list %s',
    async (settlement) => {
      authenticate({ token: 'old-list-token' })
      const oldEpoch = useSessionStore.getState().sessionEpoch
      const pendingList = deferred<Response>()
      let queryClient!: QueryClient
      vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
        const authorization = new Headers(init?.headers).get('Authorization')
        if (authorization === 'Bearer old-list-token') return pendingList.promise
        if (authorization === 'Bearer current-list-token') {
          return Promise.resolve(json({ items: [{ ...group, name: '当前会话线路' }] }))
        }
        throw new Error(`unexpected authorization: ${authorization}`)
      })

      renderWithProviders(<>
        <NodeL2TopologyPage />
        <QueryClientCapture onCapture={(client) => { queryClient = client }} />
      </>)
      expect(screen.getByTestId('node-l2-topology-table')).toHaveAttribute('aria-busy', 'true')

      act(() => useSessionStore.setState({
        accessToken: 'current-list-token',
        expiresAt: Date.now() + 60_000,
        sessionEpoch: oldEpoch + 1,
      }))
      expect(await screen.findByText('当前会话线路')).toBeInTheDocument()

      await act(async () => {
        pendingList.resolve(settlement === 'success'
          ? json({ items: [{ ...group, name: '旧会话私有线路' }] })
          : json({
            error: { code: 'private_old_error', message: 'old private server detail' },
          }, settlement === 'forbidden' ? 403 : 500))
        await Promise.resolve()
        await Promise.resolve()
      })

      expect(screen.getByText('当前会话线路')).toBeInTheDocument()
      expect(screen.queryByText('旧会话私有线路')).not.toBeInTheDocument()
      expect(screen.queryByText('old private server detail')).not.toBeInTheDocument()
      expect(screen.queryByText('无权查看节点调度配置')).not.toBeInTheDocument()
      await waitFor(() => {
        expect(queryClient.getQueryCache().getAll().some((entry) => entry.queryKey.includes(oldEpoch))).toBe(false)
      })
    },
  )

  it.each(['success', 'error', 'forbidden'] as const)(
    'ignores a delayed old-owner create %s',
    async (settlement) => {
      authenticate({ token: 'old-create-token' })
      const oldEpoch = useSessionStore.getState().sessionEpoch
      const pendingCreate = deferred<Response>()
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
        const authorization = new Headers(init?.headers).get('Authorization')
        if (init?.method === 'POST') return pendingCreate.promise
        if (authorization === 'Bearer old-create-token') return Promise.resolve(json({ items: [group] }))
        if (authorization === 'Bearer current-create-token') {
          return Promise.resolve(json({ items: [{ ...group, name: '当前会话线路' }] }))
        }
        throw new Error(`unexpected authorization: ${authorization}`)
      })
      const user = userEvent.setup()

      renderWithProviders(<>
        <NodeL2TopologyPage />
        <LocationCapture />
      </>, ['/node/l2-config?mode=advanced'])
      expect(await screen.findByText('华东 L2 线路')).toBeInTheDocument()
      await submitValidCreate(user, '旧会话敏感新线路')

      act(() => useSessionStore.setState({
        accessToken: 'current-create-token',
        expiresAt: Date.now() + 60_000,
        sessionEpoch: oldEpoch + 1,
      }))
      expect(await screen.findByText('当前会话线路')).toBeInTheDocument()
      expect(screen.queryByRole('dialog', { name: '新增L2配置' })).not.toBeInTheDocument()

      await act(async () => {
        pendingCreate.resolve(settlement === 'success'
          ? json({ ...group, name: '旧会话敏感新线路' })
          : json({
            error: { code: 'private_old_error', message: 'old private write detail' },
          }, settlement === 'forbidden' ? 403 : 500))
        await Promise.resolve()
        await Promise.resolve()
      })

      expect(screen.getByText('当前会话线路')).toBeInTheDocument()
      expect(screen.queryByText('L2 配置已保存')).not.toBeInTheDocument()
      expect(screen.queryByText('线路配置保存失败')).not.toBeInTheDocument()
      expect(screen.getByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: '新增配置' })).toBeDisabled()
      expect(screen.queryByText('old private write detail')).not.toBeInTheDocument()
      expect(screen.getByTestId('location')).toHaveTextContent('/')
      expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1)
    },
  )

  it.each([
    ['tenant foreign scope', 'tenant' as const, tenantB],
    ['tenant missing scope', 'tenant' as const, undefined],
    ['platform foreign scope', 'platform' as const, tenantB],
  ])('fails closed for a %s list response', async (_caseName, scopeKind, responseScope) => {
    authenticate({
      scopeKind,
      permissions: scopeKind === 'tenant' ? ['node_scheduling.read'] : ['platform.admin'],
    })
    const sensitive = { ...group, tenant_scope_id: responseScope, name: '越权私有线路' }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [sensitive] }))
    renderWithProviders(<NodeL2TopologyPage />)

    expect(await screen.findByText('节点调度配置加载失败')).toBeInTheDocument()
    expect(screen.getByText('请求失败，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('越权私有线路')).not.toBeInTheDocument()
  })

  it.each([
    ['foreign', tenantB],
    ['missing', undefined],
  ])('fails closed for a %s create response without navigating or exposing data', async (_caseName, responseScope) => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => Promise.resolve(
      init?.method === 'POST'
        ? json({ ...group, tenant_scope_id: responseScope, name: '越权新线路' })
        : json({ items: [group] }),
    ))
    const user = userEvent.setup()

    renderWithProviders(<>
      <NodeL2TopologyPage />
      <LocationCapture />
    </>, ['/node/l2-config?mode=advanced'])
    expect(await screen.findByText('华东 L2 线路')).toBeInTheDocument()
    await submitValidCreate(user, '越权新线路')

    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增配置' })).toBeDisabled()
    expect(screen.queryByText('L2 配置已保存')).not.toBeInTheDocument()
    expect(screen.getByTestId('location')).toHaveTextContent('/')
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1)
  })

  it('keeps a current-owner list 403 terminal across refresh, focus, reconnect, retry, and invalidation', async () => {
    authenticate({ token: 'denied-list-token' })
    const ownerEpoch = useSessionStore.getState().sessionEpoch
    let queryClient!: QueryClient
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'node_scheduling_permission_denied', message: 'private list denial' },
    }, 403))

    renderWithProviders(<>
      <NodeL2TopologyPage />
      <QueryClientCapture onCapture={(client) => { queryClient = client }} />
    </>)
    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()

    act(() => useSessionStore.setState({
      accessToken: 'refreshed-denied-list-token',
      expiresAt: Date.now() + 60_000,
    }))
    await act(async () => {
      await queryClient.invalidateQueries({
        queryKey: ['node-l2-topology', 'tenant', tenantA, tenantA, userA, ownerEpoch],
      })
      window.dispatchEvent(new Event('focus'))
      window.dispatchEvent(new Event('online'))
      await Promise.resolve()
    })

    expect(screen.getByText('无权查看节点调度配置')).toBeInTheDocument()
    expect(screen.queryByText('private list denial')).not.toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('makes a current-owner create 403 terminal and cannot reawaken it after token refresh', async () => {
    authenticate({ token: 'denied-create-token' })
    const ownerEpoch = useSessionStore.getState().sessionEpoch
    let queryClient!: QueryClient
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => Promise.resolve(
      init?.method === 'POST'
        ? json({ error: { code: 'node_scheduling_permission_denied', message: 'private create denial' } }, 403)
        : json({ items: [group] }),
    ))
    const user = userEvent.setup()

    renderWithProviders(<>
      <NodeL2TopologyPage />
      <QueryClientCapture onCapture={(client) => { queryClient = client }} />
    </>, ['/node/l2-config?mode=advanced'])
    expect(await screen.findByText('华东 L2 线路')).toBeInTheDocument()
    await submitValidCreate(user, '权限拒绝新线路')
    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()
    expect(screen.queryByText('private create denial')).not.toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()

    act(() => useSessionStore.setState({
      accessToken: 'refreshed-denied-create-token',
      expiresAt: Date.now() + 60_000,
    }))
    await act(async () => {
      await queryClient.invalidateQueries({
        queryKey: ['node-l2-topology', 'tenant', tenantA, tenantA, userA, ownerEpoch],
      })
      window.dispatchEvent(new Event('focus'))
      window.dispatchEvent(new Event('online'))
      await Promise.resolve()
    })

    expect(screen.getByText('无权查看节点调度配置')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1)
    expect(fetchSpy.mock.calls.filter(([, init]) => !init?.method)).toHaveLength(1)
  })
})
