import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import userEvent from '@testing-library/user-event'

import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import { nodeMonitoringApi } from '../api/nodeMonitoring'
import { nodeInstallationTicketsApi } from '../api/nodeInstallationTickets'
import { useSessionStore } from '../auth/session'
import NodeListPage from '../pages/NodeListPage'
import { nodeUpdateRetryStorageKey, restoreNodeUpdateRetry } from '../pages/nodeUpdateRetryRecord'
import nodeListCSS from '../pages/NodeListPage.css?raw'
import nodeListSource from '../pages/NodeListPage.tsx?raw'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const scopeID = '22222222-2222-4222-8222-222222222222'
beforeEach(() => {
  sessionStorage.clear()
  // The bandwidth suite exercises the real batch adapter; CRUD tests keep
  // their existing fetch sequences scoped to inventory and writes.
  vi.spyOn(nodesApi, 'getLatestMetricsBatch').mockImplementation(async (_token, ids) => ({
    observed_at: '2026-10-10T10:00:00Z', items: [], not_reported_node_ids: [...ids],
  }))
  // The monitoring suite covers the real batch contract and owner isolation.
  vi.spyOn(nodeMonitoringApi, 'getLatest').mockImplementation(async (_token, ids) => ({
    schema_version: 1, observed_at: '2026-10-10T10:00:00Z',
    configuration: { state: 'unconfigured', head_revision: 0, active_revision: null, activated_at: null, policy: null },
    items: ids.map((node_id) => ({ node_id, sample: null, freshness: 'not_reported', revision_state: 'unknown', delivery_state: 'serving', stale_after_ms: null })),
  }))
  // The frozen tag reads service tickets (covered in the monitoring suite).
  vi.spyOn(nodeInstallationTicketsApi, 'get').mockImplementation(async (_token, ids) => ({
    observed_at: '2026-10-10T10:00:00Z',
    items: ids.map((node_id) => ({ node_id, state: 'unknown', issued_at: null, not_after: null, days_left: null, reported_at: null })),
  }))
})

const node: NodeInventoryItem = {
  id: '018f0000-0000-7000-8000-000000000001',
  display_id: '1',
  name: 'Edge Shanghai',
  description: 'primary edge',
  region: 'CN-East',
  ipv4: '192.0.2.10',
  ipv6: '2001:db8::10',
  admin_state: 'active',
  management_settings: {
    schema_version: 1,
    sort: 100,
    node_type: 'L1',
    cache_directory: '/www/server/cdnca/cache',
    cache_limit_gb: 500,
    log_directory: '/www/server/cdnca/logs',
    ip_location: { country: '中国', province: '上海', city: '上海', isp: '电信', country_code: 'CN' },
    auto_disable: {
      bandwidth_limit: 0,
      bandwidth_unit: 'Mbps',
      traffic_enabled: true,
      traffic_from_day: 1,
      traffic_from_time: '00:00:00',
      traffic_total_gb: 500,
      traffic_types: ['outbound'],
      excluded_interfaces: '',
      disabled_periods: '',
    },
    secondary_ips: [],
    external_probe: true,
  },
  revision: 4,
  created_at: '2026-07-22T08:00:00Z',
  updated_at: '2026-07-22T09:00:00Z',
  presence: {
    status: 'online',
    last_heartbeat_at: '2026-07-22T08:59:55Z',
    agent_version: '2.4.1',
    session_epoch: 7,
    heartbeat_sequence: 11,
    projection_freshness: 'fresh',
    lease_signal: 'present',
  },
}

function authenticate(
  permissions = ['nodes.read', 'nodes.manage', 'regions.read', 'regions.manage'],
  overrides: Parameters<typeof principal>[0] = {},
  accessToken = 'memory-only-access-token',
) {
  const admin = principal({
    scope_kind: 'platform',
    scope_id: scopeID,
    tenant_id: null,
    username: 'admin',
    display_name: 'admin',
    roles: ['platform_owner'],
    permissions,
    ...overrides,
  })
  useSessionStore.getState().setSession({ ...authResponse(admin), access_token: accessToken }, admin)
}

function json(body: unknown, status = 200, filters: { status?: string } = {}): Response {
  if (typeof body === 'object' && body !== null && 'items' in body && Array.isArray(body.items) &&
    body.items.every((item) => item && 'management_settings' in item && 'presence' in item)) {
    const items = [...body.items as NodeInventoryItem[]].sort((a, b) => b.management_settings.sort - a.management_settings.sort ||
      (BigInt(a.display_id) > BigInt(b.display_id) ? -1 : BigInt(a.display_id) < BigInt(b.display_id) ? 1 : b.id.localeCompare(a.id)))
    const last = items.at(-1)
    const next = 'next_cursor' in body && body.next_cursor !== undefined && last ? `nso1.${btoa(JSON.stringify({
      version: 1, scope_id: scopeID, order: 'management_sort_desc', status: filters.status ?? '', presence: '', search: '',
      last_sort: last.management_settings.sort, last_display_id: last.display_id, last_id: last.id,
    })).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')}` : undefined
    body = { ...body, order: 'management_sort_desc', items, ...(next ? { next_cursor: next } : {}) }
  }
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

async function chooseOpenOption(user: ReturnType<typeof userEvent.setup>, label: string) {
  const candidates = await screen.findAllByText(label)
  const option = candidates.find((candidate) => candidate.closest('.ant-select-item-option, .ant-dropdown-menu-item'))
  if (!option) throw new Error(`open option not found: ${label}`)
  await user.click(option)
}

async function openBatchAction(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: '更多操作' }))
  await user.click(await screen.findByRole('menuitem', { name: '批量状态' }))
}

async function openAdvancedRegistration(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: '更多操作' }))
  await user.click(await screen.findByRole('menuitem', { name: '高级注册' }))
  return screen.findByRole('dialog', { name: '添加节点' })
}

async function openRowAction(
  user: ReturnType<typeof userEvent.setup>,
  row: HTMLElement,
  action: string,
) {
  await user.click(within(row).getByRole('button', { name: '更多' }))
  await user.click(await screen.findByRole('menuitem', { name: action }))
}

async function openRowStatus(user: ReturnType<typeof userEvent.setup>, row: HTMLElement) {
  await user.click(within(row).getByRole('button', { name: '更多' }))
  const candidates = await screen.findAllByText('状态')
  const item = candidates.find((candidate) => candidate.closest('.ant-dropdown-menu-submenu-title, .ant-dropdown-menu-item'))
  if (!item) throw new Error('row status action not found')
  await user.click(item)
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise })
  return { promise, resolve }
}

function QueryClientCapture({ onCapture }: { onCapture: (client: QueryClient) => void }) {
  onCapture(useQueryClient())
  return null
}

async function submitNodeEdit(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: node.name }))
  const dialog = await screen.findByRole('dialog', { name: '编辑节点' })
  fireEvent.change(within(dialog).getByLabelText('排序'), { target: { value: '0' } })
  await user.click(within(dialog).getByRole('button', { name: '确定' }))
}

describe('node automatic IP status', function nodeNetworkStatusRegression() {
  it('shows the actual inventory IPs with independent family evidence and preserves zero sort', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [{ ...node,
      management_settings: { ...node.management_settings, sort: 0 },
      network_inventory: { schema_version: 1, ipv4_state: 'verified', ipv6_state: 'peer_mismatch', received_at: '2026-07-22T08:59:55Z' },
    }] }))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    const row = (await screen.findByRole('button', { name: node.name })).closest('tr')!
    expect(within(row).getByText(node.ipv4!)).toBeInTheDocument()
    expect(within(row).getByText(node.ipv6!)).toBeInTheDocument()
    expect(within(row).getByRole('cell', { name: '0' })).toBeInTheDocument()
    const ipv4 = within(row).getByRole('note', { name: 'IPv4：192.0.2.10；最近来源核验一致' })
    expect(within(row).getByRole('note', { name: 'IPv6：2001:db8::10；连接来源不一致' })).toBeInTheDocument()
    await user.hover(ipv4)
    const tooltip = await screen.findByRole('tooltip')
    expect(tooltip).toHaveTextContent('不代表 HTTP/HTTPS 等入站服务可达')
    expect(tooltip).toHaveTextContent('最近报告接收时间：')
    expect(tooltip).not.toHaveTextContent('peer_mismatch')
    expect(fetchSpy.mock.calls.every(([, init]) => !init?.method)).toBe(true)
  })

  it.each([
    ['legacy manual addresses', undefined, node.ipv4, node.ipv6, '自动上报状态未提供', '自动上报状态未提供'],
    ['manual addresses without a report', { schema_version: 1, ipv4_state: 'not_reported', ipv6_state: 'not_reported' }, node.ipv4, node.ipv6, '未自动上报', '未自动上报'],
    ['empty addresses', { schema_version: 1, ipv4_state: 'not_reported', ipv6_state: 'not_reported' }, undefined, undefined, '未自动上报', '未自动上报'],
    ['only IPv4', { schema_version: 1, ipv4_state: 'verified', ipv6_state: 'no_global_address', received_at: '2026-07-22T08:59:55Z' }, node.ipv4, undefined, '最近来源核验一致', '未发现公网候选'],
    ['only IPv6', { schema_version: 1, ipv4_state: 'no_default_route', ipv6_state: 'verified', received_at: '2026-07-22T08:59:55Z' }, undefined, node.ipv6, '未发现默认出口', '最近来源核验一致'],
    ['manual change after a report', { schema_version: 1, ipv4_state: 'address_conflict', ipv6_state: 'ambiguous_route', received_at: '2026-07-22T08:59:55Z' }, '192.0.2.99', node.ipv6, '当前 IP 与报告冲突', '默认出口不明确'],
  ])('does not invent verification or an IP for %s', async (_name, network_inventory, ipv4, ipv6, status4, status6) => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [{ ...node, ipv4, ipv6, network_inventory }] }))
    renderWithProviders(<NodeListPage />)
    const row = (await screen.findByRole('button', { name: node.name })).closest('tr')!
    const cell = row.querySelector('.node-addresses') as HTMLElement
    const notes = within(cell).getAllByRole('note')
    if (!ipv4 && !ipv6) {
      expect(notes).toHaveLength(1)
      expect(notes[0]).toHaveAccessibleName(`IPv4：—；${status4} IPv6：—；${status6}`)
      expect(cell).toHaveTextContent(/^—$/)
    } else {
      expect(notes.map((note) => note.getAttribute('aria-label'))).toEqual([
        ...(ipv4 ? [`IPv4：${ipv4}；${status4}`] : []), ...(ipv6 ? [`IPv6：${ipv6}；${status6}`] : []),
      ])
      expect(cell).toHaveTextContent([ipv4, ipv6].filter(Boolean).join(''))
    }
    for (const status of [status4, status6]) expect(cell).not.toHaveTextContent(status)
    expect(row).not.toHaveTextContent('0.0.0.0')
    expect(row).not.toHaveTextContent('undefined')
  })

  it('explains automatic default-egress detection instead of requiring a manual installation IP', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [node] }))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await screen.findByRole('button', { name: node.name })
    await user.click(screen.getByRole('button', { name: '安装节点' }))
    const dialog = await screen.findByRole('dialog', { name: '安装节点' })
    expect(dialog).toHaveTextContent('默认出口')
    expect(dialog).toHaveTextContent('不会覆盖已有 IP')
    expect(dialog).toHaveTextContent('不代表入站服务可达')
    expect(dialog).not.toHaveTextContent('补全实际 IP')
    expect(fetchSpy.mock.calls.every(([, init]) => !init?.method)).toBe(true)
  })
})

describe('node update safety', function nodeUpdateSafetyRegression() {
  it.each([-1, 0.5])('rejects non-contract sort %s in the form before storing or sending a request', async (sort) => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [node] }))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await user.click(await screen.findByRole('button', { name: node.name }))
    const dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    fireEvent.change(within(dialog).getByLabelText('排序'), { target: { value: String(sort) } })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('排序须为 0 至 999999 的整数')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(0)
    expect(sessionStorage.length).toBe(0)
  })

  it('renders real zero sort and the default region without changing cursor order', async () => {
    authenticate()
    const second = { ...node, id: '018f0000-0000-7000-8000-000000000002', display_id: '2', name: 'Second Edge',
      region: '', management_settings: { ...node.management_settings, sort: 0 } }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [node, second], next_cursor: second.id }))
    renderWithProviders(<NodeListPage />)
    const firstRow = (await screen.findByRole('button', { name: node.name })).closest('tr')!
    const secondRow = screen.getByRole('button', { name: second.name }).closest('tr')!
    expect(within(firstRow).getByRole('cell', { name: '100' })).toBeInTheDocument()
    expect(within(secondRow).getByRole('cell', { name: '0' })).toBeInTheDocument()
    expect(within(secondRow).getByText('默认')).toBeInTheDocument()
    expect(screen.getAllByRole('row').slice(1).map((row) => row.querySelector('.node-list-name-link')?.textContent)).toEqual([node.name, second.name])
  })

  it.each([409, 422])('keeps the exact unknown request locked after a replay returns %s', async (status) => {
    authenticate()
    let writes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => Promise.resolve(init?.method === 'PATCH'
      ? (++writes === 1 ? json({ error: { code: 'unavailable' } }, 503) : json({ error: { code: 'version_conflict' } }, status))
      : json({ items: [node] })))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await submitNodeEdit(user)
    await user.click(await screen.findByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(writes).toBe(2))
    expect(await screen.findByRole('button', { name: '使用同一请求重试' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '安装节点' })).toBeDisabled()
    const calls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')
    expect(calls[1]![1]?.body).toBe(calls[0]![1]?.body)
    expect(new Headers(calls[1]![1]?.headers).get('Idempotency-Key')).toBe(new Headers(calls[0]![1]?.headers).get('Idempotency-Key'))
    expect(new Headers(calls[1]![1]?.headers).get('If-Match')).toBe('"4"')
  })

  it('treats a malformed successful write response as unknown and restores the same request in a new session epoch and QueryClient', async () => {
    authenticate()
    let writes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => Promise.resolve(init?.method === 'PATCH'
      ? (++writes === 1 ? json({ id: node.id }) : json({ error: { code: 'unavailable' } }, 503))
      : json({ items: [node] })))
    const user = userEvent.setup({ delay: null })
    const view = renderWithProviders(<NodeListPage />)
    await submitNodeEdit(user)
    expect(await screen.findByRole('button', { name: '使用同一请求重试' })).toBeInTheDocument()
    view.unmount()
    authenticate(undefined, {}, 'renewed-owner-token')
    renderWithProviders(<NodeListPage />)
    await screen.findByRole('button', { name: node.name })
    expect(writes).toBe(1)
    await user.click(await screen.findByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(writes).toBe(2))
    const calls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')
    expect(calls[1]![1]?.body).toBe(calls[0]![1]?.body)
    const original = new Headers(calls[0]![1]?.headers)
    const retried = new Headers(calls[1]![1]?.headers)
    expect(retried.get('Idempotency-Key')).toBe(original.get('Idempotency-Key'))
    expect(retried.get('If-Match')).toBe(original.get('If-Match'))
    expect(retried.get('Authorization')).toBe('Bearer renewed-owner-token')
    expect(JSON.stringify(Object.values(sessionStorage))).not.toContain('renewed-owner-token')
  })

  it('stops before PATCH when durable storage fails', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [node] }))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await screen.findByRole('button', { name: node.name })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('quota') })
    await submitNodeEdit(user)
    expect(await screen.findByText('节点编辑恢复记录不可用')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(0)
    expect(screen.getByRole('button', { name: '安装节点' })).toBeDisabled()
  })

  it('restores a confirmed write as GET-only readback and does not report success until the fresh reads succeed', async () => {
    authenticate()
    let writes = 0
    let failReads = false
    const saved = { ...node, revision: 5, management_settings: { ...node.management_settings, sort: 0 } }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (init?.method === 'PATCH') {
        writes += 1
        failReads = true
        return Promise.resolve(json({ ...saved, presence: undefined }))
      }
      if (failReads) return Promise.resolve(json({ error: { code: 'unavailable' } }, 503))
      return Promise.resolve(json(String(input) === `/v1/nodes/${node.id}` ? saved : { items: [writes ? saved : node] }))
    })
    const user = userEvent.setup({ delay: null })
    const view = renderWithProviders(<NodeListPage />)
    await submitNodeEdit(user)
    expect(await screen.findByText('节点修改已保存，回读待确认')).toBeInTheDocument()
    expect(screen.queryByText('节点信息已更新')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    view.unmount()
    renderWithProviders(<NodeListPage />)
    await screen.findByText('节点修改已保存，回读待确认')
    expect(writes).toBe(1)
    failReads = false
    await user.click(screen.getByRole('button', { name: '仅重试回读' }))
    expect(await screen.findByText('节点信息已更新')).toBeInTheDocument()
    expect(writes).toBe(1)
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1)
    expect(within(screen.getByRole('button', { name: node.name }).closest('tr')!).getByRole('cell', { name: '0' })).toBeInTheDocument()
  })

  it('keeps a confirmed write read-only when the item GET succeeds but the list GET fails', async () => {
    authenticate()
    const saved = { ...node, revision: 5, management_settings: { ...node.management_settings, sort: 0 } }
    let written = false
    let failList = true
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (init?.method === 'PATCH') {
        written = true
        return Promise.resolve(json({ ...saved, presence: undefined }))
      }
      if (String(input) === `/v1/nodes/${node.id}`) return Promise.resolve(json(saved))
      return Promise.resolve(written && failList ? json({ error: { code: 'unavailable' } }, 503) : json({ items: [written ? saved : node] }))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await submitNodeEdit(user)
    await screen.findByText('节点修改已保存，回读待确认')
    expect(await screen.findByText('节点列表加载失败')).toBeInTheDocument()
    expect(screen.queryByText('节点信息已更新')).not.toBeInTheDocument()
    failList = false
    await user.click(screen.getByRole('button', { name: '仅重试回读' }))
    await screen.findByText('节点信息已更新')
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1)
  })

  it('rejects a readback revision older than the acknowledged write', async () => {
    authenticate()
    let revision = 4
    const saved = { ...node, revision: 5, management_settings: { ...node.management_settings, sort: 0 } }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => Promise.resolve(init?.method === 'PATCH'
      ? json({ ...saved, presence: undefined })
      : String(input) === `/v1/nodes/${node.id}` ? json({ ...saved, revision }) : json({ items: [revision === 5 ? saved : node] })))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await submitNodeEdit(user)
    await screen.findByText('节点修改已保存，回读待确认')
    expect(screen.queryByText('节点信息已更新')).not.toBeInTheDocument()
    revision = 5
    await user.click(screen.getByRole('button', { name: '仅重试回读' }))
    await screen.findByText('节点信息已更新')
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1)
  })

  it('preserves unknown recovery data without exposing or replaying it for another owner or a revoked writer', async () => {
    authenticate()
    const original = useSessionStore.getState().principal!
    const pending = deferred<Response>()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => init?.method === 'PATCH'
      ? pending.promise : Promise.resolve(json({ items: [node] })))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await submitNodeEdit(user)
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(true))
    act(() => authenticate(undefined, { user_id: '44444444-4444-4444-8444-444444444444' }, 'other-owner-token'))
    await screen.findByRole('button', { name: node.name })
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    await act(async () => pending.resolve(json({ ...node, presence: undefined, revision: 5 })))
    expect(screen.queryByText('节点信息已更新')).not.toBeInTheDocument()
    expect(restoreNodeUpdateRetry(['platform', scopeID, original.user_id]).record?.phase).toBe('unknown')
    act(() => authenticate(['nodes.read'], { user_id: original.user_id }, 'read-only-token'))
    expect(await screen.findByRole('button', { name: '使用同一请求重试' })).toBeDisabled()
    act(() => useSessionStore.setState({ accessToken: 'refreshed-read-only-token' }))
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1)
    const stored = sessionStorage.getItem(nodeUpdateRetryStorageKey(['platform', scopeID, original.user_id]))!
    expect(stored).not.toContain('token')
    expect(stored).not.toContain('ownerKey')
  })

  it('fences an in-flight update immediately after a list 403 and retains its recovery record', async () => {
    authenticate()
    const owner = useSessionStore.getState().principal!
    const pending = deferred<Response>()
    let reads = 0
    let client!: QueryClient
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => init?.method === 'PATCH'
      ? pending.promise : Promise.resolve(++reads === 1 ? json({ items: [node] }) : json({ error: { code: 'permission_denied' } }, 403)))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<><NodeListPage /><QueryClientCapture onCapture={(value) => { client = value }} /></>)
    await submitNodeEdit(user)
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(true))
    await act(async () => { await client.invalidateQueries({ queryKey: ['nodes'] }) })
    await screen.findByText('无权查看节点列表')
    await act(async () => pending.resolve(json({ ...node, presence: undefined, revision: 5 })))
    expect(screen.queryByText('节点信息已更新')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '仅重试回读' })).not.toBeInTheDocument()
    expect(restoreNodeUpdateRetry(['platform', scopeID, owner.user_id]).record?.phase).toBe('unknown')
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1)
  })

  it('blocks corrupted stored recovery data without sending a new write or erasing evidence', async () => {
    authenticate()
    const owner = useSessionStore.getState().principal!
    const key = nodeUpdateRetryStorageKey(['platform', scopeID, owner.user_id])
    sessionStorage.setItem(key, '{')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [node] }))
    renderWithProviders(<NodeListPage />)
    await screen.findByRole('button', { name: node.name })
    expect(screen.getByText('节点编辑恢复记录不可用')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '安装节点' })).toBeDisabled()
    expect(fetchSpy.mock.calls.every(([, init]) => !init?.method)).toBe(true)
    expect(sessionStorage.getItem(key)).toBe('{')
  })
})

describe('NodeListPage', () => {
  it('does not query or expose management controls without nodes.read', async () => {
    authenticate([])
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<NodeListPage />)

    expect(await screen.findByText('无权查看节点列表')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '安装节点' })).not.toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['tenant scope', { scope_kind: 'tenant' as const, tenant_id: '22222222-2222-4222-8222-222222222222' }],
    ['platform scope carrying a tenant', { tenant_id: '22222222-2222-4222-8222-222222222222' }],
    ['missing scope ID', { scope_id: '' }],
    ['missing user ID', { user_id: '' }],
  ])('fails closed with zero requests for %s', async (_caseName, overrides) => {
    authenticate(['nodes.read', 'nodes.manage'], overrides)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<NodeListPage />)

    expect(await screen.findByText('无权查看节点列表')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('fails closed for a zero session epoch but accepts the platform admin wildcard', async () => {
    authenticate(['nodes.read'])
    useSessionStore.setState({ sessionEpoch: 0 })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [node] }))
    const view = renderWithProviders(<NodeListPage />)

    expect(await screen.findByText('无权查看节点列表')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()

    view.unmount()
    authenticate(['platform.admin'])
    renderWithProviders(<NodeListPage />)
    const row = (await screen.findByText('Edge Shanghai')).closest('tr')!
    expect(within(row).getByLabelText(node.display_id)).toHaveTextContent(node.display_id)
    expect(within(row).queryByText(node.id)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '安装节点' })).toBeInTheDocument()
  })

  it('keeps the table mounted while loading and when the inventory is empty', async () => {
    authenticate()
    let resolveList!: (response: Response) => void
    vi.spyOn(globalThis, 'fetch').mockReturnValue(new Promise((resolve) => { resolveList = resolve }))

    renderWithProviders(<NodeListPage />, ['/node/list'])

    const table = screen.getByTestId('node-table-scroll')
    expect(table).toHaveAttribute('aria-busy', 'true')
    await act(async () => { resolveList(json({ items: [] })) })
    expect(await screen.findByText('暂无节点')).toBeInTheDocument()
    expect(table).toBeInTheDocument()
    expect(table).toHaveAttribute('aria-busy', 'false')
  })

  it('keeps the observed node-list tabs and baseline table headings', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<NodeListPage />, ['/node/list'])

    expect(screen.getByRole('heading', { name: '节点管理' })).toBeInTheDocument()
    expect(await screen.findAllByRole('tab')).toHaveLength(4)
    expect(screen.getByRole('tab', { name: '节点列表', selected: true })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '待初始化' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '同步失败已禁用' })).not.toHaveAttribute('aria-disabled', 'true')
    expect(screen.getByRole('tab', { name: '区域管理' })).not.toHaveAttribute('aria-disabled', 'true')
    for (const heading of ['ID', '名称', '区域', '节点IP', '监控', '带宽', '状态', '备注', '排序']) {
      expect(screen.getByRole('columnheader', { name: heading })).toBeInTheDocument()
    }
    expect(screen.getByRole('columnheader', { name: /^月流量/ })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '操作' })).not.toHaveClass('ant-table-cell-fix-right')
    const installButton = screen.getByRole('button', { name: '安装节点' })
    expect(installButton).toHaveTextContent('安装节点')
    expect(installButton.querySelector('svg')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '禁用节点' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '启用节点' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '更多操作' })).toBeInTheDocument()
    // 节点列表筛选行没有「清除」。
    expect(screen.queryByRole('button', { name: '清除' })).not.toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '每页节点数' }).closest('.ant-select')).toHaveTextContent('10 条/页')

    await user.click(installButton)
    const installDialog = await screen.findByRole('dialog', { name: '安装节点' })
    expect(within(installDialog).getByRole('heading', { name: '1. 执行命令' })).toBeInTheDocument()
    // 注册凭据读取完成前按钮处于 loading（可访问名带 loading），等它就绪。
    expect(await within(installDialog).findByRole('button', { name: '复制安装命令' })).toBeInTheDocument()
    expect(within(installDialog).queryByRole('link', { name: '打开维护升级' })).not.toBeInTheDocument()
    expect(within(installDialog).queryByRole('combobox')).not.toBeInTheDocument()
    expect(within(installDialog).getByRole('heading', { name: '2. 节点初始化' })).toBeInTheDocument()
    // NET-UX-6: one short step line; the IP details fold away.
    expect(within(installDialog).getByText(/点击「初始化」才会上线、同步配置并加入 DNS 解析/)).toBeInTheDocument()
    expect(within(installDialog).getByText('节点 IP 如何确定').closest('details')).not.toHaveAttribute('open')
    expect(installDialog.querySelector('.ant-modal-footer')).not.toBeInTheDocument()
    await user.click(installDialog.querySelector('.ant-modal-close')!)

    await user.click(screen.getByRole('combobox', { name: '筛选节点状态' }))
    const statusPopup = document.querySelector('.node-status-popup')
    expect(statusPopup).toHaveClass('node-select-popup')
    const statusOptions = within(statusPopup as HTMLElement).getAllByRole('option').map((option) => option.textContent)
    expect(statusOptions).toEqual(['待注册', '已启用', '排空中', '已禁用'])

    const mobileCSS = nodeListCSS.slice(nodeListCSS.indexOf('@media (max-width: 767px)'))
    expect(mobileCSS).toMatch(/\.node-page\s*\{[\s\S]*?padding:\s*18px 20px 20px;/)
    expect(mobileCSS).toMatch(/\.node-toolbar-filters\s*\{[\s\S]*?min-width:\s*0;[\s\S]*?justify-content:\s*flex-start;/)
    expect(mobileCSS).toMatch(/\.node-toolbar-filters > \.ant-select,[\s\S]*?width:\s*200px;[\s\S]*?flex:\s*0 0 200px;/)
    expect(mobileCSS).toMatch(/\.node-search\s*\{[\s\S]*?width:\s*170px;[\s\S]*?flex-basis:\s*170px;/)
    expect(nodeListCSS).toMatch(/\.node-tabs \.ant-tabs-tab \+ \.ant-tabs-tab\s*\{[\s\S]*?margin-left:\s*0 !important;/)
    expect(mobileCSS).toMatch(/\.node-tabs \.ant-tabs-nav-operations\s*\{[\s\S]*?display:\s*none !important;/)
    expect(mobileCSS).toMatch(/\.node-install-modal\s*\{[\s\S]*?top:\s*100px;[\s\S]*?width:\s*calc\(100% - 20px\) !important;/)
    expect(mobileCSS).toMatch(/\.node-install-command \.ant-input\s*\{[\s\S]*?min-height:\s*328px;/)
    expect(nodeListCSS).toMatch(/\.node-list-bandwidth-control > \.ant-select \.ant-select-selector\s*\{[\s\S]*?overflow:\s*hidden;/)
    expect(nodeListCSS).toMatch(/\.node-list-bandwidth-control > \.ant-select\s*\{[\s\S]*?min-width:\s*0;/)
    expect(mobileCSS).toMatch(/\.node-list-auto-disable-form \.ant-form-item-row\s*\{[\s\S]*?flex-direction:\s*column;/)
    expect(mobileCSS).toMatch(/\.node-list-auto-disable-form \.ant-form-item-control\s*\{[\s\S]*?width:\s*100%;[\s\S]*?max-width:\s*100%;/)
    expect(mobileCSS).toMatch(/\.node-list-auto-disable-form \.node-list-form-actions\s*\{[\s\S]*?margin-left:\s*0;/)
    expect(nodeListCSS).toMatch(/\.node-dropdown-popup \.ant-dropdown-menu\s*\{[\s\S]*?min-width:\s*116px;[\s\S]*?padding:\s*0;/)
    expect(nodeListCSS).toMatch(/\.node-batch-dropdown-popup \.ant-dropdown-menu\s*\{[\s\S]*?width:\s*116px;[\s\S]*?max-height:\s*170px;[\s\S]*?overflow-y:\s*auto;[\s\S]*?scrollbar-width:\s*none;/)
    expect(nodeListCSS).toMatch(/\.node-batch-dropdown-popup \.ant-dropdown-menu::-webkit-scrollbar\s*\{[\s\S]*?display:\s*none;/)
    expect(nodeListCSS).toMatch(/\.node-dropdown-popup \.ant-dropdown-menu-item,[\s\S]*?min-height:\s*34px !important;[\s\S]*?padding:\s*7px 16px !important;[\s\S]*?line-height:\s*20px !important;[\s\S]*?white-space:\s*nowrap;/)
    expect(nodeListSource).toContain('align={{ offset: [-5, 10] }}')
  })

  it('keeps the wide desktop toolbar on one unshrunk row and wraps complete groups below 1700px', () => {
    const desktopCSS = nodeListCSS.slice(0, nodeListCSS.indexOf('@media (max-width: 1699px)'))
    const compactDesktopCSS = nodeListCSS.slice(
      nodeListCSS.indexOf('@media (max-width: 1699px)'),
      nodeListCSS.indexOf('.node-search .ant-input-affix-wrapper'),
    )

    expect(desktopCSS).toMatch(/\.node-toolbar\s*\{[\s\S]*?flex-wrap:\s*nowrap;/)
    expect(desktopCSS).toMatch(/\.node-toolbar-actions,[\s\S]*?\.node-toolbar-filters\s*\{[\s\S]*?flex:\s*0 0 auto;[\s\S]*?width:\s*auto;/)
    expect(desktopCSS).toMatch(/\.node-toolbar-filters\s*\{[\s\S]*?min-width:\s*max-content;[\s\S]*?justify-content:\s*flex-end;[\s\S]*?margin-left:\s*auto;/)
    expect(nodeListCSS).toMatch(/\.node-toolbar-filters > \.ant-select\s*\{[\s\S]*?flex:\s*0 0 200px;/)
    expect(nodeListCSS).toMatch(/\.node-search\s*\{[\s\S]*?flex:\s*0 0 220px;/)
    expect(nodeListCSS).not.toContain('flex: 1 1 680px')
    expect(compactDesktopCSS).toMatch(/\.node-toolbar\s*\{[\s\S]*?flex-wrap:\s*wrap;/)
    expect(compactDesktopCSS).toMatch(/\.node-toolbar-actions,[\s\S]*?\.node-toolbar-filters\s*\{[\s\S]*?flex-basis:\s*100%;[\s\S]*?width:\s*100%;/)
    expect(compactDesktopCSS).toMatch(/\.node-toolbar-filters\s*\{[\s\S]*?justify-content:\s*flex-start;[\s\S]*?margin-left:\s*0;/)
    // 1330px 只由 scroll.x 给出，CSS min-width 会把外层撑出第二条滚动条。
    expect(nodeListCSS).not.toMatch(/\.node-table-scroll \.ant-table\s*\{[^}]*min-width:\s*1330px;/)
    expect(nodeListSource).toContain("title: t('columns.region'), dataIndex: 'region', width: 140")
    expect(nodeListSource).toContain("scroll={{ x: nodeTab === 'list' ? 1330 : nodeTab === 'pending' ? 630 : 580 }}")
  })

  it('renders every observed node status and the real empty region catalog', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(
      String(input).startsWith('/v1/regions') ? json({ count: 0, data: [] }) : json({ items: [] }),
    ))
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<NodeListPage />, ['/node/list'])
    await screen.findByText('暂无节点')

    await user.click(screen.getByRole('tab', { name: '待初始化' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledWith('/v1/nodes?limit=10&order=management_sort_desc&status=pending', expect.anything()))
    expect(screen.getByRole('button', { name: '刷新' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '删除' })).toBeDisabled()
    for (const heading of ['ID', '节点IP', '添加时间', '操作']) {
      expect(screen.getByRole('columnheader', { name: heading })).toBeInTheDocument()
    }
    expect(screen.getByText('暂无待初始化节点')).toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: '同步失败已禁用' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledWith('/v1/nodes?limit=10&order=management_sort_desc&status=disabled', expect.anything()))
    for (const heading of ['ID', '名称', '备注', '禁用时间', '操作']) {
      expect(screen.getByRole('columnheader', { name: heading })).toBeInTheDocument()
    }
    expect(screen.getByText('暂无同步失败已禁用节点')).toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: '区域管理' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledWith(
      '/v1/regions?page=1&page_size=10',
      expect.anything(),
    ))
    expect(screen.getByRole('button', { name: '新增区域' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '删除' })).toBeDisabled()
    for (const heading of ['ID', '名称', '备注', '排序', '添加时间', '操作']) {
      expect(screen.getByRole('columnheader', { name: heading })).toBeInTheDocument()
    }
    expect(screen.getByText('暂无区域')).toBeInTheDocument()
    expect(screen.getByText('共 0 条')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '新增区域' }))
    const dialog = await screen.findByRole('dialog', { name: '新增区域' })
    expect(within(dialog).getByPlaceholderText('请输入区域名称')).toBeInTheDocument()
    expect(within(dialog).getByPlaceholderText('请输入备注')).toBeInTheDocument()
    expect(within(dialog).getByRole('spinbutton', { name: 'L2检查端口' })).toHaveValue('80')
    expect(within(dialog).getByRole('spinbutton', { name: '排序' })).toHaveValue('100')
    expect(within(dialog).getByText('该端口用于在L1边缘节点检查L2节点是否在线')).toBeInTheDocument()
    expect(dialog.querySelector('.node-region-warning')).toHaveTextContent('注意：建议所有节点归属在同一个区域，')
    expect(within(dialog).getByRole('button', { name: '确定' })).toBeEnabled()
  })

  it('initializes a self-registered pending node and keeps replacement on the enrollment-token path', async () => {
    authenticate()
    const pendingNode = { ...node, id: '018f0000-0000-7000-8000-000000000009', display_id: '9', name: 'Pending Edge', admin_state: 'pending' as const }
    const tokenBodies: Array<{ purpose: string; ttl_seconds: number }> = []
    const patches: Array<{ body: unknown; ifMatch: string | null }> = []
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.includes('status=pending')) return Promise.resolve(json({ items: [pendingNode] }))
      if (url.endsWith(`/v1/nodes/${pendingNode.id}`) && init?.method === 'PATCH') {
        patches.push({ body: JSON.parse(String(init.body)), ifMatch: new Headers(init.headers).get('If-Match') })
        return Promise.resolve(json({ ...pendingNode, admin_state: 'active', revision: pendingNode.revision + 1 }))
      }
      if (url.endsWith('/enrollment-tokens') && init?.method === 'POST') {
        tokenBodies.push(JSON.parse(String(init.body)) as { purpose: string; ttl_seconds: number })
        return Promise.resolve(json({
          id: '018f0000-0000-7000-8000-000000000010', node_id: pendingNode.id, purpose: tokenBodies.at(-1)!.purpose,
          created_at: '2026-07-22T09:00:00Z', expires_at: '2026-07-22T09:10:00Z', token: 'P'.repeat(43),
        }, 201))
      }
      return Promise.resolve(json({ items: [] }))
    })
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<NodeListPage />, ['/node/list'])
    await screen.findByText('暂无节点')
    await user.click(screen.getByRole('tab', { name: '待初始化' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).includes('status=pending'))).toBe(true))
    const row = await screen.findByRole('button', { name: '初始化' }).then((element) => element.closest('tr')!)

    await user.click(within(row).getByRole('button', { name: '替换节点' }))
    await user.click(within(await screen.findByRole('dialog', { name: '签发注册令牌' })).getByRole('button', { name: '签发' }))
    await screen.findByRole('dialog', { name: '注册令牌（仅显示一次）' })
    expect(tokenBodies).toEqual([{ purpose: 're_enrollment', ttl_seconds: 600 }])
    expect(fetchSpy.mock.calls.filter(([url, init]) => String(url).endsWith('/enrollment-tokens') && init?.method === 'POST')).toHaveLength(1)
    await user.click(screen.getByRole('button', { name: '我已保存' }))

    // Initialize = pending -> active after the node registered itself; no token.
    await user.click(within(row).getByRole('button', { name: '初始化' }))
    const confirm = await screen.findByRole('dialog', { name: '初始化节点 Pending Edge？' })
    expect(confirm).toHaveTextContent('开始同步系统与网站配置')
    await user.click(within(confirm).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(patches).toEqual([{ body: { admin_state: 'active' }, ifMatch: `"${pendingNode.revision}"` }]))
  })

  it('localizes list failures, hides server messages, and retries in the same table shell', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ error: { code: 'request_failed', message: 'private node topology' } }, 503))
      .mockResolvedValueOnce(json({ items: [] }))
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<NodeListPage />, ['/node/list'])

    expect(await screen.findByText('节点列表加载失败')).toBeInTheDocument()
    expect(screen.getByText('请求失败，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('private node topology')).not.toBeInTheDocument()
    expect(screen.getByTestId('node-table-scroll')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无节点')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('gives the current-page node search a stable DOM identifier', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [node] }))
    renderWithProviders(<NodeListPage />, ['/node/list'])

    await screen.findByRole('button', { name: node.name })
    const input = screen.getByRole('textbox', { name: '搜索当前页节点' })
    expect(input.tagName).toBe('INPUT')
    expect(input).toHaveAttribute('id', 'node-list-search')
    expect(input).toHaveAttribute('placeholder', '填ID、IP或名称搜索')
    expect(document.querySelectorAll('#node-list-search')).toHaveLength(1)
  })

  it('uses server state and cursor filters while searching only the current page', async () => {
    authenticate()
    const nextID = node.id
    const secondID = '018f0000-0000-7000-8000-000000000002'
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      return Promise.resolve(json({
        items: url.includes('cursor=') ? [{ ...node, id: secondID, display_id: '2', name: 'Edge Beijing', management_settings: { ...node.management_settings, sort: 0 } }] : [node],
        next_cursor: url.includes('cursor=') ? undefined : nextID,
      }, 200, { status: new URL(url, 'https://test.invalid').searchParams.get('status') ?? '' }))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />, ['/node/list'])

    expect(await screen.findByText('Edge Shanghai')).toBeInTheDocument()
    await user.type(screen.getByLabelText('搜索当前页节点'), 'not-found')
    await user.click(screen.getByRole('button', { name: '查询' }))
    expect(screen.getByText('当前页无匹配节点')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url]) => String(url).includes('search='))).toHaveLength(0)

    await user.clear(screen.getByLabelText('搜索当前页节点'))
    await user.click(screen.getByRole('button', { name: '查询' }))
    await user.click(screen.getByRole('combobox', { name: '筛选节点状态' }))
    await chooseOpenOption(user, '已启用')
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledWith(
      '/v1/nodes?limit=10&order=management_sort_desc&status=active',
      expect.anything(),
    ))

    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('Edge Beijing')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.stringMatching(/^\/v1\/nodes\?limit=10&order=management_sort_desc&status=active&cursor=nso1\./),
      expect.anything(),
    )
  })

  it('filters regions locally without adding an unsupported query parameter', async () => {
    authenticate()
    const second = { ...node, id: '018f0000-0000-7000-8000-000000000002', display_id: '2', name: 'Edge Beijing', region: 'CN-North' }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [node, second] }))
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<NodeListPage />, ['/node/list'])

    expect(await screen.findByText('Edge Shanghai')).toBeInTheDocument()
    expect(screen.getByText('Edge Beijing')).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: '筛选节点区域' }))
    await chooseOpenOption(user, 'CN-North')

    expect(screen.queryByText('Edge Shanghai')).not.toBeInTheDocument()
    expect(screen.getByText('Edge Beijing')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(String(fetchSpy.mock.calls[0]?.[0])).toBe('/v1/nodes?limit=10&order=management_sort_desc')
  })

  it('keeps region, monitoring, and status cells compact while preserving diagnostics in details', async () => {
    authenticate(['nodes.read', 'nodes.manage', 'node_scheduling.read'])
    const offline = {
      ...node,
      id: '018f0000-0000-7000-8000-000000000002',
      display_id: '2',
      name: 'Offline Edge',
      presence: {
        status: 'offline' as const,
        last_heartbeat_at: '2026-07-22T08:58:00Z',
        projection_freshness: 'stale' as const,
        lease_signal: 'unavailable' as const,
      },
    }
    const unknown = {
      ...node,
      id: '018f0000-0000-7000-8000-000000000003',
      display_id: '3',
      name: 'Never Seen Edge',
      region: '',
      presence: {
        status: 'unknown' as const,
        projection_freshness: 'never' as const,
        lease_signal: 'absent' as const,
      },
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(
      String(input).startsWith('/v1/node-line-groups')
        ? json({ items: [] })
        : json({ items: [node, offline, unknown] }),
    ))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)

    const onlineRow = (await screen.findByText('Edge Shanghai')).closest('tr')!
    expect(within(onlineRow).getByText('CN-East')).toBeInTheDocument()
    expect(within(onlineRow).getByRole('link', { name: '线路组(0个)' })).toHaveAttribute('href', '/node/line-group')
    const onlineMonitor = onlineRow.querySelector('.node-monitor-cell') as HTMLElement
    expect(await within(onlineMonitor).findByRole('link', { name: '未配置' })).toHaveAttribute('href', '/node/monitor-setting')
    expect(onlineMonitor).toHaveAttribute('data-state', 'unconfigured')
    expect(onlineMonitor).toHaveAttribute('title', expect.stringContaining('未配置监控'))
    expect(within(onlineMonitor).queryByRole('link', { name: '[日志]' })).not.toBeInTheDocument()
    expect(onlineMonitor).not.toHaveAttribute('title', expect.stringContaining('在线'))
    expect(onlineRow.querySelector('.node-state-cell')).toHaveAttribute('title', expect.stringContaining('在线状态: 在线'))
    expect(onlineRow.querySelector('.node-state-cell')).toHaveAttribute('title', expect.stringContaining('投影新鲜'))
    expect(onlineRow.querySelector('.node-state-cell')).toHaveAttribute('title', expect.stringContaining('租约有效'))
    expect(onlineRow.querySelector('.node-state-cell')).toHaveAttribute('title', expect.stringContaining('2.4.1'))
    expect(onlineRow.querySelector('.node-state-cell')).toHaveAttribute('title', expect.stringContaining('e7 / #11'))
    expect(within(onlineRow).queryByText('投影新鲜 · 租约有效')).not.toBeInTheDocument()
    expect(within(onlineRow).queryByText('2.4.1')).not.toBeInTheDocument()
    expect(within(onlineRow).queryByText('e7 / #11')).not.toBeInTheDocument()
    expect(onlineRow).not.toHaveTextContent('r4')

    const offlineRow = screen.getByText('Offline Edge').closest('tr')!
    const offlineMonitor = offlineRow.querySelector('.node-monitor-cell') as HTMLElement
    expect(within(offlineMonitor).getByRole('link', { name: '未配置' })).toBeInTheDocument()
    expect(offlineMonitor).not.toHaveAttribute('title', expect.stringContaining('离线'))
    expect(offlineRow.querySelector('.node-state-cell')).toHaveAttribute('title', expect.stringContaining('在线状态: 离线'))
    expect(within(offlineRow).queryByText('投影过期 · 租约信号不可用')).not.toBeInTheDocument()

    const unknownRow = screen.getByText('Never Seen Edge').closest('tr')!
    expect(within(unknownRow.querySelector('.node-region-cell') as HTMLElement).getByText('默认')).toBeInTheDocument()
    const unknownMonitor = unknownRow.querySelector('.node-monitor-cell') as HTMLElement
    expect(within(unknownMonitor).getByRole('link', { name: '未配置' })).toBeInTheDocument()
    expect(unknownMonitor).not.toHaveAttribute('title', expect.stringContaining('未知'))
    expect(unknownRow.querySelector('.node-state-cell')).toHaveAttribute('title', expect.stringContaining('在线状态: 未知'))
    expect(within(unknownRow).queryByText('从未上报 · 租约缺失')).not.toBeInTheDocument()

    await user.click(screen.getByRole('combobox', { name: '筛选在线状态' }))
    await chooseOpenOption(user, '在线')
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledWith(
      '/v1/nodes?limit=10&order=management_sort_desc&presence=online',
      expect.anything(),
    ))
  })

  it('opens the baseline editor read-only and keeps the advanced detail as an explicit link', async () => {
    authenticate(['nodes.read'])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [node] }))
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<NodeListPage />, ['/node/list'])

    const row = (await screen.findByText(node.name)).closest('tr')!
    expect(within(row).queryByRole('link', { name: '线路组' })).not.toBeInTheDocument()
    expect(within(row).getByRole('link', { name: '高级详情' }))
      .toHaveAttribute('href', `/node/list/${node.id}`)
    await user.click(within(row).getByRole('button', { name: '管理' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    expect(within(dialog).getByRole('button', { name: '确定' })).toBeDisabled()
    expect(within(row).queryByRole('button', { name: '编辑' })).not.toBeInTheDocument()
    expect(within(row).queryByRole('button', { name: '令牌' })).not.toBeInTheDocument()
  })

  it('matches the five-tab editor and persists every executable tab through the node update contract', async () => {
    authenticate()
    const writes: Array<Record<string, unknown>> = []
    let current = node
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (String(input) === `/v1/nodes/${node.id}` && init?.method === 'PATCH') {
        writes.push(JSON.parse(String(init.body)) as Record<string, unknown>)
        current = { ...current, ...writes.at(-1), revision: current.revision + 1 }
        return Promise.resolve(json({ ...current, presence: undefined }))
      }
      return Promise.resolve(json(String(input) === `/v1/nodes/${node.id}` ? current : { items: [current] }))
    })
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<NodeListPage />, ['/node/list'])

    const nameButton = await screen.findByRole('button', { name: node.name })
    const row = nameButton.closest('tr')!
    await user.click(nameButton)
    let dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    expect(dialog.closest('.ant-modal')).toHaveStyle({ width: '520px' })
    expect(within(dialog).getAllByRole('tab').map((tab) => tab.textContent)).toEqual([
      '基本设置', '节点设置', 'IP归属', '自动禁用', '添加子IP',
    ])
    expect(within(dialog).getByLabelText('名称')).toHaveValue(node.name)
    expect(within(dialog).getByLabelText('备注')).toHaveValue(node.description)
    // Each address family has its own field (NET-09).
    expect(within(dialog).getByLabelText('IPv4')).toHaveValue(node.ipv4)
    expect(within(dialog).getByLabelText('IPv6')).toHaveValue(node.ipv6)
    await user.type(within(dialog).getByLabelText('IPv4'), '{selectall}2001:db8::99')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('请输入有效的 IPv4 地址')).toBeInTheDocument()
    expect(writes).toHaveLength(0)
    await user.clear(within(dialog).getByLabelText('IPv4'))
    await user.type(within(dialog).getByLabelText('IPv4'), node.ipv4!)
    await user.clear(within(dialog).getByLabelText('IPv6'))
    await user.type(within(dialog).getByLabelText('IPv6'), '2001:db8::20')
    expect(within(dialog).getByLabelText('排序')).toHaveValue('100')
    expect(within(dialog).getByRole('radio', { name: 'L1边缘节点' })).toBeChecked()
    expect(within(dialog).getByRole('radio', { name: 'L2中间节点' })).not.toBeChecked()
    expect(within(dialog).getByText('如果新旧IP是不同节点，请使用待初始化里的替换节点功能')).toBeInTheDocument()
    expect(within(dialog).queryByRole('link', { name: '高级详情' })).not.toBeInTheDocument()
    // 类型说明指向 L2 配置页的说明卡
    expect(within(dialog).getByRole('link', { name: 'L2 是什么、怎么配置' })).toHaveAttribute('href', '/node/l2-config')
    await user.click(within(dialog).getByRole('radio', { name: 'L2中间节点' }))
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await screen.findByText('节点信息已更新')
    expect(writes.at(-1)).toMatchObject({ ipv4: node.ipv4, ipv6: '2001:db8::20', management_settings: { sort: 100, node_type: 'L2' } })

    await user.click(within(row).getByRole('button', { name: '管理' }))
    dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    await user.click(within(dialog).getByRole('tab', { name: '节点设置' }))
    expect(within(dialog).getByLabelText('缓存目录')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('缓存上限')).toBeInTheDocument()
    expect(within(dialog).getAllByText('GB')).toHaveLength(2)
    expect(within(dialog).getByLabelText('日志目录')).toBeInTheDocument()
    // A node whose agent does not declare NODE_STORAGE
    // (here its latest metrics cannot be read) stays read-only with the reason.
    expect(await within(dialog).findByText('该节点版本不支持在这里修改缓存目录、缓存上限和日志目录')).toBeInTheDocument()
    // #62: the reason is in user terms, without implementation details.
    expect(within(dialog).getByText(/请先把节点升级到 1.0.35 或更新版本/)).toBeInTheDocument()
    expect(within(dialog).queryByText(/ProtectSystem|systemd|NODE_STORAGE/)).not.toBeInTheDocument()
    expect(within(dialog).getByLabelText('缓存上限')).toBeDisabled()
    expect(within(dialog).getByLabelText('缓存目录')).toBeDisabled()
    expect(within(dialog).getByLabelText('日志目录')).toBeDisabled()
    expect(within(dialog).getByRole('button', { name: '确定' })).toBeDisabled()
    // C38/ND01: the read-only tab still closes.
    expect(within(dialog).getByRole('button', { name: '关闭' })).toBeEnabled()
    await user.click(within(dialog).getByRole('button', { name: '关闭' }))
    expect(writes).toHaveLength(1)

    await user.click(within(row).getByRole('button', { name: '管理' }))
    dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    await user.click(within(dialog).getByRole('tab', { name: 'IP归属' }))
    expect(within(dialog).getByText(/L2 配置里按节点国家代码、省份、城市、ISP 设置的条件/)).toBeInTheDocument()
    for (const field of ['国家', '省份/州', '城市', 'ISP', '国家码']) {
      expect(within(dialog).getByLabelText(field)).toBeInTheDocument()
    }
    await user.clear(within(dialog).getByLabelText('城市'))
    await user.type(within(dialog).getByLabelText('城市'), '杭州')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(writes).toHaveLength(2))
    expect(writes.at(-1)).toMatchObject({ management_settings: { ip_location: { city: '杭州' }, ip_location_manual: ['city'] } })

    await user.click(within(row).getByRole('button', { name: '管理' }))
    dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    await user.click(within(dialog).getByRole('tab', { name: '自动禁用' }))
    expect(within(dialog).getByRole('switch', { name: '流量限制' })).toBeChecked()
    expect(within(dialog).getByRole('checkbox', { name: '出站流量' })).toBeChecked()
    expect(within(dialog).getByRole('checkbox', { name: '入站流量' })).not.toBeChecked()
    const bandwidthUnit = within(dialog).getByRole('combobox', { name: '带宽限制' })
    expect(bandwidthUnit.closest('.ant-select')).toHaveTextContent('Mbps')
    await user.click(bandwidthUnit)
    const unitPopup = document.querySelector('.node-bandwidth-unit-popup') as HTMLElement
    expect(within(unitPopup).getAllByRole('option').map((option) => option.textContent)).toEqual(['Mbps', 'Gbps'])
    await user.click(within(unitPopup).getByRole('option', { name: 'Gbps' }))
    expect(bandwidthUnit.closest('.ant-select')).toHaveTextContent('Gbps')
    expect(within(dialog).getByDisplayValue('1')).toBeInTheDocument()
    expect(within(dialog).getByDisplayValue('00:00:00')).toBeInTheDocument()
    expect(dialog.querySelector('#node-list-traffic-total')).toHaveValue('500')
    expect(within(dialog).getByPlaceholderText('如eth0，多个网卡空格分隔')).toBeInTheDocument()
    expect(within(dialog).getByPlaceholderText(/格式为00:00:00-03:00:00/)).toBeInTheDocument()
    // Enforced through serving holds: editable, with how it takes effect.
    expect(within(dialog).getByText(/从线路分组的解析记录中移除/)).toBeInTheDocument()
    expect(within(dialog).getByRole('switch', { name: '流量限制' })).toBeEnabled()
    await user.clear(within(dialog).getByPlaceholderText(/格式为00:00:00-03:00:00/))
    await user.type(within(dialog).getByPlaceholderText(/格式为00:00:00-03:00:00/), '00:00:00-03:00:00')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(writes).toHaveLength(3))
    expect(writes.at(-1)).toMatchObject({ management_settings: { auto_disable: { disabled_periods: '00:00:00-03:00:00', bandwidth_limit: 0 } } })

    // A zero bandwidth limit means "no limit" and reads back as an empty field.
    await user.click(within(row).getByRole('button', { name: '管理' }))
    dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    await user.click(within(dialog).getByRole('tab', { name: '自动禁用' }))
    expect(within(dialog).getByPlaceholderText('留空不限制')).toHaveValue('')
    await user.type(within(dialog).getByPlaceholderText('留空不限制'), '800')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(writes).toHaveLength(4))
    expect(writes.at(-1)).toMatchObject({ management_settings: { auto_disable: { bandwidth_limit: 800 } } })
    await user.click(within(row).getByRole('button', { name: '管理' }))
    dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    await user.click(within(dialog).getByRole('tab', { name: '自动禁用' }))
    expect(within(dialog).getByPlaceholderText('留空不限制')).toHaveValue('800')
    await user.clear(within(dialog).getByPlaceholderText('留空不限制'))
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(writes).toHaveLength(5))
    expect(writes.at(-1)).toMatchObject({ management_settings: { auto_disable: { bandwidth_limit: 0 } } })

    await user.click(within(row).getByRole('button', { name: '管理' }))
    dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    await user.click(within(dialog).getByRole('tab', { name: '添加子IP' }))
    expect(within(dialog).getByLabelText('子IP')).toHaveAttribute('placeholder', '一行一个')
    await user.type(within(dialog).getByLabelText('子IP'), '198.51.100.10\n2001:db8::20')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(writes).toHaveLength(6))
    expect(writes.at(-1)).toMatchObject({ management_settings: { secondary_ips: ['198.51.100.10', '2001:db8::20'] } })
    expect((writes.at(-1) as { management_settings: Record<string, unknown> }).management_settings).not.toHaveProperty('schedule302_hostname')

    // 302 direct hostname: an IP is refused, a hostname is lower-cased.
    await user.click(within(row).getByRole('button', { name: '管理' }))
    dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    await user.click(within(dialog).getByRole('tab', { name: '添加子IP' }))
    const hostname = within(dialog).getByLabelText('302 直连域名')
    await user.type(hostname, '198.51.100.10')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('填写一个域名（不能是 IP）')).toBeInTheDocument()
    await user.clear(hostname)
    await user.type(hostname, 'Edge-01.CDNCA.com')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(writes).toHaveLength(7))
    expect(writes.at(-1)).toMatchObject({ management_settings: { schedule302_hostname: 'edge-01.cdnca.com' } })
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(7)
  }, 60_000)

  it('creates a pending node and displays its raw enrollment token only once', async () => {
    authenticate()
    const rawToken = 'T'.repeat(43)
    const created = { ...node, name: 'Edge Guangzhou', admin_state: 'pending' as const, revision: 1 }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url === '/v1/nodes' && init?.method === 'POST') {
        return Promise.resolve(json({
          node: created,
          enrollment_token: {
            id: '018f0000-0000-7000-8000-000000000010',
            node_id: created.id,
            purpose: 'initial_enrollment',
            created_at: '2026-07-22T09:00:00Z',
            expires_at: '2026-07-22T09:10:00Z',
            token: rawToken,
          },
        }, 201))
      }
      return Promise.resolve(json({ items: init?.method ? [] : [created] }))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await screen.findByText('Edge Guangzhou')

    const dialog = await openAdvancedRegistration(user)
    fireEvent.change(within(dialog).getByLabelText('节点名称'), { target: { value: 'Edge Guangzhou' } })
    await user.click(within(dialog).getByRole('button', { name: '保存' }))

    const tokenDialog = await screen.findByRole('dialog', { name: '注册令牌（仅显示一次）' })
    expect(within(tokenDialog).getByLabelText('一次性注册令牌')).toHaveValue(rawToken)
    const createCall = fetchSpy.mock.calls.find(([url, init]) => String(url) === '/v1/nodes' && init?.method === 'POST')
    expect(JSON.parse(String(createCall?.[1]?.body))).toEqual({
      name: 'Edge Guangzhou',
      issue_enrollment_token: true,
      enrollment_purpose: 'initial_enrollment',
      enrollment_token_ttl_seconds: 600,
    })
    expect(new Headers(createCall?.[1]?.headers).get('Idempotency-Key')).toMatch(/^create-node-/)

    await user.click(within(tokenDialog).getByRole('button', { name: '我已保存' }))
    await waitFor(() => expect(screen.queryByDisplayValue(rawToken)).not.toBeInTheDocument())
  })

  it('freezes an uncertain node creation and retries the exact request after token refresh', async () => {
    authenticate(undefined, {}, 'create-token-before-refresh')
    const created = { ...node, name: 'Edge Guangzhou', admin_state: 'pending' as const, revision: 1 }
    const rawToken = 'C'.repeat(43)
    let writes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url === '/v1/nodes' && init?.method === 'POST') {
        writes += 1
        if (writes === 1) return Promise.reject(new TypeError('connection reset'))
        return Promise.resolve(json({
          node: created,
          enrollment_token: {
            id: '018f0000-0000-7000-8000-000000000010', node_id: created.id,
            purpose: 'initial_enrollment', created_at: '2026-07-22T09:00:00Z',
            expires_at: '2026-07-22T09:10:00Z', token: rawToken,
          },
        }, 201))
      }
      return Promise.resolve(json({ items: writes > 1 ? [created] : [node] }))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await screen.findByText('Edge Shanghai')
    const dialog = await openAdvancedRegistration(user)
    fireEvent.change(within(dialog).getByLabelText('节点名称'), { target: { value: created.name } })
    await user.click(within(dialog).getByRole('button', { name: '保存' }))

    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '添加节点' })).not.toBeInTheDocument()
    act(() => useSessionStore.setState({ accessToken: 'create-token-after-refresh', expiresAt: Date.now() + 60_000 }))
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByRole('dialog', { name: '注册令牌（仅显示一次）' })).toBeInTheDocument()

    const calls = fetchSpy.mock.calls.filter(([url, init]) => String(url) === '/v1/nodes' && init?.method === 'POST')
    expect(calls).toHaveLength(2)
    expect(calls[1][1]?.body).toBe(calls[0][1]?.body)
    const firstHeaders = new Headers(calls[0][1]?.headers)
    const retryHeaders = new Headers(calls[1][1]?.headers)
    expect(firstHeaders.get('Authorization')).toBe('Bearer create-token-before-refresh')
    expect(retryHeaders.get('Authorization')).toBe('Bearer create-token-after-refresh')
    expect(retryHeaders.get('Idempotency-Key')).toBe(firstHeaders.get('Idempotency-Key'))
  })

  it('keys all node reads and writes by the complete owner without retaining access or enrollment tokens', async () => {
    const userID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
    const accessToken = 'cache-secret-access-token'
    const rawToken = 'R'.repeat(43)
    const second = { ...node, id: '018f0000-0000-7000-8000-000000000002', display_id: '2', name: 'Edge Beijing', admin_state: 'draining' as const }
    authenticate(undefined, { user_id: userID }, accessToken)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    let queryClient!: QueryClient
    let patchCalls = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url === '/v1/nodes' && init?.method === 'POST') return Promise.resolve(json({ node }, 201))
      if (url.endsWith('/enrollment-tokens') && init?.method === 'POST') return Promise.resolve(json({
        id: '018f0000-0000-7000-8000-000000000010', node_id: node.id, purpose: 're_enrollment',
        created_at: '2026-07-22T09:00:00Z', expires_at: '2026-07-22T09:10:00Z', token: rawToken,
      }, 201))
      if (url === `/v1/nodes/${node.id}` && init?.method === 'PATCH') {
        patchCalls += 1
        return patchCalls === 1
          ? Promise.reject(new TypeError('connection reset'))
          : Promise.resolve(json({ ...node, presence: undefined, revision: 5 }))
      }
      if (url === `/v1/nodes/${node.id}`) return Promise.resolve(json({ ...node, revision: 5 }))
      if (url === '/v1/nodes/batch-admin-state' && init?.method === 'POST') {
        return Promise.resolve(json({ items: [{ id: node.id, status: 'updated', node }] }))
      }
      return Promise.resolve(json({ items: [node, second] }))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<>
      <NodeListPage />
      <QueryClientCapture onCapture={(client) => { queryClient = client }} />
    </>)
    expect(await screen.findByText('Edge Beijing')).toBeInTheDocument()

    const createDialog = await openAdvancedRegistration(user)
    fireEvent.change(within(createDialog).getByLabelText('节点名称'), { target: { value: 'New Edge' } })
    await user.click(within(createDialog).getByRole('button', { name: '保存' }))
    await screen.findByText('节点已创建')

    const firstRow = screen.getByText('Edge Shanghai').closest('tr')!
    await openRowAction(user, firstRow, '令牌')
    await user.click(within(await screen.findByRole('dialog', { name: '签发注册令牌' })).getByRole('button', { name: '签发' }))
    const resultDialog = await screen.findByRole('dialog', { name: '注册令牌（仅显示一次）' })
    expect(within(resultDialog).getByLabelText('一次性注册令牌')).toHaveValue(rawToken)
    await user.click(within(resultDialog).getByRole('button', { name: '我已保存' }))

    await openRowAction(user, firstRow, '编辑')
    await user.click(within(await screen.findByRole('dialog', { name: '编辑节点' })).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await screen.findByText('节点信息已更新')

    await user.click(screen.getByRole('checkbox', { name: 'Edge Shanghai' }))
    await user.click(screen.getByRole('checkbox', { name: 'Edge Beijing' }))
    await openBatchAction(user)
    await user.click(within(await screen.findByRole('dialog', { name: '批量变更状态（2 个节点）' })).getByRole('button', { name: '确认变更' }))
    await screen.findByRole('dialog', { name: '批量操作结果' })

    const owner = ['platform', scopeID, null, userID, sessionEpoch]
    expect(queryClient.getQueryCache().getAll().some((entry) => owner.every((part, index) => entry.queryKey[index + 1] === part))).toBe(true)
    const mutationKeys = queryClient.getMutationCache().getAll().map((entry) => entry.options.mutationKey)
    for (const operation of ['create', 'token', 'update', 'batch']) {
      expect(mutationKeys).toContainEqual(['nodes-write', ...owner, operation])
    }
    const cacheState = JSON.stringify({
      queries: queryClient.getQueryCache().getAll().map((entry) => ({ key: entry.queryKey, state: entry.state })),
      mutations: queryClient.getMutationCache().getAll().map((entry) => ({ key: entry.options.mutationKey, state: entry.state })),
    })
    expect(cacheState).not.toContain(accessToken)
    expect(cacheState).not.toContain(rawToken)
    expect(fetchSpy).toHaveBeenCalled()
  })

  it('retries an unknown metadata update with the exact body, revision, and idempotency key', async () => {
    authenticate(undefined, {}, 'token-before-refresh')
    let writes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url === `/v1/nodes/${node.id}` && init?.method === 'PATCH') {
        writes += 1
        return writes === 1
          ? Promise.reject(new TypeError('connection reset'))
          : Promise.resolve(json({ ...node, presence: undefined, description: 'changed', revision: 5 }))
      }
      const current = writes >= 2 ? { ...node, description: 'changed', revision: 5 } : node
      return Promise.resolve(json(url === `/v1/nodes/${node.id}` ? current : { items: [current] }))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await screen.findByText('Edge Shanghai')

    await user.click(screen.getByRole('checkbox', { name: 'Edge Shanghai' }))
    await openRowAction(user, screen.getByText('Edge Shanghai').closest('tr')!, '编辑')
    const dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    const description = within(dialog).getByLabelText('备注')
    await user.clear(description)
    await user.type(description, 'changed')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '安装节点' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '更多' })).toBeDisabled()
    expect(screen.getByRole('checkbox', { name: 'Edge Shanghai' })).toBeDisabled()
    // 编辑弹窗已关闭；仅剩 OutcomeUnknown 的说明弹窗（它自带 ×）。
    expect(screen.queryAllByRole('button', { name: 'Close' }).filter((button) => !button.closest('.cdnca-feedback'))).toHaveLength(0)
    act(() => useSessionStore.setState({ accessToken: 'token-after-refresh', expiresAt: Date.now() + 60_000 }))
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('节点信息已更新')).toBeInTheDocument()

    const calls = fetchSpy.mock.calls.filter(([url, init]) => String(url) === `/v1/nodes/${node.id}` && init?.method === 'PATCH')
    expect(calls).toHaveLength(2)
    expect(calls[0][1]?.body).toBe(calls[1][1]?.body)
    const firstHeaders = new Headers(calls[0][1]?.headers)
    const retryHeaders = new Headers(calls[1][1]?.headers)
    expect(firstHeaders.get('Authorization')).toBe('Bearer token-before-refresh')
    expect(retryHeaders.get('Authorization')).toBe('Bearer token-after-refresh')
    expect(retryHeaders.get('If-Match')).toBe(firstHeaders.get('If-Match'))
    expect(retryHeaders.get('Idempotency-Key')).toBe(firstHeaders.get('Idempotency-Key'))
    expect(firstHeaders.get('If-Match')).toBe('"4"')
  })

  it('clears sensitive state and ignores a delayed enrollment-token response after a new session starts', async () => {
    const oldUserID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
    const newUserID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
    authenticate(undefined, { user_id: oldUserID }, 'old-session-token')
    const oldEpoch = useSessionStore.getState().sessionEpoch
    const pendingToken = deferred<Response>()
    const currentNode = { ...node, id: '018f0000-0000-7000-8000-000000000099', name: 'Current Session Edge' }
    let queryClient!: QueryClient
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const authorization = new Headers(init?.headers).get('Authorization')
      if (String(input).endsWith('/enrollment-tokens') && init?.method === 'POST') return pendingToken.promise
      if (authorization === 'Bearer old-session-token') return Promise.resolve(json({ items: [node] }))
      if (authorization === 'Bearer new-session-token') return Promise.resolve(json({ items: [currentNode] }))
      throw new Error(`unexpected authorization: ${authorization}`)
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<>
      <NodeListPage />
      <QueryClientCapture onCapture={(client) => { queryClient = client }} />
    </>)
    const oldRow = (await screen.findByText('Edge Shanghai')).closest('tr')!
    await openRowAction(user, oldRow, '令牌')
    await user.click(within(await screen.findByRole('dialog', { name: '签发注册令牌' })).getByRole('button', { name: '签发' }))

    act(() => useSessionStore.setState({
      accessToken: 'new-session-token',
      expiresAt: Date.now() + 60_000,
      principal: principal({
        scope_kind: 'platform', scope_id: scopeID, tenant_id: null, user_id: newUserID,
        permissions: ['nodes.read', 'nodes.manage'], roles: ['platform_owner'],
      }),
      sessionEpoch: oldEpoch + 1,
      status: 'authenticated',
    }))
    expect(await screen.findByText('Current Session Edge')).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '签发注册令牌' })).not.toBeInTheDocument()

    const rawOldToken = 'O'.repeat(43)
    await act(async () => {
      pendingToken.resolve(json({
        id: '018f0000-0000-7000-8000-000000000010', node_id: node.id, purpose: 're_enrollment',
        created_at: '2026-07-22T09:00:00Z', expires_at: '2026-07-22T09:10:00Z', token: rawOldToken,
      }, 201))
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(screen.getByText('Current Session Edge')).toBeInTheDocument()
    expect(screen.queryByDisplayValue(rawOldToken)).not.toBeInTheDocument()
    expect(screen.queryByText('注册令牌（仅显示一次）')).not.toBeInTheDocument()
    await waitFor(() => {
      const oldOwner = ['platform', scopeID, null, oldUserID, oldEpoch]
      expect(queryClient.getQueryCache().getAll().some((entry) => oldOwner.every((part, index) => entry.queryKey[index + 1] === part))).toBe(false)
      expect(queryClient.getMutationCache().getAll().some((entry) => oldOwner.every((part, index) => entry.options.mutationKey?.[index + 1] === part))).toBe(false)
    })
  })

  it.each(['success', 'forbidden'] as const)(
    'ignores a delayed old-session list %s after the current owner renders',
    async (settlement) => {
      const oldUserID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
      const newUserID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
      authenticate(['nodes.read'], { user_id: oldUserID }, 'old-list-token')
      const oldEpoch = useSessionStore.getState().sessionEpoch
      const pendingList = deferred<Response>()
      const currentNode = { ...node, id: '018f0000-0000-7000-8000-000000000099', name: 'Current Owner Edge' }
      let queryClient!: QueryClient
      vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
        const authorization = new Headers(init?.headers).get('Authorization')
        if (authorization === 'Bearer old-list-token') return pendingList.promise
        if (authorization === 'Bearer current-list-token') return Promise.resolve(json({ items: [currentNode] }))
        throw new Error(`unexpected authorization: ${authorization}`)
      })
      renderWithProviders(<>
        <NodeListPage />
        <QueryClientCapture onCapture={(client) => { queryClient = client }} />
      </>)
      await waitFor(() => expect(globalThis.fetch).toHaveBeenCalledTimes(1))

      act(() => useSessionStore.setState({
        accessToken: 'current-list-token',
        expiresAt: Date.now() + 60_000,
        principal: principal({
          scope_kind: 'platform', scope_id: scopeID, tenant_id: null, user_id: newUserID,
          permissions: ['nodes.read'], roles: ['platform_owner'],
        }),
        sessionEpoch: oldEpoch + 1,
        status: 'authenticated',
      }))
      expect(await screen.findByText('Current Owner Edge')).toBeInTheDocument()

      await act(async () => {
        pendingList.resolve(settlement === 'success'
          ? json({ items: [{ ...node, name: 'Old Sensitive Edge' }] })
          : json({ error: { code: 'permission_denied', message: 'old private denial' } }, 403))
        await Promise.resolve()
        await Promise.resolve()
      })

      expect(screen.getByText('Current Owner Edge')).toBeInTheDocument()
      expect(screen.queryByText('Old Sensitive Edge')).not.toBeInTheDocument()
      expect(screen.queryByText('无权查看节点列表')).not.toBeInTheDocument()
      expect(JSON.stringify(queryClient.getQueryCache().getAll().map((entry) => entry.state.data))).not.toContain('Old Sensitive Edge')
    },
  )

  it('keeps a current-owner list 403 terminal across token refresh', async () => {
    authenticate(['nodes.read'], {}, 'denied-list-token')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'permission_denied', message: 'private list denial' },
    }, 403))
    renderWithProviders(<NodeListPage />)

    expect(await screen.findByText('无权查看节点列表')).toBeInTheDocument()
    expect(screen.queryByText('private list denial')).not.toBeInTheDocument()
    act(() => useSessionStore.setState({ accessToken: 'refreshed-denied-list-token', expiresAt: Date.now() + 60_000 }))
    await act(async () => { await Promise.resolve(); await Promise.resolve() })
    expect(screen.getByText('无权查看节点列表')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('makes a current-owner mutation 403 terminal and cannot reawaken it after token refresh', async () => {
    authenticate(undefined, {}, 'denied-write-token')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => Promise.resolve(
      init?.method === 'PATCH'
        ? json({ error: { code: 'permission_denied', message: 'private write denial' } }, 403)
        : json({ items: [node] }),
    ))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    expect(await screen.findByText('Edge Shanghai')).toBeInTheDocument()
    await openRowAction(user, screen.getByText('Edge Shanghai').closest('tr')!, '编辑')
    await user.click(within(await screen.findByRole('dialog', { name: '编辑节点' })).getByRole('button', { name: '确定' }))

    expect(await screen.findByText('无权查看节点列表')).toBeInTheDocument()
    expect(screen.queryByText('private write denial')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    act(() => useSessionStore.setState({ accessToken: 'refreshed-denied-write-token', expiresAt: Date.now() + 60_000 }))
    await act(async () => { await Promise.resolve(); await Promise.resolve() })
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1)
  })

  it('immediately fences a pending mutation after a current-owner list 403', async () => {
    authenticate(undefined, {}, 'concurrent-denial-token')
    const session = useSessionStore.getState()
    const owner = ['platform', scopeID, null, session.principal!.user_id, session.sessionEpoch] as const
    const tokenMutationKey = ['nodes-write', ...owner, 'token'] as const
    const pendingToken = deferred<Response>()
    const rawToken = 'S'.repeat(43)
    let queryClient!: QueryClient
    let reads = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.endsWith('/enrollment-tokens') && init?.method === 'POST') return pendingToken.promise
      reads += 1
      return Promise.resolve(reads === 1
        ? json({ items: [node] })
        : json({ error: { code: 'permission_denied', message: 'private concurrent denial' } }, 403))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<>
      <NodeListPage />
      <QueryClientCapture onCapture={(client) => { queryClient = client }} />
    </>)
    const row = (await screen.findByText('Edge Shanghai')).closest('tr')!
    await openRowAction(user, row, '令牌')
    await user.click(within(await screen.findByRole('dialog', { name: '签发注册令牌' })).getByRole('button', { name: '签发' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).endsWith('/enrollment-tokens'))).toBe(true))
    const tokenMutation = queryClient.getMutationCache().find({ mutationKey: tokenMutationKey, exact: true })
    if (!tokenMutation) throw new Error('pending token mutation not found')
    expect(tokenMutation.state.status).toBe('pending')

    await act(async () => { await queryClient.invalidateQueries({ queryKey: ['nodes'] }) })
    expect(await screen.findByText('无权查看节点列表')).toBeInTheDocument()

    await act(async () => {
      pendingToken.resolve(json({
        id: '018f0000-0000-7000-8000-000000000010', node_id: node.id, purpose: 're_enrollment',
        created_at: '2026-07-22T09:00:00Z', expires_at: '2026-07-22T09:10:00Z', token: rawToken,
      }, 201))
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(screen.getByText('无权查看节点列表')).toBeInTheDocument()
    expect(screen.queryByDisplayValue(rawToken)).not.toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(3)
    await waitFor(() => expect(tokenMutation.state.status).toBe('error'))
    expect(tokenMutation.state.data).toBeUndefined()
    expect(JSON.stringify(tokenMutation.state)).not.toContain(rawToken)
    await waitFor(() => expect(queryClient.getMutationCache().findAll({
      mutationKey: ['nodes-write', ...owner],
    })).toHaveLength(0))
    expect(JSON.stringify(queryClient.getMutationCache().getAll().map((mutation) => mutation.state))).not.toContain(rawToken)
  })

  it('refreshes the inventory after a revision conflict', async () => {
    authenticate()
    let reads = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'PATCH') {
        return Promise.resolve(json({ error: { code: 'version_conflict', message: 'stale revision' } }, 409))
      }
      reads += 1
      return Promise.resolve(json({ items: [{
        ...node,
        revision: reads === 1 ? 4 : 5,
        description: reads === 1 ? node.description : 'server-refreshed',
      }] }))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await screen.findByText('Edge Shanghai')

    await openRowAction(user, screen.getByText('Edge Shanghai').closest('tr')!, '编辑')
    const dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    await user.clear(within(dialog).getByLabelText('备注'))
    await user.type(within(dialog).getByLabelText('备注'), 'concurrent edit')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    expect(await screen.findByText('节点已被其他操作修改，列表已刷新，请重新操作')).toBeInTheDocument()
    await waitFor(() => expect(reads).toBeGreaterThan(1))
    expect(await screen.findByText('server-refreshed')).toBeInTheDocument()
    expect(screen.queryByText('r5')).not.toBeInTheDocument()
  })

  it('keeps legacy retired nodes immutable but deletable and surfaces the identity gate from the server', async () => {
    authenticate()
    const disabled = { ...node, admin_state: 'disabled' as const }
    const retired = { ...node, id: '018f0000-0000-7000-8000-000000000003', display_id: '3', name: 'Retired Edge', admin_state: 'retired' as const }
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'PATCH') {
        return Promise.resolve(json({ error: { code: 'node_identity_required', message: 'identity required' } }, 409))
      }
      return Promise.resolve(json({ items: [disabled, retired] }))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await screen.findByText('Retired Edge')

    const retiredRow = screen.getByText('Retired Edge').closest('tr')!
    await user.click(within(retiredRow).getByRole('button', { name: '更多' }))
    expect(await screen.findByRole('menuitem', { name: '编辑' })).toHaveAttribute('aria-disabled', 'true')
    expect(screen.getByRole('menuitem', { name: '令牌' })).toHaveAttribute('aria-disabled', 'true')
    expect(screen.getByRole('menuitem', { name: '删除' })).not.toHaveAttribute('aria-disabled', 'true')
    expect(screen.queryByRole('menuitem', { name: '状态' })).not.toBeInTheDocument()
    expect(within(retiredRow).getByRole('checkbox')).toBeEnabled()
    fireEvent.keyDown(document, { key: 'Escape' })

    const disabledRow = screen.getByText('Edge Shanghai').closest('tr')!
    await openRowStatus(user, disabledRow)
    await chooseOpenOption(user, '启用（需注册授权）')
    const confirm = await screen.findByRole('dialog', { name: /将 Edge Shanghai 设为已启用/ })
    expect(within(confirm).getByText(/已消费的注册授权/)).toBeInTheDocument()
    await user.click(within(confirm).getByRole('button', { name: '确认' }))
    expect(await screen.findByText('节点尚未完成注册或证书已失效，不能初始化或恢复启用；请先在节点上执行安装命令')).toBeInTheDocument()
  })

  // C38/ND04: every status entry shares one matrix. A pending node can only be
  // deleted; its enable/disable entries are disabled with the reason, and the
  // status batch (which never offers deletion) is unavailable.
  it('disables status actions a pending node cannot take and keeps deletion out of the status batch', async () => {
    authenticate()
    const pendingNode = { ...node, admin_state: 'pending' as const }
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(json({ items: [pendingNode] })))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    const row = (await screen.findByText('Edge Shanghai')).closest('tr')!
    await user.click(within(row).getByRole('checkbox'))
    expect(screen.getByRole('button', { name: '启用节点' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '禁用节点' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    const menu = (await screen.findByRole('menuitem', { name: '批量状态' })).closest('ul')!
    expect(within(menu).getByRole('menuitem', { name: '批量状态' })).toHaveAttribute('aria-disabled', 'true')
    expect(within(menu).getByRole('menuitem', { name: '启用节点' })).toHaveAttribute('aria-disabled', 'true')
    expect(within(menu).getByRole('menuitem', { name: '禁用节点' })).toHaveAttribute('aria-disabled', 'true')
    expect(within(menu).getByRole('menuitem', { name: '删除节点' })).not.toHaveAttribute('aria-disabled', 'true')
    expect(within(menu).getAllByTitle(/先完成节点安装与身份注册/).length).toBeGreaterThan(0)
  })

  it('offers only status changes in the status batch', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(json({ items: [node] })))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    const row = (await screen.findByText('Edge Shanghai')).closest('tr')!
    await user.click(within(row).getByRole('checkbox'))
    await openBatchAction(user)
    const dialog = await screen.findByRole('dialog', { name: '批量变更状态（1 个节点）' })
    await user.click(within(dialog).getByRole('combobox'))
    const options = [...document.querySelectorAll('.node-batch-state-popup .ant-select-item-option')].map((option) => option.textContent)
    expect(options).not.toContain('已退役')
    expect(options.length).toBeGreaterThan(0)
    expect(within(dialog).getByRole('button', { name: '确认变更' })).not.toHaveClass('ant-btn-dangerous')
  })

  it('exposes permanent node deletion in both menus and reports deleted nodes', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (String(input) === '/v1/nodes/batch-admin-state' && init?.method === 'POST') {
        return Promise.resolve(json({ items: [{ id: node.id, status: 'updated', node: { ...node, admin_state: 'retired', revision: 5 } }] }))
      }
      return Promise.resolve(json({ items: [node] }))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)

    const row = (await screen.findByText('Edge Shanghai')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '更多' }))
    expect(await screen.findByRole('menuitem', { name: '删除' })).not.toHaveAttribute('aria-disabled', 'true')
    fireEvent.keyDown(document, { key: 'Escape' })

    await user.click(within(row).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    const deleteIP = await screen.findByRole('menuitem', { name: '删除节点' })
    expect(deleteIP).not.toHaveAttribute('aria-disabled', 'true')
    await user.click(deleteIP)
    // C38: deleting is its own danger confirmation naming the nodes, not a status option.
    const batchDialog = await screen.findByRole('dialog', { name: '删除 1 个节点' })
    expect(batchDialog).toHaveTextContent('节点与其证书、监控数据将被永久删除，操作记录保留在系统日志中')
    expect(batchDialog).toHaveTextContent(node.name)
    expect(within(batchDialog).queryByRole('combobox')).not.toBeInTheDocument()
    await user.click(within(batchDialog).getByRole('button', { name: '删除 1 个节点' }))
    const results = await screen.findByRole('dialog', { name: '批量操作结果' })
    expect(results).toHaveTextContent('已删除')
    expect(results).toHaveTextContent(node.display_id)
    const batchCall = fetchSpy.mock.calls.find(([input, init]) => String(input) === '/v1/nodes/batch-admin-state' && init?.method === 'POST')
    expect(JSON.parse(String(batchCall?.[1]?.body))).toMatchObject({ admin_state: 'retired', items: [{ id: node.id, expected_revision: node.revision }] })
  })

  it('confirms deletion with the real consequences and explains a node still in use', async () => {
    authenticate()
    let deletes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (init?.method === 'PATCH') {
        deletes += 1
        return Promise.resolve(json({ error: { code: 'node_in_use', message: 'internal wording' } }, 409))
      }
      if (String(input) === '/v1/nodes/batch-admin-state' && init?.method === 'POST') {
        return Promise.resolve(json({ items: [{ id: node.id, status: 'failed', error: { code: 'node_in_use' } }] }))
      }
      return Promise.resolve(json({ items: [node] }))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)

    const row = (await screen.findByText('Edge Shanghai')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '更多' }))
    await user.click(await screen.findByRole('menuitem', { name: '删除' }))
    const dialog = await screen.findByRole('dialog', { name: '删除节点 Edge Shanghai？' })
    expect(dialog).toHaveTextContent('节点与其证书、监控数据将被永久删除，操作记录保留在系统日志中')
    expect(dialog).toHaveTextContent('节点名称与授权节点数立即释放')
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(deletes).toBe(1))
    const patch = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')
    expect(JSON.parse(String(patch?.[1]?.body))).toEqual({ admin_state: 'retired' })
    expect(await screen.findByText(/节点仍被线路分组或 L2 配置使用/)).toBeInTheDocument()
    expect(screen.queryByText('internal wording')).not.toBeInTheDocument()
  })

  it('retries ordered batch revisions with the latest token and the exact frozen request', async () => {
    authenticate(undefined, {}, 'batch-token-before-refresh')
    const second = { ...node, id: '018f0000-0000-7000-8000-000000000002', display_id: '2', name: 'Edge Beijing', admin_state: 'draining' as const, revision: 2 }
    let batchWrites = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url === '/v1/nodes/batch-admin-state' && init?.method === 'POST') {
        batchWrites += 1
        if (batchWrites === 1) return Promise.reject(new TypeError('connection reset'))
        return Promise.resolve(json({ items: [
          { id: node.id, status: 'updated', node: { ...node, admin_state: 'disabled', revision: 5 } },
          { id: second.id, status: 'failed', error: { code: 'version_conflict' } },
        ] }))
      }
      return Promise.resolve(json({ items: [node, second] }))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await screen.findByText('Edge Beijing')

    await user.click(screen.getByRole('checkbox', { name: 'Edge Shanghai' }))
    await user.click(screen.getByRole('checkbox', { name: 'Edge Beijing' }))
    await openBatchAction(user)
    const dialog = await screen.findByRole('dialog', { name: '批量变更状态（2 个节点）' })
    expect(within(dialog).getByText('已禁用')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '确认变更' }))

    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    act(() => useSessionStore.setState({ accessToken: 'batch-token-after-refresh', expiresAt: Date.now() + 60_000 }))
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    const result = await screen.findByRole('dialog', { name: '批量操作结果' })
    expect(within(result).getByText('已更新')).toBeInTheDocument()
    expect(within(result).getByText('节点已被其他操作修改，列表已刷新，请重新操作')).toBeInTheDocument()
    expect(within(result).queryByText('version_conflict')).not.toBeInTheDocument()
    const calls = fetchSpy.mock.calls.filter(([url]) => String(url) === '/v1/nodes/batch-admin-state')
    expect(calls).toHaveLength(2)
    expect(JSON.parse(String(calls[0][1]?.body))).toEqual({
      admin_state: 'disabled',
      items: [
        { id: second.id, expected_revision: 2 },
        { id: node.id, expected_revision: 4 },
      ],
    })
    expect(calls[1][1]?.body).toBe(calls[0][1]?.body)
    const firstHeaders = new Headers(calls[0][1]?.headers)
    const retryHeaders = new Headers(calls[1][1]?.headers)
    expect(firstHeaders.get('Authorization')).toBe('Bearer batch-token-before-refresh')
    expect(retryHeaders.get('Authorization')).toBe('Bearer batch-token-after-refresh')
    expect(retryHeaders.get('Idempotency-Key')).toBe(firstHeaders.get('Idempotency-Key'))
  })

  it('retries only failed batch items with refreshed revisions and a new idempotency key', async () => {
    authenticate()
    const failed = {
      ...node,
      id: '018f0000-0000-7000-8000-000000000002',
      display_id: '2',
      name: 'Edge Beijing',
      admin_state: 'draining' as const,
      revision: 2,
    }
    let listReads = 0
    let batchWrites = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url === '/v1/nodes/batch-admin-state' && init?.method === 'POST') {
        batchWrites += 1
        if (batchWrites === 1) {
          return Promise.resolve(json({ items: [
            { id: node.id, status: 'updated', node: { ...node, admin_state: 'disabled', revision: 5 } },
            { id: failed.id, status: 'failed', error: { code: 'version_conflict' } },
          ] }))
        }
        return Promise.resolve(json({ items: [
          { id: failed.id, status: 'updated', node: { ...failed, admin_state: 'disabled', revision: 7 } },
        ] }))
      }
      listReads += 1
      return Promise.resolve(json({ items: listReads === 1 ? [node, failed] : [
        { ...node, admin_state: 'disabled', revision: 5 },
        { ...failed, revision: 6 },
      ] }))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await screen.findByText('Edge Beijing')

    await user.click(screen.getByRole('checkbox', { name: 'Edge Shanghai' }))
    await user.click(screen.getByRole('checkbox', { name: 'Edge Beijing' }))
    await openBatchAction(user)
    const confirm = await screen.findByRole('dialog', { name: '批量变更状态（2 个节点）' })
    await user.click(within(confirm).getByRole('button', { name: '确认变更' }))

    const partial = await screen.findByRole('dialog', { name: '批量操作结果' })
    await waitFor(() => expect(listReads).toBeGreaterThan(1))
    await user.click(within(partial).getByRole('button', { name: '仅重试失败节点' }))
    await waitFor(() => expect(batchWrites).toBe(2))

    const calls = fetchSpy.mock.calls.filter(([url]) => String(url) === '/v1/nodes/batch-admin-state')
    expect(JSON.parse(String(calls[1][1]?.body))).toEqual({
      admin_state: 'disabled',
      items: [{ id: failed.id, expected_revision: 6 }],
    })
    const firstHeaders = new Headers(calls[0][1]?.headers)
    const retryHeaders = new Headers(calls[1][1]?.headers)
    expect(retryHeaders.get('Idempotency-Key')).not.toBe(firstHeaders.get('Idempotency-Key'))
  })
})

describe('node modal validation failures (ui-click F2)', () => {
  it('keeps a failed add-node validation local without an unhandled rejection or write', async () => {
    authenticate()
    const rejections: unknown[] = []
    const onRejection = (reason: unknown) => { rejections.push(reason) }
    process.on('unhandledRejection', onRejection)
    try {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(json({ items: [] })))
      const user = userEvent.setup({ delay: null })
      renderWithProviders(<NodeListPage />, ['/node/list'])
      await screen.findByText('暂无节点')
      const dialog = await openAdvancedRegistration(user)
      await user.click(within(dialog).getByRole('button', { name: '保存' }))
      await waitFor(() => expect(dialog.querySelector('.ant-form-item-explain-error')).not.toBeNull())
      await new Promise((resolve) => setTimeout(resolve, 0))
      expect(rejections).toEqual([])
      expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
    } finally {
      process.off('unhandledRejection', onRejection)
    }
  })
})

describe('A17 node delete acknowledgement', () => {
  const other = { ...node, id: '018f0000-0000-7000-8000-000000000002', display_id: '2', name: 'Edge Beijing' }

  async function deleteNode(user: ReturnType<typeof userEvent.setup>) {
    const row = (await screen.findByText('Edge Shanghai')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '更多' }))
    await user.click(await screen.findByRole('menuitem', { name: '删除' }))
    const dialog = await screen.findByRole('dialog', { name: '删除节点 Edge Shanghai？' })
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
  }

  it('confirms a physical delete from the verified ACK without GETting the deleted node, and does not lock writes', async () => {
    authenticate()
    let deleted = false
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (init?.method === 'PATCH') {
        deleted = true
        return Promise.resolve(json({ ...node, admin_state: 'retired', revision: 5, presence: undefined }))
      }
      if (String(input) === `/v1/nodes/${node.id}`) return Promise.resolve(json({ error: { code: 'node_not_found' } }, 404))
      return Promise.resolve(json({ items: deleted ? [other] : [node, other] }))
    })
    const user = userEvent.setup({ delay: null })
    const view = renderWithProviders(<NodeListPage />)
    await deleteNode(user)
    expect(await screen.findByText('节点已删除')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('Edge Shanghai')).not.toBeInTheDocument())
    expect(fetchSpy.mock.calls.filter(([input, init]) => String(input) === `/v1/nodes/${node.id}` && init?.method !== 'PATCH')).toHaveLength(0)
    expect(screen.queryByText('节点修改已保存，回读待确认')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '安装节点' })).toBeEnabled()
    expect(Object.keys(sessionStorage).filter((key) => key.startsWith('cdnca:node-update-retry'))).toHaveLength(0)
    view.unmount()
    renderWithProviders(<NodeListPage />)
    await screen.findByText('Edge Beijing')
    expect(screen.getByRole('button', { name: '安装节点' })).toBeEnabled()
  })

  it.each([
    ['wrong id', { ...other, admin_state: 'retired', revision: 5 }],
    ['not retired', { ...node, admin_state: 'active', revision: 5 }],
  ] as const)('does not accept a delete ACK with %s as success', async (_name, ack) => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => Promise.resolve(init?.method === 'PATCH'
      ? json({ ...ack, presence: undefined })
      : json({ items: [node, other] })))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await deleteNode(user)
    expect(await screen.findByRole('button', { name: '使用同一请求重试' })).toBeInTheDocument()
    expect(screen.queryByText('节点已删除')).not.toBeInTheDocument()
  })

  it('recovers a legacy v1 delete readback record by replaying the same idempotency key instead of GETting a 404', async () => {
    authenticate()
    const attempt = { item: { id: node.id, revision: 4 }, input: { admin_state: 'retired' as const }, key: 'node-delete-legacy-key' }
    const realOwner = ['platform', scopeID, useSessionStore.getState().principal!.user_id] as const
    sessionStorage.setItem(nodeUpdateRetryStorageKey(realOwner), JSON.stringify({ version: 1, owner: realOwner, phase: 'readback', confirmedRevision: 5, attempt, body: JSON.stringify(attempt) }))
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (init?.method === 'PATCH') return Promise.resolve(json({ ...node, admin_state: 'retired', revision: 5, presence: undefined }))
      if (String(input) === `/v1/nodes/${node.id}`) return Promise.resolve(json({ error: { code: 'node_not_found' } }, 404))
      return Promise.resolve(json({ items: [other] }))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    expect(await screen.findByText('节点修改已保存，回读待确认')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '仅重试回读' }))
    expect(await screen.findByText('节点已删除')).toBeInTheDocument()
    const patch = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')!
    expect(new Headers(patch[1]?.headers).get('Idempotency-Key')).toBe('node-delete-legacy-key')
    expect(fetchSpy.mock.calls.filter(([input, init]) => String(input) === `/v1/nodes/${node.id}` && init?.method !== 'PATCH')).toHaveLength(0)
    expect(restoreNodeUpdateRetry(realOwner).record).toBeNull()
    expect(screen.getByRole('button', { name: '安装节点' })).toBeEnabled()
  })
})

describe('node storage tab', () => {
  const latest = (storageSupported: boolean, storage?: Record<string, unknown>) => ({
    record_kind: 'host_metric', node_id: node.id, node_name: node.name,
    config_revision: 0, active_config_revision: 0, publication_sequence: 1,
    observed_at: '2026-10-27T10:00:00Z', ingested_at: '2026-10-27T10:00:01Z',
    probe_port: 0, healthy: false, probe_succeeded: false, consecutive_failures: 0,
    consecutive_successes: 0, probes_total: 0, probe_failures_total: 0,
    recovered: false, recovery_notified: false, rolled_back: false, known: true,
    cpu_percent: 0, memory_used_bytes: 0, memory_total_bytes: 1, active_connections: 0,
    rx_bandwidth_bps: 0, tx_bandwidth_bps: 0, total_rx_bytes: 0, total_tx_bytes: 0,
    puback_stream: 'NODE_MONITORING_STATUS', puback_sequence: 1,
    consumer_durable: 'control_api_node_metrics', consumer_sequence: 1,
    storage_supported: storageSupported,
    telemetry: { schema_version: 1, network_interfaces: [], disks: [], total_rx_bytes: 0, total_tx_bytes: 0, ...(storage ? { storage } : {}) },
  })

  async function openStorageTab(metrics: unknown, settings: Partial<NodeInventoryItem['management_settings']> = {}) {
    authenticate()
    const writes: Array<Record<string, unknown>> = []
    let current = { ...node, management_settings: { ...node.management_settings, ...settings } }
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url === `/v1/nodes/${node.id}/metrics/latest`) return Promise.resolve(json(metrics))
      if (url === `/v1/nodes/${node.id}` && init?.method === 'PATCH') {
        writes.push(JSON.parse(String(init.body)) as Record<string, unknown>)
        current = { ...current, ...writes.at(-1), revision: current.revision + 1 }
        return Promise.resolve(json({ ...current, presence: undefined }))
      }
      return Promise.resolve(json(url === `/v1/nodes/${node.id}` ? current : { items: [current] }))
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />, ['/node/list'])
    await user.click(await screen.findByRole('button', { name: node.name }))
    const dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    await user.click(within(dialog).getByRole('tab', { name: '节点设置' }))
    return { dialog, user, writes }
  }

  it('edits and saves the cache directory, cache limit and log directory on a node that declares NODE_STORAGE', async () => {
    const { dialog, user, writes } = await openStorageTab(latest(true, {
      cache_directory: '/var/lib/cdnca-edge/dynroute/shared/cache', cache_max_bytes: 10 * 2 ** 30,
      log_directory: '/var/lib/cdnca-edge/dynroute/shared', state: 'default',
    }))
    expect(await within(dialog).findByText(/缓存目录、缓存上限保存后随下一次发布在节点上重载生效/)).toBeInTheDocument()
    expect(within(dialog).getByText(/旧的缓存和日志目录会保留在节点上，不会自动删除/)).toBeInTheDocument()
    expect(within(dialog).getByText(/缓存目录 \/var\/lib\/cdnca-edge\/dynroute\/shared\/cache/)).toBeInTheDocument()
    expect(within(dialog).getByText('使用节点默认值')).toBeInTheDocument()
    expect(within(dialog).queryByText('节点设置暂未下发到节点，当前不可修改')).not.toBeInTheDocument()
    const cacheDirectory = within(dialog).getByLabelText('缓存目录')
    expect(cacheDirectory).toBeEnabled()
    await user.clear(cacheDirectory)
    await user.clear(within(dialog).getByLabelText('日志目录'))

    // outside the allowed roots, then overlapping the log directory: refused before any write
    await user.type(cacheDirectory, '/etc/cache')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect((await within(dialog).findAllByText(/须为 \/data、\/var\/cache/)).length).toBeGreaterThan(0)
    await user.clear(cacheDirectory)
    await user.type(cacheDirectory, '/data/cdnca')
    await user.type(within(dialog).getByLabelText('日志目录'), '/data/cdnca/logs')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect((await within(dialog).findAllByText('缓存目录与日志目录不能相同或互相包含')).length).toBeGreaterThan(0)
    expect(writes).toHaveLength(0)

    await user.clear(within(dialog).getByLabelText('日志目录'))
    await user.type(within(dialog).getByLabelText('日志目录'), '/data/cdnca-logs')
    await user.clear(within(dialog).getByLabelText('缓存上限'))
    await user.type(within(dialog).getByLabelText('缓存上限'), '20')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await screen.findByText('节点信息已更新')
    expect(writes.at(-1)).toMatchObject({ management_settings: {
      cache_directory: '/data/cdnca', cache_limit_gb: 20, log_directory: '/data/cdnca-logs',
    } })
  })

  // Unset fields show what the node runs when unset, in the field.
  const unset = { cache_directory: '', cache_limit_gb: 0, log_directory: '' }

  it('shows the defaults the node reports inside the empty fields and saves them as unset', async () => {
    const { dialog, user, writes } = await openStorageTab(latest(true, {
      cache_directory: '/var/lib/dynroute/shared/cache', cache_max_bytes: 16 * 2 ** 30,
      log_directory: '/var/lib/dynroute/shared', state: 'default',
    }), unset)
    const cacheDirectory = within(dialog).getByLabelText('缓存目录')
    const cacheLimit = within(dialog).getByLabelText('缓存上限')
    const logDirectory = within(dialog).getByLabelText('日志目录')
    await waitFor(() => expect(cacheDirectory).toHaveAttribute('placeholder', '/var/lib/dynroute/shared/cache'))
    expect(cacheDirectory).toHaveValue('')
    expect(cacheLimit).toHaveAttribute('placeholder', '16')
    expect(cacheLimit).toHaveValue('')
    expect(logDirectory).toHaveAttribute('placeholder', '/var/lib/dynroute/shared')
    expect(logDirectory).toHaveValue('')
    expect(within(dialog).getByText(/留空为自动：缓存目录所在磁盘容量的 1\/4，最多 64 GB/)).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '恢复默认' })).toBeDisabled()

    // untouched defaults are not written as explicit settings
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await screen.findByText('节点信息已更新')
    expect(writes.at(-1)).toMatchObject({ management_settings: unset })
  })

  it('shows the installer defaults before the node reports and writes only the changed field', async () => {
    const { dialog, user, writes } = await openStorageTab(latest(true), unset)
    const cacheLimit = within(dialog).getByLabelText('缓存上限')
    await waitFor(() => expect(cacheLimit).toBeEnabled())
    expect(within(dialog).getByLabelText('缓存目录')).toHaveAttribute('placeholder', '/var/lib/dynroute/shared/cache')
    expect(within(dialog).getByLabelText('日志目录')).toHaveAttribute('placeholder', '/var/lib/dynroute/shared')
    expect(cacheLimit).toHaveAttribute('placeholder', '自动')
    await user.type(cacheLimit, '20')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await screen.findByText('节点信息已更新')
    expect(writes.at(-1)).toMatchObject({ management_settings: { ...unset, cache_limit_gb: 20 } })
  })

  it('restores the defaults by clearing every field', async () => {
    const { dialog, user, writes } = await openStorageTab(latest(true, {
      cache_directory: '/data/custom-cache', cache_max_bytes: 30 * 2 ** 30, log_directory: '/data/custom-logs', state: 'applied',
    }), { cache_directory: '/data/custom-cache', cache_limit_gb: 30, log_directory: '/data/custom-logs' })
    const cacheDirectory = within(dialog).getByLabelText('缓存目录')
    await waitFor(() => expect(cacheDirectory).toBeEnabled())
    expect(cacheDirectory).toHaveValue('/data/custom-cache')
    expect(within(dialog).getByLabelText('缓存上限')).toHaveValue('30')
    // the node runs the custom values: the empty-field hint falls back to the installer defaults
    await user.click(within(dialog).getByRole('button', { name: '恢复默认' }))
    expect(cacheDirectory).toHaveValue('')
    expect(cacheDirectory).toHaveAttribute('placeholder', '/var/lib/dynroute/shared/cache')
    expect(within(dialog).getByLabelText('缓存上限')).toHaveValue('')
    expect(within(dialog).getByLabelText('缓存上限')).toHaveAttribute('placeholder', '自动')
    expect(within(dialog).getByLabelText('日志目录')).toHaveValue('')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await screen.findByText('节点信息已更新')
    expect(writes.at(-1)).toMatchObject({ management_settings: unset })
  })

  it('shows the default traffic period start and saves a cleared one as the default', async () => {
    const { dialog, user, writes } = await openStorageTab(latest(true), {
      auto_disable: { ...node.management_settings.auto_disable, traffic_from_time: '08:30:00' },
    })
    await user.click(within(dialog).getByRole('tab', { name: '自动禁用' }))
    const start = within(dialog).getByDisplayValue('08:30:00')
    await user.clear(start)
    // node.DefaultNodeManagementSettings / migration 378: 00:00:00
    expect(start).toHaveAttribute('placeholder', '00:00:00')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await screen.findByText('节点信息已更新')
    expect(writes.at(-1)).toMatchObject({ management_settings: { auto_disable: { traffic_from_time: '00:00:00' } } })
  })

  it('shows a refusal and a pending log directory the node reports', async () => {
    const { dialog } = await openStorageTab(latest(true, {
      cache_directory: '/data/old', cache_max_bytes: 2 ** 30, log_directory: '/data/logs-old', state: 'failed',
      reason: 'cache directory /data/new: permission denied',
    }))
    expect(await within(dialog).findByText(/节点拒绝了上次的设置，仍按原设置运行/)).toBeInTheDocument()
    expect(within(dialog).getByText(/permission denied/)).toBeInTheDocument()
  })

  it('keeps the tab read-only on a node that does not declare NODE_STORAGE', async () => {
    const { dialog } = await openStorageTab(latest(false))
    expect(await within(dialog).findByText('该节点版本不支持在这里修改缓存目录、缓存上限和日志目录')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('缓存目录')).toBeDisabled()
    expect(within(dialog).getByRole('button', { name: '确定' })).toBeDisabled()
    expect(within(dialog).getByText(/节点尚未上报/)).toBeInTheDocument()
  })
})

describe('NodeListPage IP location', () => {
  const resolvedAt = '2026-10-27T08:00:00Z'
  const automatic = { country: '中国', province: '上海市', city: '上海市', isp: '中国电信', country_code: 'CN' }

  function mount(view: Record<string, unknown>, settings: Partial<typeof node.management_settings> = {}) {
    authenticate()
    const writes: Array<Record<string, unknown>> = []
    let current = { ...node, management_settings: { ...node.management_settings, ...settings } }
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url === `/v1/nodes/${node.id}/ip-location`) return Promise.resolve(json({ node_id: node.id, ...view }))
      if (url === `/v1/nodes/${node.id}` && init?.method === 'PATCH') {
        writes.push(JSON.parse(String(init.body)) as Record<string, unknown>)
        current = { ...current, ...writes.at(-1), revision: current.revision + 1 }
        return Promise.resolve(json({ ...current, presence: undefined }))
      }
      return Promise.resolve(json(url === `/v1/nodes/${node.id}` ? current : { items: [current] }))
    })
    renderWithProviders(<NodeListPage />, ['/node/list'])
    return writes
  }

  async function openTab(user: ReturnType<typeof userEvent.setup>) {
    await user.click(await screen.findByRole('button', { name: node.name }))
    const dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    await user.click(within(dialog).getByRole('tab', { name: 'IP归属' }))
    return dialog
  }

  it('shows each field as automatic or edited with the lookup time and IP library version', async () => {
    mount({
      effective: { ...automatic, city: '杭州' }, manual_fields: ['city'],
      resolution: { node_id: node.id, outcome: 'resolved', address: '192.0.2.10', automatic, library_revision: 7,
        library_version: '2026.10.27', resolved_at: resolvedAt },
    }, { ip_location: { ...automatic, city: '杭州' }, ip_location_manual: ['city'] })
    const dialog = await openTab(userEvent.setup({ delay: null }))
    expect(await within(dialog).findByText(/按 IP 192.0.2.10 自动解析.*IP 库版本 2026.10.27/)).toBeInTheDocument()
    expect(within(dialog).getAllByText('自动解析').filter((element) => element.classList.contains('node-ip-location-tag'))).toHaveLength(4)
    expect(within(dialog).getAllByText('人工修正')).toHaveLength(1)
    expect(within(dialog).getByRole('button', { name: '城市恢复自动' })).toBeInTheDocument()
  })

  it('restores an edited field to the automatic value and saves it as automatic', async () => {
    const writes = mount({
      effective: { ...automatic, isp: 'BGP' }, manual_fields: ['isp'],
      resolution: { node_id: node.id, outcome: 'resolved', address: '192.0.2.10', automatic, library_revision: 7,
        library_version: '', resolved_at: resolvedAt },
    }, { ip_location: { ...automatic, isp: 'BGP' }, ip_location_manual: ['isp'] })
    const user = userEvent.setup({ delay: null })
    const dialog = await openTab(user)
    expect(within(dialog).getByLabelText('ISP')).toHaveValue('BGP')
    await user.click(await within(dialog).findByRole('button', { name: 'ISP恢复自动' }))
    expect(within(dialog).getByLabelText('ISP')).toHaveValue('中国电信')
    expect(within(dialog).queryByText('人工修正')).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(writes).toHaveLength(1))
    expect(writes.at(-1)).toMatchObject({ management_settings: { ip_location: { isp: '中国电信' }, ip_location_manual: [] } })
  })

  it('says 未能解析 instead of leaving the lookup blank', async () => {
    mount({
      effective: { country: '', province: '', city: '', isp: '', country_code: '' }, manual_fields: [],
      resolution: { node_id: node.id, outcome: 'unresolved', automatic: { country: '', province: '', city: '', isp: '', country_code: '' },
        library_revision: 7, library_version: '2026.10.27', resolved_at: resolvedAt },
    }, { ip_location: { country: '', province: '', city: '', isp: '', country_code: '' } })
    const dialog = await openTab(userEvent.setup({ delay: null }))
    expect(await within(dialog).findByText(/未能解析：IP 库里查不到这个节点的 IP/)).toBeInTheDocument()
  })

  it('says when the controller has no IP library or has not looked the node up yet', async () => {
    mount({ effective: automatic, manual_fields: [], resolution: null })
    const dialog = await openTab(userEvent.setup({ delay: null }))
    expect(await within(dialog).findByText(/还没有自动解析结果/)).toBeInTheDocument()
  })
})
