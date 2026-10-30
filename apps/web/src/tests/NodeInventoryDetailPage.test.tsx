import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError, type Principal } from '../api/auth'
import { nodesApi, type NodeDDoSProtection, type NodeInventoryItem, type NodeMetricsLatest } from '../api/nodes'
import { nodeInstallationTicketsApi, type NodeTicket } from '../api/nodeInstallationTickets'
import { resetSessionStore, useSessionStore } from '../auth/session'
import i18n from '../i18n'
import NodeInventoryDetailPage from '../pages/NodeInventoryDetailPage'
import { authResponse, nodeManagementSettingsFixture, principal } from '../test/fixtures'

const nodeID = '018f0000-0000-7000-8000-000000000001'

function latestMetrics(protection: NodeDDoSProtection | undefined): NodeMetricsLatest {
  const time = '2026-10-24T10:00:00Z'
  return {
    node_id: nodeID, node_name: 'edge', record_kind: 'host_metric',
    config_revision: 0, active_config_revision: 0, publication_sequence: 1, observed_at: time, ingested_at: time,
    probe_port: 0, healthy: true, probe_succeeded: true, consecutive_failures: 0, consecutive_successes: 0,
    probes_total: 0, probe_failures_total: 0, recovered: false, recovery_notified: false, rolled_back: false,
    known: true, cpu_percent: 0, memory_used_bytes: 0, memory_total_bytes: 1, active_connections: 0,
    rx_bandwidth_bps: 0, tx_bandwidth_bps: 0, total_rx_bytes: 0, total_tx_bytes: 0,
    telemetry: { schema_version: 1, total_rx_bytes: 0, total_tx_bytes: 0, disks: [], network_interfaces: [],
      ...(protection ? { ddos_protection: protection } : {}) },
    puback_stream: 'NODE_MONITORING_STATUS', puback_sequence: 1,
    consumer_durable: 'control_api_node_metrics', consumer_sequence: 1,
  } as NodeMetricsLatest
}
const inventory: NodeInventoryItem = {
  id: nodeID,
  display_id: '1',
  name: '上海边缘节点',
  description: '主服务节点',
  region: 'CN-East',
  ipv4: '192.0.2.10',
  ipv6: '2001:db8::10',
  admin_state: 'active',
  management_settings: nodeManagementSettingsFixture(),
  revision: 4,
  created_at: '2026-08-01T08:00:00Z',
  updated_at: '2026-08-01T09:00:00Z',
  presence: {
    status: 'online',
    last_heartbeat_at: '2026-08-01T08:59:55Z',
    agent_version: '2.4.1',
    session_epoch: 7,
    heartbeat_sequence: 11,
    projection_freshness: 'fresh',
    lease_signal: 'present',
    projected_at: '2026-08-01T08:59:56Z',
  },
}

const validTicket: NodeTicket = {
  node_id: nodeID, state: 'valid', node_status: 'serving', issued_at: '2026-07-31T08:00:00Z',
  not_after: '2026-08-30T08:00:00Z', days_left: 29, reported_at: '2026-08-01T08:59:00Z',
}

const switchedTransition = {
  id: '018f0000-0000-7000-8000-000000000010',
  scope_id: '018f0000-0000-7000-8000-000000000011',
  node_id: nodeID,
  revision: 1,
  expected_node_revision: 4,
  old_endpoint: { address: 'gateway.example.com:7443', server_name: 'gateway.example.com', listen_address: '0.0.0.0:7443' },
  new_endpoint: { address: 'gateway.example.com:8443', server_name: 'gateway.example.com', listen_address: '0.0.0.0:8443' },
  compatibility_deadline: '2026-08-01T09:30:00Z',
  rollback_deadline: '2026-08-01T10:00:00Z',
  state: 'switched' as const,
  status_revision: 2,
  active_endpoint: { address: 'gateway.example.com:8443', server_name: 'gateway.example.com', listen_address: '0.0.0.0:8443' },
  error_code: '',
  created_at: '2026-08-01T09:00:00Z',
  updated_at: '2026-08-01T09:01:00Z',
}

function platform(overrides: Partial<Principal> = {}): Principal {
  return principal({
    scope_kind: 'platform',
    scope_id: 'platform',
    tenant_id: null,
    roles: ['platform_owner'],
    permissions: ['nodes.read'],
    ...overrides,
  })
}

function authenticate(
  actor = platform(),
  token = 'node-detail-token',
  update: 'new' | 'refresh' = 'new',
) {
  useSessionStore.getState().setSession(
    { ...authResponse(actor), access_token: token },
    actor,
    update,
  )
  return actor
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((next, fail) => {
    resolve = next
    reject = fail
  })
  return { promise, resolve, reject }
}

function renderPage(
  path = `/node/list/${nodeID}`,
  queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } }),
) {
  const view = render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={[path]}>
            <Routes>
              <Route path="/node/list/:id" element={<NodeInventoryDetailPage />} />
            </Routes>
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
  return { ...view, queryClient }
}

describe('NodeInventoryDetailPage', () => {
  beforeEach(async () => {
    resetSessionStore()
    await i18n.changeLanguage('zh-CN')
    vi.restoreAllMocks()
    // The tenants panel reads its own endpoint; covered in NodeConfigurationScopesPanel.test.tsx.
    vi.spyOn(nodesApi, 'getConfigurationScopes').mockResolvedValue({ node_id: nodeID, scopes: [], rejections: [], capability_regressions: [] })
    vi.spyOn(nodesApi, 'getLatestMetrics').mockResolvedValue(latestMetrics(undefined))
    vi.spyOn(nodeInstallationTicketsApi, 'get').mockResolvedValue({ observed_at: '2026-08-01T09:00:00Z', items: [validTicket] })
  })

  // fix-stoppolicy2: the status area shows the service ticket; a frozen node
  // gets 已冻结 with reason, recovery condition and the last ticket expiry.
  it('shows a frozen node with reason, recovery and the last ticket expiry', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'get').mockResolvedValue(inventory)
    vi.spyOn(nodeInstallationTicketsApi, 'get').mockResolvedValue({ observed_at: '2026-08-01T09:00:00Z', items: [{
      ...validTicket, state: 'expired', node_status: 'service_ticket_expired', not_after: '2026-07-30T08:00:00Z', days_left: 0,
    }] })
    renderPage()
    const detail = await waitFor(() => {
      const element = document.querySelector<HTMLElement>('.node-frozen-detail')
      expect(element).not.toBeNull()
      return element!
    })
    expect(within(detail).getByText('已冻结')).toBeInTheDocument()
    expect(detail).toHaveTextContent('服务票据过期（授权到期或主控与授权中心失联）')
    expect(detail).toHaveTextContent('恢复条件')
    expect(detail).toHaveTextContent(/最近票据到期时间：2026/)
    expect(nodeInstallationTicketsApi.get).toHaveBeenCalledWith(expect.any(String), [nodeID], expect.anything())
  })

  it('shows a valid ticket as its expiry without a frozen tag', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'get').mockResolvedValue(inventory)
    renderPage()
    expect(await screen.findByText(/^有效至 2026/)).toBeInTheDocument()
    expect(document.querySelector('.node-frozen-tag')).toBeNull()
  })

  // E1 遗留：节点详情单独显示 DDoS 防护状态（列表只在 XDP 列显示异常）。
  it.each([
    [{ state: 'applied' }, ['已生效'], []],
    [{ state: 'off' }, ['未开启'], []],
    [{ state: 'pending' }, ['等待首次发布'], []],
    [{ state: 'failed', detail: 'nft: table busy' }, ['防护异常', 'nft: table busy', /应用失败/], []],
    [{ state: 'unavailable', reason: 'nft_missing' }, ['防护不可用', /没有安装 nftables/], ['节点说明']],
  ] as const)('shows the DDoS protection block for %o', async (protection, expected, absent) => {
    authenticate()
    vi.spyOn(nodesApi, 'get').mockResolvedValue(inventory)
    vi.spyOn(nodesApi, 'getLatestMetrics').mockResolvedValue(latestMetrics(protection as NodeDDoSProtection))
    renderPage()
    const block = await screen.findByRole('region', { name: 'DDoS 防护' })
    for (const value of expected) expect(await within(block).findByText(value)).toBeInTheDocument()
    for (const value of absent) expect(within(block).queryByText(value)).not.toBeInTheDocument()
  })

  it('says when the node has not reported protection', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'get').mockResolvedValue(inventory)
    renderPage()
    expect(await screen.findByText('节点尚未上报防护状态（离线或 Agent 版本较旧）')).toBeInTheDocument()
  })

  it('keeps the detail when the protection read fails', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'get').mockResolvedValue(inventory)
    vi.spyOn(nodesApi, 'getLatestMetrics').mockRejectedValue(new Error('offline'))
    renderPage()
    expect(await screen.findByText('读取防护状态失败')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: inventory.name })).toBeInTheDocument()
  })

  it.each([
    ['tenant scope', platform({ scope_kind: 'tenant', tenant_id: '22222222-2222-4222-8222-222222222222' })],
    ['platform carrying tenant identity', platform({ tenant_id: '22222222-2222-4222-8222-222222222222' })],
    ['missing nodes.read', platform({ permissions: [] })],
    ['missing scope', platform({ scope_id: '' })],
    ['whitespace-only scope', platform({ scope_id: ' \t ' })],
    ['missing user', platform({ user_id: '' })],
    ['whitespace-only user', platform({ user_id: ' \t ' })],
  ])('denies %s locally without a request', async (_name, actor) => {
    authenticate(actor)
    const get = vi.spyOn(nodesApi, 'get')

    renderPage()

    expect(await screen.findByText('无权查看节点详情')).toBeInTheDocument()
    expect(get).not.toHaveBeenCalled()
  })

  it('fails closed for a zero session epoch and invalid route identifier', async () => {
    authenticate()
    useSessionStore.setState({ sessionEpoch: 0 })
    const get = vi.spyOn(nodesApi, 'get')
    const first = renderPage()
    expect(await screen.findByText('无权查看节点详情')).toBeInTheDocument()
    expect(get).not.toHaveBeenCalled()
    first.unmount()

    authenticate()
    renderPage('/node/list/not-a-node')
    expect(await screen.findByText('节点详情不存在')).toBeInTheDocument()
    expect(get).not.toHaveBeenCalled()
  })

  it('renders loading and the confirmed inventory and presence details', async () => {
    authenticate()
    const pending = deferred<NodeInventoryItem>()
    vi.spyOn(nodesApi, 'get').mockReturnValue(pending.promise)

    renderPage()
    expect(await screen.findByLabelText('正在加载节点详情')).toHaveAttribute('aria-busy', 'true')
    await act(async () => pending.resolve(inventory))

    expect(await screen.findByRole('heading', { name: inventory.name })).toBeInTheDocument()
    for (const value of [
      nodeID, '主服务节点', 'CN-East', '192.0.2.10', '2001:db8::10', '在线', '2.4.1',
      '会话 7 / 心跳 11', '投影新鲜', '租约有效', '版本 4',
    ]) expect(screen.getByText(value)).toBeInTheDocument()
  })

  it.each([
    ['probe_only', '仅探测'], ['join_market', '加入市场'], ['disabled', '关闭'],
  ] as const)('shows market probe role %s', async (role, label) => {
    authenticate()
    vi.spyOn(nodesApi, 'get').mockResolvedValue({ ...inventory, presence: { ...inventory.presence, market_probe_role: role } })

    renderPage()
    expect(await screen.findByText('市场探测')).toBeInTheDocument()
    expect(screen.getByText(label)).toBeInTheDocument()
  })

  it.each([
    [new ApiError('raw forbidden detail', 403, 'permission_denied'), '无权查看节点详情'],
    [new ApiError('raw missing detail', 404, 'node_not_found'), '节点详情不存在'],
  ])('maps terminal errors without exposing raw messages', async (error, expected) => {
    authenticate()
    vi.spyOn(nodesApi, 'get').mockRejectedValue(error)

    renderPage()

    expect(await screen.findByText(expected)).toBeInTheDocument()
    expect(document.body.textContent).not.toContain(error.message)
  })

  it('localizes an ordinary failure and retries to recovery', async () => {
    authenticate()
    const get = vi.spyOn(nodesApi, 'get')
      .mockRejectedValueOnce(new ApiError('private inventory outage', 503, 'node_inventory_unavailable'))
      .mockResolvedValueOnce(inventory)
    const user = userEvent.setup()
    renderPage()

    expect(await screen.findByText('节点详情暂不可用，请稍后重试')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('private inventory outage')
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByRole('heading', { name: inventory.name })).toBeInTheDocument()
    expect(get).toHaveBeenCalledTimes(2)
  })

  it('localizes an invalid detail response and retries without exposing parser wording', async () => {
    authenticate()
    const get = vi.spyOn(nodesApi, 'get')
      .mockRejectedValueOnce(new ApiError('Invalid node inventory response for private upstream', 200, 'invalid_response'))
      .mockResolvedValueOnce(inventory)
    const user = userEvent.setup()
    renderPage()

    expect(await screen.findByText('节点详情响应无效，请重试')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('Invalid node inventory response')
    expect(document.body.textContent).not.toContain('private upstream')
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByRole('heading', { name: inventory.name })).toBeInTheDocument()
    expect(get).toHaveBeenCalledTimes(2)
  })

  it('preserves detail and a token-free query identity across same-epoch token refresh', async () => {
    const actor = authenticate()
    const get = vi.spyOn(nodesApi, 'get').mockResolvedValue(inventory)
    const { queryClient } = renderPage()
    const user = userEvent.setup()
    expect(await screen.findByRole('heading', { name: inventory.name })).toBeInTheDocument()
    const epoch = useSessionStore.getState().sessionEpoch

    act(() => authenticate(actor, 'refreshed-node-token', 'refresh'))
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(get).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('heading', { name: inventory.name })).toBeInTheDocument()
    const keys = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey))
    expect(keys).not.toContain('node-detail-token')
    expect(keys).not.toContain('refreshed-node-token')

    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(get).toHaveBeenLastCalledWith('refreshed-node-token', nodeID))
  })

  it('clears old owner cache and ignores a delayed response after a new session', async () => {
    const actorA = authenticate(platform({ user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }))
    const oldRead = deferred<NodeInventoryItem>()
    const get = vi.spyOn(nodesApi, 'get')
      .mockReturnValueOnce(oldRead.promise)
      .mockResolvedValueOnce({ ...inventory, name: '新会话节点' })
    const { queryClient } = renderPage()
    expect(await screen.findByLabelText('正在加载节点详情')).toBeInTheDocument()

    const actorB = platform({ user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' })
    act(() => authenticate(actorB, 'new-session-token'))
    expect(await screen.findByRole('heading', { name: '新会话节点' })).toBeInTheDocument()
    await act(async () => oldRead.resolve({ ...inventory, name: '迟到旧节点' }))
    expect(screen.queryByText('迟到旧节点')).not.toBeInTheDocument()
    const keys = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey))
    expect(keys).not.toContain(actorA.user_id)
    expect(keys).toContain(actorB.user_id)
    expect(get).toHaveBeenCalledTimes(2)
  })

  it('lets a node manager create a transition and exposes durable actions', async () => {
    authenticate(platform({ permissions: ['nodes.read', 'nodes.manage'] }))
    vi.spyOn(nodesApi, 'get').mockResolvedValue(inventory)
    const create = vi.spyOn(nodesApi, 'createGatewayPortTransition').mockResolvedValue(switchedTransition)
    const user = userEvent.setup()
    renderPage()

    await screen.findByRole('heading', { name: inventory.name })
    await user.click(screen.getByRole('button', { name: '切换通信端口' }))
    await user.type(screen.getByLabelText('旧公开地址'), 'gateway.example.com:7443')
    await user.type(screen.getByLabelText('旧监听地址'), '0.0.0.0:7443')
    await user.type(screen.getByLabelText('旧服务名'), 'gateway.example.com')
    await user.type(screen.getByLabelText('新公开地址'), 'gateway.example.com:8443')
    await user.type(screen.getByLabelText('新监听地址'), '0.0.0.0:8443')
    await user.type(screen.getByLabelText('新服务名'), 'gateway.example.com')
    await user.click(screen.getByRole('button', { name: '创建切换' }))

    expect(create).toHaveBeenCalledWith('node-detail-token', nodeID, expect.objectContaining({ expected_node_revision: 4 }), expect.any(String))
    expect(await screen.findByText('已切换')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '最终确认' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '回滚' })).toBeInTheDocument()
  })
})
