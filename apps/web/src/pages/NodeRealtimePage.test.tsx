import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { init as initChart } from '../components/echartsRuntime'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'

import { ApiError, type Principal } from '../api/auth'
import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import { resetSessionStore, useSessionStore } from '../auth/session'
import { RouteErrorBoundary } from '../components/RouteErrorBoundary'
import i18n from '../i18n'
import { authResponse, nodeManagementSettingsFixture, principal } from '../test/fixtures'
import nodeRealtimeCSS from './NodeRealtimePage.css?raw'
import NodeRealtimePage from './NodeRealtimePage'
import nodeRealtimeSource from './NodeRealtimePage.tsx?raw'

const chartMocks = vi.hoisted(() => ({ setOption: vi.fn(), resize: vi.fn(), dispose: vi.fn() }))
vi.mock('../components/echartsRuntime')

const node: NodeInventoryItem = {
  id: '018f0000-0000-7000-8000-000000000001',
  display_id: '1',
  name: '上海边缘节点',
  description: 'primary edge',
  region: 'CN-East',
  ipv4: '192.0.2.10',
  admin_state: 'active',
  management_settings: nodeManagementSettingsFixture(),
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
    projected_at: '2026-07-22T08:59:56Z',
  },
}

const metrics = {
  node_id: node.id,
  node_name: node.name,
  config_revision: 7,
  active_config_revision: 7,
  publication_sequence: 41,
  observed_at: '2026-07-22T08:59:58Z',
  probe_port: 8443,
  healthy: false,
  probe_succeeded: true,
  consecutive_failures: 0,
  consecutive_successes: 2,
  probes_total: 9,
  probe_failures_total: 4,
  recovered: false,
  recovery_notified: false,
  rolled_back: false,
  known: true,
  cpu_percent: 25,
  memory_used_bytes: 512,
  memory_total_bytes: 1024,
  active_connections: 8,
  rx_bandwidth_bps: 1600,
  tx_bandwidth_bps: 800,
  total_rx_bytes: null,
  total_tx_bytes: null,
  puback_stream: 'NODE_MONITORING_STATUS' as const,
  puback_sequence: 91,
  consumer_durable: 'control_api_node_metrics' as const,
  consumer_sequence: 17,
  ingested_at: '2026-07-22T08:59:59Z',
  latest_recovery: {
    config_revision: 6,
    publication_sequence: 40,
    recovered_at: '2026-07-22T08:58:00Z',
    reason_code: 'probe_recovered' as const,
    puback_stream: 'NODE_MONITORING_STATUS' as const,
    puback_sequence: 90,
  },
}

function admin(overrides: Partial<Principal> = {}) {
  return principal({
    scope_kind: 'platform',
    tenant_id: null,
    roles: ['platform_owner'],
    permissions: ['nodes.read'],
    ...overrides,
  })
}

function authenticate(actor = admin(), token = 'node-realtime-token', update?: 'new' | 'refresh') {
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor, update)
  return useSessionStore.getState().sessionEpoch
}

function renderPage(queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false, gcTime: Infinity },
    mutations: { retry: false, gcTime: Infinity },
  },
})) {
  if (!vi.isMockFunction(nodesApi.getLatestMetricsBatch)) {
    vi.spyOn(nodesApi, 'getLatestMetricsBatch').mockImplementation(async (_token, ids) => (
      { observed_at: '2026-07-22T09:00:00Z', items: [], not_reported_node_ids: [...ids] }))
  }
  // 页面只用批量接口；单节点接口一旦被调用就是回归到 N+1。
  if (!vi.isMockFunction(nodesApi.getLatestMetrics)) {
    vi.spyOn(nodesApi, 'getLatestMetrics').mockRejectedValue(new Error('per-node latest metrics must not be read'))
  }
  if (!vi.isMockFunction(nodesApi.getMetricsHistory)) {
    vi.spyOn(nodesApi, 'getMetricsHistory').mockResolvedValue({ items: [] })
  }
  const result = render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/node/realtime']}>
            <NodeRealtimePage />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
  return { ...result, queryClient }
}

type LatestMetrics = Awaited<ReturnType<typeof nodesApi.getLatestMetrics>>

/** Serves GET /v1/nodes/metrics/latest from a per-node answer (undefined = not reported). */
function mockLatest(answer: (nodeID: string, call: number) => LatestMetrics | undefined) {
  let call = 0
  return vi.spyOn(nodesApi, 'getLatestMetricsBatch').mockImplementation(async (_token, ids) => {
    call += 1
    const items: LatestMetrics[] = []
    const missing: string[] = []
    for (const id of ids) {
      const value = answer(id, call)
      if (value) items.push(value)
      else missing.push(id)
    }
    return { observed_at: '2026-07-22T09:00:00Z', items, not_reported_node_ids: missing }
  })
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

describe('NodeRealtimePage', () => {
  beforeEach(async () => {
    resetSessionStore()
    await i18n.changeLanguage('zh-CN')
    vi.mocked(initChart).mockReturnValue(chartMocks as unknown as ReturnType<typeof initChart>)
  })

  it('renders translated views without falling into the route 500 boundary', async () => {
    authenticate()
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [] })

    render(
      <ConfigProvider button={{ autoInsertSpace: false }}>
        <AntApp>
          <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
            <MemoryRouter initialEntries={['/node/realtime']}>
              <RouteErrorBoundary>
                <NodeRealtimePage />
              </RouteErrorBoundary>
            </MemoryRouter>
          </QueryClientProvider>
        </AntApp>
      </ConfigProvider>,
    )

    expect(await screen.findByText('节点实时监控')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '资源排行' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '监控指标' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '节点流量' })).toBeInTheDocument()
    expect(screen.queryByText('500')).not.toBeInTheDocument()
    expect(screen.queryByText('服务异常')).not.toBeInTheDocument()
  })

  it.each([
    ['tenant scope', admin({ scope_kind: 'tenant', tenant_id: '22222222-2222-4222-8222-222222222222' })],
    ['platform scope carrying tenant identity', admin({ tenant_id: '22222222-2222-4222-8222-222222222222' })],
    ['missing read permission', admin({ permissions: ['nodes.manage'] })],
    ['missing scope identity', admin({ scope_id: '' })],
    ['blank scope identity', admin({ scope_id: '   ' })],
    ['missing user identity', admin({ user_id: '' })],
    ['blank user identity', admin({ user_id: '   ' })],
  ])('renders a local 403 with zero requests for %s', async (_name, actor) => {
    authenticate(actor)
    const listSpy = vi.spyOn(nodesApi, 'list')

    renderPage()

    expect(await screen.findByText('无权查看节点实时状态')).toBeInTheDocument()
    expect(listSpy).not.toHaveBeenCalled()
  })

  it('fails closed for a zero session epoch and accepts platform.admin as a read wildcard', async () => {
    authenticate()
    useSessionStore.setState({ sessionEpoch: 0 })
    const listSpy = vi.spyOn(nodesApi, 'list')
    const { unmount } = renderPage()
    expect(await screen.findByText('无权查看节点实时状态')).toBeInTheDocument()
    expect(listSpy).not.toHaveBeenCalled()
    unmount()

    authenticate(admin({ permissions: ['platform.admin'] }))
    listSpy.mockResolvedValue({ items: [] })
    renderPage()
    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    expect(listSpy).toHaveBeenCalledTimes(1)
  })

  it('renders natural loading, empty, localized error, and retry recovery states', async () => {
    authenticate()
    const first = deferred<{ items: NodeInventoryItem[] }>()
    vi.spyOn(nodesApi, 'list')
      .mockReturnValueOnce(first.promise)
      .mockRejectedValueOnce(new ApiError('raw private service message', 503, 'node_inventory_unavailable'))
      .mockResolvedValueOnce({ items: [node] })
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByLabelText('正在加载节点实时状态')).toBeInTheDocument()

    await act(async () => first.resolve({ items: [] }))
    expect(await screen.findByText('暂无数据')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('节点实时状态暂不可用，请稍后重试')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw private service message')

    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText(`${node.name} (${node.display_id})`)).toBeInTheDocument()
  })

  it('keeps the empty competitor table to five observed columns with the reference controls', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [] })

    renderPage()

    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '刷新' })).toHaveClass('ant-btn-primary')
    expect(screen.getByRole('tab', { name: '资源排行' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: '监控指标' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '节点流量' })).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: '带宽' })).toHaveAttribute('value', 'bandwidth')
    expect(screen.getByRole('radio', { name: '1分钟' })).toHaveAttribute('value', '1m')
    expect(screen.queryByRole('button', { name: '上一页' })).not.toBeInTheDocument()

    const user = userEvent.setup()
    await user.click(screen.getByRole('tab', { name: '资源排行' }))
    expect(screen.getAllByRole('columnheader').map((header) => header.textContent?.trim())).toEqual([
      '排行', '节点', '网卡', '出站带宽', '入站带宽',
    ])
    expect(nodeRealtimeSource).toContain("title: t('columns.rank'), key: 'rank', width: 100")
    expect(nodeRealtimeSource).toContain("title: t('columns.name'), key: 'name', width: 180")
    expect(nodeRealtimeSource).toContain("title: t('columns.nic'), key: 'nic', width: 100")
    expect(nodeRealtimeSource).toContain("sortable(t('columns.egressBandwidth')")
    expect(nodeRealtimeSource).toContain("sortable(t('columns.ingressBandwidth')")

    const mobileCSS = nodeRealtimeCSS.slice(nodeRealtimeCSS.indexOf('@media (max-width: 767px)'))
    expect(nodeRealtimeCSS).toMatch(/\.node-realtime-tabs \.ant-tabs-tab \+ \.ant-tabs-tab\s*\{[\s\S]*?margin-left:\s*0 !important;/)
    expect(nodeRealtimeCSS).toMatch(/\.node-realtime-control-label\s*\{[\s\S]*?flex:\s*0 0 60px;/)
    expect(nodeRealtimeCSS).toMatch(/\.node-realtime-refresh\s*\{[\s\S]*?width:\s*78px;/)
    expect(mobileCSS).toMatch(/\.node-realtime-page\s*\{[\s\S]*?padding:\s*18px 20px 20px;/)
    expect(mobileCSS).toMatch(/\.node-realtime-tabs \.ant-tabs-nav-operations\s*\{[\s\S]*?display:\s*none !important;/)
    expect(mobileCSS).toMatch(/\.node-realtime-tabs \.ant-tabs-nav-list\s*\{[\s\S]*?min-width:\s*100%;[\s\S]*?transform:\s*none !important;/)
    expect(nodeRealtimeCSS).toMatch(/\.node-realtime-table-scroll \.ant-table-placeholder \.ant-table-cell\s*\{[\s\S]*?height:\s*48px;/)
  })

  it('switches to the competitor-specific monitoring and traffic controls', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [] })
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByText('暂无数据')).toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: '监控指标' }))
    expect(screen.getByRole('tab', { name: '监控指标' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('radio', { name: '1小时' })).toBeChecked()
    expect(screen.getByRole('radio', { name: '6小时' })).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: '12小时' })).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: '自定义' })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '节点' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: '节点监控指标' })).toBeInTheDocument()
    expect(screen.getByText('暂无节点流量数据')).toBeInTheDocument()
    expect(screen.queryByRole('columnheader')).not.toBeInTheDocument()

    await user.click(screen.getByText('自定义'))
    // fix-rangepicker：自定义为共享组件的双月面板；fix-nicinline2：由「自定义」按钮直接弹出，不在筛选条里加输入框。
    expect(screen.getByRole('dialog', { name: '选择时间范围' })).toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: '选择时间范围' })).not.toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: '节点流量' }))
    expect(screen.getByRole('tab', { name: '节点流量' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('checkbox', { name: '出站流量' })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: '入站流量' })).not.toBeChecked()
    // 节点流量快捷项统一为今天/近7天/近30天，默认今天（监控曲线保留小时级）。
    expect(screen.getByRole('radio', { name: '今天' })).toBeChecked()
    expect(screen.getByRole('radio', { name: '近7天' })).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: '近30天' })).toBeInTheDocument()
    expect(screen.getByPlaceholderText('排除网卡，多个网卡用空格分隔')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: '节点流量' })).toBeInTheDocument()
    expect(screen.getByText('总流量：未上报')).toBeInTheDocument()
    expect(screen.queryByRole('columnheader')).not.toBeInTheDocument()
  })

  it('loads real metric history for the selected node and renders the monitoring chart state', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const historySpy = vi.spyOn(nodesApi, 'getMetricsHistory').mockResolvedValue({
      items: [{
        node_id: node.id,
        node_name: node.name,
        publication_sequence: 41,
        observed_at: '2026-07-22T08:59:58Z',
        known: true,
        cpu_percent: 25,
        memory_used_bytes: 512,
        memory_total_bytes: 1024,
        active_connections: 8,
        rx_bandwidth_bps: 1600,
        tx_bandwidth_bps: 800,
        total_rx_bytes: null,
        total_tx_bytes: null,
      }],
    })
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByText(`${node.name} (${node.display_id})`)).toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: '监控指标' }))

    await user.click(screen.getByRole('checkbox', { name: '自动选择出口网卡' }))
    expect(await screen.findByRole('region', { name: '节点监控指标' })).toBeInTheDocument()
    await waitFor(() => expect(historySpy).toHaveBeenCalledWith(
      'node-realtime-token', node.id, expect.objectContaining({ limit: 2000 }),
    ))
    expect(screen.queryByText('暂无节点流量数据')).not.toBeInTheDocument()
  })

  it('uses the durable realtime series endpoint for monitoring charts', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const realtimeSpy = vi.spyOn(nodesApi, 'getNodeRealtimeSeries').mockResolvedValue({
      data: { eth0: [{ name: 'inbound', data: [[1721638798000, 1600]] }] },
      msg: '',
      code: 0,
    })
    const user = userEvent.setup()

    renderPage()
    await screen.findByText(`${node.name} (${node.display_id})`)
    await user.click(screen.getByRole('tab', { name: '监控指标' }))

    await waitFor(() => expect(realtimeSpy).toHaveBeenCalledWith(
      'node-realtime-token', expect.objectContaining({ node: node.id, type: 'bandwidth', limit: 2000 }),
    ))
    const realtimeParams = realtimeSpy.mock.calls[0]?.[1]
    expect(realtimeParams).toBeDefined()
    expect(new Date(realtimeParams!.end).getTime() - new Date(realtimeParams!.start).getTime()).toBe(60 * 60 * 1000)
    expect(screen.getByRole('img', { name: '节点监控指标' })).toBeInTheDocument()
  })

  it.each(['zh-CN', 'en-US', 'qps-ploc'])('keeps distinct timestamps with compact %s ticks and exact tooltip time', async (language) => {
    authenticate()
    await i18n.changeLanguage(language)
    chartMocks.setOption.mockClear()
    const first = Date.parse('2026-10-09T10:01:14Z')
    const second = Date.parse('2026-10-09T10:01:44Z')
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    vi.spyOn(nodesApi, 'getNodeRealtimeSeries').mockResolvedValue({
      data: { ens17: [{ name: 'inbound', data: [[first, 1600], [second, 1700]] }] }, msg: '', code: 0,
    })
    const user = userEvent.setup()
    renderPage()
    await screen.findByText(i18n.t('nodeRealtime:columns.nodeDisplay', { name: node.name, id: node.display_id }))
    await user.click(screen.getByRole('tab', { name: i18n.t('nodeRealtime:views.monitoring') }))
    await waitFor(() => expect(chartMocks.setOption).toHaveBeenCalled())
    const options = chartMocks.setOption.mock.lastCall![0]
    expect(options.xAxis.data).toEqual([first, second])
    expect(options.series[0].data).toEqual([1600, 1700])
    const expectedTick = new Intl.DateTimeFormat(language === 'en-US' ? 'en-US' : 'zh-CN', {
      timeZone: 'Asia/Shanghai', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
    }).format(new Date(first))
    expect(options.xAxis.axisLabel.formatter(String(first))).toBe(expectedTick)
    expect(options.xAxis.axisLabel.formatter(String(second))).toBe(expectedTick)
    expect(options.xAxis.axisLabel).toMatchObject({
      hideOverlap: true, alignMinLabel: 'left', alignMaxLabel: 'right', showMinLabel: true, showMaxLabel: true,
    })
    const fullTime = options.xAxis.axisPointer.label.formatter({ value: String(first) })
    expect(fullTime).toContain('2026')
    expect(fullTime).toContain('18:01:14')
    expect(options.tooltip.confine).toBe(true)
  })

  it.each([
    ['监控指标', 'getNodeRealtimeSeries', '节点监控指标'],
    ['节点流量', 'getNodeTraffic', '节点流量'],
  ] as const)('shows %s request loading and retries its primary API without hiding errors behind history', async (tab, method, chartName) => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const pending = deferred<never>()
    const retry = deferred<never>()
    const request = vi.spyOn(nodesApi, method)
      .mockReturnValueOnce(pending.promise)
      .mockReturnValueOnce(retry.promise)
    const history = vi.spyOn(nodesApi, 'getMetricsHistory').mockResolvedValue({ items: [] })
    const inactive = vi.spyOn(nodesApi, method === 'getNodeTraffic' ? 'getNodeRealtimeSeries' : 'getNodeTraffic')
    const user = userEvent.setup()
    renderPage()
    await screen.findByText(`${node.name} (${node.display_id})`)
    await user.click(screen.getByRole('tab', { name: tab }))
    expect(await screen.findByLabelText('正在加载节点监控历史')).toBeInTheDocument()
    expect(screen.queryByText('暂无节点流量数据')).not.toBeInTheDocument()
    await act(async () => pending.reject(new Error('private connection closed')))
    expect(await screen.findByRole('alert')).toHaveTextContent('节点探测与指标加载失败，请重试')
    expect(screen.queryByText('暂无节点流量数据')).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain('private connection closed')
    expect(history).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: '重试' }))
    await waitFor(() => expect(request).toHaveBeenCalledTimes(2))
    expect(await screen.findByLabelText('正在加载节点监控历史')).toBeInTheDocument()
    expect(inactive).not.toHaveBeenCalled()
    await act(async () => retry.reject(new Error('still closed')))
    expect(await screen.findByRole('alert')).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: chartName })).not.toBeInTheDocument()
    request.mockResolvedValue(method === 'getNodeTraffic'
      ? { count: 1, data: [{ bytes_received: 100, bytes_sent: 200, create_at: '2026-10-09 10:01:14' }], msg: '', code: 0 }
      : { data: { ens17: [{ name: 'inbound', data: [[Date.parse('2026-10-09T10:01:14Z'), 1600]] }] }, msg: '', code: 0 })
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByRole('img', { name: chartName })).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('retries both monitoring sources when history fallback is usable and keeps the selected metric', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const realtime = vi.spyOn(nodesApi, 'getNodeRealtimeSeries').mockImplementation(async (_token, params) => {
      if (params.type === 'bandwidth') return { data: {}, msg: '', code: 0 }
      throw new Error('realtime closed')
    })
    const history = vi.spyOn(nodesApi, 'getMetricsHistory').mockRejectedValue(new Error('history closed'))
    const user = userEvent.setup()
    renderPage()
    await screen.findByText(`${node.name} (${node.display_id})`)
    await user.click(screen.getByRole('tab', { name: '监控指标' }))
    await user.click(screen.getByText('连接', { exact: true }))
    expect(await screen.findByRole('alert')).toBeInTheDocument()
    const before = realtime.mock.calls.length
    history.mockResolvedValue({ items: [{ ...metrics, total_rx_bytes: 100, total_tx_bytes: 200 }] })
    await user.click(screen.getByRole('button', { name: '重试' }))
    await waitFor(() => expect(realtime.mock.calls.length).toBeGreaterThan(before))
    expect(realtime).toHaveBeenLastCalledWith('node-realtime-token', expect.objectContaining({ type: 'connections' }))
    expect(history.mock.calls.length).toBeGreaterThan(1)
    expect(await screen.findByRole('img', { name: '节点监控指标' })).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('waits for traffic history, reports its failure, and retries the active traffic sources', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const traffic = vi.spyOn(nodesApi, 'getNodeTraffic').mockRejectedValue(new Error('traffic unavailable'))
    const realtime = vi.spyOn(nodesApi, 'getNodeRealtimeSeries')
    const pending = deferred<never>()
    const history = vi.spyOn(nodesApi, 'getMetricsHistory').mockReturnValueOnce(pending.promise)
    const user = userEvent.setup()
    renderPage()
    await screen.findByText(`${node.name} (${node.display_id})`)
    await user.click(screen.getByRole('checkbox', { name: '自动选择出口网卡' }))
    await user.click(screen.getByRole('tab', { name: '节点流量' }))
    await waitFor(() => expect(history).toHaveBeenCalledTimes(1))
    expect(screen.getByLabelText('正在加载节点监控历史')).toBeInTheDocument()
    await act(async () => pending.reject(new ApiError('private history error', 503, 'node_metrics_unavailable')))
    expect(await screen.findByRole('alert')).toHaveTextContent('节点探测与指标暂不可用，请稍后重试')
    history.mockResolvedValue({ items: [
      { ...metrics, observed_at: '2026-10-09T10:00:00Z', total_rx_bytes: 100, total_tx_bytes: 200 },
      { ...metrics, observed_at: '2026-10-09T10:01:00Z', total_rx_bytes: 150, total_tx_bytes: 260 },
    ] })
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('60 B')).toBeInTheDocument()
    expect(traffic).toHaveBeenCalledTimes(2)
    expect(history.mock.calls.length).toBeGreaterThan(1)
    expect(realtime).not.toHaveBeenCalled()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it.each([
    [401, '节点探测与指标加载失败，请重试'],
    [403, '无权查看该节点探测与指标'],
    [429, '请求过于频繁，请稍后重试'],
  ])('does not fall back to history after a primary %i response', async (status, message) => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    vi.spyOn(nodesApi, 'getNodeRealtimeSeries').mockRejectedValue(new ApiError('private denial', status, 'denied'))
    const history = vi.spyOn(nodesApi, 'getMetricsHistory').mockResolvedValue({ items: [metrics] })
    const user = userEvent.setup()
    renderPage()
    await screen.findByText(`${node.name} (${node.display_id})`)
    await user.click(screen.getByRole('tab', { name: '监控指标' }))
    await user.click(screen.getByText('连接', { exact: true }))
    expect(await screen.findByRole('alert')).toHaveTextContent(message)
    expect(history).not.toHaveBeenCalled()
    expect(screen.queryByRole('region', { name: '节点监控指标' })).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain('private denial')
  })

  it('does not replace the active traffic loading or successful empty state with a late monitoring error', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const monitoring = deferred<never>()
    vi.spyOn(nodesApi, 'getNodeRealtimeSeries').mockReturnValue(monitoring.promise)
    const traffic = deferred<Awaited<ReturnType<typeof nodesApi.getNodeTraffic>>>()
    vi.spyOn(nodesApi, 'getNodeTraffic').mockReturnValue(traffic.promise)
    const history = vi.spyOn(nodesApi, 'getMetricsHistory').mockResolvedValue({ items: [] })
    const user = userEvent.setup()
    renderPage()
    await screen.findByText(`${node.name} (${node.display_id})`)
    await user.click(screen.getByRole('tab', { name: '监控指标' }))
    await user.click(screen.getByRole('tab', { name: '节点流量' }))
    await act(async () => monitoring.reject(new Error('late monitor failure')))
    expect(screen.getByLabelText('正在加载节点监控历史')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    await act(async () => traffic.resolve({ count: 0, data: [], code: 0, msg: '' }))
    expect(await screen.findByText('暂无节点流量数据')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(history).not.toHaveBeenCalled()
  })

  it('gives every visible filter input a stable identity and preserves full selected node names', async () => {
    authenticate()
    const longName = `install-${node.id}`
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [{ ...node, name: longName }] })
    const user = userEvent.setup()
    const { container } = renderPage()
    await screen.findByText(`${longName} (${node.display_id})`)
    for (const tab of ['资源排行', '监控指标', '节点流量']) {
      await user.click(screen.getByRole('tab', { name: tab }))
      if (tab !== '资源排行') {
        await user.click(screen.getByText('自定义', { exact: true }))
        expect(screen.getByTitle(longName)).toBeInTheDocument()
      }
      for (const input of container.querySelectorAll('input')) {
        expect(input.id || input.name).toMatch(/^node-realtime-/)
      }
    }
  })

  it('renders load telemetry as the competitor CPU, memory, and system-load charts', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const realtimeSpy = vi.spyOn(nodesApi, 'getNodeRealtimeSeries').mockResolvedValue({
      data: {
        all: [
          { name: 'cpu', data: [[1721638798000, 25]] },
          { name: 'system_load', data: [[1721638798000, 1.25]] },
          { name: 'memory', data: [[1721638798000, 50]] },
        ],
      },
      msg: '',
      code: 0,
    })
    const user = userEvent.setup()

    renderPage()
    await screen.findByText(`${node.name} (${node.display_id})`)
    await user.click(screen.getByRole('tab', { name: '监控指标' }))
    await user.click(screen.getByText('负载', { exact: true }))

    await waitFor(() => expect(realtimeSpy).toHaveBeenCalledWith(
      'node-realtime-token', expect.objectContaining({ node: node.id, type: 'load', limit: 2000 }),
    ))
    expect(screen.getAllByRole('region', { name: '节点监控指标' })).toHaveLength(3)
  })

  it('uses interval traffic bytes for the traffic total and chart', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const trafficSpy = vi.spyOn(nodesApi, 'getNodeTraffic').mockResolvedValue({
      count: 1,
      data: [{ bytes_received: 1024, bytes_sent: 2048, create_at: '2026-07-22 09:00:00' }],
      msg: '',
      code: 0,
    })
    const user = userEvent.setup()

    renderPage()
    await screen.findByText(`${node.name} (${node.display_id})`)
    await user.click(screen.getByRole('tab', { name: '节点流量' }))

    await waitFor(() => expect(trafficSpy).toHaveBeenCalledWith(
      'node-realtime-token', expect.objectContaining({ node: node.id, excludedNIC: '', limit: 2000 }),
    ))
    expect(screen.getByText('2 KB')).toBeInTheDocument()
    expect(screen.getByRole('img', { name: '节点流量' })).toBeInTheDocument()
  })

  it('derives traffic intervals from two or more history snapshots when the interval API is unavailable', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    vi.spyOn(nodesApi, 'getNodeTraffic').mockRejectedValue(
      new ApiError('interval traffic unavailable', 503, 'node_metrics_unavailable'),
    )
    vi.spyOn(nodesApi, 'getMetricsHistory').mockResolvedValue({
      items: [
        { ...metrics, observed_at: '2026-07-22T08:58:00Z', publication_sequence: 40, total_rx_bytes: 100, total_tx_bytes: 200 },
        { ...metrics, observed_at: '2026-07-22T08:59:00Z', publication_sequence: 41, total_rx_bytes: 150, total_tx_bytes: 260 },
        { ...metrics, observed_at: '2026-07-22T09:00:00Z', publication_sequence: 42, total_rx_bytes: 8, total_tx_bytes: 12 },
      ],
    })
    const user = userEvent.setup()

    renderPage()
    await screen.findByText(`${node.name} (${node.display_id})`)
    await user.click(screen.getByRole('tab', { name: '节点流量' }))
    await user.click(screen.getByRole('checkbox', { name: '自动选择出口网卡' }))

    expect(await screen.findByText('72 B')).toBeInTheDocument()
    expect(screen.getByRole('img', { name: '节点流量' })).toBeInTheDocument()
  })

  it('does not display cumulative traffic from a single history snapshot', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    vi.spyOn(nodesApi, 'getNodeTraffic').mockRejectedValue(
      new ApiError('interval traffic unavailable', 503, 'node_metrics_unavailable'),
    )
    vi.spyOn(nodesApi, 'getMetricsHistory').mockResolvedValue({
      items: [{ ...metrics, total_rx_bytes: 100, total_tx_bytes: 200 }],
    })
    const user = userEvent.setup()

    renderPage()
    await screen.findByText(`${node.name} (${node.display_id})`)
    await user.click(screen.getByRole('tab', { name: '节点流量' }))
    await user.click(screen.getByRole('checkbox', { name: '自动选择出口网卡' }))

    expect(await screen.findByText('总流量：未上报')).toBeInTheDocument()
    expect(screen.getByText('暂无节点流量数据')).toBeInTheDocument()
    expect(screen.queryByText('200 B')).not.toBeInTheDocument()
  })

  it('keeps an empty interval response unsettled instead of showing zero traffic', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const trafficSpy = vi.spyOn(nodesApi, 'getNodeTraffic').mockResolvedValue({
      count: 0,
      data: [],
      msg: '',
      code: 0,
    })
    const user = userEvent.setup()

    renderPage()
    await screen.findByText(`${node.name} (${node.display_id})`)
    await user.click(screen.getByRole('tab', { name: '节点流量' }))

    await waitFor(() => expect(trafficSpy).toHaveBeenCalled())
    expect(screen.getByText('总流量：未上报')).toBeInTheDocument()
    expect(screen.getByText('暂无节点流量数据')).toBeInTheDocument()
  })

  it('matches the competitor shell and loads the resource table without pagination', async () => {
    authenticate()
    const second = { ...node, id: '018f0000-0000-7000-8000-000000000002', name: '北京边缘节点' }
    const listSpy = vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node, second] })
    const user = userEvent.setup()

    renderPage()
    await user.click(screen.getByRole('tab', { name: '资源排行' }))
    const row = (await screen.findByText(`${node.name} (${node.display_id})`)).closest('tr')!
    expect(within(row).getByText('1')).toBeInTheDocument()
    expect(within(row).getAllByText('未上报')).toHaveLength(2)
    expect(within(row).getByText('出口未确认')).toBeInTheDocument()
    expect(within(row).getAllByRole('cell')).toHaveLength(5)

    expect(screen.queryByRole('combobox', { name: '筛选管理状态' })).not.toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: '筛选在线状态' })).not.toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: '每页数量' })).not.toBeInTheDocument()
    expect(await screen.findByText(`${second.name} (${second.display_id})`)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '下一页' })).not.toBeInTheDocument()
    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith(
      'node-realtime-token',
      { status: undefined, presence: undefined, limit: 300 },
    ))
  })

  it('reads every inventory page past 300 nodes and asks latest metrics in batches of 300', async () => {
    authenticate()
    const many = Array.from({ length: 301 }, (_, index) => ({
      ...node, id: `018f0000-0000-7000-8000-${String(index + 1).padStart(12, '0')}`, display_id: String(index + 1), name: `节点${index + 1}`,
    }))
    const listSpy = vi.spyOn(nodesApi, 'list').mockImplementation(async (_token, params) => params.cursor === 'p2'
      ? { items: many.slice(300) }
      : { items: many.slice(0, 300), next_cursor: 'p2' })
    const batchSpy = mockLatest((id) => id === many[300]!.id ? { ...metrics, node_id: id, node_name: many[300]!.name } : undefined)
    const user = userEvent.setup()

    renderPage()
    await user.click(screen.getByRole('tab', { name: '资源排行' }))
    await waitFor(() => expect(batchSpy).toHaveBeenCalledTimes(2))
    expect(listSpy).toHaveBeenCalledTimes(2)
    expect(listSpy.mock.calls[1]![1]).toMatchObject({ cursor: 'p2', limit: 300 })
    expect(batchSpy.mock.calls.map(([, ids]) => ids.length).sort()).toEqual([1, 300])
    expect(nodesApi.getLatestMetrics).not.toHaveBeenCalled()
    expect(await screen.findByText('节点301 (301)')).toBeInTheDocument()
  })

  it('keeps the reference five-column table backed by latest metrics', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const metricsSpy = mockLatest((_id, call) => call === 1 ? metrics : { ...metrics, tx_bandwidth_bps: 2400, rx_bandwidth_bps: 3200 })
    const user = userEvent.setup()

    renderPage()
    await user.click(screen.getByRole('tab', { name: '资源排行' }))
    await user.click(screen.getByRole('checkbox', { name: '自动选择出口网卡' }))
    const row = (await screen.findByText(`${node.name} (${node.display_id})`)).closest('tr')!
    expect(await within(row).findByText('800 bps')).toBeInTheDocument()
    expect(within(row).getByText('1.6 Kbps')).toBeInTheDocument()
    expect(within(row).getAllByText('未上报')).toHaveLength(1)

    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await within(row).findByText('2.4 Kbps')).toBeInTheDocument()
    expect(within(row).getByText('3.2 Kbps')).toBeInTheDocument()
    expect(metricsSpy).toHaveBeenCalledTimes(2)

    expect(within(row).getAllByRole('cell')).toHaveLength(5)
    expect(screen.queryByRole('button', { name: '查看探测与指标' })).not.toBeInTheDocument()
    expect(metricsSpy).toHaveBeenCalledWith('node-realtime-token', [node.id], expect.anything())
  })

  it('keeps inventory rows when the top ranking response is empty', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    vi.spyOn(nodesApi, 'getNodeRealtimeTop').mockResolvedValue({
      data: [],
      msg: '',
      code: 0,
    })
    const user = userEvent.setup()

    renderPage()
    await user.click(screen.getByRole('tab', { name: '资源排行' }))

    const row = (await screen.findByText(`${node.name} (${node.display_id})`)).closest('tr')!
    expect(within(row).getAllByText('未上报')).toHaveLength(2)
    expect(within(row).getByText('出口未确认')).toBeInTheDocument()
    expect(screen.queryByText('暂无数据')).not.toBeInTheDocument()
  })

  it('keeps separate ranking rows when one node reports multiple network interfaces', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    vi.spyOn(nodesApi, 'getNodeRealtimeTop').mockResolvedValue({
      data: [
        { node_id: node.id, node_name: node.name, nic: 'eth0', inbound: 1600, outbound: 800 },
        { node_id: node.id, node_name: node.name, nic: 'eth1', inbound: 400, outbound: 200 },
      ],
      msg: '',
      code: 0,
    })
    const user = userEvent.setup()

    renderPage()
    await user.click(screen.getByRole('tab', { name: '资源排行' }))

    expect(await screen.findByText('eth0')).toBeInTheDocument()
    expect(screen.getByText('eth1')).toBeInTheDocument()
    expect(screen.getAllByRole('row')).toHaveLength(3)
    expect(screen.getAllByText(`${node.name} (${node.display_id})`)).toHaveLength(2)
  })

  it('requests automatic egress selection by default and allows all NIC diagnostics', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const external = { node_id: node.id, node_name: node.name, nic: 'ens17', inbound: 1600, outbound: 800 }
    const internal = { ...external, nic: 'docker0', inbound: 99000, outbound: 88000 }
    const top = vi.spyOn(nodesApi, 'getNodeRealtimeTop').mockImplementation(async (_token, params) => ({
      data: params.externalOnly ? [external] : [internal, external], msg: '', code: 0,
    }))
    const user = userEvent.setup()
    renderPage()
    expect(await screen.findByText('ens17')).toBeInTheDocument()
    expect(screen.queryByText('docker0')).not.toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: '自动选择出口网卡' })).toBeChecked()
    expect(top).toHaveBeenCalledWith('node-realtime-token', expect.objectContaining({ externalOnly: true }))
    await user.click(screen.getByRole('checkbox', { name: '自动选择出口网卡' }))
    expect(await screen.findByText('docker0')).toBeInTheDocument()
    expect(top).toHaveBeenLastCalledWith('node-realtime-token', expect.objectContaining({ externalOnly: false }))
  })

  it('keeps the egress checkbox inline right after refresh with its hint behind a help tooltip (fix-nicinline)', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [] })
    const user = userEvent.setup()
    const { container } = renderPage()
    expect(await screen.findByText('暂无数据')).toBeInTheDocument()

    const expectInline = (hint: string) => {
      const checkbox = screen.getByRole('checkbox', { name: '自动选择出口网卡' })
      const item = checkbox.closest('.node-realtime-egress-item')
      expect(item).not.toBeNull()
      expect(item?.parentElement).toHaveClass('node-realtime-controls')
      expect(item?.previousElementSibling).toHaveClass('node-realtime-refresh-item')
      expect(within(item as HTMLElement).getByRole('button', { name: hint })).toBeInTheDocument()
      expect(screen.queryByText(hint)).not.toBeInTheDocument()
      expect(container.querySelector('.node-realtime-network-selection #node-realtime-external-only')).toBeNull()
    }
    expectInline('按系统默认路由识别；双栈或多出口分别展示，不修改监听绑定。')
    await user.click(screen.getByRole('checkbox', { name: '自动选择出口网卡' }))
    expectInline('当前显示全部网卡，可用于内网及特殊路由诊断。')
    await user.click(screen.getByRole('checkbox', { name: '自动选择出口网卡' }))

    await user.click(screen.getByRole('tab', { name: '监控指标' }))
    expectInline('按系统默认路由识别；双栈或多出口分别展示，不修改监听绑定。')
    await user.click(screen.getByRole('tab', { name: '节点流量' }))
    expectInline('按系统默认路由识别；双栈或多出口分别展示，不修改监听绑定。')

    await user.click(screen.getByRole('tab', { name: '资源排行' }))
    await user.click(screen.getByText('负载', { exact: true }))
    expect(screen.queryByRole('checkbox', { name: '自动选择出口网卡' })).not.toBeInTheDocument()
    expect(nodeRealtimeCSS).toMatch(/\.node-realtime-egress-item\s*\{[\s\S]*?white-space:\s*nowrap;/)
  })

  it('keeps the monitoring and traffic filter bars on one row with the NIC exclusion behind advanced filters (fix-nicinline2)', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const user = userEvent.setup()
    const { container } = renderPage()
    expect(await screen.findByText(`${node.name} (${node.display_id})`)).toBeInTheDocument()

    for (const tab of ['监控指标', '节点流量']) {
      await user.click(screen.getByRole('tab', { name: tab }))
      const controls = container.querySelector('.node-realtime-controls') as HTMLElement
      expect(controls).toHaveClass('node-realtime-controls--inline')
      // 自定义只在按钮上弹出日期面板，不在行内多出「选择时间范围」框。
      await user.click(within(controls).getByText('自定义', { exact: true }))
      expect(screen.getByRole('dialog', { name: '选择时间范围' })).toBeInTheDocument()
      expect(within(controls).queryByRole('textbox', { name: '选择时间范围' })).not.toBeInTheDocument()
    }

    // 节点流量：排除网卡收进行尾「高级筛选」，启用后按钮带条件数。
    const controls = container.querySelector('.node-realtime-controls') as HTMLElement
    const advanced = within(controls).getByRole('button', { name: '高级筛选' })
    expect(controls.lastElementChild).toContainElement(advanced)
    expect(advanced).toHaveAttribute('aria-expanded', 'false')
    expect(within(controls).queryByPlaceholderText('排除网卡，多个网卡用空格分隔')).not.toBeInTheDocument()
    await user.click(advanced)
    expect(advanced).toHaveAttribute('aria-expanded', 'true')
    const panel = screen.getByRole('group', { name: '高级筛选' })
    await user.type(within(panel).getByRole('textbox', { name: '排除网卡' }), 'docker0')
    expect(within(controls).getByRole('button', { name: '高级筛选（已启用 1 项）' })).toBeInTheDocument()
    expect(nodeRealtimeCSS).toMatch(/@media \(min-width: 768px\)\s*\{[\s\S]*?\.node-realtime-controls--inline\s*\{[\s\S]*?flex-wrap:\s*nowrap;/)
  })

  it('advances the realtime query window when refreshed', async () => {
    authenticate()
    let now = Date.parse('2026-10-09T09:00:00Z')
    vi.spyOn(Date, 'now').mockImplementation(() => now)
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const ranking = vi.spyOn(nodesApi, 'getNodeRealtimeTop').mockResolvedValue({ data: [], msg: '', code: 0 })
    const traffic = vi.spyOn(nodesApi, 'getNodeTraffic')
    const series = vi.spyOn(nodesApi, 'getNodeRealtimeSeries').mockResolvedValue({ data: {}, msg: '', code: 0 })
    const user = userEvent.setup()
    renderPage()
    await screen.findByText(`${node.name} (${node.display_id})`)
    await user.click(screen.getByRole('tab', { name: '监控指标' }))
    await waitFor(() => expect(series).toHaveBeenCalledWith('node-realtime-token', expect.objectContaining({
      start: '2026-10-09T08:00:00.000Z', end: '2026-10-09T09:00:00.000Z', externalOnly: true,
    })))
    now += 60_000
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(series).toHaveBeenLastCalledWith('node-realtime-token', expect.objectContaining({
      start: '2026-10-09T08:01:00.000Z', end: '2026-10-09T09:01:00.000Z', externalOnly: true,
    })))
    expect(ranking).toHaveBeenCalledTimes(1)
    expect(traffic).not.toHaveBeenCalled()
  })

  it('does not guess the first NIC or display aggregate bandwidth as automatic egress', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    mockLatest(() => ({ ...metrics, telemetry: {
      schema_version: 1, total_rx_bytes: 100, total_tx_bytes: 200, disks: [],
      network_selection: { source: 'unavailable', interfaces: [] },
      network_interfaces: [{ name: 'docker0', rx_bytes: 100, tx_bytes: 200, rx_bandwidth_bps: 1600, tx_bandwidth_bps: 800 }],
    } }))
    vi.spyOn(nodesApi, 'getNodeRealtimeTop').mockResolvedValue({ data: [], msg: '', code: 0 })
    renderPage()
    expect(await screen.findByText('出口未确认')).toBeInTheDocument()
    expect(await screen.findByRole('status')).toHaveTextContent('无法自动识别')
    expect(screen.queryByText('docker0')).not.toBeInTheDocument()
    expect(screen.queryByText('800 bps')).not.toBeInTheDocument()
  })

  it('uses disk ranking rows for the reported partition and space usage', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    vi.spyOn(nodesApi, 'getNodeRealtimeTop').mockResolvedValue({
      data: [
        { node_id: node.id, node_name: node.name, nic: '/var', inbound: 73.5, outbound: 0 },
        { node_id: node.id, node_name: node.name, nic: '/', inbound: 41.25, outbound: 0 },
      ],
      msg: '',
      code: 0,
    })
    const user = userEvent.setup()

    renderPage()
    await user.click(screen.getByRole('tab', { name: '资源排行' }))
    await user.click(screen.getByText('硬盘', { exact: true }))

    const rows = screen.getAllByRole('row').slice(1)
    expect(rows).toHaveLength(2)
    expect(rows[0]).toHaveTextContent('/var')
    expect(rows[0]).toHaveTextContent('73.5%')
    expect(rows[0]).toHaveTextContent('未上报')
    expect(rows[1]).toHaveTextContent('/')
    expect(rows[1]).toHaveTextContent('41.3%')
  })

  it('lists every mount with why the disk ranking filters it, and old agents as version not reported (fz-x11)', async () => {
    authenticate()
    const old = { ...node, id: '018f0000-0000-7000-8000-000000000002', name: '旧版本节点' }
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node, old] })
    mockLatest((nodeID) => nodeID === node.id
      ? { ...metrics, telemetry_detail: true, telemetry: {
        schema_version: 1, total_rx_bytes: 100, total_tx_bytes: 200, network_interfaces: [],
        disks: [{ path: '/', total_bytes: 100, used_bytes: 40, total_inodes: 10, used_inodes: 1, space_percent: 40, inode_percent: 10 }],
        mounts: [
          { path: '/', device: '8:1', fstype: 'ext4', read_only: false, bind: false },
          { path: '/etc', device: '8:1', fstype: 'ext4', read_only: false, bind: true, filter_reason: 'bind_duplicate' },
          { path: '/snap/core', device: '7:0', fstype: 'squashfs', read_only: true, bind: false, filter_reason: 'squashfs' },
        ],
      } }
      : { ...metrics, node_id: old.id, node_name: old.name })
    vi.spyOn(nodesApi, 'getNodeRealtimeTop').mockResolvedValue({ data: [], msg: '', code: 0 })
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByRole('tab', { name: '资源排行' }))
    await screen.findByText(`${node.name} (${node.display_id})`)
    await user.click(screen.getByText('硬盘', { exact: true }))
    expect(screen.queryByTestId('node-realtime-all-mounts')).not.toBeInTheDocument()
    await user.click(screen.getByRole('checkbox', { name: '显示全部挂载' }))
    const detail = await screen.findByTestId('node-realtime-all-mounts')
    const rows = within(detail).getAllByRole('row').slice(1)
    expect(rows).toHaveLength(4)
    expect(rows[0]).toHaveTextContent('/8:1ext4否否计入排行')
    expect(rows[1]).toHaveTextContent('/etc8:1ext4否是已过滤：同设备已有一行（bind 挂载）')
    expect(rows[2]).toHaveTextContent('/snap/core7:0squashfs是否已过滤：squashfs 只读镜像')
    expect(rows[3]).toHaveTextContent('旧版本节点')
    expect(rows[3]).toHaveTextContent('节点版本未上报')
  })

  it('shows each DDoS packet filter drop count in the connections ranking', async () => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    mockLatest(() => ({ ...metrics, telemetry: {
      schema_version: 1, total_rx_bytes: 100, total_tx_bytes: 200, disks: [], network_interfaces: [],
      ddos_drops: [{ kind: 'ct_invalid', packets: 3, bytes: 120 }, { kind: 'tcp_fin', packets: 1, bytes: 40 }, { kind: 'tcp_xmas', packets: 12, bytes: 480 }],
    } }))
    vi.spyOn(nodesApi, 'getNodeRealtimeTop').mockResolvedValue({ data: [], msg: '', code: 0 })
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByRole('tab', { name: '资源排行' }))
    await screen.findByText(`${node.name} (${node.display_id})`)
    await user.click(screen.getByText('连接', { exact: true }))
    expect(screen.getAllByRole('row')[1]).toHaveTextContent('无效连接 3 / 孤立 FIN 1 / Xmas 12')
  })

  it('switches ranking columns and keeps metric sorting tied to the selected value', async () => {
    authenticate()
    const second = { ...node, id: '018f0000-0000-7000-8000-000000000002', name: '北京边缘节点' }
    const nodeMetrics = new Map([
      [node.id, metrics],
      [second.id, { ...metrics, node_id: second.id, node_name: second.name, tx_bandwidth_bps: 2400, rx_bandwidth_bps: 3200, active_connections: 2, cpu_percent: 75 }],
    ])
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node, second] })
    mockLatest((nodeID) => nodeMetrics.get(nodeID))
    const user = userEvent.setup()

    renderPage()
    await user.click(screen.getByRole('tab', { name: '资源排行' }))
    await screen.findByText(`${node.name} (${node.display_id})`)
    const rows = () => screen.getAllByRole('row').slice(1)
    await user.click(screen.getByRole('checkbox', { name: '自动选择出口网卡' }))
    expect(rows()[0]).toHaveTextContent(`${second.name} (${second.display_id})`)

    await user.click(screen.getByText('连接', { exact: true }))
    expect(screen.getAllByRole('columnheader').map((header) => header.textContent?.trim())).toEqual(['排行', '节点', '连接数', 'DDoS 丢弃包'])
    expect(rows()[0]).toHaveTextContent(`${node.name} (${node.display_id})`)

    await user.click(screen.getByText('负载', { exact: true }))
    expect(screen.getAllByRole('columnheader').map((header) => header.textContent?.trim())).toEqual(['排行', '节点', 'CPU使用率', '内存使用率', '系统负载'])
    expect(rows()[0]).toHaveTextContent(`${second.name} (${second.display_id})`)
    await user.click(screen.getByRole('columnheader', { name: 'CPU使用率' }))
    expect(rows()[0]).toHaveTextContent(`${node.name} (${node.display_id})`)
  })

  it('keeps token-free cache identity across a same-epoch token refresh', async () => {
    const actor = admin()
    const epoch = authenticate(actor, 'old-node-token')
    const listSpy = vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    const { queryClient } = renderPage()
    const user = userEvent.setup()

    await user.click(screen.getByRole('tab', { name: '资源排行' }))
    expect(await screen.findByText(`${node.name} (${node.display_id})`)).toBeInTheDocument()
    const callsBeforeRefresh = listSpy.mock.calls.length

    await act(async () => {
      authenticate(actor, 'new-node-token', 'refresh')
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(listSpy).toHaveBeenCalledTimes(callsBeforeRefresh)
    for (const query of queryClient.getQueryCache().getAll()) {
      expect(JSON.stringify(query.queryKey)).not.toContain('old-node-token')
      expect(JSON.stringify(query.queryKey)).not.toContain('new-node-token')
    }

    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(listSpy).toHaveBeenCalledTimes(callsBeforeRefresh + 1))
    expect(listSpy.mock.calls.at(-1)?.[0]).toBe('new-node-token')
    expect(listSpy.mock.calls.at(-1)?.[1]).toMatchObject({ limit: 300 })
  })

  it('clears old owner cache and ignores its late response after a new session starts', async () => {
    const actorA = admin({ user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' })
    const actorB = admin({ user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' })
    authenticate(actorA, 'session-a-token')
    const pendingA = deferred<{ items: NodeInventoryItem[] }>()
    vi.spyOn(nodesApi, 'list')
      .mockReturnValueOnce(pendingA.promise)
      .mockResolvedValueOnce({ items: [{ ...node, name: '新会话节点' }] })
    const { queryClient } = renderPage()
    const user = userEvent.setup()

    expect(await screen.findByLabelText('正在加载节点实时状态')).toBeInTheDocument()
    await act(async () => {
      authenticate(actorB, 'session-b-token')
      await Promise.resolve()
    })
    await user.click(screen.getByRole('tab', { name: '资源排行' }))
    expect(await screen.findByText('新会话节点 (1)')).toBeInTheDocument()

    await act(async () => pendingA.resolve({ items: [{ ...node, name: '迟到旧节点' }] }))
    expect(screen.queryByText('迟到旧节点 (1)')).not.toBeInTheDocument()
    const keys = queryClient.getQueryCache().getAll().map((query) => JSON.stringify(query.queryKey))
    expect(keys.some((key) => key.includes(actorA.user_id))).toBe(false)
    expect(keys.some((key) => key.includes(actorB.user_id))).toBe(true)
  })

  it.each([
    [new ApiError('raw denial', 403, 'permission_denied'), '无权查看节点实时状态'],
    [new ApiError('raw missing', 404, 'node_not_found'), '节点实时状态不存在'],
  ])('maps terminal server errors without exposing their message', async (error, expected) => {
    authenticate()
    vi.spyOn(nodesApi, 'list').mockRejectedValue(error)

    renderPage()

    expect(await screen.findByText(expected)).toBeInTheDocument()
    expect(document.body.textContent).not.toContain(error.message)
  })
})
