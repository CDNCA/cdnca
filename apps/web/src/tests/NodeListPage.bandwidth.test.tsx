import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'

import type { NodeInventoryItem, NodeMetricsLatest } from '../api/nodes'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import NodeListPage from '../pages/NodeListPage'
import css from '../pages/NodeListPage.css?raw'
import { authResponse, nodeManagementSettingsFixture, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

describe('node list page bandwidth', function nodeBandwidthBatchRegression() {
  const nodeID = '018f0000-0000-7000-8000-000000000001'
  const otherID = '018f0000-0000-7000-8000-000000000002'
  const time = '2026-10-10T10:00:00Z'
  const node: NodeInventoryItem = {
    id: nodeID, display_id: '1', name: 'Edge one', description: '', region: '',
    admin_state: 'active', management_settings: nodeManagementSettingsFixture(), revision: 1,
    created_at: time, updated_at: time,
    presence: { status: 'online', last_heartbeat_at: time, agent_version: '1.0.11',
      session_epoch: 1, heartbeat_sequence: 2, projection_freshness: 'fresh', lease_signal: 'present' },
  }
  const metric: NodeMetricsLatest = {
    node_id: nodeID, node_name: node.name, record_kind: 'host_metric',
    config_revision: 0, active_config_revision: 0, publication_sequence: 1, observed_at: time, ingested_at: time,
    probe_port: 0, healthy: false, probe_succeeded: false, consecutive_failures: 0, consecutive_successes: 0,
    probes_total: 0, probe_failures_total: 0, recovered: false, recovery_notified: false, rolled_back: false,
    known: true, cpu_percent: 0, memory_used_bytes: 0, memory_total_bytes: 1, active_connections: 0,
    rx_bandwidth_bps: 999999, tx_bandwidth_bps: 999999, total_rx_bytes: 0, total_tx_bytes: 0,
    telemetry: { schema_version: 1, total_rx_bytes: 0, total_tx_bytes: 0, disks: [],
      network_selection: { source: 'default_route', interfaces: ['ens17', 'ens18'] },
      network_interfaces: [
        { name: 'docker0', rx_bytes: 0, tx_bytes: 0, rx_bandwidth_bps: 999999, tx_bandwidth_bps: 999999 },
        { name: 'ens17', rx_bytes: 0, tx_bytes: 0, rx_bandwidth_bps: 3000, tx_bandwidth_bps: 4000 },
        { name: 'ens18', rx_bytes: 0, tx_bytes: 0, rx_bandwidth_bps: 700, tx_bandwidth_bps: 1990 },
      ] },
    puback_stream: 'NODE_MONITORING_STATUS', puback_sequence: 1,
    consumer_durable: 'control_api_node_metrics', consumer_sequence: 1,
  }
  const admin = principal({ scope_kind: 'platform', tenant_id: null, permissions: ['nodes.read'], roles: ['platform_owner'] })
  let metricsBody: unknown
  let metricsStatus: number
  let inventoryBody: unknown
  let metricsReply: Promise<Response> | undefined
  let client: QueryClient
  let monotonic: number
  const calls: string[] = []

  beforeEach(() => {
    sessionStorage.clear()
    calls.length = 0
    monotonic = 0
    vi.spyOn(performance, 'now').mockImplementation(() => monotonic)
    metricsBody = { observed_at: time, items: [metric], not_reported_node_ids: [] }
    metricsStatus = 200
    metricsReply = undefined
    inventoryBody = { items: [node] }
    useSessionStore.getState().setSession(authResponse(admin), admin)
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      calls.push(url)
      if (url.startsWith('/v1/nodes/metrics/latest?')) {
        if (metricsReply) return metricsReply
        return new Response(JSON.stringify(metricsBody), { status: metricsStatus })
      }
      if (url.startsWith('/v1/nodes?')) {
        const body = inventoryBody as { items: NodeInventoryItem[]; next_cursor?: string }
        const items = [...body.items].sort((a, b) => b.management_settings.sort - a.management_settings.sort ||
          (BigInt(a.display_id) > BigInt(b.display_id) ? -1 : BigInt(a.display_id) < BigInt(b.display_id) ? 1 : b.id.localeCompare(a.id)))
        const last = items.at(-1)
        const next = body.next_cursor && last ? `nso1.${btoa(JSON.stringify({ version: 1, scope_id: admin.scope_id,
          order: 'management_sort_desc', status: '', presence: '', search: '', last_sort: last.management_settings.sort,
          last_display_id: last.display_id, last_id: last.id,
        })).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')}` : undefined
        return new Response(JSON.stringify({ order: 'management_sort_desc', items, ...(next ? { next_cursor: next } : {}) }), { status: 200 })
      }
      throw new Error(`unexpected test route: ${url}`)
    })
  })

  afterEach(() => vi.useRealTimers())

  const CaptureClient = () => { client = useQueryClient(); return null }
  const renderPage = () => renderWithProviders(<><CaptureClient /><NodeListPage /></>)
  const batchCalls = () => calls.filter((url) => url.startsWith('/v1/nodes/metrics/latest?'))

  it('uses one exact page batch, sums only confirmed egress NICs and does not interpret host healthy=false as failure', async () => {
    inventoryBody = { items: [node, { ...node, id: otherID, display_id: '2', name: 'Edge two' }] }
    metricsBody = { observed_at: time, items: [metric], not_reported_node_ids: [otherID] }
    renderPage()
    expect(await screen.findByLabelText('出站带宽：5.99 Kbps')).toBeInTheDocument()
    expect(screen.getByLabelText('入站带宽：3.7 Kbps')).toBeInTheDocument()
    const cell = screen.getByLabelText('出站带宽：5.99 Kbps').closest('td')!
    expect(within(cell).getByLabelText('入站带宽：3.7 Kbps')).toBeInTheDocument()
    expect(screen.getByText('未上报')).toBeInTheDocument()
    expect(cell).not.toHaveTextContent('999.99')
    expect(batchCalls()).toEqual([`/v1/nodes/metrics/latest?node_id=${otherID}&node_id=${nodeID}`])
    expect(calls.some((url) => url.includes('/top') || url.includes(`/${nodeID}/metrics`))).toBe(false)
    const keys = JSON.stringify(client.getQueryCache().getAll().map((query) => query.queryKey))
    expect(keys).toContain(admin.scope_id)
    expect(keys).toContain(admin.user_id)
    expect(keys).not.toContain('access-token')
  })

  it('renders a genuine zero and exposes the sample time and age to keyboard users', async () => {
    metricsBody = { observed_at: time, items: [{ ...metric, telemetry: { ...metric.telemetry,
      network_selection: { source: 'default_route', interfaces: ['ens17'] },
      network_interfaces: [{ name: 'ens17', rx_bytes: 0, tx_bytes: 0, rx_bandwidth_bps: 0, tx_bandwidth_bps: 0 }],
    } }], not_reported_node_ids: [] }
    renderPage()
    const value = await screen.findByLabelText('出站带宽：0 bps')
    expect(screen.getByLabelText('入站带宽：0 bps')).toBeInTheDocument()
    fireEvent.focus(value.closest('[tabindex]')!)
    expect(await screen.findByRole('tooltip')).toHaveTextContent('采样时间：')
    expect(screen.getByRole('tooltip')).toHaveTextContent('样本年龄：0 秒')
  })

  it('keeps an unknown load sample distinct from a genuine zero', async () => {
    metricsBody = { observed_at: time, items: [{ ...metric, record_kind: 'metric',
      config_revision: 1, active_config_revision: 1, probe_port: 80, known: false, telemetry: undefined,
      cpu_percent: null, memory_used_bytes: null, memory_total_bytes: null, active_connections: null,
      rx_bandwidth_bps: null, tx_bandwidth_bps: null, total_rx_bytes: null, total_tx_bytes: null,
    }], not_reported_node_ids: [] }
    renderPage()
    expect(await screen.findByText('未上报')).toBeInTheDocument()
    expect(screen.queryByLabelText(/带宽：0 bps/)).not.toBeInTheDocument()
  })

  it('rejects an unsafe multi-NIC sum rather than rounding it into a displayed value', async () => {
    metricsBody = { observed_at: time, items: [{ ...metric, telemetry: { ...metric.telemetry,
      network_interfaces: metric.telemetry!.network_interfaces.map((nic) => ({ ...nic, tx_bandwidth_bps: Number.MAX_SAFE_INTEGER })),
    } }], not_reported_node_ids: [] }
    renderPage()
    expect(await screen.findByText('数据无效')).toBeInTheDocument()
  })

  it.each([
    ['missing', undefined, '出口未知'],
    ['unavailable', { source: 'unavailable', interfaces: [] }, '出口未知'],
    ['duplicate selection', { source: 'default_route', interfaces: ['ens17', 'ens17'] }, '数据无效'],
    ['missing selected NIC', { source: 'default_route', interfaces: ['missing'] }, '数据无效'],
  ])('does not invent bandwidth for %s', async (_name, selection, label) => {
    metricsBody = { observed_at: time, items: [{ ...metric, telemetry: { ...metric.telemetry, network_selection: selection } }], not_reported_node_ids: [] }
    renderPage()
    expect(await screen.findByText(String(label))).toBeInTheDocument()
    expect(screen.queryByLabelText(/带宽：0 bps/)).not.toBeInTheDocument()
  })

  it.each([
    [503, 'node_metrics_unavailable', '暂不可用'],
    [404, 'node_metrics_not_found', '节点不可读取'],
    [400, 'validation_error', '数据无效'],
    [200, 'invalid_response', '数据无效'],
  ])('distinguishes %s failures without showing private messages', async (status, code, label) => {
    metricsStatus = status
    metricsBody = { error: { code, message: 'private-backend-message' } }
    renderPage()
    expect(await screen.findByText(label)).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private-backend-message')
  })

  it.each([
    // Live 1.0.27: samples reach the server ~14s after observation and the list polls every 10s,
    // so a healthy node is routinely 25-35s old at render time.
    ['host_metric', 35, false], ['host_metric', 60, false], ['host_metric', 60.001, true],
    ['metric', 390, false], ['metric', 390.001, true],
    [undefined, 390, false], [undefined, 390.001, true],
  ] as const)('uses the exact %s age boundary %s seconds', async (kind, age, expired) => {
    const sample = kind === 'host_metric' ? metric : { ...metric, record_kind: kind, config_revision: 1, active_config_revision: 1, probe_port: 80 }
    metricsBody = { observed_at: new Date(Date.parse(time) + age * 1000).toISOString(), items: [sample], not_reported_node_ids: [] }
    renderPage()
    if (expired) expect(await screen.findByText('已过期')).toBeInTheDocument()
    else expect(await screen.findByLabelText('出站带宽：5.99 Kbps')).toBeInTheDocument()
    expect(screen.queryByLabelText(/带宽：0 bps/)).not.toBeInTheDocument()
  })

  it.each([[5, false], [5.001, true]] as const)('clamps an allowed future sample and rejects future skew %s seconds', async (future, invalid) => {
    metricsBody = { observed_at: time, items: [{ ...metric, observed_at: new Date(Date.parse(time) + future * 1000).toISOString() }], not_reported_node_ids: [] }
    renderPage()
    if (invalid) expect(await screen.findByText('时间异常')).toBeInTheDocument()
    else {
      const value = await screen.findByLabelText('出站带宽：5.99 Kbps')
      fireEvent.focus(value.closest('[tabindex]')!)
      expect(await screen.findByRole('tooltip')).toHaveTextContent('样本年龄：0 秒')
    }
  })

  it('expires from monotonic elapsed time while a refresh hangs, ignoring wall clock jumps', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    renderPage()
    expect(await screen.findByLabelText('出站带宽：5.99 Kbps')).toBeInTheDocument()
    metricsReply = new Promise(() => undefined)
    fireEvent.click(screen.getByRole('button', { name: '刷新带宽' }))
    vi.spyOn(Date, 'now').mockReturnValue(0)
    monotonic = 60_001
    await act(async () => { await vi.advanceTimersByTimeAsync(1000) })
    expect(await screen.findByText('已过期')).toBeInTheDocument()
    expect(batchCalls()).toHaveLength(2)
  })

  it('polls once per 10 seconds without refreshing the age of an unchanged sample', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    renderPage()
    expect(await screen.findByLabelText('出站带宽：5.99 Kbps')).toBeInTheDocument()
    monotonic = 20_000
    metricsBody = { observed_at: '2026-10-10T10:00:20Z', items: [metric], not_reported_node_ids: [] }
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000) })
    await waitFor(() => expect(batchCalls()).toHaveLength(2))
    monotonic = 60_001
    await act(async () => { await vi.advanceTimersByTimeAsync(1000) })
    expect(await screen.findByText('已过期')).toBeInTheDocument()
  })

  it('bounds polling to one pending batch and stops it when leaving the node list', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    metricsReply = new Promise(() => undefined)
    renderPage()
    await waitFor(() => expect(batchCalls()).toHaveLength(1))
    expect(screen.getByText('读取中')).toBeInTheDocument()
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
    expect(batchCalls()).toHaveLength(1)
    fireEvent.click(screen.getByRole('tab', { name: '待初始化' }))
    await waitFor(() => expect(calls).toContain('/v1/nodes?limit=10&order=management_sort_desc&status=pending'))
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
    expect(batchCalls()).toHaveLength(1)
  })

  it('uses a refreshed token without putting tokens in query keys or refetching on token change', async () => {
    renderPage()
    expect(await screen.findByLabelText('出站带宽：5.99 Kbps')).toBeInTheDocument()
    act(() => useSessionStore.setState({ accessToken: 'renewed-private-token' }))
    expect(batchCalls()).toHaveLength(1)
    fireEvent.click(screen.getByRole('button', { name: '刷新带宽' }))
    await waitFor(() => expect(batchCalls()).toHaveLength(2))
    const latest = vi.mocked(globalThis.fetch).mock.calls.filter(([url]) => String(url).startsWith('/v1/nodes/metrics/latest?')).at(-1)!
    expect(new Headers(latest[1]?.headers).get('Authorization')).toBe('Bearer renewed-private-token')
    expect(JSON.stringify(client.getQueryCache().getAll().map((query) => query.queryKey))).not.toContain('renewed-private-token')
  })

  it('does not fetch on an empty page or for an unprivileged owner', async () => {
    inventoryBody = { items: [] }
    renderPage()
    await waitFor(() => expect(calls).toHaveLength(1))
    expect(batchCalls()).toHaveLength(0)
    act(() => useSessionStore.setState({ principal: { ...admin, permissions: [] } }))
    expect(await screen.findByText('无权查看节点列表')).toBeInTheDocument()
    expect(batchCalls()).toHaveLength(0)
  })

  it('keeps an unavailable bandwidth read out of successful inventory invalidation and readback', async () => {
    metricsStatus = 503
    metricsBody = { error: { code: 'node_metrics_unavailable' } }
    renderPage()
    expect(await screen.findByText('暂不可用')).toBeInTheDocument()
    await act(async () => {
      await expect(client.invalidateQueries({ queryKey: ['nodes'] }, { throwOnError: true })).resolves.toBeUndefined()
    })
    expect(batchCalls()).toHaveLength(1)
    expect(screen.getByRole('button', { name: node.name })).toBeInTheDocument()
  })

  it('fails the owner closed immediately on a current batch 403', async () => {
    metricsStatus = 403
    metricsBody = { error: { code: 'forbidden', message: 'private permission detail' } }
    renderPage()
    expect(await screen.findByText('无权查看节点列表')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: node.name })).not.toBeInTheDocument()
    await waitFor(() => expect(client.getQueryCache().getAll()
      .filter((query) => ['nodes', 'node-bandwidth'].includes(String(query.queryKey[0])))
      .every((query) => query.state.data === undefined)).toBe(true))
  })

  it.each([200, 403])('ignores a late page response %s after the visible page changes', async (status) => {
    let resolve!: (response: Response) => void
    metricsReply = new Promise((done) => { resolve = done })
    inventoryBody = { items: [node], next_cursor: nodeID }
    renderPage()
    await waitFor(() => expect(batchCalls()).toHaveLength(1))
    metricsReply = undefined
    inventoryBody = { items: [{ ...node, id: otherID, display_id: '2', name: 'Edge two', management_settings: { ...node.management_settings, sort: 0 } }] }
    metricsBody = { observed_at: time, items: [], not_reported_node_ids: [otherID] }
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('未上报')).toBeInTheDocument()
    await act(async () => resolve(new Response(JSON.stringify(status === 200
      ? { observed_at: time, items: [metric], not_reported_node_ids: [] }
      : { error: { code: 'forbidden' } }), { status })))
    expect(screen.getByRole('button', { name: 'Edge two' })).toBeInTheDocument()
    expect(screen.queryByLabelText('出站带宽：5.99 Kbps')).not.toBeInTheDocument()
    expect(batchCalls()).toHaveLength(2)
  })

  it.each(['owner', 'scope', 'epoch', 'permission'] as const)('does not leak a late batch after %s changes', async (change) => {
    let resolve!: (response: Response) => void
    metricsReply = new Promise((done) => { resolve = done })
    renderPage()
    await waitFor(() => expect(batchCalls()).toHaveLength(1))
    metricsReply = undefined
    metricsBody = { observed_at: time, items: [], not_reported_node_ids: [nodeID] }
    const next = { ...admin, ...(change === 'owner' ? { user_id: otherID } : {}),
      ...(change === 'scope' ? { scope_id: otherID } : {}), ...(change === 'permission' ? { permissions: [] } : {}) }
    act(() => useSessionStore.getState().setSession(authResponse(next), next, change === 'permission' ? 'refresh' : 'new'))
    if (change === 'permission') expect(await screen.findByText('无权查看节点列表')).toBeInTheDocument()
    else expect(await screen.findByText('未上报')).toBeInTheDocument()
    await act(async () => resolve(new Response(JSON.stringify({ observed_at: time, items: [metric], not_reported_node_ids: [] }))))
    expect(screen.queryByLabelText('出站带宽：5.99 Kbps')).not.toBeInTheDocument()
    expect(JSON.stringify(client.getQueryCache().getAll().map((query) => query.state.data))).not.toContain('999999')
  })

  it.each([
    ['en-US', 'Outbound bandwidth: 5.99 Kbps', 'Inbound bandwidth: 3.7 Kbps'],
    ['qps-ploc', '［出~站~带~宽~：~5.99 Kbps］', '［入~站~带~宽~：~3.7 Kbps］'],
  ] as const)('keeps %s feedback wrappable and directions accessible in the same cell', async (locale, outbound, inbound) => {
    await changeLocale(locale)
    renderPage()
    expect(await screen.findByLabelText(outbound)).toBeInTheDocument()
    expect(screen.getByLabelText(inbound)).toBeInTheDocument()
    expect(css).toMatch(/\.node-bandwidth\s*\{[^}]*flex-wrap:\s*wrap/s)
    expect(css).toMatch(/\.node-bandwidth-state\s*\{[^}]*overflow-wrap:\s*anywhere/s)
    expect(css).toMatch(/\.node-bandwidth-outbound[^}]*var\(--cdnca-color-primary\)/s)
    expect(css).toMatch(/\.node-bandwidth-inbound[^}]*var\(--cdnca-color-warning\)/s)
  })

  it('shows the XDP mode and, when the node falls back, the reason in both languages', async () => {
    const other = { ...node, id: otherID, display_id: '2', name: 'Edge two' }
    inventoryBody = { items: [node, other] }
    metricsBody = { observed_at: time, items: [
      { ...metric, telemetry: { ...metric.telemetry, xdp: { mode: 'generic', interfaces: ['ens17=generic'],
        drops: [{ kind: 'xdp_block', packets: 12, bytes: 720 }] } } },
      { ...metric, node_id: otherID, node_name: other.name, telemetry: { ...metric.telemetry,
        xdp: { mode: 'nftables', reason: 'bpf_unavailable', detail: 'function not implemented' } } },
    ], not_reported_node_ids: [] }
    renderPage()
    const generic = await screen.findByText('通用 XDP')
    expect(screen.getByText('nftables')).toBeInTheDocument()
    expect(screen.getByText('（不支持 BPF）')).toBeInTheDocument()
    fireEvent.focus(generic.closest('[tabindex]')!)
    expect(await screen.findByRole('tooltip')).toHaveTextContent('网卡：ens17 (通用 XDP) · XDP 丢弃包：自动防御 L5 12')
    await changeLocale('en-US')
    expect(await screen.findByText('Generic XDP')).toBeInTheDocument()
    expect(screen.getByText('(No BPF)', { exact: false })).toBeInTheDocument()
  })

  // 10-23 reinstall: both nodes rebooted, counters restarted. The column
  // shows the bytes accumulated this month (as the competitor's 月流量 does)
  // and marks the restart with a badge + tooltip, not only "计数器已重置".
  it('shows accumulated monthly traffic with a reset badge instead of only a state text', async () => {
    const other = { ...node, id: otherID, display_id: '2', name: 'Edge two' }
    inventoryBody = { items: [node, other] }
    const monthly = { period_key: '2026-10', period_start: '2026-09-30T16:00:00Z', period_end: '2026-10-31T16:00:00Z',
      timezone: 'Asia/Shanghai', source_finalized_through: time, samples: 600 }
    metricsBody = { observed_at: time, items: [
      { ...metric, monthly_traffic: { ...monthly, state: 'available', usage_bytes: 1_431_000_000, counter_resets: 1 } },
      // An older control API still reporting counter_reset (no counter_resets).
      { ...metric, node_id: otherID, node_name: other.name, monthly_traffic: { ...monthly, state: 'counter_reset', usage_bytes: 0 } },
    ], not_reported_node_ids: [] }
    renderPage()
    const badges = await screen.findAllByRole('img', { name: '计数器重置 1 次' })
    expect(badges).toHaveLength(2)
    expect(screen.queryByText('计数器已重置')).not.toBeInTheDocument()
    const value = badges[0].closest('.node-monthly-traffic-value')!
    expect(value.textContent).toMatch(/\d/)
    fireEvent.focus(value)
    expect(await screen.findByRole('tooltip')).toHaveTextContent('本月网卡计数器重置 1 次')
  })

  it('drops a sample whose XDP status is inconsistent', async () => {
    metricsBody = { observed_at: time, items: [{ ...metric, telemetry: { ...metric.telemetry,
      xdp: { mode: 'nftables', drops: [{ kind: 'xdp_ban', packets: 1, bytes: 60 }] } } }], not_reported_node_ids: [] }
    renderPage()
    expect(await screen.findByText('数据无效')).toBeInTheDocument()
    expect(screen.queryByText('nftables')).not.toBeInTheDocument()
  })
})
