import { act, configure, fireEvent, getConfig, screen, waitFor, within } from '@testing-library/react'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import userEvent from '@testing-library/user-event'

import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import type { NodeMonitoringLatestBatch } from '../api/nodeMonitoring'
import { nodeInstallationTicketsApi, type NodeTicket } from '../api/nodeInstallationTickets'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import NodeListPage from '../pages/NodeListPage'
import css from '../pages/NodeListPage.css?raw'
import { authResponse, nodeManagementSettingsFixture, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

describe('node list real probe monitoring', function nodeMonitoringPageRegression() {
  const id = '018f0000-0000-7000-8000-000000000001'
  const other = '018f0000-0000-7000-8000-000000000002'
  const time = '2026-10-10T10:00:00Z'
  const node: NodeInventoryItem = { id, display_id: '1', name: 'Edge probe', description: '', region: '',
    admin_state: 'active', management_settings: nodeManagementSettingsFixture(), revision: 1, created_at: time, updated_at: time,
    presence: { status: 'online', projection_freshness: 'fresh', lease_signal: 'present', agent_version: '1.0.15',
      last_heartbeat_at: time, session_epoch: 2, heartbeat_sequence: 3 } }
  const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['nodes.read'] })
  const managerPrincipal = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['nodes.read', 'nodes.manage'] })
  const valid: NodeMonitoringLatestBatch = {
    schema_version: 1, observed_at: time,
    configuration: { state: 'active', head_revision: 3, active_revision: 3, activated_at: time,
      policy: { enabled: true, requested_protocol: 'tcp', requested_port: 80,
        probe_interval_ms: 10000, probe_timeout_ms: 3000, failure_threshold: 3, recovery_threshold: 3,
        failure_debounce_ms: 0, recovery_debounce_ms: 0 } },
    items: [{ node_id: id, freshness: 'fresh', revision_state: 'current', delivery_state: 'serving', stale_after_ms: 43000,
      sample: { source: 'agent_local_tcp', config_revision: 3, active_config_revision: 3, publication_sequence: '9007199254740993',
        observed_at: time, ingested_at: time, probe_port: 80, healthy: true, probe_succeeded: true,
        consecutive_failures: 0, consecutive_successes: 3, probes_total: '10', probe_failures_total: '0',
        recovered: false, recovery_notified: false, rolled_back: false } }],
  }
  let body: NodeMonitoringLatestBatch
  let status: number
  let reply: Promise<Response> | undefined
  let list: { items: NodeInventoryItem[]; next_cursor?: string }
  let monotonic: number
  let tickets: NodeTicket[]
  let client: QueryClient
  const originalWidth = window.innerWidth
  const calls: string[] = []
  // 整页 antd 表格在 jsdom 里首屏渲染较重，机器负载高时单次渲染就超过 RTL 默认的 1 秒等待，
  // 断言本身只要求“最终出现”，所以只放宽本文件的等待时限（单测时限见 describe 第三个参数）。
  const originalAsyncUtilTimeout = getConfig().asyncUtilTimeout
  beforeAll(() => configure({ asyncUtilTimeout: 20_000 }))
  afterAll(() => configure({ asyncUtilTimeout: originalAsyncUtilTimeout }))

  beforeEach(() => {
    sessionStorage.clear()
    for (const nodeID of [id, other]) localStorage.removeItem(`cdnca.ui.nodeMonitorSource.${nodeID}`)
    body = structuredClone(valid); status = 200; reply = undefined; monotonic = 0; calls.length = 0
    list = { items: [node] }
    vi.spyOn(performance, 'now').mockImplementation(() => monotonic)
    useSessionStore.getState().setSession(authResponse(admin), admin)
    vi.spyOn(nodesApi, 'list').mockImplementation(async () => list)
    vi.spyOn(nodesApi, 'getLatestMetricsBatch').mockImplementation(async (_token, ids) => ({
      observed_at: time, items: [], not_reported_node_ids: [...ids],
    }))
    // Service tickets are their own batch; this file counts monitoring requests only.
    tickets = []
    vi.spyOn(nodeInstallationTicketsApi, 'get').mockImplementation(async (_token, ids) => ({
      observed_at: time, items: ids.map((nodeID) => tickets.find((item) => item.node_id === nodeID) ?? {
        node_id: nodeID, state: 'valid', node_status: 'serving', issued_at: time, not_after: '2026-11-09T10:00:00Z',
        days_left: 30, reported_at: time,
      }),
    }))
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input); calls.push(url)
      if (!url.startsWith('/v1/nodes/monitoring/latest?')) throw new Error('unexpected route: ' + url)
      return reply ?? new Response(JSON.stringify(status === 200 ? body : {
        error: { code: status === 403 ? 'permission_denied' : status === 404 ? 'node_monitoring_not_found' : 'node_monitoring_unavailable', message: 'private-backend-text' },
      }), { status })
    })
  })
  afterEach(() => {
    vi.useRealTimers()
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: originalWidth })
  })
  const CaptureClient = () => { client = useQueryClient(); return null }
  const renderPage = () => renderWithProviders(<><CaptureClient /><NodeListPage /></>)
  const cells = (state: string) => [...document.querySelectorAll<HTMLElement>(`.node-monitor-cell[data-state="${state}"]`)]
  // The test setup stubs antd ids, so the still-open cell tooltip shares the
  // modal title id; locate the dialog by its class and assert the title text.
  const findDialog = async (className: string, title: string) => {
    const dialog = await waitFor(() => {
      const element = document.querySelector<HTMLElement>(`[role="dialog"].${className}, .${className} [role="dialog"]`)
      expect(element).not.toBeNull()
      return element!
    })
    expect(dialog.querySelector('.ant-modal-title')).toHaveTextContent(title)
    return dialog
  }
  const findCell = async (state: string) => {
    await waitFor(() => expect(cells(state)).toHaveLength(1))
    return cells(state)[0]!
  }

  // An expired service ticket freezes the node; the status
  // cell tags it with reason, recovery and the last ticket expiry.
  it('tags a frozen node in the status cell with reason, recovery and ticket expiry', async () => {
    tickets = [{ node_id: id, state: 'expired', node_status: 'service_ticket_expired', issued_at: '2026-09-08T10:00:00Z',
      not_after: '2026-10-08T10:00:00Z', days_left: 0, reported_at: time }]
    renderPage()
    const tag = await waitFor(() => {
      const element = document.querySelector<HTMLElement>('.node-status-cell .node-frozen-tag')
      expect(element).not.toBeNull()
      return element!
    })
    expect(tag).toHaveTextContent(/^已冻结$/)
    expect(tag).toHaveAttribute('aria-label', expect.stringContaining('服务票据过期'))
    expect(tag).toHaveAttribute('aria-label', expect.stringContaining('恢复条件'))
    expect(tag).toHaveAttribute('aria-label', expect.stringContaining('最近票据到期时间：2026'))
    fireEvent.focus(tag)
    expect(await screen.findByRole('tooltip')).toHaveTextContent('已有站点继续服务')
  })

  it('shows no frozen tag for a node with a valid ticket or a banned node', async () => {
    tickets = [{ node_id: id, state: 'expired', node_status: 'banned', issued_at: '2026-09-08T10:00:00Z',
      not_after: '2026-10-08T10:00:00Z', days_left: 0, reported_at: time }]
    renderPage()
    await findCell('healthy')
    await waitFor(() => expect(nodeInstallationTicketsApi.get).toHaveBeenCalled())
    expect(document.querySelector('.node-frozen-tag')).toBeNull()
  })

  it('reads one exact batch, shows the reference protocol and log links and moves presence diagnostics to the status cell', async () => {
    renderPage()
    const cell = await findCell('healthy')
    expect(cell).toHaveClass('is-success')
    expect(cell).toHaveTextContent(/^tcp\[日志\]$/)
    expect(cell).toHaveAttribute('title', expect.stringContaining('TCP 正常'))
    expect(cell).toHaveAttribute('title', expect.stringContaining('节点本机 TCP 探测'))
    expect(cell).not.toHaveAttribute('title', expect.stringContaining('在线状态'))
    expect(within(cell).getByRole('button', { name: 'tcp' })).toBeInTheDocument()
    expect(within(cell).getByRole('button', { name: '[日志]' })).toBeInTheDocument()
    expect(within(cell).queryByRole('link')).not.toBeInTheDocument()
    const row = cell.closest('tr')!
    expect(row.querySelector('.node-state-cell')).toHaveAttribute('title', expect.stringContaining('在线状态: 在线'))
    expect(row.querySelector('.node-state-cell')).toHaveAttribute('title', expect.stringContaining('管理状态: 已启用'))
    expect(row.querySelector('.node-state-cell')).toHaveAttribute('title', expect.stringContaining('租约: 租约有效'))
    expect(row.querySelector('.node-state-cell')).toHaveTextContent(/^正常$/)
    // Reference: a normal node has no "[任务]" link.
    expect(within(row.querySelector('.node-status-cell') as HTMLElement).queryByRole('link', { name: '查看任务' })).not.toBeInTheDocument()
    expect(row).not.toHaveTextContent('同步中')
    expect(calls).toEqual([`/v1/nodes/monitoring/latest?node_id=${id}`])
    fireEvent.focus(cell)
    expect(await screen.findByRole('tooltip')).toHaveTextContent('9007199254740993')
    expect(screen.getByRole('tooltip')).toHaveTextContent('采样时间')
  })

  it.each([
    ['unconfigured', 'unconfigured', '未配置监控', '未配置'], ['not_activated', 'notActivated', '已保存未激活', '已保存未激活'],
    ['saved', 'savedNotActivated', '新配置未激活', 'tcp[日志]'], ['disabled', 'disablePending', '关闭待确认', '关闭待确认'],
    ['not_reported', 'notReported', '监控未上报', 'tcp[日志]'], ['stale', 'stale', '监控已过期', 'tcp[日志]'],
    ['clock_skew', 'clockSkew', '监控时间异常', 'tcp[日志]'], ['different', 'oldConfiguration', '旧配置样本', 'tcp[日志]'],
    ['rolled_back', 'rolledBack', '监控已回滚', 'tcp[日志]'], ['unhealthy', 'unhealthy', 'TCP 异常', 'tcp[日志]'],
    ['awaiting_configuration', 'awaitingConfiguration', '节点尚未激活任何站点配置', 'tcp[日志]'],
    ['inactive', 'nodeInactive', '节点未处于启用状态', 'tcp[日志]'],
  ])('separates %s from healthy and from administrative presence', async (state, cellState, expected, visible) => {
    if (state === 'unconfigured' || state === 'not_activated') {
      body.configuration = { state, head_revision: state === 'unconfigured' ? 0 : 1, active_revision: null, activated_at: null, policy: null }
      body.items[0] = { node_id: id, freshness: 'not_reported', revision_state: 'unknown', delivery_state: 'serving', stale_after_ms: null, sample: null }
    } else if (state === 'saved') body.configuration.head_revision = 4
    else if (state === 'disabled') body.configuration.policy!.enabled = false
    else if (state === 'not_reported') Object.assign(body.items[0]!, { sample: null, freshness: 'not_reported', revision_state: 'unknown', delivery_state: 'serving' })
    else if (state === 'stale') { body.observed_at = '2026-10-10T10:01:00Z'; body.items[0]!.freshness = 'stale' }
    else if (state === 'clock_skew') { body.items[0]!.freshness = 'clock_skew'; body.items[0]!.sample!.observed_at = '2026-10-10T10:00:06Z' }
    else if (state === 'different') { body.items[0]!.revision_state = 'different'; body.items[0]!.sample!.config_revision = 2 }
    else if (state === 'rolled_back') { body.items[0]!.revision_state = 'rolled_back'; body.items[0]!.sample!.rolled_back = true }
    else if (state === 'awaiting_configuration') {
      // A blank node never received the artifact: no sample, and never "not reported yet".
      Object.assign(body.items[0]!, { sample: null, freshness: 'not_reported', revision_state: 'unknown', delivery_state: state })
    } else if (state === 'inactive') body.items[0]!.delivery_state = state
    else { body.items[0]!.sample!.healthy = false; body.items[0]!.sample!.probe_succeeded = false }
    renderPage()
    const cell = await findCell(cellState)
    expect(cell).toHaveTextContent(visible)
    expect(cell).toHaveAttribute('title', expect.stringContaining(expected))
    expect(cell).not.toHaveClass('is-success')
    if (['stale', 'clock_skew', 'rolled_back', 'unhealthy'].includes(state)) expect(cell).toHaveClass('is-danger')
    if (state === 'unconfigured' || state === 'not_activated') {
      expect(within(cell).getByRole('link')).toHaveAttribute('href', '/node/monitor-setting')
    }
    expect(cell.closest('tr')!.querySelector('.node-state-cell')).toHaveAttribute('title', expect.stringContaining('在线'))
    expect(document.body).not.toHaveTextContent('监控已关闭')
  })

  it.each(['http', 'ping'] as const)('does not present requested %s as executed, and preserves last probe failure separately from threshold health', async (protocol) => {
    body.configuration.policy!.requested_protocol = protocol
    body.items[0]!.sample!.probe_succeeded = false
    renderPage()
    const cell = await findCell('healthy')
    expect(cell).toHaveTextContent(`${protocol}[日志]`)
    expect(cell).not.toHaveClass('is-success')
    expect(cell).toHaveAttribute('title', expect.stringContaining(protocol === 'http' ? '请求协议：HTTP' : '请求协议：Ping'))
    expect(cell).toHaveAttribute('title', expect.stringContaining('本次探测：失败'))
    expect(cell).toHaveAttribute('title', expect.stringContaining('仅证明节点本机端口'))
    expect(cell).not.toHaveTextContent(/HTTP 正常|Ping 正常/)
  })

  it.each([['saved', '新配置未激活', '监控已回滚'], ['disabled', '关闭待确认', '监控已过期']])(
    'preserves the actual sample problem while %s configuration is pending', async (state, label, sampleState) => {
      if (state === 'saved') {
        body.configuration.head_revision = 4
        body.items[0]!.revision_state = 'rolled_back'
        body.items[0]!.sample!.rolled_back = true
      } else {
        body.configuration.policy!.enabled = false
        body.observed_at = '2026-10-10T10:01:00Z'
        body.items[0]!.freshness = 'stale'
      }
      renderPage()
      const cell = await findCell(state === 'saved' ? 'savedNotActivated' : 'disablePending')
      expect(cell).toHaveAttribute('title', expect.stringContaining(label))
      expect(cell).toHaveAttribute('title', expect.stringContaining(`最近样本状态：${sampleState}`))
      expect(cell).not.toHaveClass('is-success')
    },
  )

  it.each([[43000, false], [43001, true], [-5000, false], [-5001, true]])('handles server sample age %s ms at exact boundaries', async (age, invalid) => {
    if (age < 0) body.items[0]!.sample!.observed_at = new Date(Date.parse(time) - age).toISOString()
    else body.observed_at = new Date(Date.parse(time) + age).toISOString()
    body.items[0]!.freshness = age < -5000 ? 'clock_skew' : age > 43000 ? 'stale' : 'fresh'
    renderPage()
    expect(await findCell(invalid ? age < 0 ? 'clockSkew' : 'stale' : 'healthy')).toBeInTheDocument()
  })

  it('ages cached probe data using monotonic time during a stalled refresh rather than the wall clock', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    renderPage()
    expect(await findCell('healthy')).toBeInTheDocument()
    reply = new Promise(() => undefined)
    fireEvent.click(screen.getByRole('button', { name: '刷新监控' }))
    vi.spyOn(Date, 'now').mockReturnValue(0)
    monotonic = 43001
    await act(async () => { await vi.advanceTimersByTimeAsync(1000) })
    expect(await findCell('stale')).toBeInTheDocument()
    expect(calls).toHaveLength(2)
  })

  it('polls at most one request every 10 seconds and does not rejuvenate an unchanged sample', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    renderPage()
    expect(await findCell('healthy')).toBeInTheDocument()
    monotonic = 40000; body.observed_at = '2026-10-10T10:00:40Z'
    await act(async () => { await vi.advanceTimersByTimeAsync(10000) })
    await waitFor(() => expect(calls).toHaveLength(2))
    monotonic = 43001
    await act(async () => { await vi.advanceTimersByTimeAsync(1000) })
    expect(await findCell('stale')).toBeInTheDocument()
    reply = new Promise(() => undefined)
    fireEvent.click(screen.getByRole('button', { name: '刷新监控' }))
    await act(async () => { await vi.advanceTimersByTimeAsync(30000) })
    expect(calls).toHaveLength(3)
    fireEvent.click(screen.getByRole('tab', { name: '待初始化' }))
    await act(async () => { await vi.advanceTimersByTimeAsync(30000) })
    expect(calls).toHaveLength(3)
  })

  it('continues aging an already displayed sample when the inventory refresh fails', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    renderPage()
    expect(await findCell('healthy')).toBeInTheDocument()
    vi.mocked(nodesApi.list).mockRejectedValueOnce(new Error('inventory temporarily unavailable'))
    await act(async () => { await client.invalidateQueries({ queryKey: ['nodes'] }) })
    await waitFor(() => expect(client.getQueryCache().getAll().find((query) => query.queryKey[0] === 'nodes')?.state.status).toBe('error'))
    expect(screen.getByRole('button', { name: '刷新监控' })).toBeDisabled()
    monotonic = 43001
    await act(async () => { await vi.advanceTimersByTimeAsync(1000) })
    expect(await findCell('stale')).toBeInTheDocument()
    expect(calls).toHaveLength(1)
  })

  it.each([503, 404, 200])('hides cached health on status %s or malformed data and permits manual GET retry', async (failure) => {
    renderPage()
    expect(await findCell('healthy')).toBeInTheDocument()
    status = failure
    if (failure === 200) body.items = []
    fireEvent.click(screen.getByRole('button', { name: '刷新监控' }))
    expect(await screen.findByText(failure === 404 ? '监控节点不可读取' : failure === 200 ? '监控数据无效' : '监控暂不可用')).toBeInTheDocument()
    expect(cells('healthy')).toHaveLength(0)
    expect(document.body).not.toHaveTextContent('private-backend-text')
    status = 200; body = structuredClone(valid)
    fireEvent.click(screen.getByRole('button', { name: '刷新监控' }))
    expect(await findCell('healthy')).toBeInTheDocument()
    expect(calls).toHaveLength(3)
  })

  it('fails current 403 closed, clears its caches and does not fetch for empty or forbidden lists', async () => {
    status = 403
    renderPage()
    expect(await screen.findByText('无权查看节点列表')).toBeInTheDocument()
    await waitFor(() => expect(client.getQueryCache().getAll().filter((query) => query.queryKey[0] === 'node-monitoring')
      .every((query) => query.state.data === undefined)).toBe(true))
    expect(screen.queryByRole('button', { name: node.name })).not.toBeInTheDocument()
    expect(calls).toHaveLength(1)
  })

  it('does not request probes on an empty page or a tenant/non-reader session', async () => {
    list = { items: [] }
    renderPage()
    await waitFor(() => expect(nodesApi.list).toHaveBeenCalledTimes(1))
    expect(calls).toHaveLength(0)
    act(() => useSessionStore.setState({ principal: { ...admin, scope_kind: 'tenant', tenant_id: other } }))
    expect(await screen.findByText('无权查看节点列表')).toBeInTheDocument()
    expect(calls).toHaveLength(0)
  })

  it('uses a renewed token only at request time and keeps keys token-free and cache failures separate from node saves', async () => {
    renderPage()
    expect(await findCell('healthy')).toBeInTheDocument()
    act(() => useSessionStore.setState({ accessToken: 'renewed-private-token' }))
    expect(calls).toHaveLength(1)
    status = 503
    fireEvent.click(screen.getByRole('button', { name: '刷新监控' }))
    expect(await screen.findByText('监控暂不可用')).toBeInTheDocument()
    const call = vi.mocked(fetch).mock.calls.at(-1)!
    expect(new Headers(call[1]?.headers).get('Authorization')).toBe('Bearer renewed-private-token')
    const keys = JSON.stringify(client.getQueryCache().getAll().map((query) => query.queryKey))
    expect(keys).toContain(admin.scope_id); expect(keys).toContain(admin.user_id)
    expect(keys).not.toMatch(/access-token|renewed-private-token/)
    await act(async () => { await expect(client.invalidateQueries({ queryKey: ['nodes'] }, { throwOnError: true })).resolves.toBeUndefined() })
    expect(calls).toHaveLength(2)
  })

  it.each([200, 403])('discards a previous-page late response %s', async (lateStatus) => {
    let resolve!: (value: Response) => void
    reply = new Promise((done) => { resolve = done })
    list = { items: [node], next_cursor: 'next-page' }
    renderPage()
    await waitFor(() => expect(calls).toHaveLength(1))
    list = { items: [{ ...node, id: other, display_id: '2', name: 'Second edge' }] }
    body.items = [{ node_id: other, sample: null, stale_after_ms: 43000, freshness: 'not_reported', revision_state: 'unknown', delivery_state: 'serving' }]
    reply = undefined
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    expect(await findCell('notReported')).toBeInTheDocument()
    await act(async () => resolve(new Response(JSON.stringify(lateStatus === 200 ? valid : { error: { code: 'permission_denied' } }), { status: lateStatus })))
    expect(screen.getByRole('button', { name: 'Second edge' })).toBeInTheDocument()
    expect(cells('healthy')).toHaveLength(0)
    expect(calls).toHaveLength(2)
  })

  it.each((['owner', 'scope', 'epoch', 'permission', 'logout'] as const).flatMap((change) => [200, 403].map((lateStatus) => [change, lateStatus] as const)))(
    'isolates %s changes from late status %s without revoking a newer owner', async (change, lateStatus) => {
    let resolve!: (value: Response) => void
    reply = new Promise((done) => { resolve = done })
    renderPage()
    await waitFor(() => expect(calls).toHaveLength(1))
    reply = undefined
    body.items = [{ node_id: id, sample: null, stale_after_ms: 43000, freshness: 'not_reported', revision_state: 'unknown', delivery_state: 'serving' }]
    const next = { ...admin, ...(change === 'owner' ? { user_id: other } : {}), ...(change === 'scope' ? { scope_id: other } : {}),
      ...(change === 'permission' ? { permissions: [] } : {}) }
    act(() => {
      if (change === 'logout') useSessionStore.setState({ accessToken: null, principal: null })
      else useSessionStore.getState().setSession(authResponse(next), next, change === 'permission' ? 'refresh' : 'new')
    })
    if (!['permission', 'logout'].includes(change)) expect(await findCell('notReported')).toBeInTheDocument()
    await act(async () => resolve(new Response(JSON.stringify(lateStatus === 200 ? valid : { error: { code: 'permission_denied' } }), { status: lateStatus })))
    expect(cells('healthy')).toHaveLength(0)
    if (!['permission', 'logout'].includes(change)) {
      expect(cells('notReported')).toHaveLength(1)
      expect(screen.queryByText('无权查看节点列表')).not.toBeInTheDocument()
    }
    expect(JSON.stringify(client.getQueryCache().getAll().map((query) => query.state.data))).not.toContain('9007199254740993')
  })

  it('batches all 300 current-page IDs once rather than per-node or top-ranking requests', async () => {
    list = { items: Array.from({ length: 300 }, (_, index) => ({ ...node,
      id: `018f0000-0000-7000-8000-${String(index + 1).padStart(12, '0')}`, display_id: String(index + 1), name: `Edge ${index + 1}` })) }
    body.items = list.items.map((item) => ({ node_id: item.id, sample: null, stale_after_ms: 43000, freshness: 'not_reported', revision_state: 'unknown', delivery_state: 'serving' }))
    renderPage()
    await waitFor(() => expect(cells('notReported')).toHaveLength(300), { timeout: 60_000 })
    expect(calls).toHaveLength(1)
    expect(new URL(calls[0]!, 'https://example.test').searchParams.getAll('node_id')).toEqual(list.items.map((item) => item.id))
  })

  it.each([['zh-CN', 'TCP 正常'], ['qps-ploc', '［T~C~P~ 正~常~］']] as const)('keeps %s long state text accessible in the existing compact narrow-screen cell', async (locale, label) => {
    await changeLocale(locale)
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    renderPage()
    const cell = await findCell('healthy')
    expect(cell).toHaveAttribute('aria-label', expect.stringContaining(label))
    expect(cell).toHaveAttribute('tabindex', '0')
    expect(cell).toHaveStyle({ maxWidth: '100%' })
    expect(css).toMatch(/\.node-monitor-cell > span\s*\{[^}]*text-overflow:\s*ellipsis/s)
    expect(css).toMatch(/\.node-monitor-cell\.is-danger > \.node-monitor-protocol\s*\{[^}]*color:/s)
    expect(cell.getAttribute('title')).not.toMatch(/monitor\.[a-z]/)
    fireEvent.focus(cell)
    expect(await screen.findByRole('tooltip')).toHaveTextContent(locale === 'zh-CN' ? '节点本机 TCP 探测' : '节~点~本~机~')
  })

  const overrideView = (revision: number, override: Record<string, unknown>, effective: Record<string, unknown>) => ({
    schema_version: 1, node_id: id, revision, updated_at: revision === 0 ? null : time,
    override: { monitor_enabled: null, protocol: null, probe_timeout_ms: null, monitor_port: null, monitor_action: null, ...override },
    platform_state: 'active', platform_revision: 3, effective_revision: 3 + revision,
    effective_policy: { ...valid.configuration.policy!, ...effective }, effective_action: 'none', delivery_state: 'serving',
  })

  it('edits the per-node "配置监控" override from the protocol and reloads what was saved', async () => {
    const user = userEvent.setup()
    useSessionStore.getState().setSession(authResponse(managerPrincipal), managerPrincipal)
    let stored = overrideView(0, {}, { probe_timeout_ms: 5000 })
    const writes: Array<{ key: string | null; body: unknown }> = []
    vi.mocked(globalThis.fetch).mockImplementation(async (input, init) => {
      const url = String(input); calls.push(url)
      if (url === `/v1/nodes/${id}/monitoring/override`) {
        if (init?.method === 'PUT') {
          const request = JSON.parse(String(init.body))
          writes.push({ key: new Headers(init.headers).get('Idempotency-Key'), body: request })
          stored = overrideView(1, request.override, { probe_timeout_ms: 4000, requested_port: 8080 })
        }
        return new Response(JSON.stringify(stored))
      }
      return new Response(JSON.stringify(body))
    })
    renderPage()
    const cell = await findCell('healthy')
    await user.click(within(cell).getByRole('button', { name: 'tcp' }))
    let dialog = await findDialog('node-monitor-config-modal', '配置监控')
    await waitFor(() => expect(within(dialog).getByLabelText('检查超时')).toHaveValue('5'))
    expect(within(dialog).getByRole('switch', { name: '监控开关' })).toBeChecked()
    expect(within(dialog).getByRole('switch', { name: '监控开关' })).toBeEnabled()
    expect(within(dialog).getByRole('radio', { name: 'TCP' })).toBeChecked()
    expect(within(dialog).getByRole('radio', { name: 'HTTP' })).toBeEnabled()
    expect(within(dialog).getByText('秒')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('端口')).toHaveValue('80')
    for (const group of ['国内组', '电信组', '联通组', '移动组', '国外组']) {
      expect(within(dialog).getByRole('checkbox', { name: group })).toBeDisabled()
    }
    // The failure action is enforced, so it is editable; untouched it inherits.
    expect(within(dialog).getByRole('radio', { name: '不处理' })).toBeChecked()
    expect(within(dialog).getByRole('radio', { name: '暂停' })).toBeEnabled()
    expect(within(dialog).getByText(/从线路分组的解析记录中移除/)).toBeInTheDocument()
    // Out-of-range input is rejected locally and never written.
    await user.clear(within(dialog).getByLabelText('检查超时'))
    await user.type(within(dialog).getByLabelText('检查超时'), '11')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText(/检查超时需在 0.1 到 10 秒之间/)).toBeInTheDocument()
    expect(writes).toHaveLength(0)
    await user.clear(within(dialog).getByLabelText('检查超时'))
    await user.type(within(dialog).getByLabelText('检查超时'), '4')
    await user.clear(within(dialog).getByLabelText('端口'))
    await user.type(within(dialog).getByLabelText('端口'), '8080')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(document.querySelector('.node-monitor-config-modal')).toBeNull())
    // Untouched switch and protocol stay inherited (null); only edited fields are pinned.
    expect(writes).toHaveLength(1)
    expect(writes[0]!.key).toMatch(/^node-monitoring-override-/)
    expect(writes[0]!.body).toEqual({ expected_revision: 0, override: {
      monitor_enabled: null, protocol: null, probe_timeout_ms: 4000, monitor_port: 8080, monitor_action: null } })
    // Saving refreshes the list snapshot; reopening shows the stored override.
    expect(calls.filter((url) => url.startsWith('/v1/nodes/monitoring/latest?')).length).toBeGreaterThan(1)
    await user.click(within(await findCell('healthy')).getByRole('button', { name: 'tcp' }))
    dialog = await findDialog('node-monitor-config-modal', '配置监控')
    await waitFor(() => expect(within(dialog).getByLabelText('检查超时')).toHaveValue('4'))
    expect(within(dialog).getByLabelText('端口')).toHaveValue('8080')
    expect(within(dialog).getByText(/本节点覆盖版本 1，下发配置版本 4/)).toBeInTheDocument()
    // Choosing "暂停" pins the action for this node.
    await user.click(within(dialog).getByRole('radio', { name: '暂停' }))
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(writes).toHaveLength(2))
    expect(writes[1]!.body).toEqual({ expected_revision: 1, override: {
      monitor_enabled: null, protocol: null, probe_timeout_ms: 4000, monitor_port: 8080, monitor_action: 'pause' } })
  })

  it('marks a monitor-paused node and opens its pause/restore log', async () => {
    const user = userEvent.setup()
    body.items[0] = { ...body.items[0]!, serving_holds: [{ source: 'availability_monitor', reason_code: 'probe_unhealthy',
      held_since: '2026-10-10T09:58:00Z', protected_groups: 0 }] }
    const servingCalls: URL[] = []
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = String(input); calls.push(url)
      if (url.startsWith(`/v1/nodes/${id}/serving/events?`)) {
        const parsed = new URL(url, 'https://example.test'); servingCalls.push(parsed)
        return new Response(JSON.stringify({ schema_version: 1, node_id: id, from: '2026-10-09T10:00:00Z', to: time, page: 1, limit: 10, total: 2,
          items: [
            { id: '018f0000-0000-7000-8000-0000000000a2', source: 'availability_monitor', event: 'released', reason_code: 'probe_recovered',
              hold_revision: 2, detail: {}, occurred_at: '2026-10-10T09:59:00Z' },
            { id: '018f0000-0000-7000-8000-0000000000a1', source: 'availability_monitor', event: 'held', reason_code: 'probe_unhealthy',
              hold_revision: 1, detail: { healthy: false }, occurred_at: '2026-10-10T09:58:00Z' },
          ] }))
      }
      return new Response(JSON.stringify(body))
    })
    renderPage()
    const paused = await screen.findByRole('button', { name: /监控故障动作：节点探测连续失败/ })
    expect(paused).toHaveTextContent('已暂停')
    await user.click(paused)
    const dialog = await findDialog('node-monitor-log-modal', '监控日志')
    expect(within(dialog).getByRole('combobox', { name: '日志查看' }).closest('.ant-select')).toHaveTextContent('暂停/恢复记录')
    await waitFor(() => expect(within(dialog).getAllByRole('row')).toHaveLength(3))
    expect(within(dialog).getAllByRole('columnheader').map((header) => header.textContent)).toEqual(['时间', '事件', '来源', '原因'])
    expect(within(within(dialog).getAllByRole('row')[2]!).getAllByRole('cell').map((td) => td.textContent).slice(1))
      .toEqual(['已暂停解析', '监控故障动作', '节点探测连续失败'])
    expect(servingCalls).toHaveLength(1)
    // 默认今天（今天 00:00 至当前）。
    expect(Date.parse(servingCalls[0]!.searchParams.get('from')!)).toBe(new Date(new Date(Date.parse(servingCalls[0]!.searchParams.get('to')!)).setHours(0, 0, 0, 0)).getTime())
    expect(within(dialog).getByText(/节点保持在线/)).toBeInTheDocument()
  })

  it('rejects a malformed serving hold rather than rendering it', async () => {
    body.items[0] = { ...body.items[0]!, serving_holds: [] }
    renderPage()
    expect(await findCell('invalid')).toBeInTheDocument()
    expect(screen.queryByText('已暂停')).not.toBeInTheDocument()
  })

  it('keeps "配置监控" read-only without node management permission', async () => {
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = String(input); calls.push(url)
      if (url === `/v1/nodes/${id}/monitoring/override`) return new Response(JSON.stringify(overrideView(0, {}, {})))
      return new Response(JSON.stringify(body))
    })
    const user = userEvent.setup()
    renderPage()
    await user.click(within(await findCell('healthy')).getByRole('button', { name: 'tcp' }))
    const dialog = await findDialog('node-monitor-config-modal', '配置监控')
    await waitFor(() => expect(within(dialog).getByLabelText('检查超时')).toHaveValue('3'))
    expect(within(dialog).getByRole('switch', { name: '监控开关' })).toBeDisabled()
    expect(within(dialog).getByRole('button', { name: '确定' })).toBeDisabled()
  })

  it('classifies an overridden node against its own effective revision and protocol', async () => {
    body.items[0] = { ...body.items[0]!, effective_revision: 5, stale_after_ms: 45000,
      effective_policy: { ...valid.configuration.policy!, requested_protocol: 'http', probe_timeout_ms: 5000 },
      sample: { ...body.items[0]!.sample!, source: 'agent_local_http', config_revision: 5, active_config_revision: 5 } }
    renderPage()
    const cell = await findCell('healthy')
    expect(cell).toHaveTextContent(/^http\[日志\]$/)
    expect(cell).toHaveAttribute('title', expect.stringContaining('本节点覆盖监控配置（版本 5）'))
  })

  it('opens "监控日志" from [日志] and pages the real per-node probe history for the last hour', async () => {
    const user = userEvent.setup()
    const historyCalls: URL[] = []
    const history = (page: number, limit: number) => ({
      schema_version: 1, node_id: id, from: '2026-10-10T09:00:00Z', to: time, page, limit, total: 12,
      items: Array.from({ length: page === 1 ? 10 : 2 }, (_, index) => ({
        observed_at: `2026-10-10T09:${String(59 - index - (page - 1) * 10).padStart(2, '0')}:00Z`, config_revision: 3,
        active_config_revision: 3, probe_port: 80, probe_succeeded: index !== 0, healthy: index !== 0,
        failed_checks: index === 0 ? 1 : 0, total_checks: 1,
      })),
    })
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = String(input); calls.push(url)
      if (url.startsWith(`/v1/nodes/${id}/monitoring/history?`)) {
        const parsed = new URL(url, 'https://example.test')
        if (parsed.searchParams.get('source') === 'peer') {
          return new Response(JSON.stringify({ schema_version: 1, source: 'peer', node_id: id, from: '2026-10-10T09:00:00Z',
            to: time, page: 1, limit: 10, total: 0, items: [] }))
        }
        historyCalls.push(parsed)
        return new Response(JSON.stringify(history(Number(parsed.searchParams.get('page')), Number(parsed.searchParams.get('limit')))))
      }
      return new Response(JSON.stringify(body))
    })
    renderPage()
    const cell = await findCell('healthy')
    await user.click(within(cell).getByRole('button', { name: '[日志]' }))
    const dialog = await findDialog('node-monitor-log-modal', '监控日志')
    expect(within(dialog).getByRole('combobox', { name: '日志查看' }).closest('.ant-select')).toHaveTextContent('可用性监控日志')
    // 共享时间范围组件；快捷项今天/近7天/近30天，默认今天；可用性日志最长 7 天，超出的快捷项不显示。
    const range = within(dialog).getByRole('group', { name: '时间段' })
    expect(within(range).getByRole('radio', { name: '今天' })).toBeChecked()
    expect(within(range).getByRole('radio', { name: '近7天' })).toBeInTheDocument()
    expect(within(range).queryByRole('radio', { name: '近30天' })).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('combobox', { name: '数据来源' }))
    await user.click(await screen.findByTitle('节点本机探测'))
    expect(within(dialog).getByRole('combobox', { name: '监控组' }).closest('.ant-select')).toHaveTextContent('所有监控组')
    expect(within(dialog).getByRole('combobox', { name: '监控组' })).toBeDisabled()
    expect(within(dialog).getAllByRole('columnheader').map((header) => header.textContent)).toEqual(['检测时间', '失败个数', '总检测点'])
    await waitFor(() => expect(within(dialog).getAllByRole('row')).toHaveLength(11))
    expect(historyCalls).toHaveLength(1)
    const [first] = historyCalls
    expect(first!.searchParams.get('page')).toBe('1')
    expect(first!.searchParams.get('limit')).toBe('10')
    expect(Date.parse(first!.searchParams.get('from')!)).toBe(new Date(new Date(Date.parse(first!.searchParams.get('to')!)).setHours(0, 0, 0, 0)).getTime())
    const firstRow = within(dialog).getAllByRole('row')[1]!
    expect(within(firstRow).getAllByRole('cell').map((td) => td.textContent).slice(1)).toEqual(['1', '1'])
    await user.click(within(dialog).getByTitle('2'))
    await waitFor(() => expect(historyCalls).toHaveLength(2))
    expect(historyCalls[1]!.searchParams.get('page')).toBe('2')
    await waitFor(() => expect(within(dialog).getAllByRole('row')).toHaveLength(3))
    expect(within(dialog).getByText(/每条记录是一次节点本机端口探测/)).toBeInTheDocument()
  })

  // 没装 dnspup 时默认看节点互拨日志（主控 + 其他节点），每条可展开检测点明细。
  it('defaults to the controller + peer node probe log without dnspup and expands each round', async () => {
    const user = userEvent.setup()
    const peerCalls: URL[] = []
    const items: unknown[] = [{ observed_at: time, address: '198.51.100.7', port: 443, failed: true, controller_ok: false,
      failed_checks: 2, total_checks: 3, checkpoints: [{ id: 'controller', ok: false },
        { id: 'n2', name: 'edge-2', address: '198.51.100.8', groups: ['domestic', 'telecom'], ok: false },
        { id: 'n3', name: 'edge-3', address: '198.51.100.9', ok: true, latency_ms: 21 }] }]
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = String(input); calls.push(url)
      if (url.startsWith(`/v1/nodes/${id}/monitoring/history?`)) {
        const parsed = new URL(url, 'https://example.test')
        if (parsed.searchParams.get('source') !== 'peer') throw new Error('non-peer history requested: ' + url)
        peerCalls.push(parsed)
        return new Response(JSON.stringify({ schema_version: 1, source: 'peer', node_id: id, from: '2026-10-10T09:00:00Z',
          to: time, page: 1, limit: 10, total: items.length, items }))
      }
      return new Response(JSON.stringify(body))
    })
    renderPage()
    const cell = await findCell('healthy')
    await user.click(within(cell).getByRole('button', { name: '[日志]' }))
    const dialog = await findDialog('node-monitor-log-modal', '监控日志')
    expect(within(dialog).getByRole('combobox', { name: '数据来源' }).closest('.ant-select')).toHaveTextContent('节点互拨')
    await waitFor(() => expect(peerCalls).toHaveLength(1))
    expect(peerCalls[0]!.searchParams.has('group')).toBe(false)
    expect(within(dialog).getAllByRole('columnheader').map((header) => header.textContent).filter(Boolean))
      .toEqual(['检测时间', '节点 IP', '失败个数', '总检测点'])
    expect(await within(dialog).findByText('198.51.100.7:443')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: /展开行|Expand row/ }))
    expect(await within(dialog).findByText(/主控 失败/)).toBeInTheDocument()
    expect(within(dialog).getByText(/edge-2（198\.51\.100\.8） 失败/)).toBeInTheDocument()
    expect(within(dialog).getByText(/edge-3（198\.51\.100\.9） 正常 21 ms/)).toBeInTheDocument()
    expect(within(dialog).getByText(/主控探测与多数互拨节点都失败才判定不可达/)).toBeInTheDocument()
  })

  it('explains an empty peer probe log by its source', async () => {
    const user = userEvent.setup()
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = String(input); calls.push(url)
      if (url.startsWith(`/v1/nodes/${id}/monitoring/history?`)) {
        return new Response(JSON.stringify({ schema_version: 1, source: 'peer', node_id: id, from: '2026-10-10T09:00:00Z',
          to: time, page: 1, limit: 10, total: 0, items: [] }))
      }
      return new Response(JSON.stringify(body))
    })
    renderPage()
    const cell = await findCell('healthy')
    await user.click(within(cell).getByRole('button', { name: '[日志]' }))
    const dialog = await findDialog('node-monitor-log-modal', '监控日志')
    expect(await within(dialog).findByText(/暂无节点互拨记录/)).toBeInTheDocument()
  })

  // probe-node：装了 dnspup 拨测插件后，监控组可按运营商筛选 dnspup 检测点日志（失败个数/总检测点）。
  it('pages dnspup checkpoint rounds by carrier when the dnspup probe plugin is installed', async () => {
    const user = userEvent.setup()
    const dnspupCalls: URL[] = []
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = String(input); calls.push(url)
      if (url.endsWith('/v1/modules')) return new Response(JSON.stringify({ status: 'active', lease_serial: 1, modules: ['module.probe.dnspup'] }))
      if (url.startsWith(`/v1/nodes/${id}/monitoring/history?`)) {
        const parsed = new URL(url, 'https://example.test')
        if (parsed.searchParams.get('source') !== 'dnspup') throw new Error('local history requested: ' + url)
        dnspupCalls.push(parsed)
        const group = parsed.searchParams.get('group') ?? ''
        return new Response(JSON.stringify({ schema_version: 1, source: 'dnspup', node_id: id, group, from: '2026-10-10T09:00:00Z',
          to: time, page: 1, limit: 10, total: 1, items: [{ observed_at: time, address: '198.51.100.7', port: 443, failed: true,
            failed_checks: 2, total_checks: 3, checkpoints: [{ id: 't1', group: 'telecom', location: '广东电信', ok: false }] }] }))
      }
      return new Response(JSON.stringify(body))
    })
    renderPage()
    const cell = await findCell('healthy')
    await user.click(within(cell).getByRole('button', { name: '[日志]' }))
    const dialog = await findDialog('node-monitor-log-modal', '监控日志')
    await waitFor(() => expect(within(dialog).getByRole('combobox', { name: '监控组' })).toBeEnabled())
    await waitFor(() => expect(dnspupCalls).toHaveLength(1))
    expect(dnspupCalls[0]!.searchParams.has('group')).toBe(false)
    expect(within(dialog).getAllByRole('columnheader').map((header) => header.textContent)).toContain('节点 IP')
    expect(await within(dialog).findByText('198.51.100.7:443')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('combobox', { name: '监控组' }))
    await user.click(await screen.findByTitle('电信组'))
    await waitFor(() => expect(dnspupCalls.at(-1)!.searchParams.get('group')).toBe('telecom'))
    expect(within(dialog).getByText(/本机探测与 dnspup 多数检测点都失败才暂停解析/)).toBeInTheDocument()
  })

  // 按节点记住上次选的数据来源；记住的来源不可用（未装 dnspup）时回退到可用来源。
  it('remembers the chosen data source per node across reopening the monitor log', async () => {
    const user = userEvent.setup()
    const sources: string[] = []
    localStorage.setItem(`cdnca.ui.nodeMonitorSource.${other}`, 'local')
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = String(input); calls.push(url)
      if (url.endsWith('/v1/modules')) return new Response(JSON.stringify({ status: 'active', lease_serial: 1, modules: ['module.probe.dnspup'] }))
      if (url.startsWith(`/v1/nodes/${id}/monitoring/history?`)) {
        const source = new URL(url, 'https://example.test').searchParams.get('source') ?? 'local'
        sources.push(source)
        return new Response(JSON.stringify({ schema_version: 1, source, node_id: id, from: '2026-10-10T09:00:00Z',
          to: time, page: 1, limit: 10, total: 0, items: [] }))
      }
      return new Response(JSON.stringify(body))
    })
    renderPage()
    const cell = await findCell('healthy')
    await user.click(within(cell).getByRole('button', { name: '[日志]' }))
    let dialog = await findDialog('node-monitor-log-modal', '监控日志')
    const sourceSelect = () => within(dialog).getByRole('combobox', { name: '数据来源' }).closest('.ant-select')
    await waitFor(() => expect(sourceSelect()).toHaveTextContent('dnspup'))
    await user.click(within(dialog).getByRole('combobox', { name: '数据来源' }))
    await user.click(await screen.findByTitle('节点互拨（主控 + 其他节点）'))
    await waitFor(() => expect(sources.at(-1)).toBe('peer'))
    await user.click(dialog.querySelector('.ant-modal-close')!)
    await waitFor(() => expect(document.querySelector('.node-monitor-log-modal [role="dialog"], [role="dialog"].node-monitor-log-modal')).toBeNull())
    sources.length = 0
    await user.click(within(cell).getByRole('button', { name: '[日志]' }))
    dialog = await findDialog('node-monitor-log-modal', '监控日志')
    expect(sourceSelect()).toHaveTextContent('节点互拨')
    await waitFor(() => expect(sources).toContain('peer'))
    expect(sources).not.toContain('dnspup')
    expect(localStorage.getItem(`cdnca.ui.nodeMonitorSource.${other}`)).toBe('local')
  })

  it('falls back to an available source when the remembered one is dnspup without the dnspup plugin', async () => {
    const user = userEvent.setup()
    const sources: string[] = []
    localStorage.setItem(`cdnca.ui.nodeMonitorSource.${id}`, 'dnspup')
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = String(input); calls.push(url)
      if (url.startsWith(`/v1/nodes/${id}/monitoring/history?`)) {
        const source = new URL(url, 'https://example.test').searchParams.get('source') ?? 'local'
        sources.push(source)
        return new Response(JSON.stringify({ schema_version: 1, source, node_id: id, from: '2026-10-10T09:00:00Z',
          to: time, page: 1, limit: 10, total: 0, items: [] }))
      }
      return new Response(JSON.stringify(body))
    })
    renderPage()
    const cell = await findCell('healthy')
    await user.click(within(cell).getByRole('button', { name: '[日志]' }))
    const dialog = await findDialog('node-monitor-log-modal', '监控日志')
    expect(within(dialog).getByRole('combobox', { name: '数据来源' }).closest('.ant-select')).toHaveTextContent('节点互拨')
    await waitFor(() => expect(sources).toEqual(['peer']))
  })

  it('shows "[任务]" only beside a non-normal state and deep-links to that node\'s tasks', async () => {
    list = { items: [{ ...node, admin_state: 'disabled' }] }
    renderPage()
    const link = await screen.findByRole('link', { name: '查看任务' })
    expect(link).toHaveTextContent('[任务]')
    expect(link).toHaveAttribute('href', `/sys/task?resource_id=${id}`)
    expect(link.closest('.node-status-cell')).toHaveTextContent(/已禁用/)
  })
}, 120_000)
