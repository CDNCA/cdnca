import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { l4SessionLogsApi, validClientFilter } from '../api/l4SessionLogs'
import { streamsApi } from '../api/streams'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { stream } from '../tests/streamFixture'
import { L4AccessLogPage, L4LiveConnectionsPage } from './L4SessionPanels'

const tenantID = '018f0000-0000-7000-8000-000000000010'
const nodeA = '018f0000-0000-7000-8000-000000000021'
const nodeB = '018f0000-0000-7000-8000-000000000022'

function authenticate(permissions: string[]) {
  const actor = principal({ scope_kind: 'tenant', scope_id: tenantID, tenant_id: tenantID, permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function json(value: unknown) {
  return new Response(JSON.stringify(value), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

describe('L4 access log and live connections', () => {
  beforeEach(async () => {
    await changeLocale('zh-CN')
    useSessionStore.getState().clearSession()
    vi.spyOn(streamsApi, 'list').mockResolvedValue({ items: [{ ...stream, session_log_enabled: true }], total: 1, page: 1, limit: 100 })
  })
  afterEach(() => vi.restoreAllMocks())

  it('validates client filters', () => {
    for (const ok of ['', '203.0.113.10', '203.0.113.0/24', '2001:db8::1', '2001:db8::/32']) expect(validClientFilter(ok)).toBe(true)
    for (const bad of ['nope', '300.1.1.1', '1.1.1.1/33', '1.1.1.1/2/3']) expect(validClientFilter(bad)).toBe(false)
  })

  it('reads and filters the access log', async () => {
    authenticate(['sites.read', 'streams.read'])
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.includes('/l4-realtime')) return json({ version: 'l4-realtime/v1', meta: { range: '1h', timezone: 'UTC', from: '2026-09-15T02:00:00Z', to: '2026-09-15T03:00:00Z', snapshot: { source_watermark: 0, finalized_through: '2026-09-15T03:00:00Z' } }, totals: { sessions: 0, bytes_up: 0, bytes_down: 0, errors: 0 }, rows: [] })
      return json({ version: 'l4-session-logs/v1', from: '2026-09-15T02:00:00Z', to: '2026-09-15T03:00:00Z', rows: [{
        event_id: 'e1', started_at: '2026-09-15T02:59:00Z', finalized_at: '2026-09-15T02:59:05Z', node_id: nodeA, site_id: stream.id,
        stream_id: stream.id, listener_id: stream.id, protocol: 'tcp', listen_port: 443, client_ip: '203.0.113.10', client_port: 61000,
        peer_ip: '192.0.2.9', upstream_addr: '10.0.0.9:443', upstream_connect_ms: 3, bytes_up: 300, bytes_down: 1200, status_code: 500, end_reason: 'rate_limited',
      }], next_cursor: 'cursor-2' })
    })
    const user = userEvent.setup()
    renderWithProviders(<L4AccessLogPage />)
    expect(screen.getByRole('heading', { name: '四层访问日志' })).toBeInTheDocument()
    expect(await screen.findByText('超新建速率')).toBeInTheDocument()
    // #48②：有下一页时不是精确总数，写明总数未统计。
    expect(screen.getByText('已加载 1 条，还有更多，总数未统计')).toBeInTheDocument()
    expect(screen.getByText('经 192.0.2.9')).toBeInTheDocument()
    await user.type(screen.getByRole('textbox', { name: '客户端 IP' }), '203.0.113.0/24')
    await user.click(screen.getByRole('button', { name: /^查询$|^search 查询$/ }))
    await waitFor(() => expect(fetch.mock.calls.some(([input]) => String(input).includes('client_ip=203.0.113.0%2F24'))).toBe(true))
    await user.clear(screen.getByRole('textbox', { name: '客户端 IP' }))
    await user.type(screen.getByRole('textbox', { name: '客户端 IP' }), 'nope')
    await user.click(screen.getByRole('button', { name: /^查询$|^search 查询$/ }))
    expect(await screen.findByText('请输入有效的 IP 或 CIDR。')).toBeInTheDocument()
  })

  it('lists every forward live connections on open, newest first, names unsupported nodes and disconnects only where allowed', async () => {
    authenticate(['sites.read', 'streams.read', 'streams.manage'])
    const listAll = vi.spyOn(l4SessionLogsApi, 'listAll').mockResolvedValue({ streams: 1, streams_truncated: false, truncated: false,
      problems: [{ node_id: nodeB, node_name: 'old-1', state: 'unsupported' }],
      connections: [
        { node_id: nodeA, node_name: 'hk-1', stream_id: stream.id, stream_name: stream.name, can_close: true, session_key: '10.0.0.1|443|192.0.2.9|50000',
          listener_id: stream.id, listen_port: 443, client_ip: '203.0.113.10', client_port: 61000, peer_ip: '192.0.2.9', upstream: '10.0.0.9:443',
          started_at: '2026-09-15T02:59:00Z', bytes_received: 10, bytes_sent: 20 },
        { node_id: nodeA, node_name: 'hk-1', stream_id: stream.id, stream_name: stream.name, can_close: true, session_key: 'older',
          listener_id: stream.id, listen_port: 443, client_ip: '203.0.113.11', client_port: 61001, upstream: '10.0.0.9:443', started_at: '2026-09-15T02:50:00Z' },
      ] })
    const close = vi.spyOn(l4SessionLogsApi, 'closeLive').mockResolvedValue({ node_id: nodeA, state: 'ok', results: [{ session_key: '10.0.0.1|443|192.0.2.9|50000' }] })
    const user = userEvent.setup()
    renderWithProviders(<L4LiveConnectionsPage />)
    expect(screen.getByText(/只有开启“会话日志”的 TCP 转发会登记连接/)).toBeInTheDocument()
    // No forward picked and no button pressed: the page already asked.
    await waitFor(() => expect(listAll).toHaveBeenCalledWith(expect.any(String), {}, expect.anything()))
    expect(await screen.findByText('203.0.113.10:61000')).toBeInTheDocument()
    const clients = screen.getAllByText(/^203\.0\.113\.1[01]:/).map((cell) => cell.textContent)
    expect(clients[0]).toContain('203.0.113.10:61000')
    expect(screen.getByText(/old-1: 节点版本不支持实时连接/)).toBeInTheDocument()
    await user.click(screen.getAllByRole('button', { name: '断开' })[0])
    await user.click(within(await screen.findByRole('tooltip')).getByRole('button', { name: /确\s*定|OK/ }))
    await waitFor(() => expect(close).toHaveBeenCalledWith(expect.any(String), stream.id, nodeA, ['10.0.0.1|443|192.0.2.9|50000']))
    expect(await screen.findByText('已断开 1 个连接')).toBeInTheDocument()
    // Filters only narrow; 端口 sits in 高级筛选 (fix-advfilter), its tag × queries without it again.
    await user.click(screen.getByRole('button', { name: '高级筛选' }))
    await user.type(screen.getByRole('textbox', { name: '端口' }), '443')
    await user.click(screen.getByRole('button', { name: '应用' }))
    await waitFor(() => expect(listAll).toHaveBeenLastCalledWith(expect.any(String), { listenPort: 443 }, expect.anything()))
    expect(screen.getByRole('button', { name: '高级筛选 · 1' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '移除条件 端口' }))
    await waitFor(() => expect(listAll).toHaveBeenLastCalledWith(expect.any(String), {}, expect.anything()))
  })

  it('bans a client in one click: a ban rule first in the forward, then its open connections closed', async () => {
    authenticate(['sites.read', 'streams.read', 'streams.manage'])
    vi.spyOn(l4SessionLogsApi, 'listAll').mockResolvedValue({ streams: 1, streams_truncated: false, truncated: false, problems: [],
      connections: [{ node_id: nodeA, node_name: 'hk-1', stream_id: stream.id, stream_name: stream.name, can_close: true, session_key: 'k1',
        listener_id: stream.id, listen_port: 443, client_ip: '198.51.100.7', client_port: 1, upstream: 'u' }] })
    const allow = { id: '99999999-9999-4999-8999-999999999991', action: 'allow' as const, client_ip: { cidrs: ['0.0.0.0/0'] } }
    const current = { ...stream, session_log_enabled: true, revision: 4, guard_rules: [allow] }
    vi.spyOn(streamsApi, 'get').mockResolvedValue(current)
    const update = vi.spyOn(streamsApi, 'update').mockImplementation(async (_token, _id, fields) => ({ ...current, ...fields, revision: 5 }))
    const close = vi.spyOn(l4SessionLogsApi, 'closeLive').mockResolvedValue({ node_id: nodeA, state: 'ok', results: [{ session_key: 'k1' }] })
    const user = userEvent.setup()
    renderWithProviders(<L4LiveConnectionsPage />)
    expect(await screen.findByText('198.51.100.7:1')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '拉黑' }))
    const tooltip = await screen.findByRole('tooltip')
    expect(within(tooltip).getByText('拉黑 198.51.100.7？')).toBeInTheDocument()
    await user.clear(within(tooltip).getByRole('spinbutton', { name: '拉黑时长（秒）' }))
    await user.type(within(tooltip).getByRole('spinbutton', { name: '拉黑时长（秒）' }), '600')
    await user.click(within(tooltip).getByRole('button', { name: /确\s*定|OK/ }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    const [, id, fields] = update.mock.calls[0]
    expect(id).toBe(stream.id)
    expect(fields.expected_revision).toBe(4)
    expect(fields.guard_rules).toHaveLength(2)
    expect(fields.guard_rules![0]).toMatchObject({ action: 'ban', ban_seconds: 600, threshold: 1, client_ip: { cidrs: ['198.51.100.7/32'] } })
    expect(fields.guard_rules![1]).toEqual(allow)
    await waitFor(() => expect(close).toHaveBeenCalledWith(expect.any(String), stream.id, nodeA, ['k1']))
    expect(await screen.findByText(/已把 198\.51\.100\.7 加入防护规则（每次连接拉黑 600 秒）/)).toBeInTheDocument()
  })

  it('hides disconnect without streams.manage', async () => {
    authenticate(['sites.read', 'streams.read'])
    vi.spyOn(l4SessionLogsApi, 'listAll').mockResolvedValue({ streams: 1, streams_truncated: false, truncated: false, problems: [],
      connections: [{ node_id: nodeA, node_name: 'hk-1', stream_id: stream.id, stream_name: stream.name, can_close: true, session_key: 'k',
        listener_id: stream.id, listen_port: 443, client_ip: '198.51.100.7', client_port: 1, upstream: 'u' }] })
    renderWithProviders(<L4LiveConnectionsPage />)
    expect(await screen.findByText('198.51.100.7:1')).toBeInTheDocument()
    expect(screen.getByText('未登记')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '断开' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '拉黑' })).not.toBeInTheDocument()
  })

  it('platform sessions read every tenant on open; tenant and node are optional filters', async () => {
    const actor = principal({ scope_kind: 'platform', scope_id: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.includes('/l4-session-logs')) return json({ version: 'l4-session-logs/v1', rows: [
        { event_id: 'new', started_at: '2026-09-15T02:59:00Z', finalized_at: '2026-09-15T02:59:30Z', node_id: nodeA, site_id: stream.id,
          stream_id: stream.id, listener_id: stream.id, protocol: 'tcp', listen_port: 443, client_ip: '203.0.113.20', client_port: 1,
          bytes_up: 1, bytes_down: 1, status_code: 200, end_reason: 'closed' },
        { event_id: 'old', started_at: '2026-09-15T02:10:00Z', finalized_at: '2026-09-15T02:10:30Z', node_id: nodeB, site_id: stream.id,
          stream_id: stream.id, listener_id: stream.id, protocol: 'tcp', listen_port: 443, client_ip: '203.0.113.21', client_port: 1,
          bytes_up: 1, bytes_down: 1, status_code: 200, end_reason: 'closed' },
      ] })
      return new Response('{}', { status: 503, headers: { 'Content-Type': 'application/json' } })
    })
    const live = vi.spyOn(l4SessionLogsApi, 'listAll').mockResolvedValue({ streams: 0, streams_truncated: false, truncated: false, problems: [], connections: [] })
    const page = renderWithProviders(<L4AccessLogPage />)
    expect(await screen.findByText('203.0.113.20:1')).toBeInTheDocument()
    const logCall = fetch.mock.calls.map(([input]) => new URL(String(input), 'https://cdnca.test')).find((url) => url.pathname.endsWith('/l4-session-logs'))!
    expect(logCall.pathname).toBe('/v1/admin/analytics/l4-session-logs')
    expect(logCall.searchParams.has('tenant_id')).toBe(false)
    expect(logCall.searchParams.has('node_id')).toBe(false)
    expect(logCall.searchParams.get('range')).toBe('1h')
    // Rows keep the server's newest-first order.
    const cells = screen.getAllByText(/^203\.0\.113\.2[01]:1$/).map((cell) => cell.textContent)
    expect(cells).toEqual(['203.0.113.20:1', '203.0.113.21:1'])
    // fix-advfilter: 租户/节点 are in the 高级筛选 panel (closed at first).
    expect(screen.getByRole('combobox', { name: '租户', hidden: true })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '节点', hidden: true })).toBeInTheDocument()
    page.unmount()
    renderWithProviders(<L4LiveConnectionsPage />)
    await waitFor(() => expect(live).toHaveBeenCalledWith(expect.any(String), {}, expect.anything()))
    expect(screen.getByRole('combobox', { name: '租户', hidden: true })).toBeInTheDocument()
  })

  it('does not list forwards on the access log without streams.read and names the missing permission', async () => {
    authenticate(['sites.read'])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ version: 'l4-session-logs/v1', from: '2026-09-15T02:00:00Z', to: '2026-09-15T03:00:00Z', rows: [] }))
    renderWithProviders(<L4AccessLogPage />)
    expect(await screen.findByText(/streams\.read/)).toBeInTheDocument()
    expect(streamsApi.list).not.toHaveBeenCalled()
  })

  it('refuses the live page without streams.read and the access log without sites.read', () => {
    authenticate(['sites.read'])
    const fetch = vi.spyOn(globalThis, 'fetch')
    const live = renderWithProviders(<L4LiveConnectionsPage />)
    expect(screen.getByText('当前身份缺少四层转发读取权限，无法查看实时连接。')).toBeInTheDocument()
    live.unmount()
    authenticate(['streams.read'])
    renderWithProviders(<L4AccessLogPage />)
    expect(screen.getByText('当前身份缺少网站读取权限，无法查看四层访问日志。')).toBeInTheDocument()
    expect(fetch).not.toHaveBeenCalled()
  })
})
