import { fireEvent, screen, waitFor } from '@testing-library/react'

import * as session from '../auth/session'
import AdminInboxPage from '../pages/AdminInboxPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import '../i18n/adminInbox'

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const page = (items: unknown[], unread: number, next: string | null = null) =>
  json({ items, unread, total: items.length, next_cursor: next, unread_only: false, page_size: 20 })
const offline = { id: '11111111-1111-4111-8111-111111111111', event_type: 'node.availability.offline',
  params: { node_name: 'edge-1', node_ip: '192.0.2.10', reason: 'probe_failed' }, created_at: '2026-10-18T08:00:00Z', read_at: null }
const drift = { id: '22222222-2222-4222-8222-222222222222', event_type: 'acme.http01.epoch_drift',
  params: { site_domain: 'a.example.com', node_count: '2', node_names: 'n1,n2' }, created_at: '2026-10-18T07:00:00Z', read_at: '2026-10-18T07:30:00Z' }

function renderPage() {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'] })
  session.useSessionStore.getState().setSession(authResponse(actor), actor)
  return renderWithProviders(<AdminInboxPage />, ['/sys/inbox'])
}

it('renders platform events per language, marks one read and all read', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(page([offline, drift], 1))
    .mockResolvedValueOnce(new Response(null, { status: 204 }))
    .mockResolvedValue(page([{ ...offline, read_at: '2026-10-18T09:00:00Z' }, drift], 0))
  renderPage()
  expect(await screen.findByText('节点 edge-1（192.0.2.10）离线：probe_failed')).toBeInTheDocument()
  expect(screen.getByText('网站 a.example.com 的 HTTP-01 验证有 2 个节点未同步：n1,n2')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '标为已读' }))
  await waitFor(() => expect(String(fetchSpy.mock.calls[1][0])).toMatch(/\/v1\/admin\/inbox\/11111111-1111-4111-8111-111111111111\/read$/))
  expect(fetchSpy.mock.calls[1][1]?.method).toBe('POST')
  await waitFor(() => expect(screen.queryByRole('button', { name: '标为已读' })).not.toBeInTheDocument())
})

it('marks all as read and reloads the list', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(page([offline], 1))
    .mockResolvedValueOnce(json({ marked: 1 }))
    .mockResolvedValue(page([{ ...offline, read_at: '2026-10-18T09:00:00Z' }], 0))
  renderPage()
  fireEvent.click(await screen.findByRole('button', { name: '全部标为已读' }))
  await waitFor(() => expect(fetchSpy.mock.calls.some(([url, init]) => String(url).endsWith('/v1/admin/inbox/read-all') && init?.method === 'POST')).toBe(true))
  expect(await screen.findByText('已全部标为已读')).toBeInTheDocument()
})

it('links an aggregated edge alert to the schedule page and ignores foreign links', async () => {
  const alert = { id: '33333333-3333-4333-8333-333333333333', event_type: 'aggregated_edge.schedule.alert',
    params: { site_domain: 'shop.example.com', line: '境外', alert_text: '当前供给故障且源站异常', origin: '异常',
      link: '/node/aggregated-edge/schedule?site=44444444-4444-4444-8444-444444444444' },
    created_at: '2026-10-20T08:00:00Z', read_at: null }
  const foreign = { ...alert, id: '55555555-5555-4555-8555-555555555555', params: { ...alert.params, link: '//evil.example' } }
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(page([alert, foreign], 2))
  renderPage()
  expect((await screen.findAllByText('聚合边缘：站点 shop.example.com 线路 境外：当前供给故障且源站异常（源站：异常）'))).toHaveLength(2)
  const links = screen.getAllByRole('link', { name: '去处理' })
  expect(links).toHaveLength(1)
  expect(links[0]).toHaveAttribute('href', '/node/aggregated-edge/schedule?site=44444444-4444-4444-8444-444444444444')
})

it('renders a node security event (kernel ban) from its public values', async () => {
  const event = { id: '66666666-6666-4666-8666-666666666666', event_type: 'node.security.event',
    params: { node_name: 'edge-1', node_ip: '203.0.113.5', event_kind: '新建连接速率超限内核封禁', client_ip: '198.51.100.7',
      count: '1', duration_seconds: '600', occurred_at: '2026-10-20T09:10:00Z' },
    created_at: '2026-10-20T09:10:01Z', read_at: null }
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(page([event], 1))
  renderPage()
  expect(await screen.findByText('节点 edge-1（203.0.113.5）新建连接速率超限内核封禁：客户端 198.51.100.7，1 次，封禁 600 秒')).toBeInTheDocument()
  expect(screen.queryByRole('link', { name: '去处理' })).toBeNull()
})

it('renders a WAF automatic ban from its public values', async () => {
  const event = { id: '88888888-8888-4888-8888-888888888888', event_type: 'node.security.waf_ban',
    params: { site_domain: 'shop.example.com', client_ip: '198.51.100.30', duration_seconds: '600', occurred_at: '2026-10-22T09:10:00Z' },
    created_at: '2026-10-22T09:10:01Z', read_at: null }
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(page([event], 1))
  renderPage()
  expect(await screen.findByText('网站 shop.example.com 的 WAF 自动封禁了客户端 198.51.100.30，封禁 600 秒')).toBeInTheDocument()
  expect(screen.queryByText(/系统事件/)).toBeNull()
})

it('renders the XDP filter fallback and reattach node security events', async () => {
  const base = { event_type: 'node.security.event', created_at: '2026-10-20T09:10:01Z', read_at: null }
  const fallback = { ...base, id: '77777777-7777-4777-8777-777777777777',
    params: { node_name: 'edge-1', node_ip: '203.0.113.5', event_kind: 'XDP 过滤器回落到 nftables', xdp_event: 'fallback',
      xdp_reason: 'verify_failed', xdp_reason_text: '运行中校验失败', occurred_at: '2026-10-20T09:10:00Z' } }
  const reattached = { ...base, id: '88888888-8888-4888-8888-888888888888',
    params: { ...fallback.params, event_kind: 'XDP 过滤器已重新挂载', xdp_event: 'reattached', xdp_reason: 'generic', xdp_reason_text: '通用模式' } }
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(page([fallback, reattached], 2))
  renderPage()
  expect(await screen.findByText('节点 edge-1（203.0.113.5）XDP 过滤器回落到 nftables：运行中校验失败；已撤销 XDP 能力，内核规则由 nftables 继续执行')).toBeInTheDocument()
  expect(screen.getByText('节点 edge-1（203.0.113.5）XDP 过滤器已重新挂载（通用模式），XDP 能力已恢复')).toBeInTheDocument()
})

it('renders node market notices (ML-10) from their public values', async () => {
  const reached = { id: '77777777-7777-4777-8777-777777777777', event_type: 'market.limit.reached',
    params: { offer: '华东 BGP', subscription: 's1', metric: 'qps', observed: '1000', cap: '1000', action: 'pause' },
    created_at: '2026-10-21T09:00:00Z', read_at: null }
  const allOver = { id: '88888888-8888-4888-8888-888888888888', event_type: 'market.supply.all_overloaded',
    params: { pool: 'pa', threshold: '80/70' }, created_at: '2026-10-21T09:01:00Z', read_at: null }
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(page([reached, allOver], 2))
  renderPage()
  expect(await screen.findByText('节点市场：供给 华东 BGP 的 qps 已到上限 1000，处置 pause')).toBeInTheDocument()
  expect(screen.getByText('节点市场：节点池 pa 全部节点过载（门槛 80/70），相关供给暂无解析')).toBeInTheDocument()
})

it('renders the later node market notices from their public values instead of the fallback', async () => {
  const low = { id: '99999999-9999-4999-8999-000000000001', event_type: 'market.commission.low',
    params: { currency: 'CNY', observed: '150', cap: '200' }, created_at: '2026-10-21T09:00:00Z', read_at: null }
  const outage = { id: '99999999-9999-4999-8999-000000000002', event_type: 'market.supply.outage',
    params: { offer: '华东 BGP', subscription: 's1' }, created_at: '2026-10-21T09:01:00Z', read_at: null }
  const defaulted = { id: '99999999-9999-4999-8999-000000000003', event_type: 'market.seller.default_compensated',
    params: { peer: '卖方甲', currency: 'CNY', observed: '500', cap: '800' }, created_at: '2026-10-21T09:02:00Z', read_at: null }
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(page([low, outage, defaulted], 3))
  renderPage()
  expect(await screen.findByText('节点市场：CNY 抽成预付余额 150 低于预警线 200（最小货币单位）')).toBeInTheDocument()
  expect(screen.getByText('节点市场：供给 华东 BGP（订阅 s1）无在线可用节点，离线期间不计费')).toBeInTheDocument()
  expect(screen.getByText('节点市场：供货方 卖方甲 失联，已用其保证金赔付你 500 CNY（最小货币单位），原有余额 800')).toBeInTheDocument()
})

it('renders a refused direct top-up report from its public values', async () => {
  const rejected = { id: '99999999-9999-4999-8999-000000000010', event_type: 'payment.market_topup.rejected',
    params: { topup: 't-1', reason_code: 'amount_mismatch' }, created_at: '2026-10-21T09:00:00Z', read_at: null }
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(page([rejected], 1))
  renderPage()
  expect(await screen.findByText('节点市场直结充值单 t-1 已到账，但市场拒收了到账报告（amount_mismatch），订阅方余额未增加，请在收款通道核对')).toBeInTheDocument()
})
