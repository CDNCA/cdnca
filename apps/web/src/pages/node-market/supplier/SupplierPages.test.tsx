import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../../auth/session'
import i18n from '../../../i18n'
import { authResponse, principal } from '../../../test/fixtures'
import { renderWithProviders } from '../../../test/render'
import NodeMarketPage from '../NodeMarketPage'
import { commissionDaysLeft, remaining } from './model'
import { SupplyStateTag } from './shared'

// ADR 0012 ML-28: supplier and subscriber pages. Response shapes follow the
// market APIs (ML-16/17/19/23/27/31).

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const seller = principal({ scope_kind: 'platform', tenant_id: null, roles: [], permissions: ['marketplace.browse', 'marketplace.sell', 'marketplace.purchase'] })
const offerID = '11111111-1111-4111-8111-111111111111'
const subID = '77777777-7777-4777-8777-777777777777'
const upstreamOffer = '99999999-9999-4999-8999-999999999999'
const myOffer = { id: offerID, seller_id: 's', name: 'HK BGP', description: '', billing_model: 'daily_bundle', status: 'listed', revision: 3,
  pricing: { currency: 'CNY', daily_minor: 100, min_days: 1, max_days: 30 }, allocation: {}, compliance: { require_icp: false },
  resale_allowed: true, site_auto_pause: false }
const direct = { relation: 'direct', subscription_id: subID, offer_id: offerID, status: 'active', paid_through: '2026-11-01T00:00:00Z',
  buyer_id: '22222222-2222-4222-8222-222222222222', buyer_name: 'Alice', supply_state: 'serving', domains: ['a.example'], pools: ['pa'],
  traffic: { last_24h_bytes: 1024, month_bytes: 2048 }, holds: [], note: '' }
const downstream = { relation: 'downstream', subscription_id: subID, offer_id: offerID, status: 'active', paid_through: '2026-11-01T00:00:00Z',
  downstream_ref: 'd-0123456789abcdef', via_name: 'Alice', supply_state: 'paused', domains: ['bad.example'], pools: ['pa'],
  traffic: { last_24h_bytes: 0, month_bytes: 0 },
  holds: [{ reason: 'operator', metric: null, action: 'pause', observed: 0, cap: 0, since: '2026-10-21T00:00:00Z', leaf_member_id: null,
    node_pool_ref: 'pa', resume_condition: 'platform_review' }], note: 'watch' }
const hold = { subscription_id: subID, leaf_member_id: 'l', node_pool_ref: 'pa', reason: 'limit', metric: 'qps', action: 'pause', observed: 9,
  cap: 5, since: '2026-10-21T00:00:00Z', resume_condition: 'limit_below_80pct_two_buckets', relation: 'downstream', downstream_ref: 'd-0123456789abcdef' }
const pause = { id: '44444444-4444-4444-8444-444444444444', root_subscription: subID, leaf_member_id: 'l', node_pool_ref: 'pa',
  leaf_site_id: '55555555-5555-4555-8555-555555555555', count: 3, after_actions: 3, since: '2026-10-21T01:00:00Z' }
// C16: the terms frozen in the upstream snapshot (market frozen_terms).
const frozen = { name: 'Up', billing_model: 'daily_bundle', allocation: { http_ports: 4, stream_ports: 0, websocket: true, http3: false },
  limits: [{ metric: 'domains', cap: 10, action: 'reject_new' }, { metric: 'monthly_traffic_bytes', cap: 2 * 1024 ** 4, action: 'pause' }],
  tags: { cc_protection: 'basic', ddos_protection_gbps: 20, complaint_resistant: false, tenancy: 'shared', mobile_reachable: true, region_block: false,
    line_class: 'BGP' },
  compliance: { require_icp: true }, prepaid_exhausted_action: 'stop' }
const complaint = { id: '66666666-6666-4666-8666-666666666666', offer_id: offerID, target_ref: 'd-0123456789abcdef', category: 'illegal',
  detail: 'x', evidence: {}, state: 'open', action: null, created_at: '2026-10-21T02:00:00Z', resolved_at: null, released_at: null, revision: 1 }

type Handler = (path: string, init?: RequestInit) => Response | undefined
function market(extra: Handler = () => undefined) {
  return vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path, init) => {
    const custom = extra(path, init)
    if (custom) return custom
    if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: ['market.sell', 'market.resell'], offers_quota: 3 })
    if (path === '/v1/admin/market/offers?mine=1') return json({ items: [myOffer] })
    if (path === '/v1/admin/market/offers') return json({ items: [myOffer, { ...myOffer, id: upstreamOffer, name: 'Up', resale_allowed: false }] })
    if (path.startsWith('/v1/admin/market/seller/subscribers?')) return json({ items: [direct, downstream], next_cursor: null })
    if (path.startsWith('/v1/admin/market/seller/holds')) return json({ items: [hold], next_cursor: null })
    if (path.startsWith('/v1/admin/market/holds')) return json({ items: [{ ...hold, reason: 'operator', action: 'stop', resume_condition: 'platform_review' }], next_cursor: null })
    if (path.startsWith('/v1/admin/market/supply-complaints?')) return json({ items: [complaint], next_cursor: null })
    if (path.startsWith('/v1/admin/market/site-pauses')) return json({ items: [pause] })
    if (path === '/v1/admin/market/supplies') return json({ items: [
      { id: 'a', name: 'Bought ok', market_subscription_id: '88888888-8888-4888-8888-888888888888', target: '', status: 'active', leaves: [] },
      { id: 'b', name: 'Bought locked', market_subscription_id: '12121212-1212-4121-8121-121212121212', target: '', status: 'active', leaves: [] }] })
    // B22: the frozen purchase right is the opposite of what the offers say today
    // (Up now forbids resale but this one was bought allowed; offerID allows but was bought forbidden).
    if (path === '/v1/admin/market/subscriptions/88888888-8888-4888-8888-888888888888') return json({ id: '88888888-8888-4888-8888-888888888888', offer_id: upstreamOffer, status: 'active', resale_allowed: true, frozen_terms: frozen })
    if (path === '/v1/admin/market/subscriptions/12121212-1212-4121-8121-121212121212') return json({ id: '12121212-1212-4121-8121-121212121212', offer_id: offerID, status: 'active', resale_allowed: false, frozen_terms: frozen })
    if (path === '/v1/admin/market/commission/prepaid') return json({ customer_id: 'c', enabled: true, currency: 'CNY', balance_minor: 0,
      threshold_minor: 500, exhausted_since: '2026-10-21T03:00:00Z', due_minor: 120, last_7_days_minor: 700 })
    if (path === '/v1/admin/market/commission/prepaid/deductions?limit=100') return json({ next_cursor: 'd2', items: [{ id: 1, member_id: 'm', currency: 'CNY',
      period_start: '2026-10-01T00:00:00Z', amount_minor: 100, due_minor: 20, idempotency_key: 'k', created_at: '2026-10-21T02:00:00Z' }] })
    if (path === '/v1/admin/market/commission/prepaid/deductions?cursor=d2&limit=100') return json({ next_cursor: null, items: [{ id: 2, member_id: 'm',
      currency: 'CNY', period_start: '2026-10-01T00:00:00Z', amount_minor: 4321, due_minor: 20, idempotency_key: 'k2', created_at: '2026-10-20T02:00:00Z' }] })
    return json({ error: 'not_found' }, 404)
  })
}

const calls = (fetchMock: ReturnType<typeof market>, method: string, path: string) =>
  fetchMock.mock.calls.filter(([p, init]) => p === path && (init?.method ?? 'GET') === method)

async function openSupplier(sub: string) {
  renderWithProviders(<NodeMarketPage />)
  fireEvent.click(await screen.findByRole('tab', { name: '供货管理' }))
  if (sub !== '订阅者') fireEvent.click(await screen.findByRole('tab', { name: sub }))
}

beforeEach(() => useSessionStore.getState().setSession({ ...authResponse(seller), access_token: 'market-token' }, seller))
afterEach(async () => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
  await i18n.changeLanguage('zh-CN')
})

describe('models', () => {
  it('formats the outage countdown and the commission days left', () => {
    expect(remaining(65_000)).toBe('1:05')
    expect(remaining(3_725_000)).toBe('1:02:05')
    expect(remaining(-5)).toBe('0:00')
    expect(commissionDaysLeft(700, 700)).toBe(7)
    expect(commissionDaysLeft(-1, 700)).toBe(0)
    expect(commissionDaysLeft(700, 0)).toBeNull()
  })
})

describe('supplier subscribers (§18.1–18.3)', () => {
  // MC12 E4: seller income sits under the selling section; the buyer's balances page no longer mixes it in.
  it('lists top-ups received under supplier management, not on the buyer balances page', async () => {
    const fetchMock = market((path) => {
      if (path.startsWith('/v1/admin/market/direct-topups?')) return json({ items: [{ id: 't1', buyer_member_id: 'b', seller_member_id: 's',
        peer_display_name: 'Buyer One', amount_minor: 2000, currency: 'CNY', method: 'alipay', state: 'paid', paid_minor: 2000,
        expires_at: '2026-10-22T10:00:00Z', created_at: '2026-10-22T09:30:00Z' }], next_cursor: null })
      if (path === '/v1/admin/market/prepaid?currency=CNY') return json({ currency: 'CNY', balance_minor: 0, sellers: [] })
      if (path === '/v1/admin/market/direct-pay/sellers') return json({ items: [] })
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    const view = renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的供货方余额' }))
    expect(await screen.findByText(/平台预付余额/)).toBeInTheDocument()
    expect(screen.queryByText('收款记录')).not.toBeInTheDocument()
    expect(screen.queryByText('Buyer One')).not.toBeInTheDocument()
    view.unmount()
    await openSupplier('收款记录')
    expect(await screen.findByText('Buyer One')).toBeInTheDocument()
    expect(screen.getByText(/你在其他供货方的余额见/)).toBeInTheDocument()
  })

  it('asks for the ledger parties in words, not raw buyer/seller field names', async () => {
    vi.stubGlobal('fetch', market())
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '收款与余额' }))
    // MC12 E4: member IDs are asked for under advanced reconciliation only.
    fireEvent.click(await screen.findByText('高级对账：按成员 ID 查询任意交易边'))
    const advanced = await screen.findByRole('region', { name: '高级对账' })
    fireEvent.click(within(advanced).getByRole('button', { name: '查询余额' }))
    expect(await screen.findByText('请填写买家成员 ID')).toBeInTheDocument()
    expect(screen.getByText('请填写卖家成员 ID')).toBeInTheDocument()
    expect(screen.queryByText(/buyer|seller/)).not.toBeInTheDocument()
  })

  // MC08: the seller row with no supply left behind it is named, in red, not 正常服务.
  it('names a subscriber row without supply', async () => {
    renderWithProviders(<SupplyStateTag value="no_supply" />)
    const tag = await screen.findByText('暂无可用供给')
    expect(tag.closest('.ant-tag')).toHaveClass('ant-tag-error')
  })

  it('shows identity for direct rows and only the reference for downstream; saves a note', async () => {
    const fetchMock = market((path, init) => path === '/v1/admin/market/seller/subscribers/note' && init?.method === 'PUT' ? json({ status: 'updated' }) : undefined)
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('订阅者')
    const table = (await screen.findByText('Alice', { selector: 'span' })).closest('table')!
    expect(within(table).getByText('d-0123456789abcdef')).toBeInTheDocument()
    expect(within(table).getByText('经由 Alice')).toBeInTheDocument()
    expect(within(table).getByText('平台处置 · 暂停调度')).toBeInTheDocument()
    // C10：订阅状态用中文，不露 active/cancelled 原值。
    expect(within(table).queryByText('active')).toBeNull()
    expect(within(table).getAllByText('正常').length).toBeGreaterThan(0)
    // No pause/stop/tighten buttons for suppliers (U2).
    expect(within(table).queryByRole('button', { name: '暂停调度' })).toBeNull()
    fireEvent.click(within(table).getAllByRole('button', { name: '备注' })[1])
    const dialog = await screen.findByRole('dialog', { name: '订阅者备注' })
    fireEvent.change(within(dialog).getByRole('textbox', { name: '备注' }), { target: { value: ' keep an eye ' } })
    fireEvent.click(within(dialog).getByRole('button', { name: /OK|确\s*定/ }))
    await waitFor(() => expect(calls(fetchMock, 'PUT', '/v1/admin/market/seller/subscribers/note')).toHaveLength(1))
    expect(JSON.parse(String(calls(fetchMock, 'PUT', '/v1/admin/market/seller/subscribers/note')[0][1]?.body))).toEqual(
      { subscription_id: subID, downstream_ref: 'd-0123456789abcdef', note: 'keep an eye' })
    expect(await screen.findByText('已保存')).toBeInTheDocument()
  })

  // 卖方看到自己这跳的停续原因与上游暂停补偿规则（披露）。
  it('shows the renewal stop of a subscriber row and explains the upstream pause rule', async () => {
    const paused = { ...direct, renewal_stop: { code: 10009, reason: 'upstream_paused', initiator: 'seller', since: '2026-10-28T00:00:00Z' },
      compensation_policy: 'upstream-pause/v1' }
    vi.stubGlobal('fetch', market((path) => path.startsWith('/v1/admin/market/seller/subscribers?')
      ? json({ items: [paused, downstream], next_cursor: null }) : undefined))
    await openSupplier('订阅者')
    const table = (await screen.findByText('Alice', { selector: 'span' })).closest('table')!
    const tag = within(table).getByText('上游暂停，停续')
    expect(within(table).getByText('正常续费')).toBeInTheDocument()
    fireEvent.mouseOver(tag)
    expect(await screen.findByText(/按补偿规则 upstream-pause\/v1：暂停期间已付未服务的时长在暂停结束时顺延给订阅方，不退现金/)).toBeInTheDocument()
  })

  // p1-subscribers：订阅者按游标服务端分页，230 条分 3 页，第 101 条之后可见。
  it('pages subscribers on the server with next_cursor beyond the first 100', async () => {
    const rows = Array.from({ length: 230 }, (_, i) => ({ ...downstream, holds: [], downstream_ref: `d-${String(i + 1).padStart(3, '0')}` }))
    const fetchMock = market((path) => {
      if (!path.startsWith('/v1/admin/market/seller/subscribers?')) return undefined
      const q = new URLSearchParams(path.split('?')[1])
      const start = q.get('cursor') ? Number(q.get('cursor')) : 0
      const end = start + Number(q.get('limit'))
      return json({ items: rows.slice(start, end), next_cursor: end < rows.length ? String(end) : null })
    })
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('订阅者')
    expect(await screen.findByText('d-100')).toBeInTheDocument()
    expect(screen.queryByText('d-101')).toBeNull()
    expect(screen.getByText('第 1 页，已加载 100 条')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('d-101')).toBeInTheDocument()
    expect(screen.getByText('d-200')).toBeInTheDocument()
    expect(screen.queryByText('d-001')).toBeNull()
    expect(screen.getByText('第 2 页，已加载 200 条')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('d-230')).toBeInTheDocument()
    expect(screen.getByText('第 3 页，已加载 230 条')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '下一页' })).toBeDisabled()
    const sent = fetchMock.mock.calls.map(([p]) => p).filter((p) => p.startsWith('/v1/admin/market/seller/subscribers?'))
    expect(sent).toEqual(['/v1/admin/market/seller/subscribers?limit=100', '/v1/admin/market/seller/subscribers?cursor=100&limit=100',
      '/v1/admin/market/seller/subscribers?cursor=200&limit=100'])
    fireEvent.click(screen.getByRole('button', { name: '上一页' }))
    expect(await screen.findByText('d-101')).toBeInTheDocument()
  })

  it('files a stop request on a downstream row and reports a duplicate', async () => {
    let first = true
    const fetchMock = market((path, init) => {
      if (path !== '/v1/admin/market/supply-complaints' || init?.method !== 'POST') return undefined
      if (first) { first = false; return json(complaint, 201) }
      return json({ error: 'conflict' }, 409)
    })
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('订阅者')
    await screen.findByText('d-0123456789abcdef')
    fireEvent.click(screen.getAllByRole('button', { name: '停止工单' })[1])
    const dialog = await screen.findByRole('dialog', { name: '提交停止工单' })
    fireEvent.change(within(dialog).getByRole('textbox', { name: '情况说明' }), { target: { value: 'phishing' } })
    fireEvent.change(within(dialog).getByRole('textbox', { name: /涉及域名/ }), { target: { value: 'bad.example, x.example' } })
    fireEvent.change(within(dialog).getByRole('textbox', { name: /证据链接/ }), { target: { value: 'https://evidence.example/1.png' } })
    // 发生时间段改用共享 TimeRangeFilter（可选、默认不填、可清空、不晚于当前）。
    const window = within(dialog).getByRole('group', { name: '发生时间段' })
    expect(within(window).getByRole('textbox', { name: '选择时间范围' })).toHaveValue('')
    const now = Date.now()
    fireEvent.click(within(window).getByText('近7天'))
    fireEvent.click(within(dialog).getByRole('button', { name: '提交' }))
    await waitFor(() => expect(calls(fetchMock, 'POST', '/v1/admin/market/supply-complaints')).toHaveLength(1))
    const body = JSON.parse(String(calls(fetchMock, 'POST', '/v1/admin/market/supply-complaints')[0][1]?.body))
    expect(Date.parse(body.evidence.to) - Date.parse(body.evidence.from)).toBe(7 * 86_400_000)
    expect(Math.abs(Date.parse(body.evidence.to) - now)).toBeLessThanOrEqual(60_000)
    expect(body).toEqual({
      offer_id: offerID, target_ref: 'd-0123456789abcdef', category: 'abuse_complaint', detail: 'phishing',
      evidence: { domains: ['bad.example', 'x.example'], from: body.evidence.from, to: body.evidence.to, attachments: [{ name: 'evidence-1', url: 'https://evidence.example/1.png' }] } })
    expect(await screen.findByText('工单已提交，等待平台审核')).toBeInTheDocument()
    // Second request on the same subscriber: 409.
    fireEvent.click(screen.getAllByRole('button', { name: '停止工单' })[1])
    const again = await screen.findByRole('dialog', { name: '提交停止工单' })
    fireEvent.change(within(again).getByRole('textbox', { name: '情况说明' }), { target: { value: 'again' } })
    fireEvent.click(within(again).getByRole('button', { name: '提交' }))
    expect(await within(again).findByText('这个订阅者已有一张未处理的工单')).toBeInTheDocument()
    // 不选时间段则不带 from/to。
    expect(JSON.parse(String(calls(fetchMock, 'POST', '/v1/admin/market/supply-complaints')[1][1]?.body)).evidence).toEqual({})
  })

  it('rejects non-https evidence links before sending', async () => {
    const fetchMock = market()
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('订阅者')
    await screen.findByText('d-0123456789abcdef')
    fireEvent.click(screen.getAllByRole('button', { name: '停止工单' })[0])
    const dialog = await screen.findByRole('dialog', { name: '提交停止工单' })
    fireEvent.change(within(dialog).getByRole('textbox', { name: '情况说明' }), { target: { value: 'x' } })
    fireEvent.change(within(dialog).getByRole('textbox', { name: /证据链接/ }), { target: { value: 'javascript:alert(1)' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '提交' }))
    expect(await within(dialog).findByText('证据链接必须是 https 地址')).toBeInTheDocument()
    expect(calls(fetchMock, 'POST', '/v1/admin/market/supply-complaints')).toHaveLength(0)
  })
})

describe('supplier holds, complaints, switches, resale, commission', () => {
  it('lists paused slots with the resume condition', async () => {
    vi.stubGlobal('fetch', market())
    await openSupplier('被暂停的订阅')
    expect(await screen.findByText('用量连续两个 5 分钟低于上限 80%')).toBeInTheDocument()
    expect(screen.getByText('到达限额')).toBeInTheDocument()
  })

  it('shows complaint progress and withdraws an open one', async () => {
    const fetchMock = market((path, init) => path === `/v1/admin/market/supply-complaints/${complaint.id}/withdraw` && init?.method === 'POST'
      ? json({ ...complaint, state: 'withdrawn' }) : undefined)
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('停止工单')
    expect(await screen.findByText('待审核')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '撤回' }))
    fireEvent.click(await screen.findByRole('button', { name: /OK|确\s*定/ }))
    await waitFor(() => expect(calls(fetchMock, 'POST', `/v1/admin/market/supply-complaints/${complaint.id}/withdraw`)).toHaveLength(1))
    expect(await screen.findByText('已撤回')).toBeInTheDocument()
  })

  it('opens a stop request detail through GET supply-complaints/{id}', async () => {
    const fetchMock = market((path, init) => path === `/v1/admin/market/supply-complaints/${complaint.id}` && !init?.method
      ? json({ ...complaint, state: 'actioned', action: 'pause', evidence: { domains: ['bad.example'], attachments: [{ name: 'shot', url: 'https://e.example/1' }] },
        resolved_at: '2026-10-21T03:00:00Z' }) : undefined)
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('停止工单')
    fireEvent.click(await screen.findByRole('button', { name: '详情' }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText('bad.example')).toBeInTheDocument()
    expect(within(dialog).getByText('暂停调度')).toBeInTheDocument()
    expect(within(dialog).getByText('shot')).toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([path, init]) => path === `/v1/admin/market/supply-complaints/${complaint.id}` && !init?.method)).toBe(true)
  })

  it('switches resale off and same-site pause on through PUT terms, and resumes a paused site', async () => {
    const fetchMock = market((path, init) => {
      if (path === `/v1/admin/market/offers/${offerID}/terms` && init?.method === 'PUT') return json(myOffer)
      if (path === `/v1/admin/market/site-pauses/${pause.id}/resume` && init?.method === 'POST') return json({ ...pause, released_at: '2026-10-21T04:00:00Z' })
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('供货开关')
    fireEvent.click(await screen.findByRole('switch', { name: '允许二次分销 HK BGP' }))
    await waitFor(() => expect(calls(fetchMock, 'PUT', `/v1/admin/market/offers/${offerID}/terms`)).toHaveLength(1))
    const first = calls(fetchMock, 'PUT', `/v1/admin/market/offers/${offerID}/terms`)[0][1]!
    expect(JSON.parse(String(first.body))).toEqual({ pricing: myOffer.pricing, expected_revision: 3, resale_allowed: false })
    expect((first.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^offer-switches-/)
    fireEvent.click(screen.getByRole('switch', { name: '同站自动暂停 HK BGP' }))
    await waitFor(() => expect(calls(fetchMock, 'PUT', `/v1/admin/market/offers/${offerID}/terms`)).toHaveLength(2))
    expect(JSON.parse(String(calls(fetchMock, 'PUT', `/v1/admin/market/offers/${offerID}/terms`)[1][1]?.body))).toEqual(
      { pricing: myOffer.pricing, expected_revision: 3, site_auto_pause: true })
    fireEvent.click(await screen.findByRole('button', { name: '恢复' }))
    fireEvent.click(await screen.findByRole('button', { name: /OK|确\s*定/ }))
    await waitFor(() => expect(calls(fetchMock, 'POST', `/v1/admin/market/site-pauses/${pause.id}/resume`)).toHaveLength(1))
    expect(await screen.findByText('已恢复调度')).toBeInTheDocument()
  })

  // MC10 (B22): the market's answer for today wins over the purchase snapshot.
  it('greys out a subscription the market says cannot be resold today even though it was bought with the right', async () => {
    const okID = '88888888-8888-4888-8888-888888888888'
    vi.stubGlobal('fetch', market((path) => path === `/v1/admin/market/subscriptions/${okID}`
      ? json({ id: okID, offer_id: upstreamOffer, status: 'active', resale_allowed: true,
        resale_now: { allowed: false, reason: 'resale_forbidden', ref: 'r-aabbccddeeff0011' }, frozen_terms: frozen }) : undefined))
    await openSupplier('转售上架')
    const picker = await screen.findByRole('combobox', { name: '我的订阅' })
    await waitFor(() => expect(picker).not.toBeDisabled())
    fireEvent.mouseDown(picker)
    const closed = await screen.findByText('Bought ok（上游禁止二次分销（编号 r-aabbccddeeff0011））')
    expect(closed.closest('.ant-select-item')).toHaveClass('ant-select-item-option-disabled')
  })

  it('greys out a subscription bought without the resale right (frozen, not the offer today) and creates a resale draft from another', async () => {
    const fetchMock = market((path, init) => path === '/v1/admin/market/offers' && init?.method === 'POST' ? json({ id: 'new' }, 201) : undefined)
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('转售上架')
    const picker = await screen.findByRole('combobox', { name: '我的订阅' })
    await waitFor(() => expect(picker).not.toBeDisabled())
    fireEvent.mouseDown(picker)
    const locked = await screen.findByText('Bought locked（上游禁止二次分销）')
    expect(locked.closest('.ant-select-item')).toHaveClass('ant-select-item-option-disabled')
    fireEvent.click(screen.getByText('Bought ok'))
    fireEvent.change(screen.getByRole('textbox', { name: '名称' }), { target: { value: 'HK resale' } })
    fireEvent.change(screen.getByRole('spinbutton', { name: '日价（元 / 天）' }), { target: { value: '1.5' } })
    fireEvent.change(screen.getByRole('spinbutton', { name: '免费试用天数' }), { target: { value: '3' } })
    fireEvent.click(screen.getByRole('checkbox', { name: '创建后直接上架' }))
    fireEvent.click(screen.getByRole('button', { name: '创建转售报价（草稿）' }))
    await waitFor(() => expect(calls(fetchMock, 'POST', '/v1/admin/market/offers')).toHaveLength(1))
    const body = JSON.parse(String(calls(fetchMock, 'POST', '/v1/admin/market/offers')[0][1]?.body))
    expect(body.components).toEqual([{ kind: 'upstream', subscription_id: '88888888-8888-4888-8888-888888888888' }])
    expect(body.pricing).toEqual({ currency: 'CNY', daily_minor: 150, min_days: 1, max_days: 365 })
    expect(body.trial_days).toBe(3)
    // C16: no more hard-coded 2 ports / unlimited / default tags: the upstream's frozen terms.
    expect(body.allocation).toEqual({ http_ports: 4, stream_ports: 0, websocket: true, http3: false })
    expect(body.limits).toEqual([{ metric: 'domains', cap: 10, action: 'reject_new' }, { metric: 'monthly_traffic_bytes', cap: 2 * 1024 ** 4, action: 'pause' }])
    expect(body.tags).toEqual({ cc_protection: 'basic', ddos_protection_gbps: 20, complaint_resistant: false, tenancy: 'shared',
      mobile_reachable: true, region_block: false, line_class: 'BGP' })
    expect(body.compliance).toEqual({ require_icp: true })
    expect(body.prepaid_exhausted_action).toBe('stop')
    expect(await screen.findByText(/转售报价已创建为草稿/)).toBeInTheDocument()
    expect(fetchMock.mock.calls.filter(([p]) => p.endsWith('/publish'))).toHaveLength(0)
  })

  it('shows the inherited upstream terms read only and lets the reseller tighten, not loosen, them', async () => {
    const fetchMock = market((path, init) => {
      if (path === '/v1/admin/market/offers' && init?.method === 'POST') return json({ id: 'new' }, 201)
      if (path === '/v1/admin/market/offers/new/publish' && init?.method === 'POST') return json({ status: 'listed' })
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('转售上架')
    const picker = await screen.findByRole('combobox', { name: '我的订阅' })
    await waitFor(() => expect(picker).not.toBeDisabled())
    fireEvent.mouseDown(picker)
    fireEvent.click(await screen.findByText('Bought ok'))
    const inherited = await screen.findByTestId('inherited-terms')
    expect(within(inherited).getByText('继承自上游，不可放宽')).toBeInTheDocument()
    expect(within(inherited).getByText('域名数 ≤ 10 个 · 拒绝新增')).toBeInTheDocument()
    expect(within(inherited).getByText('HTTP 4 个 · 四层 0 个')).toBeInTheDocument()
    expect(screen.getByTestId('upstream-domains')).toHaveTextContent('上游 ≤ 10 个（拒绝新增），只能调低')
    expect(screen.getByTestId('upstream-qps')).toHaveTextContent('上游不限，可自设')
    // Inherited caps stay on; the cap field is bounded by the upstream; tags the upstream lacks are off.
    const table = screen.getByRole('table', { name: '限额' })
    expect(within(table).getByRole('checkbox', { name: '域名数' })).toBeDisabled()
    expect(within(table).getByRole('spinbutton', { name: '上限 域名数' })).toHaveAttribute('aria-valuemax', '10')
    expect(screen.getByRole('spinbutton', { name: 'HTTP 端口数' })).toHaveAttribute('aria-valuemax', '4')
    expect(screen.getByRole('switch', { name: '抗投诉' })).toBeDisabled()
    expect(screen.getByRole('switch', { name: '要求订阅方域名已备案' })).toBeDisabled()
    // Tightened: fewer ports and domains.
    fireEvent.change(screen.getByRole('textbox', { name: '名称' }), { target: { value: 'tight' } })
    fireEvent.change(screen.getByRole('spinbutton', { name: '日价（元 / 天）' }), { target: { value: '0.09' } })
    fireEvent.change(within(table).getByRole('spinbutton', { name: '上限 域名数' }), { target: { value: '3' } })
    fireEvent.change(screen.getByRole('spinbutton', { name: 'HTTP 端口数' }), { target: { value: '1' } })
    fireEvent.click(screen.getByRole('button', { name: '创建并上架转售报价' }))
    expect(await screen.findByText('转售报价已上架')).toBeInTheDocument()
    const body = JSON.parse(String(calls(fetchMock, 'POST', '/v1/admin/market/offers')[0][1]?.body))
    expect(body.allocation.http_ports).toBe(1)
    expect(body.limits[0]).toEqual({ metric: 'domains', cap: 3, action: 'reject_new' })
  })

  // u4g: upstream snapshots keep plugin codes; the form names them from the local catalogue, unknown ones stay as codes.
  it('names the upstream plugins of a resale from the local catalogue, falling back to the code', async () => {
    const withPlugins = { ...frozen, tags: { ...frozen.tags, plugins: ['ja4', 'rule_pack:system/unknown'] } }
    const fetchMock = market((path) => {
      if (path === '/v1/admin/market/subscriptions/88888888-8888-4888-8888-888888888888') return json({ id: '88888888-8888-4888-8888-888888888888',
        offer_id: upstreamOffer, status: 'active', resale_allowed: true, frozen_terms: withPlugins })
      if (path === '/v1/admin/market/plugin-names') return json({ items: [{ code: 'ja4', name_zh: 'JA4 指纹', name_en: 'JA4 fingerprints' }] })
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('转售上架')
    const picker = await screen.findByRole('combobox', { name: '我的订阅' })
    await waitFor(() => expect(picker).not.toBeDisabled())
    fireEvent.mouseDown(picker)
    fireEvent.click(await screen.findByText('Bought ok'))
    expect(await screen.findByRole('checkbox', { name: 'JA4 指纹' })).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: 'rule_pack:system/unknown' })).toBeInTheDocument()
    expect(within(screen.getByTestId('inherited-terms')).getByText(/JA4 指纹 · rule_pack:system\/unknown/)).toBeInTheDocument()
    const [, init] = calls(fetchMock, 'POST', '/v1/admin/market/plugin-names')[0]
    expect(JSON.parse(String(init?.body))).toEqual({ codes: ['ja4', 'rule_pack:system/unknown'] })
  })

  // u4g: the combined source — several subscriptions (or with my nodes) in one createOffer; limits shown as the sum.
  it('combines two bought subscriptions into one offer and shows the summed limits', async () => {
    const second = { ...frozen, name: 'Up2', allocation: { http_ports: 2, stream_ports: 1, websocket: false, http3: false },
      limits: [{ metric: 'domains', cap: 5, action: 'reject_new' }], tags: { ...frozen.tags, plugins: ['ja4'] } }
    const fetchMock = market((path, init) => {
      if (path === '/v1/admin/market/subscriptions/12121212-1212-4121-8121-121212121212') return json({ id: '12121212-1212-4121-8121-121212121212',
        offer_id: offerID, status: 'active', resale_allowed: true, frozen_terms: second })
      if (path === '/v1/admin/market/plugin-names') return json({ items: [{ code: 'ja4', name_zh: 'JA4 指纹', name_en: 'JA4 fingerprints' }] })
      if (path === '/v1/admin/market/offers' && init?.method === 'POST') return json({ id: 'new' }, 201)
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('转售上架')
    fireEvent.click(await screen.findByRole('radio', { name: '组合' }))
    const picker = await screen.findByRole('combobox', { name: '已购订阅（可多选）' })
    fireEvent.mouseDown(picker)
    fireEvent.click(await screen.findByText('Bought ok'))
    fireEvent.change(screen.getByRole('textbox', { name: '名称' }), { target: { value: 'combo' } })
    fireEvent.change(screen.getByRole('spinbutton', { name: '日价（元 / 天）' }), { target: { value: '0.2' } })
    fireEvent.click(screen.getByRole('checkbox', { name: '创建后直接上架' }))
    // One subscription and no nodes is not a combination.
    fireEvent.click(screen.getByRole('button', { name: '创建组合报价（草稿）' }))
    expect(await screen.findByText('组合至少要两个成分：选两个以上订阅，或订阅加自有节点')).toBeInTheDocument()
    fireEvent.mouseDown(picker)
    fireEvent.click(await screen.findByText('Bought locked'))
    const totals = await screen.findByTestId('combo-totals')
    expect(within(totals).getByText('各上游叶子按路径取最小值：每个上游仍受它自己的冻结条款约束，合计只作参考。')).toBeInTheDocument()
    expect(within(totals).getByText('HTTP 6 个 · 四层 1 个')).toBeInTheDocument()
    expect(within(totals).getByText('≤ 15 个')).toBeInTheDocument()
    // Traffic is capped on one component only: no total.
    expect(within(totals).queryByText(/月流量/)).not.toBeInTheDocument()
    // Plugins: only those every component has (the first has none).
    expect(screen.queryByRole('checkbox', { name: 'JA4 指纹' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '创建组合报价（草稿）' }))
    await waitFor(() => expect(calls(fetchMock, 'POST', '/v1/admin/market/offers')).toHaveLength(1))
    const body = JSON.parse(String(calls(fetchMock, 'POST', '/v1/admin/market/offers')[0][1]?.body))
    expect(body.components).toEqual([{ kind: 'upstream', subscription_id: '12121212-1212-4121-8121-121212121212' },
      { kind: 'upstream', subscription_id: '88888888-8888-4888-8888-888888888888' }])
    expect(body.allocation).toEqual({ http_ports: 6, stream_ports: 1, websocket: false, http3: false })
    expect(calls(fetchMock, 'POST', '/v1/admin/market/supply-groups')).toHaveLength(0)
    expect(await screen.findByText(/转售报价已创建为草稿/)).toBeInTheDocument()
  })

  it('explains an upstream_terms_exceeded refusal from the market', async () => {
    const fetchMock = market((path, init) => path === '/v1/admin/market/offers' && init?.method === 'POST'
      ? json({ error: 'upstream_terms_exceeded', field: 'limits.domains', upstream: 10 }, 400) : undefined)
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('转售上架')
    const picker = await screen.findByRole('combobox', { name: '我的订阅' })
    await waitFor(() => expect(picker).not.toBeDisabled())
    fireEvent.mouseDown(picker)
    fireEvent.click(await screen.findByText('Bought ok'))
    await screen.findByTestId('inherited-terms')
    fireEvent.change(screen.getByRole('textbox', { name: '名称' }), { target: { value: 'x' } })
    fireEvent.change(screen.getByRole('spinbutton', { name: '日价（元 / 天）' }), { target: { value: '0.01' } })
    fireEvent.click(screen.getByRole('button', { name: '创建并上架转售报价' }))
    expect(await screen.findByText('条款宽于上游订阅（域名数），继承的条款只能收紧')).toBeInTheDocument()
  })

  // C16: resale goes through the same publish endpoint as own-node listings, may be free like them,
  // and reports the real status instead of "created".
  it.each([
    ['pending_review', '转售报价已提交审核，审核通过后上架'],
    ['listed', '转售报价已上架'],
  ])('publishes a free resale offer and reports %s', async (status, text) => {
    const fetchMock = market((path, init) => {
      if (path === '/v1/admin/market/offers' && init?.method === 'POST') return json({ id: 'new' }, 201)
      if (path === '/v1/admin/market/offers/new/publish' && init?.method === 'POST') return json({ status })
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('转售上架')
    const picker = await screen.findByRole('combobox', { name: '我的订阅' })
    await waitFor(() => expect(picker).not.toBeDisabled())
    fireEvent.mouseDown(picker)
    fireEvent.click(await screen.findByText('Bought ok'))
    fireEvent.change(screen.getByRole('textbox', { name: '名称' }), { target: { value: 'free' } })
    fireEvent.change(screen.getByRole('spinbutton', { name: '日价（元 / 天）' }), { target: { value: '0' } })
    fireEvent.click(screen.getByRole('button', { name: '创建并上架转售报价' }))
    expect(await screen.findByText(text)).toBeInTheDocument()
    expect(JSON.parse(String(calls(fetchMock, 'POST', '/v1/admin/market/offers')[0][1]?.body)).pricing.daily_minor).toBe(0)
    expect(calls(fetchMock, 'POST', '/v1/admin/market/offers/new/publish')).toHaveLength(1)
  })

  it('keeps the draft and explains a failed publish instead of reporting the whole action as failed', async () => {
    const fetchMock = market((path, init) => {
      if (path === '/v1/admin/market/offers' && init?.method === 'POST') return json({ id: 'new' }, 201)
      if (path === '/v1/admin/market/offers/new/publish' && init?.method === 'POST') return json({ error: 'seller_overdue' }, 409)
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('转售上架')
    const picker = await screen.findByRole('combobox', { name: '我的订阅' })
    await waitFor(() => expect(picker).not.toBeDisabled())
    fireEvent.mouseDown(picker)
    fireEvent.click(await screen.findByText('Bought ok'))
    fireEvent.change(screen.getByRole('textbox', { name: '名称' }), { target: { value: 'x' } })
    fireEvent.change(screen.getByRole('spinbutton', { name: '日价（元 / 天）' }), { target: { value: '0.05' } })
    fireEvent.click(screen.getByRole('button', { name: '创建并上架转售报价' }))
    expect(await screen.findByText(/已保存为草稿，但上架未成功/)).toBeInTheDocument()
    expect(screen.getByText(/seller_overdue/)).toBeInTheDocument()
  })

  it('explains a resale_forbidden refusal from the market', async () => {
    const fetchMock = market((path, init) => path === '/v1/admin/market/offers' && init?.method === 'POST'
      ? json({ error: 'resale_forbidden', forbidden_by: 'r-0011223344556677' }, 400) : undefined)
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('转售上架')
    const picker = await screen.findByRole('combobox', { name: '我的订阅' })
    await waitFor(() => expect(picker).not.toBeDisabled())
    fireEvent.mouseDown(picker)
    fireEvent.click(await screen.findByText('Bought ok'))
    fireEvent.change(screen.getByRole('textbox', { name: '名称' }), { target: { value: 'x' } })
    fireEvent.change(screen.getByRole('spinbutton', { name: '日价（元 / 天）' }), { target: { value: '0.01' } })
    fireEvent.click(screen.getByRole('button', { name: '创建并上架转售报价' }))
    expect(await screen.findByText('上游禁止二次分销（编号 r-0011223344556677）')).toBeInTheDocument()
  })

  it('shows the exhausted prepaid balance in red, tops up and saves the alert line', async () => {
    const open = vi.spyOn(window, 'open').mockImplementation(() => null)
    const fetchMock = market((path, init) => {
      if (path === '/v1/admin/market/orders' && init?.method === 'POST') return json({ order: { order_no: 42 }, checkout_url: 'https://portal.example/pay/42' }, 201)
      if (path === '/v1/admin/market/commission/prepaid/alert' && init?.method === 'PUT') return json({ status: 'updated' })
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('平台抽成预付')
    expect(await screen.findByText(/余额已用完/)).toBeInTheDocument()
    expect(screen.getByTestId('commission-balance')).toHaveClass('ant-typography-danger')
    expect(screen.getByText('约可用 0 天', { exact: false })).toBeInTheDocument()
    fireEvent.change(screen.getByRole('spinbutton', { name: '金额（元）' }), { target: { value: '10' } })
    fireEvent.click(screen.getByRole('button', { name: '去付款' }))
    await waitFor(() => expect(calls(fetchMock, 'POST', '/v1/admin/market/orders')).toHaveLength(1))
    const order = calls(fetchMock, 'POST', '/v1/admin/market/orders')[0][1]!
    expect(JSON.parse(String(order.body))).toEqual({ kind: 'commission_topup', amount_minor: 1000, currency: 'CNY' })
    expect((order.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^commission-topup-/)
    expect(open).toHaveBeenCalledWith('https://portal.example/pay/42', '_blank', 'noopener,noreferrer')
    expect(await screen.findByText('已创建充值单 #42')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('spinbutton', { name: '预警线（元）' }), { target: { value: '8' } })
    fireEvent.click(screen.getByRole('button', { name: '保存预警线' }))
    await waitFor(() => expect(calls(fetchMock, 'PUT', '/v1/admin/market/commission/prepaid/alert')).toHaveLength(1))
    expect(JSON.parse(String(calls(fetchMock, 'PUT', '/v1/admin/market/commission/prepaid/alert')[0][1]?.body))).toEqual({ currency: 'CNY', threshold_minor: 800 })
  })

  // Deductions page by next_cursor (the market no longer truncates at 5000).
  it('pages the commission deductions by cursor', async () => {
    const fetchMock = market()
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('平台抽成预付')
    expect(await screen.findByText('1.00')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('43.21')).toBeInTheDocument()
    expect(calls(fetchMock, 'GET', '/v1/admin/market/commission/prepaid/deductions?cursor=d2&limit=100')).toHaveLength(1)
  })

  it('turns prepaid on, and leaving asks first', async () => {
    let enabled = false
    const fetchMock = market((path, init) => {
      if (path !== '/v1/admin/market/commission/prepaid') return undefined
      if (init?.method === 'PUT') enabled = JSON.parse(String(init.body)).enabled
      return json({ customer_id: 'c', enabled, currency: 'CNY', balance_minor: 300, threshold_minor: 0, exhausted_since: null, due_minor: 0, last_7_days_minor: 0 })
    })
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('平台抽成预付')
    fireEvent.click(await screen.findByRole('button', { name: '开启预付' }))
    await waitFor(() => expect(calls(fetchMock, 'PUT', '/v1/admin/market/commission/prepaid')).toHaveLength(1))
    expect(JSON.parse(String(calls(fetchMock, 'PUT', '/v1/admin/market/commission/prepaid')[0][1]?.body))).toEqual({ enabled: true, currency: 'CNY' })
    fireEvent.click(await screen.findByRole('button', { name: '退出预付' }))
    expect((await screen.findAllByText('退出后余额留在平台、不退回，之后按月度账单结算。确认退出？')).length).toBeGreaterThan(0)
    fireEvent.click(screen.getAllByRole('button', { name: /OK|确\s*定/ }).at(-1)!)
    await waitFor(() => expect(calls(fetchMock, 'PUT', '/v1/admin/market/commission/prepaid')).toHaveLength(2))
    expect(JSON.parse(String(calls(fetchMock, 'PUT', '/v1/admin/market/commission/prepaid')[1][1]?.body))).toEqual({ enabled: false, currency: 'CNY' })
  })

  it('hides the supplier tab without marketplace.sell', async () => {
    const buyer = principal({ scope_kind: 'platform', tenant_id: null, roles: [], permissions: ['marketplace.browse', 'marketplace.purchase'] })
    useSessionStore.getState().setSession({ ...authResponse(buyer), access_token: 'market-token' }, buyer)
    vi.stubGlobal('fetch', market())
    renderWithProviders(<NodeMarketPage />)
    expect(await screen.findByRole('tab', { name: '暂停调度' })).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: '供货管理' })).toBeNull()
  })
})

// 授权租约只有 market.participate 时，供货管理不弹“操作失败：forbidden”，页内说明未开通。
describe('supplier without a selling licence', () => {
  const notOpen = /当前授权未开通节点供货/
  const participantOnly = (path: string) => path === '/v1/admin/market/member'
    ? json({ id: 'm', display_name: 'me', status: 'active', features: ['market.participate'], offers_quota: 0 })
    : path.startsWith('/v1/admin/market/seller/') || path.startsWith('/v1/admin/market/supply-complaints') || path.startsWith('/v1/admin/market/node-admissions')
      ? json({ error: 'forbidden' }, 403) : undefined

  it('explains in the page instead of an error dialog', async () => {
    const fetchMock = market(participantOnly)
    vi.stubGlobal('fetch', fetchMock)
    await openSupplier('订阅者')
    expect((await screen.findAllByText(notOpen)).length).toBeGreaterThan(0)
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.queryByText('操作失败：forbidden')).toBeNull()
    expect(fetchMock.mock.calls.some(([p]) => String(p).startsWith('/v1/admin/market/seller/'))).toBe(false)
  })

  it('a 403 from an auto-loaded seller list stays in the page', async () => {
    vi.stubGlobal('fetch', market((path) => path.startsWith('/v1/admin/market/seller/holds') ? json({ error: 'forbidden' }, 403) : undefined))
    await openSupplier('被暂停的订阅')
    expect((await screen.findAllByText(notOpen)).length).toBeGreaterThan(0)
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})

describe('subscriber side', () => {
  it('lists my paused nodes and the same-site pause notice without a resume button', async () => {
    vi.stubGlobal('fetch', market())
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '暂停调度' }))
    expect(await screen.findByText('平台复核后解除')).toBeInTheDocument()
    expect(await screen.findByText(/你有站点被供货方的同站自动暂停停掉了调度/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '恢复' })).toBeNull()
  })

  const outageMarket = (ready: boolean) => {
    const supply = { id: 's1', name: 'HK supply', market_subscription_id: subID, target: 't', status: 'active', leaves: [] }
    return market((path, init) => {
      if (path === '/v1/admin/market/supplies') return json({ items: [supply] })
      if (path === `/v1/admin/market/subscriptions/${subID}`) return json({ id: subID, buyer_id: 'b', seller_id: 's', offer_id: offerID, status: 'active',
        settlement_mode: 'direct', renewal_price_policy: 'always', cancel_at_period_end: false,
        outage: { id: 'o', since: '2026-10-21T09:45:00Z', ...(ready ? { cancel_available_at: '2026-10-21T10:15:00Z' } : {}) } })
      if (path === `/v1/admin/market/subscriptions/${subID}/limits?hours=24`) return json({ subscription_id: subID, offer_id: offerID, status: 'active',
        billing_model: 'daily_bundle', currency: 'CNY', prepaid_exhausted_action: 'pause', limits: [], load_thresholds: { cpu_percent: 70, memory_percent: 70 },
        holds: [], supplies: [], series: [], report_lag_seconds: 0 })
      if (path === '/v1/admin/market/supply-limits-policy') return json({ version: 1, policy: { load_floor: { cpu_percent: 80, memory_percent: 80 }, outage_cancel_after_minutes: 30 } })
      if (path === `/v1/admin/market/subscriptions/${subID}/outage-cancel` && init?.method === 'POST') return json({ status: 'cancelled' })
      return undefined
    })
  }
  async function openSubscription() {
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    fireEvent.click(await screen.findByRole('button', { name: '订阅详情' }))
  }

  it('counts down to T1 with no cancel button yet', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true, now: Date.parse('2026-10-21T10:00:00Z') })
    vi.stubGlobal('fetch', outageMarket(false))
    await openSubscription()
    expect(await screen.findByText('再过 15:00 若仍无在线节点，可无责取消。')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '无责取消' })).toBeNull()
    await act(async () => { await vi.advanceTimersByTimeAsync(2000) })
    expect(screen.getByText(/再过 14:5[78] 若仍无在线节点/)).toBeInTheDocument()
  })

  it('cancels without liability once T1 passed', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true, now: Date.parse('2026-10-21T10:16:00Z') })
    const fetchMock = outageMarket(true)
    vi.stubGlobal('fetch', fetchMock)
    await openSubscription()
    expect(await screen.findByText(/已满足无责取消条件/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '无责取消' }))
    fireEvent.click(await screen.findByRole('button', { name: /OK|确\s*定/ }))
    const path = `/v1/admin/market/subscriptions/${subID}/outage-cancel`
    await waitFor(() => expect(calls(fetchMock, 'POST', path)).toHaveLength(1))
    expect((calls(fetchMock, 'POST', path)[0][1]?.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^outage-cancel-/)
    expect(await screen.findByText('已无责取消')).toBeInTheDocument()
  })

  it('explains outage_not_eligible', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true, now: Date.parse('2026-10-21T10:16:00Z') })
    const base = outageMarket(true)
    vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => path.endsWith('/outage-cancel')
      ? json({ error: 'outage_not_eligible' }, 409) : base(path, init)))
    await openSubscription()
    fireEvent.click(await screen.findByRole('button', { name: '无责取消' }))
    fireEvent.click(await screen.findByRole('button', { name: /OK|确\s*定/ }))
    expect(await screen.findByText('暂不满足无责取消条件（节点已恢复或未到时间）')).toBeInTheDocument()
  })
})
