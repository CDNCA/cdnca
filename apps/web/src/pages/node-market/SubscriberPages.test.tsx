import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../auth/session'
import i18n from '../../i18n'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import NodeMarketPage from './NodeMarketPage'
import { hoursLeft, recoveryKey, seriesOf, usagePercent, usageStatus, worstState } from './subscriberModel'

const chart = vi.hoisted(() => ({ setOption: vi.fn(), resize: vi.fn(), dispose: vi.fn() }))
vi.mock('../../components/echartsRuntime', () => ({ init: vi.fn(() => chart) }))

// ADR 0012 ML-12: subscriber-side supply detail (§9.2) and usage page (§9.3).
// The market endpoints of ML-04 (prepaid/alert) and ML-06 (supply-unscheduled)
// are not merged yet; their shapes here follow the ADR (see ml-12.md).

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['sites.manage'] })
const offer = {
  id: '11111111-1111-4111-8111-111111111111', seller_id: '22222222-2222-4222-8222-222222222222', name: 'HK BGP', description: '',
  billing_model: 'traffic', status: 'listed', settlement_mode: 'escrow',
  quality: { score: 2.4, tier: 'high', regions: ['hk'], carriers: ['cn2'], serving_nodes: 2, unit_price: 30, computed_at: '2026-10-25T08:00:00Z' },
  pricing: { currency: 'CNY', deposit_minor: 1000 }, allocation: { http_ports: 2 }, compliance: { require_icp: false },
  prepaid_exhausted_action: 'stop', plugins_unavailable: ['pack.crs'],
  limits: [
    { metric: 'monthly_traffic_bytes', cap: 10 * 1024 ** 4, action: 'throttle', throttle_bps: 50e6 },
    { metric: 'qps', cap: 5000, action: 'pause', sustain_buckets: 2 },
    { metric: 'node_cpu_percent', cap: 70, action: 'remove_node' },
  ],
  tags: { cc_protection: 'advanced', ddos_protection_gbps: 300, complaint_resistant: true, tenancy: 'dedicated', mobile_reachable: false,
    region_block: true, line_class: 'CN2 GIA', plugins: ['module.autodefense', 'pack.crs'], custom: ['原生 IP', '免备案'] },
}
const nodes = {
  offer_id: offer.id, nodes: 5,
  groups: [{ region: 'HK', carrier: '电信', benchmark_grade: 's', nodes: 3 }, { region: 'HK', carrier: '联通', benchmark_grade: '', nodes: 2 }],
  load_thresholds: { cpu_percent: 70, memory_percent: 70 }, load_floor: { cpu_percent: 80, memory_percent: 70 },
}
const subID = '77777777-7777-4777-8777-777777777777'
const supply = { id: '66666666-6666-4666-8666-666666666666', name: 'HK supply', market_subscription_id: subID, target: 's.market.example',
  status: 'active', leaves: [] }
const terms = { id: subID, buyer_id: 'b', seller_id: offer.seller_id, offer_id: offer.id, status: 'active', settlement_mode: 'escrow',
  renewal_price_policy: 'always', cancel_at_period_end: false }
const leaf = '33333333-3333-4333-8333-333333333333'
const limits = {
  subscription_id: subID, offer_id: offer.id, status: 'active', billing_model: 'traffic', currency: 'CNY', prepaid_exhausted_action: 'stop',
  limits: [
    { metric: 'monthly_traffic_bytes', cap: 10 * 1024 ** 4, action: 'throttle', throttle_bps: 50e6, value: 8.5 * 1024 ** 4, stage: 'warn80',
      evaluated_through: '2026-10-21T08:45:00Z' },
    { metric: 'qps', cap: 5000, action: 'pause', value: 4900, stage: 'reached', evaluated_through: '2026-10-21T08:45:00Z' },
  ],
  load_thresholds: { cpu_percent: 70, memory_percent: 70 },
  holds: [
    { subscription_id: subID, leaf_member_id: null, node_pool_ref: null, reason: 'limit', metric: 'qps', action: 'pause', observed: 4900, cap: 5000,
      since: '2026-10-21T08:30:00Z', upstream: false },
    { subscription_id: '88888888-8888-4888-8888-888888888888', leaf_member_id: null, node_pool_ref: null, reason: 'prepaid', metric: null,
      action: 'stop', observed: 0, cap: 0, since: '2026-10-21T07:00:00Z', upstream: true },
  ],
  supplies: [{ leaf_member_id: leaf, node_pool_ref: 'pa', state: 'paused' }, { leaf_member_id: leaf, node_pool_ref: 'pb', state: 'serving' }],
  series: [
    { bucket_start: '2026-10-21T08:35:00Z', bytes_out: 100, requests: 1, peak_bps: 1, max_concurrent: 1, max_qps: 4800, max_new_cps: 1 },
    { bucket_start: '2026-10-21T08:40:00Z', bytes_out: 200, requests: 1, peak_bps: 1, max_concurrent: 1, max_qps: 4900, max_new_cps: 1 },
  ],
  report_lag_seconds: 900,
}
const prepaid = { currency: 'CNY', balance_minor: 1200, arrears_minor: 0, overdraft_cap_minor: 5000, alert_minor: 2000, spent_24h_minor: 600 }
const credit = { deposit_effective: true, deposit_minor: 5000, required_minor: 4000, sufficient: true, defaults_count: 0, absconded: false, faults_30d: 1 }
const sellerRow = { seller_member_id: offer.seller_id, display_name: 'HK Seller', balance_minor: 800, overdraft_minor: 0, credit_limit_minor: 1000,
  below_alert: true, spent_24h_minor: 100, spent_by_day: [0, 0, 100, 0, 200, 0, 100],
  by_subscription: [{ subscription_id: subID, offer_name: 'HK BGP', spent_7d_minor: 400 }], seller_credit: credit }

type Handler = (path: string, init?: RequestInit) => Response | undefined
function market(extra: Handler = () => undefined) {
  return vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path, init) => {
    const custom = extra(path, init)
    if (custom) return custom
    if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
    if (path === '/v1/admin/market/offers?limit=50') return json({ items: [offer] })
    if (path === `/v1/admin/market/offers/${offer.id}/nodes`) return json(nodes)
    if (path === '/v1/admin/market/supplies') return json({ items: [supply] })
    if (path === `/v1/admin/market/subscriptions/${subID}`) return json(terms)
    if (path === `/v1/admin/market/subscriptions/${subID}/limits?hours=24`) return json(limits)
    if (path === '/v1/admin/market/supply-unscheduled') return json({ items: [] })
    if (path === '/v1/admin/market/prepaid?currency=CNY') return json(prepaid)
    if (path === '/v1/admin/market/prepaid/alert') return json({ status: 'ok' })
    return json({ error: 'not_found' }, 404)
  })
}

async function openUsage() {
  renderWithProviders(<NodeMarketPage />)
  fireEvent.click(await screen.findByRole('tab', { name: i18n.t('nodeMarket:tabs.supplies') }))
  fireEvent.click(await screen.findByRole('button', { name: i18n.t('nodeMarket:subscription.manage') }))
  return screen.findByRole('dialog')
}

beforeEach(() => useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'market-token' }, admin))
afterEach(async () => {
  vi.unstubAllGlobals()
  await i18n.changeLanguage('zh-CN')
})

describe('subscriberModel', () => {
  it('computes usage bars, series, recovery keys, worst state and remaining time', () => {
    expect(usagePercent(4900, 5000)).toBe(98)
    expect(usagePercent(9, 0)).toBe(0)
    expect(usagePercent(7000, 5000)).toBe(100)
    expect([usageStatus(98), usageStatus(85), usageStatus(10)]).toEqual(['exception', 'active', 'normal'])
    expect(seriesOf(limits.series, 'qps')).toEqual([4800, 4900])
    expect(seriesOf(limits.series, 'monthly_traffic_bytes')).toEqual([100, 200])
    expect(seriesOf(limits.series, 'domains')).toEqual([])
    expect(recoveryKey({ reason: 'limit', metric: 'qps' })).toBe('limitRealtime')
    expect(recoveryKey({ reason: 'limit', metric: 'monthly_traffic_bytes' })).toBe('limitMonthly')
    expect(recoveryKey({ reason: 'overdraft_cap', metric: null })).toBe('topUp')
    expect(recoveryKey({ reason: 'operator', metric: null })).toBe('operator')
    expect(worstState(['serving', 'paused', 'overloaded'])).toBe('paused')
    expect(worstState(['serving', 'stopped', 'paused'])).toBe('stopped')
    expect(hoursLeft({ balance_minor: 1200, spent_24h_minor: 600 })).toBe(48)
    expect(hoursLeft({ balance_minor: -5, spent_24h_minor: 600 })).toBe(0)
    expect(hoursLeft({ balance_minor: 1200, spent_24h_minor: 0 })).toBeNull()
  })
})

describe('supply detail (§9.2)', () => {
  it('shows node groups, limits with actions, declared and measured tags apart, and the floor against the seller threshold', async () => {
    const fetchMock = market()
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    fireEvent.click(await screen.findByRole('button', { name: '详情' }))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('在服务节点共 5 个')).toBeInTheDocument()
    const nodeTable = within(drawer).getAllByRole('table')[0]
    expect(within(nodeTable).getByText('S')).toBeInTheDocument()
    expect(within(nodeTable).getByText('未测')).toBeInTheDocument()
    expect(within(nodeTable).getByText('电信')).toBeInTheDocument()
    // Limits: node rows are not listed as subscription limits.
    expect(within(drawer).getByText('10 TB')).toBeInTheDocument()
    expect(within(drawer).getByText('限速到 50 Mbps')).toBeInTheDocument()
    expect(within(drawer).getByText('暂停调度')).toBeInTheDocument()
    expect(within(drawer).getByText(/预付余额用完时：停止服务/)).toBeInTheDocument()
    // Declared vs measured.
    const declared = within(drawer).getByText('卖方自述').closest('.ant-card') as HTMLElement
    const measured = within(drawer).getByText('平台实测').closest('.ant-card') as HTMLElement
    expect(within(declared).getByText('CN2 GIA')).toBeInTheDocument()
    expect(within(declared).getByText('300 Gbps')).toBeInTheDocument()
    expect(within(declared).getByText('高级')).toBeInTheDocument()
    // fix-offerform: custom tags sit with the other self-declared tags, not with what the platform measured.
    expect(within(declared).getByTestId('declared-custom')).toHaveTextContent('原生 IP免备案')
    expect(within(measured).queryByText('原生 IP')).toBeNull()
    expect(within(measured).queryByText('CN2 GIA')).toBeNull()
    expect(within(measured).getByText('S、未测')).toBeInTheDocument()
    expect(within(measured).getByText(/^2\.40（.+评估）$/)).toBeInTheDocument()
    expect(within(measured).getByText('pack.crs')).toHaveStyle({ textDecoration: 'line-through' })
    expect(within(measured).getByText('module.autodefense')).toBeInTheDocument()
    // Floor 80/70, seller CPU 70 → in effect 70/70.
    expect(within(drawer).getByText('CPU 80% · 节点内存 70%')).toBeInTheDocument()
    expect(within(drawer).getByText('CPU 70% · 节点内存 —%')).toBeInTheDocument()
    expect(within(drawer).getByText('CPU 70% · 节点内存 70%')).toBeInTheDocument()
  })

  it('still shows limits and tags when the market does not serve node groups yet', async () => {
    vi.stubGlobal('fetch', market((path) => path.endsWith('/nodes') ? json({ error: 'market_feature_unavailable' }, 501) : undefined))
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    fireEvent.click(await screen.findByRole('button', { name: '详情' }))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText(/市场端还没有开放这个功能/)).toBeInTheDocument()
    expect(within(drawer).getByText('CN2 GIA')).toBeInTheDocument()
  })
})

describe('usage page (§9.3)', () => {
  it('shows the service state, usage bars with the lag, holds with recovery conditions and the prepaid balance', async () => {
    const fetchMock = market()
    vi.stubGlobal('fetch', fetchMock)
    const drawer = await openUsage()
    expect(await within(drawer).findByText('数据延迟约 10–15 分钟')).toBeInTheDocument()
    // Availability in the card header (one slot paused, one serving: partly available); each slot listed.
    expect(await within(drawer).findByText('部分可用')).toBeInTheDocument()
    expect(within(drawer).getByText(/部分供给不可用，剩余供给仍在服务/)).toBeInTheDocument()
    expect(within(drawer).getByText('已暂停')).toBeInTheDocument()
    expect(within(drawer).getByText('服务中')).toBeInTheDocument()
    // Usage bars.
    expect(within(drawer).getByLabelText('月流量 85%')).toBeInTheDocument()
    expect(within(drawer).getByLabelText('QPS 98%')).toBeInTheDocument()
    expect(within(drawer).getByText('8.5 TB / 10 TB')).toBeInTheDocument()
    expect(within(drawer).getByText('到限：暂停调度')).toBeInTheDocument()
    // Holds: own limit hold and an upstream prepaid hold.
    const holds = within(drawer).getByText('处置中').closest('.ant-card') as HTMLElement
    expect(within(holds).getByText('到达限额 · QPS')).toBeInTheDocument()
    expect(within(holds).getByText('回落到上限 80% 以下连续 2 个 5 分钟桶')).toBeInTheDocument()
    expect(within(holds).getByText('上游供给')).toBeInTheDocument()
    expect(within(holds).getByText('充值到余额不小于 0')).toBeInTheDocument()
    expect(within(holds).getByText('停止服务')).toBeInTheDocument()
    // Prepaid: escrow balance, overdraft cap, remaining time, alert line.
    const pre = within(drawer).getByText('预付与透支').closest('.ant-card') as HTMLElement
    expect(await within(pre).findByText('12.00 CNY')).toBeInTheDocument()
    expect(within(pre).getByText('0.00 CNY / 封顶 50.00 CNY')).toBeInTheDocument()
    expect(within(pre).getByText('约 2 天')).toBeInTheDocument()
    expect(within(pre).getByDisplayValue('20')).toBeInTheDocument()
    expect(fetchMock.mock.calls.map(([p]) => p)).toContain(`/v1/admin/market/subscriptions/${subID}/limits?hours=24`)
    // 5-minute curve of the first limit (monthly traffic: bytes per bucket), then QPS peaks.
    await waitFor(() => expect(chart.setOption).toHaveBeenCalled())
    expect(chart.setOption.mock.lastCall![0].series[0].data).toEqual([100, 200])
    fireEvent.click(within(drawer).getByText('QPS', { selector: '.ant-segmented-item-label' }))
    await waitFor(() => expect(chart.setOption.mock.lastCall![0].series[0].data).toEqual([4800, 4900]))
  })

  // A12 / MSTATE-01: no supply is never shown as serving.
  it('shows no supply, not serving, when the subscription has no active grant', async () => {
    vi.stubGlobal('fetch', market((path) => path === `/v1/admin/market/subscriptions/${subID}/limits?hours=24`
      ? json({ ...limits, holds: [], supplies: [], availability: 'no_supply' }) : undefined))
    const drawer = await openUsage()
    expect(await within(drawer).findByText('无可用供给')).toBeInTheDocument()
    expect(within(drawer).getByText(/当前没有任何有效供给/)).toBeInTheDocument()
    expect(within(drawer).queryByText('服务中')).not.toBeInTheDocument()
  })

  it('derives no supply from an empty list when an older market sends no availability', async () => {
    vi.stubGlobal('fetch', market((path) => path === `/v1/admin/market/subscriptions/${subID}/limits?hours=24`
      ? json({ ...limits, holds: [], supplies: [] }) : undefined))
    const drawer = await openUsage()
    expect(await within(drawer).findByText('无可用供给')).toBeInTheDocument()
    expect(within(drawer).queryByText('服务中')).not.toBeInTheDocument()
  })

  it('saves the alert line in minor units', async () => {
    const fetchMock = market()
    vi.stubGlobal('fetch', fetchMock)
    const drawer = await openUsage()
    const pre = (await within(drawer).findByText('预付与透支')).closest('.ant-card') as HTMLElement
    const input = await within(pre).findByLabelText('余额预警线')
    fireEvent.change(input, { target: { value: '35.5' } })
    fireEvent.click(within(pre).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/prepaid/alert', expect.objectContaining({ method: 'PUT' })))
    const [, init] = fetchMock.mock.calls.find(([p]) => p === '/v1/admin/market/prepaid/alert')!
    expect(JSON.parse(init!.body as string)).toEqual({ currency: 'CNY', threshold_minor: 3550 })
  })

  it('lists unscheduled nodes of this subscription and says when ML-04/ML-06 are not on the market yet', async () => {
    vi.stubGlobal('fetch', market((path) => {
      if (path === '/v1/admin/market/supply-unscheduled') return json({ items: [
        { subscription_id: subID, leaf_member_id: leaf, node_pool_ref: 'pa', label: 'l', node_id: 'n1n1n1n1-0000', ip: '192.0.2.1', region: 'HK',
          carrier: '电信', state: 'overloaded', overloaded_since: '2026-10-21T08:00:00Z', holds: [] },
        { subscription_id: 'other', leaf_member_id: leaf, node_pool_ref: 'pa', label: 'l', node_id: 'n2n2n2n2-0000', ip: '192.0.2.2', region: 'JP',
          carrier: 'IIJ', state: 'paused', holds: [] },
      ] })
      if (path.startsWith('/v1/admin/market/prepaid')) return json({ error: 'market_feature_unavailable' }, 501)
      return undefined
    }))
    const drawer = await openUsage()
    const card = (await within(drawer).findByText('未参与调度的节点')).closest('.ant-card') as HTMLElement
    expect(within(card).getByText('n1n1n1n1')).toBeInTheDocument()
    expect(within(card).queryByText('n2n2n2n2')).toBeNull()
    expect(within(card).getByText('节点全部过载')).toBeInTheDocument()
    const pre = within(drawer).getByText('预付与透支').closest('.ant-card') as HTMLElement
    expect(await within(pre).findByText(/市场端还没有开放这个功能/)).toBeInTheDocument()
  })

  // ADR 0015 §12: the direct card reads the seller's row of the prepaid summary.
  it('reads a direct subscription balance from the prepaid summary row of its seller', async () => {
    const fetchMock = market((path) => {
      if (path === `/v1/admin/market/subscriptions/${subID}`) return json({ ...terms, settlement_mode: 'direct' })
      if (path === '/v1/admin/market/prepaid?currency=CNY') return json({ ...prepaid, sellers: [{ ...sellerRow, balance_minor: -300 }] })
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    const drawer = await openUsage()
    const pre = (await within(drawer).findByText('预付与透支')).closest('.ant-card') as HTMLElement
    expect(await within(pre).findByText('-3.00 CNY')).toBeInTheDocument()
    expect(within(pre).getByText('10.00 CNY')).toBeInTheDocument()
    expect(within(pre).getByText('保证金 50.00 CNY')).toBeInTheDocument()
    expect(within(pre).queryByLabelText('余额预警线')).toBeNull()
    expect(fetchMock.mock.calls.map(([p]) => p).some((p) => p.startsWith('/v1/admin/market/ledger/balance'))).toBe(false)
  })

  it('renders in English', async () => {
    await i18n.changeLanguage('en-US')
    vi.stubGlobal('fetch', market())
    const drawer = await openUsage()
    expect(await within(drawer).findByText('Data lags about 10–15 minutes')).toBeInTheDocument()
    expect(await within(drawer).findByText('Below 80% of the cap for two 5-minute buckets')).toBeInTheDocument()
    expect(within(drawer).getByText('Upstream supply')).toBeInTheDocument()
    expect(await within(drawer).findByText('2 days')).toBeInTheDocument()
  })
})

// ADR 0015 §3.4 / §11.4 / §12: the supplier balances tab and the direct top-up.
// antd test modals all carry a test-id aria-labelledby: find a dialog by its title text.
async function dialogTitled(title: string): Promise<HTMLElement> {
  const titles = await screen.findAllByText(title, { selector: '.ant-modal-title' })
  return titles.at(-1)!.closest('[role="dialog"]') as HTMLElement
}

describe('supplier balances and direct top-up', () => {
  it('lists balances with deposit and record, highlights the alert line, and tops up through the seller checkout', async () => {
    let polled = 0
    const topup = { id: '99999999-9999-4999-8999-999999999999', buyer_member_id: 'b', seller_member_id: offer.seller_id,
      peer_display_name: 'HK Seller', amount_minor: 2000, currency: 'CNY', method: 'alipay', state: 'requested', paid_minor: 0,
      expires_at: '2026-10-22T10:00:00Z', created_at: '2026-10-22T09:30:00Z' }
    const fetchMock = market((path, init) => {
      if (path === '/v1/admin/market/prepaid?currency=CNY') return json({ ...prepaid, sellers: [sellerRow] })
      if (path === '/v1/admin/market/direct-pay/sellers') return json({ items: [{ seller_id: offer.seller_id, display_name: 'HK Seller', currency: 'CNY',
        balance_minor: 800, credit_limit_minor: 1000, online: true, methods: [{ method: 'alipay', display_name: '支付宝', min_minor: 100, max_minor: 500000 }],
        seller_credit: credit }] })
      if (path === '/v1/admin/market/direct-topups' && init?.method === 'POST') return json(topup)
      if (path === `/v1/admin/market/direct-topups/${topup.id}`) {
        polled += 1
        return json(polled === 1 ? { ...topup, state: 'awaiting_payment', channel_display_name: '支付宝',
          action: { kind: 'qr_code', qr_content: 'https://qr.alipay.com/x' } } : { ...topup, state: 'paid', paid_minor: 2000 })
      }
      if (path.startsWith('/v1/admin/market/direct-topups?')) return json({ items: [] })
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的供货方余额' }))
    expect(await screen.findByText('HK Seller')).toBeInTheDocument()
    expect(screen.getByText('低于预警线')).toBeInTheDocument()
    expect(screen.getByText('保证金 50.00 CNY')).toBeInTheDocument()
    expect(screen.getByText('近 30 天无在线节点 1 次')).toBeInTheDocument()
    expect(screen.getByText('平台预付余额（插件市场与平台费用）：12.00 CNY')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '充值' }))
    const modal = await screen.findByRole('dialog')
    expect(within(modal).getByText(/平台不经手资金/)).toBeInTheDocument()
    fireEvent.change(within(modal).getByLabelText('金额'), { target: { value: '20' } })
    fireEvent.click(within(modal).getByRole('button', { name: '生成支付码' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/direct-topups', expect.objectContaining({ method: 'POST' })))
    const [, init] = fetchMock.mock.calls.find(([p, i]) => p === '/v1/admin/market/direct-topups' && i?.method === 'POST')!
    expect(JSON.parse(init!.body as string)).toEqual({ seller_member_id: offer.seller_id, amount_minor: 2000, currency: 'CNY', method: 'alipay' })
    expect((init!.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^direct-topup-/)
    expect(await within(modal).findByText(/请扫码或点击/, {}, { timeout: 5000 })).toBeInTheDocument()
    expect(await within(modal).findByText('已到账 20.00 CNY', {}, { timeout: 8000 })).toBeInTheDocument()
  }, 20000)

  // MK-DIRECT-TOPUP-FEEDBACK-01: an expired checkout keeps being checked
  // (a late real payment is still credited), a failed check says so, and the
  // page never pushes rows into the cached summary (MK-DIRECT-CACHE-01).
  it('keeps checking an expired top-up, reports failed checks and leaves the query cache as fetched', async () => {
    let polled = 0
    const topup = { id: '99999999-9999-4999-8999-999999999999', buyer_member_id: 'b', seller_member_id: offer.seller_id,
      peer_display_name: 'HK Seller', amount_minor: 2000, currency: 'CNY', method: 'alipay', state: 'expired', paid_minor: 0,
      expires_at: '2026-10-22T10:00:00Z', created_at: '2026-10-22T09:30:00Z' }
    const summary = Object.freeze({ ...prepaid, sellers: Object.freeze([]) })
    const fetchMock = market((path, init) => {
      if (path === '/v1/admin/market/prepaid?currency=CNY') return json(summary)
      if (path === '/v1/admin/market/direct-pay/sellers') return json({ items: [{ seller_id: offer.seller_id, display_name: 'HK Seller', currency: 'CNY',
        balance_minor: 0, credit_limit_minor: 0, online: true, methods: [{ method: 'alipay', display_name: '支付宝', min_minor: 100, max_minor: 500000 }] }] })
      if (path === '/v1/admin/market/direct-topups' && init?.method === 'POST') return json(topup)
      if (path === `/v1/admin/market/direct-topups/${topup.id}`) {
        polled += 1
        if (polled === 1) return json({ error: 'internal' }, 500)
        return json({ ...topup, state: 'paid', paid_minor: 2000 })
      }
      if (path.startsWith('/v1/admin/market/direct-topups?')) return json({ items: [] })
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的供货方余额' }))
    // The seller without a ledger row is shown from a derived array (frozen input would throw on push).
    expect(await screen.findByText('HK Seller')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '充值' }))
    const modal = await screen.findByRole('dialog')
    fireEvent.change(within(modal).getByLabelText('金额'), { target: { value: '20' } })
    fireEvent.click(within(modal).getByRole('button', { name: '生成支付码' }))
    expect(await within(modal).findByText(/收银台已失效/)).toBeInTheDocument()
    expect(within(modal).queryByRole('button', { name: '生成支付码' })).not.toBeInTheDocument()
    expect(await within(modal).findByText(/查询充值状态失败（internal）/)).toBeInTheDocument()
    fireEvent.click(within(modal).getAllByRole('button', { name: '立即查询' })[0])
    expect(await within(modal).findByText('已到账 20.00 CNY')).toBeInTheDocument()
  })

  // market-buy-idem: a lost answer shows "result unknown"; checking replays the
  // same Idempotency-Key, also after closing and reopening the dialog.
  it('replays an unknown direct top-up with the same key instead of creating another', async () => {
    let answer = 0
    const topup = { id: '99999999-9999-4999-8999-999999999999', buyer_member_id: 'b', seller_member_id: offer.seller_id,
      peer_display_name: 'HK Seller', amount_minor: 2000, currency: 'CNY', method: 'alipay', state: 'paid', paid_minor: 2000,
      expires_at: '2026-10-22T10:00:00Z', created_at: '2026-10-22T09:30:00Z' }
    const fetchMock = market((path, init) => {
      if (path === '/v1/admin/market/prepaid?currency=CNY') return json({ ...prepaid, sellers: [sellerRow] })
      if (path === '/v1/admin/market/direct-pay/sellers') return json({ items: [{ seller_id: offer.seller_id, display_name: 'HK Seller', currency: 'CNY',
        balance_minor: 800, credit_limit_minor: 1000, online: true, methods: [{ method: 'alipay', display_name: '支付宝', min_minor: 100, max_minor: 500000 }] }] })
      if (path === '/v1/admin/market/direct-topups' && init?.method === 'POST') {
        answer += 1
        return answer === 1 ? json({ error: 'internal' }, 502) : json(topup)
      }
      if (path.startsWith('/v1/admin/market/direct-topups?')) return json({ items: [] })
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的供货方余额' }))
    expect(await screen.findByText('HK Seller')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '充值' }))
    let modal = await dialogTitled('给 HK Seller 充值')
    fireEvent.change(within(modal).getByLabelText('金额'), { target: { value: '20' } })
    fireEvent.click(within(modal).getByRole('button', { name: '生成支付码' }))
    expect(await within(modal).findAllByText('结果未知')).not.toHaveLength(0)
    // OutcomeUnknown also opens its explaining dialog once; acknowledge it.
    fireEvent.click(await screen.findByRole('button', { name: '知道了' }))
    expect(within(modal).getByRole('button', { name: '生成支付码' })).toBeDisabled()
    fireEvent.click(within(modal).getByRole('button', { name: 'Close' }))
    fireEvent.click(screen.getByRole('button', { name: '充值' }))
    modal = await dialogTitled('给 HK Seller 充值')
    fireEvent.click(await screen.findByRole('button', { name: '查询结果' }))
    expect(await within(modal).findByText('已到账 20.00 CNY')).toBeInTheDocument()
    const keys = fetchMock.mock.calls.filter(([p, i]) => p === '/v1/admin/market/direct-topups' && i?.method === 'POST')
      .map(([, i]) => (i!.headers as Record<string, string>)['Idempotency-Key'])
    expect(keys).toHaveLength(2)
    expect(keys[0]).toMatch(/^direct-topup-/)
    expect(keys[1]).toBe(keys[0])
  })

  it('disables top-up with the reason when the seller is offline and shows a short deposit on the listing', async () => {
    const fetchMock = market((path) => {
      if (path === '/v1/admin/market/offers?limit=50') return json({ items: [{ ...offer, seller_credit: { ...credit, sufficient: false } }] })
      if (path === '/v1/admin/market/prepaid?currency=CNY') return json({ ...prepaid, sellers: [sellerRow] })
      if (path === '/v1/admin/market/direct-pay/sellers') return json({ items: [{ seller_id: offer.seller_id, display_name: 'HK Seller', currency: 'CNY',
        balance_minor: 800, credit_limit_minor: 1000, online: false, methods: [], unavailable: 'seller_offline' }] })
      if (path.startsWith('/v1/admin/market/direct-topups?')) return json({ items: [] })
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的供货方余额' }))
    expect(await screen.findByText('供货方主控暂时离线，暂不能在线充值')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '充值' })).toBeDisabled()
    fireEvent.click(screen.getByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('保证金 50.00 CNY · 不足')).toBeInTheDocument()
  })

  it('pages the received top-ups by cursor instead of keeping only the first 50', async () => {
    const received = (n: number) => ({ id: `t-${n}`, buyer_member_id: 'b', seller_member_id: offer.seller_id, peer_display_name: `Payer ${n}`,
      amount_minor: 100, method: 'alipay', state: 'paid', paid_minor: 100, created_at: '2026-10-20T00:00:00Z' })
    const fetchMock = market((path) => {
      if (path === '/v1/admin/market/prepaid?currency=CNY') return json({ ...prepaid, sellers: [] })
      if (path === '/v1/admin/market/direct-pay/sellers') return json({ items: [] })
      if (!path.startsWith('/v1/admin/market/direct-topups?')) return undefined
      const cursor = Number(new URLSearchParams(path.split('?')[1]).get('cursor') ?? 0)
      const end = Math.min(cursor + 50, 120)
      return json({ items: Array.from({ length: end - cursor }, (_, i) => received(cursor + i + 1)), next_cursor: end < 120 ? String(end) : null })
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    // MC12 E4: received top-ups live under 供货管理 → 收款记录.
    fireEvent.click(await screen.findByRole('tab', { name: '供货管理' }))
    fireEvent.click(await screen.findByRole('tab', { name: '收款记录' }))
    expect(await screen.findByText('Payer 50')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('Payer 100')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('Payer 120')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '下一页' })).toBeDisabled()
    expect(screen.getByText('第 3 页，已加载 120 条')).toBeInTheDocument()
    expect(fetchMock.mock.calls.map(([p]) => String(p)).filter((p) => p.startsWith('/v1/admin/market/direct-topups?'))).toEqual([
      '/v1/admin/market/direct-topups?as=seller&limit=50', '/v1/admin/market/direct-topups?as=seller&cursor=50&limit=50',
      '/v1/admin/market/direct-topups?as=seller&cursor=100&limit=50'])
  })
})
