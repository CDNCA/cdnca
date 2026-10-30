import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../auth/session'
import i18n from '../../i18n'
import { authResponse, nodeManagementSettingsFixture, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import { defaultRows, overriddenBy, shareOf, toLimits } from './limitsModel'
import { customProblem, exampleCharge, moneyProblems, normalizeCustom, pricingOf } from './listingModel'
import NodeMarketPage from './NodeMarketPage'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['sites.manage'] })
const nodeA = '018f0000-0000-7000-8000-00000000000a'
const nodeB = '018f0000-0000-7000-8000-00000000000b'
const nodeC = '018f0000-0000-7000-8000-00000000000c'

function node(id: string, display: string, name: string, country: string, isp: string) {
  const settings = nodeManagementSettingsFixture()
  return {
    id, display_id: display, name, description: '', region: 'r', ipv4: '192.0.2.1', admin_state: 'active',
    management_settings: { ...settings, ip_location: { ...settings.ip_location, country_code: country, isp } },
    revision: 1, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
    presence: { status: 'online', projection_freshness: 'fresh', lease_signal: 'present' },
  }
}

function latest(id: string, cpu: number, memoryPercent: number) {
  return {
    node_id: id, node_name: 'a', config_revision: 1, active_config_revision: 1, publication_sequence: 1, observed_at: '2026-10-21T00:00:00Z',
    probe_port: 8443, healthy: true, probe_succeeded: true, consecutive_failures: 0, consecutive_successes: 1, probes_total: 1, probe_failures_total: 0,
    recovered: false, recovery_notified: false, rolled_back: false, known: true,
    cpu_percent: cpu, memory_used_bytes: memoryPercent * 10, memory_total_bytes: 1000, active_connections: 1,
    rx_bandwidth_bps: 0, tx_bandwidth_bps: 0, total_rx_bytes: 0, total_tx_bytes: 0,
    puback_stream: 'NODE_MONITORING_STATUS', puback_sequence: 1, consumer_durable: 'control_api_node_metrics', consumer_sequence: 1,
    ingested_at: '2026-10-21T00:00:01Z',
  }
}

type Handler = (path: string, init?: RequestInit) => Response | undefined

function market(extra: Handler = () => undefined, floor = { cpu_percent: 80, memory_percent: 70 }) {
  return vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path, init) => {
    const custom = extra(path, init)
    if (custom) return custom
    if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
    if (path === '/v1/admin/market/offers?mine=1') return json({ items: [] })
    if (path.startsWith('/v1/nodes?')) return json({ items: [node(nodeA, '1', 'HK-1', 'HK', '电信'), node(nodeB, '2', 'HK-2', 'HK', '联通'), node(nodeC, '3', 'JP-1', 'JP', 'IIJ')] })
    if (path.startsWith('/v1/nodes/metrics/latest?')) {
      const asked = new URLSearchParams(path.split('?')[1]).getAll('node_id')
      return json({ observed_at: '2026-10-21T00:00:00Z', items: asked.includes(nodeA) ? [latest(nodeA, 40, 50)] : [],
        not_reported_node_ids: asked.filter((id) => id !== nodeA) })
    }
    if (path.startsWith('/v1/nodes/')) return json({ items: [] })
    if (path === '/v1/admin/market/node-admissions?limit=200') return json({ items: [
      { node_pool_ref: 'p', node_id: nodeA, benchmark_grade: 'a', status: 'admitted' },
      { node_pool_ref: 'q', node_id: nodeA, benchmark_grade: 's', status: 'admitted' },
    ] })
    if (path === '/v1/admin/market/supply-limits-policy') return json({ version: 4, policy: { load_floor: floor } })
    if (path === '/v1/admin/market/supply-plugins') {
      const ids = JSON.parse(init!.body as string).node_ids as string[]
      // ML-09 intersection: autodefense on every node, CRS only on A; the free JA4 cannot be sold as a tag,
      // a bought rule pack can (rule_pack:<pack id>, ML-25), a malformed rule pack code cannot.
      return json({ items: [
        { code: 'module.autodefense', name_zh: '智能自动防御（学习、观察、告警）', name_en: 'Automatic defense' },
        ...(ids.every((id) => id === nodeA) ? [{ code: 'pack.crs', name_zh: 'OWASP CRS 档位', name_en: 'OWASP CRS levels' }] : []),
        { code: 'ja4', name_zh: 'JA4 指纹', name_en: 'JA4 fingerprints' },
        { code: 'rule_pack:p1', name_zh: '规则包 P1', name_en: 'Rule pack P1' },
        { code: 'rule_pack:dev/io.cdnca.examples/bad-bots', name_zh: '坏机器人规则包', name_en: 'Bad bots pack' },
      ] })
    }
    if (path === '/v1/admin/market/listing-templates') return json({ items: [] })
    if (path === '/v1/admin/market/listing-batches') {
      const ids = JSON.parse(init!.body as string).node_ids as string[]
      return json({ items: [{ node_ids: ids, status: 'created', group_id: 'g', offer_id: 'o', published: 'listed', removed_plugins: [] }] })
    }
    return json({ error: 'not_found' }, 404)
  })
}

function limitsTable() {
  return screen.getByRole('table', { name: '限额' })
}

async function openSell() {
  renderWithProviders(<NodeMarketPage />)
  fireEvent.click(await screen.findByRole('tab', { name: '我的上架' }))
  await screen.findByText('HK-1')
}

beforeEach(() => useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'market-token' }, admin))
afterEach(() => { vi.unstubAllGlobals(); void i18n.changeLanguage('zh-CN') })

describe('limitsModel', () => {
  it('splits realtime caps over the nodes and leaves node and total rows unsplit', () => {
    const rows = defaultRows().map((r) => r.metric === 'bandwidth_peak_bps' ? { ...r, enabled: true, value: 1, unit: 'Gbps' as const } : r)
    // ceil(1e9 / 3) = 333333334 bit/s per node.
    expect(shareOf(rows[1], 3)).toEqual({ kind: 'split', value: 333333334 / 1e9 })
    expect(shareOf({ ...rows[6], enabled: true, value: 70 }, 3)).toEqual({ kind: 'perNode' })
    expect(shareOf({ ...rows[2], enabled: true, value: 1 }, 3)).toEqual({ kind: 'total' })
  })

  it('refuses node rows above the floor, converts units and requires the throttle rate', () => {
    const rows = defaultRows().map((r) => {
      if (r.metric === 'node_cpu_percent') return { ...r, enabled: true, value: 85 }
      if (r.metric === 'monthly_traffic_bytes') return { ...r, enabled: true, value: 2, unit: 'TB' as const, action: 'throttle' as const }
      if (r.metric === 'qps') return { ...r, enabled: true, value: 500 }
      return r
    })
    const { limits, problems } = toLimits(rows, { cpu_percent: 80, memory_percent: 70 })
    expect(problems).toEqual([{ metric: 'monthly_traffic_bytes', code: 'throttle' }, { metric: 'node_cpu_percent', code: 'floor', floor: 80 }])
    expect(limits).toEqual([{ metric: 'qps', cap: 500, action: 'throttle' }])
    const fixed = rows.map((r) => r.metric === 'monthly_traffic_bytes' ? { ...r, throttleMbps: 10 } : r.metric === 'node_cpu_percent' ? { ...r, value: 75 } : r)
    expect(toLimits(fixed, { cpu_percent: 80, memory_percent: 70 }).limits).toEqual([
      { metric: 'monthly_traffic_bytes', cap: 2 * 1024 ** 4, action: 'throttle', throttle_bps: 10_000_000 },
      { metric: 'qps', cap: 500, action: 'throttle' },
      { metric: 'node_cpu_percent', cap: 75, action: 'remove_node' },
    ])
    expect(overriddenBy([{ metric: 'node_cpu_percent', cap: 75, action: 'remove_node' }], { cpu_percent: 60, memory_percent: 70 }))
      .toEqual([{ metric: 'node_cpu_percent', effective: 60 }])
  })
})

describe('listing money and custom tags (fix-offerform)', () => {
  it('converts yuan to minor units exactly and flags what it would have to round', () => {
    const v = { billing_model: 'traffic' as const, price: 0.29, deposit: 10.1, minDays: 1, maxDays: 30 }
    expect(pricingOf(v)).toEqual({ currency: 'CNY', tiers: [{ up_to_gb: 0, price_per_gb_minor: 29 }], deposit_minor: 1010 })
    expect(moneyProblems(v)).toEqual([])
    expect(moneyProblems({ ...v, price: 0.001, deposit: 0 })).toEqual(['price', 'deposit'])
    expect(moneyProblems({ billing_model: 'daily_bundle', price: 1.5, deposit: 0 })).toEqual([])
    expect(() => pricingOf({ ...v, price: 1.234 })).toThrow()
    expect(exampleCharge('bandwidth_95', 1)).toEqual({ quantity: 100, total: 10000 })
    expect(exampleCharge('daily_bundle', 1.5)).toEqual({ quantity: 30, total: 4500 })
    expect(exampleCharge('traffic', 1.005)).toBeNull()
  })

  it('normalizes and validates custom tags like the market', () => {
    expect(normalizeCustom([' 高防 ', '高防', '', '原生 IP'])).toEqual(['高防', '原生 IP'])
    expect(customProblem(Array.from({ length: 10 }, (_, i) => `t${i}`))).toBeNull()
    expect(customProblem(Array.from({ length: 11 }, (_, i) => `t${i}`))).toBe('tooMany')
    expect(customProblem(['长'.repeat(16)])).toBeNull()
    expect(customProblem(['长'.repeat(17)])).toBe('tooLong')
    expect(customProblem(['高\u0007防'])).toBe('control')
  })
})

describe('offer listing page', () => {
  // MC09 (ML-26/26f): the quota is explained before the long form is filled; 0 or too few block creating.
  it('blocks creating with a zero quota and says who changes it', async () => {
    vi.stubGlobal('fetch', market((path) => path === '/v1/admin/market/member'
      ? json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 0, offers_used: 0 }) : undefined))
    await openSell()
    expect(await screen.findByText(/报价额度为 0，不能新建报价/)).toBeInTheDocument()
    expect(screen.getAllByText(/由平台运营调整/).length).toBeGreaterThan(0)
    fireEvent.click(screen.getByRole('checkbox', { name: 'HK-1' }))
    expect(screen.getByRole('button', { name: /创建 1 条报价（每个节点一条）/ })).toBeDisabled()
  })

  it('shows total, used and remaining and needs one offer per node in single mode', async () => {
    vi.stubGlobal('fetch', market((path) => path === '/v1/admin/market/member'
      ? json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 5, offers_used: 4 }) : undefined))
    await openSell()
    expect(await screen.findByText('报价额度：上限 5，已占用 4，还可新建 1 条（已下架的不占额度）')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox', { name: 'HK-1' }))
    expect(screen.getByRole('button', { name: /创建 1 条报价（每个节点一条）/ })).toBeEnabled()
    fireEvent.click(screen.getByRole('checkbox', { name: 'HK-2' }))
    expect(screen.getByText(/还可新建 1 条，本次需要 2 条/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /创建 2 条报价（每个节点一条）/ })).toBeDisabled()
  })

  it('shows each node with region, carrier, best line grade and current load', async () => {
    vi.stubGlobal('fetch', market())
    await openSell()
    const row = screen.getByText('HK-1').closest('tr')!
    expect(within(row).getByText('HK')).toBeInTheDocument()
    expect(within(row).getByText('电信')).toBeInTheDocument()
    expect(within(row).getByText('S')).toBeInTheDocument()
    expect(await within(row).findByText('CPU 40% · 内存 50%')).toBeInTheDocument()
    expect(within(screen.getByText('JP-1').closest('tr')!).getByText('无数据')).toBeInTheDocument()
  })

  it('reads every page of node admissions, not only the first 200', async () => {
    const fetchMock = market((path) => {
      if (path === '/v1/admin/market/node-admissions?limit=200') return json({ items: [
        { node_pool_ref: 'p', node_id: nodeA, benchmark_grade: 'a', status: 'admitted' }], next_cursor: 'k1' })
      if (path === '/v1/admin/market/node-admissions?cursor=k1&limit=200') return json({ items: [
        { node_pool_ref: 'p', node_id: nodeB, benchmark_grade: 'b', status: 'admitted' }], next_cursor: null })
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    await openSell()
    expect(await within(screen.getByText('HK-2').closest('tr')!).findByText('B')).toBeInTheDocument()
    expect(within(screen.getByText('HK-1').closest('tr')!).getByText('A')).toBeInTheDocument()
    expect(fetchMock.mock.calls.map(([p]) => String(p)).filter((p) => p.includes('node-admissions'))).toEqual([
      '/v1/admin/market/node-admissions?limit=200', '/v1/admin/market/node-admissions?cursor=k1&limit=200'])
  })

  it('defaults each checked limit to its §3.1 action, caps node rows at the floor and previews the per-node share', async () => {
    vi.stubGlobal('fetch', market())
    await openSell()
    // One multi-node supply: realtime caps are split over its nodes.
    fireEvent.click(screen.getByRole('radio', { name: '所选节点合成一条多节点供给' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'HK-1' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'HK-2' }))
    const table = limitsTable()
    // Unchecked = unlimited: nothing editable until the row is checked.
    expect(within(table).getByLabelText('上限 峰值带宽')).toBeDisabled()
    fireEvent.click(within(table).getByRole('checkbox', { name: '峰值带宽' }))
    fireEvent.click(within(table).getByRole('checkbox', { name: '月流量' }))
    fireEvent.click(within(table).getByRole('checkbox', { name: '并发连接' }))
    const actionOf = (metric: string) => within(table).getAllByLabelText(`到限处置 ${metric}`)[0].closest('.ant-select')!
    expect(within(actionOf('峰值带宽') as HTMLElement).getByText('限速')).toBeInTheDocument()
    expect(within(actionOf('月流量') as HTMLElement).getByText('暂停调度')).toBeInTheDocument()
    expect(within(actionOf('并发连接') as HTMLElement).getByText('限速')).toBeInTheDocument()
    fireEvent.change(within(table).getByLabelText('上限 峰值带宽'), { target: { value: '1000' } })
    expect(screen.getByTestId('share-bandwidth_peak_bps')).toHaveTextContent('每节点 500 Mbps（2 个节点）')
    fireEvent.change(within(table).getByLabelText('上限 并发连接'), { target: { value: '1001' } })
    expect(screen.getByTestId('share-concurrent_connections')).toHaveTextContent('每节点 501 个（2 个节点）')
    expect(screen.getByTestId('share-monthly_traffic_bytes')).toHaveTextContent('整个订阅合计')
    // Node capacity: floor shown, checking fills the floor, the input is bounded by it.
    expect(within(table).getByText('平台底线 80%，不能高于底线')).toBeInTheDocument()
    fireEvent.click(within(table).getByRole('checkbox', { name: '节点内存' }))
    expect(within(table).getByLabelText('上限 节点内存')).toHaveValue('70')
    expect(within(table).getByLabelText('上限 节点内存')).toHaveAttribute('aria-valuemax', '70')
    expect(screen.getByTestId('share-node_memory_percent')).toHaveTextContent('每个节点各自判定')
    expect(within(actionOf('节点内存') as HTMLElement).getByText('摘除该节点')).toBeInTheDocument()
  })

  it('lists only plugins every selected node has and that an offer may carry', async () => {
    vi.stubGlobal('fetch', market())
    await openSell()
    fireEvent.click(screen.getByRole('radio', { name: '所选节点合成一条多节点供给' }))
    expect(screen.getByText('选好节点后这里会列出可附带的功能', { selector: '.ant-form-item-extra *, .ant-form-item-extra' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox', { name: 'HK-1' }))
    expect(await screen.findByRole('checkbox', { name: 'OWASP CRS 档位' })).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: '智能自动防御（学习、观察、告警）' })).toBeInTheDocument()
    expect(screen.queryByText('JA4 指纹')).not.toBeInTheDocument()
    expect(screen.queryByText('规则包 P1')).not.toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: '坏机器人规则包' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox', { name: 'HK-2' }))
    await waitFor(() => expect(screen.queryByRole('checkbox', { name: 'OWASP CRS 档位' })).not.toBeInTheDocument())
    expect(await screen.findByRole('checkbox', { name: '智能自动防御（学习、观察、告警）' })).toBeInTheDocument()
  })

  it('sends one batch of the merged nodes with limits, tags, prepaid action and no components', async () => {
    const fetchMock = market()
    vi.stubGlobal('fetch', fetchMock)
    await openSell()
    fireEvent.click(screen.getByRole('radio', { name: '所选节点合成一条多节点供给' }))
    fireEvent.change(screen.getByLabelText('名称'), { target: { value: ' HK pair ' } })
    fireEvent.click(screen.getByRole('checkbox', { name: 'HK-2' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'HK-1' }))
    fireEvent.click(await screen.findByRole('checkbox', { name: '智能自动防御（学习、观察、告警）' }))
    const table = limitsTable()
    fireEvent.click(within(table).getByRole('checkbox', { name: 'QPS' }))
    fireEvent.change(within(table).getByLabelText('上限 QPS'), { target: { value: '2000' } })
    fireEvent.click(within(table).getByRole('checkbox', { name: '节点 CPU' }))
    fireEvent.change(within(table).getByLabelText('上限 节点 CPU'), { target: { value: '75' } })
    fireEvent.click(screen.getByRole('button', { name: '创建 1 条多节点报价' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/listing-batches', expect.objectContaining({ method: 'POST' })))
    const [, init] = fetchMock.mock.calls.find(([path]) => path === '/v1/admin/market/listing-batches')!
    expect(JSON.parse(init!.body as string)).toEqual({ mode: 'multi', node_ids: [nodeA, nodeB], publish: true, offer: {
      name: 'HK pair', billing_model: 'daily_bundle', allocation: { http_ports: 2 },
      limits: [{ metric: 'qps', cap: 2000, action: 'throttle' }, { metric: 'node_cpu_percent', cap: 75, action: 'remove_node' }],
      tags: { cc_protection: 'none', ddos_protection_gbps: 0, complaint_resistant: false, tenancy: 'shared', mobile_reachable: false,
        region_block: false, plugins: ['module.autodefense'] },
      prepaid_exhausted_action: 'pause', compliance: { require_icp: false },
      pricing: { currency: 'CNY', daily_minor: 100, min_days: 1, max_days: 365 }, trial_days: 0,
    } })
    expect(await screen.findByText('已创建')).toBeInTheDocument()
  })

  // fix-offerform: no "create 0 offers" button; it waits for nodes and says where to pick them.
  it('disables the create button until a node is picked and says where to pick one', async () => {
    const fetchMock = market()
    vi.stubGlobal('fetch', fetchMock)
    await openSell()
    fireEvent.change(screen.getByLabelText('名称'), { target: { value: 'x' } })
    const create = screen.getByRole('button', { name: '创建 0 条报价（每个节点一条）' })
    expect(create).toBeDisabled()
    expect(screen.getByTestId('pick-nodes-first')).toHaveTextContent('请先在上方“选择节点”里勾选节点')
    fireEvent.click(create)
    expect(fetchMock.mock.calls.filter(([path]) => path === '/v1/admin/market/listing-batches')).toHaveLength(0)
    fireEvent.click(screen.getByRole('checkbox', { name: 'HK-1' }))
    expect(screen.getByRole('button', { name: '创建 1 条报价（每个节点一条）' })).toBeEnabled()
    expect(screen.queryByTestId('pick-nodes-first')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('radio', { name: '所选节点合成一条多节点供给' }))
    expect(screen.getByRole('button', { name: '创建 1 条多节点报价' })).toBeEnabled()
    // The node CPU input is bounded by the floor.
    fireEvent.click(screen.getByRole('checkbox', { name: 'HK-1' }))
    fireEvent.click(within(limitsTable()).getByRole('checkbox', { name: '节点 CPU' }))
    expect(within(limitsTable()).getByLabelText('上限 节点 CPU')).toHaveAttribute('aria-valuemax', '80')
  })

  it('switches to metered pricing with a deposit and the prepaid stop action', async () => {
    const fetchMock = market()
    vi.stubGlobal('fetch', fetchMock)
    await openSell()
    fireEvent.change(screen.getByLabelText('名称'), { target: { value: 'traffic' } })
    fireEvent.click(screen.getByRole('checkbox', { name: 'JP-1' }))
    fireEvent.mouseDown(screen.getByLabelText('计费方式'))
    fireEvent.click(await screen.findByTitle('按流量'))
    fireEvent.change(await screen.findByLabelText('每 GB 单价（元）'), { target: { value: '0.3' } })
    fireEvent.mouseDown(screen.getByLabelText('预付用完处置'))
    fireEvent.click(await screen.findByTitle('停止服务'))
    fireEvent.click(screen.getByRole('button', { name: '创建 1 条报价（每个节点一条）' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/listing-batches', expect.objectContaining({ method: 'POST' })))
    const body = JSON.parse(fetchMock.mock.calls.find(([path]) => path === '/v1/admin/market/listing-batches')![1]!.body as string).offer
    expect(body).toMatchObject({ billing_model: 'traffic', prepaid_exhausted_action: 'stop', limits: [],
      pricing: { currency: 'CNY', tiers: [{ up_to_gb: 0, price_per_gb_minor: 30 }], deposit_minor: 1000 } })
  })

  // fix-offerform: prices in yuan (2 decimals), sent as minor units; more decimals are refused, not rounded.
  it('takes prices in yuan, shows a live example and sends minor units', async () => {
    const fetchMock = market()
    vi.stubGlobal('fetch', fetchMock)
    await openSell()
    expect(screen.queryByText(/（分）/)).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('名称'), { target: { value: '95' } })
    fireEvent.click(screen.getByRole('checkbox', { name: 'JP-1' }))
    fireEvent.mouseDown(screen.getByLabelText('计费方式'))
    expect(await screen.findByText('每月取 95 百分位带宽 × 单价')).toBeInTheDocument()
    fireEvent.click(await screen.findByTitle('95 带宽'))
    fireEvent.change(await screen.findByLabelText('单价（元 / Mbps / 月）'), { target: { value: '1.005' } })
    fireEvent.change(screen.getByLabelText('押金（元）'), { target: { value: '50.5' } })
    expect(screen.queryByTestId('price-example')).not.toBeInTheDocument()
    expect(screen.getByText('订阅方预付不少于押金才能开始使用，用完按下方“预付用完处置”处理。')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '创建 1 条报价（每个节点一条）' }))
    expect(await screen.findByText('单价（元 / Mbps / 月）：金额最多 2 位小数且不能为负')).toBeInTheDocument()
    expect(fetchMock.mock.calls.filter(([path]) => path === '/v1/admin/market/listing-batches')).toHaveLength(0)
    fireEvent.change(screen.getByLabelText('单价（元 / Mbps / 月）'), { target: { value: '0.29' } })
    expect(screen.getByTestId('price-example')).toHaveTextContent('订阅方 95 带宽 100 Mbps 用满一个月 = 29.00 元')
    fireEvent.click(screen.getByRole('button', { name: '创建 1 条报价（每个节点一条）' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/listing-batches', expect.objectContaining({ method: 'POST' })))
    const body = JSON.parse(fetchMock.mock.calls.find(([path]) => path === '/v1/admin/market/listing-batches')![1]!.body as string).offer
    expect(body.pricing).toEqual({ currency: 'CNY', per_mbps_month_minor: 29, deposit_minor: 5050 })
  })

  it('adds custom tags with Enter, trims and dedupes them, and refuses an 11th', async () => {
    const fetchMock = market()
    vi.stubGlobal('fetch', fetchMock)
    await openSell()
    fireEvent.change(screen.getByLabelText('名称'), { target: { value: 'tags' } })
    fireEvent.click(screen.getByRole('checkbox', { name: 'JP-1' }))
    const input = screen.getByRole('combobox', { name: '自定义标签' })
    for (const word of [' 原生 IP ', '原生 IP', '免备案']) {
      fireEvent.change(input, { target: { value: word } })
      fireEvent.keyDown(input, { key: 'Enter', code: 'Enter', keyCode: 13 })
    }
    expect(screen.getAllByText(/原生 IP|免备案/, { selector: '.ant-select-selection-item-content' }).map((n) => n.textContent)).toEqual(['原生 IP', '免备案'])
    fireEvent.click(screen.getByRole('button', { name: '创建 1 条报价（每个节点一条）' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/listing-batches', expect.objectContaining({ method: 'POST' })))
    const body = JSON.parse(fetchMock.mock.calls.find(([path]) => path === '/v1/admin/market/listing-batches')![1]!.body as string).offer
    expect(body.tags.custom).toEqual(['原生 IP', '免备案'])
  })

  it('renders the listing page in English', async () => {
    await i18n.changeLanguage('en-US')
    vi.stubGlobal('fetch', market())
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: 'My listings' }))
    expect(await screen.findByText('Select nodes')).toBeInTheDocument()
    expect(await screen.findByText('Platform floor 80%; cannot be higher', { selector: 'span' }, { timeout: 3000 })).toBeInTheDocument()
    fireEvent.click(await screen.findByRole('checkbox', { name: 'HK-1' }))
    expect(await screen.findByRole('checkbox', { name: 'OWASP CRS levels' })).toBeInTheDocument()
  })
})

describe('my offers', () => {
  const listed = { id: '77777777-7777-4777-8777-777777777777', seller_id: 's', name: 'HK pair', description: '', billing_model: 'daily_bundle',
    status: 'listed', revision: 2, pricing: { currency: 'CNY', daily_minor: 100, min_days: 1, max_days: 30 }, allocation: { http_ports: 2 },
    compliance: { require_icp: false }, prepaid_exhausted_action: 'stop', plugins_unavailable: ['pack.crs'],
    limits: [{ metric: 'bandwidth_peak_bps', cap: 2e9, action: 'throttle' }, { metric: 'node_cpu_percent', cap: 75, action: 'remove_node' }] }

  it('shows limits, the floor override and missing plugins, and the subscriber view with usage, holds and overloads', async () => {
    const fetchMock = market((path) => {
      if (path === '/v1/admin/market/offers?mine=1') return json({ items: [listed] })
      if (path === `/v1/admin/market/offers/${listed.id}/subscribers?limit=100`) return json({
        subscribers: [{ relation: 'direct', subscription_id: 'sub-1', buyer_id: 'b1b1b1b1-0000', buyer_name: 'Buyer One', status: 'active',
          paid_through: '2026-11-01T00:00:00Z', state: 'paused', domains: ['a.example.com'], domain_count: 1, bytes_24h: 2 ** 30, bytes_month: 5 * 2 ** 40,
          usage: [{ metric: 'bandwidth_peak_bps', value: 1.96e9, cap: 2e9, action: 'throttle', stage: 'warn95', evaluated_through: null }],
          holds: [{ subscription_id: 'sub-1', leaf_member_id: null, node_pool_ref: null, reason: 'prepaid', metric: null, action: 'pause', observed: 0, cap: 0,
            since: '2026-10-21T01:00:00Z' }] },
        // Visibility a: a downstream root shows only its reference, the direct buyer it comes through, domains and traffic.
        { relation: 'downstream', subscription_id: 'sub-1', downstream_ref: 'd-0123456789abcdef', via_name: 'Buyer One', status: 'active', state: 'paused',
          domains: ['c.example.com'], domain_count: 4, bytes_24h: 0, bytes_month: 0, usage: [], holds: [] }],
        overloads: [{ node_id: nodeA, state: 'overloaded', since: '2026-10-21T02:00:00Z', cpu_threshold: 60, memory_threshold: 70 }],
      })
      return undefined
    }, { cpu_percent: 60, memory_percent: 70 })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的上架' }))
    expect(await screen.findByText('峰值带宽 2 Gbps · 限速')).toBeInTheDocument()
    expect(await screen.findByText('已被平台底线覆盖：节点 CPU 60%')).toBeInTheDocument()
    expect(screen.getByText('节点已不具备：pack.crs')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '订阅者' }))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('Buyer One')).toBeInTheDocument()
    expect(within(drawer).getByText('峰值带宽：1.96 Gbps / 2 Gbps')).toBeInTheDocument()
    expect(within(drawer).getByLabelText('峰值带宽 98%')).toBeInTheDocument()
    expect(within(drawer).getByText('预付用完')).toBeInTheDocument()
    expect(within(drawer).getByText('暂停调度')).toBeInTheDocument()
    expect(within(drawer).getByText('已摘除')).toBeInTheDocument()
    expect(within(drawer).getByText('60% / 70%')).toBeInTheDocument()
    expect(within(drawer).getByText('d-0123456789abcdef')).toBeInTheDocument()
    expect(within(drawer).getByText('经由 Buyer One')).toBeInTheDocument()
    expect(within(drawer).getByText('c.example.com')).toBeInTheDocument()
    expect(within(drawer).getByText('共 4 个')).toBeInTheDocument()
    expect(within(drawer).getByText('本月 5 TB')).toBeInTheDocument()
    expect(within(drawer).getAllByText('已暂停调度')).toHaveLength(2)
    // C10：同一 hop 的直接与下游两行共用 subscription_id，行 key 仍各自独立（两行都渲染）。
    expect(within(drawer).getAllByRole('row').filter((row) => row.getAttribute('data-row-key')?.startsWith('sub-1'))
      .map((row) => row.getAttribute('data-row-key'))).toEqual(['sub-1/', 'sub-1/d-0123456789abcdef'])
  })

  // MC08 offer drawer: an active contract with no supply behind it says so in a column of its own, as the seller list does.
  it('shows the contract and the supply state apart, naming no supply in red like the seller list', async () => {
    const row = (id: string, name: string, state: string) => ({ relation: 'direct', subscription_id: id, buyer_id: `${id}-b`, buyer_name: name,
      status: 'active', paid_through: null, state, domains: [], domain_count: 0, bytes_24h: 0, bytes_month: 0, usage: [], holds: [] })
    vi.stubGlobal('fetch', market((path) => {
      if (path === '/v1/admin/market/offers?mine=1') return json({ items: [listed] })
      if (path === `/v1/admin/market/offers/${listed.id}/subscribers?limit=100`) return json({
        subscribers: [row('sub-cut', 'Cut Buyer', 'no_supply'), row('sub-ok', 'Served Buyer', 'serving')], overloads: [], next_cursor: null })
      return undefined
    }))
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的上架' }))
    fireEvent.click(await screen.findByRole('button', { name: '订阅者' }))
    const drawer = await screen.findByRole('dialog')
    const headers = within(drawer).getAllByRole('columnheader').map((h) => h.textContent)
    expect(headers.indexOf('供给状态')).toBe(headers.indexOf('合同状态') + 1)
    const cut = (await within(drawer).findByText('Cut Buyer')).closest('tr') as HTMLElement
    expect(within(cut).getByText('正常')).toBeInTheDocument()
    const tag = within(cut).getByText('暂无可用供给')
    expect(tag.closest('.ant-tag')).toHaveClass('ant-tag-error')
    expect(within(cut).getByText(/不会经本报价调度/)).toBeInTheDocument()
    expect(within(cut).queryByText('正常服务')).not.toBeInTheDocument()
    const ok = within(drawer).getByText('Served Buyer').closest('tr') as HTMLElement
    expect(within(ok).getByText('正常服务').closest('.ant-tag')).toHaveClass('ant-tag-success')
  })

  it('pages the subscriber view by cursor beyond the first page', async () => {
    const row = (n: number) => ({ relation: 'direct', subscription_id: `sub-${n}`, buyer_id: `b-${n}`, buyer_name: `Buyer ${n}`, status: 'active',
      paid_through: null, state: 'serving', domains: [], domain_count: 0, bytes_24h: 0, bytes_month: 0, usage: [], holds: [] })
    const fetchMock = market((path) => {
      if (path === '/v1/admin/market/offers?mine=1') return json({ items: [listed] })
      if (!path.startsWith(`/v1/admin/market/offers/${listed.id}/subscribers?`)) return undefined
      const cursor = Number(new URLSearchParams(path.split('?')[1]).get('cursor') ?? 0)
      const end = Math.min(cursor + 100, 230)
      // Like the market: the overloads come with the first page only.
      return json({ subscribers: Array.from({ length: end - cursor }, (_, i) => row(cursor + i + 1)),
        overloads: cursor === 0 ? [{ node_id: 'node-hot', state: 'overloaded', since: '2026-10-21T02:00:00Z', cpu_threshold: 60, memory_threshold: 70 }] : [],
        next_cursor: end < 230 ? String(end) : null })
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的上架' }))
    fireEvent.click(await screen.findByRole('button', { name: '订阅者' }))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('Buyer 100')).toBeInTheDocument()
    fireEvent.click(within(drawer).getByRole('button', { name: '下一页' }))
    expect(await within(drawer).findByText('Buyer 200')).toBeInTheDocument()
    fireEvent.click(within(drawer).getByRole('button', { name: '下一页' }))
    expect(await within(drawer).findByText('Buyer 230')).toBeInTheDocument()
    expect(within(drawer).getByRole('button', { name: '下一页' })).toBeDisabled()
    expect(within(drawer).getByText('第 3 页，已加载 230 条')).toBeInTheDocument()
    // Page 3 carries no overloads; the list read with page 1 is still shown.
    expect(within(drawer).getByText('node-hot')).toBeInTheDocument()
    fireEvent.click(within(drawer).getByRole('button', { name: '上一页' }))
    expect(await within(drawer).findByText('Buyer 101')).toBeInTheDocument()
    const sent = fetchMock.mock.calls.map(([p]) => String(p)).filter((p) => p.includes('/subscribers?'))
    // Going back refetches the stale page 2 with its cursor; no other request is made.
    expect([...new Set(sent)]).toEqual([`/v1/admin/market/offers/${listed.id}/subscribers?limit=100`,
      `/v1/admin/market/offers/${listed.id}/subscribers?cursor=100&limit=100`, `/v1/admin/market/offers/${listed.id}/subscribers?cursor=200&limit=100`])
  })

  it('says the market does not serve the subscriber view yet', async () => {
    vi.stubGlobal('fetch', market((path) => {
      if (path === '/v1/admin/market/offers?mine=1') return json({ items: [listed] })
      if (path.includes('/subscribers?')) return json({ error: 'market_feature_unavailable' }, 501)
      return undefined
    }))
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的上架' }))
    fireEvent.click(await screen.findByRole('button', { name: '订阅者' }))
    expect(await within(await screen.findByRole('dialog')).findByText(/市场端还没有开放这个功能/)).toBeInTheDocument()
  })
})
