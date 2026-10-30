import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { MarketOfferListing } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import i18n from '../../i18n'
import { authResponse, nodeManagementSettingsFixture, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import { defaultRows } from './limitsModel'
import { filterNodes, fromTemplate, mergeResults, repriced, retryNodes, runLimited, templateBody, defaultValues, trialDaysOf, unpublished } from './listingModel'
import NodeMarketPage from './NodeMarketPage'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['sites.manage'] })
const ids = ['018f0000-0000-7000-8000-00000000000a', '018f0000-0000-7000-8000-00000000000b', '018f0000-0000-7000-8000-00000000000c']

function node(id: string, display: string, name: string, country: string, isp: string, online = true, description = '') {
  const settings = nodeManagementSettingsFixture()
  return {
    id, display_id: display, name, description, region: 'r', ipv4: '192.0.2.1', admin_state: 'active',
    management_settings: { ...settings, ip_location: { ...settings.ip_location, country_code: country, isp } },
    revision: 1, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
    presence: { status: online ? 'online' : 'offline', projection_freshness: 'fresh', lease_signal: 'present' },
  }
}
const nodes = [node(ids[0], '1', 'HK-1', 'HK', '电信', true, '机房 A'), node(ids[1], '2', 'HK-2', 'HK', '联通', false), node(ids[2], '3', 'JP-1', 'JP', 'IIJ')]

const offer = (over: Partial<MarketOfferListing>): MarketOfferListing => ({
  id: 'o1', seller_id: 's', name: 'HK-1 包天', description: '', billing_model: 'daily_bundle', status: 'listed', revision: 1,
  pricing: { currency: 'CNY', daily_minor: 100, min_days: 1, max_days: 30 }, allocation: { http_ports: 2 }, compliance: { require_icp: false },
  components: [{ kind: 'own_pool', node_pool_ref: 'pool-1' }], ...over,
})

type Handler = (path: string, init?: RequestInit) => Response | undefined

function market(extra: Handler = () => undefined) {
  return vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path, init) => {
    const custom = extra(path, init)
    if (custom) return custom
    if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 30 })
    if (path === '/v1/admin/market/offers?mine=1') return json({ items: [] })
    if (path.startsWith('/v1/nodes?')) return json({ items: nodes })
    if (path.startsWith('/v1/nodes/')) return json({ items: [] })
    if (path === '/v1/admin/market/node-admissions?limit=200') return json({ items: [{ node_pool_ref: 'p', node_id: ids[2], benchmark_grade: 'a', status: 'admitted' }], next_cursor: null })
    if (path === '/v1/admin/market/supply-limits-policy') return json({ version: 1, policy: { load_floor: { cpu_percent: 80, memory_percent: 70 } } })
    if (path === '/v1/admin/market/supply-plugins') {
      const [only] = JSON.parse(init!.body as string).node_ids as string[]
      // CRS only on HK-1; automatic defense on every node.
      return json({ items: [{ code: 'module.autodefense', name_zh: '智能自动防御', name_en: 'Automatic defense' },
        ...(only === ids[0] ? [{ code: 'pack.crs', name_zh: 'OWASP CRS 档位', name_en: 'OWASP CRS levels' }] : [])] })
    }
    if (path === '/v1/admin/market/listing-templates') return json({ items: [] })
    return json({ error: 'not_found' }, 404)
  })
}

async function openSell() {
  renderWithProviders(<NodeMarketPage />)
  fireEvent.click(await screen.findByRole('tab', { name: '我的上架' }))
  await screen.findByText('HK-1')
}

beforeEach(() => useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'market-token' }, admin))
afterEach(() => { vi.unstubAllGlobals(); void i18n.changeLanguage('zh-CN') })

describe('listingModel', () => {
  it('filters nodes by region, carrier, grade, presence and keyword', () => {
    const all = nodes as never[]
    expect(filterNodes(all, { region: 'HK' }, {}).map((n: { name: string }) => n.name)).toEqual(['HK-1', 'HK-2'])
    expect(filterNodes(all, { carrier: 'IIJ' }, {}).map((n: { name: string }) => n.name)).toEqual(['JP-1'])
    expect(filterNodes(all, { grade: 'a' }, { [ids[2]]: 'a' }).map((n: { name: string }) => n.name)).toEqual(['JP-1'])
    expect(filterNodes(all, { onlineOnly: true }, {}).map((n: { name: string }) => n.name)).toEqual(['HK-1', 'JP-1'])
    expect(filterNodes(all, { keyword: '机房' }, {}).map((n: { name: string }) => n.name)).toEqual(['HK-1'])
  })

  it('round-trips a template and ignores unknown or bad fields', () => {
    const rows = defaultRows().map((r) => r.metric === 'qps' ? { ...r, enabled: true, value: 500 } : r)
    // The form edits yuan; a template keeps minor units (older templates read back the same).
    const body = templateBody({ ...defaultValues, name: '包天', price: 1.2, deposit: 9.99, plugins: ['pack.crs'], custom: ['原生 IP'] }, rows)
    expect(body.values).toMatchObject({ price: 120, deposit: 999 })
    const back = fromTemplate(JSON.parse(JSON.stringify(body)))
    expect(back.values).toMatchObject({ name: '包天', price: 1.2, deposit: 9.99, plugins: ['pack.crs'], custom: ['原生 IP'] })
    expect(back.rows.find((r) => r.metric === 'qps')).toMatchObject({ enabled: true, value: 500, action: 'throttle' })
    const bad = fromTemplate({ values: { price: 'x', billing_model: 'monthly', extra: 1 }, limits: [{ metric: 'qps', value: 1, action: 'remove_node' }] })
    expect(bad.values.price).toBe(1)
    expect(bad.values.billing_model).toBe('daily_bundle')
    expect(bad.rows.find((r) => r.metric === 'qps')!.action).toBe('throttle')
  })

  it('retries only failed items and merges their new results', () => {
    const first = [
      { node_ids: ['a'], status: 'created' as const, removed_plugins: [] },
      { node_ids: ['b'], status: 'failed' as const, error: 'node_unusable', removed_plugins: [] },
    ]
    expect(retryNodes(first)).toEqual(['b'])
    const merged = mergeResults(first, [{ node_ids: ['b'], status: 'created', removed_plugins: [] }])
    expect(merged.map((i) => i.status)).toEqual(['created', 'created'])
  })

  it('B19: retries an item whose publish failed (same offer, resubmitted) and counts it as unpublished', () => {
    const items = [
      { node_ids: ['a'], status: 'created' as const, offer_id: 'o1', published: 'listed', removed_plugins: [] },
      { node_ids: ['b'], status: 'created' as const, offer_id: 'o2', error: 'publish_market_unavailable', removed_plugins: [] },
      { node_ids: ['c'], status: 'existing' as const, offer_id: 'o3', error: 'publish_seller_overdue', removed_plugins: [] },
    ]
    expect(retryNodes(items)).toEqual(['b', 'c'])
    expect(unpublished(items).map((i) => i.offer_id)).toEqual(['o2', 'o3'])
  })

  it('reprices the main price per billing model', () => {
    expect(repriced(offer({}), { kind: 'percent', value: 10 })).toMatchObject({ daily_minor: 110, min_days: 1 })
    expect(repriced(offer({ billing_model: 'traffic', pricing: { currency: 'CNY', tiers: [{ up_to_gb: 0, price_per_gb_minor: 30 }], deposit_minor: 1 } }),
      { kind: 'set', value: 25 })).toMatchObject({ tiers: [{ up_to_gb: 0, price_per_gb_minor: 25 }], deposit_minor: 1 })
    expect(repriced(offer({}), { kind: 'percent', value: -200 })).toBeNull()
  })

  it('limits concurrency and keeps order', async () => {
    let inFlight = 0, peak = 0
    const out = await runLimited([1, 2, 3, 4, 5], 2, async (n) => {
      inFlight++; peak = Math.max(peak, inFlight)
      await new Promise((r) => setTimeout(r, 1))
      inFlight--
      return n * 2
    })
    expect(out).toEqual([2, 4, 6, 8, 10])
    expect(peak).toBe(2)
  })
})

describe('trial days', () => {
  it('keeps 0–30 on daily bundles and drops it on metered offers (market offers.go:177)', () => {
    expect(trialDaysOf({ billing_model: 'daily_bundle', trialDays: 7 })).toBe(7)
    expect(trialDaysOf({ billing_model: 'daily_bundle', trialDays: 45 })).toBe(30)
    expect(trialDaysOf({ billing_model: 'daily_bundle', trialDays: Number.NaN })).toBe(0)
    expect(trialDaysOf({ billing_model: 'traffic', trialDays: 7 })).toBe(0)
    expect(fromTemplate({ values: { trialDays: 5 } }).values.trialDays).toBe(5)
    expect(fromTemplate({ values: {} }).values.trialDays).toBe(0)
  })
})

describe('batch listing page', () => {
  it('selects the filtered nodes, lists one offer per node and shows per-item results with dropped plugins', async () => {
    const fetchMock = market((path, init) => {
      if (path !== '/v1/admin/market/listing-batches') return undefined
      const body = JSON.parse(init!.body as string)
      return json({ items: (body.node_ids as string[]).map((id) => id === ids[1]
        ? { node_ids: [id], status: 'failed', error: 'node_unusable', removed_plugins: [] }
        : { node_ids: [id], status: 'created', group_id: 'g', offer_id: 'o', published: 'listed', removed_plugins: id === ids[0] ? [] : ['pack.crs'] }) })
    })
    vi.stubGlobal('fetch', fetchMock)
    await openSell()
    fireEvent.change(screen.getByLabelText('名称'), { target: { value: '包天' } })
    fireEvent.change(screen.getByRole('spinbutton', { name: '免费试用天数' }), { target: { value: '7' } })
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '地区' }))
    fireEvent.click(await screen.findByTitle('HK'))
    await waitFor(() => expect(screen.queryByText('JP-1')).not.toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: '全选当前筛选（2）' }))
    expect(screen.getByText('已选 2 个节点，将创建 2 条报价')).toBeInTheDocument()
    // Single-node mode: the union of the nodes' plugins is offered.
    fireEvent.click(await screen.findByRole('checkbox', { name: 'OWASP CRS 档位' }))
    fireEvent.click(screen.getByRole('button', { name: '创建 2 条报价（每个节点一条）' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/listing-batches', expect.objectContaining({ method: 'POST' })))
    const body = JSON.parse(fetchMock.mock.calls.find(([p]) => p === '/v1/admin/market/listing-batches')![1]!.body as string)
    expect(body).toMatchObject({ mode: 'single', node_ids: [ids[0], ids[1]], publish: true, offer: { name: '包天', tags: { plugins: ['pack.crs'] }, trial_days: 7 } })
    expect(body.offer.components).toBeUndefined()
    const results = await screen.findByLabelText('批量结果')
    // 有失败项时汇总改为警告弹窗（FeedbackWhen），逐项原因仍在结果表里。
    expect(await screen.findByText('共 2 条：新建 1，已存在 0，失败 1', { selector: '.cdnca-feedback-warning .cdnca-feedback-title span' })).toBeInTheDocument()
    expect(within(results).getByText('有节点不能用于市场供给（离线或没有公网地址）')).toBeInTheDocument()
    // The failed item is resubmitted alone.
    fireEvent.click(within(results).getByRole('button', { name: '修改后重试失败项（1）' }))
    await waitFor(() => expect(fetchMock.mock.calls.filter(([p]) => p === '/v1/admin/market/listing-batches')).toHaveLength(2))
    const retry = JSON.parse(fetchMock.mock.calls.filter(([p]) => p === '/v1/admin/market/listing-batches')[1][1]!.body as string)
    expect(retry.node_ids).toEqual([ids[1]])
  })

  it('B19: a publish failure is a warning with a retry, not a green success', async () => {
    const fetchMock = market((path, init) => path === '/v1/admin/market/listing-batches'
      ? json({ items: [{ node_ids: JSON.parse(init!.body as string).node_ids, status: 'created', offer_id: 'o', group_id: 'g',
        error: 'publish_market_unavailable', removed_plugins: [] }] }) : undefined)
    vi.stubGlobal('fetch', fetchMock)
    await openSell()
    fireEvent.change(screen.getByLabelText('名称'), { target: { value: '包天' } })
    fireEvent.click(screen.getByRole('checkbox', { name: 'JP-1' }))
    fireEvent.click(screen.getByRole('button', { name: '创建 1 条报价（每个节点一条）' }))
    const results = await screen.findByLabelText('批量结果')
    expect(await screen.findByText('共 1 条：新建 1，已存在 0，失败 0，待上架 1', { selector: '.cdnca-feedback-warning .cdnca-feedback-title span' })).toBeInTheDocument()
    fireEvent.click(within(results).getByRole('button', { name: '修改后重试失败项（1）' }))
    await waitFor(() => expect(fetchMock.mock.calls.filter(([p]) => p === '/v1/admin/market/listing-batches')).toHaveLength(2))
    const retry = JSON.parse(fetchMock.mock.calls.filter(([p]) => p === '/v1/admin/market/listing-batches')[1][1]!.body as string)
    expect(retry).toMatchObject({ node_ids: [ids[2]], publish: true })
  })

  it('B21/B23: reads every node page by cursor and loads the visible rows in one metrics batch', async () => {
    const many = Array.from({ length: 205 }, (_, i) => {
      const id = `018f0000-0000-7000-8000-${(i + 1).toString(16).padStart(12, '0')}`
      return node(id, String(i + 1), `N-${i + 1}`, 'HK', '电信')
    })
    const fetchMock = market((path) => {
      if (path.startsWith('/v1/nodes?')) {
        const q = new URLSearchParams(path.slice('/v1/nodes?'.length))
        const start = q.get('cursor') ? many.findIndex((n) => n.id === q.get('cursor')) + 1 : 0
        const page = many.slice(start, start + Number(q.get('limit')))
        return json({ items: page, ...(start + page.length < many.length ? { next_cursor: page.at(-1)!.id } : {}) })
      }
      if (path.startsWith('/v1/nodes/metrics/latest?')) {
        const asked = new URLSearchParams(path.split('?')[1]).getAll('node_id')
        return json({ observed_at: '2026-10-24T00:00:00Z', items: [], not_reported_node_ids: asked })
      }
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的上架' }))
    expect(await screen.findByRole('button', { name: '全选当前筛选（205）' })).toBeInTheDocument()
    await waitFor(() => expect(fetchMock.mock.calls.filter(([p]) => String(p).startsWith('/v1/nodes/metrics/latest?'))).toHaveLength(1))
    const latest = fetchMock.mock.calls.find(([p]) => String(p).startsWith('/v1/nodes/metrics/latest?'))![0] as string
    expect(new URLSearchParams(latest.split('?')[1]).getAll('node_id')).toHaveLength(10)
    expect(fetchMock.mock.calls.some(([p]) => String(p).includes('/metrics/history'))).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: '全选当前筛选（205）' }))
    expect(screen.getByText('已选 205 个节点，将创建 205 条报价')).toBeInTheDocument()
  })

  it('reports an existing item instead of listing it twice', async () => {
    vi.stubGlobal('fetch', market((path, init) => path === '/v1/admin/market/listing-batches'
      ? json({ items: [{ node_ids: JSON.parse(init!.body as string).node_ids, status: 'existing', offer_id: 'o', removed_plugins: [] }] }) : undefined))
    await openSell()
    fireEvent.change(screen.getByLabelText('名称'), { target: { value: '包天' } })
    fireEvent.click(screen.getByRole('checkbox', { name: 'JP-1' }))
    fireEvent.click(screen.getByRole('button', { name: '创建 1 条报价（每个节点一条）' }))
    expect(await screen.findByText('已存在（未重复创建）')).toBeInTheDocument()
  })

  it('saves the form as a template and applies it back', async () => {
    const saved = { id: 't1', name: '香港包天', revision: 1, updated_at: '2026-10-22T00:00:00Z',
      body: templateBody({ ...defaultValues, name: '香港', price: 1.8 }, defaultRows().map((r) => r.metric === 'qps' ? { ...r, enabled: true, value: 900 } : r)) }
    const fetchMock = market((path, init) => {
      if (path === '/v1/admin/market/listing-templates' && init?.method === 'POST') return json(saved, 201)
      if (path === '/v1/admin/market/listing-templates') return json({ items: [saved] })
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    await openSell()
    fireEvent.change(screen.getByLabelText('名称'), { target: { value: '香港' } })
    fireEvent.click(screen.getByRole('button', { name: '保存为模板' }))
    fireEvent.change(await screen.findByLabelText('模板名称'), { target: { value: '香港包天' } })
    fireEvent.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/listing-templates', expect.objectContaining({ method: 'POST' })))
    const posted = JSON.parse(fetchMock.mock.calls.find(([p, i]) => p === '/v1/admin/market/listing-templates' && i?.method === 'POST')![1]!.body as string)
    expect(posted).toMatchObject({ name: '香港包天', body: { values: { name: '香港' } } })
    // The saved template is the current one; reset the form, then apply it again.
    await waitFor(() => expect(screen.getByRole('button', { name: '删除模板' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('日价（元 / 天）'), { target: { value: '0.05' } })
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '套用模板' }))
    fireEvent.click(await screen.findByText('香港包天', { selector: '.ant-select-item-option-content' }))
    expect(await screen.findByDisplayValue(/^1\.80?$/)).toBeInTheDocument()
    expect(within(screen.getByRole('table', { name: '限额' })).getByLabelText('上限 QPS')).toHaveValue('900')
  })
})

describe('batch operations on own offers', () => {
  const mine = [offer({ id: 'o1', name: 'HK-1 包天' }), offer({ id: 'o2', name: 'HK-2 包天', components: [{ kind: 'own_pool', node_pool_ref: 'pool-2' }] })]

  it('reprices each selected offer through its terms', async () => {
    const fetchMock = market((path) => {
      if (path === '/v1/admin/market/offers?mine=1') return json({ items: mine })
      if (path.endsWith('/terms')) return path.includes('o2') ? json({ error: 'conflict' }, 409) : json(mine[0])
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的上架' }))
    fireEvent.click(await screen.findByRole('checkbox', { name: 'HK-1 包天' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'HK-2 包天' }))
    fireEvent.click(screen.getByRole('button', { name: '批量调价' }))
    fireEvent.change(await screen.findByRole('spinbutton', { name: '按百分比调整（%）' }), { target: { value: '20' } })
    fireEvent.click(screen.getByRole('button', { name: '执行' }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText('1.00 → 1.20')).toBeInTheDocument()
    expect(within(dialog).getByText('已被修改，请刷新后重试')).toBeInTheDocument()
    const [, init] = fetchMock.mock.calls.find(([p]) => p === '/v1/admin/market/offers/o1/terms')!
    expect(JSON.parse(init!.body as string)).toEqual({ pricing: { currency: 'CNY', daily_minor: 120, min_days: 1, max_days: 30 } })
    expect((init!.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^bulk-price-/)
  })

  it('delists per offer and says when the market does not offer it yet', async () => {
    vi.stubGlobal('fetch', market((path) => {
      if (path === '/v1/admin/market/offers?mine=1') return json({ items: mine })
      if (path.endsWith('/delist')) return json({ error: 'market_feature_unavailable' }, 501)
      return undefined
    }))
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的上架' }))
    fireEvent.click(await screen.findByRole('checkbox', { name: 'HK-1 包天' }))
    fireEvent.click(screen.getByRole('button', { name: '批量下架' }))
    expect(await screen.findByText(/下架只停止新购买/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '执行' }))
    expect(await screen.findByText('市场尚未开放该操作')).toBeInTheDocument()
  })

  it('removes nodes from the supplies and reports the keep-one-online refusal per supply', async () => {
    const fetchMock = market((path) => {
      if (path === '/v1/admin/market/offers?mine=1') return json({ items: mine })
      if (path === '/v1/admin/market/supply-node-removals') return json({ items: [
        { group_id: 'pool-1', status: 'failed', removed: [], error: 'supply_keeps_online_node' },
        { group_id: 'pool-2', status: 'updated', removed: [ids[0]], revision: 3 },
      ] })
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的上架' }))
    fireEvent.click(await screen.findByRole('checkbox', { name: 'HK-1 包天' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'HK-2 包天' }))
    fireEvent.click(screen.getByRole('button', { name: '从所选报价的供给中移出节点' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '从所选报价的供给中移出节点' }))
    fireEvent.click(await screen.findByTitle('HK-1'))
    fireEvent.click(within(dialog).getByRole('button', { name: '执行' }))
    expect(await within(dialog).findByText('仍有正常订阅方，至少要保留 1 个在线可用节点')).toBeInTheDocument()
    // The run clears the table selection; the dialog keeps the offers it acted on.
    expect(within(dialog).getByText('已选 2 条报价：HK-1 包天、HK-2 包天')).toBeInTheDocument()
    const [, init] = fetchMock.mock.calls.find(([p]) => p === '/v1/admin/market/supply-node-removals')!
    expect(JSON.parse(init!.body as string)).toEqual({ group_ids: ['pool-1', 'pool-2'], node_ids: [ids[0]] })
  })

  it('renders the batch listing in English', async () => {
    await i18n.changeLanguage('en-US')
    vi.stubGlobal('fetch', market())
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: 'My listings' }))
    expect(await screen.findByText('One offer per node')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save as template' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create 0 offers (one per node)' })).toBeInTheDocument()
  })
})
