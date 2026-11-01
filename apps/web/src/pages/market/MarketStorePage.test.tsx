import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import MarketStorePage from './MarketStorePage'
import { configPath, enablePath, headlinePlan, ownedRows, publisherOf, storeState } from './marketModel'
import { marketStoreMessages } from './messages'

function json(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, text: vi.fn().mockResolvedValue(JSON.stringify(body)) } as unknown as Response
}

const paidPlan = { id: 'p-paid', plugin_id: 'r1', revision: 1, kind: 'one_time', price_minor: 9900, currency: 'CNY', trial_days: 0,
  status: 'active', active_revision: 1 }
const freePlan = { ...paidPlan, id: 'p-free', kind: 'free', price_minor: 0 }
const official = { id: '11111111-1111-4111-8111-111111111111', plugin_id: 'io.cdnca.waf-pro', namespace: 'io.cdnca', kind: 'rule_pack',
  risk_class: 'sandboxed', title: '高级 WAF', status: 'listed', publisher_kind: 'official', feature_code: 'module.waf-pro',
  latest_version: '1.0.0', price_plans: [paidPlan] }
const certified = { ...official, id: '22222222-2222-4222-8222-222222222222', plugin_id: 'acme.reports', namespace: 'acme', kind: 'ui_page',
  title: 'Acme 报表', publisher_kind: 'certified', feature_code: null, price_plans: [freePlan] }
const third = { ...official, id: '33333333-3333-4333-8333-333333333333', plugin_id: 'bob.theme', namespace: 'bob', kind: 'theme',
  title: 'Bob 主题', publisher_kind: 'third_party', feature_code: null, price_plans: [paidPlan] }
const license = (pluginID: string) => ({ id: `l-${pluginID}`, plugin_id: pluginID, installation_id: 'i', kind: 'one_time', status: 'active' })
const uiVersion = { id: 'v1', plugin_id: 'acme.reports', version: '2.1.0', status: 'published', manifest_sha256: 'a'.repeat(64),
  permissions: ['plugin.ui_page', 'sites.read'], permissions_changed: false, channel: 'stable',
  ui_page: { origin: 'https://ui.acme.example', pages: [{ id: 'r', path: '/r', mount: 'menu', menu_parent: 'monitor', role: 'admin',
    title: { 'zh-CN': '流量报表', 'en-US': 'Traffic report' } }] } }

type Fetch = (path: string, init?: RequestInit) => Promise<Response>

function routes(state: { licenses: unknown[]; library: unknown[]; modules?: string[] }, extra: Record<string, () => Response> = {}) {
  return vi.fn<Fetch>(async (path) => {
    for (const [prefix, respond] of Object.entries(extra)) if (path.startsWith(prefix)) return respond()
    if (path.startsWith('/v1/admin/market/plugins?')) return json({ items: [official, certified, third], next_cursor: null })
    if (path === `/v1/admin/market/plugins/${certified.id}`) return json({ plugin: certified, versions: [uiVersion], price_plans: [freePlan] })
    if (path.startsWith('/v1/admin/market/plugins/')) return json({ plugin: official, versions: [], price_plans: [paidPlan] })
    if (path.startsWith('/v1/admin/market/licenses')) return json({ items: state.licenses, next_cursor: null })
    if (path === '/v1/admin/market/plugin-library') return json({ items: state.library })
    if (path === '/v1/modules') return json({ status: 'valid', lease_serial: 1, modules: state.modules ?? [] })
    if (path.startsWith('/v1/admin/market/advisories')) return json({ items: [] })
    return json({ error: 'not_found' }, 404)
  })
}

const card = async (pluginID: string) => screen.findByTestId(`market-card-${pluginID}`)

beforeEach(async () => {
  await changeLocale('zh-CN')
  const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['marketplace.purchase'] })
  useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'store-token' }, admin)
})
afterEach(() => vi.unstubAllGlobals())

describe('market model', () => {
  it('derives badges, headline prices and the three-step state', () => {
    expect(publisherOf({})).toBe('third_party')
    expect(publisherOf({ publisher_kind: 'certified' })).toBe('certified')
    expect(headlinePlan([paidPlan, freePlan] as never)?.kind).toBe('free')
    expect(headlinePlan([{ ...paidPlan, status: 'retired' }] as never)).toBeNull()
    const lib = (enabled: boolean, installed = true, withdrawn = false) => [{ plugin_id: 'bob.theme', installed, enabled, withdrawn }]
    expect(storeState(third as never, [], [], [])).toBe('purchase')
    // F1：许可已取得但本主控还没有安装记录——正在同步，不提前“去启用”，也不再给“下载”。
    expect(storeState(third as never, [license('bob.theme')] as never, [], [])).toBe('distributing')
    expect(storeState(third as never, [license('bob.theme')] as never, lib(false), [])).toBe('enable')
    expect(storeState(third as never, [license('bob.theme')] as never, lib(true), [])).toBe('installed')
    expect(storeState(third as never, [], lib(false, false, true), [])).toBe('revoked')
    expect(storeState(official as never, [license('io.cdnca.waf-pro')] as never, [], [])).toBe('activating')
    expect(storeState(official as never, [license('io.cdnca.waf-pro')] as never, [], ['module.waf-pro'])).toBe('enabled')
    // 社区版没有主题管理页（只有默认主题），主题插件没有启用入口。
    expect(enablePath({ kind: 'theme', applies_to: ['user'] })).toBeNull()
    expect(enablePath({ kind: 'theme', applies_to: ['admin', 'user'] })).toBeNull()
    expect(enablePath({ kind: 'rule_pack' })).toBe('/site/rule-packs')
  })

  // 安装≠功能生效。平台主题/规则包的“已启用”只代表安装可用，不能冒充槽位已应用。
  // 官方功能码由租约授予才算“已启用”（见上面 storeState 断言）；插件安装启用不等于主题槽已应用。
  it('shows an installed theme as ready to use, never as in use, with no theme management link', async () => {
    vi.stubGlobal('fetch', routes({ licenses: [license('bob.theme')],
      library: [{ plugin_id: 'bob.theme', installed: true, enabled: true, withdrawn: false }] }))
    renderWithProviders(<MarketStorePage />)
    const themeCard = await card('bob.theme')
    expect(await within(themeCard).findByText('已安装，可使用')).toBeInTheDocument()
    expect(within(themeCard).queryByText('已启用')).toBeNull()
    expect(within(themeCard).queryByRole('link', { name: '去主题管理' })).toBeNull()
  })

  it('keeps zh-CN, en-US and pseudo locales structurally complete', () => {
    const keys = (v: unknown, prefix = ''): string[] => Object.entries(v as Record<string, unknown>).flatMap(([k, c]) =>
      typeof c === 'string' ? [`${prefix}${k}`] : keys(c, `${prefix}${k}.`)).sort()
    const zh = keys(marketStoreMessages['zh-CN'])
    expect(keys(marketStoreMessages['en-US'])).toEqual(zh)
    expect(keys(marketStoreMessages['qps-ploc'])).toEqual(zh)
    expect(marketStoreMessages['qps-ploc'].state.revoked).toMatch(/^［.+］$/)
  })
})

describe('MarketStorePage', () => {
  it('shows publisher badges, free/paid prices and the state of each plugin', async () => {
    vi.stubGlobal('fetch', routes({ licenses: [], library: [{ plugin_id: 'bob.theme', installed: true, enabled: true, withdrawn: true }] }))
    renderWithProviders(<MarketStorePage />)
    const o = await card('io.cdnca.waf-pro')
    expect(within(o).getByText('官方')).toBeInTheDocument()
    expect(within(o).getByText('收费')).toBeInTheDocument()
    expect(within(o).getByText('99.00 CNY 买断')).toBeInTheDocument()
    expect(within(o).getByRole('button', { name: '购买' })).toBeInTheDocument()
    const c = await card('acme.reports')
    expect(within(c).getByText('认证开发者')).toBeInTheDocument()
    expect(within(c).getByText('免费')).toBeInTheDocument()
    expect(within(c).getByRole('button', { name: '获取' })).toBeInTheDocument()
    // Rebound to another controller: held here before, no live licence now.
    const b = await card('bob.theme')
    expect(within(b).getByText('第三方')).toBeInTheDocument()
    expect(within(b).getAllByText('授权失效').length).toBeGreaterThan(0)
    expect(within(b).queryByRole('button', { name: '购买' })).toBeNull()
  })

  it('pays from the balance and points a held theme licence to the administrator confirmation, not enabled yet', async () => {
    const state = { licenses: [] as unknown[], library: [] as unknown[] }
    const fetchMock = routes(state, {
      '/v1/admin/market/plugin-purchases': () => { state.licenses = [license('bob.theme')]; return json(license('bob.theme'), 201) },
      '/v1/admin/market/plugin-downloads': () => json({ plugin_id: 'bob.theme', publisher_kind: 'third_party', source: 'licensed', license: license('bob.theme') }),
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<MarketStorePage />)
    fireEvent.click(within(await card('bob.theme')).getByRole('button', { name: '购买' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: '确认付款' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([p]) => p === '/v1/admin/market/plugin-downloads')).toBe(true))
    const [, init] = fetchMock.mock.calls.find(([p]) => p === '/v1/admin/market/plugin-purchases')!
    expect(JSON.parse(init!.body as string)).toEqual({ price_plan_id: 'p-paid', plan_revision: 1 })
    expect((init!.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^plugin-prepaid-/)
    const b = await card('bob.theme')
    // 报告 A：主题是实例级资源，等的是主控管理员确认，不笼统写“正在同步”；给出去“我的插件”的入口。
    expect(await within(b).findByRole('button', { name: '去我的插件确认' })).toBeInTheDocument()
    expect(within(b).queryByText('使用权已取得，正在同步')).toBeNull()
    expect(within(b).queryByRole('button', { name: '去启用' })).toBeNull()
    expect(within(b).queryByRole('button', { name: '下载' })).toBeNull()
  })

  // F1：免费“获取”只取得/重放许可；本机没有安装记录前不显示完成或“去启用”，重入后状态一致。
  it('gets a free plugin and keeps showing it as syncing after a remount, with no 去启用 before it is installed', async () => {
    const state = { licenses: [] as unknown[], library: [] as unknown[] }
    const fetchMock = routes(state, {
      '/v1/admin/market/plugin-downloads': () => {
        state.licenses = [license('acme.reports')]
        return json({ plugin_id: 'acme.reports', publisher_kind: 'certified', source: 'free', license: license('acme.reports') })
      },
    })
    vi.stubGlobal('fetch', fetchMock)
    const first = renderWithProviders(<MarketStorePage />)
    fireEvent.click(within(await card('acme.reports')).getByRole('button', { name: '获取' }))
    expect(await screen.findByText('已取得使用权，正在同步到本主控')).toBeInTheDocument()
    expect(await within(await card('acme.reports')).findByText('使用权已取得，正在同步')).toBeInTheDocument()
    expect(screen.queryByText('下载完成')).toBeNull()
    expect(within(await card('acme.reports')).queryByText('去启用')).toBeNull()
    first.unmount()

    renderWithProviders(<MarketStorePage />)
    expect(await within(await card('acme.reports')).findByText('使用权已取得，正在同步')).toBeInTheDocument()
    expect(within(await card('acme.reports')).queryByRole('button', { name: '获取' })).toBeNull()
  })

  it('gives an installed theme no link to the removed theme management page', async () => {
    const userTheme = { ...third, applies_to: ['user'] }
    vi.stubGlobal('fetch', routes({ licenses: [license('bob.theme')], library: [{ plugin_id: 'bob.theme', installed: true, enabled: false, withdrawn: false }] }, {
      '/v1/admin/market/plugins?': () => json({ items: [userTheme], next_cursor: null }),
    }))
    renderWithProviders(<MarketStorePage />)
    expect(await within(await card('bob.theme')).findByText('已购买，待你确认')).toBeInTheDocument()
    expect(within(await card('bob.theme')).queryByRole('link', { name: '去启用' })).toBeNull()
  })

  // market-buy-idem: a lost answer keeps the dialog on "check result", which
  // replays the same Idempotency-Key instead of charging the balance again.
  it('replays an unknown balance purchase with the same key', async () => {
    const state = { licenses: [] as unknown[], library: [] as unknown[] }
    let answer = 0
    const fetchMock = routes(state, {
      '/v1/admin/market/plugin-purchases': () => {
        answer += 1
        if (answer === 1) return json({ error: 'internal' }, 500)
        state.licenses = [license('bob.theme')]
        return json(license('bob.theme'), 201)
      },
      '/v1/admin/market/plugin-downloads': () => json({ plugin_id: 'bob.theme', publisher_kind: 'third_party', source: 'licensed', license: license('bob.theme') }),
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<MarketStorePage />)
    fireEvent.click(within(await card('bob.theme')).getByRole('button', { name: '购买' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: '确认付款' }))
    expect(await within(dialog).findByText(/不会重复扣款/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '查询结果' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([p]) => p === '/v1/admin/market/plugin-downloads')).toBe(true))
    const keys = fetchMock.mock.calls.filter(([p]) => p === '/v1/admin/market/plugin-purchases')
      .map(([, i]) => (i!.headers as Record<string, string>)['Idempotency-Key'])
    expect(keys).toHaveLength(2)
    expect(keys[1]).toBe(keys[0])
  })

  // Codex 复查卡 59：只有价格修订变了（plan_revision_changed / price_changed）才提示“价格刚改过”，
  // 其他 409 各说各的原因。
  it.each([
    ['plan_revision_changed', '价格刚刚改过，请重新确认'],
    ['price_changed', '价格刚刚改过，请重新确认'],
    ['trial_used', '已经试用过这个插件，不能再次试用'],
    ['not_on_sale', '这个价格已停售，请刷新后重新选择'],
    ['idempotency_conflict', '请求标识冲突，请重新确认付款'],
    ['request_in_progress', '上一次购买还在处理中，请稍后点“查询结果”'],
    ['conflict', '操作失败：conflict'],
  ])('names the purchase 409 %s instead of always saying the price changed', async (code, text) => {
    const state = { licenses: [] as unknown[], library: [] as unknown[] }
    vi.stubGlobal('fetch', routes(state, { '/v1/admin/market/plugin-purchases': () => json({ error: code }, 409) }))
    renderWithProviders(<MarketStorePage />)
    fireEvent.click(within(await card('bob.theme')).getByRole('button', { name: '购买' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: '确认付款' }))
    expect(await screen.findByText(text)).toBeInTheDocument()
    if (!/价格刚刚改过/.test(text)) expect(screen.queryByText('价格刚刚改过，请重新确认')).toBeNull()
    // still running: the same key is kept for "check result"
    if (code === 'request_in_progress') expect(within(dialog).getByRole('button', { name: '查询结果' })).toBeInTheDocument()
  })

  it('falls back to an in-page QR cashier when the balance is short and shows 下载 once paid', async () => {
    let polls = 0
    const order = { id: 'o1', order_no: 77, market: 'plugin', kind: 'purchase', amount_minor: 9900, currency: 'CNY',
      settlement_mode: 'escrow', status: 'awaiting_payment', created_at: '2026-10-19T00:00:00Z' }
    const state = { licenses: [] as unknown[], library: [] as unknown[] }
    const fetchMock = routes(state, {
      '/v1/admin/market/plugin-purchases': () => json({ error: 'insufficient_balance' }, 402),
      '/v1/admin/market/orders/': () => {
        if (++polls > 1) state.licenses = [license('bob.theme')]
        return json({ ...order, status: polls > 1 ? 'fulfilled' : 'awaiting_payment' })
      },
      '/v1/admin/market/orders': () => json({ order, checkout_url: 'https://pay.cdnca.com/qr/o1' }, 201),
      '/v1/admin/market/plugin-downloads': () => json({ plugin_id: 'bob.theme', source: 'licensed', license: license('bob.theme') }),
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<MarketStorePage />)
    fireEvent.click(within(await card('bob.theme')).getByRole('button', { name: '购买' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: '确认付款' }))
    expect(await within(dialog).findByText('余额不足，已切换为扫码支付')).toBeInTheDocument()
    expect(await within(dialog).findByText('扫描二维码付款')).toBeInTheDocument()
    const [, init] = fetchMock.mock.calls.find(([p]) => p === '/v1/admin/market/orders')!
    expect(JSON.parse(init!.body as string)).toEqual({ market: 'plugin', price_plan_id: 'p-paid', plan_revision: 1 })
    await waitFor(() => expect(fetchMock.mock.calls.some(([p]) => p === '/v1/admin/market/plugin-downloads')).toBe(true), { timeout: 8000 })
  }, 15000)

  it('details versions, permissions, publisher and the ui_page menus with their origin', async () => {
    vi.stubGlobal('fetch', routes({ licenses: [], library: [] }))
    renderWithProviders(<MarketStorePage />)
    fireEvent.click(within(await card('acme.reports')).getByRole('button', { name: 'Acme 报表' }))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('流量报表（菜单）')).toBeInTheDocument()
    expect(within(drawer).getAllByText(/https:\/\/ui\.acme\.example/).length).toBeGreaterThan(0)
    expect(within(drawer).getByText('sites.read')).toBeInTheDocument()
    expect(within(drawer).getByText('认证开发者 · acme')).toBeInTheDocument()
    expect(within(drawer).getAllByText('2.1.0').length).toBeGreaterThan(0)
  })

  // store-pricing (user 10-31): the market prices buyer reads for this controller's edition (market 068); the card and
  // the detail show that price only — a community controller sees its monthly price, never the commercial 限免.
  it('shows the price of this controller edition and names the edition in the detail', async () => {
    const community = { ...paidPlan, kind: 'subscription', interval: 'month', price_minor: 1990, edition: 'community' }
    vi.stubGlobal('fetch', routes({ licenses: [], library: [] }, {
      '/v1/admin/market/plugins?': () => json({ items: [{ ...official, price_plans: [community] }], next_cursor: null }),
      [`/v1/admin/market/plugins/${official.id}`]: () => json({ plugin: official, versions: [], price_plans: [community] }),
    }))
    renderWithProviders(<MarketStorePage />)
    const o = await card('io.cdnca.waf-pro')
    expect(within(o).getByText('19.90 CNY / 月')).toBeInTheDocument()
    expect(within(o).queryByText(/限免/)).toBeNull()
    fireEvent.click(within(o).getByRole('button', { name: official.title }))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('按本主控的社区版价格')).toBeInTheDocument()
  })

  it('lets a browse-only administrator look but not buy', async () => {
    const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['marketplace.browse'] })
    useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'store-token' }, admin)
    vi.stubGlobal('fetch', routes({ licenses: [], library: [] }))
    renderWithProviders(<MarketStorePage />)
    expect(within(await card('bob.theme')).getByRole('button', { name: '购买' })).toBeDisabled()
  })

  it('opens the purchase dialog when the download answers 402 purchase_required', async () => {
    // The free plan was retired after the list loaded: the market refuses the free licence with 402.
    const fetchMock = routes({ licenses: [], library: [] }, {
      '/v1/admin/market/plugin-downloads': () => json({ error: 'purchase_required' }, 402),
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<MarketStorePage />)
    fireEvent.click(within(await card('acme.reports')).getByRole('button', { name: '获取' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('购买 Acme 报表')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '确认付款' })).toBeEnabled()
  })

  it('narrows the store to the entry that unlocks ?feature= and offers to show everything again', async () => {
    vi.stubGlobal('fetch', routes({ licenses: [], library: [] }))
    renderWithProviders(<MarketStorePage />, ['/sys/plugin-store?feature=module.waf-pro'])
    expect(await card('io.cdnca.waf-pro')).toBeInTheDocument()
    expect(screen.queryByTestId('market-card-bob.theme')).toBeNull()
    expect(screen.getByText('下面是解锁 module.waf-pro 的插件：购买后授权会绑定到本主控。')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '查看全部插件' }))
    expect(await card('bob.theme')).toBeInTheDocument()
  })

  it('passes ?kind=theme&applies_to= from a theme slot through to the market query', async () => {
    const fetchMock = routes({ licenses: [], library: [] })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<MarketStorePage />, ['/sys/plugin-store?kind=theme&applies_to=site'])
    expect(await card('bob.theme')).toBeInTheDocument()
    const list = fetchMock.mock.calls.map(([path]) => path).find((path) => path.startsWith('/v1/admin/market/plugins?'))!
    expect(new URLSearchParams(list.split('?')[1]).get('kind')).toBe('theme')
    expect(new URLSearchParams(list.split('?')[1]).get('applies_to')).toBe('site')
  })

  it('ignores applies_to without kind=theme and unknown slots', async () => {
    const fetchMock = routes({ licenses: [], library: [] })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<MarketStorePage />, ['/sys/plugin-store?kind=theme&applies_to=admin'])
    expect(await card('bob.theme')).toBeInTheDocument()
    const list = fetchMock.mock.calls.map(([path]) => path).find((path) => path.startsWith('/v1/admin/market/plugins?'))!
    expect(list).not.toContain('applies_to')
  })

  it('says so when no entry unlocks the requested feature', async () => {
    vi.stubGlobal('fetch', routes({ licenses: [], library: [] }))
    renderWithProviders(<MarketStorePage />, ['/sys/plugin-store?feature=module.unknown'])
    expect(await screen.findByText('市场里没有解锁 module.unknown 的插件条目。')).toBeInTheDocument()
    expect(screen.queryByTestId('market-card-bob.theme')).toBeNull()
  })

  it('pages the store by next_cursor past the first 50 entries and restarts on a new filter', async () => {
    const entry = (n: number) => ({ ...third, id: `p-${n}`, plugin_id: `x.p${n}`, title: `插件 ${n}` })
    const fetchMock = routes({ licenses: [], library: [] }, {
      '/v1/admin/market/plugins?': () => {
        const path = String(fetchMock.mock.calls.at(-1)?.[0])
        const cursor = Number(new URLSearchParams(path.split('?')[1]).get('cursor') ?? 0)
        const end = Math.min(cursor + 50, 120)
        return json({ items: Array.from({ length: end - cursor }, (_, i) => entry(cursor + i + 1)), next_cursor: end < 120 ? String(end) : null })
      },
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<MarketStorePage />)
    await card('x.p50')
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    await card('x.p100')
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    await card('x.p120')
    expect(screen.getByRole('button', { name: '下一页' })).toBeDisabled()
    expect(screen.getByText('第 3 页，已加载 120 条')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('搜索插件名称或 ID'), { target: { value: 'waf' } })
    fireEvent.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(String(fetchMock.mock.calls.at(-1)?.[0])).toBe('/v1/admin/market/plugins?q=waf&limit=50'))
    const sent = fetchMock.mock.calls.map(([p]) => String(p)).filter((p) => p.startsWith('/v1/admin/market/plugins?'))
    expect(sent.slice(0, 3)).toEqual(['/v1/admin/market/plugins?limit=50', '/v1/admin/market/plugins?cursor=50&limit=50',
      '/v1/admin/market/plugins?cursor=100&limit=50'])
  })

  it('renders the English copy', async () => {
    await changeLocale('en-US')
    vi.stubGlobal('fetch', routes({ licenses: [], library: [] }))
    renderWithProviders(<MarketStorePage />)
    expect(within(await card('io.cdnca.waf-pro')).getByText('Official')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Plugin store' })).toBeInTheDocument()
  })
})

describe('market runtime off (W3)', () => {
  it('shows only the not-connected notice and sends no tab requests', async () => {
    const fetchMock = vi.fn<Fetch>(async () =>
      ({ ok: false, status: 404, text: vi.fn().mockResolvedValue('404 page not found\n') }) as unknown as Response)
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<MarketStorePage />)
    expect(await screen.findByText(/本机尚未接入市场/)).toBeInTheDocument()
    expect(screen.queryByRole('tab')).not.toBeInTheDocument()
    expect(fetchMock.mock.calls.map(([path]) => path)).toEqual(['/v1/admin/market/member'])
  })

  // Codex 复查卡 47：没有“在主控配置中开启”的界面开关；提示说明由服务器管理员配置部署，修好后可重新检测。
  it('points to the server deployment instead of a non-existent switch and re-checks on demand', async () => {
    let mounted = false
    const fetchMock = vi.fn<Fetch>(async (path) => {
      if (mounted) return routes({ licenses: [], library: [] })(path)
      return ({ ok: false, status: 404, text: vi.fn().mockResolvedValue('404 page not found\n') }) as unknown as Response
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<MarketStorePage />)
    const notice = await screen.findByText(/本机尚未接入市场/)
    expect(notice.textContent).not.toMatch(/开启市场运行时/)
    expect(notice.textContent).toMatch(/服务器管理员/)
    mounted = true
    fireEvent.click(screen.getByRole('button', { name: '重新检测' }))
    expect(await screen.findByRole('tab', { name: '浏览' })).toBeInTheDocument()
  })
})

// 已购显示中文名；我的插件列出本主控已拥有的全部插件（官方模块也算），可配置的给入口。
describe('我的插件与已购名称', () => {
  const autodefense = { ...official, id: '44444444-4444-4444-8444-444444444444', plugin_id: 'io.cdnca.autodefense', kind: 'module',
    title: '智能自动防御', feature_code: 'module.autodefense', price_plans: [freePlan] }
  const migrate = { ...autodefense, id: '55555555-5555-4555-8555-555555555555', plugin_id: 'io.cdnca.migrate-import', title: '迁移导入',
    feature_code: 'module.migrate.import' }
  const catalogRoutes = (state: { licenses: unknown[]; library: unknown[]; modules?: string[] }) => routes(state, {
    '/v1/admin/market/plugins?': () => json({ items: [official, certified, third, autodefense, migrate], next_cursor: null }),
    '/v1/plugin-ui/pages': () => json({ items: [] }),
    // fetchGrantedModules 读 response.json()，通用 json() 夹具只有 text()。
    '/v1/modules': () => ({ ok: true, status: 200, json: async () => ({ status: 'valid', lease_serial: 1, modules: state.modules ?? [] }) }) as unknown as Response,
  })

  it('derives owned rows and the configure page from the feature code, the ui page or the kind', () => {
    // 社区版没有自动防御、迁移导入与攻击升级页面；有页面的官方功能码（CRS 档位）落到对应页。
    expect(configPath({ ...autodefense, feature_code: 'pack.crs' } as never, [])).toBe('/site/waf-rule')
    expect(configPath(certified as never, [{ plugin_id: 'acme.reports', page_id: 'r', mount: 'menu', role: 'admin' }])).toBe('/plugin-ui/acme.reports/r')
    expect(configPath(third as never, [])).toBeNull()
    expect(configPath({ ...autodefense, feature_code: 'module.unknown' } as never, [])).toBeNull()
    const catalog = new Map([autodefense, third].map((p) => [p.plugin_id, p as never]))
    const rows = ownedRows([license('io.cdnca.autodefense'), license('bob.theme'), { ...license('gone.x'), status: 'expired' }] as never,
      [{ plugin_id: 'old.y', installed: true, enabled: false, withdrawn: true }], ['module.autodefense'], catalog, () => '/x')
    expect(rows.map((r) => [r.pluginID, r.state, r.path])).toEqual([
      ['io.cdnca.autodefense', 'enabled', '/x'], ['bob.theme', 'pendingConfirm', null], ['old.y', 'revoked', null]])
  })

  it('lists official modules this controller owns under 我的插件 with their names and a configure link', async () => {
    const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['custom'],
      permissions: ['marketplace.purchase', 'platform.admin', 'plugin_installations.platform.read'] })
    useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'store-token' }, admin)
    vi.stubGlobal('fetch', catalogRoutes({ licenses: [license('io.cdnca.autodefense'), license('io.cdnca.migrate-import')], library: [],
      modules: ['module.autodefense', 'module.migrate.import'] }))
    renderWithProviders(<MarketStorePage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的插件' }))
    const owned = (await screen.findByRole('heading', { name: '本主控已拥有的插件' })).closest('section')!
    const row = (await within(owned).findByText('智能自动防御')).closest('tr')!
    expect(within(row).getByText('io.cdnca.autodefense')).toBeInTheDocument()
    expect(await within(row).findByText('已启用')).toBeInTheDocument()
    // 社区版没有自动防御与迁移导入页面，已拥有但不给去配置入口。
    expect(within(row).queryByRole('link', { name: '去配置' })).toBeNull()
    expect(within(within(owned).getByText('迁移导入').closest('tr')!).queryByRole('link', { name: '去配置' })).toBeNull()
    expect(within(owned).queryByText('本主控还没有插件')).toBeNull()
    // 主题与规则包的安装确认仍在，作为其中一节。
    expect(screen.getByRole('heading', { name: '主题与规则包安装记录' })).toBeInTheDocument()
  })

  it('shows 我的插件 to a buyer without platform install rights and says plainly when nothing is owned', async () => {
    vi.stubGlobal('fetch', catalogRoutes({ licenses: [], library: [] }))
    renderWithProviders(<MarketStorePage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的插件' }))
    expect(await screen.findByText('本主控还没有插件')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '主题与规则包安装记录' })).toBeNull()
  })

  it('names purchased plugins from the catalog and keeps the ID as secondary text', async () => {
    vi.stubGlobal('fetch', catalogRoutes({ licenses: [license('io.cdnca.autodefense'), license('vanished.plugin')], library: [] }))
    renderWithProviders(<MarketStorePage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购' }))
    const row = (await screen.findByText('智能自动防御')).closest('tr')!
    expect(within(row).getByText('io.cdnca.autodefense')).toBeInTheDocument()
    // 目录里已没有的插件回退为 plugin_id，只显示一次。
    expect(screen.getAllByText('vanished.plugin')).toHaveLength(1)
  })

  // 名称只按已购/已装的插件 ID 批量取（不再读 200 条目录），英文界面显示英文名，没有则回退中文。
  it('looks names up by the owned plugin ids and shows the English name in en-US', async () => {
    await changeLocale('en-US')
    const fetchMock = routes({ licenses: [license('io.cdnca.autodefense'), license('io.cdnca.migrate-import')], library: [] }, {
      '/v1/admin/market/plugins?plugin_ids=': () => json({ items: [{ ...autodefense, title_en: 'Smart Auto Defense' }, migrate], next_cursor: null }),
      '/v1/admin/market/plugins?': () => json({ items: [], next_cursor: null }),
      '/v1/plugin-ui/pages': () => json({ items: [] }),
      '/v1/modules': () => ({ ok: true, status: 200, json: async () => ({ status: 'valid', lease_serial: 1, modules: [] }) }) as unknown as Response,
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<MarketStorePage />)
    fireEvent.click(await screen.findByRole('tab', { name: 'Purchased' }))
    expect(await screen.findByText('Smart Auto Defense')).toBeInTheDocument()
    // 没有英文名的回退中文。
    expect(screen.getByText('迁移导入')).toBeInTheDocument()
    const sent = fetchMock.mock.calls.map(([path]) => String(path)).filter((path) => path.includes('plugin_ids='))
    expect(sent).toContain('/v1/admin/market/plugins?plugin_ids=io.cdnca.autodefense%2Cio.cdnca.migrate-import')
    expect(fetchMock.mock.calls.some(([path]) => String(path).includes('limit=200'))).toBe(false)
  })
})
