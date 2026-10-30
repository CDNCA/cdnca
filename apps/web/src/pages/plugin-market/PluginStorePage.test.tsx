import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { marketPluginKinds } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { pluginStoreMessages } from '../../i18n/pluginStore'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import PluginStorePage from './PluginStorePage'
import { highRiskPermission, safeLink } from './pluginStoreModel'

function json(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, text: vi.fn().mockResolvedValue(JSON.stringify(body)) } as unknown as Response
}

const plugin = { id: '11111111-1111-4111-8111-111111111111', plugin_id: 'acme.waf', namespace: 'acme', kind: 'rule_pack',
  risk_class: 'sandboxed', title: 'Acme WAF', summary: '规则包', status: 'listed', latest_version: '1.4.2', installs: 12,
  homepage: 'javascript:alert(1)', support_url: 'https://acme.example/support' }
// A price change under review (revision 4) while revision 3 keeps selling.
const plan = { id: '22222222-2222-4222-8222-222222222222', plugin_id: plugin.id, revision: 4, kind: 'subscription', interval: 'month',
  price_minor: 9900, currency: 'CNY', trial_days: 7, status: 'pending_review', active_revision: 3 }
const version = { id: '33333333-3333-4333-8333-333333333333', plugin_id: 'acme.waf', version: '1.4.2', status: 'published',
  manifest_sha256: 'a'.repeat(64), permissions: ['sites.read', 'waf.rules.write'], permissions_changed: true,
  compat: { control_api: '>=1.0.30' }, changelog_md: '修复 <script>alert(1)</script> 绕过', channel: 'stable' }
const advisory = { id: '44444444-4444-4444-8444-444444444444', plugin_id: 'acme.waf', affected_versions: '<1.4.2', fixed_version: '1.4.2',
  severity: 'high', action: 'disable', title: '规则绕过', body: '升级到 1.4.2', published_at: '2026-10-16T00:00:00Z', acknowledgement: null }
const order = { id: '55555555-5555-4555-8555-555555555555', order_no: 1001, market: 'plugin', kind: 'purchase', amount_minor: 9900,
  currency: 'CNY', settlement_mode: 'escrow', status: 'awaiting_payment', created_at: '2026-10-16T00:00:00Z' }

type Fetch = (path: string, init?: RequestInit) => Promise<Response>

function setAdmin(permissions: string[]) {
  const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions })
  useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'store-token' }, admin)
}

function routes(extra: Record<string, () => Response> = {}): ReturnType<typeof vi.fn<Fetch>> {
  return vi.fn<Fetch>(async (path) => {
    for (const [prefix, respond] of Object.entries(extra)) if (path.startsWith(prefix)) return respond()
    if (path.startsWith('/v1/admin/market/plugins?')) return json({ items: [plugin], next_cursor: null })
    if (path === `/v1/admin/market/plugins/${plugin.id}`) return json({ plugin, versions: [version], price_plans: [plan,
      { ...plan, id: 'retired', status: 'retired' }, { ...plan, id: 'first-review', status: 'pending_review', active_revision: null }] })
    if (path.startsWith('/v1/admin/market/advisories')) return json({ items: [advisory] })
    if (path.startsWith('/v1/admin/market/licenses')) return json({ items: [], next_cursor: null })
    return json({ error: 'not_found' }, 404)
  })
}

beforeEach(async () => {
  await changeLocale('zh-CN')
  setAdmin(['marketplace.purchase'])
})
afterEach(() => vi.unstubAllGlobals())

describe('plugin store model', () => {
  it('flags risky permissions and drops unsafe links', () => {
    expect(highRiskPermission({ risk_class: 'sandboxed' }, 'waf.rules.write')).toBe(true)
    expect(highRiskPermission({ risk_class: 'sandboxed' }, 'sites.read')).toBe(false)
    expect(highRiskPermission({ risk_class: 'privileged' }, 'sites.read')).toBe(true)
    expect(safeLink('javascript:alert(1)')).toBeNull()
    expect(safeLink('http://a.example')).toBeNull()
    expect(safeLink('https://u:p@a.example')).toBeNull()
    expect(safeLink('https://a.example/x')).toBe('https://a.example/x')
  })

  it('lists the eight market 030 kinds from the shared kinds.json, each with a label', () => {
    expect(marketPluginKinds).toEqual(['module', 'rule_pack', 'dataset', 'engine_module', 'theme', 'provider', 'external_service', 'ui_page'])
    for (const kind of marketPluginKinds) {
      expect(pluginStoreMessages['zh-CN'].kinds[kind]).toBeTruthy()
      expect(pluginStoreMessages['en-US'].kinds[kind]).toBeTruthy()
    }
  })

  it('keeps every locale structurally complete', () => {
    const keys = (tree: object, prefix = ''): string[] => Object.entries(tree).flatMap(([k, v]) =>
      typeof v === 'string' ? [`${prefix}${k}`] : keys(v as object, `${prefix}${k}.`))
    expect(keys(pluginStoreMessages['en-US'])).toEqual(keys(pluginStoreMessages['zh-CN']))
    expect(keys(pluginStoreMessages['qps-ploc'])).toEqual(keys(pluginStoreMessages['zh-CN']))
  })
})

describe('PluginStorePage', () => {
  it('browses with filters, marks plugins with open advisories and shows permissions and history', async () => {
    const fetchMock = routes()
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<PluginStorePage />)
    expect(await screen.findByText('Acme WAF')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/plugins?limit=50', expect.anything())
    expect(screen.getByText('1 条安全公告待处理')).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('搜索插件名称、ID 或简介'), { target: { value: ' waf ' } })
    fireEvent.click(screen.getByRole('checkbox', { name: '显示不兼容本主控的插件' }))
    fireEvent.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/plugins?q=waf&all_versions=1&limit=50', expect.anything()))

    fireEvent.click(await screen.findByText('Acme WAF'))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('waf.rules.write')).toBeInTheDocument()
    expect(within(drawer).getByText('waf.rules.write').closest('.ant-tag')).toHaveClass('ant-tag-red')
    expect(within(drawer).getByText('sites.read').closest('.ant-tag')).not.toHaveClass('ant-tag-red')
    expect(within(drawer).getAllByText('本版本权限有变化').length).toBeGreaterThan(0)
    // Changelog is plain text, never HTML.
    expect(within(drawer).getByText('修复 <script>alert(1)</script> 绕过')).toBeInTheDocument()
    expect(within(drawer).queryByRole('link', { name: '主页' })).not.toBeInTheDocument()
    expect(within(drawer).getByRole('link', { name: '支持' })).toHaveAttribute('href', 'https://acme.example/support')
    expect(within(drawer).getByText('可试用 7 天')).toBeInTheDocument()
    expect(within(drawer).getAllByRole('button', { name: '购买' })).toHaveLength(1)
  })

  it('buys through the portal checkout and follows the order until the install candidate exists', async () => {
    const open = vi.fn()
    vi.stubGlobal('open', open)
    let polls = 0
    const fetchMock = routes({
      '/v1/admin/market/orders/': () => json({ ...order, status: ++polls > 1 ? 'fulfilled' : 'paid' }),
      '/v1/admin/market/orders': () => json({ order, checkout_url: 'https://portal.example/checkout/p1' }, 201),
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<PluginStorePage />)
    fireEvent.click(await screen.findByText('Acme WAF'))
    const drawer = await screen.findByRole('dialog')
    fireEvent.click(await within(drawer).findByRole('button', { name: '购买' }))
    await waitFor(() => expect(open).toHaveBeenCalledWith('https://portal.example/checkout/p1', '_blank', 'noopener,noreferrer'))
    const [, init] = fetchMock.mock.calls.find(([path]) => path === '/v1/admin/market/orders')!
    expect(JSON.parse(init!.body as string)).toEqual({ market: 'plugin', price_plan_id: plan.id, plan_revision: 3 })
    expect((init!.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^plugin-order-/)
    expect(await within(drawer).findByText(/订单 1001/)).toBeInTheDocument()
  })

  it('pays from the market prepaid balance and explains an insufficient balance', async () => {
    let attempt = 0
    const fetchMock = routes({
      '/v1/admin/market/plugin-purchases': () => ++attempt === 1 ? json({ error: 'insufficient_balance' }, 402)
        : json({ id: 'l', plugin_id: 'acme.waf', installation_id: 'i', kind: 'subscription', status: 'active' }, 201),
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<PluginStorePage />)
    fireEvent.click(await screen.findByText('Acme WAF'))
    const drawer = await screen.findByRole('dialog')
    fireEvent.click(await within(drawer).findByRole('button', { name: '用市场余额支付' }))
    expect(await screen.findByText(/市场预付余额不足：可在“节点市场 → 收款与余额”充值/)).toBeInTheDocument()
    fireEvent.click(within(drawer).getByRole('button', { name: '用市场余额支付' }))
    expect(await screen.findByText(/已用市场余额付款/)).toBeInTheDocument()
    const calls = fetchMock.mock.calls.filter(([path]) => path === '/v1/admin/market/plugin-purchases')
    expect(calls).toHaveLength(2)
    expect(JSON.parse(calls[0][1]!.body as string)).toEqual({ price_plan_id: plan.id, plan_revision: 3 })
    const keys = calls.map(([, init]) => (init!.headers as Record<string, string>)['Idempotency-Key'])
    expect(keys[0]).toMatch(/^plugin-prepaid-/)
    expect(keys[0]).not.toBe(keys[1])
  })

  it('refuses to open a non-https checkout and reloads the plan on a price change', async () => {
    const open = vi.fn()
    vi.stubGlobal('open', open)
    let attempt = 0
    const fetchMock = routes({
      '/v1/admin/market/orders': () => ++attempt === 1 ? json({ error: 'price_changed' }, 409)
        : json({ order, checkout_url: 'javascript:alert(1)' }, 201),
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<PluginStorePage />)
    fireEvent.click(await screen.findByText('Acme WAF'))
    const drawer = await screen.findByRole('dialog')
    fireEvent.click(await within(drawer).findByRole('button', { name: '试用' }))
    expect(await screen.findByText('价格刚刚改过，已刷新，请重新确认')).toBeInTheDocument()
    const trialBody = JSON.parse(fetchMock.mock.calls.find(([path]) => path === '/v1/admin/market/orders')![1]!.body as string)
    expect(trialBody.trial).toBe(true)
    fireEvent.click(within(drawer).getByRole('button', { name: '购买' }))
    expect(await screen.findByText('收银台地址不安全，已拒绝打开')).toBeInTheDocument()
    expect(open).not.toHaveBeenCalled()
  })

  it('lets a browse-only administrator look but not buy or acknowledge', async () => {
    setAdmin(['marketplace.browse'])
    vi.stubGlobal('fetch', routes())
    renderWithProviders(<PluginStorePage />)
    fireEvent.click(await screen.findByText('Acme WAF'))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('waf.rules.write')).toBeInTheDocument()
    expect(within(drawer).queryByRole('button', { name: '购买' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: /安全公告/ }))
    expect(await screen.findByText('规则绕过')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '我已处理' })).not.toBeInTheDocument()
  })

  it('cancels a subscription licence and opens an order dispute', async () => {
    const licence = { id: '66666666-6666-4666-8666-666666666666', plugin_id: 'acme.waf', plan_id: plan.id, plan_revision: 3,
      installation_id: '77777777-7777-4777-8777-777777777777', kind: 'subscription', status: 'active', cancel_at_period_end: false,
      current_period_end: '2026-11-16T00:00:00Z', order_id: order.id }
    const fetchMock = routes({
      [`/v1/admin/market/licenses/${licence.id}/cancel`]: () => json({ ...licence, cancel_at_period_end: true }),
      '/v1/admin/market/licenses': () => json({ items: [licence], next_cursor: null }),
      '/v1/admin/market/disputes': () => json({ id: 'd', subject_kind: 'order', subject_id: order.id, state: 'awaiting_seller', amount_minor: 9900, reason_code: 'not_working' }, 201),
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<PluginStorePage />)
    fireEvent.click(await screen.findByRole('tab', { name: '许可证' }))
    expect(await screen.findByText('有效')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '退订' }))
    fireEvent.click(await screen.findByRole('button', { name: 'OK' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/admin/market/licenses/${licence.id}/cancel`, expect.objectContaining({ method: 'POST' })))
    const cancelInit = fetchMock.mock.calls.find(([path]) => path.endsWith('/cancel'))![1]!
    expect((cancelInit.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^license-cancel-/)

    fireEvent.click(screen.getByRole('button', { name: '申请争议' }))
    fireEvent.change(await screen.findByLabelText('说明'), { target: { value: '无法加载规则' } })
    fireEvent.click(screen.getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/disputes', expect.objectContaining({ method: 'POST' })))
    const body = JSON.parse(fetchMock.mock.calls.find(([path]) => path === '/v1/admin/market/disputes')![1]!.body as string)
    expect(body).toEqual({ subject_kind: 'plugin_order', order_id: order.id, reason_code: 'not_working', note: '无法加载规则' })
  })

  it('explains up front that a prepaid licence has no order to dispute (PL-PREPAID-DISPUTE-01)', async () => {
    const licence = { id: '68686868-6868-4868-8868-686868686868', plugin_id: 'acme.waf', installation_id: 'i', kind: 'one_time',
      status: 'active', order_id: null }
    const fetchMock = routes({ '/v1/admin/market/licenses': () => json({ items: [licence], next_cursor: null }) })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<PluginStorePage />)
    fireEvent.click(await screen.findByRole('tab', { name: '许可证' }))
    fireEvent.click(await screen.findByRole('button', { name: '申请争议' }))
    expect(await screen.findByText(/没有关联售后订单/)).toBeInTheDocument()
    expect(screen.queryByLabelText('说明')).not.toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([path]) => path === '/v1/admin/market/disputes')).toBe(false)
  })

  it('renews a past-due subscription on the same licence and checks the new end (PL-RENEWAL-01)', async () => {
    const licence = { id: '69696969-6969-4969-8969-696969696969', plugin_id: 'acme.waf', plan_id: plan.id, plan_revision: 3,
      installation_id: 'i', kind: 'subscription', status: 'past_due', cancel_at_period_end: false,
      current_period_end: '2026-10-16T00:00:00Z', order_id: null }
    const fetchMock = routes({
      [`/v1/admin/market/licenses/${licence.id}/renew`]: () => json({ ...licence, status: 'active', current_period_end: '2026-11-16T00:00:00Z' }),
      '/v1/admin/market/licenses': () => json({ items: [licence], next_cursor: null }),
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<PluginStorePage />)
    fireEvent.click(await screen.findByRole('tab', { name: '许可证' }))
    fireEvent.click(await screen.findByRole('button', { name: '续费' }))
    fireEvent.click(await screen.findByRole('button', { name: 'OK' }))
    expect(await screen.findByText(/已续费，有效期至/)).toBeInTheDocument()
    const renewCalls = fetchMock.mock.calls.filter(([path]) => path === `/v1/admin/market/licenses/${licence.id}/renew`)
    expect(renewCalls).toHaveLength(1)
    expect((renewCalls[0]![1]!.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^license-renew-/)
    expect(fetchMock.mock.calls.some(([path]) => path === '/v1/admin/market/orders')).toBe(false)
  })

  it('warns when the renewal answer does not move the period end', async () => {
    const licence = { id: '6a6a6a6a-6a6a-4a6a-8a6a-6a6a6a6a6a6a', plugin_id: 'acme.waf', installation_id: 'i', kind: 'subscription',
      status: 'expired', current_period_end: '2026-10-16T00:00:00Z', order_id: null }
    vi.stubGlobal('fetch', routes({
      [`/v1/admin/market/licenses/${licence.id}/renew`]: () => json({ ...licence }),
      '/v1/admin/market/licenses': () => json({ items: [licence], next_cursor: null }),
    }))
    renderWithProviders(<PluginStorePage />)
    fireEvent.click(await screen.findByRole('tab', { name: '许可证' }))
    fireEvent.click(await screen.findByRole('button', { name: '续费' }))
    fireEvent.click(await screen.findByRole('button', { name: 'OK' }))
    expect(await screen.findByText(/续费结果未能确认/)).toBeInTheDocument()
  })

  it('shows the trial end and cancels a trial through the period-end cancel', async () => {
    const licence = { id: '6b6b6b6b-6b6b-4b6b-8b6b-6b6b6b6b6b6b', plugin_id: 'acme.waf', plan_id: plan.id, plan_revision: 3,
      installation_id: 'i', kind: 'subscription', status: 'trialing', cancel_at_period_end: false,
      trial_ends_at: '2026-10-23T00:00:00Z', current_period_end: null, order_id: null }
    const fetchMock = routes({
      [`/v1/admin/market/licenses/${licence.id}/cancel`]: () => json({ ...licence, cancel_at_period_end: true }),
      '/v1/admin/market/licenses': () => json({ items: [licence], next_cursor: null }),
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<PluginStorePage />)
    fireEvent.click(await screen.findByRole('tab', { name: '许可证' }))
    expect(await screen.findByText(/^试用至 /)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '续费' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '转为付费' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '取消试用' }))
    fireEvent.click(await screen.findByRole('button', { name: 'OK' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/admin/market/licenses/${licence.id}/cancel`, expect.objectContaining({ method: 'POST' })))
  })

  it('acknowledges an advisory with what was done', async () => {
    const fetchMock = routes({
      [`/v1/admin/market/advisories/${advisory.id}/acknowledge`]: () => json({ disposition: 'upgraded', note: '', acknowledged_by: 'u', acknowledged_at: 'x' }),
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<PluginStorePage />)
    fireEvent.click(await screen.findByRole('tab', { name: /安全公告/ }))
    fireEvent.click(await screen.findByRole('button', { name: '我已处理' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: '我已处理' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/admin/market/advisories/${advisory.id}/acknowledge`,
      expect.objectContaining({ method: 'POST' })))
    const body = JSON.parse(fetchMock.mock.calls.find(([path]) => path.endsWith('/acknowledge'))![1]!.body as string)
    expect(body).toEqual({ disposition: 'upgraded', note: '' })
  })

  it('shows only the same-origin package preview in the detail drawer, never third-party screenshots', async () => {
    const themed = { ...plugin, kind: 'theme', has_preview: true,
      screenshots: ['https://evil.example/shot.png', '//cdn.evil.example/a.webp', 'http://evil.example/b.jpg'] }
    const createObjectURL = vi.fn(() => 'blob:http://localhost:3000/preview-1')
    vi.stubGlobal('URL', Object.assign(globalThis.URL, { createObjectURL, revokeObjectURL: vi.fn() }))
    const previewPath = `/v1/admin/market/plugins/${plugin.id}/preview`
    const fetchMock = vi.fn<Fetch>(async (path) => {
      if (path === previewPath) {
        return { ok: true, status: 200, headers: new Headers({ 'Content-Type': 'image/png' }),
          blob: async () => new Blob([new Uint8Array(8)], { type: 'image/png' }) } as unknown as Response
      }
      if (path.startsWith('/v1/admin/market/plugins?')) return json({ items: [themed], next_cursor: null })
      if (path === `/v1/admin/market/plugins/${plugin.id}`) return json({ plugin: themed, versions: [version], price_plans: [] })
      if (path.startsWith('/v1/admin/market/advisories')) return json({ items: [] })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<PluginStorePage />)
    fireEvent.click(await screen.findByText('Acme WAF'))
    const drawer = await screen.findByRole('dialog')
    await waitFor(() => expect(drawer.querySelector('img[src^="blob:"]')).not.toBeNull())
    expect(fetchMock).toHaveBeenCalledWith(previewPath, expect.anything())
    for (const img of drawer.querySelectorAll('img')) {
      const src = img.getAttribute('src') ?? ''
      expect(src.startsWith('blob:') || src.startsWith('data:') || (src.startsWith('/') && !src.startsWith('//')), src).toBe(true)
    }
    expect(drawer.innerHTML).not.toContain('evil.example')
  })

  it('explains when the market has not mounted licences yet', async () => {
    vi.stubGlobal('fetch', routes({ '/v1/admin/market/licenses': () => json({ error: 'market_feature_unavailable' }, 501) }))
    renderWithProviders(<PluginStorePage />)
    fireEvent.click(await screen.findByRole('tab', { name: '许可证' }))
    expect(await screen.findByText('市场端还没有开放这个功能，市场升级后自动可用。')).toBeInTheDocument()
  })

  it('refuses tenant sessions and administrators without a marketplace code', () => {
    const tenant = principal({ scope_kind: 'tenant', permissions: ['marketplace.browse'] })
    useSessionStore.getState().setSession(authResponse(tenant), tenant)
    const { unmount } = renderWithProviders(<PluginStorePage />)
    expect(screen.getByText('需要插件市场的浏览权限')).toBeInTheDocument()
    unmount()
    setAdmin(['nodes.read'])
    renderWithProviders(<PluginStorePage />)
    expect(screen.getByText('需要插件市场的浏览权限')).toBeInTheDocument()
  })
})
