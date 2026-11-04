import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../auth/session'
import i18n from '../../i18n'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import type { MarketOfferListing } from '../../api/market'
import NodeMarketPage from './NodeMarketPage'
import { pricingOf, rowsOf } from './offerLifecycleModel'

// 我的上架 rows show 已上架 / 下架中（预计 X 完成，N 个买方）/ 已下架（无买方）and
// carry 修改报价 / 下架 / 删除, enabled by state with the reason when not.

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['sites.manage'] })
const base = {
  seller_id: 'm', description: '', billing_model: 'daily_bundle', revision: 4,
  pricing: { currency: 'CNY', daily_minor: 1200, min_days: 1, max_days: 30 }, allocation: { http_ports: 2 }, compliance: { require_icp: false },
  limits: [], tags: {}, prepaid_exhausted_action: 'pause',
}
const later = '2026-11-20T08:00:00Z'
const listed = { ...base, id: '11111111-1111-4111-8111-111111111111', name: 'HK BGP', status: 'listed',
  lifecycle: { state: 'listed', active_subscriptions: 2, renewing_subscriptions: 2, completes_at: later, operator_delisted: false, deletable: false } }
const delisting = { ...base, id: '22222222-2222-4222-8222-222222222222', name: 'JP CN2', status: 'delisted',
  lifecycle: { state: 'delisting', active_subscriptions: 3, renewing_subscriptions: 0, completes_at: later, operator_delisted: false, deletable: false } }
const done = { ...base, id: '33333333-3333-4333-8333-333333333333', name: 'SG Edge', status: 'delisted',
  lifecycle: { state: 'delisted', active_subscriptions: 0, renewing_subscriptions: 0, operator_delisted: false, deletable: true } }
const quiet = { ...base, id: '44444444-4444-4444-8444-444444444444', name: 'US West', status: 'listed',
  lifecycle: { state: 'listed', active_subscriptions: 0, renewing_subscriptions: 0, operator_delisted: false, deletable: false } }

function stub(offers: unknown[]) {
  const calls: Array<{ method: string; path: string; body?: string; key?: string }> = []
  const fetchMock = vi.fn(async (path: string, init: RequestInit = {}): Promise<Response> => {
    const method = init.method ?? 'GET'
    const headers = (init.headers ?? {}) as Record<string, string>
    if (method !== 'GET') calls.push({ method, path, body: init.body as string | undefined, key: headers['Idempotency-Key'] })
    if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: ['market.sell'], offers_quota: 5,
      supplier: { status: 'active', can_sell: true } })
    if (path === '/v1/admin/market/offers?mine=1') return json({ items: offers })
    if (path.startsWith('/v1/nodes?')) return json({ items: [] })
    if (method === 'POST' && path.endsWith('/delist')) return json({ ...listed, status: 'delisted', lifecycle: { ...listed.lifecycle, state: 'delisting', renewing_subscriptions: 0 } })
    if (method === 'DELETE') return json({ id: done.id, deleted: true })
    if (method === 'PUT' && path.endsWith('/terms')) return json({ ...listed, revision: 5 })
    return json({ error: 'not_found' }, 404)
  })
  vi.stubGlobal('fetch', fetchMock)
  return calls
}

async function rowOf(name: string) {
  renderWithProviders(<NodeMarketPage />)
  fireEvent.click(await screen.findByRole('tab', { name: '我的上架' }))
  return (await screen.findByText(name)).closest('tr')! as HTMLElement
}

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
  useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'market-token' }, admin)
})
afterEach(() => vi.unstubAllGlobals())

describe('我的上架 lifecycle', () => {
  it('shows the three states and gates delist / delete by them', async () => {
    stub([listed, delisting, done])
    const row = await rowOf('HK BGP')
    expect(within(row).getByText('已上架')).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: '下架' })).toBeEnabled()
    expect(within(row).getByRole('button', { name: '删除' })).toBeDisabled()
    const winding = screen.getByText('JP CN2').closest('tr')! as HTMLElement
    expect(within(winding).getByText('下架中')).toBeInTheDocument()
    expect(within(winding).getByText(/^预计 .+ 完成，3 个买方$/)).toBeInTheDocument()
    expect(within(winding).getByRole('button', { name: '下架' })).toBeDisabled()
    expect(within(winding).getByRole('button', { name: '删除' })).toBeDisabled()
    const gone = screen.getByText('SG Edge').closest('tr')! as HTMLElement
    expect(within(gone).getByText('已下架（无买方）')).toBeInTheDocument()
    expect(within(gone).getByRole('button', { name: '删除' })).toBeEnabled()
    expect(within(gone).getByRole('button', { name: '修改报价' })).toBeEnabled()
  })

  it('confirms a delisting with buyers: count and when it completes, then posts with a key', async () => {
    const calls = stub([listed])
    const row = await rowOf('HK BGP')
    fireEvent.click(within(row).getByRole('button', { name: '下架' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/现有 2 个在期买方照常服务到各自已付到期，不再续费/)).toBeInTheDocument()
    expect(within(dialog).getByText(/^预计下架完成时间：.+（最后一个订阅到期）$/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '确定下架' }))
    await waitFor(() => expect(calls).toHaveLength(1))
    expect(calls[0]).toMatchObject({ method: 'POST', path: `/v1/admin/market/offers/${listed.id}/delist` })
    expect(calls[0].key).toBeTruthy()
  })

  it('confirms a delisting with no buyer as immediate', async () => {
    stub([quiet])
    const row = await rowOf('US West')
    fireEvent.click(within(row).getByRole('button', { name: '下架' }))
    expect(await screen.findByText(/当前没有在期买方，确定后立即下架完成/)).toBeInTheDocument()
  })

  it('deletes a delisted offer with no buyer after confirming', async () => {
    const calls = stub([done])
    const row = await rowOf('SG Edge')
    fireEvent.click(within(row).getByRole('button', { name: '删除' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/历史订单、账单、用量确认单和已结束的订阅仍可查询/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '删除' }))
    await waitFor(() => expect(calls).toHaveLength(1))
    expect(calls[0]).toMatchObject({ method: 'DELETE', path: `/v1/admin/market/offers/${done.id}` })
  })

  it('an offer the platform delisted cannot be listed again by the seller', async () => {
    stub([{ ...done, name: 'OP pulled', lifecycle: { ...done.lifecycle, operator_delisted: true } }])
    const row = await rowOf('OP pulled')
    expect(within(row).getByText('由平台下架，需联系平台恢复上架')).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: '重新提交上架' })).toBeDisabled()
  })

  it('edits the price of one row: buyers in period keep theirs, the opened revision is sent', async () => {
    const calls = stub([listed])
    const row = await rowOf('HK BGP')
    fireEvent.click(within(row).getByRole('button', { name: '修改报价' }))
    const dialog = await screen.findByRole('dialog', { name: '修改报价「HK BGP」' })
    expect(within(dialog).getByText(/当期合约中的买家价格不变/)).toBeInTheDocument()
    fireEvent.change(within(dialog).getByRole('spinbutton', { name: '主价格（元）' }), { target: { value: '15.5' } })
    fireEvent.click(within(dialog).getAllByRole('button', { name: '保存' })[0])
    await waitFor(() => expect(calls).toHaveLength(1))
    expect(calls[0].path).toBe(`/v1/admin/market/offers/${listed.id}/terms`)
    expect(JSON.parse(calls[0].body!)).toEqual({ pricing: { currency: 'CNY', daily_minor: 1550, min_days: 1, max_days: 30 }, expected_revision: 4 })
  })
})

describe('offer terms model', () => {
  it('reads limits back exactly and refuses a price it would round', () => {
    const rows = rowsOf([{ metric: 'bandwidth_peak_bps', cap: 1_500_000, action: 'throttle' }, { metric: 'monthly_traffic_bytes', cap: 1024 ** 3 * 3, action: 'pause' }])
    expect(rows.find((r) => r.metric === 'bandwidth_peak_bps')).toMatchObject({ enabled: true, value: 1.5, unit: 'Mbps' })
    expect(rows.find((r) => r.metric === 'monthly_traffic_bytes')).toMatchObject({ enabled: true, value: 3, unit: 'GB' })
    const offer = { ...base, billing_model: 'traffic', pricing: { currency: 'CNY', deposit_minor: 10000, tiers: [{ up_to_gb: 100, price_per_gb_minor: 20 }, { up_to_gb: 0, price_per_gb_minor: 10 }] } } as unknown as MarketOfferListing
    expect(pricingOf(offer, { main: null, minDays: null, maxDays: null, deposit: 50, tiers: [0.3, 0.12] })).toEqual(
      { currency: 'CNY', deposit_minor: 5000, tiers: [{ up_to_gb: 100, price_per_gb_minor: 30 }, { up_to_gb: 0, price_per_gb_minor: 12 }] })
    expect(pricingOf(offer, { main: null, minDays: null, maxDays: null, deposit: 50, tiers: [0.333, 0.1] })).toBeNull()
  })
})
