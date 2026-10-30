import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../../api/auth'
import { marketApi } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import NodeMarketPage from './NodeMarketPage'

// MC12 E4 (MK-BUYER-FLOW-01, 10-28 review §9): the ordinary balance check picks
// one of my suppliers (the rows of 我的供货方余额) instead of typing member IDs;
// each answer or failure carries the parties, currency and time it is for and
// never stands in for another query. L01/L02 are the review's probes
// (output/ecosystem-closure-20261028/market/probes/ledger-context.test.tsx).

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const me = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const sellerA = '11111111-1111-4111-8111-111111111111'
const sellerB = '22222222-2222-4222-8222-222222222222'
const row = (id: string, name: string) => ({ seller_member_id: id, display_name: name, balance_minor: 0, overdraft_minor: 0, credit_limit_minor: 0,
  below_alert: false, spent_24h_minor: 0, spent_by_day: [], by_subscription: [], seller_credit: { deposit_effective: false, defaults_count: 0, absconded: false, faults_30d: 0 } })
const owner = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['marketplace.browse', 'marketplace.purchase'] })
const other = principal({ user_id: '44444444-4444-4444-8444-444444444444', scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'],
  permissions: ['marketplace.browse', 'marketplace.purchase'] })

function stubMarket(sellers = [row(sellerA, 'Seller A'), row(sellerB, 'Seller B')]) {
  vi.stubGlobal('fetch', vi.fn(async (path: string) => {
    if (path === '/v1/admin/market/member') return json({ id: me, display_name: 'me', status: 'active', features: [], offers_quota: 3 })
    if (path === '/v1/admin/market/prepaid?currency=CNY') return json({ currency: 'CNY', balance_minor: 0, arrears_minor: 0, overdraft_cap_minor: 0,
      alert_minor: 0, spent_24h_minor: 0, sellers })
    if (path === '/v1/admin/market/direct-pay/sellers') return json({ items: [{ seller_id: sellerB, display_name: 'Seller B', currency: 'USD',
      balance_minor: 0, credit_limit_minor: 0, online: true, methods: [] }] })
    return json({ error: 'not_found' }, 404)
  }))
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}

async function openLedger() {
  renderWithProviders(<NodeMarketPage />)
  fireEvent.click(await screen.findByRole('tab', { name: '收款与余额' }))
  return screen.findByRole('region', { name: '我在供货方的余额' })
}

async function pick(region: HTMLElement, name: string) {
  fireEvent.mouseDown(within(region).getByRole('combobox', { name: '供货方' }))
  fireEvent.click(await screen.findByTitle(name))
}

const settle = () => act(() => new Promise<void>((done) => setTimeout(done, 20)))
const checkButton = (region: HTMLElement) => within(region).getByRole('button', { name: /查询余额/ })

beforeEach(() => { useSessionStore.getState().setSession(authResponse(owner), owner) })
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

describe('MC12 E4 balance with a supplier', () => {
  it('L01: picks a supplier, sends my own member ID and shows whose balance it is, in its currency', async () => {
    stubMarket()
    const balance = vi.spyOn(marketApi, 'balance').mockResolvedValue({ balance_minor: 1000 })
    const region = await openLedger()
    expect(within(region).queryByRole('textbox', { name: '买家成员 ID' })).not.toBeInTheDocument()
    expect(checkButton(region)).toBeDisabled()
    await pick(region, 'Seller A')
    fireEvent.click(checkButton(region))
    await waitFor(() => expect(balance).toHaveBeenCalledWith(expect.any(String), me, sellerA, 'CNY'))
    const answer = await within(region).findByRole('status')
    expect(answer).toHaveTextContent('Seller A')
    expect(answer).toHaveTextContent('10.00 CNY')
    expect(answer).toHaveTextContent('查询时间')
  })

  it('L02: a failing query for B does not keep A’s balance as its answer; it names B and can be retried', async () => {
    stubMarket()
    const balance = vi.spyOn(marketApi, 'balance').mockResolvedValueOnce({ balance_minor: 1000 })
      .mockRejectedValueOnce(new ApiError('synthetic unavailable', 503, 'request_failed')).mockResolvedValueOnce({ balance_minor: 250 })
    const region = await openLedger()
    await pick(region, 'Seller A')
    fireEvent.click(checkButton(region))
    expect(await within(region).findByText(/10\.00 CNY/)).toBeInTheDocument()
    await pick(region, 'Seller B')
    fireEvent.click(checkButton(region))
    const failure = await within(region).findByRole('alert')
    expect(failure).toHaveTextContent('Seller B')
    expect(within(region).queryByText(/10\.00 CNY/)).not.toBeInTheDocument()
    fireEvent.click(within(failure).getByRole('button', { name: '重试' }))
    expect(await within(region).findByText(/2\.50 USD/)).toBeInTheDocument()
    expect(balance).toHaveBeenLastCalledWith(expect.any(String), me, sellerB, 'USD')
    expect(within(region).queryByRole('alert')).not.toBeInTheDocument()
  })

  it('changing the supplier drops the shown answer without a new query', async () => {
    stubMarket()
    const balance = vi.spyOn(marketApi, 'balance').mockResolvedValue({ balance_minor: 1000 })
    const region = await openLedger()
    await pick(region, 'Seller A')
    fireEvent.click(checkButton(region))
    expect(await within(region).findByText(/10\.00 CNY/)).toBeInTheDocument()
    await pick(region, 'Seller B')
    expect(within(region).queryByText(/10\.00 CNY/)).not.toBeInTheDocument()
    expect(balance).toHaveBeenCalledTimes(1)
  })

  it('a late answer for A after switching to B and asking again is dropped', async () => {
    stubMarket()
    const late = deferred<{ balance_minor: number }>()
    vi.spyOn(marketApi, 'balance').mockReturnValueOnce(late.promise).mockResolvedValueOnce({ balance_minor: 250 })
    const region = await openLedger()
    await pick(region, 'Seller A')
    fireEvent.click(checkButton(region))
    await pick(region, 'Seller B')
    fireEvent.click(checkButton(region))
    expect(await within(region).findByText(/2\.50 USD/)).toBeInTheDocument()
    await act(async () => late.resolve({ balance_minor: 1000 }))
    await settle()
    expect(within(region).queryByText(/10\.00/)).not.toBeInTheDocument()
    expect(within(region).getByText(/2\.50 USD/)).toBeInTheDocument()
  })

  it('changing the currency drops the answer of the old currency', async () => {
    stubMarket()
    vi.spyOn(marketApi, 'balance').mockResolvedValue({ balance_minor: 1000 })
    const region = await openLedger()
    await pick(region, 'Seller A')
    fireEvent.click(checkButton(region))
    expect(await within(region).findByText(/10\.00 CNY/)).toBeInTheDocument()
    fireEvent.change(within(region).getByRole('textbox', { name: '币种' }), { target: { value: 'USD' } })
    expect(within(region).queryByText(/10\.00 CNY/)).not.toBeInTheDocument()
  })

  it('an answer that comes after the account changed is dropped', async () => {
    stubMarket()
    const late = deferred<{ balance_minor: number }>()
    vi.spyOn(marketApi, 'balance').mockReturnValueOnce(late.promise)
    const region = await openLedger()
    await pick(region, 'Seller A')
    fireEvent.click(checkButton(region))
    act(() => useSessionStore.getState().setSession(authResponse(other), other))
    await act(async () => late.resolve({ balance_minor: 1000 }))
    await settle()
    expect(screen.queryByText(/10\.00 CNY/)).not.toBeInTheDocument()
  })

  // F P3 (10-28 复验 F09–F12): going back to the same supplier or currency
  // does not bring an older answer back; it asks for a new query.
  it('F09: a finished A balance does not come back after A→B→A without a new query', async () => {
    stubMarket()
    const balance = vi.spyOn(marketApi, 'balance').mockResolvedValue({ balance_minor: 1000 })
    const region = await openLedger()
    await pick(region, 'Seller A')
    fireEvent.click(checkButton(region))
    expect(await within(region).findByText(/10\.00 CNY/)).toBeInTheDocument()
    await pick(region, 'Seller B')
    await pick(region, 'Seller A')
    await settle()
    expect(within(region).queryByText(/10\.00 CNY/)).not.toBeInTheDocument()
    expect(balance).toHaveBeenCalledTimes(1)
  })

  it('F10/F11: a late A answer or failure sent before A→B→A is dropped', async () => {
    stubMarket()
    const ok = deferred<{ balance_minor: number }>()
    const bad = deferred<{ balance_minor: number }>()
    vi.spyOn(marketApi, 'balance').mockReturnValueOnce(ok.promise).mockReturnValueOnce(bad.promise)
    const region = await openLedger()
    await pick(region, 'Seller A')
    fireEvent.click(checkButton(region))
    await pick(region, 'Seller B')
    await pick(region, 'Seller A')
    await act(async () => ok.resolve({ balance_minor: 1000 }))
    await settle()
    expect(within(region).queryByText(/10\.00 CNY/)).not.toBeInTheDocument()
    fireEvent.click(checkButton(region))
    await pick(region, 'Seller B')
    await pick(region, 'Seller A')
    await act(async () => bad.reject(new ApiError('synthetic unavailable', 503, 'request_failed')))
    await settle()
    expect(within(region).queryByRole('alert')).not.toBeInTheDocument()
  })

  it('F12: a late answer sent before CNY→USD→CNY is dropped', async () => {
    stubMarket()
    const late = deferred<{ balance_minor: number }>()
    vi.spyOn(marketApi, 'balance').mockReturnValueOnce(late.promise)
    const region = await openLedger()
    await pick(region, 'Seller A')
    fireEvent.click(checkButton(region))
    const input = within(region).getByRole('textbox', { name: '币种' })
    fireEvent.change(input, { target: { value: 'USD' } })
    await settle()
    fireEvent.change(input, { target: { value: 'CNY' } })
    await act(async () => late.resolve({ balance_minor: 1000 }))
    await settle()
    expect(within(region).queryByText(/10\.00 CNY/)).not.toBeInTheDocument()
  })

  it('says there is no supplier yet instead of asking for member IDs', async () => {
    stubMarket([])
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/v1/admin/market/member') return json({ id: me, display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/prepaid?currency=CNY') return json({ currency: 'CNY', balance_minor: 0, arrears_minor: 0, overdraft_cap_minor: 0,
        alert_minor: 0, spent_24h_minor: 0, sellers: [] })
      if (path === '/v1/admin/market/direct-pay/sellers') return json({ items: [] })
      return json({ error: 'not_found' }, 404)
    }))
    const region = await openLedger()
    expect(await within(region).findByText(/还没有供货方/)).toBeInTheDocument()
  })

  it('keeps the any-pair lookup under advanced reconciliation, with the queried IDs on the answer', async () => {
    stubMarket()
    const balance = vi.spyOn(marketApi, 'balance').mockResolvedValue({ balance_minor: 1000 })
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '收款与余额' }))
    fireEvent.click(await screen.findByText('高级对账：按成员 ID 查询任意交易边'))
    const advanced = await screen.findByRole('region', { name: '高级对账' })
    fireEvent.change(within(advanced).getByRole('textbox', { name: '买家成员 ID' }), { target: { value: sellerB } })
    fireEvent.change(within(advanced).getByRole('textbox', { name: '卖家成员 ID' }), { target: { value: sellerA } })
    fireEvent.click(within(advanced).getByRole('button', { name: '查询余额' }))
    await waitFor(() => expect(balance).toHaveBeenCalledWith(expect.any(String), sellerB, sellerA, 'CNY'))
    const answer = await within(advanced).findByRole('status')
    expect(answer).toHaveTextContent(sellerB.slice(0, 8))
    expect(answer).toHaveTextContent('10.00 CNY')
    fireEvent.change(within(advanced).getByRole('textbox', { name: '卖家成员 ID' }), { target: { value: sellerB } })
    expect(within(advanced).queryByRole('status')).not.toBeInTheDocument()
  })
})
