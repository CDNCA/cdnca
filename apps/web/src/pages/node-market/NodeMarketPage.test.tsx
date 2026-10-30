import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { marketApi } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import NodeMarketPage from './NodeMarketPage'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import listingContract from '../../test/contracts/offer_listing_contract.json'

function json(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, text: vi.fn().mockResolvedValue(JSON.stringify(body)),
    json: vi.fn().mockResolvedValue(body) } as unknown as Response
}

// antd test modals all carry a test-id aria-labelledby: find a dialog by its title text.
async function dialogTitled(title: string): Promise<HTMLElement> {
  const titles = await screen.findAllByText(title, { selector: '.ant-modal-title' })
  return titles.at(-1)!.closest('[role="dialog"]') as HTMLElement
}

// MC12 E2: the site picker reads /v1/sites; one saved site for the supplies tests.
const pickedSite = '88888888-8888-4888-8888-888888888888'
const siteList = {
  items: [{ id: pickedSite, display_id: '1', version: 7, owner: null, domain: 'shop.example.test', domains: ['shop.example.test'], listen_ports: ['80'],
    origins: ['203.0.113.10'], cname: '', lock: { locked: false, reason: null, locked_at: null, operator: null },
    listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' } }],
  total: 1, page: 1, limit: 20,
}

async function pickSite() {
  fireEvent.mouseDown(await screen.findByRole('combobox', { name: '站点' }))
  fireEvent.click(await screen.findByText('shop.example.test', { selector: '.ant-select-item-option-content' }))
}

const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['sites.manage'] })
const offer = { id: '11111111-1111-4111-8111-111111111111', seller_id: '22222222-2222-4222-8222-222222222222', name: 'HK BGP',
  description: '', billing_model: 'daily_bundle', status: 'listed', revision: 4, pricing: { currency: 'CNY', daily_minor: 100, min_days: 2, max_days: 30 },
  allocation: { http_ports: 2 }, limits: [{ metric: 'domains', cap: 5, action: 'reject_new' }], compliance: { require_icp: true } }

beforeEach(() => {
  useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'market-token' }, admin)
  localStorage.removeItem('cdnca.advancedFilters.node-market-offers')
})
afterEach(() => { vi.unstubAllGlobals(); window.sessionStorage.clear() })

describe('marketApi', () => {
  it('relays through the controller with the session token and maps market errors', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(json({ items: [offer] })).mockResolvedValueOnce(json({ error: 'insufficient_balance' }, 402))
    vi.stubGlobal('fetch', fetchMock)
    await expect(marketApi.offers('t')).resolves.toEqual({ items: [offer], next_cursor: null })
    expect(fetchMock.mock.calls[0][0]).toBe('/v1/admin/market/offers?limit=50')
    expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe('Bearer t')
    await expect(marketApi.purchase('t', offer.id, 2, 'k')).rejects.toMatchObject({ status: 402, code: 'insufficient_balance' })
  })
})

describe('NodeMarketPage', () => {
  it('lists offers and buys with the minimum days and a fresh idempotency key', async () => {
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/offers?limit=50') return json({ items: [offer] })
      if (path === '/v1/admin/market/subscriptions') return json({ id: 's', grants: 1 }, 201)
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '购买' }))
    const dialog = await dialogTitled('购买 HK BGP')
    expect(within(dialog).getByText('2 天 × 1.00 元 / 天 = 2.00 元，从你在该卖家处的余额扣')).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '确认购买' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/subscriptions', expect.objectContaining({ method: 'POST' })))
    const body = JSON.parse(fetchMock.mock.calls.find(([path]) => path === '/v1/admin/market/subscriptions')![1]!.body as string)
    expect(body).toMatchObject({ offer_id: offer.id, days: 2, expected_revision: 4 })
    expect(body.idempotency_key).toMatch(/^buy-/)
  })

  // market-buy-idem: a lost answer is "result unknown"; checking replays the
  // same key (no second charge), and only a finished purchase gets a new key.
  it('replays an unknown purchase with the same idempotency key and never re-buys', async () => {
    let answer = 0
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path, init) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/offers?limit=50') return json({ items: [offer] })
      if (path === '/v1/admin/market/subscriptions' && init?.method === 'POST') {
        answer += 1
        if (answer === 1) return json({ error: 'internal' }, 503)
        if (answer === 2) throw new TypeError('Failed to fetch')
        return json({ id: 's', grants: 1 }, 201)
      }
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '购买' }))
    const dialog = await dialogTitled('购买 HK BGP')
    fireEvent.click(within(dialog).getByRole('button', { name: '确认购买' }))
    expect(await within(dialog).findByText(/不会重复扣款/)).toBeInTheDocument()
    // The dialog offers only "check result" now; the offer row cannot start another purchase.
    expect(within(dialog).queryByRole('button', { name: '确认购买' })).not.toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '查询结果' }))
    await waitFor(() => expect(answer).toBe(2))
    fireEvent.click(await within(dialog).findByRole('button', { name: '查询结果' }))
    await waitFor(() => expect(answer).toBe(3))
    const keys = fetchMock.mock.calls.filter(([p, i]) => p === '/v1/admin/market/subscriptions' && i?.method === 'POST')
      .map(([, i]) => JSON.parse(i!.body as string).idempotency_key as string)
    expect(keys).toHaveLength(3)
    expect(new Set(keys).size).toBe(1)
    expect(await screen.findByText('已下单')).toBeInTheDocument()

    // A new purchase after the success gets a fresh key.
    fireEvent.click(screen.getByRole('button', { name: '购买' }))
    fireEvent.click(within(await dialogTitled('购买 HK BGP')).getByRole('button', { name: '确认购买' }))
    await waitFor(() => expect(answer).toBe(4))
    const last = JSON.parse(fetchMock.mock.calls.filter(([p, i]) => p === '/v1/admin/market/subscriptions' && i?.method === 'POST').at(-1)![1]!.body as string)
    expect(last.idempotency_key).not.toBe(keys[0])
  })

  // MC01 (NM02): an unknown purchase survives leaving the section and a reload;
  // checking replays the same key and days, and no other purchase starts meanwhile.
  it('keeps an unknown purchase across sections and reloads and replays it with its own key', async () => {
    let answer = 0
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path, init) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/offers?limit=50') return json({ items: [offer] })
      if (path === '/v1/admin/market/subscriptions' && init?.method === 'POST') {
        answer += 1
        return answer === 1 ? json({ error: 'internal' }, 503) : json({ id: 's', grants: 1 }, 201)
      }
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    const posted = () => fetchMock.mock.calls.filter(([p, i]) => p === '/v1/admin/market/subscriptions' && i?.method === 'POST')
      .map(([, i]) => JSON.parse(i!.body as string) as { days: number; idempotency_key: string })
    const view = renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('天数'), { target: { value: '2' } })
    fireEvent.click(screen.getByRole('button', { name: '购买' }))
    const dialog = await dialogTitled('购买 HK BGP')
    fireEvent.click(within(dialog).getByRole('button', { name: '确认购买' }))
    expect(await within(dialog).findByText(/不会重复扣款/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: /Close|关闭/ }))

    fireEvent.click(screen.getByRole('tab', { name: '已购供给与站点' }))
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: '查询结果' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '购买' })).toBeDisabled()

    // A reload (fresh mount) still finds it.
    view.unmount()
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '购买' })).toBeDisabled()
    fireEvent.click(await screen.findByRole('button', { name: '查询结果' }))
    await waitFor(() => expect(posted()).toHaveLength(2))
    expect(posted()[1]).toEqual(posted()[0])
    expect(await screen.findByText('已下单')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('button', { name: '购买' })).toBeEnabled())
    expect(screen.queryByRole('button', { name: '查询结果' })).not.toBeInTheDocument()
  })

  it('keeps a cancelled in-flight purchase as the one to check; a late answer never turns a new draft into it', async () => {
    let release: (r: Response) => void = () => undefined
    let answer = 0
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path, init) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/offers?limit=50') return json({ items: [offer] })
      if (path === '/v1/admin/market/subscriptions' && init?.method === 'POST') {
        answer += 1
        if (answer === 1) return new Promise<Response>((resolve) => { release = resolve })
        return json({ id: 's', grants: 1 }, 201)
      }
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    const posted = () => fetchMock.mock.calls.filter(([p, i]) => p === '/v1/admin/market/subscriptions' && i?.method === 'POST')
      .map(([, i]) => JSON.parse(i!.body as string) as { days: number; idempotency_key: string })
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '购买' }))
    fireEvent.click(within(await dialogTitled('购买 HK BGP')).getByRole('button', { name: '确认购买' }))
    await waitFor(() => expect(posted()).toHaveLength(1))
    fireEvent.click(within(await dialogTitled('购买 HK BGP')).getByRole('button', { name: /Close|关闭/ }))
    // While A has no answer no other purchase starts.
    fireEvent.change(screen.getByLabelText('天数'), { target: { value: '5' } })
    expect(screen.getByRole('button', { name: '购买' })).toBeDisabled()
    await act(async () => { release(json({ error: 'internal' }, 503)) })
    fireEvent.click(await screen.findByRole('button', { name: '查询结果' }))
    await waitFor(() => expect(posted()).toHaveLength(2))
    expect(posted()[1]).toEqual(posted()[0])
    expect(posted()[1].days).toBe(2)
  })

  it('keeps one account\'s unknown purchase away from another account', async () => {
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path, init) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/offers?limit=50') return json({ items: [offer] })
      if (path === '/v1/admin/market/subscriptions' && init?.method === 'POST') return json({ error: 'internal' }, 503)
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    const view = renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '购买' }))
    fireEvent.click(within(await dialogTitled('购买 HK BGP')).getByRole('button', { name: '确认购买' }))
    expect(await screen.findByText(/不会重复扣款/)).toBeInTheDocument()
    view.unmount()
    const other = principal({ ...admin, user_id: 'another-admin' })
    useSessionStore.getState().setSession({ ...authResponse(other), access_token: 'other-token' }, other)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '购买' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: '查询结果' })).not.toBeInTheDocument()
  })

  // u4d: an offer with trial days shows "试用"; it posts trial=true with days 0
  // (the market takes the offer's trial days) and names a used-up trial.
  it('starts a free trial of a daily offer and explains a trial already used', async () => {
    const trialOffer = { ...offer, trial_days: 3 }
    const metered = { ...offer, id: '33333333-3333-4333-8333-333333333333', name: '按量', billing_model: 'traffic', trial_days: 0,
      pricing: { currency: 'CNY', deposit_minor: 100, tiers: [] } }
    let posts = 0
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path, init) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path.startsWith('/v1/admin/market/offers')) return json({ items: [trialOffer, metered], next_cursor: null })
      if (path === '/v1/admin/market/subscriptions' && init?.method === 'POST') {
        posts += 1
        return posts === 1 ? json({ id: 's', grants: 1 }, 201) : json({ error: 'trial_used' }, 409)
      }
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    // Only the daily offer with trial days has the entry.
    expect(screen.getAllByRole('button', { name: /^试用/ })).toHaveLength(1)
    fireEvent.click(screen.getByRole('button', { name: '试用 3 天' }))
    const dialog = await dialogTitled('试用 HK BGP')
    expect(within(dialog).getByText(/免费试用 3 天，不扣款。试用到期后按日价 1.00 元/)).toBeInTheDocument()
    expect(within(dialog).getByText(/每个报价只能试用一次/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '确认试用' }))
    expect(await screen.findByText('已开始试用')).toBeInTheDocument()
    const posted = () => fetchMock.mock.calls.filter(([p, i]) => p === '/v1/admin/market/subscriptions' && i?.method === 'POST')
      .map(([, i]) => JSON.parse(i!.body as string) as Record<string, unknown>)
    // A trial is checked against the confirmed revision too (merge-p10: u4d trial + u4e C17).
    expect(posted()[0]).toMatchObject({ offer_id: offer.id, days: 0, trial: true, expected_revision: 4 })
    expect(String(posted()[0].idempotency_key)).toMatch(/^buy-/)

    fireEvent.click(screen.getByRole('button', { name: '试用 3 天' }))
    fireEvent.click(within(await dialogTitled('试用 HK BGP')).getByRole('button', { name: '确认试用' }))
    expect(await screen.findByText('你已经试用过这个报价，不能再次试用；可以直接购买。')).toBeInTheDocument()
    // A paid purchase carries no trial flag.
    fireEvent.click(await screen.findByRole('button', { name: '知道了' }))
    fireEvent.click(screen.getAllByRole('button', { name: '购买' })[0])
    fireEvent.click(within(await dialogTitled('购买 HK BGP')).getByRole('button', { name: '确认购买' }))
    await waitFor(() => expect(posted()).toHaveLength(3))
    expect(posted()[2]).not.toHaveProperty('trial')
    expect(posted()[2].idempotency_key).not.toBe(posted()[0].idempotency_key)
  })

  it('starts a new key after a definite refusal and when the days change', async () => {
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path, init) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/offers?limit=50') return json({ items: [offer] })
      if (path === '/v1/admin/market/subscriptions' && init?.method === 'POST') return json({ error: 'insufficient_balance' }, 402)
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    const posted = () => fetchMock.mock.calls.filter(([p, i]) => p === '/v1/admin/market/subscriptions' && i?.method === 'POST')
      .map(([, i]) => JSON.parse(i!.body as string) as { days: number; idempotency_key: string })
    fireEvent.click(screen.getByRole('button', { name: '购买' }))
    fireEvent.click(within(await dialogTitled('购买 HK BGP')).getByRole('button', { name: '确认购买' }))
    await waitFor(() => expect(posted()).toHaveLength(1))
    fireEvent.click(await screen.findByRole('button', { name: '知道了' }))
    // A definite refusal (402) ends the attempt: the next one is a new key.
    fireEvent.click(screen.getByRole('button', { name: '购买' }))
    fireEvent.click(within(await dialogTitled('购买 HK BGP')).getByRole('button', { name: '确认购买' }))
    await waitFor(() => expect(posted()).toHaveLength(2))
    fireEvent.click(await screen.findByRole('button', { name: '知道了' }))
    expect(posted()[1].idempotency_key).not.toBe(posted()[0].idempotency_key)
    fireEvent.change(screen.getByLabelText('天数'), { target: { value: '5' } })
    fireEvent.click(screen.getByRole('button', { name: '购买' }))
    fireEvent.click(within(await dialogTitled('购买 HK BGP')).getByRole('button', { name: '确认购买' }))
    await waitFor(() => expect(posted()).toHaveLength(3))
    expect(posted()[2]).toMatchObject({ days: 5 })
    expect(posted()[2].idempotency_key).not.toBe(posted()[1].idempotency_key)
  })

  it('lists own offers in every status and publishes drafts from the list', async () => {
    const draft = { ...offer, id: '33333333-3333-4333-8333-333333333333', name: 'JP CN2', status: 'draft' }
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/offers?mine=1') return json({ items: [draft, offer] })
      if (path === `/v1/admin/market/offers/${draft.id}/publish`) return json({ status: 'listed' })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的上架' }))
    expect(await screen.findByText('JP CN2')).toBeInTheDocument()
    // fix-offerform: the probing notice is one short line; the explanation opens on demand.
    expect(screen.getByText('开启质量拨测后报价会显示实测数据。')).toBeInTheDocument()
    expect(screen.queryByText(/打开即表示同意该节点始终开放 80 端口/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '查看说明' }))
    expect(screen.getByText(/打开即表示同意该节点始终开放 80 端口/)).toBeInTheDocument()
    expect(screen.getByText('草稿')).toBeInTheDocument()
    expect(screen.getByText('已上架')).toBeInTheDocument()
    const publish = screen.getAllByRole('button', { name: /上\s*架/ })
    expect(publish).toHaveLength(1)
    fireEvent.click(publish[0])
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/admin/market/offers/${draft.id}/publish`, expect.objectContaining({ method: 'POST' })))
  })

  // C18: a delisted offer is listed again under the same ID; the answer's
  // status tells a pending review apart from an immediate listing.
  it('re-submits a delisted offer under the same ID and reports a pending review', async () => {
    const delisted = { ...offer, id: '66666666-6666-4666-8666-666666666666', name: 'SG BGP', status: 'delisted' }
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/offers?mine=1') return json({ items: [delisted, offer] })
      if (path === `/v1/admin/market/offers/${delisted.id}/publish`) return json({ status: 'pending_review' })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的上架' }))
    expect(await screen.findByText('已下架')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '重新提交上架' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/已有订阅一直照常服务/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '重新提交上架' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/admin/market/offers/${delisted.id}/publish`, expect.objectContaining({ method: 'POST' })))
    expect(await screen.findByText('已提交审核，审核通过后上架')).toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([path, init]) => path === '/v1/admin/market/offers' && init?.method === 'POST')).toBe(false)
  })

  // A13: node escrow is retired. An old escrow offer (if an older market still
  // lists it) shows why it cannot be bought and never creates a node order.
  it('never orders retired escrow offers and warns purchase-only roles about site binding', async () => {
    const escrow = { ...offer, id: '44444444-4444-4444-8444-444444444444', name: 'SG escrow', revision: 3, settlement_mode: 'escrow' }
    const metered = { ...offer, id: '55555555-5555-4555-8555-555555555555', name: 'Traffic', billing_model: 'traffic',
      pricing: { currency: 'CNY', deposit_minor: 900 }, limits: [{ metric: 'domains', cap: 1, action: 'reject_new' },
        { metric: 'monthly_traffic_bytes', cap: 1024 ** 4, action: 'pause' }] }
    const buyer = principal({ scope_kind: 'platform', tenant_id: null, roles: ['market_buyer'], permissions: ['marketplace.purchase'] })
    useSessionStore.getState().setSession({ ...authResponse(buyer), access_token: 'market-token' }, buyer)
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path.startsWith('/v1/admin/market/offers')) return json({ items: [offer, escrow, metered] })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('SG escrow')).toBeInTheDocument()
    expect(screen.getByText('流量上限 1 TiB')).toBeInTheDocument()
    expect(screen.getByText(/押金 9.00 元/)).toBeInTheDocument()
    expect(screen.getByText(/平台托管已停用，不能购买/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '去付款' })).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /购\s*买/ })).toHaveLength(2)
    expect(screen.getByText(/没有站点管理权限/)).toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([path]) => path === '/v1/admin/market/orders')).toBe(false)
  })

  // C17: the market applies the filters; a price needs a billing model (its
  // unit), and the page shows what came back without narrowing it again.
  it('asks for a billing model before a price and sends the filters to the market', async () => {
    const metered = { ...offer, id: '55555555-5555-4555-8555-555555555555', name: 'Traffic', billing_model: 'traffic' }
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path.startsWith('/v1/admin/market/offers')) return json({ items: [offer, metered] })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('Traffic')).toBeInTheDocument()
    expect(screen.getByLabelText('单价上限（元）')).toBeDisabled()
    expect(screen.getByPlaceholderText('先选计费方式再填价格')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('地区'), { target: { value: 'hk' } })
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '计费方式' }))
    fireEvent.click(await screen.findByTitle('包天（包月按天数）'))
    expect(screen.getByLabelText('单价上限（元）')).toBeEnabled()
    expect(screen.getByPlaceholderText('日价上限（元 / 天）')).toBeInTheDocument()
    // fix-advfilter2：单价上限在「高级筛选」里，应用后显示徽标与可关闭标签。
    fireEvent.click(screen.getByRole('button', { name: '高级筛选' }))
    fireEvent.change(screen.getByLabelText('单价上限（元）'), { target: { value: '0.5' } })
    fireEvent.click(screen.getByRole('button', { name: '应用' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/offers?region=hk&billing_model=daily_bundle&max_price=50&limit=50', expect.anything()))
    expect(screen.getByRole('button', { name: '高级筛选 · 1' })).toBeInTheDocument()
    fireEvent.click(within(screen.getByRole('list', { name: '已启用的高级条件' })).getByRole('button', { name: '移除条件 单价上限（元）' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/offers?region=hk&billing_model=daily_bundle&limit=50', expect.anything()))
    // Whatever the market answered is shown as is.
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    expect(screen.getByText('Traffic')).toBeInTheDocument()
  })

  it('shows a catalogue read failure with retry instead of an empty market', async () => {
    let fail = true
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path.startsWith('/v1/admin/market/offers')) return fail ? json({ error: 'invalid' }, 400) : json({ items: [offer] })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('报价目录读取失败（invalid），筛选条件已保留，可重试')).toBeInTheDocument()
    expect(screen.queryByText('市场里暂无上架报价')).not.toBeInTheDocument()
    fail = false
    fireEvent.click(screen.getByRole('button', { name: /重\s*试/ }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    expect(screen.queryByText(/报价目录读取失败/)).not.toBeInTheDocument()
  })

  // C17: the listing exactly as market-service serializes it (Go test
  // TestOfferListingContract writes the file): nested quality, per-model units.
  it('reads quality and unit prices from the market-service listing JSON', async () => {
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path.startsWith('/v1/admin/market/offers')) return json(listingContract)
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    const row = async (name: string) => (await screen.findByText(name)).closest('tr') as HTMLElement
    expect(within(await row('never-scored')).getByText('尚未评估')).toBeInTheDocument()
    expect(within(await row('never-scored')).getByText('1.00 元 / 天')).toBeInTheDocument()
    expect(within(await row('few-samples')).getByText('样本不足')).toBeInTheDocument()
    expect(within(await row('few-samples')).getByText('0.00 元 / 天')).toBeInTheDocument()
    expect(within(await row('scored-zero')).getByText('0.00')).toBeInTheDocument()
    expect(within(await row('scored-zero')).getByText('0.30 元 / GB 起')).toBeInTheDocument()
    expect(within(await row('scored-high')).getByText('2.50')).toBeInTheDocument()
    expect(within(await row('scored-high')).getByText('20.00 元 / Mbps / 月')).toBeInTheDocument()
    expect(within(await row('peak')).getByText('0.80 元 / Mbps / 天')).toBeInTheDocument()
  })

  // C17: the catalogue pages on the market's keyset cursor; filters restart at page 1.
  it('pages the catalogue with the market cursor and restarts on a new filter', async () => {
    const second = { ...offer, id: '66666666-6666-4666-8666-666666666666', name: 'SG BGP' }
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/offers?limit=50') return json({ items: [offer], next_cursor: '100~' + offer.id })
      if (path === `/v1/admin/market/offers?cursor=100%7E${offer.id}&limit=50`) return json({ items: [second], next_cursor: null })
      if (path.startsWith('/v1/admin/market/offers?region=sg')) return json({ items: [second], next_cursor: null })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    expect(screen.getByText('第 1 页')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /上一页/ })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: /下一页/ }))
    expect(await screen.findByText('SG BGP')).toBeInTheDocument()
    expect(screen.queryByText('HK BGP')).not.toBeInTheDocument()
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /下一页/ })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: /上一页/ }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /下一页/ }))
    expect(await screen.findByText('SG BGP')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('地区'), { target: { value: 'sg' } })
    fireEvent.click(screen.getByRole('button', { name: '筛选' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/offers?region=sg&limit=50', expect.anything()))
    // A one-page result shows no pager.
    await waitFor(() => expect(screen.queryByText(/第 \d 页/)).not.toBeInTheDocument())
  })

  // C17: one confirmation for every billing model, with the terms charged and
  // the offer revision checked; a seller change re-shows the new terms.
  it('confirms the full terms and re-confirms when the seller changed the offer', async () => {
    const metered = { ...offer, id: '77777777-7777-4777-8777-777777777777', name: 'Traffic', billing_model: 'traffic', revision: 2,
      pricing: { currency: 'CNY', deposit_minor: 900, tiers: [{ up_to_gb: 0, price_per_gb_minor: 30 }] },
      limits: [{ metric: 'monthly_traffic_bytes', cap: 1024 ** 4, action: 'pause' }], prepaid_exhausted_action: 'stop',
      sla: { availability_target: 0.999, measure_window: 'month', credit_schedule: [], daily_penalty_minor: 0, max_credit_percent: 0, terminate_after: 0 } }
    let listing = [metered]
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path, init) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path.startsWith('/v1/admin/market/offers')) return json({ items: listing, next_cursor: null })
      if (path === '/v1/admin/market/subscriptions' && init?.method === 'POST') {
        const body = JSON.parse(init.body as string)
        return body.expected_revision === 2 ? json({ error: 'offer_changed' }, 409) : json({ id: 's', grants: 1 }, 201)
      }
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('Traffic')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '购买' }))
    let dialog = await dialogTitled('购买 Traffic')
    expect(within(dialog).getByText(/先开通 1 天，不预扣；需要在该卖家处有不少于押金 9.00 元的余额/)).toBeInTheDocument()
    expect(within(dialog).getByText('按流量 · 0.30 元 / GB 起')).toBeInTheDocument()
    expect(within(dialog).getByText(/→ 暂停调度/)).toBeInTheDocument()
    expect(within(dialog).getByText('每月可用率 ≥ 99.90%')).toBeInTheDocument()
    expect(within(dialog).getByText(/预付余额用完时：停止服务/)).toBeInTheDocument()
    expect(within(dialog).getByText(/报价第 2 版的条款/)).toBeInTheDocument()
    listing = [{ ...metered, revision: 3, pricing: { ...metered.pricing, tiers: [{ up_to_gb: 0, price_per_gb_minor: 45 }] } }]
    fireEvent.click(within(dialog).getByRole('button', { name: '确认购买' }))
    dialog = await dialogTitled('购买 Traffic')
    expect(await within(dialog).findByText(/卖家刚修改了这个报价/)).toBeInTheDocument()
    expect(within(dialog).getByText('按流量 · 0.45 元 / GB 起')).toBeInTheDocument()
    expect(within(dialog).getByText(/报价第 3 版的条款/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '确认购买' }))
    expect(await screen.findByText('已下单')).toBeInTheDocument()
    const posts = fetchMock.mock.calls.filter(([p, i]) => p === '/v1/admin/market/subscriptions' && i?.method === 'POST')
      .map(([, i]) => JSON.parse(i!.body as string) as { expected_revision: number; idempotency_key: string })
    expect(posts.map((b) => b.expected_revision)).toEqual([2, 3])
    expect(posts[1].idempotency_key).not.toBe(posts[0].idempotency_key)
  })

  it('shows the subscription terms and sets the renewal condition and selection limits on the market', async () => {
    const supply = { id: '66666666-6666-4666-8666-666666666666', name: 'HK supply', market_subscription_id: '77777777-7777-4777-8777-777777777777',
      target: 's.market.example', status: 'active', leaves: [] }
    const terms = { id: supply.market_subscription_id, buyer_id: 'b', seller_id: 's', offer_id: 'o', status: 'active', settlement_mode: 'escrow',
      renewal_price_policy: 'always', cancel_at_period_end: false, close_code: null, max_unit_price_minor: null, min_quality_score: 1.5 }
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/supplies') return json({ items: [supply] })
      if (path === `/v1/admin/market/subscriptions/${supply.market_subscription_id}`) return json(terms)
      if (path.endsWith('/renewal-policy') || path.endsWith('/selection')) return json({ status: 'ok' })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    expect(await screen.findByText('HK supply')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '订阅详情' }))
    const drawer = await screen.findByRole('dialog')
    // The drawer opens on usage (ML-12); terms are the second tab.
    fireEvent.click(await within(drawer).findByRole('tab', { name: '订阅详情' }))
    const termsPane = await within(drawer).findByRole('tabpanel', { name: '订阅详情' })
    expect(await within(termsPane).findByText('平台托管')).toBeInTheDocument()
    expect(within(termsPane).getByDisplayValue('1.5')).toBeInTheDocument()
    expect(within(termsPane).getByText('正常')).toBeInTheDocument()

    fireEvent.mouseDown(within(drawer).getByRole('combobox', { name: '续费价格条件' }))
    fireEvent.click(await screen.findByText('不高于上期价格才续'))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      `/v1/admin/market/subscriptions/${supply.market_subscription_id}/renewal-policy`, expect.objectContaining({ method: 'PUT' })))
    const [, renewalInit] = fetchMock.mock.calls.find(([path]) => path.endsWith('/renewal-policy'))!
    expect(JSON.parse(renewalInit!.body as string)).toEqual({ renewal_price_policy: 'if_lesser_or_equal' })
    expect((renewalInit!.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^renewal-policy-/)

    fireEvent.change(within(drawer).getByLabelText(/单价上限/), { target: { value: '3' } })
    fireEvent.click(within(drawer).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      `/v1/admin/market/subscriptions/${supply.market_subscription_id}/selection`, expect.objectContaining({ method: 'PUT' })))
    const [, limitsInit] = fetchMock.mock.calls.find(([path]) => path.endsWith('/selection'))!
    expect(JSON.parse(limitsInit!.body as string)).toEqual({ max_unit_price_minor: 300, min_quality_score: 1.5 })
  })

  it('discloses an upstream pause stop, the compensation rule and how the last pause was compensated (NM03)', async () => {
    const supply = { id: '66666666-6666-4666-8666-666666666666', name: 'HK supply', market_subscription_id: '77777777-7777-4777-8777-777777777777',
      target: 's.market.example', status: 'active', leaves: [] }
    const terms = { id: supply.market_subscription_id, buyer_id: 'b', seller_id: 's', offer_id: 'o', status: 'active', settlement_mode: 'direct',
      renewal_price_policy: 'always', cancel_at_period_end: false, close_code: null, max_unit_price_minor: null, min_quality_score: null,
      renewal_stop: { code: 10009, reason: 'upstream_paused', initiator: 'seller', since: '2026-10-28T00:00:00Z' },
      compensation_policy: 'upstream-pause/v1',
      upstream_pause: { id: 'p', policy_version: 'upstream-pause/v1', started_at: '2026-10-27T00:00:00Z', ended_at: '2026-10-27T02:00:00Z',
        outcome: 'extended', extended_seconds: 5400, refund_minor: 0 } }
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/supplies') return json({ items: [supply] })
      if (path === `/v1/admin/market/subscriptions/${supply.market_subscription_id}`) return json(terms)
      return json({ error: 'not_found' }, 404)
    }))
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    fireEvent.click(await screen.findByRole('button', { name: '订阅详情' }))
    const drawer = await screen.findByRole('dialog')
    // The banner says time, not cash: no "refunded" wording for an upstream pause.
    expect(await within(drawer).findByText(/本订阅已停止续费：全部供给因上游原因暂停/)).toBeInTheDocument()
    expect(within(drawer).getByText(/不退现金：暂停结束时按秒顺延到期时间/)).toBeInTheDocument()
    expect(within(drawer).queryByText(/已按秒退回你在该供货方处的余额（已扣除同期离线冲抵）/)).toBeNull()
    fireEvent.click(await within(drawer).findByRole('tab', { name: '订阅详情' }))
    const termsPane = await within(drawer).findByRole('tabpanel', { name: '订阅详情' })
    expect(await within(termsPane).findByText(/已顺延到期时间 1 小时 30 分钟/)).toBeInTheDocument()
    expect(within(termsPane).getByText(/第 1 版：你自己欠费不补/)).toBeInTheDocument()
  })

  it('does not offer a new site binding the zero-leaf supply would refuse', async () => {
    const supply = { id: '66666666-6666-4666-8666-666666666666', name: 'Empty supply', market_subscription_id: null,
      target: 's.market.example', status: 'active', leaves: [] }
    const site = '88888888-8888-4888-8888-888888888888'
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/supplies') return json({ items: [supply] })
      if (path === `/v1/admin/sites/${site}/market-supplies/${supply.id}`) return json({ error: 'no_active_leaf' }, 409)
      if (path.startsWith('/v1/sites?')) return json(siteList)
      if (path === `/v1/admin/sites/${site}/market-supplies`) return json({ items: [] })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    expect(await screen.findByText('Empty supply')).toBeInTheDocument()
    await pickSite()
    // MC05: the page no longer offers the new binding the market would refuse; the refusal stays explained.
    expect(await screen.findByRole('button', { name: '绑定到 shop.example.test' })).toBeDisabled()
    expect(fetchMock.mock.calls.some(([path]) => path.includes('/market-supplies/'))).toBe(false)
  })

  // MC12 E1: nothing bought → a short empty state pointing to buying, no ID/JSON forms to fill.
  it('shows an empty supplies page without the binding and rollout forms', async () => {
    vi.stubGlobal('fetch', vi.fn<(path: string) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/supplies') return json({ items: [] })
      return json({ error: 'not_found' }, 404)
    }))
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    expect(await screen.findByText('还没有已购供给')).toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: '站点' })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('站点 ID')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('站点配置（JSON，cdnca.market.site/v1）')).not.toBeInTheDocument()
  })

  it('points a finished purchase to its supplies', async () => {
    vi.stubGlobal('fetch', vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path, init) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/offers?limit=50') return json({ items: [offer] })
      if (path === '/v1/admin/market/subscriptions' && init?.method === 'POST') return json({ id: 's', grants: 1 }, 201)
      if (path === '/v1/admin/market/supplies') return json({ items: [] })
      return json({ error: 'not_found' }, 404)
    }))
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    fireEvent.click(await screen.findByRole('button', { name: '购买' }))
    fireEvent.click(within(await dialogTitled('购买 HK BGP')).getByRole('button', { name: '确认购买' }))
    expect(await screen.findByText('已购买「HK BGP」')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '查看已购供给' }))
    expect(await screen.findByRole('tab', { name: '已购供给与站点', selected: true })).toBeInTheDocument()
  })

  // MC05 (MK-CONTROL-NOLEAF-03): an active contract without leaves is not shown as serving and
  // offers no new binding; adjusting or unbinding an existing one stays possible (the server allows it).
  it('shows a zero-leaf supply as without supply and disables only the new binding', async () => {
    const empty = { id: '66666666-6666-4666-8666-666666666666', name: 'Empty supply', market_subscription_id: null,
      target: 's.market.example', status: 'active', leaves: [] }
    const full = { ...empty, id: '67676767-6767-4767-8767-676767676767', name: 'Full supply',
      leaves: [{ leaf_member_id: 'l', node_pool_ref: 'pa', grant_id: 'g' }] }
    let bound: unknown[] = []
    vi.stubGlobal('fetch', vi.fn<(path: string) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/supplies') return json({ items: [empty, full] })
      if (path.startsWith('/v1/sites?')) return json(siteList)
      if (path === `/v1/admin/sites/${pickedSite}/market-supplies`) return json({ items: bound })
      return json({ error: 'not_found' }, 404)
    }))
    bound = [{ supply_id: empty.id, name: 'Empty supply', role: 'primary', priority: 10, status: 'active', leaves: 0 }]
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    const emptyRow = (await screen.findByText('Empty supply')).closest('tr')!
    const fullRow = screen.getByText('Full supply').closest('tr')!
    expect(within(emptyRow).getByText('暂无可用供给')).toBeInTheDocument()
    expect(within(emptyRow).queryByText('正常')).not.toBeInTheDocument()
    expect(within(emptyRow).getByText(/新绑定暂不可用/)).toBeInTheDocument()
    await pickSite()
    // Already bound to the picked site: adjusting it stays possible, and unbinding is in the bound list.
    await waitFor(() => expect(within(emptyRow).getByRole('button', { name: '绑定到 shop.example.test' })).toBeEnabled())
    const boundList = await screen.findByRole('heading', { name: 'shop.example.test 已绑定的供给' })
    expect(boundList).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: '解绑' })).toBeEnabled()
    expect(within(fullRow).getByText('正常')).toBeInTheDocument()
    expect(within(fullRow).getByRole('button', { name: '绑定到 shop.example.test' })).toBeEnabled()
  })

  // MC06 (MK-BUYER-RESULT-01): a late preview answer belongs to the site and revision it was sent for.
  it('labels a rollout result with the site it was sent for and marks it stale once the form changes', async () => {
    const siteA = '88888888-8888-4888-8888-888888888888'
    const siteB = '99999999-9999-4999-8999-999999999999'
    let release: (r: Response) => void = () => undefined
    let sent = false
    vi.stubGlobal('fetch', vi.fn<(path: string) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/supplies') return json({ items: [{ id: '66666666-6666-4666-8666-666666666666', name: 'HK supply', market_subscription_id: null, target: 's.market.example', status: 'active', leaves: [{ leaf_member_id: 'l', node_pool_ref: 'pa', grant_id: 'g' }] }] })
      if (path === `/v1/admin/sites/${siteA}/market-rollout/preview`) { sent = true; return new Promise<Response>((resolve) => { release = resolve }) }
      return json({ error: 'not_found' }, 404)
    }))
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    fireEvent.click(await screen.findByText('高级诊断：手工填写版本号与 JSON 下发'))
    const config = await screen.findByLabelText('站点配置（JSON，cdnca.market.site/v1）')
    const siteField = screen.getByLabelText('站点 ID')
    fireEvent.change(siteField, { target: { value: siteA } })
    fireEvent.change(config, { target: { value: '{"schema":"cdnca.market.site/v1"}' } })
    fireEvent.click(screen.getByRole('button', { name: '预检' }))
    await waitFor(() => expect(sent).toBe(true))
    fireEvent.change(siteField, { target: { value: siteB } })
    await act(async () => { release(json({ revision: 1, digest: 'abcdef0123456789', applied: false,
      leaves: [{ leaf: { leaf_member_id: '12345678-0000-4000-8000-000000000000', node_pool_ref: 'pa' }, state: 'failed', error: 'leaf refused' }] })) })
    const result = await screen.findByRole('region', { name: '预检结果' })
    expect(within(result).getByText(new RegExp(siteA))).toBeInTheDocument()
    expect(within(result).getByText(/修订 1/)).toBeInTheDocument()
    expect(within(result).getByText(/已过期/)).toBeInTheDocument()
  })

  // MC12 E2: choose a saved site; the server builds the revision; apply sends the preview's site version and digest.
  it('rolls out a picked site without a revision number or JSON', async () => {
    const supply = { id: '66666666-6666-4666-8666-666666666666', name: 'HK supply', market_subscription_id: null, target: 's.market.example', status: 'active',
      leaves: [{ leaf_member_id: '12345678-0000-4000-8000-000000000000', node_pool_ref: 'pa', grant_id: 'g' }] }
    const digest = 'a'.repeat(64)
    const plan = { site_id: pickedSite, domain: 'shop.example.test', site_version: 7, revision: 3, digest, config: { schema: 'cdnca.market.site/v1' }, unsupported: [] }
    const leaves = [{ leaf: { leaf_member_id: '12345678-0000-4000-8000-000000000000', node_pool_ref: 'pa' }, state: 'applied' }]
    let bound: unknown[] = []
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path, init) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/supplies') return json({ items: [supply] })
      if (path.startsWith('/v1/sites?')) return json(siteList)
      if (path === `/v1/admin/sites/${pickedSite}/market-supplies`) return json({ items: bound })
      if (path === `/v1/admin/sites/${pickedSite}/market-supplies/${supply.id}` && init?.method === 'PUT') {
        bound = [{ supply_id: supply.id, name: 'HK supply', role: 'primary', priority: 10, status: 'active', leaves: 1 }]
        return { ok: true, status: 204, text: vi.fn().mockResolvedValue('') } as unknown as Response
      }
      if (path.endsWith('/market-rollout/site-preview')) return json({ plan, result: { revision: 3, digest, applied: false, leaves } })
      if (path.endsWith('/market-rollout/site-apply')) return json({ plan, result: { revision: 3, digest, applied: true, leaves } })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    await pickSite()
    expect(await screen.findByText('shop.example.test 还没有绑定市场供给')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '绑定到 shop.example.test' }))
    // Read back after binding, not just a toast.
    expect(await screen.findByRole('cell', { name: '主' })).toBeInTheDocument()
    const rollout = screen.getByRole('region', { name: '下发站点配置' })
    expect(within(rollout).getByRole('button', { name: '应用' })).toBeDisabled()
    fireEvent.click(within(rollout).getByRole('button', { name: '预检' }))
    expect(await within(rollout).findByText('预检通过：所有供货叶子都能接受这份配置')).toBeInTheDocument()
    const [, previewInit] = fetchMock.mock.calls.find(([path]) => path.endsWith('/site-preview'))!
    expect(JSON.parse(previewInit!.body as string)).toEqual({})
    fireEvent.click(within(rollout).getByRole('button', { name: '应用' }))
    fireEvent.click(await screen.findByRole('button', { name: /确\s*定|OK/ }))
    expect(await within(rollout).findByText('全部叶子已应用')).toBeInTheDocument()
    const [, applyInit] = fetchMock.mock.calls.find(([path]) => path.endsWith('/site-apply'))!
    expect(JSON.parse(applyInit!.body as string)).toEqual({ site_version: 7, digest })
  })

  // MC12 E2/E3: what siteconf cannot carry blocks in words; a site saved after the preview is refused and re-shown.
  it('explains blocked site settings and a site changed since the preview', async () => {
    const supply = { id: '66666666-6666-4666-8666-666666666666', name: 'HK supply', market_subscription_id: null, target: 's.market.example', status: 'active',
      leaves: [{ leaf_member_id: '12345678-0000-4000-8000-000000000000', node_pool_ref: 'pa', grant_id: 'g' }] }
    const digest = 'b'.repeat(64)
    let blocked = true
    vi.stubGlobal('fetch', vi.fn<(path: string) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/supplies') return json({ items: [supply] })
      if (path.startsWith('/v1/sites?')) return json(siteList)
      if (path === `/v1/admin/sites/${pickedSite}/market-supplies`) return json({ items: [] })
      if (path.endsWith('/site-preview')) {
        return blocked
          ? json({ plan: { site_id: pickedSite, domain: 'shop.example.test', site_version: 7, revision: 0, digest: '', config: {}, unsupported: [{ code: 'site_l2_custom' }, { code: 'brand_new_code' }] } })
          : json({ plan: { site_id: pickedSite, domain: 'shop.example.test', site_version: 7, revision: 1, digest, config: {}, unsupported: [] },
            result: { revision: 1, digest, applied: false, leaves: [{ leaf: { leaf_member_id: '12345678-0000-4000-8000-000000000000', node_pool_ref: 'pa' }, state: 'applied' }] } })
      }
      if (path.endsWith('/site-apply')) return json({ error: 'site_changed', plan: { site_id: pickedSite, domain: 'shop.example.test', site_version: 8, revision: 2, digest: 'c'.repeat(64), config: {}, unsupported: [] } }, 409)
      return json({ error: 'not_found' }, 404)
    }))
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    await pickSite()
    const rollout = await screen.findByRole('region', { name: '下发站点配置' })
    fireEvent.click(within(rollout).getByRole('button', { name: '预检' }))
    expect(await within(rollout).findByText(/站点 L2 配置选择了本平台的自定义 L2 节点/)).toBeInTheDocument()
    expect(within(rollout).getByText(/未识别的原因（brand_new_code）/)).toBeInTheDocument()
    expect(within(rollout).getByRole('button', { name: '应用' })).toBeDisabled()
    blocked = false
    fireEvent.click(within(rollout).getByRole('button', { name: '预检' }))
    await waitFor(() => expect(within(rollout).getByRole('button', { name: '应用' })).toBeEnabled())
    fireEvent.click(within(rollout).getByRole('button', { name: '应用' }))
    fireEvent.click(await screen.findByRole('button', { name: /确\s*定|OK/ }))
    expect(await within(rollout).findByText(/预检之后站点又被保存过/)).toBeInTheDocument()
    expect(within(rollout).getByText('8')).toBeInTheDocument()
    expect(within(rollout).getByRole('button', { name: '应用' })).toBeDisabled()
  })

  // fix-mktsiteconf5 (10-28 ①): a leaf that dropped a conditional origin rule
  // with no node in that location says so in the leaf result; it is advisory,
  // so the site can still be applied.
  it('shows the leaf hint for a conditional origin rule without nodes in that location', async () => {
    const supply = { id: '66666666-6666-4666-8666-666666666666', name: 'HK supply', market_subscription_id: null, target: 's.market.example', status: 'active',
      leaves: [{ leaf_member_id: '12345678-0000-4000-8000-000000000000', node_pool_ref: 'pa', grant_id: 'g' }] }
    const digest = 'd'.repeat(64)
    const plan = { site_id: pickedSite, domain: 'shop.example.test', site_version: 7, revision: 2, digest, config: {}, unsupported: [] }
    const leaves = [{ leaf: { leaf_member_id: '12345678-0000-4000-8000-000000000000', node_pool_ref: 'pa' }, state: 'applied',
      blockers: [{ code: 'origin_route_geo_unmatched', detail: 'route-cn-gd' }] }]
    vi.stubGlobal('fetch', vi.fn<(path: string) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/supplies') return json({ items: [supply] })
      if (path.startsWith('/v1/sites?')) return json(siteList)
      if (path === `/v1/admin/sites/${pickedSite}/market-supplies`) return json({ items: [] })
      if (path.endsWith('/site-preview')) return json({ plan, result: { revision: 2, digest, applied: false, leaves } })
      return json({ error: 'not_found' }, 404)
    }))
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    await pickSite()
    const rollout = await screen.findByRole('region', { name: '下发站点配置' })
    fireEvent.click(within(rollout).getByRole('button', { name: '预检' }))
    expect(await within(rollout).findByText(/该供给没有对应地区的节点，此条件回源规则在该供给上不生效（route-cn-gd）/)).toBeInTheDocument()
    expect(within(rollout).getByRole('button', { name: '应用' })).toBeEnabled()
  })

  // fix-mktsiteconf6: the leaf sends origin auth credentials to its nodes by
  // itself; a delivery still waiting reads as words with its reason.
  it('shows a leaf origin auth delivery that has not reached its nodes', async () => {
    const supply = { id: '66666666-6666-4666-8666-666666666666', name: 'HK supply', market_subscription_id: null, target: 's.market.example', status: 'active',
      leaves: [{ leaf_member_id: '12345678-0000-4000-8000-000000000000', node_pool_ref: 'pa', grant_id: 'g' }] }
    const digest = 'e'.repeat(64)
    const plan = { site_id: pickedSite, domain: 'shop.example.test', site_version: 7, revision: 3, digest, config: {}, unsupported: [] }
    const leaves = [{ leaf: { leaf_member_id: '12345678-0000-4000-8000-000000000000', node_pool_ref: 'pa' }, state: 'applied',
      blockers: [{ code: 'origin_auth_delivery', detail: 'waiting_nodes' }] }]
    vi.stubGlobal('fetch', vi.fn<(path: string) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/supplies') return json({ items: [supply] })
      if (path.startsWith('/v1/sites?')) return json(siteList)
      if (path === `/v1/admin/sites/${pickedSite}/market-supplies`) return json({ items: [] })
      if (path.endsWith('/site-preview')) return json({ plan, result: { revision: 3, digest, applied: false, leaves } })
      return json({ error: 'not_found' }, 404)
    }))
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    await pickSite()
    const rollout = await screen.findByRole('region', { name: '下发站点配置' })
    fireEvent.click(within(rollout).getByRole('button', { name: '预检' }))
    expect(await within(rollout).findByText(/回源鉴权凭据还没有送达供货方节点.*（部分供货方节点离线或尚未就绪，上线后自动送达）/)).toBeInTheDocument()
    expect(within(rollout).queryByText(/waiting_nodes/)).not.toBeInTheDocument()
    expect(within(rollout).getByRole('button', { name: '应用' })).toBeEnabled()
  })

  // fix-mktsiteconf7 §1/§3: after an apply each leaf reads 已应用 → 送达节点中 →
  // 已在节点生效 / 部分失败（原因）from the subscriber's saved checks; the reason
  // wraps in two lines with an expand control instead of a horizontal scroll.
  it('follows each applied leaf to its nodes and wraps the reason', async () => {
    const member = '12345678-0000-4000-8000-000000000000'
    const supply = { id: '66666666-6666-4666-8666-666666666666', name: 'HK supply', market_subscription_id: null, target: 's.market.example', status: 'active',
      leaves: [{ leaf_member_id: member, node_pool_ref: 'pa', grant_id: 'g' }] }
    const digest = 'f'.repeat(64)
    const plan = { site_id: pickedSite, domain: 'shop.example.test', site_version: 7, revision: 4, digest, config: {}, unsupported: [] }
    const leaves = [{ leaf: { leaf_member_id: member, node_pool_ref: 'pa' }, state: 'applied' }]
    const status = (node: Record<string, string>) => ({ items: [{ supply_id: supply.id, leaf: { leaf_member_id: member, node_pool_ref: 'pa', grant_id: 'g' },
      state: 'applied', revision: 4, node, updated_at: '2026-10-28T07:00:00Z' }] })
    let node: Record<string, string> = { state: 'delivering', reason: 'site_syncing' }
    vi.stubGlobal('fetch', vi.fn<(path: string) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/supplies') return json({ items: [supply] })
      if (path.startsWith('/v1/sites?')) return json(siteList)
      if (path === `/v1/admin/sites/${pickedSite}/market-supplies`) return json({ items: [] })
      if (path.endsWith('/site-preview')) return json({ plan, result: { revision: 4, digest, applied: false, leaves } })
      if (path.endsWith('/site-apply')) return json({ plan, result: { revision: 4, digest, applied: true, leaves } })
      if (path === `/v1/admin/sites/${pickedSite}/market-rollout/leaves`) return json(status(node))
      return json({ error: 'not_found' }, 404)
    }))
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    await pickSite()
    const rollout = await screen.findByRole('region', { name: '下发站点配置' })
    fireEvent.click(within(rollout).getByRole('button', { name: '预检' }))
    await waitFor(() => expect(within(rollout).getByRole('button', { name: '应用' })).toBeEnabled())
    // A preview has nothing on the nodes yet.
    expect(within(rollout).queryByText('送达节点中')).not.toBeInTheDocument()
    fireEvent.click(within(rollout).getByRole('button', { name: '应用' }))
    fireEvent.click(await screen.findByRole('button', { name: /确\s*定|OK/ }))
    expect(await within(rollout).findByText('送达节点中')).toBeInTheDocument()
    expect(within(rollout).getByText('已应用')).toBeInTheDocument()
    expect(within(rollout).getByText(/供货方正在把站点同步到节点/)).toBeInTheDocument()

    node = { state: 'failed', reason: 'security_failed', detail: 'waf:candidate_rejected', checked_at: '2026-10-28T07:05:00Z' }
    fireEvent.click(within(rollout).getByRole('button', { name: '刷新送达状态' }))
    expect(await within(rollout).findByText('部分失败')).toBeInTheDocument()
    const reason = within(rollout).getByText(/安全策略在供货方节点上激活失败（waf:candidate_rejected）/)
    expect(within(rollout).queryByText('送达节点中')).not.toBeInTheDocument()
    // §3: the reason column wraps (two lines, then expand); no horizontal scroll.
    const clamp = reason.closest('[data-clamp]') as HTMLElement
    expect(clamp.style.whiteSpace).toBe('normal')
    expect(clamp.dataset.clamp).toBe('2')
    expect(rollout.querySelector('.ant-table-content table')?.getAttribute('style') ?? '').not.toMatch(/max-content/)

    node = { state: 'effective', checked_at: '2026-10-28T07:06:00Z' }
    fireEvent.click(within(rollout).getByRole('button', { name: '刷新送达状态' }))
    expect(await within(rollout).findByText('已在节点生效')).toBeInTheDocument()
  })

  // fix-mktsiteconf7 §3: a reason longer than two lines opens and closes in place.
  it('expands a long leaf reason in place', async () => {
    const heights = vi.spyOn(HTMLElement.prototype, 'scrollHeight', 'get').mockReturnValue(120)
    const clients = vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockReturnValue(44)
    try {
      const supply = { id: '66666666-6666-4666-8666-666666666666', name: 'HK supply', market_subscription_id: null, target: 's.market.example', status: 'active',
        leaves: [{ leaf_member_id: '12345678-0000-4000-8000-000000000000', node_pool_ref: 'pa', grant_id: 'g' }] }
      const digest = 'd'.repeat(64)
      const plan = { site_id: pickedSite, domain: 'shop.example.test', site_version: 7, revision: 2, digest, config: {}, unsupported: [] }
      const leaves = [{ leaf: { leaf_member_id: '12345678-0000-4000-8000-000000000000', node_pool_ref: 'pa' }, state: 'applied',
        blockers: [{ code: 'origin_route_geo_unmatched', detail: 'route-cn-gd' }, { code: 'origin_auth_delivery', detail: 'waiting_nodes' }] }]
      vi.stubGlobal('fetch', vi.fn<(path: string) => Promise<Response>>(async (path) => {
        if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
        if (path === '/v1/admin/market/supplies') return json({ items: [supply] })
        if (path.startsWith('/v1/sites?')) return json(siteList)
        if (path === `/v1/admin/sites/${pickedSite}/market-supplies`) return json({ items: [] })
        if (path.endsWith('/site-preview')) return json({ plan, result: { revision: 2, digest, applied: false, leaves } })
        return json({ error: 'not_found' }, 404)
      }))
      renderWithProviders(<NodeMarketPage />)
      fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
      await pickSite()
      const rollout = await screen.findByRole('region', { name: '下发站点配置' })
      fireEvent.click(within(rollout).getByRole('button', { name: '预检' }))
      const more = await within(rollout).findByRole('button', { name: '展开' })
      const clamp = rollout.querySelector('[data-clamp]') as HTMLElement
      expect(more).toHaveAttribute('aria-expanded', 'false')
      fireEvent.click(more)
      expect(clamp.dataset.clamp).toBe('open')
      expect(within(rollout).getByRole('button', { name: '收起' })).toHaveAttribute('aria-expanded', 'true')
    } finally {
      heights.mockRestore()
      clients.mockRestore()
    }
  })

  // MC12 E3: close codes read as words in the subscription record; the number stays copyable.
  it('shows a subscription close reason in words', async () => {
    const supply = { id: '66666666-6666-4666-8666-666666666666', name: 'HK supply', market_subscription_id: '77777777-7777-4777-8777-777777777777',
      target: 's.market.example', status: 'active', leaves: [] }
    const terms = { id: supply.market_subscription_id, buyer_id: 'b', seller_id: 's', offer_id: 'o', status: 'cancelled', settlement_mode: 'escrow',
      renewal_price_policy: 'always', cancel_at_period_end: false, close_code: 20002, close_initiator: 'system', max_unit_price_minor: null, min_quality_score: null }
    vi.stubGlobal('fetch', vi.fn<(path: string) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/supplies') return json({ items: [supply] })
      if (path === `/v1/admin/market/subscriptions/${supply.market_subscription_id}`) return json(terms)
      return json({ error: 'not_found' }, 404)
    }))
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    expect(screen.queryByText(/关闭原因码：1–9999/)).not.toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: '订阅详情' }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.click(await within(drawer).findByRole('tab', { name: '订阅详情' }))
    expect(await within(drawer).findByText(/连续违反 SLA/)).toBeInTheDocument()
    expect(within(drawer).getByText('20002')).toBeInTheDocument()
  })

  it('reports usage statements the market does not offer yet', async () => {
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path.startsWith('/v1/admin/market/usage-statements')) return json({ error: 'market_feature_unavailable' }, 501)
      return json({ items: [] })
    }))
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '用量确认单' }))
    expect(await screen.findByText('市场端还没有开放这个功能，市场升级后自动可用。')).toBeInTheDocument()
  })

  it('lists disputes of both markets with filters and paging', async () => {
    const pluginDispute = { id: '88888888-8888-4888-8888-888888888888', subject_kind: 'order', market: 'plugin',
      subject_id: '99999999-9999-4999-8999-999999999999', state: 'awaiting_seller', amount_minor: 500, held_minor: 450,
      reason_code: 'not_working', waiting_on: 'seller', escalations: 1, opened_at: '2026-10-16T01:00:00Z' }
    const statementDispute = { ...pluginDispute, id: '77777777-7777-4777-8777-777777777777', subject_kind: 'usage_statement',
      market: undefined, state: 'resolved_buyer', escalations: 0, refund_id: '66666666-6666-4666-8666-666666666666' }
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/disputes?limit=50') return json({ items: [pluginDispute, statementDispute], next_cursor: 'c2' })
      if (path.startsWith('/v1/admin/market/disputes?')) return json({ items: [statementDispute], next_cursor: null })
      if (path.endsWith('/withdraw')) return json({ ...pluginDispute, state: 'withdrawn' })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '争议' }))
    expect(await screen.findByText('插件订单')).toBeInTheDocument()
    expect(screen.queryByText('市场端还没有开放这个功能，市场升级后自动可用。')).not.toBeInTheDocument()
    expect(screen.getByText('已追加 1 次')).toBeInTheDocument()
    const pluginRow = screen.getByText('插件订单').closest('tr')!
    expect(within(pluginRow).getByText('4.50')).toBeInTheDocument()
    expect(within(pluginRow).getByText('卖方')).toBeInTheDocument()
    expect(screen.getByText('已退款')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: '撤诉' })).toHaveLength(1)

    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/disputes?cursor=c2&limit=50', expect.anything()))
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '对象' }))
    fireEvent.click(await screen.findByText('全部订单'))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/disputes?subject_kind=order&limit=50', expect.anything()))

    fireEvent.mouseDown(screen.getByRole('combobox', { name: '对象' }))
    fireEvent.click(await screen.findByTitle('插件订单'))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/disputes?subject_kind=plugin_order&limit=50', expect.anything()))
  })

  it('withdraws an open dispute with an Idempotency-Key', async () => {
    const dispute = { id: '88888888-8888-4888-8888-888888888888', subject_kind: 'order', market: 'node',
      subject_id: '99999999-9999-4999-8999-999999999999', state: 'under_review', amount_minor: 500, reason_code: 'x' }
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path.startsWith('/v1/admin/market/disputes?')) return json({ items: [dispute], next_cursor: null })
      if (path.endsWith('/withdraw')) return json({ ...dispute, state: 'withdrawn' })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '争议' }))
    expect(await screen.findByText('节点订单')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '撤诉' }))
    fireEvent.click(await screen.findByRole('button', { name: 'OK' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/admin/market/disputes/${dispute.id}/withdraw`,
      expect.objectContaining({ method: 'POST' })))
    const [, init] = fetchMock.mock.calls.find(([path]) => path.endsWith('/withdraw'))!
    expect((init!.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^dispute-withdraw-/)
  })

  it('tops up the market prepaid balance through the portal checkout', async () => {
    const open = vi.fn()
    vi.stubGlobal('open', open)
    let attempt = 0
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/orders') return ++attempt === 1 ? json({ error: 'unavailable' }, 503)
        : json({ order: { id: 'o', order_no: 2001, market: 'platform', kind: 'topup_prepaid', seller_id: null, amount_minor: 5000,
          currency: 'CNY', settlement_mode: 'escrow', status: 'awaiting_payment', created_at: 'x' }, checkout_url: 'https://portal.example/c/t1' }, 201)
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '收款与余额' }))
    fireEvent.change(await screen.findByLabelText('金额（元）'), { target: { value: '50' } })
    fireEvent.click(screen.getByRole('button', { name: '充值' }))
    expect(await screen.findByText('平台尚未开启托管收款，暂时不能充值')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '充值' }))
    await waitFor(() => expect(open).toHaveBeenCalledWith('https://portal.example/c/t1', '_blank', 'noopener,noreferrer'))
    expect(await screen.findByText(/充值单 2001 已创建/)).toBeInTheDocument()
    const calls = fetchMock.mock.calls.filter(([path]) => path === '/v1/admin/market/orders')
    expect(JSON.parse(calls[1][1]!.body as string)).toEqual({ kind: 'prepaid_topup', amount_minor: 5000, currency: 'CNY' })
    expect((calls[1][1]!.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^prepaid-topup-/)
  })

  it('shows a browse-only administrator no buy, sell or site controls', async () => {
    const viewer = principal({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['marketplace.browse'] })
    useSessionStore.getState().setSession({ ...authResponse(viewer), access_token: 'v' }, viewer)
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path.startsWith('/v1/admin/market/offers')) return json({ items: [offer] })
      return json({ items: [] })
    }))
    renderWithProviders(<NodeMarketPage />)
    expect(screen.queryByRole('tab', { name: '我的上架' })).not.toBeInTheDocument()
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '购买' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: '已购供给与站点' }))
    await waitFor(() => expect(screen.queryByPlaceholderText('站点 ID')).not.toBeInTheDocument())
    expect(screen.queryByText('下发站点配置')).not.toBeInTheDocument()
  })

  it('edits the SLA of an own offer through the terms endpoint with the pricing unchanged', async () => {
    const own = { ...offer, id: '99999999-9999-4999-8999-999999999999', name: 'SG CN2', status: 'listed', revision: 4,
      pricing: { currency: 'CNY', daily_minor: 300, min_days: 1, max_days: 30 },
      sla: { availability_target: 0.995, measure_window: 'month', credit_schedule: [{ below: 0.99, credit_percent: 20 }],
        daily_penalty_minor: 0, max_credit_percent: 50, terminate_after: 2 } }
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/offers?mine=1') return json({ items: [own] })
      if (path.endsWith('/terms')) return json({ ...own, revision: 2 })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的上架' }))
    expect(await screen.findByText('每月可用率 ≥ 99.50%')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'SLA 设置' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByLabelText('承诺可用率（%）')).toHaveValue('99.50')
    expect(within(dialog).getByLabelText('可用率低于（%） 1')).toHaveValue('99.00')
    // A tier above the commitment is refused before any request.
    fireEvent.change(within(dialog).getByLabelText('可用率低于（%） 1'), { target: { value: '99.8' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(await within(dialog).findByText(/每档的可用率线要低于承诺值/)).toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([path]) => path.endsWith('/terms'))).toBe(false)
    fireEvent.change(within(dialog).getByLabelText('可用率低于（%） 1'), { target: { value: '99' } })
    fireEvent.change(within(dialog).getByLabelText('承诺可用率（%）'), { target: { value: '99.9' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/admin/market/offers/${own.id}/terms`, expect.objectContaining({ method: 'PUT' })))
    const [, init] = fetchMock.mock.calls.find(([path]) => path.endsWith('/terms'))!
    expect(JSON.parse(init!.body as string)).toEqual({ pricing: own.pricing, expected_revision: 4, sla: { availability_target: 0.999, measure_window: 'month',
      daily_penalty_minor: 0, max_credit_percent: 50, terminate_after: 2, credit_schedule: [{ below: 0.99, credit_percent: 20 }] } })
    expect((init!.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^offer-terms-/)
  })

  it('refuses to overwrite a price changed elsewhere and tells the seller to reopen (card 11)', async () => {
    const own = { ...offer, id: '99999999-9999-4999-8999-999999999999', name: 'SG CN2', status: 'listed', revision: 4,
      pricing: { currency: 'CNY', daily_minor: 300, min_days: 1, max_days: 30 } }
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/offers?mine=1') return json({ items: [own] })
      if (path.endsWith('/terms')) return json({ error: 'offer_changed' }, 409)
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '我的上架' }))
    fireEvent.click(await screen.findByRole('button', { name: 'SLA 设置' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(await screen.findByText('报价已在别处修改（价格或开关），请关闭后重新打开再保存')).toBeInTheDocument()
    const [, init] = fetchMock.mock.calls.find(([path]) => path.endsWith('/terms'))!
    expect(JSON.parse(init!.body as string)).toMatchObject({ expected_revision: 4 })
  })

  it('asks for the site ID instead of throwing when the rollout preview has none (E3)', async () => {
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/supplies') return json({ items: [{ id: '66666666-6666-4666-8666-666666666666', name: 'HK supply', market_subscription_id: null, target: 's.market.example', status: 'active', leaves: [{ leaf_member_id: 'l', node_pool_ref: 'pa', grant_id: 'g' }] }] })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    fireEvent.click(await screen.findByText('高级诊断：手工填写版本号与 JSON 下发'))
    fireEvent.click(await screen.findByRole('button', { name: '预检' }))
    expect(await screen.findByText('请填写站点 ID')).toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([path]) => path.includes('market-rollout'))).toBe(false)
  })

  // MKT-RESP-02: a direct statement dispute only marks the statement; the page says so.
  it('explains that a direct statement dispute freezes and refunds nothing', async () => {
    const statement = { id: '99999999-9999-4999-8999-999999999999', subscription_id: 's', period_start: '2026-10-20T00:00:00Z',
      period_end: '2026-10-21T00:00:00Z', bytes_out: 10, amount_minor: 200, settlement_mode: 'direct', status: 'issued' }
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path, init) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path.startsWith('/v1/admin/market/usage-statements') && init?.method === 'POST') return json({ statement: { ...statement, status: 'disputed' }, dispute: null })
      if (path.startsWith('/v1/admin/market/usage-statements')) return json({ items: [statement] })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '用量确认单' }))
    fireEvent.click(await screen.findByRole('button', { name: '发起争议' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/平台不经手、不冻结也不退款/)).toBeInTheDocument()
    fireEvent.change(within(dialog).getByLabelText('争议说明'), { target: { value: '流量不对' } })
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|OK/ }))
    expect(await screen.findByText(/已标记为争议中（直结/)).toBeInTheDocument()
  })

  // S6: the config starts empty (the example is only a placeholder), so a
  // placeholder origin such as 203.0.113.10 can never be applied by accident.
  it('does not prefill the rollout config and refuses an empty one', async () => {
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/supplies') return json({ items: [{ id: '66666666-6666-4666-8666-666666666666', name: 'HK supply', market_subscription_id: null, target: 's.market.example', status: 'active', leaves: [{ leaf_member_id: 'l', node_pool_ref: 'pa', grant_id: 'g' }] }] })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    fireEvent.click(await screen.findByText('高级诊断：手工填写版本号与 JSON 下发'))
    const config = await screen.findByLabelText('站点配置（JSON，cdnca.market.site/v1）')
    expect((config as HTMLTextAreaElement).value).toBe('')
    expect((config as HTMLTextAreaElement).value).not.toContain('203.0.113.10')
    expect(config.getAttribute('placeholder')).toContain('<你的源站地址>')
    fireEvent.change(screen.getAllByLabelText('站点 ID').at(-1)!, { target: { value: '88888888-8888-4888-8888-888888888888' } })
    fireEvent.click(screen.getByRole('button', { name: '预检' }))
    expect(await screen.findByText('请填写站点配置')).toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([path]) => path.includes('market-rollout'))).toBe(false)
  })

  // CORE-RECEIPT-02 / CORE-REV-01: a 202 receipt_pending is neither applied
  // nor failed, and a revision conflict tells the user to reload and resave.
  it.each([
    [() => json({ revision: 2, digest: 'd', applied: false, reason: 'receipt_pending',
      leaves: [{ leaf: { leaf_member_id: 'aaaaaaaa-0000-4000-8000-000000000000', node_pool_ref: 'p' }, state: 'receipt_pending', error: 'receipt not saved' }] }, 202),
      // fix-cfgflow2 §2: the controller confirms it in the background.
      /叶子已答复，但本机未能保存结果，状态待确认。后台会自动对账/, '待确认'],
    [() => json({ error: 'revision_conflict' }, 409), /该版本号已下发过另一份配置/, null],
  ])('explains a rollout that is pending or conflicts (%#)', async (reply, message, state) => {
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      // MC12: the manual rollout shows once the controller has a supply.
      if (path === '/v1/admin/market/supplies') return json({ items: [{ id: '66666666-6666-4666-8666-666666666666', name: 'HK supply', market_subscription_id: null, target: 's.market.example', status: 'active', leaves: [{ leaf_member_id: 'l', node_pool_ref: 'pa', grant_id: 'g' }] }] })
      if (path.includes('market-rollout/preview')) return reply()
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    // The manual form sits under advanced diagnostics (MC12 E2), as above.
    fireEvent.click(await screen.findByText('高级诊断：手工填写版本号与 JSON 下发'))
    fireEvent.change((await screen.findAllByLabelText('站点 ID')).at(-1)!, { target: { value: '88888888-8888-4888-8888-888888888888' } })
    fireEvent.change(await screen.findByLabelText('站点配置（JSON，cdnca.market.site/v1）'), { target: { value: '{"schema":"x"}' } })
    fireEvent.click(screen.getByRole('button', { name: '预检' }))
    expect(await screen.findByText(message, undefined, { timeout: 3000 })).toBeInTheDocument()
    if (state) expect(screen.getByText(state)).toBeInTheDocument()
  })

  it('shows only the not-connected notice and sends no tab requests when the market runtime is off (W3)', async () => {
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async () =>
      ({ ok: false, status: 404, text: vi.fn().mockResolvedValue('404 page not found\n') }) as unknown as Response)
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    expect(await screen.findByText(/本机尚未接入市场/)).toBeInTheDocument()
    // Codex 复查卡 47：不再指向不存在的开关，给“重新检测”
    expect(screen.queryByText(/开启市场运行时/)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重新检测' })).toBeInTheDocument()
    expect(screen.queryByRole('tab')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /全选当前筛选/ })).not.toBeInTheDocument()
    expect(fetchMock.mock.calls.map(([path]) => path)).toEqual(['/v1/admin/market/member'])
  })

  // MC04 (NM05): a failed read is a read failure with a retry, not "not joined" nor an empty list.
  it('reports a failing member read as a read failure with a retry, not as not joined', async () => {
    let member = 0
    const fetchMock = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return ++member <= 2 ? json({ error: 'market_unavailable' }, 502)
        : json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/offers?limit=50') return json({ items: [offer] })
      return json({ error: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    expect(await screen.findByText(/市场身份读取失败/)).toBeInTheDocument()
    expect(screen.queryByText(/本机尚未接入市场/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('正常', { selector: '.site-tab-summary-value' })).toBeInTheDocument()
    expect(screen.queryByText(/市场身份读取失败/)).not.toBeInTheDocument()
  })

  it('says not registered only when the market says so', async () => {
    vi.stubGlobal('fetch', vi.fn<(path: string) => Promise<Response>>(async (path) =>
      path === '/v1/admin/market/member' ? json({ error: 'not_registered' }, 403) : json({ error: 'not_found' }, 404)))
    renderWithProviders(<NodeMarketPage />)
    expect(await screen.findByText(/本机尚未在市场注册/)).toBeInTheDocument()
    expect(screen.queryByText(/市场身份读取失败/)).not.toBeInTheDocument()
  })

  it('shows a failing supplies read as an error with a retry, not as an empty list', async () => {
    let supplies = 0
    vi.stubGlobal('fetch', vi.fn<(path: string) => Promise<Response>>(async (path) => {
      if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
      if (path === '/v1/admin/market/supplies') return ++supplies === 1 ? json({ error: 'market_unavailable' }, 502) : json({ items: [] })
      return json({ error: 'not_found' }, 404)
    }))
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    expect(await screen.findByText(/已购供给读取失败（market_unavailable）/)).toBeInTheDocument()
    expect(screen.getByText('已购供给读取失败')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '重试' }))
    await waitFor(() => expect(screen.queryByText(/已购供给读取失败/)).not.toBeInTheDocument())
  })

  it('refuses tenant users', () => {
    const tenant = principal({ scope_kind: 'tenant' })
    useSessionStore.getState().setSession({ ...authResponse(tenant), access_token: 'x' }, tenant)
    renderWithProviders(<NodeMarketPage />)
    expect(screen.getByText('需要平台管理员权限')).toBeInTheDocument()
  })
})

// fix-mktui: nine sections in three groups, membership as a summary strip, section kept in ?tab=.
describe('node market layout', () => {
  it('groups the sections, shows the membership strip and keeps the section in the URL', async () => {
    const seller = principal({ scope_kind: 'platform', tenant_id: null, roles: [], permissions: ['marketplace.browse', 'marketplace.sell', 'marketplace.purchase'] })
    useSessionStore.getState().setSession({ ...authResponse(seller), access_token: 'market-token' }, seller)
    vi.stubGlobal('fetch', vi.fn(async (path: string) => path === '/v1/admin/market/member'
      ? json({ id: 'abcdef12-0000-4000-8000-000000000000', display_name: 'me', status: 'active', features: ['market.participate'], offers_quota: 0 })
      : json({ items: [], next_cursor: null })))
    renderWithProviders(<NodeMarketPage />)
    const nav = await screen.findByRole('navigation', { name: '节点市场分区' })
    for (const group of ['买节点', '卖节点', '资金与争议']) expect(within(nav).getByText(group)).toBeInTheDocument()
    expect(within(nav).queryByRole('tab', { name: '市场身份' })).toBeNull()
    const strip = screen.getByRole('region', { name: '本机市场身份' })
    expect(await within(strip).findByText('未开通')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '浏览与购买' })).toHaveAttribute('aria-selected', 'true')
    fireEvent.click(screen.getByRole('tab', { name: '争议' }))
    expect(screen.getByRole('tab', { name: '争议' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tabpanel')).toHaveAccessibleName('争议')
  })
})
