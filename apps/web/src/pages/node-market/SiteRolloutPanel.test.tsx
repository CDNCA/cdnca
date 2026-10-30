import { StrictMode, useState } from 'react'
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { useLocation, useNavigate } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../../api/auth'
import { marketApi, type MarketSiteRollout } from '../../api/market'
import { sitesApi } from '../../api/sites'
import { useSessionStore } from '../../auth/session'
import '../../i18n/nodeMarket'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import NodeMarketPage from './NodeMarketPage'
import { SiteRollout, type PickedSite } from './SiteRolloutPanel'

// MC06 (MK-BUYER-RESULT-01, 10-28 review §7): the ordinary rollout freezes the
// account, site, version, digest and sequence of each request; results, errors
// and the apply confirmation belong to that snapshot only. P01–P03 are the
// review's probes (output/ecosystem-closure-20261028/market/probes/site-owner.test.tsx).

const siteA: PickedSite = { id: '11111111-1111-4111-8111-111111111111', domain: 'a.example.test' }
const siteB: PickedSite = { id: '22222222-2222-4222-8222-222222222222', domain: 'b.example.test' }
const digest = 'a'.repeat(64)

function result(site: PickedSite, version = 7, siteID = site.id): MarketSiteRollout {
  return {
    plan: { site_id: siteID, domain: site.domain, site_version: version, revision: 2, digest, config: {}, unsupported: [] },
    result: { revision: 2, digest, applied: false, leaves: [
      { leaf: { leaf_member_id: '33333333-3333-4333-8333-333333333333', node_pool_ref: 'pool' }, state: 'applied' },
    ] },
  }
}

const owner = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['sites.manage', 'sites.read'] })
const other = principal({ user_id: '44444444-4444-4444-8444-444444444444', scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'],
  permissions: ['sites.manage', 'sites.read'] })

function Harness() {
  const [site, setSite] = useState(siteA)
  return <>
    <button onClick={() => setSite(siteB)}>switch to B</button>
    <button onClick={() => setSite(siteA)}>switch to A</button>
    <button onClick={() => useSessionStore.getState().setSession(authResponse(other), other)}>switch account</button>
    <SiteRollout site={site} />
  </>
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}

// Lets the settled request's callbacks and the re-render run before asserting.
const settle = () => act(() => new Promise<void>((done) => setTimeout(done, 20)))
const previewButton = () => screen.getByRole('button', { name: /预检/ })
const applyButton = () => screen.getByRole('button', { name: '应用' })
const shownSite = (domain: string) => screen.queryByText(domain, { selector: '.ant-descriptions-item-content' })

async function openConfirmation() {
  fireEvent.click(previewButton())
  await waitFor(() => expect(applyButton()).toBeEnabled())
  fireEvent.click(applyButton())
  return screen.findByRole('dialog')
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

// The page's own member/prepaid reads; everything else the test spies on.
function stubMarketPage() {
  vi.stubGlobal('fetch', vi.fn(async (path: string) => {
    if (path === '/v1/admin/market/member') return json({ id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
    if (path === '/v1/admin/market/prepaid?currency=CNY') return json({ currency: 'CNY', balance_minor: 0, arrears_minor: 0, overdraft_cap_minor: 0,
      alert_minor: 0, spent_24h_minor: 0, sellers: [] })
    if (path === '/v1/admin/market/direct-pay/sellers') return json({ items: [] })
    return json({ error: 'not_found' }, 404)
  }))
}

async function previewPending(preview: { mock: { calls: unknown[][] } }, site: PickedSite) {
  fireEvent.click(previewButton())
  await waitFor(() => expect(preview).toHaveBeenLastCalledWith(expect.any(String), site.id))
}

beforeEach(() => { useSessionStore.getState().setSession(authResponse(owner), owner) })
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

describe('MC06 site rollout keeps each answer with its own request', () => {
  it('P01: a preview of the unchanged site enables apply', async () => {
    const preview = vi.spyOn(marketApi, 'sitePreview').mockResolvedValue(result(siteA))
    renderWithProviders(<Harness />)
    fireEvent.click(previewButton())
    await waitFor(() => expect(preview).toHaveBeenCalledWith(expect.any(String), siteA.id))
    expect(await screen.findByText(siteA.domain, { selector: '.ant-descriptions-item-content' })).toBeInTheDocument()
    expect(applyButton()).toBeEnabled()
  })

  it('P02: a late A preview does not show or enable apply under B', async () => {
    const late = deferred<MarketSiteRollout>()
    const preview = vi.spyOn(marketApi, 'sitePreview').mockReturnValue(late.promise)
    renderWithProviders(<Harness />)
    await previewPending(preview, siteA)
    fireEvent.click(screen.getByRole('button', { name: 'switch to B' }))
    await act(async () => late.resolve(result(siteA)))
    await settle()
    expect(shownSite(siteA.domain)).not.toBeInTheDocument()
    expect(applyButton()).toBeDisabled()
  })

  it('P03: a late A error is not shown as a B failure', async () => {
    const late = deferred<MarketSiteRollout>()
    const preview = vi.spyOn(marketApi, 'sitePreview').mockReturnValue(late.promise)
    renderWithProviders(<Harness />)
    await previewPending(preview, siteA)
    fireEvent.click(screen.getByRole('button', { name: 'switch to B' }))
    await act(async () => late.reject(new ApiError('synthetic failure', 503, 'request_failed')))
    await settle()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.queryByText(/预检失败/)).not.toBeInTheDocument()
  })

  it('A→B→A: the answer to the A request sent before the switch does not come back', async () => {
    const late = deferred<MarketSiteRollout>()
    const preview = vi.spyOn(marketApi, 'sitePreview').mockReturnValue(late.promise)
    renderWithProviders(<Harness />)
    await previewPending(preview, siteA)
    fireEvent.click(screen.getByRole('button', { name: 'switch to B' }))
    fireEvent.click(screen.getByRole('button', { name: 'switch to A' }))
    await act(async () => late.resolve(result(siteA)))
    await settle()
    expect(shownSite(siteA.domain)).not.toBeInTheDocument()
    expect(applyButton()).toBeDisabled()
  })

  it('a finished A result is dropped on switching away, so returning to A asks for a new preview', async () => {
    vi.spyOn(marketApi, 'sitePreview').mockResolvedValue(result(siteA))
    renderWithProviders(<Harness />)
    fireEvent.click(previewButton())
    expect(await screen.findByText(siteA.domain, { selector: '.ant-descriptions-item-content' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'switch to B' }))
    fireEvent.click(screen.getByRole('button', { name: 'switch to A' }))
    expect(shownSite(siteA.domain)).not.toBeInTheDocument()
    expect(applyButton()).toBeDisabled()
  })

  // The preview button is busy while its request runs, so a second preview of the same site goes out only after
  // switching away and back; the first answer then arrives after the second.
  it('same site, two previews out of order: only the latest answer counts', async () => {
    const first = deferred<MarketSiteRollout>()
    const preview = vi.spyOn(marketApi, 'sitePreview').mockReturnValueOnce(first.promise).mockResolvedValueOnce(result(siteA, 8))
    renderWithProviders(<Harness />)
    await previewPending(preview, siteA)
    fireEvent.click(screen.getByRole('button', { name: 'switch to B' }))
    fireEvent.click(screen.getByRole('button', { name: 'switch to A' }))
    fireEvent.click(previewButton())
    expect(await screen.findByText('8', { selector: '.ant-descriptions-item-content' })).toBeInTheDocument()
    await act(async () => first.resolve(result(siteA, 7)))
    await settle()
    expect(screen.getByText('8', { selector: '.ant-descriptions-item-content' })).toBeInTheDocument()
    expect(screen.queryByText('7', { selector: '.ant-descriptions-item-content' })).not.toBeInTheDocument()
  })

  it('an answer whose plan names another site is refused, not shown as this one', async () => {
    vi.spyOn(marketApi, 'sitePreview').mockResolvedValue(result(siteA, 7, siteB.id))
    renderWithProviders(<Harness />)
    fireEvent.click(previewButton())
    expect(await screen.findByRole('alert')).toHaveTextContent('不是本次所选站点')
    expect(applyButton()).toBeDisabled()
  })

  it('switching site while the apply confirmation is open closes it and sends nothing', async () => {
    vi.spyOn(marketApi, 'sitePreview').mockResolvedValue(result(siteA))
    const apply = vi.spyOn(marketApi, 'siteApply').mockResolvedValue(result(siteA))
    renderWithProviders(<Harness />)
    fireEvent.click(previewButton())
    await waitFor(() => expect(applyButton()).toBeEnabled())
    fireEvent.click(applyButton())
    await waitFor(() => expect(screen.queryAllByText(/a\.example\.test（站点版本 7）/).length).toBeGreaterThan(0))
    fireEvent.click(screen.getByRole('button', { name: 'switch to B' }))
    await waitFor(() => expect(screen.queryAllByText(/a\.example\.test（站点版本 7）/)).toHaveLength(0))
    expect(apply).not.toHaveBeenCalled()
  })

  it('apply sends the frozen site, version and digest of the confirmed preview', async () => {
    vi.spyOn(marketApi, 'sitePreview').mockResolvedValue(result(siteA))
    const apply = vi.spyOn(marketApi, 'siteApply').mockResolvedValue({ ...result(siteA), result: { ...result(siteA).result!, applied: true } })
    vi.spyOn(marketApi, 'siteLeaves').mockResolvedValue([])
    renderWithProviders(<Harness />)
    fireEvent.click(previewButton())
    await waitFor(() => expect(applyButton()).toBeEnabled())
    fireEvent.click(applyButton())
    fireEvent.click(await screen.findByRole('button', { name: /确\s*定|OK/ }))
    await waitFor(() => expect(apply).toHaveBeenCalledWith(expect.any(String), siteA.id, 7, digest))
    expect(await screen.findByText('全部叶子已应用')).toBeInTheDocument()
  })

  it('a late answer after the account changed is dropped', async () => {
    const late = deferred<MarketSiteRollout>()
    const preview = vi.spyOn(marketApi, 'sitePreview').mockReturnValue(late.promise)
    renderWithProviders(<Harness />)
    await previewPending(preview, siteA)
    fireEvent.click(screen.getByRole('button', { name: 'switch account' }))
    await act(async () => late.resolve(result(siteA)))
    await settle()
    expect(shownSite(siteA.domain)).not.toBeInTheDocument()
    expect(applyButton()).toBeDisabled()
  })

  // D12/D16 (10-28 复验 D-补1): leaving the panel with the confirmation open
  // cancels it; its OK no longer applies anything.
  it('D12: unmounting the panel while the apply confirmation is open closes it and sends nothing', async () => {
    vi.spyOn(marketApi, 'sitePreview').mockResolvedValue(result(siteA))
    const apply = vi.spyOn(marketApi, 'siteApply').mockResolvedValue(result(siteA))
    function Leave() {
      const [show, setShow] = useState(true)
      return <><button onClick={() => setShow(false)}>leave panel</button>{show ? <SiteRollout site={siteA} /> : <p>another page</p>}</>
    }
    renderWithProviders(<Leave />)
    const dialog = await openConfirmation()
    const ok = within(dialog).getByRole('button', { name: /确\s*定|OK/ })
    fireEvent.click(screen.getByRole('button', { name: 'leave panel' }))
    await settle()
    // Even a click that reaches the closing dialog does not apply.
    if (ok.isConnected) fireEvent.click(ok)
    await settle()
    await waitFor(() => expect(screen.queryAllByText(/a\.example\.test（站点版本 7）/)).toHaveLength(0))
    expect(apply).not.toHaveBeenCalled()
  })

  it('D16: history back from supplies to ledger in the real page cancels the open confirmation', async () => {
    const buyer = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'],
      permissions: ['marketplace.browse', 'marketplace.purchase', 'sites.manage', 'sites.read'] })
    useSessionStore.getState().setSession(authResponse(buyer), buyer)
    stubMarketPage()
    vi.spyOn(marketApi, 'supplies').mockResolvedValue([{ id: 'supply', name: 'supply', market_subscription_id: '', target: '', status: 'active',
      leaves: [{ leaf_member_id: '33333333-3333-4333-8333-333333333333', node_pool_ref: 'pool', grant_id: 'grant' }] }])
    vi.spyOn(marketApi, 'siteBindings').mockResolvedValue([])
    vi.spyOn(sitesApi, 'list').mockResolvedValue({ items: [siteA], page: 1, limit: 20, total: 1 } as never)
    vi.spyOn(marketApi, 'sitePreview').mockResolvedValue(result(siteA))
    const apply = vi.spyOn(marketApi, 'siteApply').mockResolvedValue(result(siteA))
    function Back() {
      const navigate = useNavigate()
      const location = useLocation()
      return <><button onClick={() => navigate(-1)}>history back</button><output aria-label="current URL">{location.pathname}{location.search}</output></>
    }
    renderWithProviders(<><Back /><NodeMarketPage /></>, ['/sys/node-market?tab=ledger', '/sys/node-market?tab=supplies'])
    fireEvent.mouseDown(await screen.findByRole('combobox', { name: '站点' }))
    fireEvent.click(await screen.findByTitle(siteA.domain))
    const dialog = await openConfirmation()
    const ok = within(dialog).getByRole('button', { name: /确\s*定|OK/ })
    fireEvent.click(screen.getByRole('button', { name: 'history back' }))
    await waitFor(() => expect(screen.getByLabelText('current URL')).toHaveTextContent('/sys/node-market?tab=ledger'))
    expect(screen.queryByRole('button', { name: '应用' })).not.toBeInTheDocument()
    await settle()
    if (ok.isConnected) fireEvent.click(ok)
    await settle()
    expect(apply).not.toHaveBeenCalled()
  })

  it('StrictMode effect replay does not cancel a confirmation opened afterwards; OK applies the frozen preview', async () => {
    vi.spyOn(marketApi, 'sitePreview').mockResolvedValue(result(siteA))
    const apply = vi.spyOn(marketApi, 'siteApply').mockResolvedValue({ ...result(siteA), result: { ...result(siteA).result!, applied: true } })
    vi.spyOn(marketApi, 'siteLeaves').mockResolvedValue([])
    renderWithProviders(<StrictMode><Harness /></StrictMode>)
    const dialog = await openConfirmation()
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|OK/ }))
    await waitFor(() => expect(apply).toHaveBeenCalledWith(expect.any(String), siteA.id, 7, digest))
    expect(apply).toHaveBeenCalledTimes(1)
  })

  it('cancelling the confirmation sends nothing, and coming back to the panel needs a new preview', async () => {
    vi.spyOn(marketApi, 'sitePreview').mockResolvedValue(result(siteA))
    const apply = vi.spyOn(marketApi, 'siteApply').mockResolvedValue(result(siteA))
    function Toggle() {
      const [show, setShow] = useState(true)
      return <><button onClick={() => setShow(!show)}>toggle panel</button>{show ? <SiteRollout site={siteA} /> : null}</>
    }
    renderWithProviders(<Toggle />)
    const dialog = await openConfirmation()
    fireEvent.click(within(dialog).getByRole('button', { name: /取\s*消|Cancel/ }))
    await settle()
    fireEvent.click(screen.getByRole('button', { name: 'toggle panel' }))
    fireEvent.click(screen.getByRole('button', { name: 'toggle panel' }))
    expect(applyButton()).toBeDisabled()
    expect(apply).not.toHaveBeenCalled()
  })

  it('a failure of the current site says which site failed and can be retried', async () => {
    const preview = vi.spyOn(marketApi, 'sitePreview')
      .mockRejectedValueOnce(new ApiError('synthetic failure', 503, 'request_failed')).mockResolvedValueOnce(result(siteA))
    renderWithProviders(<Harness />)
    fireEvent.click(previewButton())
    expect(await screen.findByRole('alert')).toHaveTextContent(siteA.domain)
    fireEvent.click(previewButton())
    expect(await screen.findByText(siteA.domain, { selector: '.ant-descriptions-item-content' })).toBeInTheDocument()
    expect(screen.queryByText(/预检失败/)).not.toBeInTheDocument()
    expect(preview).toHaveBeenCalledTimes(2)
  })
})
