import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../auth/session'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import NodeMarketPage from '../node-market/NodeMarketPage'
import PluginStorePage from '../plugin-market/PluginStorePage'

function json(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, text: vi.fn().mockResolvedValue(JSON.stringify(body)) } as unknown as Response
}

const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['sites.manage'] })
const offer = { id: '11111111-1111-4111-8111-111111111111', seller_id: '22222222-2222-4222-8222-222222222222', name: 'HK BGP',
  description: '', billing_model: 'daily_bundle', status: 'listed', pricing: { currency: 'CNY', daily_minor: 100, min_days: 2, max_days: 30 },
  allocation: { http_ports: 2 }, limits: [], compliance: {}, revision: 3 }
const privacy = { kind: 'privacy', version: '2026-10-25.1', body: '# 隐私政策\n\n我们只收集**必要**信息。', note: '', published_at: '2026-10-25T00:00:00Z' }
const terms = { kind: 'seller_terms', version: '2026-10-25.2', body: '服务协议正文', note: '', published_at: '2026-10-25T00:00:00Z' }

function market(agreements: unknown[]) {
  return vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path) => {
    if (path === '/v1/admin/market/agreements') return json({ items: agreements })
    if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: [], offers_quota: 3 })
    if (path.startsWith('/v1/admin/market/offers')) return json({ items: [offer], next_cursor: null })
    if (path === '/v1/admin/market/subscriptions') return json({ id: 's', grants: 1 }, 201)
    if (path.startsWith('/v1/admin/market/plugins') || path.startsWith('/v1/admin/market/advisories')) return json({ items: [] })
    return json({ error: 'not_found' }, 404)
  })
}

beforeEach(() => useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'market-token' }, admin))
afterEach(() => vi.unstubAllGlobals())

describe('market agreements (MARKET-03 buyer)', () => {
  it('node market footer links the published agreements and reads the text in a dialog', async () => {
    const fetchMock = market([privacy, terms])
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('button', { name: '隐私政策' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('版本 2026-10-25.1')).toBeInTheDocument()
    expect(within(dialog).getByText('必要')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '服务协议' })).toBeInTheDocument()
  })

  it('shows no links when nothing is published', async () => {
    const fetchMock = market([])
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<PluginStorePage />)
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/agreements', expect.anything()))
    expect(screen.queryByRole('button', { name: '隐私政策' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '服务协议' })).not.toBeInTheDocument()
  })

  it('plugin store footer shows only the published kinds', async () => {
    vi.stubGlobal('fetch', market([terms]))
    renderWithProviders(<PluginStorePage />)
    expect(await screen.findByRole('button', { name: '服务协议' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '隐私政策' })).not.toBeInTheDocument()
  })

  // merge-p10: the notice is part of the one purchase confirmation (C17 PurchaseConfirm), not a second dialog.
  it('notes the privacy policy in the purchase confirmation when privacy is published', async () => {
    const fetchMock = market([privacy])
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    await screen.findByRole('button', { name: '隐私政策' })
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '购买' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('本次扣款')).toBeInTheDocument()
    expect(within(dialog).getByText(/购买即表示同意/)).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '《隐私政策》' })).toBeInTheDocument()
    expect(screen.getAllByRole('dialog')).toHaveLength(1)
    expect(fetchMock).not.toHaveBeenCalledWith('/v1/admin/market/subscriptions', expect.anything())
    fireEvent.click(within(dialog).getByRole('button', { name: /确认购买/ }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/admin/market/subscriptions', expect.objectContaining({ method: 'POST' })))
    const call = fetchMock.mock.calls.find(([path]) => path === '/v1/admin/market/subscriptions')
    expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({ offer_id: offer.id, days: 2, expected_revision: 3 })
  })

  it('has no privacy notice in the purchase confirmation when privacy is not published', async () => {
    vi.stubGlobal('fetch', market([terms]))
    renderWithProviders(<NodeMarketPage />)
    await screen.findByRole('button', { name: '服务协议' })
    fireEvent.click(await screen.findByRole('tab', { name: '浏览与购买' }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '购买' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('本次扣款')).toBeInTheDocument()
    expect(within(dialog).queryByText(/购买即表示同意/)).not.toBeInTheDocument()
  })
})
