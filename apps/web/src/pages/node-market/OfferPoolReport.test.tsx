import { fireEvent, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../../api/auth'
import type { MarketOfferListing, MarketPoolReport, MarketPoolReportNode } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import { nextStep, OfferPoolReportDrawer, PoolReportCell, UnmappedNodesAlert } from './OfferPoolReport'

const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['sites.manage'] })
const json = (body: unknown, status = 200) => ({ ok: status < 300, status, text: async () => JSON.stringify(body) }) as unknown as Response

const pool = '7860f80e-3296-5427-85f0-f6cc41a9ce3e'
const offer = { id: 'a7e3c1d2-5b4f-4e6a-9c8d-1f2e3a4b5c6d', name: '测试 · 3b08628a', status: 'listed',
  components: [{ kind: 'own_pool', node_pool_ref: pool }] } as unknown as MarketOfferListing
const node = (patch: Partial<MarketPoolReportNode>): MarketPoolReportNode => ({ node_id: '3b08628a-0000-4000-8000-000000000001',
  name: '3b08628a', address: '11.0.0.118', region: 'CN', carrier: '', reason: '', role: 'join_market', role_capable: true, ...patch })
// A pool of one node whose carrier is empty: never reported.
const report = (patch: Partial<MarketPoolReport> = {}): MarketPoolReport => ({ probe: 'running', total: 1, reportable: 0,
  nodes: [node({ reason: 'carrier_unmapped', value: '', role_source: 'assigned' })], ...patch })

beforeEach(() => useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 't' }, admin))
afterEach(() => vi.unstubAllGlobals())

describe('OfferPoolReport', () => {
  it('shows 0 / 1 in the listing column', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(report())))
    renderWithProviders(<PoolReportCell offer={offer} onOpen={() => undefined} />)
    expect(await screen.findByText('0 / 1')).toBeInTheDocument()
  })

  it('says node reports are off for the whole controller', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(report({ probe: 'no_edge_nats', nodes: [node({ reason: 'node_not_join_market', role: 'probe_only' })] }))))
    renderWithProviders(<OfferPoolReportDrawer offer={offer} onClose={() => undefined} />)
    expect(await screen.findByText(/没有连上边缘消息服务/)).toBeInTheDocument()
  })

  it('names the unrecognized carrier, links to the node and refreshes the group', async () => {
    const calls: Array<{ url: string; method: string; body?: string }> = []
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, method: init?.method ?? 'GET', body: init?.body as string | undefined })
      if (url.endsWith('/report')) return json(report())
      if (init?.method === 'PUT') return json({ id: pool, revision: 2, name: '测试', nodes: [], node_pool_ref: pool, plugins: [] })
      return json({ id: pool, revision: 1, name: '测试', nodes: [{ node_id: node({}).node_id, name: '3b08628a', address: '11.0.0.118',
        region: 'CN', carrier: '' }], node_pool_ref: pool, plugins: [] })
    }))
    renderWithProviders(<OfferPoolReportDrawer offer={offer} onClose={() => undefined} />)
    expect(await screen.findByText(/^中国大陆节点的运营商无法识别：（空）/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '去编辑 IP 归属' })).toHaveAttribute('href', '/node/list?q=11.0.0.118')
    fireEvent.click(screen.getByRole('button', { name: '按当前 IP 归属刷新' }))
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true))
    const put = calls.find((c) => c.method === 'PUT')!
    expect(put.url).toContain(`/v1/admin/market/supply-groups/${pool}`)
    expect(JSON.parse(put.body!)).toEqual({ name: '测试', node_ids: [node({}).node_id], expected_revision: 1 })
  })

  it('gives each reason its next step', () => {
    const t = (key: string) => key
    expect(nextStep(node({ reason: 'node_not_join_market', role: 'probe_only', role_source: 'local_leave' }), t)).toBe('next.joinLeave')
    expect(nextStep(node({ reason: 'node_not_join_market', role: 'probe_only', role_capable: false }), t)).toBe('next.joinOld')
    expect(nextStep(node({ reason: 'node_not_join_market', role: 'disabled' }), t)).toBe('next.joinDisabled')
    expect(nextStep(node({ reason: 'node_not_join_market', role: 'probe_only' }), t)).toBe('next.joinPending')
    expect(nextStep(node({ reason: 'region_unmapped' }), t)).toBe('next.location')
    expect(nextStep(node({ reason: '' }), t)).toBe('—')
  })

  it('lists the nodes a location refusal is about', () => {
    const error = Object.assign(new ApiError('refused', 422, 'node_location_unmapped'), { refusal: { error: 'node_location_unmapped',
      nodes: [{ node_id: node({}).node_id, name: '3b08628a', region: 'CN', carrier: '', fields: ['carrier'] }] } })
    renderWithProviders(<UnmappedNodesAlert error={error} />)
    expect(screen.getByText('3b08628a：缺运营商（地区 CN，运营商 （空））')).toBeInTheDocument()
  })
})
