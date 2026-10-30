import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../../auth/session'
import { authResponse, principal } from '../../../test/fixtures'
import { renderWithProviders } from '../../../test/render'
import NodeMarketPage from '../NodeMarketPage'

// u4d (C22): subscription fault reports — the buyer files from the
// subscription drawer, the seller answers from the supplier tab.

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const user = principal({ scope_kind: 'platform', tenant_id: null, roles: [], permissions: ['marketplace.browse', 'marketplace.sell', 'marketplace.purchase', 'sites.manage'] })
const subID = '77777777-7777-4777-8777-777777777777'
const ticketID = '33333333-3333-4333-8333-333333333333'
const supply = { id: '66666666-6666-4666-8666-666666666666', name: 'HK supply', market_subscription_id: subID, target: 's.market.example', status: 'active', leaves: [] }
const terms = { id: subID, buyer_id: 'b', seller_id: 's', offer_id: 'o', status: 'active', settlement_mode: 'direct', renewal_price_policy: 'always',
  cancel_at_period_end: false, close_code: null, max_unit_price_minor: null, min_quality_score: null }
const ticket = { id: ticketID, subscription_id: subID, offer_name: 'HK BGP', category: 'outage', title: '全部 502', state: 'open',
  respond_by: '2026-10-25T00:00:00Z', seller_responded_at: null, escalable: true, dispute_id: null, decision: null, created_at: '2026-10-22T00:00:00Z',
  updated_at: '2026-10-22T00:00:00Z', revision: 1,
  messages: [{ seq: 1, author_role: 'buyer', kind: 'reply', body: '从 10:00 起全部 502', created_at: '2026-10-22T00:00:00Z' }] }

type Handler = (path: string, init?: RequestInit) => Response | undefined
function market(extra: Handler) {
  return vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(async (path, init) => {
    const custom = extra(path, init)
    if (custom) return custom
    if (path === '/v1/admin/market/member') return json({ id: 'm', display_name: 'me', status: 'active', features: ['market.sell'], offers_quota: 3 })
    if (path === '/v1/admin/market/supplies') return json({ items: [supply] })
    if (path === `/v1/admin/market/subscriptions/${subID}`) return json(terms)
    if (path.startsWith('/v1/admin/market/seller/subscribers')) return json({ items: [], next_cursor: null })
    return json({ error: 'not_found' }, 404)
  })
}

const posts = (fetchMock: ReturnType<typeof market>, path: string) =>
  fetchMock.mock.calls.filter(([p, i]) => p === path && i?.method === 'POST')
    .map(([, i]) => ({ body: JSON.parse(String(i!.body)) as Record<string, unknown>, key: (i!.headers as Record<string, string>)['Idempotency-Key'] }))

beforeEach(() => useSessionStore.getState().setSession({ ...authResponse(user), access_token: 'market-token' }, user))
afterEach(() => vi.unstubAllGlobals())

describe('subscription fault reports', () => {
  it('files a report from the subscription drawer, then escalates it once the seller is overdue', async () => {
    let filed = false
    const fetchMock = market((path, init) => {
      if (path === `/v1/admin/market/subscriptions/${subID}/feedback` && init?.method === 'POST') { filed = true; return json(ticket, 201) }
      if (path.startsWith('/v1/admin/market/buyer/feedback?')) return json({ items: filed ? [ticket] : [], next_cursor: null })
      if (path === `/v1/admin/market/buyer/feedback/${ticketID}`) return json(ticket)
      if (path === `/v1/admin/market/buyer/feedback/${ticketID}/escalate`) return json({ ...ticket, escalable: false, dispute_id: '44444444-4444-4444-8444-444444444444' })
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '已购供给与站点' }))
    fireEvent.click(await screen.findByRole('button', { name: '订阅详情' }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.click(await within(drawer).findByRole('tab', { name: '反馈故障' }))
    expect(await within(drawer).findByText('暂无故障反馈')).toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([p]) => p === `/v1/admin/market/buyer/feedback?subscription=${subID}&limit=50`)).toBe(true)
    fireEvent.click(within(drawer).getByRole('button', { name: '反馈故障' }))
    const form = (await screen.findAllByRole('dialog')).at(-1)!
    fireEvent.change(within(form).getByLabelText('标题'), { target: { value: ' 全部 502 ' } })
    fireEvent.change(within(form).getByLabelText('描述'), { target: { value: '从 10:00 起全部 502' } })
    fireEvent.click(within(form).getByRole('button', { name: '提交反馈' }))
    await waitFor(() => expect(posts(fetchMock, `/v1/admin/market/subscriptions/${subID}/feedback`)).toHaveLength(1))
    const [open] = posts(fetchMock, `/v1/admin/market/subscriptions/${subID}/feedback`)
    expect(open.body).toEqual({ category: 'outage', title: '全部 502', body: '从 10:00 起全部 502' })
    expect(open.key).toMatch(/^feedback-open-/)

    // The new ticket opens: conversation, overdue notice, escalation.
    expect(await screen.findByText('卖方已超过处理时限仍未处理，你可以升级为争议。')).toBeInTheDocument()
    expect(screen.getAllByText('从 10:00 起全部 502').length).toBeGreaterThan(0)
    fireEvent.click(screen.getByRole('button', { name: '升级为争议' }))
    const modal = (await screen.findAllByRole('dialog')).at(-1)!
    expect(within(modal).getByText(/直结订阅的款项不经平台/)).toBeInTheDocument()
    const confirm = within(modal).getByRole('button', { name: '确认升级' })
    expect(confirm).toBeDisabled()
    fireEvent.change(within(modal).getByLabelText('主张金额（元）'), { target: { value: '5' } })
    fireEvent.click(confirm)
    await waitFor(() => expect(posts(fetchMock, `/v1/admin/market/buyer/feedback/${ticketID}/escalate`)).toHaveLength(1))
    expect(posts(fetchMock, `/v1/admin/market/buyer/feedback/${ticketID}/escalate`)[0].body).toEqual({ amount_minor: 500, note: '' })
    expect(await screen.findByText('已升级为争议，可在"争议"页跟进')).toBeInTheDocument()
  })

  it('lets the seller reply and mark resolved from the supplier tab, and explains a closed ticket', async () => {
    let answers = 0
    const fetchMock = market((path, init) => {
      if (path.startsWith('/v1/admin/market/seller/feedback?')) return json({ items: [{ ...ticket, escalable: false }], next_cursor: null })
      if (path === `/v1/admin/market/seller/feedback/${ticketID}`) return json({ ...ticket, escalable: false })
      if (path === `/v1/admin/market/seller/feedback/${ticketID}/messages` && init?.method === 'POST') {
        answers += 1
        return answers < 3 ? json({ ...ticket, state: 'in_progress', escalable: false }) : json({ error: 'feedback_closed' }, 409)
      }
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '供货管理' }))
    fireEvent.click(await screen.findByRole('tab', { name: '故障反馈' }))
    expect(await screen.findByText('HK BGP')).toBeInTheDocument()
    // Sellers never see an escalation entry.
    fireEvent.click(screen.getByRole('button', { name: '查看' }))
    expect(await screen.findByText(/请在 .* 前回复或标为处理中/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '升级为争议' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '关闭反馈' })).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('回复'), { target: { value: '已重启回源' } })
    fireEvent.click(screen.getByRole('button', { name: '发送回复' }))
    await waitFor(() => expect(answers).toBe(1))
    fireEvent.click(screen.getByRole('button', { name: '标为已解决' }))
    await waitFor(() => expect(answers).toBe(2))
    const sent = posts(fetchMock, `/v1/admin/market/seller/feedback/${ticketID}/messages`)
    expect(sent[0].body).toEqual({ body: '已重启回源' })
    expect(sent[1].body).toEqual({ state: 'resolved' })
    expect(sent[0].key).not.toBe(sent[1].key)
    fireEvent.click(screen.getByRole('button', { name: '标为处理中' }))
    expect(await screen.findByText('反馈已关闭，不能再回复或修改')).toBeInTheDocument()
  })

  it('card 10: retries a reply of unknown outcome with the same key, a definite refusal starts a new one', async () => {
    let answers = 0
    const fetchMock = market((path, init) => {
      if (path.startsWith('/v1/admin/market/seller/feedback?')) return json({ items: [{ ...ticket, escalable: false }], next_cursor: null })
      if (path === `/v1/admin/market/seller/feedback/${ticketID}`) return json({ ...ticket, escalable: false })
      if (path === `/v1/admin/market/seller/feedback/${ticketID}/messages` && init?.method === 'POST') {
        answers += 1
        if (answers === 1) return json({ error: 'internal' }, 502)
        return answers === 2 ? json({ error: 'invalid' }, 400) : json({ ...ticket, escalable: false })
      }
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '供货管理' }))
    fireEvent.click(await screen.findByRole('tab', { name: '故障反馈' }))
    fireEvent.click(await screen.findByRole('button', { name: '查看' }))
    fireEvent.change(await screen.findByLabelText('回复'), { target: { value: '已重启回源' } })
    for (const n of [1, 2, 3]) {
      fireEvent.click(screen.getByRole('button', { name: '发送回复' }))
      await waitFor(() => expect(answers).toBe(n))
      if (n < 3) await waitFor(() => expect(screen.getByRole('button', { name: '发送回复' })).toBeEnabled())
    }
    const sent = posts(fetchMock, `/v1/admin/market/seller/feedback/${ticketID}/messages`)
    expect(sent[1].key).toBe(sent[0].key) // 502: may have been written, replay it
    expect(sent[2].key).not.toBe(sent[1].key) // 400: nothing written
  })

  it('shows the dispute ruling on a ticket the decision closed (u4g)', async () => {
    const decided = { ...ticket, state: 'closed', escalable: false, dispute_id: '44444444-4444-4444-8444-444444444444',
      decision: { outcome: 'resolved_split', amount_minor: 500, buyer_share_minor: 200, currency: 'CNY', decided_at: '2026-10-29T08:00:00Z' },
      messages: [...ticket.messages, { seq: 2, author_role: 'system', kind: 'state', body: '', to_state: 'closed', created_at: '2026-10-29T08:00:00Z' }] }
    const fetchMock = market((path) => {
      if (path.startsWith('/v1/admin/market/seller/feedback?')) return json({ items: [decided], next_cursor: null })
      if (path === `/v1/admin/market/seller/feedback/${ticketID}`) return json(decided)
      return undefined
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<NodeMarketPage />)
    fireEvent.click(await screen.findByRole('tab', { name: '供货管理' }))
    fireEvent.click(await screen.findByRole('tab', { name: '故障反馈' }))
    fireEvent.click(await screen.findByRole('button', { name: '查看' }))
    expect(await screen.findByText('争议裁决')).toBeInTheDocument()
    expect(screen.getByText(/部分支持：订阅方得 2\.00 CNY（主张 5\.00 CNY）/)).toBeInTheDocument()
    expect(screen.getByText(/裁决于 /)).toBeInTheDocument()
    expect(screen.getAllByText('已关闭').length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: '发送回复' })).not.toBeInTheDocument()
  })
})
