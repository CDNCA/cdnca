import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import TicketsPage from './TicketsPage'

function json(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, text: vi.fn().mockResolvedValue(JSON.stringify(body)),
    json: vi.fn().mockResolvedValue(body), headers: new Headers({ 'Content-Type': 'application/json' }) } as unknown as Response
}
type Fetch = (path: string, init?: RequestInit) => Promise<Response>

const user = {
  id: '55555555-5555-4555-8555-555555555555', display_id: '1024', scope_id: '66666666-6666-4666-8666-666666666666',
  tenant_id: '66666666-6666-4666-8666-666666666666', username: 'jason', display_name: 'jason', email: 'jason@example.com',
  phone: null, status: 'active', role: 'tenant_owner', group_id: null, group_name: null, revision: 1,
  created_at: '2026-10-27T00:00:00Z', updated_at: '2026-10-27T00:00:00Z',
}
const created = {
  ticket: { id: '33333333-3333-4333-8333-333333333333', ticket_no: 10077, category: 'billing', subject: '本月账单调整',
    priority: 'high', status: 'pending_customer', unread: false, revision: 1, last_message_at: '2026-10-27T01:00:00Z',
    created_at: '2026-10-27T01:00:00Z', updated_at: '2026-10-27T01:00:00Z' },
  messages: [], events: [],
}
const sub = (event_type: string, extra: Record<string, unknown> = {}) => ({ event_type, sms_enabled: false, email_enabled: true,
  sms_supported: true, email_supported: true, inbox_enabled: true, revision: 0, changed: false, ...extra })

function signIn(overrides: Parameters<typeof principal>[0]) {
  const value = principal(overrides)
  useSessionStore.getState().setSession({ ...authResponse(value), access_token: 'ticket-token' }, value)
}

beforeEach(async () => {
  await changeLocale('zh-CN')
  window.history.pushState({}, '', '/sys/tickets')
})
afterEach(() => vi.unstubAllGlobals())

describe('fix-ticket2 staff create and ticket notifications', () => {
  it('lets staff open a ticket for a searched user with an idempotency key', async () => {
    signIn({ scope_kind: 'platform', tenant_id: null, permissions: ['tickets.read', 'tickets.manage', 'identity.users.read'] })
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path.startsWith('/v1/admin/tickets?')) return json({ items: [], total: 0, limit: 20, offset: 0 })
      if (path === '/v1/admin/tickets/summary') return json({ unread: 0, pending: 0, mine: 0, sla_breached: 0 })
      if (path === '/v1/admin/tickets/assignees') return json({ items: [{ user_id: '77777777-7777-4777-8777-777777777777', username: 'ajie', display_name: '阿杰' }] })
      if (path.startsWith('/v1/admin/users?')) return json({ items: [user], page: 1, limit: 20, total: 1 })
      if (path === '/v1/admin/tickets' && init?.method === 'POST') return json(created, 201)
      if (path.startsWith('/v1/admin/tickets/')) return json(created)
      return json({ code: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<TicketsPage mode="admin" />)
    fireEvent.click(await screen.findByRole('button', { name: '新建工单' }))
    const drawer = await screen.findByRole('dialog', { name: '新建工单' })
    // Required fields are checked before anything is sent.
    fireEvent.click(within(drawer).getByRole('button', { name: '提交' }))
    expect(await within(drawer).findByText('请选择目标用户')).toBeInTheDocument()

    const picker = within(drawer).getByRole('combobox', { name: '目标用户' })
    fireEvent.mouseDown(picker)
    fireEvent.change(picker, { target: { value: '1024' } })
    await waitFor(() => expect(fetchMock.mock.calls.some(([path]) => path.startsWith('/v1/admin/users?') &&
      path.includes('display_id=1024'))).toBe(true))
    fireEvent.click(await screen.findByText('jason（1024） · jason@example.com'))
    fireEvent.change(within(drawer).getByLabelText('标题'), { target: { value: '本月账单调整' } })
    fireEvent.change(within(drawer).getByLabelText('首条内容'), { target: { value: '您好，本月账单有一笔调整。' } })
    fireEvent.click(within(drawer).getByRole('button', { name: '提交' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([path, i]) => path === '/v1/admin/tickets' && i?.method === 'POST')).toBe(true))
    const [, init] = fetchMock.mock.calls.find(([path, i]) => path === '/v1/admin/tickets' && i?.method === 'POST')!
    expect(JSON.parse(init!.body as string)).toEqual({ user_id: user.id, category: 'technical', priority: 'normal',
      subject: '本月账单调整', body: '您好，本月账单有一笔调整。' })
    expect((init!.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^ticket-staff-create-/)
  })

  it('hides staff create and staff reminders for a reader without tickets.manage', async () => {
    signIn({ scope_kind: 'platform', tenant_id: null, permissions: ['tickets.read'] })
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => path.startsWith('/v1/admin/tickets?')
      ? json({ items: [], total: 0, limit: 20, offset: 0 }) : json({ unread: 0 })))
    renderWithProviders(<TicketsPage mode="admin" />)
    expect(await screen.findByRole('button', { name: '重置' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新建工单' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '工单通知' })).not.toBeInTheDocument()
  })

  it('saves the customer ticket notification choices per event, in-app included', async () => {
    window.history.pushState({}, '', '/account/tickets')
    signIn({})
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path.startsWith('/v1/tickets?')) return json({ items: [], total: 0, limit: 20, offset: 0 })
      if (path === '/v1/tickets/summary') return json({ unread: 0 })
      const match = path.match(/^\/v1\/account\/notification-subscriptions\/(.+)$/)
      if (match && init?.method === 'PUT') return json(sub(match[1], { ...JSON.parse(init.body as string), revision: 1, changed: true }))
      if (match) return json(sub(match[1]))
      return json({ code: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<TicketsPage mode="user" />)
    fireEvent.click(await screen.findByRole('button', { name: '工单通知' }))
    const drawer = await screen.findByRole('dialog', { name: '工单通知' })
    expect(within(drawer).getByText('客服回复')).toBeInTheDocument()
    expect(within(drawer).queryByText('有新工单')).not.toBeInTheDocument()
    const inbox = await within(drawer).findByRole('checkbox', { name: '客服回复 站内信' })
    expect(inbox).toBeChecked()
    fireEvent.click(inbox)
    await waitFor(() => expect(fetchMock.mock.calls.some(([path, i]) => i?.method === 'PUT' &&
      path === '/v1/account/notification-subscriptions/ticket.replied')).toBe(true))
    const [, init] = fetchMock.mock.calls.find(([path, i]) => i?.method === 'PUT' && path.endsWith('ticket.replied'))!
    expect(JSON.parse(init!.body as string)).toEqual({ sms_enabled: false, email_enabled: true, inbox_enabled: false })
    expect((init!.headers as Record<string, string>)['If-Match']).toBe('"0"')
  })

  it('offers the staff their own ticket events, overdue reminders included', async () => {
    signIn({ scope_kind: 'platform', tenant_id: null, permissions: ['tickets.read', 'tickets.manage'] })
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => {
      if (path.startsWith('/v1/admin/tickets?')) return json({ items: [], total: 0, limit: 20, offset: 0 })
      const match = path.match(/^\/v1\/account\/notification-subscriptions\/(.+)$/)
      if (match) return json(sub(match[1]))
      return json({ unread: 0 })
    }))
    renderWithProviders(<TicketsPage mode="admin" />)
    fireEvent.click(await screen.findByRole('button', { name: '工单通知' }))
    const drawer = await screen.findByRole('dialog', { name: '工单通知' })
    for (const label of ['有新工单', '用户回复了工单', '工单超时未响应']) expect(within(drawer).getByText(label)).toBeInTheDocument()
    expect(within(drawer).queryByText('客服回复')).not.toBeInTheDocument()
    expect(await within(drawer).findByRole('checkbox', { name: '工单超时未响应 邮件' })).toBeChecked()
  })

  // 代建归因：管理员视图把客服写成创建者、客户写成归属，
  // 与用户视图和审计一致；客户自建时仍显示客户提交。
  it('names the staff member who opened the ticket for the customer, in both views', async () => {
    const staffMade = { ...created, ticket: { ...created.ticket, username: 'jason', creator_kind: 'staff', creator_name: 'admin' },
      messages: [{ id: 'm1', author_kind: 'staff', author_name: 'admin', body: '本月账单有一笔调整', attachments: [],
        created_at: '2026-10-27T01:00:00Z' }] }
    signIn({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['tickets.read', 'tickets.manage'] })
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => {
      if (path === `/v1/admin/tickets/${created.ticket.id}`) return json(staffMade)
      if (path === '/v1/admin/tickets/assignees') return json({ items: [] })
      return json({ unread: 0, items: [], total: 0 })
    }))
    const { unmount } = renderWithProviders(<TicketsPage mode="admin" />, [`/sys/tickets?id=${created.ticket.id}`])
    expect(await screen.findByText(/客服 admin 为 jason 创建了工单/)).toBeInTheDocument()
    expect(screen.queryByText(/jason 提交了工单/)).not.toBeInTheDocument()
    unmount()

    // 用户视图：后端已带「客服」前缀，没有 username。
    signIn({})
    const customerView = { ...staffMade, ticket: { ...staffMade.ticket, username: undefined, creator_name: '客服 admin' },
      messages: [{ ...staffMade.messages[0], author_name: '客服 admin' }] }
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => path === `/v1/tickets/${created.ticket.id}`
      ? json(customerView) : json({ unread: 0, items: [], total: 0 })))
    const user = renderWithProviders(<TicketsPage mode="user" />, [`/account/tickets?id=${created.ticket.id}`])
    expect(await screen.findByText(/客服 admin 创建了工单/)).toBeInTheDocument()
    expect(screen.queryByText(/客服 客服/)).not.toBeInTheDocument()
    user.unmount()

    // 客户自建：管理员视图仍是客户提交。
    signIn({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['tickets.read', 'tickets.manage'] })
    const own = { ...staffMade, ticket: { ...staffMade.ticket, creator_kind: 'customer', creator_name: 'jason' },
      messages: [{ ...staffMade.messages[0], author_kind: 'customer', author_name: 'jason' }] }
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => path === `/v1/admin/tickets/${created.ticket.id}`
      ? json(own) : json({ unread: 0, items: [], total: 0 })))
    renderWithProviders(<TicketsPage mode="admin" />, [`/sys/tickets?id=${created.ticket.id}`])
    expect(await screen.findByText(/jason 提交了工单/)).toBeInTheDocument()
  })
})
