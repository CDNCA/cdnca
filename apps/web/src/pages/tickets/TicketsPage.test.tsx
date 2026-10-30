import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { validateAttachment } from '../../api/tickets'
import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { ticketsMessages } from '../../i18n/tickets'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import TicketsPage from './TicketsPage'

function json(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, text: vi.fn().mockResolvedValue(JSON.stringify(body)) } as unknown as Response
}

type Fetch = (path: string, init?: RequestInit) => Promise<Response>

const ticket = {
  id: '33333333-3333-4333-8333-333333333333', ticket_no: 10001, category: 'technical', subject: '网站 502',
  priority: 'normal', status: 'pending_customer', unread: true, revision: 3, last_message_at: '2026-10-17T01:00:00Z',
  created_at: '2026-10-17T00:00:00Z', updated_at: '2026-10-17T01:00:00Z',
}
const detail = {
  ticket: { ...ticket, unread: false },
  messages: [
    { id: 'm1', author_kind: 'customer', author_name: 'jason', body: '访问首页返回 502', attachments: [], created_at: '2026-10-17T00:00:00Z' },
    { id: 'm2', author_kind: 'staff', author_name: '客服 小王', body: '<b>请检查源站</b>', created_at: '2026-10-17T01:00:00Z',
      attachments: [{ id: 'a1', file_name: 'log.txt', mime_type: 'text/plain', size_bytes: 3, sha256: 'x', created_at: '2026-10-17T01:00:00Z' }] },
  ],
}

function signIn(overrides: Parameters<typeof principal>[0]) {
  const user = principal(overrides)
  useSessionStore.getState().setSession({ ...authResponse(user), access_token: 'ticket-token' }, user)
}

beforeEach(async () => {
  await changeLocale('zh-CN')
})
afterEach(() => vi.unstubAllGlobals())

describe('TicketsPage', () => {
  it('keeps every locale structurally complete', () => {
    const keys = (tree: object, prefix = ''): string[] => Object.entries(tree).flatMap(([k, v]) =>
      typeof v === 'string' ? [`${prefix}${k}`] : keys(v as object, `${prefix}${k}.`))
    expect(keys(ticketsMessages['en-US'])).toEqual(keys(ticketsMessages['zh-CN']))
  })

  it('rejects a platform session on the customer page and a tenant on the admin page', () => {
    signIn({ scope_kind: 'platform', tenant_id: null, permissions: ['platform.admin'] })
    const { unmount } = renderWithProviders(<TicketsPage mode="user" />)
    expect(screen.getByText('需要工单权限')).toBeInTheDocument()
    unmount()
    signIn({ permissions: ['tickets.read'] })
    renderWithProviders(<TicketsPage mode="admin" />)
    expect(screen.getByText('需要工单权限')).toBeInTheDocument()
  })

  it('lists own tickets with the unread badge and files a new ticket with an idempotency key', async () => {
    signIn({})
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path.startsWith('/v1/tickets?') && !init?.method) {
        expect(path).toBe('/v1/tickets?limit=20')
        return json({ items: [ticket], total: 1, limit: 20, offset: 0 })
      }
      if (path === '/v1/tickets/summary') return json({ unread: 1 })
      if (path === '/v1/tickets' && init?.method === 'POST') return json({ ...detail, ticket: { ...detail.ticket, ticket_no: 10002 } }, 201)
      if (path === `/v1/tickets/${ticket.id}`) return json(detail)
      return json({ code: 'ticket_not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<TicketsPage mode="user" />)
    expect(await screen.findByRole('button', { name: '网站 502' })).toBeInTheDocument()
    expect(screen.getByText('新回复')).toBeInTheDocument()
    // redesign-a：摘要改为"标签 + 数值"两行，限定在摘要分区内查。
    const summary = within(screen.getByRole('list', { name: '工单概况' }))
    expect(summary.getByText('未读').nextSibling).toHaveTextContent('1')
    expect(screen.queryByText('处理人')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '提交工单' }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.change(within(drawer).getByLabelText('标题'), { target: { value: '证书没生效' } })
    fireEvent.change(within(drawer).getByLabelText('问题描述'), { target: { value: '已上传证书，HTTPS 仍报错' } })
    fireEvent.click(within(drawer).getByRole('button', { name: '提交' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/v1/tickets', expect.objectContaining({ method: 'POST' })))
    const [, init] = fetchMock.mock.calls.find(([path, i]) => path === '/v1/tickets' && i?.method === 'POST')!
    expect(JSON.parse(init!.body as string)).toEqual({ category: 'technical', priority: 'normal', subject: '证书没生效',
      body: '已上传证书，HTTPS 仍报错' })
    expect((init!.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^ticket-create-/)
  })

  // 第七节“普通用户求助”：从网站失败处进入（?new=1&site_id=）直接打开新建并预填关联网站。
  it('opens a new ticket with the site prefilled when arriving from a site failure', async () => {
    signIn({})
    const siteID = '44444444-4444-4444-8444-444444444444'
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => {
      if (path.startsWith('/v1/tickets?')) return json({ items: [], total: 0, limit: 20, offset: 0 })
      if (path === '/v1/tickets/summary') return json({ unread: 0 })
      return json({ code: 'ticket_not_found' }, 404)
    }))
    renderWithProviders(<TicketsPage mode="user" />, [`/account/tickets?new=1&site_id=${siteID}`])
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByLabelText('关联站点 ID（可选）')).toHaveValue(siteID)
  })

  it('ignores a malformed prefilled site ID', async () => {
    signIn({})
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => {
      if (path.startsWith('/v1/tickets?')) return json({ items: [], total: 0, limit: 20, offset: 0 })
      if (path === '/v1/tickets/summary') return json({ unread: 0 })
      return json({ code: 'ticket_not_found' }, 404)
    }))
    renderWithProviders(<TicketsPage mode="user" />, ['/account/tickets?new=1&site_id=<x>'])
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByLabelText('关联站点 ID（可选）')).toHaveValue('')
  })

  it('points ticket ID errors at the related field instead of a generic message (W6)', async () => {
    signIn({})
    const siteID = '44444444-4444-4444-8444-444444444444'
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path.startsWith('/v1/tickets?') && !init?.method) return json({ items: [], total: 0, limit: 20, offset: 0 })
      if (path === '/v1/tickets/summary') return json({ unread: 0 })
      if (path === '/v1/tickets' && init?.method === 'POST') return json({ code: 'invalid_ticket' }, 400)
      return json({ code: 'ticket_not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<TicketsPage mode="user" />)
    fireEvent.click(await screen.findByRole('button', { name: '提交工单' }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.change(within(drawer).getByLabelText('标题'), { target: { value: '站点异常' } })
    fireEvent.change(within(drawer).getByLabelText('问题描述'), { target: { value: '打不开' } })
    fireEvent.change(within(drawer).getByLabelText('关联站点 ID（可选）'), { target: { value: 'site-123' } })
    fireEvent.click(within(drawer).getByRole('button', { name: '提交' }))
    expect(await within(drawer).findByText('请填写完整的 ID（形如 0190a1b2-…，小写）')).toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([path, i]) => path === '/v1/tickets' && i?.method === 'POST')).toBe(false)

    fireEvent.change(within(drawer).getByLabelText('关联站点 ID（可选）'), { target: { value: siteID } })
    fireEvent.click(within(drawer).getByRole('button', { name: '提交' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([path, i]) => path === '/v1/tickets' && i?.method === 'POST')).toBe(true))
    expect(await within(drawer).findByText('找不到该 ID，或它不属于当前账户')).toBeInTheDocument()
  })

  it('renders the timeline as plain text and replies', async () => {
    signIn({})
    window.history.pushState({}, '', `/account/tickets?id=${ticket.id}`)
    const fetchMock = vi.fn<Fetch>(async (path) => {
      if (path === `/v1/tickets/${ticket.id}`) return json(detail)
      if (path === `/v1/tickets/${ticket.id}/messages`) return json(detail, 201)
      return json({ unread: 0, items: [], total: 0 })
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<TicketsPage mode="user" />, [`/account/tickets?id=${ticket.id}`])
    expect(await screen.findByText('<b>请检查源站</b>')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '下载 log.txt' })).toBeInTheDocument()
    expect(screen.queryByText('作为内部备注（用户不可见）')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('回复'), { target: { value: '源站正常' } })
    fireEvent.click(screen.getByRole('button', { name: '发送' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/tickets/${ticket.id}/messages`, expect.objectContaining({ method: 'POST' })))
    const [, init] = fetchMock.mock.calls.find(([path]) => path.endsWith('/messages'))!
    expect(JSON.parse(init!.body as string)).toEqual({ body: '源站正常' })
  })

  it('offers reopen on a resolved ticket within the window and no reply box', async () => {
    signIn({})
    const resolved = { ...detail, ticket: { ...detail.ticket, status: 'resolved', resolved_at: '2026-10-17T02:00:00Z',
      reopenable_until: '2026-10-24T02:00:00Z' } }
    const fetchMock = vi.fn<Fetch>(async (path) => {
      if (path === `/v1/tickets/${ticket.id}`) return json(resolved)
      if (path === `/v1/tickets/${ticket.id}/reopen`) return json(detail)
      return json({ unread: 0, items: [], total: 0 })
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<TicketsPage mode="user" />, [`/account/tickets?id=${ticket.id}`])
    expect(await screen.findByText('工单已结束，如问题仍未解决可以重新打开。')).toBeInTheDocument()
    expect(screen.queryByLabelText('回复')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '重新打开' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/tickets/${ticket.id}/reopen`, expect.objectContaining({ method: 'POST' })))
  })

  it('lets staff change status with the expected revision and post an internal note', async () => {
    signIn({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['tickets.read', 'tickets.manage'] })
    const staffDetail = { ...detail, ticket: { ...detail.ticket, username: 'jason', assignee_user_id: '' } }
    const fetchMock = vi.fn<Fetch>(async (path) => {
      if (path === `/v1/admin/tickets/${ticket.id}`) return json(staffDetail)
      if (path === '/v1/admin/tickets/assignees') return json({ items: [] })
      if (path === `/v1/admin/tickets/${ticket.id}/messages`) return json(staffDetail, 201)
      return json({ unread: 0, items: [], total: 0 })
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<TicketsPage mode="admin" />, [`/sys/tickets?id=${ticket.id}`])
    expect(await screen.findByText('请检查源站', { exact: false })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox', { name: '作为内部备注（用户不可见）' }))
    fireEvent.change(screen.getByLabelText('回复'), { target: { value: '怀疑源站' } })
    fireEvent.click(screen.getByRole('button', { name: '发送' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/admin/tickets/${ticket.id}/messages`, expect.anything()))
    const [, init] = fetchMock.mock.calls.find(([path]) => path.endsWith('/messages'))!
    expect(JSON.parse(init!.body as string)).toEqual({ body: '怀疑源站', internal: true })

    fireEvent.click(screen.getByRole('button', { name: '认领' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/admin/tickets/${ticket.id}`, expect.objectContaining({ method: 'PATCH' })))
    const [, patch] = fetchMock.mock.calls.find(([, i]) => i?.method === 'PATCH')!
    expect(JSON.parse(patch!.body as string)).toEqual({ expected_revision: 3, assignee_user_id: '11111111-1111-4111-8111-111111111111' })
  })

  // p1-tickets TKT-01：一次提交固定一个幂等键。假后端按 key 去重（同 key 同正文重放、同 key 异正文 409），
  // 记录真实写入次数；failures 依次决定每次请求“写入后”返回什么（丢响应 / 502 / 504）。
  function fakeWrites(path: string, failures: Array<'lost' | 502 | 504>) {
    const stored = new Map<string, string>()
    const keys: string[] = []
    let records = 0
    const handle = async (init?: RequestInit): Promise<Response> => {
      const key = (init!.headers as Record<string, string>)['Idempotency-Key']
      keys.push(key)
      const body = init!.body as string
      if (stored.has(key) && stored.get(key) !== body) return json({ code: 'idempotency_conflict' }, 409)
      if (!stored.has(key)) { stored.set(key, body); records++ }
      const failure = failures.shift()
      if (failure === 'lost') throw new TypeError('Failed to fetch')
      if (failure) return json({ code: 'bad_gateway' }, failure)
      return json({ ...detail, ticket: { ...detail.ticket, ticket_no: 10002 } }, 201)
    }
    return { path, handle, keys, records: () => records }
  }

  async function openCreate(fetchMock: ReturnType<typeof vi.fn<Fetch>>) {
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<TicketsPage mode="user" />)
    fireEvent.click(await screen.findByRole('button', { name: '提交工单' }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.change(within(drawer).getByLabelText('标题'), { target: { value: '证书没生效' } })
    fireEvent.change(within(drawer).getByLabelText('问题描述'), { target: { value: 'HTTPS 报错' } })
    return drawer
  }

  function listFetch(writes: ReturnType<typeof fakeWrites>) {
    return vi.fn<Fetch>(async (path, init) => {
      if (path === writes.path && init?.method === 'POST') return writes.handle(init)
      if (path === '/v1/tickets/summary') return json({ unread: 0 })
      if (path.startsWith('/v1/tickets?')) return json({ items: [], total: 0, limit: 20, offset: 0 })
      if (path === `/v1/tickets/${ticket.id}`) return json(detail)
      return json({ code: 'ticket_not_found' }, 404)
    })
  }

  it.each([['lost' as const], [502 as const], [504 as const]])(
    'retries a ticket whose outcome is unknown (%s) with the same key and files it once', async (failure) => {
      signIn({})
      const writes = fakeWrites('/v1/tickets', [failure])
      const drawer = await openCreate(listFetch(writes))
      fireEvent.click(within(drawer).getByRole('button', { name: '提交' }))
      expect(await within(drawer).findByText(/提交结果未知/)).toBeInTheDocument()
      fireEvent.click(within(drawer).getByRole('button', { name: '查询结果/重试' }))
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(writes.keys).toHaveLength(2)
      expect(writes.keys[1]).toBe(writes.keys[0])
      expect(writes.records()).toBe(1)
    })

  it('sends one create for a double click and a new key once the content changes', async () => {
    signIn({})
    const writes = fakeWrites('/v1/tickets', [504])
    const drawer = await openCreate(listFetch(writes))
    const submit = within(drawer).getByRole('button', { name: '提交' })
    fireEvent.click(submit)
    fireEvent.click(submit)
    expect(await within(drawer).findByText(/提交结果未知/)).toBeInTheDocument()
    expect(writes.keys).toHaveLength(1)
    // 改了正文就是一次新提交：按钮回到“提交”，换新 key。
    fireEvent.change(within(drawer).getByLabelText('问题描述'), { target: { value: 'HTTPS 报错，补充：仅 IPv6' } })
    fireEvent.click(within(drawer).getByRole('button', { name: '提交' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(writes.keys).toHaveLength(2)
    expect(writes.keys[1]).not.toBe(writes.keys[0])
  })

  it('drops the key after a definite 409 so the next submission starts fresh', async () => {
    signIn({})
    const keys: string[] = []
    let calls = 0
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path === '/v1/tickets' && init?.method === 'POST') {
        keys.push((init.headers as Record<string, string>)['Idempotency-Key'])
        return ++calls === 1 ? json({ code: 'idempotency_conflict' }, 409) : json(detail, 201)
      }
      if (path === '/v1/tickets/summary') return json({ unread: 0 })
      if (path.startsWith('/v1/tickets?')) return json({ items: [], total: 0, limit: 20, offset: 0 })
      return json(detail)
    })
    const drawer = await openCreate(fetchMock)
    fireEvent.click(within(drawer).getByRole('button', { name: '提交' }))
    expect(await within(drawer).findByText('操作失败：idempotency_conflict')).toBeInTheDocument()
    expect(within(drawer).queryByRole('button', { name: '查询结果/重试' })).not.toBeInTheDocument()
    fireEvent.click(within(drawer).getByRole('button', { name: '提交' }))
    await waitFor(() => expect(keys).toHaveLength(2))
    expect(keys[1]).not.toBe(keys[0])
  })

  it('replays an unknown reply with its key, then uses a new key for the next reply', async () => {
    signIn({})
    const writes = fakeWrites(`/v1/tickets/${ticket.id}/messages`, ['lost', 502])
    vi.stubGlobal('fetch', listFetch(writes))
    renderWithProviders(<TicketsPage mode="user" />, [`/account/tickets?id=${ticket.id}`])
    fireEvent.change(await screen.findByLabelText('回复'), { target: { value: '源站正常' } })
    const send = screen.getByRole('button', { name: '发送' })
    fireEvent.click(send)
    fireEvent.click(send)
    expect(await screen.findByText(/发送结果未知/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '查询结果/重试' }))
    await waitFor(() => expect(writes.keys).toHaveLength(2))
    expect(await screen.findByText(/发送结果未知/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '查询结果/重试' }))
    await waitFor(() => expect(screen.getByLabelText('回复')).toHaveValue(''))
    expect(new Set(writes.keys).size).toBe(1)
    expect(writes.keys).toHaveLength(3)
    expect(writes.records()).toBe(1)

    // 成功后清掉 key：下一条回复（即使正文相同）是新的写入。
    fireEvent.change(screen.getByLabelText('回复'), { target: { value: '源站正常' } })
    fireEvent.click(screen.getByRole('button', { name: '发送' }))
    await waitFor(() => expect(writes.keys).toHaveLength(4))
    expect(writes.keys[3]).not.toBe(writes.keys[0])
    expect(writes.records()).toBe(2)
  })

  it('gives an edited reply a new key after an unknown outcome', async () => {
    signIn({})
    const writes = fakeWrites(`/v1/tickets/${ticket.id}/messages`, [504])
    vi.stubGlobal('fetch', listFetch(writes))
    renderWithProviders(<TicketsPage mode="user" />, [`/account/tickets?id=${ticket.id}`])
    fireEvent.change(await screen.findByLabelText('回复'), { target: { value: '源站正常' } })
    fireEvent.click(screen.getByRole('button', { name: '发送' }))
    expect(await screen.findByRole('button', { name: '查询结果/重试' })).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('回复'), { target: { value: '源站正常，已重启' } })
    fireEvent.click(screen.getByRole('button', { name: '发送' }))
    await waitFor(() => expect(writes.keys).toHaveLength(2))
    expect(writes.keys[1]).not.toBe(writes.keys[0])
  })

  // p1-tickets TKT-03：重开成功但响应丢失后再点，服务端回 ticket_invalid_state；页面重新读取详情并提示状态已变化。
  it('reloads the detail and says the status changed after ticket_invalid_state', async () => {
    signIn({})
    const resolved = { ...detail, ticket: { ...detail.ticket, status: 'resolved', resolved_at: '2026-10-17T02:00:00Z',
      reopenable_until: '2026-10-24T02:00:00Z' } }
    let reopened = false
    const fetchMock = vi.fn<Fetch>(async (path) => {
      if (path === `/v1/tickets/${ticket.id}`) return json(reopened ? { ...detail, ticket: { ...detail.ticket, status: 'open' } } : resolved)
      if (path === `/v1/tickets/${ticket.id}/reopen`) { reopened = true; return json({ code: 'ticket_invalid_state' }, 409) }
      return json({ unread: 0, items: [], total: 0 })
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<TicketsPage mode="user" />, [`/account/tickets?id=${ticket.id}`])
    fireEvent.click(await screen.findByRole('button', { name: '重新打开' }))
    expect(await screen.findByText('工单状态已变化，已重新读取最新详情')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '重新打开' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('回复')).toBeInTheDocument()
    expect(fetchMock.mock.calls.filter(([path]) => path === `/v1/tickets/${ticket.id}`).length).toBeGreaterThanOrEqual(2)
  })

  it('keeps the invalid-state message when the reloaded status is unchanged', async () => {
    signIn({})
    const fetchMock = vi.fn<Fetch>(async (path) => {
      if (path === `/v1/tickets/${ticket.id}`) return json(detail)
      if (path === `/v1/tickets/${ticket.id}/close`) return json({ code: 'ticket_invalid_state' }, 409)
      return json({ unread: 0, items: [], total: 0 })
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<TicketsPage mode="user" />, [`/account/tickets?id=${ticket.id}`])
    fireEvent.click(await screen.findByRole('button', { name: '关闭工单' }))
    fireEvent.click(await screen.findByRole('button', { name: /确\s*定|OK/ }))
    expect(await screen.findByText('工单当前状态不允许这个操作')).toBeInTheDocument()
    await waitFor(() => expect(fetchMock.mock.calls.filter(([path]) => path === `/v1/tickets/${ticket.id}`).length).toBe(2))
    expect(screen.queryByText('工单状态已变化，已重新读取最新详情')).not.toBeInTheDocument()
  })

  // redesign-a：聊天气泡——用户左、客服右，同人 5 分钟内合并，内部备注标"仅客服可见"，Ctrl/⌘+Enter 发送。
  it('lays the conversation out as chat bubbles and sends with Ctrl+Enter', async () => {
    signIn({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['tickets.read', 'tickets.manage'] })
    const chatDetail = {
      ticket: { ...detail.ticket, username: 'jason' },
      messages: [
        detail.messages[0],
        { ...detail.messages[0], id: 'm1b', body: '补充：只有移动线路', created_at: '2026-10-17T00:03:00Z' },
        { ...detail.messages[1], internal: true, body: '怀疑源站限流' },
      ],
    }
    const fetchMock = vi.fn<Fetch>(async (path) => {
      if (path === `/v1/admin/tickets/${ticket.id}`) return json(chatDetail)
      if (path === '/v1/admin/tickets/assignees') return json({ items: [] })
      if (path === `/v1/admin/tickets/${ticket.id}/messages`) return json(chatDetail, 201)
      return json({ unread: 0, items: [], total: 0 })
    })
    vi.stubGlobal('fetch', fetchMock)
    const { container } = renderWithProviders(<TicketsPage mode="admin" />, [`/sys/tickets?id=${ticket.id}`])
    expect(await screen.findByText('怀疑源站限流')).toBeInTheDocument()
    const groups = container.querySelectorAll('.ticket-chat-group')
    expect(groups).toHaveLength(2)
    expect(groups[0]).toHaveClass('ticket-chat-group--customer')
    expect(groups[0].querySelectorAll('.ticket-chat-bubble')).toHaveLength(2)
    expect(groups[1]).toHaveClass('ticket-chat-group--staff', 'ticket-chat-group--internal')
    expect(within(groups[1] as HTMLElement).getByText(/仅客服可见/)).toBeInTheDocument()
    expect(screen.getByText(/jason 提交了工单/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '查看用户' })).toHaveAttribute('href', '/sys/user?username=jason')

    const box = screen.getByLabelText('回复')
    fireEvent.change(box, { target: { value: '已确认' } })
    fireEvent.keyDown(box, { key: 'Enter', ctrlKey: true })
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/admin/tickets/${ticket.id}/messages`, expect.objectContaining({ method: 'POST' })))
  })

  // fix-decide1027b 第6项：详情气泡流里按时间居中显示状态/优先级/处理人变更与关闭、重新打开。
  it('shows ticket events as centered system lines in the chat stream', async () => {
    signIn({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['tickets.read', 'tickets.manage'] })
    const eventsDetail = {
      ticket: { ...detail.ticket, username: 'jason' },
      messages: [detail.messages[0]],
      events: [
        { id: 'e1', kind: 'status', from: 'open', to: 'processing', actor_kind: 'staff', actor_name: '小王', created_at: '2026-10-17T00:10:00Z' },
        { id: 'e2', kind: 'priority', from: 'normal', to: 'urgent', actor_kind: 'staff', actor_name: '小王', created_at: '2026-10-17T00:10:00Z' },
        { id: 'e3', kind: 'assignee', from: '', to: '小王', actor_kind: 'staff', actor_name: '小王', created_at: '2026-10-17T00:10:00Z' },
        { id: 'e4', kind: 'closed', from: 'processing', to: 'closed', actor_kind: 'customer', actor_name: 'jason', created_at: '2026-10-17T00:20:00Z' },
        { id: 'e5', kind: 'reopened', from: 'closed', to: 'processing', actor_kind: 'customer', actor_name: 'jason', created_at: '2026-10-17T00:30:00Z' },
      ],
    }
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => {
      if (path === `/v1/admin/tickets/${ticket.id}`) return json(eventsDetail)
      if (path === '/v1/admin/tickets/assignees') return json({ items: [] })
      return json({ unread: 0, items: [], total: 0 })
    }))
    const { container } = renderWithProviders(<TicketsPage mode="admin" />, [`/sys/tickets?id=${ticket.id}`])
    expect(await screen.findByText(/小王 将状态从「待处理」改为「处理中」/)).toBeInTheDocument()
    expect(screen.getByText(/小王 将优先级从「普通」改为「紧急」/)).toBeInTheDocument()
    expect(screen.getByText(/小王 将处理人改为「小王」/)).toBeInTheDocument()
    expect(screen.getByText(/jason 关闭了工单/)).toBeInTheDocument()
    expect(screen.getByText(/jason 重新打开了工单/)).toBeInTheDocument()
    const lines = [...container.querySelectorAll('.ticket-chat-system')].map((node) => node.textContent ?? '')
    const order = ['提交了工单', '改为「处理中」', '关闭了工单', '重新打开了工单']
      .map((text) => lines.findIndex((line) => line.includes(text)))
    expect(order.every((index, at) => index >= 0 && (at === 0 || index > order[at - 1]))).toBe(true)
    // 有事件时不再按 closed_at 时间戳另造一行"工单已关闭"。
    expect(lines.filter((line) => line.includes('工单已关闭'))).toHaveLength(0)
  })

  // fix-ticketops：管理员在列表行内改状态/关闭/删除，多选批量关闭/删除；详情页顶部关闭与删除；危险操作二次确认写明影响。
  it('lets staff change status, close and delete from the list, one by one and in batch', async () => {
    signIn({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['tickets.read', 'tickets.manage'] })
    const second = { ...ticket, id: '44444444-4444-4444-8444-444444444444', ticket_no: 10002, subject: '账单疑问', status: 'open', revision: 1 }
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path.startsWith('/v1/admin/tickets?')) return json({ items: [ticket, second], total: 2, limit: 20, offset: 0 })
      if (path === '/v1/admin/tickets/summary') return json({ unread: 0, pending: 1, mine: 0, sla_breached: 0 })
      if (init?.method === 'PATCH') return json(detail)
      if (init?.method === 'DELETE') return { ok: true, status: 204, text: vi.fn().mockResolvedValue('') } as unknown as Response
      return json({ code: 'ticket_not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<TicketsPage mode="admin" />)
    expect(await screen.findByRole('button', { name: '账单疑问' })).toBeInTheDocument()

    // 行内改状态：带该行 revision。
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '改状态 #10002' }))
    fireEvent.click(await screen.findByTitle('处理中'))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/admin/tickets/${second.id}`, expect.objectContaining({ method: 'PATCH' })))
    const [, patch] = fetchMock.mock.calls.find(([, i]) => i?.method === 'PATCH')!
    expect(JSON.parse(patch!.body as string)).toEqual({ expected_revision: 1, status: 'processing' })

    // 删除：先确认（写明不可恢复），再发 DELETE。
    fireEvent.click(screen.getByRole('button', { name: '删除工单 #10001' }))
    expect(await screen.findByText(/无法恢复/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '确认' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/admin/tickets/${ticket.id}`, expect.objectContaining({ method: 'DELETE' })))

    // 批量关闭：两行全选。
    fetchMock.mockClear()
    const table = within(screen.getByRole('table'))
    const rows = table.getAllByRole('checkbox')
    expect(rows).toHaveLength(3) // 全选 + 两行
    fireEvent.click(rows[1]); fireEvent.click(rows[2])
    expect(await screen.findByText('已选 2 个')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '批量关闭' }))
    expect(await screen.findByText('关闭选中的 2 个工单？')).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: '确认' }).at(-1)!)
    await waitFor(() => expect(fetchMock.mock.calls.filter(([, i]) => i?.method === 'PATCH')).toHaveLength(2))
    for (const [, init] of fetchMock.mock.calls.filter(([, i]) => i?.method === 'PATCH')) {
      expect(JSON.parse(init!.body as string)).toMatchObject({ status: 'closed' })
    }
  })

  it('hides list actions from read-only staff and lets managers delete from the detail page', async () => {
    signIn({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['tickets.read'] })
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => path.startsWith('/v1/admin/tickets?')
      ? json({ items: [ticket], total: 1, limit: 20, offset: 0 }) : json({ unread: 0 })))
    const { unmount } = renderWithProviders(<TicketsPage mode="admin" />)
    expect(await screen.findByRole('button', { name: '网站 502' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '删除工单 #10001' })).not.toBeInTheDocument()
    expect(within(screen.getByRole('table')).queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: '操作' })).not.toBeInTheDocument()
    unmount()

    signIn({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['platform.admin'] })
    const staffDetail = { ...detail, ticket: { ...detail.ticket, username: 'jason', assignee_user_id: '' } }
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path === `/v1/admin/tickets/${ticket.id}` && init?.method === 'DELETE') {
        return { ok: true, status: 204, text: vi.fn().mockResolvedValue('') } as unknown as Response
      }
      if (path === `/v1/admin/tickets/${ticket.id}` && init?.method === 'PATCH') return json({ ...staffDetail, ticket: { ...staffDetail.ticket, status: 'closed' } })
      if (path === `/v1/admin/tickets/${ticket.id}`) return json(staffDetail)
      if (path === '/v1/admin/tickets/assignees') return json({ items: [] })
      return json({ unread: 0, items: [], total: 0 })
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<TicketsPage mode="admin" />, [`/sys/tickets?id=${ticket.id}`])
    fireEvent.click(await screen.findByRole('button', { name: '关闭工单' }))
    expect(await screen.findByText(/7 天内重新打开/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '确认' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/admin/tickets/${ticket.id}`, expect.objectContaining({ method: 'PATCH' })))
    const [, patch] = fetchMock.mock.calls.find(([, i]) => i?.method === 'PATCH')!
    expect(JSON.parse(patch!.body as string)).toEqual({ expected_revision: 3, status: 'closed' })

    fireEvent.click(screen.getByRole('button', { name: '删除工单' }))
    expect(await screen.findByText(/无法恢复/)).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: '确认' }).at(-1)!)
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/v1/admin/tickets/${ticket.id}`, expect.objectContaining({ method: 'DELETE' })))
    expect(await screen.findByRole('list', { name: '工单概况' })).toBeInTheDocument()
  })

  it('fix-advfilter2: staff keep status + search in the row; category, priority, assignee and overdue fold into 高级筛选', async () => {
    localStorage.removeItem('cdnca.advancedFilters.tickets-admin')
    signIn({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['tickets.read'] })
    const paths: string[] = []
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => {
      if (path.startsWith('/v1/admin/tickets?')) { paths.push(path); return json({ items: [ticket], total: 1, limit: 20, offset: 0 }) }
      if (path === '/v1/admin/tickets/summary') return json({ unread: 0, pending: 0, mine: 0, sla_breached: 0 })
      return json({ code: 'ticket_not_found' }, 404)
    }))
    const last = () => new URLSearchParams(paths.at(-1)!.split('?')[1])
    renderWithProviders(<TicketsPage mode="admin" />)
    expect(await screen.findByRole('button', { name: '网站 502' })).toBeInTheDocument()

    const toggle = screen.getByRole('button', { name: '高级筛选' })
    const panel = document.getElementById(toggle.getAttribute('aria-controls')!)!
    expect(panel).not.toBeVisible()
    expect(within(panel).getByRole('combobox', { name: '优先级', hidden: true })).toBeInTheDocument()
    expect(within(panel).getByRole('combobox', { name: '处理人', hidden: true })).toBeInTheDocument()
    expect(within(panel).getByRole('combobox', { name: '分类', hidden: true })).toBeInTheDocument()

    fireEvent.change(screen.getByRole('textbox', { name: '编号或标题' }), { target: { value: '502' } })
    fireEvent.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(last().get('q')).toBe('502'))

    fireEvent.click(toggle)
    fireEvent.click(within(panel).getByRole('checkbox', { name: '只看超时' }))
    await waitFor(() => expect(last().get('sla_breached')).toBe('true'))
    expect(screen.getByRole('button', { name: '高级筛选 · 1' })).toBeInTheDocument()
    const tags = screen.getByRole('list', { name: '已启用的高级条件' })
    fireEvent.click(within(tags).getByRole('button', { name: '移除条件 只看超时' }))
    await waitFor(() => expect(last().get('sla_breached')).toBeNull())
    expect(last().get('q')).toBe('502')

    fireEvent.click(screen.getByRole('button', { name: '重置' }))
    await waitFor(() => expect(last().get('q')).toBeNull())
  })

  it('keeps the customer filters (status, category, search) in the row without 高级筛选', async () => {
    signIn({})
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => {
      if (path.startsWith('/v1/tickets?')) return json({ items: [ticket], total: 1, limit: 20, offset: 0 })
      if (path === '/v1/tickets/summary') return json({ unread: 0 })
      return json({ code: 'ticket_not_found' }, 404)
    }))
    renderWithProviders(<TicketsPage mode="user" />)
    expect(await screen.findByRole('button', { name: '网站 502' })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '分类' }).closest('[hidden]')).toBeNull()
    expect(screen.queryByRole('button', { name: /^高级筛选/ })).not.toBeInTheDocument()
  })

  it('shows the last replier column from last_reply_author (AUDIT-FINAL-1027 P6)', async () => {
    signIn({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['tickets.read'] })
    const second = { ...ticket, id: '44444444-4444-4444-8444-444444444444', ticket_no: 10002, subject: '账单疑问' }
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => {
      if (path.startsWith('/v1/admin/tickets?')) {
        return json({ items: [{ ...ticket, last_reply_author: '小王', last_reply_author_kind: 'staff' }, second], total: 2, limit: 20, offset: 0 })
      }
      if (path === '/v1/admin/tickets/summary') return json({ unread: 0, pending: 0, mine: 0, sla_breached: 0 })
      return json({ code: 'ticket_not_found' }, 404)
    }))
    renderWithProviders(<TicketsPage mode="admin" />)
    expect(await screen.findByRole('button', { name: '账单疑问' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '最后回复人' })).toBeInTheDocument()
    const [first, other] = within(screen.getByRole('table')).getAllByRole('row').slice(1)
    expect(within(first).getByText('小王')).toBeInTheDocument()
    expect(within(other).getByText('-')).toBeInTheDocument()
  })

  it('validates attachment type and size before upload', () => {
    expect(validateAttachment(new File(['x'], 'a.svg', { type: 'image/svg+xml' }))).toBe('type')
    expect(validateAttachment(new File([new Uint8Array((1 << 20) + 1)], 'a.txt', { type: 'text/plain' }))).toBe('size')
    expect(validateAttachment(new File(['x'], 'a.txt', { type: 'text/plain' }))).toBeNull()
  })
})
