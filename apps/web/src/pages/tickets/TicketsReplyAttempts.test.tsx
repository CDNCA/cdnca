import { act, fireEvent, screen, waitFor } from '@testing-library/react'
import { useNavigate } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import TicketsPage from './TicketsPage'

// 
// 每笔结果未知的回复按 身份+工单 保留原 key 与原输入；迟到结果只更新发起时的工单，不串到当前详情、不清当前草稿。

function json(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, text: vi.fn().mockResolvedValue(JSON.stringify(body)) } as unknown as Response
}

type Fetch = (path: string, init?: RequestInit) => Promise<Response>
type Outcome = 'lost' | 'ok' | 500 | 409 | Promise<void>

const ids = { a: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', b: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' } as const
type Name = keyof typeof ids

function ticketOf(name: Name) {
  return {
    id: ids[name], ticket_no: name === 'a' ? 10001 : 10002, category: 'technical', subject: `工单${name.toUpperCase()}`,
    priority: 'normal', status: 'open', unread: false, revision: 1, last_message_at: '2026-10-17T01:00:00Z',
    created_at: '2026-10-17T00:00:00Z', updated_at: '2026-10-17T01:00:00Z',
  }
}

// 假后端按 工单+key 去重；outcomes[name] 依次决定该工单每次回复“写入后”返回什么。
function fakeBackend(outcomes: Record<Name, Outcome[]>) {
  const keys: Record<Name, string[]> = { a: [], b: [] }
  const stored: Record<Name, Map<string, string>> = { a: new Map(), b: new Map() }
  const messages = (name: Name) => [...stored[name].values()].map((body, index) => ({
    id: `${name}-m${index}`, author_kind: 'customer', author_name: 'jason', body: (JSON.parse(body) as { body: string }).body,
    attachments: [], created_at: '2026-10-17T02:00:00Z',
  }))
  const detailOf = (name: Name) => ({ ticket: ticketOf(name), messages: messages(name) })
  const fetchMock = vi.fn<Fetch>(async (path, init) => {
    for (const name of ['a', 'b'] as const) {
      if (path === `/v1/tickets/${ids[name]}/messages` && init?.method === 'POST') {
        const key = (init.headers as Record<string, string>)['Idempotency-Key']
        keys[name].push(key)
        if (!stored[name].has(key)) stored[name].set(key, init.body as string)
        const outcome = outcomes[name].shift() ?? 'ok'
        if (outcome instanceof Promise) await outcome
        if (outcome === 'lost') throw new TypeError('Failed to fetch')
        if (outcome === 500) return json({ code: 'internal' }, 500)
        if (outcome === 409) return json({ code: 'ticket_invalid_state' }, 409)
        return json(detailOf(name), 201)
      }
      if (path === `/v1/tickets/${ids[name]}`) return json(detailOf(name))
    }
    if (path === '/v1/tickets/summary') return json({ unread: 0 })
    if (path.startsWith('/v1/tickets?')) return json({ items: [ticketOf('a'), ticketOf('b')], total: 2, limit: 20, offset: 0 })
    return json({ code: 'ticket_not_found' }, 404)
  })
  return { fetchMock, keys, records: (name: Name) => stored[name].size }
}

function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>((done) => { resolve = done })
  return { promise, resolve }
}

// 浏览器历史菜单可表达的跳转：不经列表直接回到两步前的详情（同一 TicketsPage 保持挂载）。
function HistoryJump() {
  const navigate = useNavigate()
  return <button type="button" onClick={() => navigate(-2)}>历史跳转</button>
}

function signIn(overrides: Parameters<typeof principal>[0] = {}) {
  const user = principal(overrides)
  useSessionStore.getState().setSession({ ...authResponse(user), access_token: 'ticket-token' }, user)
}

async function open(name: Name) {
  fireEvent.click(await screen.findByRole('button', { name: `工单${name.toUpperCase()}` }))
  expect(await screen.findByRole('heading', { name: `工单${name.toUpperCase()}` })).toBeInTheDocument()
  await screen.findByLabelText('回复')
}

async function back() {
  fireEvent.click(screen.getByRole('button', { name: '返回列表' }))
  await screen.findByRole('button', { name: '工单A' })
}

function type(body: string) {
  fireEvent.change(screen.getByLabelText('回复'), { target: { value: body } })
}

beforeEach(async () => {
  await changeLocale('zh-CN')
})
afterEach(() => vi.unstubAllGlobals())

describe('TicketsPage reply attempts (TKT-01)', () => {
  it('keeps each ticket its own unknown reply: A unknown, B unknown, back to A replays with A\'s key', async () => {
    signIn()
    const api = fakeBackend({ a: ['lost'], b: ['lost'] })
    vi.stubGlobal('fetch', api.fetchMock)
    renderWithProviders(<TicketsPage mode="user" />)
    await open('a'); type('A 的回复'); fireEvent.click(screen.getByRole('button', { name: '发送' }))
    expect(await screen.findByRole('button', { name: '查询结果/重试' })).toBeInTheDocument()
    await back()
    await open('b'); type('B 的回复'); fireEvent.click(screen.getByRole('button', { name: '发送' }))
    expect(await screen.findByRole('button', { name: '查询结果/重试' })).toBeInTheDocument()
    await back()
    await open('a')
    // 返回 A：未决草稿与查询入口随工单恢复。
    expect(screen.getByLabelText('回复')).toHaveValue('A 的回复')
    expect(screen.getByText(/发送结果未知/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '查询结果/重试' }))
    await waitFor(() => expect(screen.getByLabelText('回复')).toHaveValue(''))
    expect(api.keys.a).toHaveLength(2)
    expect(api.keys.a[1]).toBe(api.keys.a[0])
    expect(api.records('a')).toBe(1)
    // B 的未决尝试不受 A 完成影响。
    await back()
    await open('b')
    expect(screen.getByLabelText('回复')).toHaveValue('B 的回复')
    fireEvent.click(screen.getByRole('button', { name: '查询结果/重试' }))
    await waitFor(() => expect(api.keys.b).toHaveLength(2))
    expect(api.keys.b[1]).toBe(api.keys.b[0])
    expect(api.records('b')).toBe(1)
  })

  it('replays the original key when the same text is typed again after leaving and coming back', async () => {
    signIn()
    const api = fakeBackend({ a: ['lost'], b: ['lost'] })
    vi.stubGlobal('fetch', api.fetchMock)
    renderWithProviders(<TicketsPage mode="user" />)
    await open('a'); type('A 的回复'); fireEvent.click(screen.getByRole('button', { name: '发送' }))
    await screen.findByRole('button', { name: '查询结果/重试' })
    await back()
    await open('b'); type('B 的回复'); fireEvent.click(screen.getByRole('button', { name: '发送' }))
    await screen.findByRole('button', { name: '查询结果/重试' })
    await back()
    await open('a')
    type(''); type('A 的回复')
    fireEvent.click(screen.getByRole('button', { name: '查询结果/重试' }))
    await waitFor(() => expect(api.keys.a).toHaveLength(2))
    expect(api.keys.a[1]).toBe(api.keys.a[0])
    expect(api.records('a')).toBe(1)
  })

  it('keeps the fixed control: A finishing late does not drop B\'s unknown key', async () => {
    signIn()
    const late = deferred()
    const api = fakeBackend({ a: [late.promise], b: ['lost'] })
    vi.stubGlobal('fetch', api.fetchMock)
    renderWithProviders(<TicketsPage mode="user" />)
    await open('a'); type('A 的回复'); fireEvent.click(screen.getByRole('button', { name: '发送' }))
    await waitFor(() => expect(api.keys.a).toHaveLength(1))
    await back()
    await open('b'); type('B 的回复'); fireEvent.click(screen.getByRole('button', { name: '发送' }))
    await screen.findByRole('button', { name: '查询结果/重试' })
    await act(async () => late.resolve())
    expect(screen.getByRole('heading', { name: '工单B' })).toBeInTheDocument()
    expect(screen.getByLabelText('回复')).toHaveValue('B 的回复')
    fireEvent.click(screen.getByRole('button', { name: '查询结果/重试' }))
    await waitFor(() => expect(api.keys.b).toHaveLength(2))
    expect(api.keys.b[1]).toBe(api.keys.b[0])
    expect(api.records('b')).toBe(1)
  })

  it.each([['ok' as const], [500 as const], [409 as const]])(
    'routes a late A result (%s) to A only after a history jump to B', async (result) => {
      signIn()
      const late = deferred()
      const api = fakeBackend({ a: [late.promise], b: [] })
      // 500/409 由 fetch 在迟到后返回。
      if (result !== 'ok') {
        const base = api.fetchMock.getMockImplementation()!
        api.fetchMock.mockImplementation(async (path, init) => {
          if (path === `/v1/tickets/${ids.a}/messages` && init?.method === 'POST') {
            api.keys.a.push((init.headers as Record<string, string>)['Idempotency-Key'])
            await late.promise
            return json({ code: result === 500 ? 'internal' : 'ticket_invalid_state' }, result)
          }
          return base(path, init)
        })
      }
      vi.stubGlobal('fetch', api.fetchMock)
      renderWithProviders(<><HistoryJump /><TicketsPage mode="user" /></>)
      await open('b'); await back()
      await open('a'); type('A 的回复'); fireEvent.click(screen.getByRole('button', { name: '发送' }))
      await waitFor(() => expect(api.keys.a).toHaveLength(1))
      fireEvent.click(screen.getByRole('button', { name: '历史跳转' }))
      expect(await screen.findByRole('heading', { name: '工单B' })).toBeInTheDocument()
      type('B尚未发送的草稿')
      await act(async () => late.resolve())
      await act(async () => { await new Promise((done) => setTimeout(done, 20)) })
      expect(screen.getByRole('heading', { level: 4 })).toHaveTextContent('工单B')
      expect(screen.getByLabelText('回复')).toHaveValue('B尚未发送的草稿')
      expect(screen.queryByText(/发送结果未知/)).not.toBeInTheDocument()
      expect(screen.queryByText('工单当前状态不允许这个操作')).not.toBeInTheDocument()
      expect(screen.queryByText(/操作失败/)).not.toBeInTheDocument()
      // B 的后续发送仍以 B 为目标。
      fireEvent.click(screen.getByRole('button', { name: '发送' }))
      await waitFor(() => expect(api.records('b')).toBe(1))
      expect(api.keys.a).toHaveLength(1)
    })

  it('treats the same text sent again after a success as a new reply', async () => {
    signIn()
    const api = fakeBackend({ a: [], b: [] })
    vi.stubGlobal('fetch', api.fetchMock)
    renderWithProviders(<TicketsPage mode="user" />)
    await open('a'); type('同样的话'); fireEvent.click(screen.getByRole('button', { name: '发送' }))
    await waitFor(() => expect(screen.getByLabelText('回复')).toHaveValue(''))
    type('同样的话'); fireEvent.click(screen.getByRole('button', { name: '发送' }))
    await waitFor(() => expect(api.keys.a).toHaveLength(2))
    expect(api.keys.a[1]).not.toBe(api.keys.a[0])
    expect(api.records('a')).toBe(2)
  })

  it('does not hand one identity\'s unknown reply to another identity', async () => {
    signIn({ user_id: '11111111-1111-4111-8111-111111111111' })
    const api = fakeBackend({ a: ['lost'], b: [] })
    vi.stubGlobal('fetch', api.fetchMock)
    renderWithProviders(<TicketsPage mode="user" />)
    await open('a'); type('A 的回复'); fireEvent.click(screen.getByRole('button', { name: '发送' }))
    await screen.findByRole('button', { name: '查询结果/重试' })
    act(() => signIn({ user_id: '22222222-2222-4222-8222-222222222222' }))
    await waitFor(() => expect(screen.getByLabelText('回复')).toHaveValue(''))
    expect(screen.queryByText(/发送结果未知/)).not.toBeInTheDocument()
    type('A 的回复'); fireEvent.click(screen.getByRole('button', { name: '发送' }))
    await waitFor(() => expect(api.keys.a).toHaveLength(2))
    expect(api.keys.a[1]).not.toBe(api.keys.a[0])
  })
})
