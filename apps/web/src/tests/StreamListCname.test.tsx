import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { vi } from 'vitest'

import type { Stream, StreamListResponse } from '../api/streams'
import { useSessionStore } from '../auth/session'
import StreamListPage from '../pages/StreamListPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

import { stream } from './streamFixture'

function listResponse(items: Stream[]): Response {
  const body: StreamListResponse = { items, total: items.length, page: 1, limit: 10 }
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

function authenticateAdmin() {
  const user = principal({
    scope_kind: 'platform', tenant_id: null, username: 'admin', display_name: 'admin', roles: ['platform_admin'],
    permissions: ['platform.admin'],
  })
  useSessionStore.getState().setSession(authResponse(user), user)
}

const listCalls = (spy: { mock: { calls: unknown[][] } }) =>
  spy.mock.calls.filter(([input]) => String(input).includes('/v1/streams?')).length

// 四层转发自有 CNAME（迁移 505）：CNAME 主机名列显示真实值与 生成中 / 已生成 / 失败可重试，
// 生成中时与网站列表一样 2 秒轮询一次，最多 60 秒。
describe('StreamListPage own CNAME', () => {
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); useSessionStore.getState().clearSession() })

  it('shows 生成中 and polls every 2 s for at most 60 s, then the generated hostname', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    authenticateAdmin()
    const pending: Stream = { ...stream, cname: null, cname_domain: 'stream.example', cname_state: 'pending' }
    const done: Stream = { ...stream, cname: 'k3x9w1ab.stream.example', cname_domain: 'stream.example', cname_state: 'done' }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => listResponse([pending]))
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    const row = (await screen.findByText('TCP gateway')).closest('tr')!
    expect(within(row).getByTestId('stream-cname-pending')).toHaveTextContent('生成中')
    const initial = listCalls(fetchSpy)
    await act(async () => { await vi.advanceTimersByTimeAsync(2100) })
    await waitFor(() => expect(listCalls(fetchSpy)).toBe(initial + 1))
    // Still pending: polling stops once 60 s have passed.
    await act(async () => { await vi.advanceTimersByTimeAsync(62_000) })
    const capped = listCalls(fetchSpy)
    // About one poll per 2 s within the 60 s window (29-31 polls), none after.
    expect(capped - initial).toBeGreaterThanOrEqual(28)
    expect(capped - initial).toBeLessThanOrEqual(31)
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000) })
    expect(listCalls(fetchSpy)).toBe(capped)

    fetchSpy.mockImplementation(async () => listResponse([done]))
    fireEvent.click(screen.getByRole('button', { name: /刷新/u }))
    expect(await screen.findByText('k3x9w1ab.stream.example')).toBeInTheDocument()
    expect(screen.queryByTestId('stream-cname-pending')).not.toBeInTheDocument()
  })

  it('shows 生成失败 with the reason and retries with cname_regenerate', async () => {
    authenticateAdmin()
    const failed: Stream = {
      ...stream, cname: null, cname_domain: 'stream.example', cname_state: 'failed',
      cname_failure_code: 'cname_zone_not_configured',
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (String(input).includes('/v1/streams/batch-action')) {
        const body = JSON.parse(String(init?.body)) as { action: string; items: Array<{ id: string }> }
        return new Response(JSON.stringify({ items: body.items.map((item) => ({ id: item.id, status: 'updated' })) }),
          { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return listResponse([failed])
    })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    const row = (await screen.findByText('TCP gateway')).closest('tr')!
    const cell = within(row).getByTestId('stream-cname-failed')
    fireEvent.click(within(cell).getByRole('button'))
    expect(await screen.findByText(/套餐 CNAME 域名 stream.example 未在 DNS 配置的 CNAME 域名里/u)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '重新生成' }))
    await waitFor(() => {
      const call = fetchSpy.mock.calls.find(([input]) => String(input).includes('/v1/streams/batch-action'))
      expect(call).toBeDefined()
      expect(JSON.parse(String(call![1]?.body))).toEqual({
        action: 'cname_regenerate', items: [{ id: stream.id, expected_revision: stream.revision }],
      })
    })
  })
})
