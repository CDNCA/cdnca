import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CdncaProvider } from '@cdnca/ui'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { SessionQueryBoundary } from '../auth/SessionQueryBoundary'
import { useSessionStore } from '../auth/session'
import AccountSubscriptionsPage from '../pages/AccountSubscriptionsPage'
import { authResponse, principal } from '../test/fixtures'

// 代登录用户的订阅写入还在途时代登录到期、恢复为管理员身份，
// 迟到的失败/成功只归原身份：管理员页不显示"部分提醒项加载或保存失败"、不出现原用户的重试目标；
// 回到原身份（A→B→A）也不把旧尝试的结果当作新身份的当前状态。

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const subscription = (event_type: string) => ({ event_type, sms_enabled: false, email_enabled: true,
  sms_supported: true, email_supported: true, revision: 0, changed: false })

const admin = principal({ user_id: '99999999-9999-4999-8999-999999999999', scope_id: '88888888-8888-4888-8888-888888888888',
  scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['tickets.manage'] })
const tenant = principal({})

function deferred() {
  let resolve!: (value: Response) => void
  const promise = new Promise<Response>((done) => { resolve = done })
  return { promise, resolve }
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
  return render(
    <CdncaProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/account/subscribe']}>
          <SessionQueryBoundary><AccountSubscriptionsPage /></SessionQueryBoundary>
        </MemoryRouter>
      </QueryClientProvider>
    </CdncaProvider>,
  )
}

function transition(next: typeof admin) {
  const epoch = useSessionStore.getState().sessionEpoch
  act(() => { expect(useSessionStore.getState().transitionPrincipal(epoch, next)).toBe(true) })
}

afterEach(() => vi.unstubAllGlobals())

describe('AccountSubscriptionsPage identity isolation', () => {
  it('drops a late group write failure from the tenant session after impersonation ends (A -> B -> A)', async () => {
    useSessionStore.getState().setSession({ ...authResponse(tenant), access_token: 'sub-token' }, tenant)
    const late = deferred()
    const fetchMock = vi.fn(async (path: string, init?: RequestInit) => {
      const event = decodeURIComponent(path.split('/').pop()!)
      if (init?.method === 'PUT') return event === 'package.monitor.traffic.triggered' ? late.promise : json({ ...subscription(event), email_enabled: false, revision: 1, changed: true })
      return json(subscription(event))
    })
    vi.stubGlobal('fetch', fetchMock)
    renderPage()
    fireEvent.click(await screen.findByRole('checkbox', { name: '流量超限 邮件提醒' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([path, i]) =>
      i?.method === 'PUT' && String(path).endsWith('/package.monitor.traffic.triggered'))).toBe(true))

    // 代登录到期：恢复为管理员（新 epoch），页面保留。
    transition(admin)
    expect(await screen.findByRole('checkbox', { name: '有新工单 邮件提醒' })).toBeInTheDocument()
    await act(async () => {
      late.resolve(json({ error: { code: 'internal_error', message: 'internal_error', request_id: 'r-late' } }, 500))
      await late.promise
    })
    await act(async () => { await new Promise((done) => setTimeout(done, 20)) })
    expect(screen.queryByText(/部分提醒项加载或保存失败/)).not.toBeInTheDocument()
    expect(screen.queryByText(/保存失败/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /重试/ })).not.toBeInTheDocument()
    expect(screen.queryByText('流量超限')).not.toBeInTheDocument()

    // 回到原租户身份（又一个新 epoch）：旧尝试不算这次会话的失败，也不残留重试目标。
    transition(tenant)
    expect(await screen.findByRole('checkbox', { name: '流量超限 邮件提醒' })).toBeInTheDocument()
    expect(screen.queryByText(/保存失败/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /流量超限 重试/ })).not.toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: '流量超限 邮件提醒' })).not.toBeDisabled()
  })

  it('keeps the current identity state across a same-epoch token refresh', async () => {
    useSessionStore.getState().setSession({ ...authResponse(tenant), access_token: 'sub-token' }, tenant)
    const late = deferred()
    vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
      const event = decodeURIComponent(path.split('/').pop()!)
      if (init?.method === 'PUT' && event === 'package.monitor.traffic.triggered') return late.promise
      if (init?.method === 'PUT') return json({ ...subscription(event), email_enabled: false, revision: 1, changed: true })
      return json(subscription(event))
    }))
    renderPage()
    fireEvent.click(await screen.findByRole('checkbox', { name: '流量超限 邮件提醒' }))
    // token 刷新不换身份、不换 epoch：在途写入的失败照常显示给本人，可重试。
    act(() => { useSessionStore.getState().setSession({ ...authResponse(tenant), access_token: 'sub-token-2' }, tenant, 'refresh') })
    await act(async () => {
      late.resolve(json({ error: { code: 'internal_error', message: 'internal_error', request_id: 'r-1' } }, 500))
      await late.promise
    })
    expect(await screen.findByRole('button', { name: '流量超限 重试' })).toBeInTheDocument()
  })
})
