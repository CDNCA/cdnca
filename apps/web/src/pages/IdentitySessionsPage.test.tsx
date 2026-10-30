import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { afterEach, vi } from 'vitest'

import { ApiError, type Principal } from '../api/auth'
import {
  identitySessionsApi,
  type IdentitySessionFamily,
  type IdentitySessionRevokeAttempt,
} from '../api/identitySessions'
import { resetSessionStore, useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import IdentitySessionsPage from './IdentitySessionsPage'

// OutcomeUnknown 的标题同时出现在恢复条和说明弹窗里，这里只认原位的恢复条。
const OUTCOME_BAR = { selector: '.cdnca-outcome-bar .ant-alert-message' }

const familyID = '11111111-1111-4111-8111-111111111111'
const otherFamily: IdentitySessionFamily = {
  family_id: familyID,
  device_label: 'Chrome on macOS',
  ip_prefix: '203.0.113.0/24',
  created_at: '2026-08-08T08:00:00Z',
  last_used_at: '2026-08-08T09:00:00Z',
  expires_at: '2026-08-09T08:00:00Z',
  current: false,
  active: true,
  session_count: 2,
  revision: 3,
}
const currentFamily: IdentitySessionFamily = {
  ...otherFamily,
  family_id: '22222222-2222-4222-8222-222222222222',
  device_label: 'Safari on iOS',
  current: true,
  session_count: 1,
}

function authenticate(actor = principal(), token = 'identity-session-token', update?: 'new' | 'refresh') {
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor, update)
}

function renderPage(queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, gcTime: Infinity } },
})) {
  const rendered = render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <IdentitySessionsPage />
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
  return { ...rendered, queryClient }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}

afterEach(() => vi.restoreAllMocks())

describe('IdentitySessionsPage', () => {
  beforeEach(async () => {
    resetSessionStore()
    await i18n.changeLanguage('zh-CN')
  })

  it('renders loading, empty, localized error/retry, 403, and no raw server text', async () => {
    authenticate()
    const pending = deferred<{ items: IdentitySessionFamily[] }>()
    vi.spyOn(identitySessionsApi, 'list')
      .mockReturnValueOnce(pending.promise)
      .mockRejectedValueOnce(new ApiError('private SQL and token', 503, 'identity_session_unavailable'))
      .mockRejectedValueOnce(new ApiError('private ACL', 403, 'permission_denied'))
    const user = userEvent.setup()
    renderPage()

    expect(await screen.findByLabelText('正在加载登录设备')).toBeInTheDocument()
    await act(async () => pending.resolve({ items: [] }))
    expect(await screen.findByText('暂无登录设备')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('登录设备服务暂不可用，请稍后重试。')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/private SQL|token/)
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('无权查看登录设备')).toBeInTheDocument()
  })

  it('shows classified devices, masked networks, localized states, and paginates', async () => {
    authenticate()
    vi.spyOn(identitySessionsApi, 'list')
      .mockResolvedValueOnce({ items: [currentFamily, otherFamily], next_cursor: 'next-page' })
      .mockResolvedValueOnce({ items: [{ ...otherFamily, family_id: '33333333-3333-4333-8333-333333333333', active: false, revoked_at: '2026-08-08T10:00:00Z' }] })
    const user = userEvent.setup()
    renderPage()

    expect(await screen.findByText('Chrome / macOS')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '登录设备' })).toHaveClass('ant-typography')
    expect(screen.getByRole('heading', { name: '登录设备' }).closest('.identity-sessions-page')).toHaveClass('identity-sessions-page')
    expect(document.querySelector('.identity-sessions-table-scroll')).toBeInTheDocument()
    expect(screen.getByText('Safari / iOS')).toBeInTheDocument()
    expect(screen.getAllByText('203.0.113.0/24')).toHaveLength(2)
    expect(screen.getByText('当前设备')).toBeInTheDocument()
    expect(screen.getAllByText('活跃').length).toBeGreaterThan(0)
    expect(document.body.textContent).not.toMatch(/Mozilla\/5\.0|203\.0\.113\.47|token hash/i)
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('已撤销')).toBeInTheDocument()
    expect(identitySessionsApi.list).toHaveBeenLastCalledWith(
      'identity-session-token', { limit: 20, cursor: 'next-page' }, expect.any(AbortSignal),
    )
  })

  it('confirms revoke and freezes the exact attempt while outcome is unknown', async () => {
    authenticate()
    vi.spyOn(identitySessionsApi, 'list').mockResolvedValue({ items: [otherFamily] })
    const revokeSpy = vi.spyOn(identitySessionsApi, 'revoke')
      .mockRejectedValueOnce(new ApiError('network detail', 0, 'network_error'))
      .mockResolvedValueOnce({
        family_id: familyID, revision: 4, revoked_at: '2026-08-08T10:00:00Z', current: false,
      })
    const user = userEvent.setup()
    renderPage()

    await user.click(await screen.findByRole('button', { name: '撤销设备' }))
    const dialog = await screen.findByRole('dialog', { name: '确认撤销设备' })
    await user.click(within(dialog).getByRole('button', { name: '确认撤销' }))
    expect(await screen.findByText('撤销结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    const firstAttempt = revokeSpy.mock.calls[0]?.[1] as IdentitySessionRevokeAttempt
    expect(firstAttempt).toMatchObject({ familyID, revision: 3 })
    expect(screen.getByRole('button', { name: '撤销设备' })).toBeDisabled()

    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(revokeSpy).toHaveBeenCalledTimes(2))
    expect(revokeSpy.mock.calls[1]?.[1]).toBe(firstAttempt)
    expect(await screen.findByText('已撤销')).toBeInTheDocument()
  })

  it('keeps an uncertain write frozen until abandon refresh succeeds', async () => {
    authenticate()
    const refresh = deferred<{ items: IdentitySessionFamily[] }>()
    const listSpy = vi.spyOn(identitySessionsApi, 'list')
      .mockResolvedValueOnce({ items: [otherFamily] })
      .mockReturnValueOnce(refresh.promise)
    vi.spyOn(identitySessionsApi, 'revoke')
      .mockRejectedValue(new ApiError('timeout', 504, 'identity_session_unavailable'))
    const user = userEvent.setup()
    renderPage()

    await user.click(await screen.findByRole('button', { name: '撤销设备' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '确认撤销' }))
    await user.click(await screen.findByRole('button', { name: '放弃并刷新' }))
    expect(screen.getByRole('button', { name: '撤销设备' })).toBeDisabled()
    expect(listSpy).toHaveBeenCalledTimes(2)
    await act(async () => refresh.resolve({ items: [otherFamily] }))
    await waitFor(() => expect(screen.getByRole('button', { name: '撤销设备' })).toBeEnabled())
  })

  it('binds reads to the full owner, keeps tokens out of keys, and ignores late old-owner data', async () => {
    const actorA = principal({ user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' })
    const actorB = principal({ user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' })
    authenticate(actorA, 'old-token')
    const oldRead = deferred<{ items: IdentitySessionFamily[] }>()
    const listSpy = vi.spyOn(identitySessionsApi, 'list')
      .mockReturnValueOnce(oldRead.promise)
      .mockResolvedValueOnce({ items: [otherFamily] })
    const { queryClient } = renderPage()

    expect(await screen.findByLabelText('正在加载登录设备')).toBeInTheDocument()
    await act(async () => {
      authenticate(actorA, 'refreshed-token', 'refresh')
      await Promise.resolve()
    })
    expect(listSpy).toHaveBeenCalledTimes(1)
    await act(async () => {
      authenticate(actorB, 'new-owner-token')
      await Promise.resolve()
    })
    expect(await screen.findByText('Chrome / macOS')).toBeInTheDocument()
    await act(async () => oldRead.resolve({ items: [currentFamily] }))
    expect(screen.queryByText('Safari / iOS')).not.toBeInTheDocument()
    for (const query of queryClient.getQueryCache().getAll()) {
      expect(JSON.stringify(query.queryKey)).not.toMatch(/old-token|refreshed-token|new-owner-token/)
    }
  })

  it('rejects malformed owner identity locally without an API request', async () => {
    const actors: Principal[] = [
      principal({ scope_id: '', tenant_id: null }),
      principal({ user_id: ' ' }),
      principal({ scope_kind: 'tenant', tenant_id: null }),
    ]
    const listSpy = vi.spyOn(identitySessionsApi, 'list')
    for (const actor of actors) {
      authenticate(actor)
      const { unmount } = renderPage()
      expect(await screen.findByText('无权查看登录设备')).toBeInTheDocument()
      unmount()
    }
    expect(listSpy).not.toHaveBeenCalled()
  })
})
