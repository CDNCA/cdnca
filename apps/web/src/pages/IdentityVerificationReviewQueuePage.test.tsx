import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  identityVerificationReviewQueueApi,
  type IdentityVerificationReviewCase,
} from '../api/identityVerificationReviewQueue'
import { resetSessionStore, useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import IdentityVerificationReviewQueuePage from './IdentityVerificationReviewQueuePage'

const reviewCase: IdentityVerificationReviewCase = {
  id: '11111111-1111-4111-8111-111111111111',
  applicant_user_id: '22222222-2222-4222-8222-222222222222',
  kind: 'enterprise',
  status: 'reviewing',
  reviewer_user_id: '33333333-3333-4333-8333-333333333333',
  revision: 3,
  created_at: '2026-08-06T08:00:00Z',
  state_changed_at: '2026-08-06T08:30:00Z',
  submitted_at: '2026-08-06T08:10:00Z',
  expires_at: '2026-08-07T08:10:00Z',
}

function reviewer(overrides: Partial<Principal> = {}) {
  return principal({
    permissions: ['identity_verification.read', 'identity_verification.review'],
    ...overrides,
  })
}

function authenticate(actor = reviewer(), token = 'review-token', update?: 'new' | 'refresh') {
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor, update)
  return useSessionStore.getState().sessionEpoch
}

function renderPage(queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, gcTime: Infinity } },
})) {
  const result = render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/sys/identity-verification']}>
            <IdentityVerificationReviewQueuePage />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
  return { ...result, queryClient }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}

async function chooseOpenOption(user: ReturnType<typeof userEvent.setup>, label: string) {
  const candidates = await screen.findAllByText(label)
  const option = candidates.find((candidate) => candidate.closest('.ant-select-item-option'))
  if (!option) throw new Error(`open option not found: ${label}`)
  await user.click(option)
}

describe('IdentityVerificationReviewQueuePage', () => {
  beforeEach(async () => {
    resetSessionStore()
    await i18n.changeLanguage('zh-CN')
  })

  it.each([
    ['missing read', reviewer({ permissions: ['identity_verification.review'] })],
    ['missing review', reviewer({ permissions: ['identity_verification.read'] })],
    ['platform identity', reviewer({ scope_kind: 'platform', tenant_id: null })],
    ['missing scope', reviewer({ scope_id: '' })],
    ['missing user', reviewer({ user_id: '' })],
  ])('renders a local 403 with zero requests for %s', async (_name, actor) => {
    authenticate(actor)
    const listSpy = vi.spyOn(identityVerificationReviewQueueApi, 'list')

    renderPage()

    expect(await screen.findByText('无权审核实名认证')).toBeInTheDocument()
    expect(listSpy).not.toHaveBeenCalled()
  })

  it('renders natural loading, empty, localized error/retry, and server 403 states', async () => {
    authenticate()
    const pending = deferred<{ items: IdentityVerificationReviewCase[] }>()
    vi.spyOn(identityVerificationReviewQueueApi, 'list')
      .mockReturnValueOnce(pending.promise)
      .mockRejectedValueOnce(new ApiError('raw private backend message', 503, 'identity_verification_unavailable'))
      .mockResolvedValueOnce({ items: [reviewCase] })
      .mockRejectedValueOnce(new ApiError('raw policy detail', 403, 'identity_verification_permission_denied'))
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByLabelText('正在加载实名认证审核队列')).toBeInTheDocument()

    await act(async () => pending.resolve({ items: [] }))
    expect(await screen.findByText('暂无待处理的实名认证案件')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('实名认证审核服务暂不可用，请稍后重试')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw private backend message')

    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText(reviewCase.id)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('无权审核实名认证')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw policy detail')
  })

  it('filters, paginates by cursor, and links each case to the canonical detail route', async () => {
    authenticate()
    const second = {
      ...reviewCase,
      id: '44444444-4444-4444-8444-444444444444',
      status: 'submitted' as const,
    }
    const listSpy = vi.spyOn(identityVerificationReviewQueueApi, 'list')
      .mockImplementation(async (_token, params) => params?.cursor
        ? { items: [second] }
        : { items: [reviewCase], next_cursor: 'next-page' })
    const user = userEvent.setup()

    renderPage()
    const firstLink = await screen.findByRole('link', { name: reviewCase.id })
    expect(firstLink).toHaveAttribute('href', `/sys/identity-verification/${reviewCase.id}`)
    const firstRow = firstLink.closest('tr')!
    expect(within(firstRow).getByText('企业认证')).toBeInTheDocument()
    expect(within(firstRow).getByText('审核中')).toBeInTheDocument()

    await user.click(screen.getByRole('combobox', { name: '认证类型' }))
    await chooseOpenOption(user, '企业认证')
    await user.click(screen.getByRole('combobox', { name: '案件状态' }))
    await chooseOpenOption(user, '审核中')
    await user.click(screen.getByRole('combobox', { name: '每页数量' }))
    await chooseOpenOption(user, '50')
    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith('review-token', {
      kind: 'enterprise', status: 'reviewing', limit: 50, cursor: undefined,
    }))

    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText(second.id)).toBeInTheDocument()
    expect(listSpy).toHaveBeenLastCalledWith('review-token', {
      kind: 'enterprise', status: 'reviewing', limit: 50, cursor: 'next-page',
    })
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
  })

  it('preserves filters, cursor, and token-free cache identity across a token refresh', async () => {
    const actor = reviewer()
    const epoch = authenticate(actor, 'old-review-token')
    const second = { ...reviewCase, id: '44444444-4444-4444-8444-444444444444' }
    const listSpy = vi.spyOn(identityVerificationReviewQueueApi, 'list')
      .mockImplementation(async (_token, params) => params?.cursor
        ? { items: [second] }
        : { items: [reviewCase], next_cursor: 'next-page' })
    const user = userEvent.setup()
    const { queryClient } = renderPage()

    expect(await screen.findByText(reviewCase.id)).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: '认证类型' }))
    await chooseOpenOption(user, '企业认证')
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText(second.id)).toBeInTheDocument()
    const callsBeforeRefresh = listSpy.mock.calls.length

    await act(async () => {
      authenticate(actor, 'new-review-token', 'refresh')
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(listSpy).toHaveBeenCalledTimes(callsBeforeRefresh)
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    expect(queryClient.getQueryCache().getAll().some((query) => (
      JSON.stringify(query.queryKey).includes('enterprise')
    ))).toBe(true)
    for (const query of queryClient.getQueryCache().getAll()) {
      expect(JSON.stringify(query.queryKey)).not.toMatch(/old-review-token|new-review-token/)
    }

    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(listSpy).toHaveBeenCalledTimes(callsBeforeRefresh + 1))
    expect(listSpy.mock.calls.at(-1)?.[0]).toBe('new-review-token')
    expect(listSpy.mock.calls.at(-1)?.[1]).toMatchObject({
      kind: 'enterprise', limit: 20, cursor: 'next-page',
    })
  })

  it('clears old owner cache and ignores a late response after a new session', async () => {
    const actorA = reviewer({ user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' })
    const actorB = reviewer({ user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' })
    authenticate(actorA, 'session-a-token')
    const pendingA = deferred<{ items: IdentityVerificationReviewCase[] }>()
    vi.spyOn(identityVerificationReviewQueueApi, 'list')
      .mockReturnValueOnce(pendingA.promise)
      .mockResolvedValueOnce({ items: [{ ...reviewCase, applicant_user_id: actorB.user_id }] })
    const { queryClient } = renderPage()

    expect(await screen.findByLabelText('正在加载实名认证审核队列')).toBeInTheDocument()
    await act(async () => {
      authenticate(actorB, 'session-b-token')
      await Promise.resolve()
    })
    expect(await screen.findByText(actorB.user_id)).toBeInTheDocument()

    await act(async () => pendingA.resolve({ items: [{ ...reviewCase, applicant_user_id: '迟到旧申请人' }] }))
    expect(screen.queryByText('迟到旧申请人')).not.toBeInTheDocument()
    const keys = queryClient.getQueryCache().getAll().map((query) => JSON.stringify(query.queryKey))
    expect(keys.some((key) => key.includes(actorA.user_id))).toBe(false)
    expect(keys.some((key) => key.includes(actorB.user_id))).toBe(true)
  })
})
