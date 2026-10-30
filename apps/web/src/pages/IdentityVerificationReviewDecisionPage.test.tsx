import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

import { ApiError } from '../api/auth'
import {
  identityVerificationReviewDecisionApi,
  type IdentityVerificationReviewCase,
} from '../api/identityVerificationReviewDecision'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import IdentityVerificationReviewDecisionPage from './IdentityVerificationReviewDecisionPage'

// 结果未知改为 OutcomeUnknown 后，弹窗标题与原位恢复条（或表单内 Alert）同文案；断言原位提示
const OUTCOME_BAR = '.ant-alert-message'

const caseID = '11111111-1111-4111-8111-111111111111'
const reviewing: IdentityVerificationReviewCase = {
  id: caseID,
  applicant_user_id: '22222222-2222-4222-8222-222222222222',
  kind: 'personal_initial',
  status: 'reviewing',
  reviewer_user_id: '11111111-1111-4111-8111-111111111111',
  revision: 2,
  created_at: '2026-08-06T08:09:10Z',
  state_changed_at: '2026-08-06T08:10:10Z',
  retention: {
    eligible: false,
    eligible_at: '2032-08-04T08:09:10Z',
    reason_code: 'case_not_terminal',
  },
  materials: [],
  replayed: false,
}

function authenticate(
  overrides: Partial<ReturnType<typeof principal>> = {},
  token = 'review-token',
  update: 'new' | 'refresh' = 'new',
) {
  const actor = principal({
    permissions: ['identity_verification.read', 'identity_verification.review'],
    ...overrides,
  })
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor, update)
  return actor
}

function renderPage(queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, gcTime: Infinity } },
})) {
  return {
    queryClient,
    ...render(
      <ConfigProvider button={{ autoInsertSpace: false }}>
        <AntApp>
          <QueryClientProvider client={queryClient}>
            <MemoryRouter initialEntries={[`/sys/identity-verification/${caseID}/decision`]}>
              <Routes>
                <Route path="/sys/identity-verification/:caseId/decision" element={<IdentityVerificationReviewDecisionPage />} />
              </Routes>
            </MemoryRouter>
          </QueryClientProvider>
        </AntApp>
      </ConfigProvider>,
    ),
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}

describe('IdentityVerificationReviewDecisionPage', () => {
  afterEach(() => vi.restoreAllMocks())

  it.each([
    ['missing read', principal({ permissions: ['identity_verification.review'] })],
    ['missing review', principal({ permissions: ['identity_verification.read'] })],
    ['platform principal', principal({
      scope_kind: 'platform', tenant_id: null,
      permissions: ['identity_verification.read', 'identity_verification.review'],
    })],
  ])('fails closed with local 403 and zero requests for %s', async (_case, actor) => {
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const getSpy = vi.spyOn(identityVerificationReviewDecisionApi, 'getCase')
    const decideSpy = vi.spyOn(identityVerificationReviewDecisionApi, 'decide')
    renderPage()

    expect(await screen.findByText('无权审批实名认证')).toBeInTheDocument()
    expect(getSpy).not.toHaveBeenCalled()
    expect(decideSpy).not.toHaveBeenCalled()
  })

  it('renders loading, detail, localized error retry, 404, and server 403 states', async () => {
    authenticate()
    const pending = deferred<IdentityVerificationReviewCase>()
    const getSpy = vi.spyOn(identityVerificationReviewDecisionApi, 'getCase')
      .mockImplementationOnce(() => pending.promise)
      .mockRejectedValueOnce(new ApiError('private topology', 503, 'identity_verification_unavailable'))
      .mockResolvedValueOnce(reviewing)
      .mockRejectedValueOnce(new ApiError('private case', 404, 'identity_verification_not_found'))
      .mockRejectedValueOnce(new ApiError('private grant', 403, 'identity_verification_permission_denied'))
    const user = userEvent.setup()
    renderPage()

    expect(screen.getByLabelText('实名认证审批状态')).toHaveAttribute('aria-busy', 'true')
    pending.resolve(reviewing)
    expect(await screen.findByText('审核中')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '返回案件详情' }))
      .toHaveAttribute('href', `/sys/identity-verification/${caseID}`)

    await user.click(screen.getByRole('button', { name: '刷新案件' }))
    expect(await screen.findByText('实名认证服务暂不可用，请稍后重试。')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('private topology')
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('审核中')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '刷新案件' }))
    expect(await screen.findByText('未找到实名认证案件')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '刷新案件' }))
    expect(await screen.findByText('无权审批实名认证')).toBeInTheDocument()
    expect(getSpy).toHaveBeenCalledTimes(5)
  })

  it('requires explicit confirmation and submits only stable decision reasons', async () => {
    authenticate()
    vi.spyOn(identityVerificationReviewDecisionApi, 'getCase').mockResolvedValue(reviewing)
    const decideSpy = vi.spyOn(identityVerificationReviewDecisionApi, 'decide')
      .mockResolvedValue({ ...reviewing, status: 'rejected', revision: 3 })
    const user = userEvent.setup()
    renderPage()

    expect(await screen.findByText('审核中')).toBeInTheDocument()
    await user.click(screen.getByLabelText('拒绝'))
    await user.click(screen.getByLabelText('证据不完整'))
    await user.click(screen.getByRole('button', { name: '提交审批决定' }))
    expect(decideSpy).not.toHaveBeenCalled()
    await user.click(await screen.findByRole('button', { name: '确认提交' }))
    expect(await screen.findByText('已拒绝')).toBeInTheDocument()
    expect(decideSpy).toHaveBeenCalledWith(
      'review-token', caseID, 2,
      { decision: 'rejected', reason_code: 'evidence_incomplete' },
      expect.objectContaining({ requestId: expect.any(String), idempotencyKey: expect.any(String) }),
    )
    expect(document.querySelector('textarea')).toBeNull()
  })

  it('does not allow a decision for a case assigned to another reviewer', async () => {
    authenticate()
    vi.spyOn(identityVerificationReviewDecisionApi, 'getCase').mockResolvedValue({
      ...reviewing, reviewer_user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    })
    const decideSpy = vi.spyOn(identityVerificationReviewDecisionApi, 'decide')

    renderPage()

    expect(await screen.findByText('审核中')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '提交审批决定' })).not.toBeInTheDocument()
    expect(decideSpy).not.toHaveBeenCalled()
  })

  it('retries an unknown decision with the frozen request or abandons and refreshes', async () => {
    authenticate()
    const getSpy = vi.spyOn(identityVerificationReviewDecisionApi, 'getCase')
      .mockResolvedValue(reviewing)
    const decideSpy = vi.spyOn(identityVerificationReviewDecisionApi, 'decide')
      .mockRejectedValueOnce(new ApiError('private timeout', 504, 'identity_verification_request_timeout'))
      .mockResolvedValueOnce({ ...reviewing, status: 'approved', revision: 3 })
      .mockRejectedValueOnce(new ApiError('private network', 0, 'network_error'))
    const user = userEvent.setup()
    renderPage()

    expect(await screen.findByText('审核中')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '提交审批决定' }))
    await user.click(await screen.findByRole('button', { name: '确认提交' }))
    expect(await screen.findByText('审批结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    const firstAttempt = decideSpy.mock.calls[0]!
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('已通过')).toBeInTheDocument()
    expect(decideSpy.mock.calls[1]).toEqual(firstAttempt)

    vi.mocked(identityVerificationReviewDecisionApi.getCase).mockResolvedValue(reviewing)
    await user.click(screen.getByRole('button', { name: '刷新案件' }))
    await waitFor(() => expect(screen.getByText('审核中')).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: '提交审批决定' }))
    await user.click(await screen.findByRole('button', { name: '确认提交' }))
    expect(await screen.findByText('审批结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    const callsBeforeAbandon = getSpy.mock.calls.length
    await user.click(screen.getByRole('button', { name: '放弃并刷新' }))
    await waitFor(() => expect(getSpy.mock.calls.length).toBeGreaterThan(callsBeforeAbandon))
    expect(screen.queryByText('审批结果待确认')).not.toBeInTheDocument()
  })

  it('keeps token-free state across refresh and clears it for a new owner session', async () => {
    const actorA = authenticate({}, 'old-token')
    const epoch = useSessionStore.getState().sessionEpoch
    const late = deferred<IdentityVerificationReviewCase>()
    const nextSession = deferred<IdentityVerificationReviewCase>()
    const getSpy = vi.spyOn(identityVerificationReviewDecisionApi, 'getCase')
      .mockResolvedValueOnce(reviewing)
      .mockImplementationOnce(() => late.promise)
      .mockImplementation(() => nextSession.promise)
    const { queryClient } = renderPage()

    expect(await screen.findByText('审核中')).toBeInTheDocument()
    const callsBeforeRefresh = getSpy.mock.calls.length
    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(actorA), access_token: 'new-token' }, actorA, 'refresh',
      )
      await Promise.resolve()
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(screen.getByText('审核中')).toBeInTheDocument()
    expect(getSpy).toHaveBeenCalledTimes(callsBeforeRefresh)
    for (const query of queryClient.getQueryCache().getAll()) {
      expect(JSON.stringify(query.queryKey)).not.toMatch(/old-token|new-token/)
    }

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: '刷新案件' }))
    await waitFor(() => expect(getSpy).toHaveBeenCalledTimes(callsBeforeRefresh + 1))
    expect(getSpy.mock.calls.at(-1)?.[0]).toBe('new-token')

    const actorB = principal({
      scope_id: '99999999-9999-4999-8999-999999999999',
      tenant_id: '99999999-9999-4999-8999-999999999999',
      user_id: '88888888-8888-4888-8888-888888888888',
      permissions: ['identity_verification.read', 'identity_verification.review'],
    })
    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(actorB), access_token: 'tenant-b-token' }, actorB,
      )
      await Promise.resolve()
    })
    expect(screen.getByLabelText('实名认证审批状态')).toHaveAttribute('aria-busy', 'true')
    expect(queryClient.getQueryCache().getAll()
      .some((query) => JSON.stringify(query.queryKey).includes(actorA.scope_id))).toBe(false)
    late.resolve({ ...reviewing, status: 'approved' })
    await act(async () => { await Promise.resolve() })
    expect(screen.queryByText('已通过')).not.toBeInTheDocument()
  })
})
