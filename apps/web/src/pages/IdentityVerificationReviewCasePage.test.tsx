import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  identityVerificationReviewCaseApi,
  type IdentityVerificationReviewCase,
} from '../api/identityVerificationReviewCase'
import { resetSessionStore, useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import IdentityVerificationReviewCasePage from './IdentityVerificationReviewCasePage'

// OutcomeUnknown 的标题同时出现在恢复条和说明弹窗里，这里只认原位的恢复条。
const OUTCOME_BAR = { selector: '.cdnca-outcome-bar .ant-alert-message' }

const caseID = '11111111-1111-4111-8111-111111111111'
const reviewerID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const submitted: IdentityVerificationReviewCase = {
  id: caseID,
  applicant_user_id: '22222222-2222-4222-8222-222222222222',
  kind: 'enterprise',
  status: 'submitted',
  agent_relationship: 'authorized_representative',
  revision: 3,
  created_at: '2026-08-06T08:09:10Z',
  state_changed_at: '2026-08-06T09:09:10Z',
  submitted_at: '2026-08-06T09:09:10Z',
  expires_at: '2026-08-07T09:09:10Z',
  retention: {
    eligible: false,
    eligible_at: '2032-08-04T09:09:10Z',
    reason_code: 'case_not_terminal',
  },
  materials: [{
    id: '33333333-3333-4333-8333-333333333333',
    kind: 'business_license',
    encrypted_envelope_present: true,
    mime_type: 'application/pdf',
    size_bytes: 2048,
    created_at: '2026-08-06T08:10:10Z',
  }],
  replayed: false,
}
const claimed: IdentityVerificationReviewCase = {
  ...submitted,
  status: 'reviewing',
  reviewer_user_id: reviewerID,
  revision: 4,
  state_changed_at: '2026-08-06T10:09:10Z',
}

function reviewer(overrides: Partial<Principal> = {}) {
  return principal({
    user_id: reviewerID,
    permissions: ['identity_verification.read', 'identity_verification.review'],
    ...overrides,
  })
}

function authenticate(actor = reviewer(), token = 'review-token', update?: 'new' | 'refresh') {
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor, update)
  return useSessionStore.getState().sessionEpoch
}

function renderPage(queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false, gcTime: Infinity },
    mutations: { retry: false, gcTime: Infinity },
  },
})) {
  const result = render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={[`/sys/identity-verification/${caseID}`]}>
            <Routes>
              <Route path="/sys/identity-verification/:caseId" element={<IdentityVerificationReviewCasePage />} />
              <Route path="/sys/identity-verification/:caseId/decision" element={<div>决定案件</div>} />
            </Routes>
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
  return { ...result, queryClient }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((next) => { resolve = next })
  return { promise, resolve }
}

describe('IdentityVerificationReviewCasePage', () => {
  beforeEach(async () => {
    resetSessionStore()
    await i18n.changeLanguage('zh-CN')
  })

  it.each([
    ['platform scope', reviewer({ scope_kind: 'platform', tenant_id: null })],
    ['missing read permission', reviewer({ permissions: ['identity_verification.review'] })],
    ['missing review permission', reviewer({ permissions: ['identity_verification.read'] })],
    ['missing actor', reviewer({ user_id: '' })],
  ])('renders a local 403 with zero requests for %s', async (_name, actor) => {
    authenticate(actor)
    const getSpy = vi.spyOn(identityVerificationReviewCaseApi, 'getCase')

    renderPage()

    expect(await screen.findByText('无权审核实名认证')).toBeInTheDocument()
    expect(getSpy).not.toHaveBeenCalled()
  })

  it('fails closed for a zero session epoch', async () => {
    authenticate()
    useSessionStore.setState({ sessionEpoch: 0 })
    const getSpy = vi.spyOn(identityVerificationReviewCaseApi, 'getCase')

    renderPage()

    expect(await screen.findByText('无权审核实名认证')).toBeInTheDocument()
    expect(getSpy).not.toHaveBeenCalled()
  })

  it('renders loading and sanitized material metadata, then claims with confirmation and links to decision', async () => {
    authenticate()
    const pending = deferred<IdentityVerificationReviewCase>()
    vi.spyOn(identityVerificationReviewCaseApi, 'getCase').mockReturnValue(pending.promise)
    const claimSpy = vi.spyOn(identityVerificationReviewCaseApi, 'claim').mockResolvedValue(claimed)
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByLabelText('正在加载实名认证案件')).toBeInTheDocument()
    await act(async () => pending.resolve(submitted))

    expect(await screen.findByRole('heading', { name: '实名认证案件' })).toBeInTheDocument()
    expect(screen.getByText('企业认证')).toBeInTheDocument()
    expect(screen.getByText('营业执照')).toBeInTheDocument()
    expect(screen.getByText('application/pdf')).toBeInTheDocument()
    expect(screen.getByText('2 KB')).toBeInTheDocument()
    expect(screen.getByText('加密材料已托管')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/object_reference|subject_fingerprint|private key/i)

    await user.click(screen.getByRole('button', { name: '认领案件' }))
    await user.click(await screen.findByRole('button', { name: '确认认领' }))
    expect(await screen.findByText('审核中')).toBeInTheDocument()
    expect(claimSpy).toHaveBeenCalledWith(
      'review-token', caseID, 3,
      expect.objectContaining({ requestId: expect.any(String), idempotencyKey: expect.any(String) }),
    )
    const decisionLink = screen.getByRole('link', { name: '进入审核决定' })
    expect(decisionLink).toHaveAttribute('href', `/sys/identity-verification/${caseID}/decision`)
  })

  it('renders localized 503 error and retry recovery without raw messages', async () => {
    authenticate()
    vi.spyOn(identityVerificationReviewCaseApi, 'getCase')
      .mockRejectedValueOnce(new ApiError('raw private topology', 503, 'identity_verification_unavailable'))
      .mockResolvedValueOnce(submitted)
    const user = userEvent.setup()

    renderPage()

    expect(await screen.findByText('实名认证服务暂不可用，请稍后重试。')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw private topology')
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('待审核')).toBeInTheDocument()
  })

  it('treats a claim assigned to another reviewer as an unknown result', async () => {
    authenticate()
    vi.spyOn(identityVerificationReviewCaseApi, 'getCase').mockResolvedValue(submitted)
    vi.spyOn(identityVerificationReviewCaseApi, 'claim').mockResolvedValue({
      ...claimed, reviewer_user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    })
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByText('待审核')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '认领案件' }))
    await user.click(await screen.findByRole('button', { name: '确认认领' }))

    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '进入审核决定' })).not.toBeInTheDocument()
  })

  it.each([
    [new ApiError('raw IAM', 403, 'identity_verification_permission_denied'), '无权审核实名认证'],
    [new ApiError('raw missing', 404, 'identity_verification_not_found'), '实名认证案件不存在'],
  ])('renders natural terminal query state for %#', async (error, expected) => {
    authenticate()
    vi.spyOn(identityVerificationReviewCaseApi, 'getCase').mockRejectedValue(error)

    renderPage()

    expect(await screen.findByText(expected)).toBeInTheDocument()
    expect(document.body.textContent).not.toContain(error.message)
  })

  it('keeps token-free state across refresh and clears old session cache with late-response isolation', async () => {
    const actorA = reviewer()
    const actorB = reviewer({
      user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      scope_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      tenant_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    })
    const epoch = authenticate(actorA, 'old-review-token')
    const lateA = deferred<IdentityVerificationReviewCase>()
    const getSpy = vi.spyOn(identityVerificationReviewCaseApi, 'getCase')
      .mockReturnValueOnce(lateA.promise)
      .mockResolvedValueOnce({ ...submitted, applicant_user_id: actorB.user_id })
    const { queryClient } = renderPage()

    expect(await screen.findByLabelText('正在加载实名认证案件')).toBeInTheDocument()
    await act(async () => {
      authenticate(actorA, 'new-review-token', 'refresh')
      await Promise.resolve()
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(getSpy).toHaveBeenCalledTimes(1)
    for (const query of queryClient.getQueryCache().getAll()) {
      expect(JSON.stringify(query.queryKey)).not.toMatch(/old-review-token|new-review-token/)
    }

    await act(async () => {
      authenticate(actorB, 'tenant-b-token')
      await Promise.resolve()
    })
    expect(await screen.findByText(actorB.user_id)).toBeInTheDocument()
    expect(getSpy).toHaveBeenLastCalledWith('tenant-b-token', caseID, expect.any(AbortSignal))
    await act(async () => lateA.resolve({ ...submitted, status: 'approved' }))
    expect(screen.queryByText('已通过')).not.toBeInTheDocument()
    const keys = queryClient.getQueryCache().getAll().map((query) => JSON.stringify(query.queryKey))
    expect(keys.some((key) => key.includes(actorA.scope_id))).toBe(false)
    expect(keys.some((key) => key.includes(actorB.scope_id))).toBe(true)
  })

  it('abandons and refreshes an unknown claim, then retries the exact frozen attempt', async () => {
    authenticate()
    const getSpy = vi.spyOn(identityVerificationReviewCaseApi, 'getCase').mockResolvedValue(submitted)
    const claimSpy = vi.spyOn(identityVerificationReviewCaseApi, 'claim')
      .mockRejectedValueOnce(new ApiError('network', 0, 'network_error'))
      .mockRejectedValueOnce(new ApiError('timeout', 504, 'identity_verification_request_timeout'))
      .mockResolvedValueOnce(claimed)
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByText('待审核')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '认领案件' }))
    await user.click(await screen.findByRole('button', { name: '确认认领' }))
    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '放弃并刷新' }))
    await waitFor(() => expect(getSpy).toHaveBeenCalledTimes(2))

    await user.click(screen.getByRole('button', { name: '认领案件' }))
    await user.click(await screen.findByRole('button', { name: '确认认领' }))
    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    const frozenAttempt = claimSpy.mock.calls[1]
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('审核中')).toBeInTheDocument()
    expect(claimSpy.mock.calls[2]).toEqual(frozenAttempt)
  })

  it('treats a spec conflict as terminal without offering an ambiguous retry', async () => {
    authenticate()
    vi.spyOn(identityVerificationReviewCaseApi, 'getCase').mockResolvedValue(submitted)
    vi.spyOn(identityVerificationReviewCaseApi, 'claim')
      .mockRejectedValue(new ApiError('raw conflict', 409, 'identity_verification_revision_conflict'))
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByText('待审核')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '认领案件' }))
    await user.click(await screen.findByRole('button', { name: '确认认领' }))
    expect(await screen.findByText('案件版本已变化，请刷新后重试。')).toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
  })
})
