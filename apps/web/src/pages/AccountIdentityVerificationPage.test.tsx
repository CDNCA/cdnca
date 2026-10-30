import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'

import { ApiError } from '../api/auth'
import {
  identityVerificationApi,
  type IdentityVerificationCase,
  type IdentityVerificationProviderSession,
  type IdentityVerificationProviderUpload,
} from '../api/identityVerification'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import AccountIdentityVerificationPage from './AccountIdentityVerificationPage'

// 结果未知改为 OutcomeUnknown 后，弹窗标题与原位恢复条（或表单内 Alert）同文案；断言原位提示
const OUTCOME_BAR = '.ant-alert-message'

const caseID = '11111111-1111-4111-8111-111111111111'
const evidenceToken = 'evidence-token-abcdefghijklmnopqrstuvwxyz'
const providerSessionID = '44444444-4444-4444-8444-444444444444'
const providerUploadID = '55555555-5555-4555-8555-555555555555'
const draft: IdentityVerificationCase = {
  id: caseID,
  applicant_user_id: '11111111-1111-4111-8111-111111111111',
  kind: 'personal_initial',
  status: 'draft',
  revision: 1,
  created_at: '2026-08-06T08:09:10Z',
  state_changed_at: '2026-08-06T08:09:10Z',
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
  token = 'identity-token',
  update: 'new' | 'refresh' = 'new',
) {
  const actor = principal({ permissions: ['identity_verification.self.manage'], ...overrides })
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor, update)
  return actor
}

function renderWithQueryClient(queryClient: QueryClient) {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/account/verification']}>
            <AccountIdentityVerificationPage />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}

describe('AccountIdentityVerificationPage', () => {
  it('keeps the verification workflow inside the compact account page shell', async () => {
    authenticate()
    renderWithProviders(<AccountIdentityVerificationPage />, ['/account/verification'])

    const title = await screen.findByRole('heading', { name: '实名认证' })
    const page = title.closest('.account-identity-verification-page')
    expect(page).not.toBeNull()
    expect(page).toHaveClass('identity-page')
    expect(page?.querySelectorAll('h2')).toHaveLength(3)
    expect(page?.querySelectorAll('.identity-section-title')).toHaveLength(3)
    expect(page?.querySelector('.identity-introduction')).toBeInTheDocument()
    expect(page?.querySelector('.identity-lookup-toolbar')).toBeInTheDocument()
    expect(page?.querySelector('.identity-create-form')).toBeInTheDocument()
    expect(page?.querySelector('.identity-provider-form')).toBeInTheDocument()
    expect(page?.querySelectorAll('.identity-toolbar')).not.toHaveLength(0)
    expect(page?.querySelector('input[type="password"]')).toBeInTheDocument()
  })

  it.each([
    ['missing permission', principal({ permissions: [] })],
    ['platform principal', principal({
      scope_kind: 'platform', tenant_id: null, permissions: ['identity_verification.self.manage'],
    })],
    ['missing user', principal({ user_id: '', permissions: ['identity_verification.self.manage'] })],
  ])('fails closed with a local 403 and zero requests for %s', async (_case, actor) => {
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const getSpy = vi.spyOn(identityVerificationApi, 'getCase')
    const createSpy = vi.spyOn(identityVerificationApi, 'createDraft')

    renderWithProviders(<AccountIdentityVerificationPage />, ['/account/verification'])

    expect(await screen.findByText('无权管理实名认证')).toBeInTheDocument()
    expect(getSpy).not.toHaveBeenCalled()
    expect(createSpy).not.toHaveBeenCalled()
  })

  it('creates and submits a sanitized draft without retaining the evidence token', async () => {
    authenticate()
    const createSpy = vi.spyOn(identityVerificationApi, 'createDraft').mockResolvedValue(draft)
    const submitSpy = vi.spyOn(identityVerificationApi, 'submit')
      .mockResolvedValue({ ...draft, status: 'submitted', revision: 2 })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity } },
    })
    const user = userEvent.setup()
    renderWithQueryClient(queryClient)

    expect(screen.getByText('尚未选择实名认证案件')).toBeInTheDocument()
    await user.type(screen.getByLabelText('可信证据令牌'), evidenceToken)
    await user.click(screen.getByRole('button', { name: '创建认证草稿' }))

    expect(await screen.findByText('草稿')).toBeInTheDocument()
    expect(createSpy).toHaveBeenCalledWith(
      'identity-token',
      { kind: 'personal_initial', evidence_token: evidenceToken },
      expect.objectContaining({ requestId: expect.any(String), idempotencyKey: expect.any(String) }),
    )
    expect(screen.queryByDisplayValue(evidenceToken)).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain(evidenceToken)
    expect(JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.state.data)))
      .not.toContain(evidenceToken)

    await user.click(screen.getByRole('button', { name: '提交审核' }))
    await user.click(await screen.findByRole('button', { name: '确认提交' }))
    expect(await screen.findByText('待审核')).toBeInTheDocument()
    expect(submitSpy).toHaveBeenCalledWith(
      'identity-token', caseID, 1,
      expect.objectContaining({ requestId: expect.any(String), idempotencyKey: expect.any(String) }),
    )
  })

  it('explains reverification consistency and renders only sanitized evidence metadata', async () => {
    authenticate()
    vi.spyOn(identityVerificationApi, 'getCase').mockResolvedValue({
      ...draft,
      kind: 'personal_reverification',
      materials: [{
        id: '33333333-3333-4333-8333-333333333333',
        kind: 'identity_document',
        encrypted_envelope_present: true,
        mime_type: 'application/pdf',
        size_bytes: 2048,
        created_at: '2026-07-10T10:05:00Z',
      }],
    })
    const user = userEvent.setup()
    renderWithProviders(<AccountIdentityVerificationPage />, ['/account/verification'])

    await user.type(screen.getByLabelText('案件 ID'), caseID)
    await user.click(screen.getByRole('button', { name: '查询案件' }))

    expect(await screen.findByText('个人重新认证')).toBeInTheDocument()
    expect(screen.getByText('服务端会将本次可信身份与首次已通过身份进行一致性校验；页面不显示身份内容。')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '脱敏证据摘要' })).toBeInTheDocument()
    expect(screen.getByText('身份材料')).toBeInTheDocument()
    expect(screen.getByText('application/pdf')).toBeInTheDocument()
    expect(screen.getByText('2 KB')).toBeInTheDocument()
    expect(screen.getByText('加密材料已托管')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/object_reference|subject_fingerprint|document number/i)
  })

  it('shows a localized stable rejection reason without raw or sensitive details', async () => {
    authenticate()
    vi.spyOn(identityVerificationApi, 'getCase').mockResolvedValue({
      ...draft,
      status: 'rejected',
      decision_reason_code: 'identity_mismatch',
      revision: 4,
    })
    const user = userEvent.setup()
    renderWithProviders(<AccountIdentityVerificationPage />, ['/account/verification'])

    await user.type(screen.getByLabelText('案件 ID'), caseID)
    await user.click(screen.getByRole('button', { name: '查询案件' }))

    expect(await screen.findByText('已拒绝')).toBeInTheDocument()
    expect(screen.getByText('身份信息与可信材料不一致')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('identity_mismatch')
    expect(document.body.textContent).not.toMatch(/证件号码|材料原文|raw server/i)
  })

  it('rejects a case owned by another applicant before rendering or mutation', async () => {
    authenticate()
    vi.spyOn(identityVerificationApi, 'getCase').mockResolvedValue({
      ...draft, applicant_user_id: '44444444-4444-4444-8444-444444444444',
    })
    const submitSpy = vi.spyOn(identityVerificationApi, 'submit')
    const user = userEvent.setup()

    renderWithProviders(<AccountIdentityVerificationPage />, ['/account/verification'])
    await user.type(screen.getByLabelText('案件 ID'), caseID)
    await user.click(screen.getByRole('button', { name: '查询案件' }))

    expect(await screen.findByText('服务响应无效，请刷新确认当前状态。')).toBeInTheDocument()
    expect(screen.queryByText('草稿')).not.toBeInTheDocument()
    expect(submitSpy).not.toHaveBeenCalled()
  })

  it('retries an unknown create with the exact request and can abandon it without retaining the secret', async () => {
    authenticate()
    const createSpy = vi.spyOn(identityVerificationApi, 'createDraft')
      .mockRejectedValueOnce(new ApiError('network', 0, 'network_error'))
      .mockResolvedValueOnce(draft)
      .mockRejectedValueOnce(new ApiError('invalid response', 502, 'invalid_response'))
    const user = userEvent.setup()
    renderWithProviders(<AccountIdentityVerificationPage />, ['/account/verification'])

    const secretInput = screen.getByLabelText('可信证据令牌')
    await user.type(secretInput, evidenceToken)
    await user.click(screen.getByRole('button', { name: '创建认证草稿' }))
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(screen.queryByDisplayValue(evidenceToken)).not.toBeInTheDocument()

    const firstAttempt = createSpy.mock.calls[0]!
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('草稿')).toBeInTheDocument()
    expect(createSpy.mock.calls[1]).toEqual(firstAttempt)
    expect(document.body.textContent).not.toContain(evidenceToken)

    await user.type(screen.getByLabelText('可信证据令牌'), evidenceToken)
    await user.click(screen.getByRole('button', { name: '创建认证草稿' }))
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '放弃并刷新' }))
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain(evidenceToken)
    expect(createSpy.mock.calls[2]![1].evidence_token).toBe('')
  })

  it('treats 429 and explicit rate-limit errors as localized terminal writes without exact retry', async () => {
    authenticate()
    const createSpy = vi.spyOn(identityVerificationApi, 'createDraft')
      .mockRejectedValue(new ApiError('raw private throttle', 429, 'identity_verification_rate_limited'))
    const user = userEvent.setup()
    renderWithProviders(<AccountIdentityVerificationPage />, ['/account/verification'])

    await user.type(screen.getByLabelText('可信证据令牌'), evidenceToken)
    await user.click(screen.getByRole('button', { name: '创建认证草稿' }))
    expect(await screen.findByText('操作过于频繁，请稍后重试。')).toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw private throttle')
    expect(createSpy.mock.calls[0]![1].evidence_token).toBe('')
  })

  it('retries a 408 transition with the frozen case, revision, and metadata but the current token', async () => {
    const actor = authenticate({}, 'old-identity-token')
    const epoch = useSessionStore.getState().sessionEpoch
    vi.spyOn(identityVerificationApi, 'getCase').mockResolvedValue(draft)
    const submitSpy = vi.spyOn(identityVerificationApi, 'submit')
      .mockRejectedValueOnce(new ApiError('raw timeout', 408, 'identity_verification_request_timeout'))
      .mockResolvedValueOnce({ ...draft, status: 'submitted', revision: 2 })
    const user = userEvent.setup()
    renderWithProviders(<AccountIdentityVerificationPage />, ['/account/verification'])
    await user.type(screen.getByLabelText('案件 ID'), caseID)
    await user.click(screen.getByRole('button', { name: '查询案件' }))
    expect(await screen.findByText('草稿')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '提交审核' }))
    await user.click(await screen.findByRole('button', { name: '确认提交' }))
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(actor), access_token: 'current-identity-token' }, actor, 'refresh',
      )
      await Promise.resolve()
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('待审核')).toBeInTheDocument()
    expect(submitSpy.mock.calls[0]![0]).toBe('old-identity-token')
    expect(submitSpy.mock.calls[1]![0]).toBe('current-identity-token')
    expect(submitSpy.mock.calls[1]!.slice(1)).toEqual(submitSpy.mock.calls[0]!.slice(1))
  })

  it('abandons an unknown non-create write by refetching the authoritative case', async () => {
    authenticate()
    const getSpy = vi.spyOn(identityVerificationApi, 'getCase').mockResolvedValue(draft)
    vi.spyOn(identityVerificationApi, 'submit')
      .mockRejectedValue(new ApiError('raw unavailable', 503, 'identity_verification_unavailable'))
    const user = userEvent.setup()
    renderWithProviders(<AccountIdentityVerificationPage />, ['/account/verification'])
    await user.type(screen.getByLabelText('案件 ID'), caseID)
    await user.click(screen.getByRole('button', { name: '查询案件' }))
    expect(await screen.findByText('草稿')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '提交审核' }))
    await user.click(await screen.findByRole('button', { name: '确认提交' }))
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '放弃并刷新' }))
    await waitFor(() => expect(getSpy).toHaveBeenCalledTimes(2))
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
  })

  it('clears sensitive create input on a new session and ignores its late result', async () => {
    const actorA = authenticate({ user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }, 'tenant-a-token')
    const pending = deferred<IdentityVerificationCase>()
    const createSpy = vi.spyOn(identityVerificationApi, 'createDraft').mockReturnValue(pending.promise)
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
    const user = userEvent.setup()
    renderWithQueryClient(queryClient)
    await user.type(screen.getByLabelText('可信证据令牌'), evidenceToken)
    await user.click(screen.getByRole('button', { name: '创建认证草稿' }))
    await waitFor(() => expect(createSpy).toHaveBeenCalledOnce())

    const actorB = principal({
      scope_id: '99999999-9999-4999-8999-999999999999',
      tenant_id: '99999999-9999-4999-8999-999999999999',
      user_id: '88888888-8888-4888-8888-888888888888',
      permissions: ['identity_verification.self.manage'],
    })
    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(actorB), access_token: 'tenant-b-token' }, actorB,
      )
      await Promise.resolve()
    })
    expect(await screen.findByText('尚未选择实名认证案件')).toBeInTheDocument()
    expect(createSpy.mock.calls[0]![1].evidence_token).toBe('')

    pending.resolve({ ...draft, status: 'approved' })
    await act(async () => { await Promise.resolve() })
    expect(screen.queryByText('已通过')).not.toBeInTheDocument()
    expect(queryClient.getQueryCache().getAll().some((query) => JSON.stringify(query.queryKey).includes(actorA.scope_id))).toBe(false)
  })

  it('renders loading, empty, localized error/retry, and server-forbidden states', async () => {
    authenticate()
    const pending = deferred<IdentityVerificationCase>()
    const getSpy = vi.spyOn(identityVerificationApi, 'getCase')
      .mockImplementationOnce(() => pending.promise)
      .mockRejectedValueOnce(new ApiError('raw private', 503, 'identity_verification_unavailable'))
      .mockResolvedValueOnce(draft)
      .mockRejectedValueOnce(new ApiError('forbidden', 403, 'identity_verification_permission_denied'))
    const user = userEvent.setup()
    renderWithProviders(<AccountIdentityVerificationPage />, ['/account/verification'])

    expect(screen.getByText('尚未选择实名认证案件')).toBeInTheDocument()
    await user.type(screen.getByLabelText('案件 ID'), caseID)
    await user.click(screen.getByRole('button', { name: '查询案件' }))
    expect(screen.getByLabelText('实名认证案件状态')).toHaveAttribute('aria-busy', 'true')
    pending.resolve(draft)
    expect(await screen.findByText('草稿')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '刷新案件' }))
    expect(await screen.findByText('实名认证服务暂不可用，请稍后重试。')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw private')
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('草稿')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '刷新案件' }))
    expect(await screen.findByText('无权管理实名认证')).toBeInTheDocument()
    expect(getSpy).toHaveBeenCalledTimes(4)
  })

  it('preserves token-free state on refresh and clears old owner cache on a new session', async () => {
    const actorA = authenticate({}, 'old-token')
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const late = deferred<IdentityVerificationCase>()
    const getSpy = vi.spyOn(identityVerificationApi, 'getCase')
      .mockResolvedValueOnce(draft)
      .mockImplementationOnce(() => late.promise)
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity } },
    })
    const user = userEvent.setup()
    renderWithQueryClient(queryClient)

    await user.type(screen.getByLabelText('案件 ID'), caseID)
    await user.click(screen.getByRole('button', { name: '查询案件' }))
    expect(await screen.findByText('草稿')).toBeInTheDocument()
    const callsBeforeRefresh = getSpy.mock.calls.length

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(actorA), access_token: 'new-token' }, actorA, 'refresh',
      )
      await Promise.resolve()
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(screen.getByText('草稿')).toBeInTheDocument()
    expect(getSpy).toHaveBeenCalledTimes(callsBeforeRefresh)
    for (const query of queryClient.getQueryCache().getAll()) {
      expect(JSON.stringify(query.queryKey)).not.toMatch(/old-token|new-token/)
    }

    await user.click(screen.getByRole('button', { name: '刷新案件' }))
    await waitFor(() => expect(getSpy).toHaveBeenCalledTimes(callsBeforeRefresh + 1))
    expect(getSpy.mock.calls.at(-1)?.[0]).toBe('new-token')

    const actorB = principal({
      scope_id: '99999999-9999-4999-8999-999999999999',
      tenant_id: '99999999-9999-4999-8999-999999999999',
      user_id: '88888888-8888-4888-8888-888888888888',
      permissions: ['identity_verification.self.manage'],
    })
    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(actorB), access_token: 'tenant-b-token' }, actorB,
      )
      await Promise.resolve()
    })
    expect(await screen.findByText('尚未选择实名认证案件')).toBeInTheDocument()
    expect(screen.getByLabelText('案件 ID')).toHaveValue('')
    const remainingKeys = queryClient.getQueryCache().getAll().map((query) => JSON.stringify(query.queryKey))
    expect(remainingKeys.some((key) => key.includes(actorA.scope_id))).toBe(false)

    late.resolve({ ...draft, status: 'approved' })
    await act(async () => { await Promise.resolve() })
    expect(screen.queryByText('已通过')).not.toBeInTheDocument()
  })

  it('treats conflicts as terminal and offers the real withdraw workflow', async () => {
    authenticate()
    vi.spyOn(identityVerificationApi, 'getCase').mockResolvedValue({
      ...draft, status: 'submitted', revision: 2,
    })
    const withdrawSpy = vi.spyOn(identityVerificationApi, 'withdraw')
      .mockRejectedValueOnce(new ApiError('raw', 409, 'identity_verification_revision_conflict'))
      .mockResolvedValueOnce({ ...draft, status: 'withdrawn', revision: 3 })
    const user = userEvent.setup()
    renderWithProviders(<AccountIdentityVerificationPage />, ['/account/verification'])

    await user.type(screen.getByLabelText('案件 ID'), caseID)
    await user.click(screen.getByRole('button', { name: '查询案件' }))
    expect(await screen.findByText('待审核')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '撤回申请' }))
    await user.click(await screen.findByRole('button', { name: '确认撤回' }))
    expect(await screen.findByText('案件版本已变化，请刷新后重试。')).toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '撤回申请' }))
    await user.click(await screen.findByRole('button', { name: '确认撤回' }))
    expect(await screen.findByText('已撤回')).toBeInTheDocument()
    expect(withdrawSpy).toHaveBeenCalledTimes(2)
  })

  it('retries the exact provider session with the current token and creates a draft without exposing evidence', async () => {
    const actor = authenticate({}, 'old-provider-token')
    const providerSession: IdentityVerificationProviderSession = {
      id: providerSessionID,
      kind: 'enterprise',
      provider: 'trusted_kyc',
      state: 'succeeded',
      revision: 2,
      evidence_token: evidenceToken,
      expires_at: '2026-08-09T08:09:10Z',
      updated_at: '2026-08-08T08:09:10Z',
      replayed: true,
    }
    const startSpy = vi.spyOn(identityVerificationApi, 'startProviderSession')
      .mockRejectedValueOnce(new ApiError('raw provider topology', 503, 'identity_verification_provider_result_unknown'))
      .mockResolvedValueOnce({
        ...providerSession,
        state: 'pending',
        revision: 1,
        evidence_token: undefined,
        replayed: false,
      })
      .mockResolvedValueOnce(providerSession)
    const createSpy = vi.spyOn(identityVerificationApi, 'createDraft').mockResolvedValue({
      ...draft,
      kind: 'enterprise',
    })
    const user = userEvent.setup()
    renderWithProviders(<AccountIdentityVerificationPage />, ['/account/verification'])

    await user.click(screen.getByLabelText('服务认证类型'))
    await user.click(screen.getByText('企业认证'))
    await user.type(screen.getByLabelText('认证服务'), 'trusted_kyc')
    await user.click(screen.getByRole('button', { name: '启动认证服务' }))
    expect(await screen.findByText('认证服务结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw provider topology')

    act(() => useSessionStore.getState().setSession(
      { ...authResponse(actor), access_token: 'current-provider-token' }, actor, 'refresh',
    ))
    await user.click(screen.getByRole('button', { name: '使用同一服务请求重试' }))
    expect(await screen.findByText('等待认证服务处理')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '使用同一服务请求重试' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用同一服务请求重试' }))
    expect(await screen.findByText('认证服务已完成')).toBeInTheDocument()
    expect(startSpy.mock.calls[0]?.[0]).toBe('old-provider-token')
    expect(startSpy.mock.calls[1]?.[0]).toBe('current-provider-token')
    expect(startSpy.mock.calls[1]?.slice(1)).toEqual(startSpy.mock.calls[0]?.slice(1))
    expect(startSpy.mock.calls[2]?.[0]).toBe('current-provider-token')
    expect(startSpy.mock.calls[2]?.slice(1)).toEqual(startSpy.mock.calls[0]?.slice(1))
    expect(document.body.textContent).not.toContain(evidenceToken)

    await user.click(screen.getByRole('button', { name: '使用服务结果创建草稿' }))
    expect(await screen.findByText('草稿')).toBeInTheDocument()
    expect(createSpy).toHaveBeenCalledWith(
      'current-provider-token',
      { kind: 'enterprise', evidence_token: evidenceToken },
      expect.objectContaining({ requestId: expect.any(String), idempotencyKey: expect.any(String) }),
    )
    expect(document.body.textContent).not.toContain(evidenceToken)
  })

  it('uploads private material with exact facts and never renders the presigned or KMS details', async () => {
    authenticate()
    const providerSession: IdentityVerificationProviderSession = {
      id: providerSessionID,
      kind: 'personal_reverification',
      provider: 'trusted_kyc',
      state: 'pending',
      revision: 1,
      expires_at: '2026-08-09T08:09:10Z',
      updated_at: '2026-08-08T08:09:10Z',
      replayed: false,
    }
    const issued: IdentityVerificationProviderUpload = {
      id: providerUploadID,
      session_id: providerSessionID,
      material_kind: 'identity_document',
      state: 'issued',
      revision: 1,
      upload_url: 'https://private-objects.example/secret-object-key',
      required_headers: {
        'Content-Type': 'image/png',
        'x-amz-server-side-encryption': 'aws:kms',
        'x-amz-server-side-encryption-aws-kms-key-id': 'private-kms-key',
      },
      expires_at: '2026-08-08T09:09:10Z',
      replayed: false,
    }
    const finalized: IdentityVerificationProviderUpload = {
      id: providerUploadID,
      session_id: providerSessionID,
      material_kind: 'identity_document',
      state: 'finalized',
      revision: 2,
      expires_at: '2026-08-08T09:09:10Z',
      replayed: false,
    }
    vi.spyOn(identityVerificationApi, 'startProviderSession').mockResolvedValue(providerSession)
    const createUploadSpy = vi.spyOn(identityVerificationApi, 'createProviderUpload').mockResolvedValue(issued)
    const putSpy = vi.spyOn(identityVerificationApi, 'putProviderUpload').mockResolvedValue(undefined)
    const finalizeSpy = vi.spyOn(identityVerificationApi, 'finalizeProviderUpload').mockResolvedValue(finalized)
    const user = userEvent.setup()
    renderWithProviders(<AccountIdentityVerificationPage />, ['/account/verification'])

    await user.click(screen.getByLabelText('服务认证类型'))
    await user.click(screen.getByText('个人重新认证'))
    await user.type(screen.getByLabelText('认证服务'), 'trusted_kyc')
    await user.click(screen.getByRole('button', { name: '启动认证服务' }))
    expect(await screen.findByText('等待认证服务处理')).toBeInTheDocument()

    await user.click(screen.getByRole('combobox', { name: '私有材料类型' }))
    await user.click(screen.getByText('营业执照'))
    const file = new File(['private image bytes'], 'private-person-name.png', { type: 'image/png' })
    await user.upload(screen.getByLabelText('选择私有材料'), file)
    await user.click(screen.getByRole('button', { name: '上传并校验材料' }))

    expect(await screen.findByText('私有材料已校验并完成托管')).toBeInTheDocument()
    expect(createUploadSpy).toHaveBeenCalledWith(
      'identity-token',
      providerSessionID,
      expect.objectContaining({
        material_kind: 'business_license',
        content_type: 'image/png',
        size_bytes: file.size,
        sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      }),
      expect.objectContaining({ requestId: expect.any(String), idempotencyKey: expect.any(String) }),
    )
    expect(putSpy).toHaveBeenCalledWith(issued, expect.objectContaining({ sha256: expect.any(String) }), file)
    expect(finalizeSpy).toHaveBeenCalledWith(
      'identity-token', providerSessionID, providerUploadID, 1,
      expect.objectContaining({ requestId: expect.any(String), idempotencyKey: expect.any(String) }),
    )
    expect(document.body.textContent).not.toMatch(/secret-object-key|private-kms-key|private-person-name|[a-f0-9]{64}/i)
  })
})
