import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ApiError, type Principal } from '../api/auth'
import {
  ja4BlocksApi,
  type JA4BlockCreateInput,
  type JA4BlockWorkflow,
} from '../api/ja4Blocks'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { authResponse } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import JA4BlockWorkflowsPage from './JA4BlockWorkflowsPage'

const scopeID = '11111111-1111-4111-8111-111111111111'
const siteID = '22222222-2222-4222-8222-222222222222'
const workflowID = '33333333-3333-4333-8333-333333333333'
const policyID = '44444444-4444-4444-8444-444444444444'
const bindingID = '55555555-5555-4555-8555-555555555555'
const publicationID = '66666666-6666-4666-8666-666666666666'
const rolloutID = '77777777-7777-4777-8777-777777777777'
const rawJA4 = 't13d1516h2_8daaf6152771_02713d6af862'
const snapshotAt = '2026-08-08T08:00:00Z'
const stepUp = 'opaque-step-up-proof'
const input: JA4BlockCreateInput = {
  site_id: siteID, ja4: rawJA4, snapshot_at: snapshotAt,
  duration_seconds: 3600, reason: 'manual_security_review',
}
const workflow: JA4BlockWorkflow = {
  id: workflowID, tenant_scope_id: scopeID, site_id: siteID, ja4_sha256: 'a'.repeat(64),
  snapshot_at: snapshotAt, duration_seconds: 3600, reason: 'manual_security_review',
  phase: 'edge_pending', revision: 2, policy_id: policyID, policy_revision: 1,
  binding_id: bindingID, binding_revision: 1, edge_publication_id: publicationID,
  rollout_id: rolloutID, edge_state: 'pending', attempt_count: 1, replayed: false,
}

function tenant(overrides: Partial<Principal> = {}): Principal {
  return {
    user_id: '88888888-8888-4888-8888-888888888888', scope_id: scopeID, scope_kind: 'tenant', tenant_id: scopeID,
    username: 'tenant-owner', display_name: 'Tenant Owner', roles: ['tenant_owner'],
    permissions: ['security_policies.read', 'security_policies.manage'], ...overrides,
  }
}

function admin(overrides: Partial<Principal> = {}): Principal {
  return {
    user_id: '99999999-9999-4999-8999-999999999999', scope_id: 'platform', scope_kind: 'platform', tenant_id: null,
    username: 'platform-admin', display_name: 'Platform Admin', roles: ['platform_admin'],
    permissions: ['platform.admin', 'security_policies.read', 'security_policies.manage'], ...overrides,
  }
}

function authenticate(principal = tenant(), token = 'ja4-token', update: 'new' | 'refresh' = 'new') {
  useSessionStore.getState().setSession({ ...authResponse(principal), access_token: token }, principal, update)
  return useSessionStore.getState().sessionEpoch
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((accept, fail) => { resolve = accept; reject = fail })
  return { promise, resolve, reject }
}

async function submitTenant(user = userEvent.setup()) {
  await user.click(screen.getByRole('button', { name: '创建 JA4 封禁' }))
  const dialog = await screen.findByRole('dialog', { name: '创建 JA4 封禁工作流' })
  await user.type(within(dialog).getByRole('textbox', { name: '站点 ID' }), siteID)
  await user.type(within(dialog).getByRole('textbox', { name: 'JA4 原始值' }), rawJA4)
  await user.type(within(dialog).getByRole('textbox', { name: '权威快照时间' }), snapshotAt)
  await user.clear(within(dialog).getByRole('spinbutton', { name: '封禁时长（秒）' }))
  await user.type(within(dialog).getByRole('spinbutton', { name: '封禁时长（秒）' }), '3600')
  await user.type(within(dialog).getByRole('textbox', { name: '原因码' }), 'manual_security_review')
  await user.type(within(dialog).getByLabelText('二次认证证明'), stepUp)
  await user.click(within(dialog).getByRole('button', { name: '确认创建' }))
  return user
}

describe('JA4BlockWorkflowsPage', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh-CN')
    vi.restoreAllMocks()
    authenticate()
  })

  it.each([
    ['missing permissions', tenant({ permissions: [] })],
    ['tenant missing user', tenant({ user_id: '' })],
    ['platform bound to tenant', admin({ tenant_id: scopeID })],
    ['platform missing admin permission', admin({ permissions: ['security_policies.read', 'security_policies.manage'] })],
  ])('rejects %s locally with zero requests', async (_name, principal) => {
    authenticate(principal)
    const tenantCreate = vi.spyOn(ja4BlocksApi, 'createTenant')
    const tenantGet = vi.spyOn(ja4BlocksApi, 'getTenant')
    const adminCreate = vi.spyOn(ja4BlocksApi, 'createAdmin')
    const adminGet = vi.spyOn(ja4BlocksApi, 'getAdmin')

    renderWithProviders(<JA4BlockWorkflowsPage />)

    expect(await screen.findByText('无权管理 JA4 封禁')).toBeInTheDocument()
    for (const spy of [tenantCreate, tenantGet, adminCreate, adminGet]) expect(spy).not.toHaveBeenCalled()
  })

  it('creates for the tenant, clears raw secrets, then reads immutable workflow state without activation claims', async () => {
    const create = vi.spyOn(ja4BlocksApi, 'createTenant').mockResolvedValue(workflow)
    const readback = deferred<JA4BlockWorkflow>()
    const get = vi.spyOn(ja4BlocksApi, 'getTenant').mockReturnValue(readback.promise)

    renderWithProviders(<JA4BlockWorkflowsPage />)
    expect(await screen.findByText('本页尚未跟踪 JA4 封禁工作流')).toBeInTheDocument()
    await submitTenant()

    await waitFor(() => expect(create).toHaveBeenCalledWith(
      'ja4-token', input,
      expect.objectContaining({
        requestId: expect.stringMatching(/^ja4-block-request-/),
        idempotencyKey: expect.stringMatching(/^ja4-block-create-/),
        stepUpToken: stepUp,
      }),
    ))
    expect(document.body.textContent).not.toContain(rawJA4)
    expect(document.body.textContent).not.toContain(stepUp)
    await waitFor(() => expect(get).toHaveBeenCalledWith('ja4-token', workflowID, expect.stringMatching(/^ja4-block-read-/)))
    expect(screen.getByLabelText('正在加载 JA4 封禁工作流')).toBeInTheDocument()

    await act(async () => readback.resolve(workflow))
    expect(await screen.findByText(workflow.ja4_sha256)).toBeInTheDocument()
    for (const value of [workflowID, policyID, bindingID, publicationID, rolloutID]) {
      expect(screen.getByText(value)).toBeInTheDocument()
    }
    expect(screen.getByText('边缘下发中')).toBeInTheDocument()
    expect(screen.getByText('回执仅陈述不可变策略、绑定、发布和灰度状态；只有工作流与边缘状态均为 active 时才表示已激活。')).toBeInTheDocument()
    expect(screen.queryByText(/^已激活$/)).not.toBeInTheDocument()
  })

  it('uses the explicit canonical tenant target for platform admin create and readback', async () => {
    authenticate(admin(), 'admin-ja4-token')
    const create = vi.spyOn(ja4BlocksApi, 'createAdmin').mockResolvedValue(workflow)
    const get = vi.spyOn(ja4BlocksApi, 'getAdmin').mockResolvedValue(workflow)
    const user = userEvent.setup()
    renderWithProviders(<JA4BlockWorkflowsPage />)

    await user.click(screen.getByRole('button', { name: '创建 JA4 封禁' }))
    const dialog = await screen.findByRole('dialog', { name: '创建 JA4 封禁工作流' })
    await user.type(within(dialog).getByRole('textbox', { name: '租户作用域 ID' }), scopeID)
    await user.type(within(dialog).getByRole('textbox', { name: '站点 ID' }), siteID)
    await user.type(within(dialog).getByRole('textbox', { name: 'JA4 原始值' }), rawJA4)
    await user.type(within(dialog).getByRole('textbox', { name: '权威快照时间' }), snapshotAt)
    await user.clear(within(dialog).getByRole('spinbutton', { name: '封禁时长（秒）' }))
    await user.type(within(dialog).getByRole('spinbutton', { name: '封禁时长（秒）' }), '3600')
    await user.type(within(dialog).getByRole('textbox', { name: '原因码' }), input.reason)
    await user.type(within(dialog).getByLabelText('二次认证证明'), stepUp)
    await user.click(within(dialog).getByRole('button', { name: '确认创建' }))

    await waitFor(() => expect(create).toHaveBeenCalledWith(
      'admin-ja4-token', { ...input, tenant_scope_id: scopeID }, expect.objectContaining({ stepUpToken: stepUp }),
    ))
    await waitFor(() => expect(get).toHaveBeenCalledWith(
      'admin-ja4-token', scopeID, workflowID, expect.stringMatching(/^ja4-block-read-/),
    ))
  })

  it.each([
    [0, 'network_error'],
    [408, 'ja4_block_timeout'],
    [503, 'ja4_block_unavailable'],
    [504, 'ja4_block_timeout'],
  ])('treats %i/%s as unknown and preserves one exact retry or abandon', async (status, code) => {
    const create = vi.spyOn(ja4BlocksApi, 'createTenant').mockRejectedValue(new ApiError('private transport detail', status, code))
    const get = vi.spyOn(ja4BlocksApi, 'getTenant')
    renderWithProviders(<JA4BlockWorkflowsPage />)
    const user = await submitTenant()

    expect(await screen.findByText('创建结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('private transport detail')
    const frozen = create.mock.calls[0]
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]).toEqual(frozen)
    expect(get).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: '放弃并清除' }))
    expect(await screen.findByText('本页尚未跟踪 JA4 封禁工作流')).toBeInTheDocument()
    expect(create).toHaveBeenCalledTimes(2)
  })

  it.each([
    [403, 'ja4_block_permission_denied', '无权创建 JA4 封禁'],
    [409, 'ja4_block_idempotency_conflict', '幂等请求与原请求不一致，请核对后重新创建。'],
    [412, 'ja4_block_revision_conflict', '创建前置修订不匹配，请重新确认。'],
    [428, 'ja4_block_step_up_required', '需要重新完成二次认证。'],
  ])('maps terminal %i/%s without raw text or unknown retry', async (status, code, localized) => {
    const create = vi.spyOn(ja4BlocksApi, 'createTenant').mockRejectedValue(new ApiError('private policy detail', status, code))
    renderWithProviders(<JA4BlockWorkflowsPage />)
    await submitTenant()

    expect(await screen.findByText(localized)).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('private policy detail')
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(create).toHaveBeenCalledOnce()
    if (status === 403) expect(screen.queryByRole('button', { name: '创建 JA4 封禁' })).not.toBeInTheDocument()
  })

  it('renders localized readback error and retry without inventing a list route', async () => {
    vi.spyOn(ja4BlocksApi, 'createTenant').mockResolvedValue(workflow)
    const get = vi.spyOn(ja4BlocksApi, 'getTenant')
      .mockRejectedValueOnce(new ApiError('private database detail', 503, 'ja4_block_unavailable'))
      .mockResolvedValueOnce(workflow)
    renderWithProviders(<JA4BlockWorkflowsPage />)
    await submitTenant()

    expect(await screen.findByText('JA4 封禁工作流加载失败')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('private database detail')
    await userEvent.setup().click(screen.getByRole('button', { name: '重试读取' }))
    expect(await screen.findByText(workflow.ja4_sha256)).toBeInTheDocument()
    expect(get).toHaveBeenCalledTimes(2)
  })

  it('keeps token-free owner state on refresh and clears tracked state on a new session', async () => {
    const principalA = tenant({ user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' })
    const principalB = tenant({ user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' })
    const epoch = authenticate(principalA, 'old-ja4-token')
    vi.spyOn(ja4BlocksApi, 'createTenant').mockResolvedValue(workflow)
    const get = vi.spyOn(ja4BlocksApi, 'getTenant').mockResolvedValue(workflow)
    renderWithProviders(<JA4BlockWorkflowsPage />)
    await submitTenant()
    expect(await screen.findByText(workflow.ja4_sha256)).toBeInTheDocument()

    await act(async () => {
      authenticate(principalA, 'refreshed-ja4-token', 'refresh')
      await Promise.resolve()
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(screen.getByText(workflow.ja4_sha256)).toBeInTheDocument()
    expect(get).toHaveBeenCalledOnce()

    await act(async () => {
      authenticate(principalB, 'new-session-token')
      await Promise.resolve()
    })
    expect(await screen.findByText('本页尚未跟踪 JA4 封禁工作流')).toBeInTheDocument()
    expect(screen.queryByText(workflow.ja4_sha256)).not.toBeInTheDocument()
  })
})
