import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App as AntApp, ConfigProvider } from 'antd'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

import { AppRoutes } from '../App'
import type { AuthResponse, Principal } from '../api/auth'
import {
  loginSession,
  logoutSession,
  refreshSession,
  resetSessionStore,
  useSessionStore,
} from '../auth/session'
import {
  accountMfaMessages,
  type AccountMfaMessageTree,
} from '../i18n/accountMfa'
import AccountUserPage from '../pages/AccountUserPage'
import AccountMfaPanel from '../pages/account/AccountMfaPanel'
import { authResponse, principal as basePrincipal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const credentialID = '11111111-1111-4111-8111-111111111111'
const secret = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const provisioningURI = `otpauth://totp/CDNCA%3Ajason?algorithm=SHA1&digits=6&issuer=CDNCA&period=30&secret=${secret}`
const provisioningURIFor = (accountLabel: string) =>
  provisioningURI.replace('jason', encodeURIComponent(accountLabel))
const recoveryCodes = Array.from(
  { length: 10 },
  (_, index) => `ABCDEFGH-ABCDEFGH-ABCDEFGH-ABCDEFG${String.fromCharCode(65 + index)}`,
)
// OutcomeUnknown 弹窗打开时恢复按钮只在弹窗里（挂在 body，f3f426931 起）；关掉弹窗后回到各面板的恢复条。
// 多个面板各有一个弹窗，按面板定位重试按钮前先全部关闭。
async function closeOutcomeDialogs() {
  await screen.findAllByText('操作结果待确认', { selector: '.cdnca-feedback .ant-modal-title, .cdnca-feedback .ant-modal-title *' })
  for (const ok of screen.queryAllByRole('button', { name: '知道了' })) fireEvent.click(ok)
}

const stepUpToken = 'abcdefghijklmnopqrstuvwxyz0123456789_-ABCDE'

function principal(overrides: Partial<Principal> = {}) {
  return basePrincipal({
    permissions: ['identity.self.read', 'identity.self.update', 'identity.password.change'],
    ...overrides,
  })
}

function impersonationMarker(subject: Principal) {
  return {
    grant_id: '33333333-3333-4333-8333-333333333333',
    actor_user_id: '44444444-4444-4444-8444-444444444444',
    actor_display_name: 'platform-operator',
    subject_user_id: subject.user_id,
    subject_display_name: subject.username,
    tenant_id: subject.tenant_id ?? '',
    expires_at: '2030-08-02T10:00:00Z',
  }
}

function authenticate(overrides: Partial<Principal> = {}) {
  const actor = principal({
    username: 'jason',
    ...overrides,
  })
  useSessionStore.getState().setSession(authResponse(actor), actor, 'new')
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function mfaError(status: number, code: string): Response {
  return json({ error: { code, message: 'private server detail', request_id: 'mfa-request-error' } }, status)
}

function inactive(): Response {
  return json({ status: 'inactive' })
}

function pending(): Response {
  return json({
    status: 'enrollment_pending', credential_id: credentialID, method: 'totp',
    enrollment_expires_at: '2026-08-02T10:00:00Z',
  })
}

function active(): Response {
  return json({ status: 'active', credential_id: credentialID, method: 'totp' })
}

function profile(userID: string, username: string) {
  return {
    id: userID,
    username,
    display_name: username,
    email: null,
    phone: null,
    revision: 1,
    created_at: '2026-08-02T08:00:00Z',
    updated_at: '2026-08-02T08:00:00Z',
  }
}

function renderPanel(queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } },
})) {
  const result = render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/account/user']}>
            <AccountMfaPanel />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
  return { ...result, queryClient }
}

function placeholders(tree: AccountMfaMessageTree, prefix = ''): Record<string, string[]> {
  const result: Record<string, string[]> = {}
  for (const [key, value] of Object.entries(tree)) {
    const path = prefix ? `${prefix}.${key}` : key
    if (typeof value === 'string') {
      result[path] = [...value.matchAll(/{{\s*([^},\s]+)[^}]*}}/g)].map((match) => match[1]).sort()
    } else {
      Object.assign(result, placeholders(value, path))
    }
  }
  return result
}

function messageLeaves(tree: AccountMfaMessageTree, prefix = ''): Record<string, string> {
  const result: Record<string, string> = {}
  for (const [key, value] of Object.entries(tree)) {
    const path = prefix ? `${prefix}.${key}` : key
    if (typeof value === 'string') result[path] = value
    else Object.assign(result, messageLeaves(value, path))
  }
  return result
}

function placeholderTokens(value: string): string[] {
  return [...value.matchAll(/{{[^}]+}}/g)].map((match) => match[0])
}

function nonPlaceholderLength(value: string): number {
  return [...value.replace(/{{[^}]+}}/g, '').replace(/\s/gu, '')].length
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, reject, resolve }
}

function valueRepresentations(value: unknown, seen = new WeakSet<object>()): string[] {
  if (typeof value === 'string') return [value]
  if (value === null || value === undefined || typeof value !== 'object') return [String(value)]
  if (seen.has(value)) return []
  seen.add(value)

  const result: string[] = []
  try {
    result.push(JSON.stringify(value))
  } catch {
    // Cyclic cache and console values are inspected property by property below.
  }
  for (const key of Reflect.ownKeys(value)) {
    result.push(String(key))
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (descriptor && 'value' in descriptor) {
      result.push(...valueRepresentations(descriptor.value, seen))
    }
  }
  return result
}

function expectNoSensitiveValue(value: unknown, forbidden: string[]) {
  for (const representation of valueRepresentations(value)) {
    for (const sensitive of forbidden) expect(representation).not.toContain(sensitive)
  }
}

function expectNoSensitivePersistence(
  queryClient: QueryClient,
  consoleSpies: Array<ReturnType<typeof vi.spyOn>>,
  forbidden: string[],
) {
  for (const storage of [localStorage, sessionStorage]) {
    for (let index = 0; index < storage.length; index += 1) {
      const key = storage.key(index)!
      const raw = storage.getItem(key) ?? ''
      expectNoSensitiveValue(key, forbidden)
      expectNoSensitiveValue(raw, forbidden)
      let parsed: unknown
      let isJson = false
      try {
        parsed = JSON.parse(raw)
        isJson = true
      } catch {
        // Non-JSON storage is already checked as its exact raw value.
      }
      if (isJson) expectNoSensitiveValue(parsed, forbidden)
    }
  }
  for (const query of queryClient.getQueryCache().getAll()) {
    expectNoSensitiveValue(query.queryKey, forbidden)
    expectNoSensitiveValue(query.state, forbidden)
  }
  for (const mutation of queryClient.getMutationCache().getAll()) {
    expectNoSensitiveValue(mutation.state, forbidden)
    expectNoSensitiveValue(mutation.options, forbidden)
  }
  for (const spy of consoleSpies) expectNoSensitiveValue(spy.mock.calls, forbidden)
}

function expectLeakScannerCoversEverySurface(
  consoleSpies: Array<ReturnType<typeof vi.spyOn>>,
) {
  const queryClient = new QueryClient()
  const assertLeakDetected = (sentinel: string) => {
    expect(() => expectNoSensitivePersistence(queryClient, consoleSpies, [sentinel])).toThrow()
  }

  try {
    localStorage.setItem('safe-storage-key', JSON.stringify({ nested: ['storage-value-probe'] }))
    assertLeakDetected('storage-value-probe')
    localStorage.clear()

    localStorage.setItem('storage-key-probe', 'safe-storage-value')
    assertLeakDetected('storage-key-probe')
    localStorage.clear()

    sessionStorage.setItem('safe-session-key', JSON.stringify({ nested: ['session-value-probe'] }))
    assertLeakDetected('session-value-probe')
    sessionStorage.clear()

    sessionStorage.setItem('session-key-probe', 'safe-session-value')
    assertLeakDetected('session-key-probe')
    sessionStorage.clear()

    queryClient.setQueryData(['query-key-probe'], { safe: true })
    assertLeakDetected('query-key-probe')
    queryClient.clear()

    queryClient.setQueryData(['safe-query-key'], { nested: ['query-state-probe'] })
    assertLeakDetected('query-state-probe')
    queryClient.clear()

    const mutation = queryClient.getMutationCache().build(queryClient, {
      mutationFn: async () => undefined,
      mutationKey: ['safe-mutation-key'],
      meta: { nested: ['mutation-options-probe'] },
    })
    assertLeakDetected('mutation-options-probe')
    queryClient.getMutationCache().remove(mutation)

    const stateMutation = queryClient.getMutationCache().build(queryClient, {
      mutationFn: async () => undefined,
      mutationKey: ['safe-state-mutation-key'],
    }, {
      context: undefined,
      data: undefined,
      error: null,
      failureCount: 0,
      failureReason: null,
      isPaused: false,
      status: 'pending',
      variables: { nested: ['mutation-state-probe'] },
      submittedAt: 1,
    })
    assertLeakDetected('mutation-state-probe')
    queryClient.getMutationCache().remove(stateMutation)

    for (const [index, method] of (['debug', 'info', 'log', 'warn', 'error'] as const).entries()) {
      const sentinel = `console-${method}-probe`
      console[method]({ nested: [sentinel] })
      assertLeakDetected(sentinel)
      consoleSpies[index].mockClear()
    }
  } finally {
    localStorage.clear()
    sessionStorage.clear()
    queryClient.clear()
  }
}

describe('AccountMfaPanel', () => {
  it('keeps platform authenticator controls without a tenant-bound proof form', async () => {
    authenticate({ scope_kind: 'platform', tenant_id: null, permissions: ['identity.self.read'] })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(active())
    renderPanel()

    expect(await screen.findByRole('button', { name: '重置 MFA' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '停用 MFA' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '创建短期授权凭据' })).not.toBeInTheDocument()
  })

  it.each([
    ['platform.admin', 'identity.self.read'],
    ['identity.users.manage', 'identity.self.read'],
  ])('lets a platform administrator enroll its own authenticator without a tenant identity: %j', async (...permissions) => {
    authenticate({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(inactive())
      .mockResolvedValueOnce(json({
        credential_id: credentialID, secret, provisioning_uri: provisioningURI,
        expires_at: '2026-08-02T10:00:00Z', replayed: false,
      }, 201))
      .mockResolvedValueOnce(pending())
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    expect(await screen.findByDisplayValue(secret)).toBeInTheDocument()
    const enrollment = fetchSpy.mock.calls.find(([url]) => String(url) === '/v1/account/mfa/enrollments')
    expect(JSON.parse(String(enrollment?.[1]?.body))).toEqual({ account_label: 'jason' })
    expect(new Headers(enrollment?.[1]?.headers).get('Authorization')).toBe('Bearer memory-only-access-token')
  })

  it.each([
    { scope_kind: 'platform' as const, tenant_id: '22222222-2222-4222-8222-222222222222' },
    { scope_kind: 'tenant' as const, tenant_id: null },
  ])('rejects inconsistent MFA scope identity without sending requests: %j', async (identity) => {
    authenticate(identity)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderPanel()
    expect(await screen.findByText('无权管理 MFA')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('lets an ordinary tenant owner enroll its own authenticator without any MFA permission code', async () => {
    // 后端 MFA 接口只认本人会话，不要求权限码；租户 owner 的真实权限里没有 identity.mfa.*。
    authenticate({ roles: ['tenant_owner'], permissions: ['identity.self.read', 'identity.self.update'] })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(inactive())
      .mockResolvedValueOnce(json({
        credential_id: credentialID, secret, provisioning_uri: provisioningURI,
        expires_at: '2026-08-02T10:00:00Z', replayed: false,
      }, 201))
      .mockResolvedValueOnce(pending())
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    expect(await screen.findByDisplayValue(secret)).toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([url]) => String(url) === '/v1/account/mfa/enrollments')).toBe(true)
  })

  it('refuses MFA management during impersonation without sending requests', async () => {
    authenticate()
    const current = useSessionStore.getState().principal!
    authenticate({ impersonation: impersonationMarker(current) })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderPanel()
    expect(await screen.findByText('无权管理 MFA')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '设置身份验证器' })).not.toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('keeps all locale trees and placeholders exact with complete English and expanded pseudo-locales', () => {
    const zh = placeholders(accountMfaMessages['zh-CN'])
    const zhLeaves = messageLeaves(accountMfaMessages['zh-CN'])
    for (const locale of ['en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(Object.keys(messageLeaves(accountMfaMessages[locale]))).toEqual(Object.keys(zhLeaves))
      expect(placeholders(accountMfaMessages[locale])).toEqual(zh)
    }
    for (const value of Object.values(messageLeaves(accountMfaMessages['en-US']))) {
      expect(value).not.toMatch(/[\u3400-\u9fff\uf900-\ufaff]/u)
    }
    expect(accountMfaMessages['qps-Ploc']).toEqual(accountMfaMessages['qps-ploc'])
    for (const locale of ['qps-ploc', 'qps-Ploc'] as const) {
      const pseudoLeaves = messageLeaves(accountMfaMessages[locale])
      for (const [path, value] of Object.entries(pseudoLeaves)) {
        expect(value.startsWith('［')).toBe(true)
        expect(value.endsWith('］')).toBe(true)
        expect(nonPlaceholderLength(value.slice(1, -1)))
          .toBeGreaterThan(nonPlaceholderLength(zhLeaves[path]))
        expect(placeholderTokens(value)).toEqual(placeholderTokens(zhLeaves[path]))
      }
      expect(pseudoLeaves.title).toBe('［多~因~素~认~证~］')
      expect(pseudoLeaves.loading).toContain('M~F~A~')
      expect(pseudoLeaves['validation.accountLabelLength']).toContain('2~5~4~')
      expect(pseudoLeaves['descriptions.pending']).toContain('{{expiresAt}}')
    }
  })

  it('purges sensitive input and keeps write requests at zero when the session turns into impersonation', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') return active()
      throw new Error(`unexpected write: ${String(url)}`)
    })
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '停用 MFA' }))
    const dialog = screen.getByRole('dialog', { name: '确认停用 MFA' })
    await user.type(within(dialog).getByLabelText('验证码或恢复码'), '123456')
    await user.type(within(dialog).getByLabelText('原因'), 'permission revoked while editing')

    const current = useSessionStore.getState().principal!
    const revoked = { ...current, impersonation: impersonationMarker(current) }
    act(() => useSessionStore.getState().setSession(authResponse(revoked), revoked, 'refresh'))

    expect(screen.queryByRole('dialog', { name: '确认停用 MFA' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '停用 MFA' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '重置 MFA' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '创建短期授权凭据' })).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('123456')
    expect(document.body).not.toHaveTextContent('permission revoked while editing')
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0)
  })

  it('issues a one-time step-up proof without persisting or exposing the token after acknowledgement', async () => {
    authenticate()
    const consoleSpies = (['debug', 'info', 'log', 'warn', 'error'] as const).map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined))
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') return active()
      if (String(url) === '/v1/account/mfa/step-up-proofs') {
        return json({
          proof_id: credentialID,
          token: stepUpToken,
          method: 'totp',
          issued_at: '2026-08-02T09:00:00Z',
          expires_at: '2026-08-02T10:00:00Z',
          max_uses: 2,
          replayed: false,
        }, 201)
      }
      throw new Error(`unexpected request: ${String(url)}`)
    })
    const user = userEvent.setup()
    const { queryClient } = renderPanel()

    try {
      await user.click(await screen.findByRole('button', { name: '创建短期授权凭据' }))
      const dialog = screen.getByRole('dialog', { name: '创建短期授权凭据' })
      await user.type(within(dialog).getByLabelText('用途'), 'billing.grant')
      await user.type(within(dialog).getByLabelText('动作'), 'grant.create')
      await user.type(within(dialog).getByLabelText('验证码或恢复码'), '123456')
      await user.click(within(dialog).getByRole('button', { name: '确认' }))

      const receipt = await screen.findByRole('dialog', { name: '短期授权凭据（仅显示一次）' })
      expect(within(receipt).getByDisplayValue(stepUpToken)).toBeInTheDocument()
      const write = fetchSpy.mock.calls.find(([url]) => String(url).endsWith('/step-up-proofs'))
      expect(write?.[1]?.body).toContain('billing.grant')
      expect(write?.[1]?.body).toContain('grant.create')
      expect(queryClient.getMutationCache().getAll()).toHaveLength(0)
      expect(document.body.textContent).not.toContain(stepUpToken)

      await user.click(within(receipt).getByRole('button', { name: '我已安全保存' }))
      expect(screen.queryByDisplayValue(stepUpToken)).not.toBeInTheDocument()
      expect(document.body).not.toHaveTextContent(stepUpToken)
      for (const spy of consoleSpies) {
        for (const call of spy.mock.calls) expect(JSON.stringify(call)).not.toContain(stepUpToken)
      }
    } finally {
      queryClient.clear()
    }
  })

  it('keeps a one-time step-up proof visible until acknowledgement when status refresh fails', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(active())
      .mockResolvedValueOnce(json({
        proof_id: credentialID,
        token: stepUpToken,
        method: 'totp',
        issued_at: '2026-08-02T09:00:00Z',
        expires_at: '2026-08-02T10:00:00Z',
        max_uses: 1,
        replayed: false,
      }, 201))
      .mockResolvedValueOnce(mfaError(503, 'mfa_unavailable'))
      .mockResolvedValueOnce(active())
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '创建短期授权凭据' }))
    const dialog = screen.getByRole('dialog', { name: '创建短期授权凭据' })
    await user.type(within(dialog).getByLabelText('用途'), 'billing.grant')
    await user.type(within(dialog).getByLabelText('动作'), 'grant.create')
    await user.type(within(dialog).getByLabelText('验证码或恢复码'), '123456')
    await user.click(within(dialog).getByRole('button', { name: '确认' }))

    const receipt = await screen.findByRole('dialog', { name: '短期授权凭据（仅显示一次）' })
    expect(within(receipt).getByDisplayValue(stepUpToken)).toBeInTheDocument()
    expect(screen.queryByText('MFA 状态加载失败')).not.toBeInTheDocument()

    await user.click(within(receipt).getByRole('button', { name: '我已安全保存' }))
    expect(await screen.findByText('MFA 状态加载失败')).toBeInTheDocument()
    expect(screen.queryByDisplayValue(stepUpToken)).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(stepUpToken)

    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('已启用')).toBeInTheDocument()
  })

  it('retries an unknown step-up proof with the exact body and idempotency metadata', async () => {
    authenticate()
    let stepUpCalls = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') return active()
      if (String(url) === '/v1/account/mfa/step-up-proofs') {
        stepUpCalls += 1
        throw new TypeError('connection closed after commit')
      }
      throw new Error(`unexpected request: ${String(url)}`)
    })
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '创建短期授权凭据' }))
    const dialog = screen.getByRole('dialog', { name: '创建短期授权凭据' })
    await user.type(within(dialog).getByLabelText('用途'), 'billing.grant')
    await user.type(within(dialog).getByLabelText('动作'), 'grant.create')
    await user.type(within(dialog).getByLabelText('验证码或恢复码'), '123456')
    await user.click(within(dialog).getByRole('button', { name: '确认' }))

    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(stepUpCalls).toBe(2))
    const writes = fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/step-up-proofs'))
    expect(writes[1][1]?.body).toBe(writes[0][1]?.body)
    for (const header of ['Idempotency-Key', 'X-Request-ID', 'Traceparent']) {
      expect(new Headers(writes[1][1]?.headers).get(header))
        .toBe(new Headers(writes[0][1]?.headers).get(header))
    }
    expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeEnabled()
    expect(screen.queryByDisplayValue('123456')).not.toBeInTheDocument()
  })

  it('uses a monotonic session epoch that distinguishes new sessions from refreshes', () => {
    const actor = principal({ username: 'same-principal' })
    const initialEpoch = useSessionStore.getState().sessionEpoch

    useSessionStore.getState().setSession(authResponse(actor), actor, 'new')
    const firstEpoch = useSessionStore.getState().sessionEpoch
    expect(firstEpoch).toBeGreaterThan(initialEpoch)

    useSessionStore.getState().setSession({
      ...authResponse(actor), access_token: 'rotated-token', expires_in: 1,
    }, actor, 'refresh')
    expect(useSessionStore.getState().sessionEpoch).toBe(firstEpoch)

    useSessionStore.getState().clearSession()
    const clearedEpoch = useSessionStore.getState().sessionEpoch
    expect(clearedEpoch).toBeGreaterThan(firstEpoch)

    useSessionStore.getState().setSession(authResponse(actor), actor, 'refresh')
    const bootstrapEpoch = useSessionStore.getState().sessionEpoch
    expect(bootstrapEpoch).toBeGreaterThan(clearedEpoch)

    useSessionStore.getState().setSession(authResponse(actor), actor, 'new')
    const reloginEpoch = useSessionStore.getState().sessionEpoch
    expect(reloginEpoch).toBeGreaterThan(bootstrapEpoch)

    resetSessionStore()
    expect(useSessionStore.getState().sessionEpoch).toBeGreaterThan(reloginEpoch)
  })

  it.each([
    ['clear', 'new-principal'] as const,
    ['logout', 'new-principal'] as const,
    ['same-principal same-expiry relogin', 'same-principal'] as const,
    ['different-principal relogin', 'different-principal'] as const,
  ])('applies the second refresh guard after a pending old me across %s', async (
    transition,
    nextIdentity,
  ) => {
    for (const oldOutcome of ['success', 'failure'] as const) {
      resetSessionStore()
      const dateSpy = vi.spyOn(Date, 'now').mockReturnValue(1_800_000_000_000)
      const oldActor = principal({ username: 'same-principal' })
      const nextActor = nextIdentity === 'same-principal'
        ? oldActor
        : principal({
            user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
            username: nextIdentity,
          })
      const initialResponse: AuthResponse = {
        ...authResponse(oldActor), access_token: `initial-${transition}-${oldOutcome}`, expires_in: 73,
      }
      useSessionStore.getState().setSession(initialResponse, oldActor, 'new')
      const initialExpiresAt = useSessionStore.getState().expiresAt
      const oldMeResponse = deferred<Response>()
      let oldMeCalls = 0
      let refreshCalls = 0
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
        const path = String(url)
        if (path === '/v1/auth/refresh') {
          refreshCalls += 1
          return json({
            ...authResponse(refreshCalls === 1 ? oldActor : nextActor),
            access_token: refreshCalls === 1
              ? `old-me-token-${transition}-${oldOutcome}`
              : `current-refresh-${transition}-${oldOutcome}`,
            expires_in: 73,
          })
        }
        if (path === '/v1/auth/login') {
          return json({ ...authResponse(nextActor), access_token: `login-${transition}-${oldOutcome}`, expires_in: 73 })
        }
        if (path === '/v1/auth/logout') return new Response(null, { status: 204 })
        if (path === '/v1/auth/me') {
          const authorization = new Headers(init?.headers).get('Authorization')
          if (authorization === `Bearer old-me-token-${transition}-${oldOutcome}`) {
            oldMeCalls += 1
            return oldMeResponse.promise
          }
          return json(nextActor)
        }
        throw new Error(`unexpected request: ${path}`)
      })

      try {
        const oldRefresh = refreshSession()
        const observedOldRefresh = oldRefresh.then(
          () => 'fulfilled' as const,
          () => 'rejected' as const,
        )
        await waitFor(() => expect(oldMeCalls).toBe(1))

        if (transition === 'clear') useSessionStore.getState().clearSession()
        else if (transition === 'logout') await logoutSession()
        else await loginSession({ username: nextActor.username, password: 'not-persisted' })

        const transitionState = useSessionStore.getState()
        if (transition === 'same-principal same-expiry relogin') {
          expect(transitionState.expiresAt).toBe(initialExpiresAt)
        }
        const currentRefresh = refreshSession()
        expect(currentRefresh).not.toBe(oldRefresh)
        await expect(currentRefresh).resolves.toEqual(nextActor)
        expect(refreshCalls).toBe(2)

        const currentState = useSessionStore.getState()
        expect(currentState).toMatchObject({
          accessToken: `current-refresh-${transition}-${oldOutcome}`,
          principal: nextActor,
          status: 'authenticated',
        })
        if (transition === 'clear' || transition === 'logout') {
          expect(currentState.sessionEpoch).toBeGreaterThan(transitionState.sessionEpoch)
        } else {
          expect(currentState.sessionEpoch).toBe(transitionState.sessionEpoch)
        }

        if (oldOutcome === 'success') oldMeResponse.resolve(json(oldActor))
        else oldMeResponse.reject(new TypeError('stale me failed'))
        expect(await observedOldRefresh).toBe('rejected')
        expect(useSessionStore.getState()).toMatchObject({
          accessToken: currentState.accessToken,
          expiresAt: currentState.expiresAt,
          principal: currentState.principal,
          sessionEpoch: currentState.sessionEpoch,
          status: currentState.status,
        })
      } finally {
        fetchSpy.mockRestore()
        dateSpy.mockRestore()
      }
    }
  })

  it.each([
    ['clear', 'new-principal'] as const,
    ['logout', 'new-principal'] as const,
    ['same-principal same-expiry relogin', 'same-principal'] as const,
    ['different-principal relogin', 'different-principal'] as const,
  ])('keeps the new refresh attempt while an old pending refresh finalizes across %s', async (
    transition,
    nextIdentity,
  ) => {
    for (const oldOutcome of ['success', 'failure'] as const) {
      resetSessionStore()
      const dateSpy = vi.spyOn(Date, 'now').mockReturnValue(1_800_000_000_000)
      const oldActor = principal({ username: 'same-principal' })
      const nextActor = nextIdentity === 'same-principal'
        ? oldActor
        : principal({
            user_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
            username: nextIdentity,
          })
      useSessionStore.getState().setSession({
        ...authResponse(oldActor), access_token: `initial-refresh-${transition}-${oldOutcome}`, expires_in: 73,
      }, oldActor, 'new')
      const initialExpiresAt = useSessionStore.getState().expiresAt
      const oldRefreshResponse = deferred<Response>()
      const newRefreshResponse = deferred<Response>()
      let refreshCalls = 0
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
        const path = String(url)
        if (path === '/v1/auth/refresh') {
          refreshCalls += 1
          return refreshCalls === 1 ? oldRefreshResponse.promise : newRefreshResponse.promise
        }
        if (path === '/v1/auth/login') {
          return json({ ...authResponse(nextActor), access_token: `login-refresh-${transition}-${oldOutcome}`, expires_in: 73 })
        }
        if (path === '/v1/auth/logout') return new Response(null, { status: 204 })
        if (path === '/v1/auth/me') return json(nextActor)
        throw new Error(`unexpected request: ${path}`)
      })

      try {
        const oldRefresh = refreshSession()
        const observedOldRefresh = oldRefresh.then(
          () => 'fulfilled' as const,
          () => 'rejected' as const,
        )
        await waitFor(() => expect(refreshCalls).toBe(1))

        if (transition === 'clear') useSessionStore.getState().clearSession()
        else if (transition === 'logout') await logoutSession()
        else await loginSession({ username: nextActor.username, password: 'not-persisted' })

        const transitionState = useSessionStore.getState()
        if (transition === 'same-principal same-expiry relogin') {
          expect(transitionState.expiresAt).toBe(initialExpiresAt)
        }
        const currentRefresh = refreshSession()
        expect(currentRefresh).not.toBe(oldRefresh)
        await waitFor(() => expect(refreshCalls).toBe(2))

        if (oldOutcome === 'success') {
          oldRefreshResponse.resolve(json({
            ...authResponse(oldActor), access_token: `stale-refresh-${transition}`, expires_in: 73,
          }))
        } else {
          oldRefreshResponse.reject(new TypeError('stale refresh failed'))
        }
        expect(await observedOldRefresh).toBe('rejected')
        expect(refreshSession()).toBe(currentRefresh)
        expect(refreshCalls).toBe(2)

        newRefreshResponse.resolve(json({
          ...authResponse(nextActor), access_token: `current-refresh-${transition}-${oldOutcome}`, expires_in: 73,
        }))
        await expect(currentRefresh).resolves.toEqual(nextActor)
        expect(useSessionStore.getState()).toMatchObject({
          accessToken: `current-refresh-${transition}-${oldOutcome}`,
          principal: nextActor,
          status: 'authenticated',
        })
      } finally {
        fetchSpy.mockRestore()
        dateSpy.mockRestore()
      }
    }
  })

  it('fails closed when refresh me returns a different principal identity', async () => {
    const actorA = principal({
      user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      username: 'refresh-a',
    })
    const actorB = principal({
      scope_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      tenant_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      username: 'refresh-b',
    })
    useSessionStore.getState().setSession({ ...authResponse(actorA), access_token: 'refresh-a-token' }, actorA, 'new')
    const startingEpoch = useSessionStore.getState().sessionEpoch
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ ...authResponse(actorA), access_token: 'mismatched-me-token' }))
      .mockResolvedValueOnce(json(actorB))

    await expect(refreshSession()).rejects.toThrow()
    expect(useSessionStore.getState()).toMatchObject({
      accessToken: null,
      principal: null,
      status: 'anonymous',
    })
    expect(useSessionStore.getState().sessionEpoch).toBeGreaterThan(startingEpoch)
  })

  it('preserves one-time receipts and unknown exact retry only for a same-session refresh', async () => {
    const actor = principal({ username: 'jason' })
    useSessionStore.getState().setSession(authResponse(actor), actor, 'new')
    let writes = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') return inactive()
      writes += 1
      if (writes === 1) {
        return json({
          credential_id: credentialID,
          secret,
          provisioning_uri: provisioningURI,
          expires_at: '2026-08-02T10:00:00Z',
          replayed: false,
        }, 201)
      }
      throw new TypeError('connection closed after commit')
    })
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    expect(await screen.findByDisplayValue(secret)).toBeInTheDocument()

    act(() => useSessionStore.getState().setSession({
      ...authResponse(actor), access_token: 'rotated-token', expires_in: 1,
    }, actor, 'refresh'))
    expect(screen.getByDisplayValue(secret)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '我已安全保存' }))
    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()

    act(() => useSessionStore.getState().setSession({
      ...authResponse(actor), access_token: 'rotated-again', expires_in: 2,
    }, actor, 'refresh'))
    expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeEnabled()
  })

  it('enrolls from the inactive empty state and purges one-time setup material after acknowledgement', async () => {
    authenticate()
    const consoleSpies = (['debug', 'info', 'log', 'warn', 'error'] as const).map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined))
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(inactive())
      .mockResolvedValueOnce(json({
        credential_id: credentialID,
        secret,
        provisioning_uri: provisioningURI,
        expires_at: '2026-08-02T10:00:00Z',
        replayed: false,
      }, 201))
      .mockResolvedValueOnce(pending())
    const user = userEvent.setup()
    const clipboard = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: clipboard } })
    const { queryClient } = renderPanel()

    expect(await screen.findByText('尚未配置身份验证器')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '设置身份验证器' }))
    const enrollment = screen.getByRole('dialog', { name: '设置身份验证器' })
    expect(within(enrollment).getByLabelText('账户标签')).toHaveValue('jason')
    await user.click(within(enrollment).getByRole('button', { name: '确认' }))

    const receipt = await screen.findByRole('dialog', { name: '验证器密钥（仅显示一次）' })
    expect(within(receipt).getByLabelText('TOTP 密钥')).toHaveAttribute('type', 'password')
    expect(within(receipt).getByLabelText('配置 URI')).toHaveAttribute('type', 'password')
    await user.click(within(receipt).getByRole('button', { name: '复制 TOTP 密钥' }))
    await user.click(within(receipt).getByRole('button', { name: '复制配置 URI' }))
    expect(clipboard).toHaveBeenNthCalledWith(1, secret)
    expect(clipboard).toHaveBeenNthCalledWith(2, provisioningURI)
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0)
    expectNoSensitivePersistence(queryClient, consoleSpies, [secret, provisioningURI])
    expectLeakScannerCoversEverySurface(consoleSpies)

    await user.click(within(receipt).getByRole('button', { name: '我已安全保存' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '验证器密钥（仅显示一次）' })).not.toBeInTheDocument())
    expect(document.body).not.toHaveTextContent(secret)
    expect(document.body).not.toHaveTextContent(provisioningURI)
    expect(await screen.findByText('等待激活')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url]) => String(url) === '/v1/account/mfa')).toHaveLength(2)
  })

  it('keeps the MFA state row compact and wrap-safe for narrow account panels', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(inactive())
    renderPanel()

    expect(await screen.findByText('尚未配置身份验证器')).toBeInTheDocument()
    const state = screen.getByText('尚未配置身份验证器').closest('.account-mfa-state')
    expect(state).toHaveStyle({ display: 'flex', width: '100%', flexWrap: 'wrap', gap: '16px' })
    expect(screen.getByRole('button', { name: '设置身份验证器' })).toBeEnabled()
  })

  it('shows recovery codes once, hidden by default, then removes them from the DOM', async () => {
    authenticate()
    const consoleSpies = (['debug', 'info', 'log', 'warn', 'error'] as const).map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined))
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(pending())
      .mockResolvedValueOnce(json({
        credential_id: credentialID,
        recovery_codes: recoveryCodes,
        activated_at: '2026-08-02T09:00:00Z',
        replayed: false,
      }, 201))
      .mockResolvedValueOnce(active())
    const user = userEvent.setup()
    const clipboard = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: clipboard } })
    const { queryClient } = renderPanel()

    await user.type(await screen.findByLabelText('六位验证码'), '123456')
    await user.click(screen.getByRole('button', { name: '激活 MFA' }))
    const receipt = await screen.findByRole('dialog', { name: '恢复码（仅显示一次）' })
    expect(within(receipt).queryByText(recoveryCodes[0])).not.toBeInTheDocument()
    await user.click(within(receipt).getByRole('button', { name: '显示恢复码' }))
    expect(within(receipt).getByText(recoveryCodes[0])).toBeInTheDocument()
    await user.click(within(receipt).getByRole('button', { name: '复制恢复码' }))
    expect(clipboard).toHaveBeenCalledWith(recoveryCodes.join('\n'))
    const activationWrite = fetchSpy.mock.calls.find(([url]) => String(url).endsWith('/activate'))
    expect(activationWrite).toBeDefined()
    expectNoSensitivePersistence(queryClient, consoleSpies, [
      ...recoveryCodes,
      '123456',
      String(activationWrite?.[1]?.body),
    ])
    await user.click(within(receipt).getByRole('button', { name: '我已安全保存' }))

    await waitFor(() => expect(screen.queryByRole('dialog', { name: '恢复码（仅显示一次）' })).not.toBeInTheDocument())
    for (const code of recoveryCodes) expect(document.body).not.toHaveTextContent(code)
    expect(await screen.findByText('已启用')).toBeInTheDocument()
  })

  it('never remounts recovery codes after acknowledgement around a failed status refresh', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(pending())
      .mockResolvedValueOnce(json({
        credential_id: credentialID,
        recovery_codes: recoveryCodes,
        activated_at: '2026-08-02T09:00:00Z',
        replayed: false,
      }, 201))
      .mockResolvedValueOnce(mfaError(503, 'mfa_unavailable'))
      .mockResolvedValueOnce(active())
    const user = userEvent.setup()
    renderPanel()

    await user.type(await screen.findByLabelText('六位验证码'), '123456')
    await user.click(screen.getByRole('button', { name: '激活 MFA' }))
    const receipt = await screen.findByRole('dialog', { name: '恢复码（仅显示一次）' })
    await user.click(within(receipt).getByRole('button', { name: '显示恢复码' }))
    expect(within(receipt).getByText(recoveryCodes[0])).toBeInTheDocument()
    await user.click(within(receipt).getByRole('button', { name: '我已安全保存' }))

    expect(await screen.findByText('MFA 状态加载失败')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('已启用')).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '恢复码（仅显示一次）' })).not.toBeInTheDocument()
    for (const code of recoveryCodes) expect(document.body).not.toHaveTextContent(code)
  })

  it.each([
    ['enrollment', inactive, '设置身份验证器', '账户标签', '确认', {
      credential_id: credentialID, expires_at: '2026-08-02T10:00:00Z', replayed: true,
    }, '请求已重放，密钥和配置 URI 不会再次显示。'],
    ['activation', pending, null, '六位验证码', '激活 MFA', {
      credential_id: credentialID, activated_at: '2026-08-02T09:00:00Z', replayed: true,
    }, '请求已重放，恢复码不会再次显示。'],
  ] as const)('explains that a same-digest %s replay cannot restore one-time values', async (
    _kind, statusResponse, openName, fieldName, submitName, replay, notice,
  ) => {
    authenticate()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(statusResponse())
      .mockResolvedValueOnce(json(replay, 200))
      .mockResolvedValueOnce('activated_at' in replay ? active() : pending())
    const user = userEvent.setup()
    renderPanel()

    if (openName) await user.click(await screen.findByRole('button', { name: openName }))
    const field = await screen.findByLabelText(fieldName)
    await user.clear(field)
    await user.type(field, fieldName === '账户标签' ? 'jason' : '123456')
    await user.click(screen.getByRole('button', { name: submitName }))

    expect(await screen.findByText(notice)).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: /仅显示一次/ })).not.toBeInTheDocument()
  })

  it('locks an unknown write to exact retry or cancel, then uses a fresh key for changed input', async () => {
    authenticate()
    let enrollmentWrites = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') return inactive()
      enrollmentWrites += 1
      if (enrollmentWrites <= 2) throw new TypeError('connection closed after commit')
      return json({
        credential_id: credentialID,
        secret,
        provisioning_uri: provisioningURIFor('jason-new'),
        expires_at: '2026-08-02T10:00:00Z',
        replayed: false,
      }, 201)
    })
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.queryByLabelText('账户标签')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(enrollmentWrites).toBe(2))

    const writesAfterRetry = fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/enrollments'))
    expect(writesAfterRetry).toHaveLength(2)
    expect(writesAfterRetry[0][1]?.body).toBe(writesAfterRetry[1][1]?.body)
    expect(new Headers(writesAfterRetry[0][1]?.headers).get('Idempotency-Key'))
      .toBe(new Headers(writesAfterRetry[1][1]?.headers).get('Idempotency-Key'))

    await user.click(screen.getByRole('button', { name: '取消并刷新' }))
    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    const label = screen.getByLabelText('账户标签')
    await user.clear(label)
    await user.type(label, 'jason-new')
    await user.click(screen.getByRole('button', { name: '确认' }))
    expect(await screen.findByRole('dialog', { name: '验证器密钥（仅显示一次）' })).toBeInTheDocument()

    const allWrites = fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/enrollments'))
    expect(allWrites).toHaveLength(3)
    expect(allWrites[2][1]?.body).not.toBe(allWrites[0][1]?.body)
    expect(new Headers(allWrites[2][1]?.headers).get('Idempotency-Key'))
      .not.toBe(new Headers(allWrites[0][1]?.headers).get('Idempotency-Key'))
  })

  it.each(['activate', 'disable', 'reset'] as const)(
    'retries an unknown %s with the exact body and correlation metadata without leaking them',
    async (action) => {
      authenticate()
      const endpoint = action === 'activate'
        ? `/v1/account/mfa/enrollments/${credentialID}/activate`
        : `/v1/account/mfa/${action}`
      const consoleSpies = (['debug', 'info', 'log', 'warn', 'error'] as const).map((method) =>
        vi.spyOn(console, method).mockImplementation(() => undefined))
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
        if (String(url) === '/v1/account/mfa' && init?.method === 'GET') {
          return action === 'activate' ? pending() : active()
        }
        if (String(url) === endpoint) throw new TypeError('connection closed after commit')
        throw new Error(`unexpected request: ${String(url)}`)
      })
      const user = userEvent.setup()
      const { queryClient } = renderPanel()

      if (action === 'activate') {
        await user.type(await screen.findByLabelText('六位验证码'), '123456')
        await user.click(screen.getByRole('button', { name: '激活 MFA' }))
      } else {
        await user.click(await screen.findByRole('button', { name: action === 'disable' ? '停用 MFA' : '重置 MFA' }))
        const dialog = screen.getByRole('dialog', { name: action === 'disable' ? '确认停用 MFA' : '确认重置 MFA' })
        await user.type(within(dialog).getByLabelText('验证码或恢复码'), '123456')
        await user.type(within(dialog).getByLabelText('原因'), 'private retry reason')
        await user.click(within(dialog).getByRole('button', { name: '确认' }))
      }

      await user.click(await screen.findByRole('button', { name: '使用同一请求重试' }))
      await waitFor(() => expect(fetchSpy.mock.calls.filter(([url]) => String(url) === endpoint)).toHaveLength(2))
      const writes = fetchSpy.mock.calls.filter(([url]) => String(url) === endpoint)
      expect(writes[1][1]?.body).toBe(writes[0][1]?.body)
      for (const header of ['Idempotency-Key', 'X-Request-ID', 'Traceparent']) {
        expect(new Headers(writes[1][1]?.headers).get(header))
          .toBe(new Headers(writes[0][1]?.headers).get(header))
      }

      const firstHeaders = new Headers(writes[0][1]?.headers)
      const sensitive = [
        secret,
        provisioningURI,
        ...recoveryCodes,
        '123456',
        'private retry reason',
        String(writes[0][1]?.body),
        firstHeaders.get('Idempotency-Key'),
        firstHeaders.get('X-Request-ID'),
        firstHeaders.get('Traceparent'),
      ].filter((value): value is string => Boolean(value))
      for (const value of sensitive) expect(document.body).not.toHaveTextContent(value)
      expect(screen.queryByDisplayValue('123456')).not.toBeInTheDocument()
      expect(screen.queryByDisplayValue('private retry reason')).not.toBeInTheDocument()
      expect(queryClient.getMutationCache().getAll()).toHaveLength(0)
      expectNoSensitivePersistence(queryClient, consoleSpies, sensitive)
    },
  )

  it('keeps every write locked until cancel-and-refresh returns a strict current state', async () => {
    authenticate()
    let resolveRefresh: ((response: Response) => void) | undefined
    let reads = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') {
        reads += 1
        if (reads === 1) return inactive()
        return new Promise<Response>((resolve) => { resolveRefresh = resolve })
      }
      throw new TypeError('connection closed after commit')
    })
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '取消并刷新' }))

    expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeDisabled()
    expect(screen.getByRole('button', { name: /取消并刷新/ })).toBeDisabled()
    expect(screen.queryByRole('button', { name: '设置身份验证器' })).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/enrollments'))).toHaveLength(1)

    resolveRefresh?.(inactive())
    expect(await screen.findByRole('button', { name: '设置身份验证器' })).toBeEnabled()
  })

  it('keeps the exact retry locked when cancel-and-refresh cannot confirm current state', async () => {
    authenticate()
    let reads = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') {
        reads += 1
        return reads === 1 ? inactive() : mfaError(503, 'mfa_unavailable')
      }
      throw new TypeError('connection closed after commit')
    })
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    await user.click(await screen.findByRole('button', { name: '取消并刷新' }))

    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '取消并刷新' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: '设置身份验证器' })).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/enrollments'))).toHaveLength(1)
  })

  it.each([
    [404, 'mfa_route_not_found'],
    [405, 'mfa_method_not_allowed'],
    [422, 'mfa_invalid_code'],
  ] as const)(
    'keeps the original unknown write locked when status refresh fails deterministically with %s',
    async (status, code) => {
      authenticate()
      let reads = 0
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
        if (String(url) === '/v1/account/mfa' && init?.method === 'GET') {
          reads += 1
          return reads === 1 ? inactive() : mfaError(status, code)
        }
        throw new TypeError('connection closed after commit')
      })
      const user = userEvent.setup()
      renderPanel()

      await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
      await user.click(screen.getByRole('button', { name: '确认' }))
      await user.click(await screen.findByRole('button', { name: '取消并刷新' }))

      expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeEnabled()
      expect(screen.getByRole('button', { name: '取消并刷新' })).toBeEnabled()
      expect(screen.queryByRole('button', { name: '设置身份验证器' })).not.toBeInTheDocument()
      expect(fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/enrollments'))).toHaveLength(1)
    },
  )

  it('locks every live panel instance when another instance records an owner tombstone', async () => {
    const actor = principal({
      user_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      username: 'shared-owner',
    })
    useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'shared-owner-token' }, actor, 'new')
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') return inactive()
      throw new TypeError('connection closed after commit')
    })
    const user = userEvent.setup()
    const first = renderPanel()
    const second = renderPanel()

    await user.click(await within(first.container).findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    expect(await within(first.container).findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    // 说明文字在 OutcomeUnknown 弹窗里（挂在 body），第二个面板内只留恢复条。
    expect(await within(second.container).findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    // 两个面板实例都锁定时各自有一个 OutcomeUnknown 弹窗，至少要有一个带此说明。
    expect(screen.getAllByText(
      '之前的写入结果仍未知，敏感请求内容已清除。严格刷新确认当前状态前，不能再次写入。',
      { selector: '.cdnca-feedback-detail' },
    ).length).toBeGreaterThan(0)
    expect(within(second.container).queryByRole('button', { name: '设置身份验证器' })).not.toBeInTheDocument()
  })

  it('does not let a pending enrollment restore one-time values after another panel receives 401', async () => {
    const actor = principal({
      user_id: '67676767-6767-4676-8676-676767676767',
      username: 'shared-auth-fence-enroll',
    })
    useSessionStore.getState().setSession({
      ...authResponse(actor), access_token: 'shared-auth-fence-enroll-token',
    }, actor, 'new')
    const oldWrite = deferred<Response>()
    let reads = 0
    let writes = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') {
        reads += 1
        return reads === 2 ? mfaError(401, 'mfa_unauthenticated') : inactive()
      }
      if (String(url).endsWith('/v1/account/mfa/enrollments')) {
        writes += 1
        return oldWrite.promise
      }
      throw new Error(`unexpected request: ${String(url)}`)
    })
    const user = userEvent.setup()
    const first = renderPanel()

    await user.click(await within(first.container).findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    await waitFor(() => expect(writes).toBe(1))

    const second = renderPanel()
    expect(await within(second.container).findByText('会话已失效')).toBeInTheDocument()

    await act(async () => {
      oldWrite.resolve(json({
        credential_id: credentialID,
        secret,
        provisioning_uri: provisioningURIFor(actor.username),
        expires_at: '2026-08-02T10:00:00Z',
        replayed: false,
      }, 201))
      await oldWrite.promise
      await new Promise((resolve) => setTimeout(resolve, 0))
    })

    expect(within(first.container).getByText('会话已失效')).toBeInTheDocument()
    expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue(provisioningURIFor(actor.username))).not.toBeInTheDocument()
  })

  it('does not restore an exact retry body after another panel receives 403', async () => {
    const actor = principal({
      user_id: '78787878-7878-4787-8787-787878787878',
      username: 'shared-auth-fence-retry',
    })
    useSessionStore.getState().setSession({
      ...authResponse(actor), access_token: 'shared-auth-fence-retry-token',
    }, actor, 'new')
    const oldRetry = deferred<Response>()
    let reads = 0
    let writes = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') {
        reads += 1
        return reads <= 2 ? active() : mfaError(403, 'mfa_principal_changed')
      }
      if (String(url) === '/v1/account/mfa/disable') {
        writes += 1
        if (writes === 1) throw new TypeError('shared auth retry outcome unknown')
        return oldRetry.promise
      }
      throw new Error(`unexpected request: ${String(url)}`)
    })
    const user = userEvent.setup()
    const first = renderPanel()
    const second = renderPanel()

    await user.click(await within(first.container).findByRole('button', { name: '停用 MFA' }))
    const dialog = screen.getByRole('dialog', { name: '确认停用 MFA' })
    await user.type(within(dialog).getByLabelText('验证码或恢复码'), '123456')
    await user.type(within(dialog).getByLabelText('原因'), 'private auth fence reason')
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    await closeOutcomeDialogs()
    await user.click(await within(first.container).findByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(writes).toBe(2))

    // fix-feedbackui: the recovery button sits in the open outcome dialog (document.body).
    await user.click(await screen.findByRole('button', { name: '刷新确认状态' }))
    expect(await within(second.container).findByText('无权管理 MFA')).toBeInTheDocument()

    await act(async () => {
      oldRetry.reject(new TypeError('old exact retry still unknown'))
      await oldRetry.promise.catch(() => undefined)
      await new Promise((resolve) => setTimeout(resolve, 0))
    })

    expect(within(first.container).getByText('无权管理 MFA')).toBeInTheDocument()
    expect(screen.queryByDisplayValue('123456')).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue('private auth fence reason')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(writes).toBe(2)
  })

  it('publishes a shared lock before the first write can create a tombstone', async () => {
    const actor = principal({
      user_id: '89898989-8989-4898-8898-898989898989',
      username: 'shared-pre-tombstone-lock',
    })
    useSessionStore.getState().setSession({
      ...authResponse(actor), access_token: 'shared-pre-tombstone-token',
    }, actor, 'new')
    const oldWrite = deferred<Response>()
    let reads = 0
    let writes = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') {
        reads += 1
        return reads === 1 ? inactive() : pending()
      }
      if (String(url).endsWith('/v1/account/mfa/enrollments')) {
        writes += 1
        return oldWrite.promise
      }
      throw new Error(`unexpected request: ${String(url)}`)
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } },
    })
    const user = userEvent.setup()
    const first = renderPanel(queryClient)
    const second = renderPanel(queryClient)

    await user.click(await within(first.container).findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    await waitFor(() => expect(writes).toBe(1))

    const secondEnrollment = within(second.container).getByRole('button', { name: '设置身份验证器' })
    expect(secondEnrollment).toBeDisabled()
    fireEvent.click(secondEnrollment)
    expect(screen.getAllByRole('dialog', { name: '设置身份验证器' })).toHaveLength(1)
    expect(writes).toBe(1)

    await act(async () => {
      oldWrite.resolve(json({
        credential_id: credentialID,
        expires_at: '2026-08-02T10:00:00Z',
        replayed: true,
      }))
      await oldWrite.promise
    })
    await waitFor(() => expect(reads).toBe(2))
  })

  it('keeps every live panel locked until an exact retry settles and a later strict read succeeds', async () => {
    const actor = principal({
      user_id: '34343434-3434-4434-8434-343434343434',
      username: 'shared-retry-success',
    })
    useSessionStore.getState().setSession({
      ...authResponse(actor), access_token: 'shared-retry-success-token',
    }, actor, 'new')
    const strictStatus = deferred<Response>()
    let reads = 0
    let writes = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') {
        reads += 1
        return reads === 1 ? inactive() : strictStatus.promise
      }
      if (String(url).endsWith('/v1/account/mfa/enrollments')) {
        writes += 1
        if (writes === 1) throw new TypeError('shared retry outcome unknown')
        return json({
          credential_id: credentialID,
          expires_at: '2026-08-02T10:00:00Z',
          replayed: true,
        })
      }
      throw new Error(`unexpected request: ${String(url)}`)
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } },
    })
    const user = userEvent.setup()
    const first = renderPanel(queryClient)
    const second = renderPanel(queryClient)

    await user.click(await within(first.container).findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    await closeOutcomeDialogs()
    await user.click(await within(first.container).findByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(reads).toBe(2))

    // 说明文字在 OutcomeUnknown 弹窗里（挂在 body），第二个面板内只留恢复条。
    expect(within(second.container).getByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    // 两个面板实例都锁定时各自有一个 OutcomeUnknown 弹窗，至少要有一个带此说明。
    expect(screen.getAllByText(
      '之前的写入结果仍未知，敏感请求内容已清除。严格刷新确认当前状态前，不能再次写入。',
      { selector: '.cdnca-feedback-detail' },
    ).length).toBeGreaterThan(0)
    expect(within(second.container).queryByRole('button', { name: '设置身份验证器' })).not.toBeInTheDocument()

    await act(async () => {
      strictStatus.resolve(pending())
      await strictStatus.promise
    })
    expect(await within(second.container).findByRole('button', { name: '激活 MFA' })).toBeEnabled()
  })

  it('keeps every live panel locked after a deterministic exact retry error without a strict read', async () => {
    const actor = principal({
      user_id: '56565656-5656-4565-8565-565656565656',
      username: 'shared-retry-error',
    })
    useSessionStore.getState().setSession({
      ...authResponse(actor), access_token: 'shared-retry-error-token',
    }, actor, 'new')
    let reads = 0
    let writes = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') {
        reads += 1
        return inactive()
      }
      if (String(url).endsWith('/v1/account/mfa/enrollments')) {
        writes += 1
        if (writes === 1) throw new TypeError('shared retry outcome unknown')
        return mfaError(409, 'mfa_idempotency_conflict')
      }
      throw new Error(`unexpected request: ${String(url)}`)
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } },
    })
    const user = userEvent.setup()
    const first = renderPanel(queryClient)
    const second = renderPanel(queryClient)

    await user.click(await within(first.container).findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    await closeOutcomeDialogs()
    await user.click(await within(first.container).findByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(writes).toBe(2))

    // 说明文字在 OutcomeUnknown 弹窗里（挂在 body），第二个面板内只留恢复条。
    expect(within(second.container).getByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    // 两个面板实例都锁定时各自有一个 OutcomeUnknown 弹窗，至少要有一个带此说明。
    expect(screen.getAllByText(
      '之前的写入结果仍未知，敏感请求内容已清除。严格刷新确认当前状态前，不能再次写入。',
      { selector: '.cdnca-feedback-detail' },
    ).length).toBeGreaterThan(0)
    expect(within(second.container).queryByRole('button', { name: '设置身份验证器' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeEnabled()
    expect(reads).toBe(1)
  })

  it('does not let an old epoch success unlock a newer session', async () => {
    const actor = principal({
      user_id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
      username: 'cas-success-owner',
    })
    useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'cas-success-a' }, actor, 'new')
    const oldRetry = deferred<Response>()
    let oldWrites = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      const authorization = new Headers(init?.headers).get('Authorization')
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') return inactive()
      if (String(url).endsWith('/v1/account/mfa/enrollments')) {
        if (authorization === 'Bearer cas-success-a') {
          oldWrites += 1
          if (oldWrites === 1) throw new TypeError('old outcome unknown')
          return oldRetry.promise
        }
        if (authorization === 'Bearer cas-success-b') throw new TypeError('new outcome unknown')
      }
      throw new Error(`unexpected request: ${String(url)}`)
    })
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    await user.click(await screen.findByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(oldWrites).toBe(2))

    act(() => useSessionStore.getState().setSession({
      ...authResponse(actor), access_token: 'cas-success-b',
    }, actor, 'new'))
    expect(await screen.findByText(
      '之前的写入结果仍未知，敏感请求内容已清除。严格刷新确认当前状态前，不能再次写入。',
    )).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '设置身份验证器' })).not.toBeInTheDocument()

    await act(async () => {
      oldRetry.resolve(json({
        credential_id: credentialID,
        secret,
        provisioning_uri: provisioningURIFor(actor.username),
        expires_at: '2026-08-02T10:00:00Z',
        replayed: false,
      }, 201))
      await oldRetry.promise
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
    expect(screen.getByText(
      '之前的写入结果仍未知，敏感请求内容已清除。严格刷新确认当前状态前，不能再次写入。',
    )).toBeInTheDocument()
    expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url, init]) =>
      String(url).endsWith('/enrollments')
      && new Headers(init?.headers).get('Authorization') === 'Bearer cas-success-b',
    )).toHaveLength(0)
  })

  it('does not let an old epoch error unlock a newer session', async () => {
    const actor = principal({
      user_id: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
      username: 'cas-error-owner',
    })
    useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'cas-error-a' }, actor, 'new')
    const oldRetry = deferred<Response>()
    let oldWrites = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      const authorization = new Headers(init?.headers).get('Authorization')
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') return inactive()
      if (String(url).endsWith('/v1/account/mfa/enrollments')) {
        if (authorization === 'Bearer cas-error-a') {
          oldWrites += 1
          if (oldWrites === 1) throw new TypeError('old outcome unknown')
          return oldRetry.promise
        }
      }
      throw new Error(`unexpected request: ${String(url)}`)
    })
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    await user.click(await screen.findByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(oldWrites).toBe(2))

    act(() => useSessionStore.getState().setSession({
      ...authResponse(actor), access_token: 'cas-error-b',
    }, actor, 'new'))
    expect(await screen.findByText(
      '之前的写入结果仍未知，敏感请求内容已清除。严格刷新确认当前状态前，不能再次写入。',
    )).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '设置身份验证器' })).not.toBeInTheDocument()

    await act(async () => {
      oldRetry.reject(new TypeError('old retry still unknown'))
      await oldRetry.promise.catch(() => undefined)
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
    expect(screen.getByText(
      '之前的写入结果仍未知，敏感请求内容已清除。严格刷新确认当前状态前，不能再次写入。',
    )).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url, init]) =>
      String(url).endsWith('/enrollments')
      && new Headers(init?.headers).get('Authorization') === 'Bearer cas-error-b',
    )).toHaveLength(0)
  })

  it('keeps a generation locked until its retry settles and a later strict status read completes', async () => {
    const actor = principal({
      user_id: '12121212-1212-4212-8212-121212121212',
      username: 'generation-flight-owner',
    })
    useSessionStore.getState().setSession({
      ...authResponse(actor), access_token: 'generation-flight-a',
    }, actor, 'new')
    const oldRetry = deferred<Response>()
    let oldWrites = 0
    let currentReads = 0
    let currentWrites = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      const authorization = new Headers(init?.headers).get('Authorization')
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') {
        if (authorization === 'Bearer generation-flight-b') {
          currentReads += 1
          return currentReads === 1 ? inactive() : pending()
        }
        return inactive()
      }
      if (String(url).endsWith('/v1/account/mfa/enrollments')) {
        if (authorization === 'Bearer generation-flight-a') {
          oldWrites += 1
          if (oldWrites === 1) throw new TypeError('old generation outcome unknown')
          return oldRetry.promise
        }
        if (authorization === 'Bearer generation-flight-b') {
          currentWrites += 1
          throw new Error('new generation write must remain locked')
        }
      }
      throw new Error(`unexpected request: ${String(url)}`)
    })
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    await user.click(await screen.findByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(oldWrites).toBe(2))

    act(() => useSessionStore.getState().setSession({
      ...authResponse(actor), access_token: 'generation-flight-b',
    }, actor, 'new'))
    await waitFor(() => expect(currentReads).toBe(1))
    expect(await screen.findByText(
      '之前的写入结果仍未知，敏感请求内容已清除。严格刷新确认当前状态前，不能再次写入。',
    )).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '设置身份验证器' })).not.toBeInTheDocument()
    expect(currentWrites).toBe(0)

    await act(async () => {
      oldRetry.resolve(json({
        credential_id: credentialID,
        secret,
        provisioning_uri: provisioningURIFor(actor.username),
        expires_at: '2026-08-02T10:00:00Z',
        replayed: false,
      }, 201))
      await oldRetry.promise
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
    expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument()
    expect(screen.getByText(
      '之前的写入结果仍未知，敏感请求内容已清除。严格刷新确认当前状态前，不能再次写入。',
    )).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '刷新确认状态' }))
    await waitFor(() => expect(currentReads).toBe(2))
    expect(await screen.findByLabelText('六位验证码')).toBeInTheDocument()
    expect(currentWrites).toBe(0)
    expect(fetchSpy.mock.calls.filter(([url, init]) =>
      String(url).endsWith('/enrollments')
      && new Headers(init?.headers).get('Authorization') === 'Bearer generation-flight-b',
    )).toHaveLength(0)
  })

  it.each([
    ['enroll', 'unauthorized'],
    ['activate', 'forbidden'],
    ['disable', 'network'],
    ['reset', 'malformed'],
  ] as const)(
    'keeps an unresolved %s tombstone across a %s refresh and reauthentication',
    async (action, refreshFailure) => {
      const actor = principal({ username: 'jason' })
      useSessionStore.getState().setSession(authResponse(actor), actor, 'new')
      let reads = 0
      let writes = 0
      let resolveReauthenticatedStatus: ((response: Response) => void) | undefined
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
        if (String(url) === '/v1/account/mfa' && init?.method === 'GET') {
          reads += 1
          if (reads === 1) return action === 'enroll' ? inactive() : action === 'activate' ? pending() : active()
          if (reads === 2) {
            if (refreshFailure === 'unauthorized') return mfaError(401, 'mfa_unauthenticated')
            if (refreshFailure === 'forbidden') return mfaError(403, 'mfa_principal_changed')
            if (refreshFailure === 'malformed') {
              return new Response('{', { status: 200, headers: { 'Content-Type': 'application/json' } })
            }
            throw new TypeError('status network unavailable')
          }
          return new Promise<Response>((resolve) => { resolveReauthenticatedStatus = resolve })
        }
        writes += 1
        throw new TypeError('connection closed after commit')
      })
      const user = userEvent.setup()
      renderPanel()

      if (action === 'enroll') {
        await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
        await user.click(screen.getByRole('button', { name: '确认' }))
      } else if (action === 'activate') {
        await user.type(await screen.findByLabelText('六位验证码'), '123456')
        await user.click(screen.getByRole('button', { name: '激活 MFA' }))
      } else {
        await user.click(await screen.findByRole('button', { name: action === 'disable' ? '停用 MFA' : '重置 MFA' }))
        const dialog = screen.getByRole('dialog', { name: action === 'disable' ? '确认停用 MFA' : '确认重置 MFA' })
        await user.type(within(dialog).getByLabelText('验证码或恢复码'), '123456')
        await user.type(within(dialog).getByLabelText('原因'), 'private terminal reason')
        await user.click(within(dialog).getByRole('button', { name: '确认' }))
      }

      await user.click(await screen.findByRole('button', { name: '取消并刷新' }))
      await waitFor(() => expect(reads).toBe(2))

      act(() => useSessionStore.getState().setSession({
        ...authResponse(actor), access_token: 'reauthenticated-token', expires_in: 97,
      }, actor, 'new'))

      expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '设置身份验证器' })).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '激活 MFA' })).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '停用 MFA' })).not.toBeInTheDocument()
      expect(screen.queryByDisplayValue('123456')).not.toBeInTheDocument()
      expect(screen.queryByDisplayValue('private terminal reason')).not.toBeInTheDocument()
      expect(writes).toBe(1)

      act(() => resolveReauthenticatedStatus?.(inactive()))
      expect(await screen.findByRole('button', { name: '设置身份验证器' })).toBeEnabled()
      expect(fetchSpy.mock.calls.filter(([url, init]) =>
        String(url) !== '/v1/account/mfa' || init?.method !== 'GET',
      )).toHaveLength(1)
    },
  )

  it('purges one-time values across identity changes and does not restore them on return', async () => {
    const actorA = principal({
      username: 'jason-a',
      user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    })
    useSessionStore.getState().setSession(authResponse(actorA), actorA, 'new')
    let reads = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') {
        reads += 1
        return reads === 1 || reads === 3 ? inactive() : pending()
      }
      return json({
        credential_id: credentialID,
        secret,
        provisioning_uri: provisioningURIFor(actorA.username),
        expires_at: '2026-08-02T10:00:00Z',
        replayed: false,
      }, 201)
    })
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    expect(await screen.findByDisplayValue(secret)).toBeInTheDocument()
    await waitFor(() => expect(reads).toBe(2))

    const actorB = principal({
      username: 'jason-b',
      user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    })
    act(() => useSessionStore.getState().setSession(authResponse(actorB), actorB))
    expect(await screen.findByText('尚未配置身份验证器')).toBeInTheDocument()
    expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue(provisioningURI)).not.toBeInTheDocument()

    act(() => useSessionStore.getState().setSession(authResponse(actorA), actorA))
    expect(await screen.findByText('等待激活')).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '验证器密钥（仅显示一次）' })).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue(provisioningURI)).not.toBeInTheDocument()
  })

  it('purges an open one-time receipt when a malformed live-session response returns 401', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(inactive())
      .mockResolvedValueOnce(json({
        credential_id: credentialID,
        secret,
        provisioning_uri: provisioningURI,
        expires_at: '2026-08-02T10:00:00Z',
        replayed: false,
      }, 201))
      .mockResolvedValueOnce(new Response('{', {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }))
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))

    expect(await screen.findByText('会话已失效')).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '验证器密钥（仅显示一次）' })).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue(provisioningURI)).not.toBeInTheDocument()
  })

  it('purges recovery codes when a malformed live-session response returns 403', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(pending())
      .mockResolvedValueOnce(json({
        credential_id: credentialID,
        recovery_codes: recoveryCodes,
        activated_at: '2026-08-02T09:00:00Z',
        replayed: false,
      }, 201))
      .mockResolvedValueOnce(new Response('forbidden', {
        status: 403,
        headers: { 'Content-Type': 'text/plain' },
      }))
    const user = userEvent.setup()
    renderPanel()

    await user.type(await screen.findByLabelText('六位验证码'), '123456')
    await user.click(screen.getByRole('button', { name: '激活 MFA' }))

    expect(await screen.findByText('无权管理 MFA')).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '恢复码（仅显示一次）' })).not.toBeInTheDocument()
    for (const code of recoveryCodes) expect(document.body).not.toHaveTextContent(code)
  })

  it('clears activation input and exact retry state after a malformed 401 write', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(pending())
      .mockResolvedValueOnce(new Response('{', {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }))
    const user = userEvent.setup()
    renderPanel()

    await user.type(await screen.findByLabelText('六位验证码'), '123456')
    await user.click(screen.getByRole('button', { name: '激活 MFA' }))

    expect(await screen.findByText('会话已失效')).toBeInTheDocument()
    expect(screen.queryByDisplayValue('123456')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
  })

  it('clears terminal credentials and exact retry state when refresh returns 403', async () => {
    authenticate()
    let reads = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') {
        reads += 1
        return reads === 1 ? active() : mfaError(403, 'mfa_principal_changed')
      }
      throw new TypeError('connection closed after commit')
    })
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '停用 MFA' }))
    const dialog = screen.getByRole('dialog', { name: '确认停用 MFA' })
    await user.type(within(dialog).getByLabelText('验证码或恢复码'), '123456')
    await user.type(within(dialog).getByLabelText('原因'), 'private terminal reason')
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    await user.click(await screen.findByRole('button', { name: '取消并刷新' }))

    expect(await screen.findByText('无权管理 MFA')).toBeInTheDocument()
    expect(screen.queryByDisplayValue('123456')).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue('private terminal reason')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
  })

  it('shows enrollment idempotency conflict inside its open dialog', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(inactive())
      .mockResolvedValueOnce(mfaError(409, 'mfa_idempotency_conflict'))
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    const dialog = screen.getByRole('dialog', { name: '设置身份验证器' })
    await user.click(within(dialog).getByRole('button', { name: '确认' }))

    expect(await within(dialog).findByText('请求内容与原幂等请求不一致，请刷新后重试。')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('账户标签')).toHaveValue('jason')
  })

  it('shows a deterministic activation error inside the active activation form', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(pending())
      .mockResolvedValueOnce(mfaError(422, 'mfa_invalid_code'))
    const user = userEvent.setup()
    renderPanel()

    await user.type(await screen.findByLabelText('六位验证码'), '123456')
    await user.click(screen.getByRole('button', { name: '激活 MFA' }))

    expect(await screen.findByText('验证码或恢复码无效。')).toBeInTheDocument()
    expect(screen.getByLabelText('六位验证码')).toHaveValue('123456')
    expect(screen.getByRole('button', { name: '激活 MFA' })).toBeEnabled()
  })

  it.each([
    ['disable', 422, 'mfa_invalid_code', '验证码或恢复码无效。'],
    ['reset', 409, 'mfa_idempotency_conflict', '请求内容与原幂等请求不一致，请刷新后重试。'],
  ] as const)('shows a deterministic %s error inside its open dialog', async (action, status, code, localized) => {
    authenticate()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(active())
      .mockResolvedValueOnce(mfaError(status, code))
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: action === 'disable' ? '停用 MFA' : '重置 MFA' }))
    const dialog = screen.getByRole('dialog', { name: action === 'disable' ? '确认停用 MFA' : '确认重置 MFA' })
    await user.type(within(dialog).getByLabelText('验证码或恢复码'), '123456')
    await user.type(within(dialog).getByLabelText('原因'), 'user request')
    await user.click(within(dialog).getByRole('button', { name: '确认' }))

    expect(await within(dialog).findByText(localized)).toBeInTheDocument()
    expect(within(dialog).getByLabelText('验证码或恢复码')).toHaveValue('123456')
  })

  it('clears an enrollment dialog after a deterministic 403', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(inactive())
      .mockResolvedValueOnce(mfaError(403, 'mfa_principal_changed'))
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    const dialog = screen.getByRole('dialog', { name: '设置身份验证器' })
    const label = within(dialog).getByLabelText('账户标签')
    await user.clear(label)
    await user.type(label, 'private-account-label')
    await user.click(within(dialog).getByRole('button', { name: '确认' }))

    expect(await screen.findByText('无权管理 MFA')).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '设置身份验证器' })).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue('private-account-label')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
  })

  it.each(['disable', 'reset'] as const)('confirms and submits %s with strong authentication', async (action) => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(active())
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(inactive())
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: action === 'disable' ? '停用 MFA' : '重置 MFA' }))
    const dialog = screen.getByRole('dialog', { name: action === 'disable' ? '确认停用 MFA' : '确认重置 MFA' })
    await user.type(within(dialog).getByLabelText('验证码或恢复码'), '123456')
    await user.type(within(dialog).getByLabelText('原因'), 'user request')
    await user.click(within(dialog).getByRole('button', { name: '确认' }))

    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url) === `/v1/account/mfa/${action}`)).toBe(true))
    const write = fetchSpy.mock.calls.find(([url]) => String(url) === `/v1/account/mfa/${action}`)
    expect(JSON.parse(String(write?.[1]?.body))).toEqual({
      authentication: { method: 'totp', code: '123456' }, reason: 'user request',
    })
    expect(await screen.findByText('尚未配置身份验证器')).toBeInTheDocument()
  })

  it('revalidates the terminal code against the selected authentication method', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(active())
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '停用 MFA' }))
    const dialog = screen.getByRole('dialog', { name: '确认停用 MFA' })
    const code = within(dialog).getByLabelText('验证码或恢复码')
    await user.type(code, '123456')
    await user.type(within(dialog).getByLabelText('原因'), 'user request')
    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '验证方式' }))
    fireEvent.click(await screen.findByText('恢复码', { selector: '.ant-select-item-option-content' }))
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    expect(await within(dialog).findByText('恢复码格式必须为四组八位大写 Base32 字符。')).toBeInTheDocument()

    await user.clear(code)
    await user.type(code, recoveryCodes[0])
    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '验证方式' }))
    fireEvent.click(await screen.findByText('TOTP 验证码', { selector: '.ant-select-item-option-content' }))
    expect(await within(dialog).findByText('TOTP 验证码必须是六位数字。')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url]) => String(url) === '/v1/account/mfa/disable')).toHaveLength(0)
  })

  it('shows a localized fail-closed error and sends no write when Web Crypto is unavailable', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(inactive())
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    vi.stubGlobal('crypto', undefined)
    try {
      const dialog = screen.getByRole('dialog', { name: '设置身份验证器' })
      await user.click(within(dialog).getByRole('button', { name: '确认' }))
      expect(await within(dialog).findByText('浏览器缺少安全随机数能力，无法发送 MFA 写入请求。')).toBeInTheDocument()
      expect(fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/enrollments'))).toHaveLength(0)
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('renders localized unauthorized and generic error states without server detail leakage', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(mfaError(401, 'mfa_unauthenticated'))
    const first = renderPanel()
    expect(await screen.findByText('会话已失效')).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private server detail')
    first.unmount()

    authenticate()
    vi.restoreAllMocks()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(mfaError(503, 'mfa_unavailable'))
    renderPanel()
    expect(await screen.findByText('MFA 状态加载失败')).toBeInTheDocument()
    expect(screen.getByText('MFA 服务暂不可用，请稍后重试。')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重试' })).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private server detail')
  })

  it.each([
    [404, 'mfa_route_not_found', 'MFA 接口不可用，请联系管理员。'],
    [405, 'mfa_method_not_allowed', 'MFA 请求方式不受支持。'],
    [413, 'mfa_request_too_large', 'MFA 请求内容过大。'],
  ])('maps stable server error %s without exposing its detail', async (status, code, localized) => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(mfaError(status, code))
    renderPanel()

    expect(await screen.findByText(localized)).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private server detail')
  })

  it('does not prefetch MFA for a profile error or a platform identity rejected by PermissionRoute', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'permission_denied', message: 'private profile policy' },
    }, 403))
    const first = renderWithProviders(<AccountUserPage />, ['/account/user'])
    expect(await screen.findByText('无权查看个人资料')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url]) => String(url) === '/v1/account/mfa')).toHaveLength(0)
    first.unmount()

    vi.restoreAllMocks()
    // 平台管理员现在可以进入自己的资料页，但入口仍受 identity.self.read 约束。
    authenticate({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
      permissions: ['platform.admin', 'identity.self.read'],
    })
    vi.restoreAllMocks()
    const platform = useSessionStore.getState().principal
    const platformFetch = vi.spyOn(globalThis, 'fetch')
      .mockImplementation(() => Promise.resolve(json(profile(platform?.user_id ?? '', platform?.username ?? ''))))
    renderWithProviders(<AppRoutes />, ['/account/user'])
    expect(await screen.findByRole('heading', { name: '个人资料' })).toBeInTheDocument()
    // 资料读成功后才读一次自己的 MFA 状态（登录安全设置徽章）。
    await waitFor(() => expect(platformFetch.mock.calls.filter(([url]) => String(url) === '/v1/account/mfa')).toHaveLength(1))
  })

  it('does not reuse an identity A profile cache or load MFA while identity B is unresolved', async () => {
    const actorA = principal({
      user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      username: 'identity-a',
    })
    const actorB = principal({
      user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      username: 'identity-b',
    })
    useSessionStore.getState().setSession({ ...authResponse(actorA), access_token: 'token-a' }, actorA, 'new')
    let resolveBProfile: ((response: Response) => void) | undefined
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      const authorization = new Headers(init?.headers).get('Authorization')
      if (String(url) === '/v1/account/profile') {
        if (authorization === 'Bearer token-a') return json(profile(actorA.user_id, actorA.username))
        return new Promise<Response>((resolve) => { resolveBProfile = resolve })
      }
      if (String(url) === '/v1/account/mfa') return inactive()
      throw new Error(`unexpected request: ${String(url)}`)
    })
    renderWithProviders(<AccountUserPage />, ['/account/user'])

    expect(await screen.findByText('identity-a')).toBeInTheDocument()
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([url]) => String(url) === '/v1/account/mfa')).toHaveLength(1))

    act(() => useSessionStore.getState().setSession({
      ...authResponse(actorB), access_token: 'token-b',
    }, actorB, 'new'))
    await waitFor(() => expect(resolveBProfile).toBeTypeOf('function'))
    expect(fetchSpy.mock.calls.filter(([url, init]) =>
      String(url) === '/v1/account/mfa' && new Headers(init?.headers).get('Authorization') === 'Bearer token-b',
    )).toHaveLength(0)

    act(() => resolveBProfile?.(json({
      error: { code: 'permission_denied', message: 'private profile policy' },
    }, 403)))
    expect(await screen.findByText('无权查看个人资料')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url, init]) =>
      String(url) === '/v1/account/mfa' && new Headers(init?.headers).get('Authorization') === 'Bearer token-b',
    )).toHaveLength(0)
  })

  it('binds profile and MFA loading to the full identity plus a non-sensitive session epoch', async () => {
    const actor = principal({ username: 'same-identity' })
    useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'token-a' }, actor, 'new')
    const epochA = useSessionStore.getState().sessionEpoch
    let resolveBProfile: ((response: Response) => void) | undefined
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      const authorization = new Headers(init?.headers).get('Authorization')
      if (String(url) === '/v1/account/profile') {
        if (authorization === 'Bearer token-a') return json(profile(actor.user_id, actor.username))
        return new Promise<Response>((resolve) => { resolveBProfile = resolve })
      }
      if (String(url) === '/v1/account/mfa' && init?.method === 'GET') {
        return authorization === 'Bearer token-a' ? inactive() : active()
      }
      if (String(url).endsWith('/v1/account/mfa/enrollments')) {
        return json({
          credential_id: credentialID,
          secret,
          provisioning_uri: provisioningURIFor(actor.username),
          expires_at: '2026-08-02T10:00:00Z',
          replayed: false,
        }, 201)
      }
      throw new Error(`unexpected request: ${String(url)}`)
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } },
    })
    const user = userEvent.setup()
    render(
      <ConfigProvider button={{ autoInsertSpace: false }}>
        <AntApp>
          <QueryClientProvider client={queryClient}>
            <MemoryRouter initialEntries={['/account/user']}>
              <AccountUserPage />
            </MemoryRouter>
          </QueryClientProvider>
        </AntApp>
      </ConfigProvider>,
    )

    await user.click(await screen.findByRole('button', { name: '立即设置' }))
    await user.click(await screen.findByRole('button', { name: '设置身份验证器' }))
    await user.click(screen.getByRole('button', { name: '确认' }))
    expect(await screen.findByDisplayValue(secret)).toBeInTheDocument()
    expect(queryClient.getQueryCache().getAll().map((query) => query.queryKey)).toContainEqual([
      'account-profile', actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, epochA,
    ])

    act(() => useSessionStore.getState().setSession({
      ...authResponse(actor), access_token: 'token-b',
    }, actor, 'new'))
    const epochB = useSessionStore.getState().sessionEpoch
    expect(epochB).toBeGreaterThan(epochA)
    await waitFor(() => expect(resolveBProfile).toBeTypeOf('function'))

    expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url, init]) =>
      String(url) === '/v1/account/mfa' && new Headers(init?.headers).get('Authorization') === 'Bearer token-b',
    )).toHaveLength(0)
    const profileKeys = queryClient.getQueryCache().getAll()
      .map((query) => query.queryKey)
      .filter((key) => key[0] === 'account-profile')
    expect(profileKeys).toContainEqual([
      'account-profile', actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, epochB,
    ])
    expect(JSON.stringify(profileKeys)).not.toContain('token-a')
    expect(JSON.stringify(profileKeys)).not.toContain('token-b')

    act(() => resolveBProfile?.(json({
      error: { code: 'permission_denied', message: 'private profile policy' },
    }, 403)))
    expect(await screen.findByText('无权查看个人资料')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url, init]) =>
      String(url) === '/v1/account/mfa' && new Headers(init?.headers).get('Authorization') === 'Bearer token-b',
    )).toHaveLength(0)
  })

  it('does not let a stale password success navigate or clear a newer session', async () => {
    const permissions = ['identity.self.read', 'identity.self.update', 'identity.password.change']
    const actorA = principal({ username: 'password-owner-a', permissions })
    useSessionStore.getState().setSession({
      ...authResponse(actorA), access_token: 'password-session-a',
    }, actorA, 'new')
    const epochA = useSessionStore.getState().sessionEpoch
    const passwordResponse = deferred<Response>()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/password' && init?.method === 'POST') {
        return passwordResponse.promise
      }
      if (String(url) === '/v1/account/profile') return json(profile(actorA.user_id, actorA.username))
      if (String(url) === '/v1/account/mfa') return inactive()
      throw new Error(`unexpected request: ${String(url)}`)
    })
    const clearSessionSpy = vi.spyOn(useSessionStore.getState(), 'clearSession')
    const user = userEvent.setup()
    renderWithProviders(<AppRoutes />, ['/account/user'])

    await user.click(await screen.findByRole('button', { name: '修改密码' }))
    await user.type(screen.getByLabelText('当前密码'), 'current-password')
    await user.type(screen.getByLabelText('新密码'), 'new-password-123')
    await user.type(screen.getByLabelText('确认密码'), 'new-password-123')
    await user.click(screen.getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([url, init]) =>
      String(url) === '/v1/account/password' && init?.method === 'POST',
    )).toHaveLength(1))
    const passwordWrite = fetchSpy.mock.calls.find(([url, init]) =>
      String(url) === '/v1/account/password' && init?.method === 'POST')
    expect(new Headers(passwordWrite?.[1]?.headers).get('Authorization')).toBe('Bearer password-session-a')

    const actorB = principal({
      user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      scope_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      tenant_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      username: 'password-owner-b',
      display_name: 'Password owner B',
      permissions,
    })
    await act(async () => {
      useSessionStore.getState().setSession({
        ...authResponse(actorB), access_token: 'password-session-b',
      }, actorB, 'new')
    })
    const epochB = useSessionStore.getState().sessionEpoch
    expect(epochB).toBeGreaterThan(epochA)

    await act(async () => {
      passwordResponse.resolve(new Response(null, { status: 204 }))
      await passwordResponse.promise
      await new Promise((resolve) => setTimeout(resolve, 0))
    })

    expect(clearSessionSpy).not.toHaveBeenCalled()
    expect(screen.queryByText('密码修改成功，请重新登录')).not.toBeInTheDocument()
    expect(useSessionStore.getState()).toMatchObject({
      accessToken: 'password-session-b',
      principal: actorB,
      sessionEpoch: epochB,
      status: 'authenticated',
    })
  })

  it.each([
    ['network', '无法连接服务，请稍后重试'],
    ['api', '当前密码不正确'],
  ] as const)('does not let a stale password %s error alter the newer session or form', async (
    outcome,
    localizedError,
  ) => {
    const permissions = ['identity.self.read', 'identity.self.update', 'identity.password.change']
    const actorA = principal({ username: `password-error-a-${outcome}`, permissions })
    useSessionStore.getState().setSession({
      ...authResponse(actorA), access_token: `password-error-a-${outcome}`,
    }, actorA, 'new')
    const passwordResponse = deferred<Response>()
    let passwordWrites = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      const authorization = new Headers(init?.headers).get('Authorization')
      if (String(url) === '/v1/account/password' && init?.method === 'POST') {
        passwordWrites += 1
        if (passwordWrites === 1) return passwordResponse.promise
        if (outcome === 'network') throw new TypeError('current owner network unavailable')
        return json({ error: { code: 'invalid_credentials', message: 'private password detail' } }, 401)
      }
      if (String(url) === '/v1/account/profile') {
        const current = authorization === `Bearer password-error-b-${outcome}`
          ? principal({ username: `password-error-b-${outcome}` })
          : actorA
        return json(profile(current.user_id, current.username))
      }
      if (String(url) === '/v1/account/mfa') return inactive()
      throw new Error(`unexpected request: ${String(url)}`)
    })
    const user = userEvent.setup()
    renderWithProviders(<AccountUserPage />, ['/account/user'])

    await user.click(await screen.findByRole('button', { name: '修改密码' }))
    await user.type(screen.getByLabelText('当前密码'), 'old-current-password')
    await user.type(screen.getByLabelText('新密码'), 'old-new-password-123')
    await user.type(screen.getByLabelText('确认密码'), 'old-new-password-123')
    await user.click(screen.getByRole('button', { name: '确定' }))
    await waitFor(() => expect(passwordWrites).toBe(1))

    const actorB = principal({
      user_id: outcome === 'network'
        ? '34343434-3434-4434-8434-343434343434'
        : '56565656-5656-4656-8656-565656565656',
      scope_id: '78787878-7878-4878-8878-787878787878',
      tenant_id: '78787878-7878-4878-8878-787878787878',
      username: `password-error-b-${outcome}`,
      permissions,
    })
    act(() => useSessionStore.getState().setSession({
      ...authResponse(actorB), access_token: `password-error-b-${outcome}`,
    }, actorB, 'new'))
    const epochB = useSessionStore.getState().sessionEpoch
    expect(await screen.findByText(actorB.username)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '修改密码' }))
    await user.type(screen.getByLabelText('当前密码'), 'b-current-password')
    await user.type(screen.getByLabelText('新密码'), 'b-new-password-123')
    await user.type(screen.getByLabelText('确认密码'), 'b-new-password-123')

    await act(async () => {
      if (outcome === 'network') passwordResponse.reject(new TypeError('old owner network unavailable'))
      else passwordResponse.resolve(json({
        error: { code: 'invalid_credentials', message: 'old private password detail' },
      }, 401))
      await passwordResponse.promise.catch(() => undefined)
      await new Promise((resolve) => setTimeout(resolve, 0))
    })

    expect(screen.queryByText(localizedError)).not.toBeInTheDocument()
    expect(screen.getByLabelText('当前密码')).toHaveValue('b-current-password')
    expect(screen.getByLabelText('新密码')).toHaveValue('b-new-password-123')
    expect(screen.getByLabelText('确认密码')).toHaveValue('b-new-password-123')
    expect(useSessionStore.getState()).toMatchObject({
      accessToken: `password-error-b-${outcome}`,
      principal: actorB,
      sessionEpoch: epochB,
      status: 'authenticated',
    })

    await user.click(screen.getByRole('button', { name: '确定' }))
    expect(await screen.findByText(localizedError)).toBeInTheDocument()
    expect(useSessionStore.getState()).toMatchObject({
      accessToken: `password-error-b-${outcome}`,
      principal: actorB,
      sessionEpoch: epochB,
      status: 'authenticated',
    })
    expect(fetchSpy.mock.calls.filter(([url, init]) =>
      String(url) === '/v1/account/password' && init?.method === 'POST',
    )).toHaveLength(2)
  })


  // 2026-09-19 资料页已删掉显示名称表单，原两条“资料保存”会话隔离用例改为覆盖同一写路径的邮箱绑定。
  it('drops a stale contact binding after a same-principal new session', async () => {
    const actor = principal({
      username: 'profile-same', permissions: ['identity.self.read', 'identity.self.update'],
    })
    useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'profile-same-a' }, actor, 'new')
    const oldPatch = deferred<Response>()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      const authorization = new Headers(init?.headers).get('Authorization')
      if (String(url) === '/v1/account/profile' && init?.method === 'PATCH') {
        if (authorization === 'Bearer profile-same-a') return oldPatch.promise
        return json({ ...profile(actor.user_id, actor.username), email: 'stale-used-b@example.com', revision: 2 })
      }
      if (String(url) === '/v1/account/profile') return json(profile(actor.user_id, actor.username))
      if (String(url) === '/v1/account/mfa') return inactive()
      throw new Error(`unexpected request: ${String(url)}`)
    })
    const user = userEvent.setup()
    renderWithProviders(<AccountUserPage />, ['/account/user'])

    const emailRow = (await screen.findAllByRole('button', { name: '立即绑定' }))[1]!
    await user.click(emailRow)
    const bindForm = within(document.querySelector('.account-user-bind-form') as HTMLElement)
    await user.type(bindForm.getByLabelText('邮箱绑定'), 'old-pending@example.com')
    await user.type(bindForm.getByLabelText('当前密码'), 'old-pending-password')
    await user.click(bindForm.getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(1))

    act(() => useSessionStore.getState().setSession({
      ...authResponse(actor), access_token: 'profile-same-b',
    }, actor, 'new'))
    await waitFor(() => expect(document.querySelector('.account-user-bind-form')).toBeNull())
    await act(async () => {
      oldPatch.reject(new TypeError('old profile outcome unknown'))
      await Promise.resolve()
    })

    expect(screen.queryByText('保存结果待确认')).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('old-pending-password')
    expect(fetchSpy.mock.calls.filter(([, init]) =>
      init?.method === 'PATCH'
      && new Headers(init.headers).get('Authorization') === 'Bearer profile-same-b',
    )).toHaveLength(0)
  })

  it('does not let an old contact binding success update a different current principal', async () => {
    const permissions = ['identity.self.read', 'identity.self.update']
    const actorA = principal({
      user_id: 'abababab-abab-4bab-8bab-abababababab', username: 'profile-a', permissions,
    })
    const actorB = principal({
      scope_id: 'bcbcbcbc-bcbc-4cbc-8cbc-bcbcbcbcbcbc',
      tenant_id: 'bcbcbcbc-bcbc-4cbc-8cbc-bcbcbcbcbcbc',
      user_id: 'bdbdbdbd-bdbd-4dbd-8dbd-bdbdbdbdbdbd',
      username: 'profile-b',
      permissions,
    })
    useSessionStore.getState().setSession({ ...authResponse(actorA), access_token: 'profile-owner-a' }, actorA, 'new')
    const oldPatch = deferred<Response>()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      const authorization = new Headers(init?.headers).get('Authorization')
      if (String(url) === '/v1/account/profile' && init?.method === 'PATCH') return oldPatch.promise
      if (String(url) === '/v1/account/profile') {
        return authorization === 'Bearer profile-owner-b'
          ? json(profile(actorB.user_id, actorB.username))
          : json(profile(actorA.user_id, actorA.username))
      }
      if (String(url) === '/v1/account/mfa') return inactive()
      throw new Error(`unexpected request: ${String(url)}`)
    })
    const user = userEvent.setup()
    renderWithProviders(<AccountUserPage />, ['/account/user'])

    await user.click((await screen.findAllByRole('button', { name: '立即绑定' }))[1]!)
    const bindForm = within(document.querySelector('.account-user-bind-form') as HTMLElement)
    await user.type(bindForm.getByLabelText('邮箱绑定'), 'old-success@example.com')
    await user.type(bindForm.getByLabelText('当前密码'), 'old-success-password')
    await user.click(bindForm.getByRole('button', { name: '确定' }))

    act(() => useSessionStore.getState().setSession({
      ...authResponse(actorB), access_token: 'profile-owner-b',
    }, actorB, 'new'))
    expect(await screen.findByText('profile-b')).toBeInTheDocument()
    await act(async () => {
      oldPatch.resolve(json({ ...profile(actorA.user_id, actorA.username), email: 'old-success@example.com', revision: 2 }))
      await Promise.resolve()
    })

    expect(useSessionStore.getState().principal).toMatchObject({ user_id: actorB.user_id })
    expect(screen.queryByText('个人资料已保存')).not.toBeInTheDocument()
    expect(screen.getByText('profile-b')).toBeInTheDocument()
    expect(screen.queryByText('profile-a')).not.toBeInTheDocument()
  })
})
