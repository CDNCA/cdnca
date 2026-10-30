import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { vi } from 'vitest'

import { AppRoutes } from '../App'
import { ApiError } from '../api/auth'
import { identityVerificationApi } from '../api/identityVerification'
import { mfaApi } from '../api/mfa'
import { usersApi, type AccountProfile } from '../api/users'
import { useSessionStore, type SessionUpdate } from '../auth/session'
import { changeLocale } from '../i18n'
import AccountUserPage from '../pages/AccountUserPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const profile: AccountProfile = {
  id: '11111111-1111-4111-8111-111111111111',
  username: 'jason',
  display_name: 'Jason',
  email: 'jason@example.com',
  // 手机未绑定、邮箱已绑定：两行分别是「立即绑定」与「更换绑定」。
  phone: null,
  revision: 1,
  created_at: '2026-07-22T08:00:00Z',
  updated_at: '2026-07-22T08:00:00Z',
}

function setAccountSession(options: {
  kind?: 'platform' | 'tenant'
  scopeID?: string
  tenantID?: string | null
  userID?: string
  displayName?: string
  permissions?: string[]
  accessToken?: string
  update?: SessionUpdate
} = {}) {
  const kind = options.kind ?? 'tenant'
  const actor = principal({
    scope_kind: kind,
    scope_id: options.scopeID ?? '22222222-2222-4222-8222-222222222222',
    tenant_id: options.tenantID === undefined
      ? (kind === 'tenant' ? '2a2a2a2a-2a2a-4a2a-8a2a-2a2a2a2a2a2a' : null)
      : options.tenantID,
    user_id: options.userID ?? profile.id,
    display_name: options.displayName ?? 'Jason',
    permissions: options.permissions ?? [
      'identity.self.read', 'identity.self.update', 'identity.password.change',
    ],
  })
  const response = authResponse(actor)
  useSessionStore.getState().setSession(
    { ...response, access_token: options.accessToken ?? response.access_token },
    actor,
    options.update,
  )
  const sessionEpoch = useSessionStore.getState().sessionEpoch
  return {
    actor,
    sessionEpoch,
    queryKey: [
      'account-profile', actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, sessionEpoch,
    ] as const,
  }
}

function authenticate() {
  return setAccountSession()
}

function profileResponse(value = profile): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function QueryClientCapture({ capture }: { capture: (queryClient: QueryClient) => void }) {
  capture(useQueryClient())
  return null
}

function renderPageWithQueryClient(routes = false) {
  let queryClient: QueryClient | undefined
  const page = routes ? <AppRoutes /> : <AccountUserPage />
  const result = renderWithProviders(
    <><QueryClientCapture capture={(client) => { queryClient = client }} />{page}</>,
    ['/account/user'],
  )
  if (!queryClient) throw new Error('query client was not captured')
  return { ...result, queryClient }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function allAccountApiSpies() {
  return [
    vi.spyOn(usersApi, 'profile'),
    vi.spyOn(usersApi, 'updateProfile'),
    vi.spyOn(usersApi, 'changePassword'),
    vi.spyOn(mfaApi, 'getStatus'),
    vi.spyOn(mfaApi, 'beginEnrollment'),
    vi.spyOn(mfaApi, 'activateEnrollment'),
    vi.spyOn(mfaApi, 'disable'),
    vi.spyOn(mfaApi, 'reset'),
  ]
}

describe('AccountUserPage', () => {
  it('renders the account summary and security action groups', async () => {
    await changeLocale('zh-CN')
    authenticate()
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    vi.spyOn(mfaApi, 'getStatus').mockResolvedValue({ status: 'inactive' })

    renderWithProviders(<AccountUserPage />, ['/account/user'])

    const title = await screen.findByRole('heading', { name: '个人资料' })
    const page = title.closest('.account-user-page')
    expect(page).not.toBeNull()
    expect(page).toHaveClass('account-profile-page')
    expect(page?.querySelector('.account-user-summary-grid')).not.toBeNull()
    // fp-role ID-03：末行是登录会话入口（/account/sessions）。
    expect(page?.querySelectorAll('.account-user-check')).toHaveLength(5)
    // 手机/邮箱绑定与登录安全（MFA）可用；没有实名认证权限时实名未开放，不显示「立即认证」。
    expect(page?.querySelectorAll('.account-user-check > .ant-btn')).toHaveLength(4)
    expect(within(page as HTMLElement).getByRole('button', { name: '查看' })).toBeEnabled()
    expect(page?.querySelectorAll('.account-user-check')[4]).toHaveTextContent('登录会话')
    expect(page?.querySelectorAll('.account-user-check > .ant-btn:disabled')).toHaveLength(0)
    expect(within(page as HTMLElement).getByRole('button', { name: '立即绑定' })).toBeEnabled()
    expect(within(page as HTMLElement).getByRole('button', { name: '更换绑定' })).toBeEnabled()
    expect(within(page as HTMLElement).getByRole('button', { name: '立即设置' })).toBeEnabled()
    expect(within(page as HTMLElement).queryByRole('button', { name: '立即认证' })).toBeNull()
    // 徽章按真实资料与 MFA 状态推导。
    const rows = [...(page as HTMLElement).querySelectorAll('.account-user-check')]
    expect(rows[1]).toHaveTextContent('未绑定')
    expect(rows[2]).toHaveTextContent('已绑定')
    expect(rows[2]).toHaveTextContent('您已绑定安全邮箱')
    await waitFor(() => expect(rows[3]).toHaveTextContent('未设置'))
    // 改密码入口是「登录密码」旁的铅笔，点开前不渲染密码输入框。
    expect(within(page as HTMLElement).getByRole('button', { name: '修改密码' })).toBeEnabled()
    expect(page?.querySelector('.account-user-password-form')).toBeNull()
  })

  it('expands the phone binding form inline and submits the new number with the current password', async () => {
    await changeLocale('zh-CN')
    authenticate()
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    vi.spyOn(mfaApi, 'getStatus').mockResolvedValue({ status: 'inactive' })
    const bindContact = vi.spyOn(usersApi, 'bindContact').mockResolvedValue({ ...profile, phone: '+8613900000000', revision: 2 })

    renderWithProviders(<AccountUserPage />, ['/account/user'])
    const title = await screen.findByRole('heading', { name: '个人资料' })
    const page = title.closest('.account-user-page') as HTMLElement

    const toggle = within(page).getByRole('button', { name: '立即绑定' })
    fireEvent.click(toggle)
    expect(page.querySelector('.account-user-bind-form')).not.toBeNull()

    fireEvent.click(within(page).getByRole('button', { name: '立即绑定' }))
    expect(page.querySelector('.account-user-bind-form')).toBeNull()

    fireEvent.click(toggle)
    const bindForm = within(page.querySelector('.account-user-bind-form') as HTMLElement)
    await userEvent.type(bindForm.getByLabelText('手机绑定'), '13900000000')
    await userEvent.type(bindForm.getByLabelText('当前密码'), 'correct horse battery')
    fireEvent.click(bindForm.getByRole('button', { name: '确定' }))

    await waitFor(() => expect(bindContact).toHaveBeenCalledTimes(1))
    expect(bindContact.mock.calls[0]![1]).toMatchObject({
      expected_revision: 1, display_name: 'Jason', phone: '13900000000', current_password: 'correct horse battery',
    })
    // 未提交的 email 字段不出现，服务端沿用现值，不会把已绑邮箱清空。
    expect(bindContact.mock.calls[0]![1]).not.toHaveProperty('email')
  })

  it('rejects incomplete and missing-read identities before profile, MFA, or fetch', async () => {
    await changeLocale('zh-CN')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(profileResponse())
    const apiSpies = allAccountApiSpies()
    const cases = [
      () => setAccountSession({ tenantID: null }),
      () => setAccountSession({ permissions: ['identity.self.update', 'identity.password.change'] }),
    ]

    for (const setup of cases) {
      setup()
      const view = renderWithProviders(<AccountUserPage />, ['/account/user'])
      expect(await screen.findByText('无权查看个人资料')).toBeInTheDocument()
      for (const apiSpy of apiSpies) expect(apiSpy).not.toHaveBeenCalled()
      expect(fetchSpy).not.toHaveBeenCalled()
      view.unmount()
    }
  })

  // 账户资料页对管理员展示的是他自己的资料，
  // 没有租户选择器，所以平台作用域读自身作用域而不是被本地拒绝。
  it('reads its own profile for a platform principal', async () => {
    await changeLocale('zh-CN')
    setAccountSession({ kind: 'platform' })
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    vi.spyOn(mfaApi, 'getStatus').mockResolvedValue({ status: 'inactive' })

    renderWithProviders(<AccountUserPage />, ['/account/user'])

    expect(await screen.findByRole('heading', { name: '个人资料' })).toBeInTheDocument()
    expect(usersApi.profile).toHaveBeenCalledTimes(1)
  })

  it('rejects a tenant session without tenant lineage before profile, MFA, or fetch', async () => {
    await changeLocale('zh-CN')
    setAccountSession({
      scopeID: '22222222-2222-4222-8222-222222222222',
      tenantID: null,
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(profileResponse())
    const apiSpies = allAccountApiSpies()

    renderWithProviders(<AccountUserPage />, ['/account/user'])

    expect(await screen.findByText('无权查看个人资料')).toBeInTheDocument()
    for (const apiSpy of apiSpies) expect(apiSpy).not.toHaveBeenCalled()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  // 资料只读展示，手机/邮箱走安全设置行内绑定，改密码走「登录密码」旁的铅笔。
  it.each([
    [['identity.self.read'], false, false],
    [['identity.self.read', 'identity.self.update'], true, false],
    [['identity.self.read', 'identity.password.change'], false, true],
  ] as const)(
    'gates contact binding and password change by permissions %j',
    async (permissions, canUpdate, canChangePassword) => {
      await changeLocale('zh-CN')
      setAccountSession({ permissions: [...permissions] })
      vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
      renderWithProviders(<AccountUserPage />, ['/account/user'])

      expect(await screen.findByText('jason')).toBeInTheDocument()
      expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
      for (const name of ['立即绑定', '更换绑定']) {
        if (canUpdate) expect(screen.getByRole('button', { name })).toBeEnabled()
        else expect(screen.getByRole('button', { name })).toBeDisabled()
      }
      const passwordEntry = screen.getByRole('button', { name: '修改密码' })
      if (canChangePassword) expect(passwordEntry).toBeEnabled()
      else expect(passwordEntry).toBeDisabled()
      expect(screen.queryByLabelText('新密码')).not.toBeInTheDocument()
    },
  )

  it('blocks a stale password submit after same-epoch password permission revocation', async () => {
    await changeLocale('zh-CN')
    const session = setAccountSession({ accessToken: 'account-permission-token-a' })
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    const changePassword = vi.spyOn(usersApi, 'changePassword')
    const user = userEvent.setup()
    renderWithProviders(<AccountUserPage />, ['/account/user'])

    await user.click(await screen.findByRole('button', { name: '修改密码' }))
    await user.type(screen.getByLabelText('当前密码'), 'current-password')
    await user.type(screen.getByLabelText('新密码'), 'new-password-123')
    await user.type(screen.getByLabelText('确认密码'), 'new-password-123')
    const staleSubmit = screen.getByRole('button', { name: '确定' })
    const passwordForm = staleSubmit.closest('form')!

    act(() => {
      setAccountSession({
        accessToken: 'account-permission-token-b', permissions: ['identity.self.read'], update: 'refresh',
      })
      staleSubmit.click()
      fireEvent.submit(passwordForm)
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
    expect(screen.getByRole('button', { name: '修改密码' })).toBeDisabled()
    await act(async () => { await Promise.resolve() })
    expect(changePassword).not.toHaveBeenCalled()
  })

  it('changes the password with the newest token after a same-session token refresh', async () => {
    await changeLocale('zh-CN')
    const session = setAccountSession({ accessToken: 'account-password-old-token' })
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    const changePassword = vi.spyOn(usersApi, 'changePassword').mockResolvedValue(undefined)
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()

    await user.click(await screen.findByRole('button', { name: '修改密码' }))
    await user.type(screen.getByLabelText('当前密码'), 'current-password')
    await user.type(screen.getByLabelText('新密码'), 'new-password-123')
    await user.type(screen.getByLabelText('确认密码'), 'new-password-123')
    act(() => setAccountSession({ accessToken: 'account-password-newest-token', update: 'refresh' }))
    expect(useSessionStore.getState().sessionEpoch).toBe(session.sessionEpoch)
    expect(screen.getByLabelText('新密码')).toHaveValue('new-password-123')

    await user.click(screen.getByRole('button', { name: '确定' }))
    await waitFor(() => expect(changePassword).toHaveBeenCalledWith('account-password-newest-token', {
      current_password: 'current-password', new_password: 'new-password-123',
    }))
    const serialized = JSON.stringify(queryClient.getMutationCache().getAll().map((mutation) => mutation.state.variables))
    expect(serialized).not.toContain('current-password')
    expect(serialized).not.toContain('new-password-123')
  })

  it('maps a wrong current password locally, clears the secret and keeps the form editable', async () => {
    await changeLocale('zh-CN')
    authenticate()
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    const changePassword = vi.spyOn(usersApi, 'changePassword').mockRejectedValue(
      new ApiError('private password hash detail', 401, 'invalid_credentials'),
    )
    const user = userEvent.setup()
    renderWithProviders(<AccountUserPage />, ['/account/user'])

    await user.click(await screen.findByRole('button', { name: '修改密码' }))
    await user.type(screen.getByLabelText('当前密码'), 'wrong-current-password')
    await user.type(screen.getByLabelText('新密码'), 'new-password-123')
    await user.type(screen.getByLabelText('确认密码'), 'new-password-123')
    await user.click(screen.getByRole('button', { name: '确定' }))

    expect(await screen.findByText('当前密码不正确')).toBeInTheDocument()
    expect(screen.queryByText('private password hash detail')).not.toBeInTheDocument()
    expect(screen.getByLabelText('当前密码')).toHaveValue('')
    expect(screen.getByLabelText('当前密码')).toBeEnabled()
    expect(changePassword).toHaveBeenCalledOnce()
  })

  // fix-fielderr-be3: a refusal naming the new password is shown under it, not in a dialog.
  it('marks a refused new password under that field', async () => {
    await changeLocale('zh-CN')
    authenticate()
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    const refusal = new ApiError('invalid', 400, 'validation_error')
    refusal.field = 'new_password'
    refusal.reason = 'invalid'
    vi.spyOn(usersApi, 'changePassword').mockRejectedValue(refusal)
    const user = userEvent.setup()
    renderWithProviders(<AccountUserPage />, ['/account/user'])

    await user.click(await screen.findByRole('button', { name: '修改密码' }))
    await user.type(screen.getByLabelText('当前密码'), 'current-password-1')
    await user.type(screen.getByLabelText('新密码'), 'new-password-123')
    await user.type(screen.getByLabelText('确认密码'), 'new-password-123')
    await user.click(screen.getByRole('button', { name: '确定' }))

    const item = screen.getByLabelText('新密码').closest('.ant-form-item')!
    await waitFor(() => expect(item).toHaveClass('ant-form-item-has-error'))
    expect(await within(item as HTMLElement).findByText('填写的内容不符合要求')).toBeInTheDocument()
    expect(screen.queryByText('资料校验失败，请检查输入')).not.toBeInTheDocument()
  })

  it('remounts a clean boundary before a new identity profile resolves', async () => {
    await changeLocale('zh-CN')
    const profileB = {
      ...profile,
      id: '88888888-8888-4888-8888-888888888888',
      username: 'tenant-b',
      display_name: 'Tenant B Profile',
      email: 'tenant-b@example.com',
      phone: null,
      revision: 8,
    }
    const pendingB = deferred<AccountProfile>()
    vi.spyOn(usersApi, 'profile').mockImplementation((token) => {
      if (token === 'tenant-a-profile-token') return Promise.resolve(profile)
      if (token === 'tenant-b-profile-token') return pendingB.promise
      throw new Error(`unexpected profile token ${token}`)
    })
    vi.spyOn(usersApi, 'changePassword').mockRejectedValue(
      new ApiError('API request failed', 401, 'invalid_credentials'),
    )
    const sessionA = setAccountSession({ accessToken: 'tenant-a-profile-token' })
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()

    await user.click(await screen.findByRole('button', { name: '修改密码' }))
    await user.type(screen.getByLabelText('当前密码'), 'tenant-a-current-password')
    await user.type(screen.getByLabelText('新密码'), 'tenant-a-new-password')
    await user.type(screen.getByLabelText('确认密码'), 'tenant-a-new-password')
    await user.click(screen.getByRole('button', { name: '确定' }))
    expect(await screen.findByText('当前密码不正确')).toBeInTheDocument()

    let sessionB!: ReturnType<typeof setAccountSession>
    act(() => {
      sessionB = setAccountSession({
        scopeID: '77777777-7777-4777-8777-777777777777',
        tenantID: '77777777-7777-4777-8777-777777777777',
        userID: profileB.id,
        displayName: 'Tenant B Session',
        accessToken: 'tenant-b-profile-token',
      })
    })
    await waitFor(() => expect(usersApi.profile).toHaveBeenCalledWith('tenant-b-profile-token'))
    await waitFor(() => expect(queryClient.getQueryState(sessionA.queryKey)).toBeUndefined())

    expect(screen.getByLabelText('个人资料加载中')).toBeInTheDocument()
    expect(screen.queryByText('jason')).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue('tenant-a-new-password')).not.toBeInTheDocument()
    expect(screen.queryByText('当前密码不正确')).not.toBeInTheDocument()
    expect(queryClient.getQueryState(sessionB.queryKey)).toMatchObject({
      status: 'pending', fetchStatus: 'fetching', data: undefined,
    })

    await act(async () => pendingB.resolve(profileB))

    expect(await screen.findByText('tenant-b')).toBeInTheDocument()
    expect(screen.queryByLabelText('新密码')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '修改密码' })).toBeEnabled()
    expect(queryClient.getQueryState(sessionB.queryKey)).toMatchObject({
      status: 'success', fetchStatus: 'idle', error: null, data: profileB,
    })
  })

  it.each([
    ['GET', 'success'],
    ['GET', 'error'],
    ['PATCH', 'success'],
    ['PATCH', 'error'],
    ['POST', 'success'],
    ['POST', 'error'],
  ] as const)(
    'isolates a delayed tenant A profile %s %s after tenant B is fully loaded',
    async (operation, outcome) => {
      await changeLocale('zh-CN')
      const profileB = {
        ...profile,
        id: '88888888-8888-4888-8888-888888888888',
        username: 'stable-tenant-b',
        display_name: 'Stable Tenant B',
        email: 'stable-b@example.com',
        phone: null,
        revision: 12,
      }
      const lateReadA = deferred<AccountProfile>()
      const lateProfileWriteA = deferred<AccountProfile>()
      const latePasswordWriteA = deferred<void>()
      const pendingReadB = deferred<AccountProfile>()
      const profileRead = vi.spyOn(usersApi, 'profile').mockImplementation((token) => {
        if (token === 'delayed-tenant-a-token') {
          return operation === 'GET' ? lateReadA.promise : Promise.resolve(profile)
        }
        if (token === 'stable-tenant-b-token') return pendingReadB.promise
        throw new Error(`unexpected delayed profile token ${token}`)
      })
      const bindContact = vi.spyOn(usersApi, 'bindContact').mockImplementation((token) => {
        if (token === 'delayed-tenant-a-token' && operation === 'PATCH') return lateProfileWriteA.promise
        throw new Error(`unexpected delayed contact binding ${token}`)
      })
      const changePassword = vi.spyOn(usersApi, 'changePassword').mockImplementation((token) => {
        if (token === 'delayed-tenant-a-token' && operation === 'POST') return latePasswordWriteA.promise
        throw new Error(`unexpected delayed password change ${token}`)
      })
      const sessionA = setAccountSession({
        accessToken: 'delayed-tenant-a-token', displayName: 'Tenant A Session',
      })
      const tenantAOwner = JSON.stringify([
        sessionA.actor.scope_kind,
        sessionA.actor.scope_id,
        sessionA.actor.tenant_id,
        sessionA.actor.user_id,
        sessionA.sessionEpoch,
      ])
      const tenantAProfileMutationKey = ['account-profile-update', tenantAOwner] as const
      const tenantAPasswordMutationKey = ['account-password-change', tenantAOwner] as const
      const user = userEvent.setup()
      const { queryClient } = renderPageWithQueryClient(true)
      const serializedMutationCache = () => JSON.stringify(
        queryClient.getMutationCache().getAll().map((mutation) => ({
          mutationKey: mutation.options.mutationKey,
          variables: mutation.state.variables,
        })),
      )
      const ownerMutation = (key: readonly unknown[]) => queryClient.getMutationCache().getAll().find(
        (mutation) => JSON.stringify(mutation.options.mutationKey) === JSON.stringify(key),
      )

      if (operation === 'GET') {
        await waitFor(() => expect(profileRead).toHaveBeenCalledWith('delayed-tenant-a-token'))
        expect(screen.getByLabelText('个人资料加载中')).toBeInTheDocument()
      } else {
        const page = (await screen.findByRole('heading', { name: '个人资料' })).closest('.account-user-page') as HTMLElement
        if (operation === 'PATCH') {
          await user.click(within(page).getByRole('button', { name: '更换绑定' }))
          const bindForm = within(page.querySelector('.account-user-bind-form') as HTMLElement)
          await user.type(bindForm.getByLabelText('邮箱绑定'), 'delayed-a@example.com')
          await user.type(bindForm.getByLabelText('当前密码'), 'tenant-a-profile-password')
          await user.click(bindForm.getByRole('button', { name: '确定' }))
          await waitFor(() => expect(bindContact).toHaveBeenCalledOnce())
          expect(ownerMutation(tenantAProfileMutationKey)?.state.status).toBe('pending')
          expect(serializedMutationCache()).not.toContain('tenant-a-profile-password')
        } else {
          await user.click(within(page).getByRole('button', { name: '修改密码' }))
          await user.type(screen.getByLabelText('当前密码'), 'tenant-a-current-password')
          await user.type(screen.getByLabelText('新密码'), 'tenant-a-new-password')
          await user.type(screen.getByLabelText('确认密码'), 'tenant-a-new-password')
          await user.click(screen.getByRole('button', { name: '确定' }))
          await waitFor(() => expect(changePassword).toHaveBeenCalledOnce())
          expect(ownerMutation(tenantAPasswordMutationKey)?.state.status).toBe('pending')
          expect(serializedMutationCache()).not.toContain('tenant-a-current-password')
          expect(serializedMutationCache()).not.toContain('tenant-a-new-password')
        }
      }

      let sessionB!: ReturnType<typeof setAccountSession>
      act(() => {
        sessionB = setAccountSession({
          scopeID: '77777777-7777-4777-8777-777777777777',
          tenantID: '77777777-7777-4777-8777-777777777777',
          userID: profileB.id,
          displayName: 'Tenant B Session',
          accessToken: 'stable-tenant-b-token',
        })
      })
      expect(sessionB.sessionEpoch).not.toBe(sessionA.sessionEpoch)
      await waitFor(() => expect(profileRead).toHaveBeenCalledWith('stable-tenant-b-token'))
      expect(screen.getByLabelText('个人资料加载中')).toBeInTheDocument()
      expect(screen.queryByText('jason')).not.toBeInTheDocument()
      if (operation === 'POST') expect(ownerMutation(tenantAPasswordMutationKey)).toBeUndefined()
      if (operation === 'PATCH') expect(ownerMutation(tenantAProfileMutationKey)).toBeUndefined()

      await act(async () => pendingReadB.resolve(profileB))
      expect(await screen.findByText('stable-tenant-b')).toBeInTheDocument()

      const lateOperation = operation === 'GET'
        ? lateReadA
        : operation === 'PATCH'
          ? lateProfileWriteA
          : latePasswordWriteA
      await act(async () => {
        if (outcome === 'success') {
          if (operation === 'GET') lateReadA.resolve({ ...profile, username: 'late-tenant-a-read' })
          if (operation === 'PATCH') lateProfileWriteA.resolve({ ...profile, username: 'late-tenant-a-write', revision: 2 })
          if (operation === 'POST') latePasswordWriteA.resolve()
        } else {
          lateOperation.reject(new Error(`private late tenant A ${operation} error`))
        }
        await lateOperation.promise.catch(() => undefined)
        await Promise.resolve()
      })

      expect(queryClient.getQueryState(sessionB.queryKey)).toMatchObject({
        status: 'success', fetchStatus: 'idle', error: null, data: profileB,
      })
      expect(useSessionStore.getState().principal).toMatchObject({
        user_id: profileB.id, display_name: 'Tenant B Session',
      })
      expect(screen.getByRole('heading', { name: '个人资料' })).toBeInTheDocument()
      expect(screen.getByText('stable-tenant-b')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: '修改密码' })).toBeEnabled()
      expect(screen.getByRole('button', { name: '更换绑定' })).toBeEnabled()
      expect(screen.queryByText(/late-tenant-a|private late tenant A/)).not.toBeInTheDocument()
      expect(screen.queryByText('个人资料已保存')).not.toBeInTheDocument()
      expect(screen.queryByText('密码修改成功，请重新登录')).not.toBeInTheDocument()
    },
  )

  it('validates the bound email and phone before sending a contact write', async () => {
    await changeLocale('zh-CN')
    authenticate()
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    const bindContact = vi.spyOn(usersApi, 'bindContact')
    const user = userEvent.setup()
    renderWithProviders(<AccountUserPage />, ['/account/user'])
    const page = (await screen.findByRole('heading', { name: '个人资料' })).closest('.account-user-page') as HTMLElement

    await user.click(within(page).getByRole('button', { name: '更换绑定' }))
    let bindForm = within(page.querySelector('.account-user-bind-form') as HTMLElement)
    await user.type(bindForm.getByLabelText('邮箱绑定'), 'invalid-email')
    await user.click(bindForm.getByRole('button', { name: '确定' }))
    expect(await bindForm.findByText('请输入当前密码')).toBeInTheDocument()
    await user.type(bindForm.getByLabelText('当前密码'), 'current-password')
    await user.click(bindForm.getByRole('button', { name: '确定' }))
    expect(await bindForm.findByText('邮箱格式不正确')).toBeInTheDocument()

    await user.click(within(page).getByRole('button', { name: '立即绑定' }))
    bindForm = within(page.querySelector('.account-user-bind-form') as HTMLElement)
    await user.type(bindForm.getByLabelText('手机绑定'), 'invalid-phone')
    await user.type(bindForm.getByLabelText('当前密码'), 'current-password')
    await user.click(bindForm.getByRole('button', { name: '确定' }))
    expect(await bindForm.findByText('手机号应为 6 到 20 位数字')).toBeInTheDocument()
    expect(bindContact).not.toHaveBeenCalled()
  })

  it('binds a contact with the current password and never caches the secret', async () => {
    await changeLocale('zh-CN')
    authenticate()
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    const bindContact = vi.spyOn(usersApi, 'bindContact').mockResolvedValue({ ...profile, email: 'new@example.com', revision: 2 })
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()
    const page = (await screen.findByRole('heading', { name: '个人资料' })).closest('.account-user-page') as HTMLElement

    await user.click(within(page).getByRole('button', { name: '更换绑定' }))
    const bindForm = within(page.querySelector('.account-user-bind-form') as HTMLElement)
    const secret = 'profile-current-password'
    await user.type(bindForm.getByLabelText('邮箱绑定'), 'new@example.com')
    await user.type(bindForm.getByLabelText('当前密码'), secret)
    await user.click(bindForm.getByRole('button', { name: '确定' }))

    await waitFor(() => expect(bindContact).toHaveBeenCalledOnce())
    expect(bindContact.mock.calls[0]![1]).toEqual({
      expected_revision: 1, display_name: 'Jason', email: 'new@example.com', current_password: secret,
    })
    await screen.findByText('个人资料已保存')
    expect(page.querySelector('.account-user-bind-form')).toBeNull()
    const serializedCaches = JSON.stringify({
      queries: queryClient.getQueryCache().getAll().map((query) => query.state.data),
      mutations: queryClient.getMutationCache().getAll().map((mutation) => mutation.state.variables),
    })
    expect(serializedCaches).not.toContain(secret)
    expect(document.body).not.toHaveTextContent(secret)
  })

  it('maps a wrong contact reauthentication password locally and clears the secret', async () => {
    await changeLocale('zh-CN')
    authenticate()
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    const bindContact = vi.spyOn(usersApi, 'bindContact').mockRejectedValue(
      new ApiError('private password hash detail', 401, 'invalid_credentials'),
    )
    const user = userEvent.setup()
    const { queryClient } = renderPageWithQueryClient()
    const page = (await screen.findByRole('heading', { name: '个人资料' })).closest('.account-user-page') as HTMLElement

    await user.click(within(page).getByRole('button', { name: '立即绑定' }))
    const bindForm = within(page.querySelector('.account-user-bind-form') as HTMLElement)
    const secret = 'wrong-profile-password'
    await user.type(bindForm.getByLabelText('手机绑定'), '+8613900000000')
    await user.type(bindForm.getByLabelText('当前密码'), secret)
    await user.click(bindForm.getByRole('button', { name: '确定' }))

    expect(await screen.findByText('当前密码不正确')).toBeInTheDocument()
    // fp-role ID-05：错误标在展开表单的当前密码项上，表单保持展开。
    expect(bindForm.getByText('当前密码不正确')).toBeInTheDocument()
    expect(screen.queryByText('private password hash detail')).not.toBeInTheDocument()
    expect(bindForm.getByLabelText('当前密码')).toHaveValue('')
    expect(JSON.stringify(queryClient.getMutationCache().getAll().map((mutation) => mutation.state.variables))).not.toContain(secret)
    expect(bindContact).toHaveBeenCalledOnce()
  })

  // fp-role ID-05：号码已被占用（服务端 validation_error）标在手机输入框上，输入保留，不当成登录失效。
  it('marks an unavailable phone number on the bind form instead of a global error', async () => {
    await changeLocale('zh-CN')
    authenticate()
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    vi.spyOn(usersApi, 'bindContact').mockRejectedValue(new ApiError('request fields are invalid', 400, 'validation_error'))
    const user = userEvent.setup()
    renderPageWithQueryClient()
    const page = (await screen.findByRole('heading', { name: '个人资料' })).closest('.account-user-page') as HTMLElement

    await user.click(within(page).getByRole('button', { name: '立即绑定' }))
    const bindForm = within(page.querySelector('.account-user-bind-form') as HTMLElement)
    await user.type(bindForm.getByLabelText('手机绑定'), '+8613900000000')
    await user.type(bindForm.getByLabelText('当前密码'), 'profile-password')
    await user.click(bindForm.getByRole('button', { name: '确定' }))

    expect(await bindForm.findByText('该手机号无法绑定：格式不正确或已被其他账号使用')).toBeInTheDocument()
    expect(bindForm.getByLabelText('手机绑定')).toHaveValue('+8613900000000')
    expect(bindForm.getByLabelText('当前密码')).toHaveValue('')
    expect(screen.queryByText('资料校验失败，请检查输入')).not.toBeInTheDocument()
  })

  it('requires matching new passwords before submitting', async () => {
    await changeLocale('zh-CN')
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(profileResponse())
    const user = userEvent.setup()
    renderWithProviders(<AccountUserPage />, ['/account/user'])

    await user.click(await screen.findByRole('button', { name: '修改密码' }))
    await user.type(screen.getByLabelText('当前密码'), 'current-password')
    await user.type(screen.getByLabelText('新密码'), 'new-password-123')
    await user.type(screen.getByLabelText('确认密码'), 'different-password')
    await user.click(screen.getByRole('button', { name: '确定' }))

    expect(await screen.findByText('两次输入的密码不一致')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0)
  })

  it('clears all local session state and returns to login after changing password', async () => {
    await changeLocale('zh-CN')
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url) === '/v1/account/password' && init?.method === 'POST') {
        return new Response(null, { status: 204 })
      }
      return profileResponse()
    })
    const user = userEvent.setup()
    renderWithProviders(<AppRoutes />, ['/account/user'])

    await user.click(await screen.findByRole('button', { name: '修改密码' }))
    await user.type(screen.getByLabelText('当前密码'), 'current-password')
    await user.type(screen.getByLabelText('新密码'), 'new-password-123')
    await user.type(screen.getByLabelText('确认密码'), 'new-password-123')
    await user.click(screen.getByRole('button', { name: '确定' }))

    expect(await screen.findByText('密码修改成功，请重新登录')).toBeInTheDocument()
    expect(useSessionStore.getState()).toMatchObject({
      status: 'anonymous',
      principal: null,
      accessToken: null,
    })
    const passwordCall = fetchSpy.mock.calls.find(([url]) => String(url) === '/v1/account/password')
    expect(JSON.parse(String(passwordCall?.[1]?.body))).toEqual({
      current_password: 'current-password', new_password: 'new-password-123',
    })
  })

  it('derives the login security badge from the real MFA status and expands the MFA panel', async () => {
    await changeLocale('zh-CN')
    authenticate()
    vi.spyOn(usersApi, 'profile').mockResolvedValue({ ...profile, phone: '+8613800000000' })
    const getStatus = vi.spyOn(mfaApi, 'getStatus').mockResolvedValue({
      status: 'active', credential_id: '99999999-9999-4999-8999-999999999999', method: 'totp',
    })
    const user = userEvent.setup()
    renderWithProviders(<AccountUserPage />, ['/account/user'])
    const page = (await screen.findByRole('heading', { name: '个人资料' })).closest('.account-user-page') as HTMLElement
    const rows = [...page.querySelectorAll('.account-user-check')]

    await waitFor(() => expect(rows[3]).toHaveTextContent('已设置'))
    expect(rows[1]).toHaveTextContent('已绑定')
    expect(within(page).getAllByRole('button', { name: '更换绑定' })).toHaveLength(2)
    const setup = within(page).getByRole('button', { name: '立即设置' })
    expect(setup).toHaveAttribute('aria-expanded', 'false')
    await user.click(setup)
    expect(setup).toHaveAttribute('aria-expanded', 'true')
    expect(await within(page.querySelector('.account-user-mfa-form') as HTMLElement).findByText('当前账户已启用 TOTP 多因素认证。'))
      .toBeInTheDocument()
    await user.click(setup)
    expect(page.querySelector('.account-user-mfa-form')).toBeNull()
    await waitFor(() => expect(getStatus.mock.calls.length).toBeGreaterThanOrEqual(2))
  })

  it('opens the tenant identity verification page from the real-name row when permitted', async () => {
    await changeLocale('zh-CN')
    setAccountSession({
      permissions: ['identity.self.read', 'identity.self.update', 'identity_verification.self.manage'],
    })
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    vi.spyOn(mfaApi, 'getStatus').mockResolvedValue({ status: 'inactive' })
    vi.spyOn(identityVerificationApi, 'getStatus').mockResolvedValue({ status: 'unverified' })
    const user = userEvent.setup()
    renderWithProviders(
      <Routes>
        <Route path="/account/user" element={<AccountUserPage />} />
        <Route path="/account/verification" element={<p>verification-route</p>} />
      </Routes>,
      ['/account/user'],
    )

    await user.click(await screen.findByRole('button', { name: '立即认证' }))
    expect(await screen.findByText('verification-route')).toBeInTheDocument()
  })

  it.each([
    ['unverified', '未认证', '请尽快完成实名认证，否则可能会影响部分功能使用。', true, 'is-warn'],
    ['pending', '审核中', '实名认证资料已提交，正在审核中', true, 'is-warn'],
    ['rejected', '被驳回', '实名认证未通过，请检查资料后重新提交', true, 'is-warn'],
    ['verified', '已认证', '您已完成实名认证', false, 'is-ok'],
  ] as const)('derives the real-name badge from the own %s status', async (status, badge, description, verifyVisible, tone) => {
    await changeLocale('zh-CN')
    setAccountSession({
      permissions: ['identity.self.read', 'identity.self.update', 'identity_verification.self.manage'],
    })
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    vi.spyOn(mfaApi, 'getStatus').mockResolvedValue({ status: 'inactive' })
    const getStatus = vi.spyOn(identityVerificationApi, 'getStatus').mockResolvedValue(
      status === 'verified'
        ? { status, verified_at: '2026-07-22T08:00:00Z' }
        : { status },
    )

    renderWithProviders(<AccountUserPage />, ['/account/user'])
    const page = (await screen.findByRole('heading', { name: '个人资料' })).closest('.account-user-page') as HTMLElement
    const realName = page.querySelectorAll('.account-user-check')[0] as HTMLElement

    expect(await within(realName).findByText(badge)).toHaveClass('account-user-status', tone)
    expect(realName).toHaveTextContent(description)
    expect(within(realName).queryByRole('button', { name: '立即认证' }) !== null).toBe(verifyVisible)
    expect(getStatus).toHaveBeenCalledWith('memory-only-access-token', expect.any(AbortSignal))
  })

  it.each([
    ['tenant without real-name permission', () => setAccountSession()],
    ['platform account', () => setAccountSession({
      kind: 'platform',
      permissions: ['identity.self.read', 'identity.self.update', 'identity_verification.self.manage'],
    })],
  ])('shows no guessed real-name badge and reads no status for a %s', async (_case, setup) => {
    await changeLocale('zh-CN')
    setup()
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    vi.spyOn(mfaApi, 'getStatus').mockResolvedValue({ status: 'inactive' })
    const getStatus = vi.spyOn(identityVerificationApi, 'getStatus')

    renderWithProviders(<AccountUserPage />, ['/account/user'])
    const page = (await screen.findByRole('heading', { name: '个人资料' })).closest('.account-user-page') as HTMLElement
    const realName = page.querySelectorAll('.account-user-check')[0] as HTMLElement
    await waitFor(() => expect(page.querySelectorAll('.account-user-check')[3]).toHaveTextContent('未设置'))

    expect(realName.querySelector('.account-user-status')).toBeNull()
    expect(realName).toHaveTextContent('实名认证未开放')
    expect(realName).not.toHaveTextContent('请尽快完成实名认证')
    expect(within(realName).queryByRole('button', { name: '立即认证' })).toBeNull()
    expect(getStatus).not.toHaveBeenCalled()
  })

  it('shows real-name verification as not available when the runtime is not mounted (404)', async () => {
    await changeLocale('zh-CN')
    setAccountSession({
      permissions: ['identity.self.read', 'identity.self.update', 'identity_verification.self.manage'],
    })
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    vi.spyOn(mfaApi, 'getStatus').mockResolvedValue({ status: 'inactive' })
    const getStatus = vi.spyOn(identityVerificationApi, 'getStatus')
      .mockRejectedValue(new ApiError('API request failed', 404, 'request_failed'))

    renderWithProviders(<AccountUserPage />, ['/account/user'])
    const page = (await screen.findByRole('heading', { name: '个人资料' })).closest('.account-user-page') as HTMLElement
    const realName = page.querySelectorAll('.account-user-check')[0] as HTMLElement

    await waitFor(() => expect(getStatus).toHaveBeenCalledOnce())
    await waitFor(() => expect(realName).toHaveTextContent('实名认证未开放'))
    expect(realName).not.toHaveTextContent('请尽快完成实名认证')
    expect(realName.querySelector('.account-user-status')).toBeNull()
    expect(within(realName).queryByRole('button', { name: '立即认证' })).toBeNull()
  })

  it('hides the real-name badge when the status read fails instead of guessing', async () => {
    await changeLocale('zh-CN')
    setAccountSession({
      permissions: ['identity.self.read', 'identity.self.update', 'identity_verification.self.manage'],
    })
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    vi.spyOn(mfaApi, 'getStatus').mockResolvedValue({ status: 'inactive' })
    const getStatus = vi.spyOn(identityVerificationApi, 'getStatus')
      .mockRejectedValue(new ApiError('unavailable', 503, 'identity_verification_unavailable'))

    renderWithProviders(<AccountUserPage />, ['/account/user'])
    const page = (await screen.findByRole('heading', { name: '个人资料' })).closest('.account-user-page') as HTMLElement
    const realName = page.querySelectorAll('.account-user-check')[0] as HTMLElement

    await waitFor(() => expect(getStatus).toHaveBeenCalledOnce())
    expect(realName.querySelector('.account-user-status')).toBeNull()
    expect(within(realName).getByRole('button', { name: '立即认证' })).toBeEnabled()
  })

  it('renders profile permission denial', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: { code: 'permission_denied', message: 'permission is required' } }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderWithProviders(<AccountUserPage />, ['/account/user'])

    expect(await screen.findByText('无权查看个人资料')).toBeInTheDocument()
  })
})
