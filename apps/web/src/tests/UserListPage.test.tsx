import { onlineManager, QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CdncaProvider } from '@cdnca/ui'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import { impersonationApi } from '../api/impersonation'
import { mfaApi } from '../api/mfa'
import { usersApi, type ManagedUser, type PlatformAdministratorUser, type UserGroup, type UserListResponse } from '../api/users'
import { useSessionStore } from '../auth/session'
import UserListPage from '../pages/UserListPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import baseStylesRaw from '../styles.css?raw'

// antd 测试环境所有 Modal 的 aria-labelledby 都是 test-id，可访问名取的是 DOM 里第一个 test-id（常是反馈弹窗标题）；
// 业务弹窗按自身标题匹配，并排除反馈弹窗（.cdnca-feedback）
const pageDialogs = (name?: string) => screen.queryAllByRole('dialog')
  .filter((element) => !element.classList.contains('cdnca-feedback'))
  .filter((element) => name === undefined || element.querySelector('.ant-modal-title, .ant-drawer-title')?.textContent?.trim() === name)
const pageDialog = (name: string) => { const [element] = pageDialogs(name); if (!element) throw new Error(`no dialog ${name}`); return element }

// 结果未知改为 OutcomeUnknown 后，弹窗标题与原位恢复条（或表单内 Alert）同文案；断言原位提示
const OUTCOME_BAR = '.ant-alert-message'

const managedUser: ManagedUser = {
  id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  display_id: '1',
  scope_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  tenant_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  username: 'alice',
  display_name: 'Alice',
  email: 'alice@example.com',
  phone: '+8613800000000',
  status: 'active',
  role: 'tenant_owner',
  group_id: null,
  group_name: null,
  metadata: { remark: null, qq: null },
  revision: 1,
  created_at: '2026-07-22T08:00:00Z',
  updated_at: '2026-07-22T08:00:00Z',
}

const managedGroup: UserGroup = {
  id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  scope_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  name: '运维组',
  revision: 1,
  member_count: 0,
  created_at: '2026-07-22T08:00:00Z',
  updated_at: '2026-07-22T08:00:00Z',
}

function listData(
  items = [managedUser],
  total = items.length,
  page = 1,
  limit = 10,
): UserListResponse {
  return { items, page, limit, total }
}

function listResponse(items = [managedUser], total = items.length, page = 1, limit = 10): Response {
  const body = listData(items.map((item) => ({
    ...item, verification: { personal_verified: false, company_verified: false },
  })), total, page, limit)
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function authenticateAdmin() {
  const admin = principal({
    scope_kind: 'platform',
    tenant_id: null,
    username: 'admin',
    display_name: 'admin',
    roles: ['platform_admin'],
    permissions: ['identity.users.manage', 'identity.impersonation.manage'],
  })
  useSessionStore.getState().setSession(authResponse(admin), admin)
}

function renderUsersWithQueryClient(queryClient: QueryClient) {
  return render(
    // 与各端一致挂 CdncaProvider：错误反馈走 FeedbackProvider 弹窗
    <CdncaProvider>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/sys/user']}>
          <UserListPage />
        </MemoryRouter>
      </QueryClientProvider>
    </CdncaProvider>,
  )
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((next, fail) => {
    resolve = next
    reject = fail
  })
  return { promise, reject, resolve }
}

function ownerTuple(actor: ReturnType<typeof principal>, sessionEpoch: number) {
  return ['platform', actor.scope_id, null, actor.user_id, sessionEpoch] as const
}

function LocationProbe() {
  const location = useLocation()
  return <div>{`${location.pathname}${location.search}`}</div>
}

function expectMutationCacheNotToContain(queryClient: QueryClient, value: string) {
  const mutations = queryClient.getMutationCache().getAll()
  expect(mutations.length).toBeGreaterThan(0)
  for (const mutation of mutations) {
    expect(JSON.stringify(mutation.state.variables) ?? '').not.toContain(value)
    expect(JSON.stringify(mutation.state.data) ?? '').not.toContain(value)
  }
}

describe('UserListPage', () => {
  beforeEach(() => {
    vi.spyOn(usersApi, 'getLoginSecurity').mockImplementation(async (_token, userID, scopeID) => ({
      user_id: userID, tenant_scope_id: scopeID, revision: 0,
      login_verification: 'none', login_allowlist: [],
    }))
    vi.spyOn(usersApi, 'getSecondaryVerification').mockImplementation(async (_token, userID, scopeID) => ({
      user_id: userID, tenant_scope_id: scopeID, revision: 0, enabled: false, deadline: null,
      expiry_action: 'none', requested_at: null, completed: false, enforced_at: null,
    }))
  })

  it('fix-livefilter: 用户名边输入边生效，停止输入 400ms 后只查一次，并写进 URL', async () => {
    authenticateAdmin()
    const list = vi.spyOn(usersApi, 'list').mockResolvedValue(listData([managedUser]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    let search = ''
    function Location() { search = useLocation().search; return null }
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><CdncaProvider>
      <MemoryRouter initialEntries={['/sys/user']}><Routes><Route path="/sys/user" element={<><UserListPage /><Location /></>} /></Routes></MemoryRouter>
    </CdncaProvider></QueryClientProvider>)
    await waitFor(() => expect(list).toHaveBeenCalledTimes(1))
    const box = screen.getByLabelText('搜索用户')
    for (const value of ['a', 'al', 'ali']) fireEvent.change(box, { target: { value } })
    await new Promise((resolve) => setTimeout(resolve, 200))
    expect(list).toHaveBeenCalledTimes(1)
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2), { timeout: 1500 })
    expect(list.mock.calls[1]![1]).toMatchObject({ username: 'ali' })
    await new Promise((resolve) => setTimeout(resolve, 500))
    expect(list).toHaveBeenCalledTimes(2)
    expect(new URLSearchParams(search).get('username')).toBe('ali')
  })

  it('W1: ?display_id= from the site list owner link filters the list to that user', async () => {
    authenticateAdmin()
    const list = vi.spyOn(usersApi, 'list').mockResolvedValue(listData([managedUser]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    renderWithProviders(<UserListPage />, ['/sys/user?display_id=2'])
    await waitFor(() => expect(list).toHaveBeenCalled())
    expect(list.mock.calls[0]![1]).toMatchObject({ display_id: '2' })
  })

  it('enables secondary verification with a deadline and site lock through its own endpoint (FX57)', async () => {
    authenticateAdmin()
    const account = { ...managedUser, metadata: { remark: null, qq: null } }
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData([account]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const update = vi.spyOn(usersApi, 'update')
    const saveSecurity = vi.spyOn(usersApi, 'updateLoginSecurity')
    const save = vi.spyOn(usersApi, 'updateSecondaryVerification').mockImplementation(async (_token, userID, scopeID, input) => ({
      user_id: userID, tenant_scope_id: scopeID, revision: 1, enabled: true, deadline: input.deadline,
      expiry_action: input.expiry_action, requested_at: '2026-10-17T00:00:00Z', completed: false, enforced_at: null,
    }))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />)
    await user.click(await screen.findByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑用户' })
    await user.click(within(dialog).getByRole('tab', { name: '实名信息' }))
    const statusSwitch = within(dialog).getByRole('switch', { name: '认证状态' })
    expect(statusSwitch).toBeDisabled()
    const toggles = within(dialog).getAllByRole('switch').filter((item) => !item.hasAttribute('disabled'))
    await user.click(toggles[0])
    fireEvent.change(within(dialog).getByLabelText('截止时间'), { target: { value: '2026-11-01 12:00:00' } })
    await user.click(within(dialog).getByRole('radio', { name: '锁定网站' }).closest('label')!)
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(save).toHaveBeenCalledOnce())
    expect(save).toHaveBeenCalledWith(expect.any(String), account.id, account.scope_id, {
      expected_revision: 0, enabled: true, deadline: new Date(2026, 10, 1, 12, 0, 0).toISOString().replace(/\.\d{3}Z$/, 'Z'),
      expiry_action: 'lock_sites',
    }, expect.any(Object))
    expect(update).not.toHaveBeenCalled()
    expect(saveSecurity).not.toHaveBeenCalled()
    expect(await screen.findByText('用户更新成功')).toBeInTheDocument()
  })

  it('rejects lock-sites without a deadline before saving secondary verification', async () => {
    authenticateAdmin()
    const account = { ...managedUser, metadata: { remark: null, qq: null } }
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData([account]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const save = vi.spyOn(usersApi, 'updateSecondaryVerification')
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />)
    await user.click(await screen.findByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑用户' })
    await user.click(within(dialog).getByRole('tab', { name: '实名信息' }))
    const toggles = within(dialog).getAllByRole('switch').filter((item) => !item.hasAttribute('disabled'))
    await user.click(toggles[0])
    await user.click(within(dialog).getByRole('radio', { name: '锁定网站' }).closest('label')!)
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('选择“锁定网站”时必须填写截止时间')).toBeInTheDocument()
    expect(save).not.toHaveBeenCalled()
  })

  it('reads and clears the selected user login security without rewriting unchanged profile fields', async () => {
    authenticateAdmin()
    const account = { ...managedUser, metadata: { remark: null, qq: null } }
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData([account]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    vi.mocked(usersApi.getLoginSecurity).mockResolvedValue({
      user_id: account.id, tenant_scope_id: account.scope_id, revision: 4,
      login_verification: 'email', login_allowlist: ['192.0.2.1', '2001:db8::1'],
    })
    const update = vi.spyOn(usersApi, 'update')
    const save = vi.spyOn(usersApi, 'updateLoginSecurity').mockResolvedValue({
      user_id: account.id, tenant_scope_id: account.scope_id, revision: 5,
      login_verification: 'none', login_allowlist: [],
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />)
    await user.click(await screen.findByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑用户' })
    await user.click(within(dialog).getByRole('tab', { name: '登录安全' }))
    expect(within(dialog).getByRole('radio', { name: '邮件' })).toBeChecked()
    expect(within(dialog).getByLabelText('登录白名单')).toHaveValue('192.0.2.1 2001:db8::1')
    await user.click(within(dialog).getByRole('radio', { name: '无' }).closest('label')!)
    await user.clear(within(dialog).getByLabelText('登录白名单'))
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(save).toHaveBeenCalledOnce())
    expect(save).toHaveBeenCalledWith(expect.any(String), account.id, account.scope_id, {
      expected_revision: 4, login_verification: 'none', login_allowlist: [],
    }, expect.any(Object))
    expect(update).not.toHaveBeenCalled()
    expect(await screen.findByText('用户更新成功')).toBeInTheDocument()
  })

  it('retries only the unknown security write after profile save and never reports partial success as complete', async () => {
    authenticateAdmin()
    const account = { ...managedUser, metadata: { remark: null, qq: null } }
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData([account]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const update = vi.spyOn(usersApi, 'update').mockResolvedValue({ ...account, revision: 2, email: 'new@example.com' })
    const save = vi.spyOn(usersApi, 'updateLoginSecurity')
      .mockRejectedValueOnce(new ApiError('network', 0, 'network_error'))
      .mockResolvedValue({ user_id: account.id, tenant_scope_id: account.scope_id, revision: 1,
        login_verification: 'email', login_allowlist: ['192.0.2.1'] })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />)
    await user.click(await screen.findByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑用户' })
    await user.clear(within(dialog).getByLabelText('邮箱'))
    await user.type(within(dialog).getByLabelText('邮箱'), 'new@example.com')
    await user.click(within(dialog).getByRole('tab', { name: '登录安全' }))
    await user.click(within(dialog).getByRole('radio', { name: '邮件' }).closest('label')!)
    await user.type(within(dialog).getByLabelText('登录白名单'), '192.0.2.1')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('用户资料已保存，登录安全或二次实名尚未确认保存。请重试或关闭后重新读取。')).toBeInTheDocument()
    expect(screen.queryByText('用户更新成功')).not.toBeInTheDocument()
    expect(within(dialog).getByLabelText('登录白名单')).toBeDisabled()
    await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('用户更新成功')).toBeInTheDocument()
    expect(update).toHaveBeenCalledOnce()
    expect(save).toHaveBeenCalledTimes(2)
    expect(save.mock.calls[1]).toEqual(save.mock.calls[0])
  })

  it.each(['unknown', 'rejected'] as const)('recovers a %s login security save after creating the user exactly once', async (outcome) => {
    authenticateAdmin()
    const account = { ...managedUser, username: 'new-user', display_name: 'new-user', email: 'new@example.com', phone: null }
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const create = vi.spyOn(usersApi, 'create').mockResolvedValue(account)
    const update = vi.spyOn(usersApi, 'update')
    const reset = vi.spyOn(usersApi, 'resetPassword')
    const save = vi.spyOn(usersApi, 'updateLoginSecurity')
      .mockRejectedValueOnce(outcome === 'unknown'
        ? new ApiError('network', 0, 'network_error')
        : new ApiError('disabled', 403, 'account_login_method_disabled'))
      .mockResolvedValue({ user_id: account.id, tenant_scope_id: account.scope_id, revision: 1,
        login_verification: outcome === 'unknown' ? 'email' : 'none', login_allowlist: ['192.0.2.1'] })
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    const user = userEvent.setup({ delay: null })
    renderUsersWithQueryClient(queryClient)
    await user.click(await screen.findByRole('button', { name: '新增用户' }))
    const dialog = await screen.findByRole('dialog', { name: '新增用户' })
    await user.type(within(dialog).getByLabelText('用户名'), account.username)
    await user.type(within(dialog).getByLabelText('密码'), 'test-only-new-user-password')
    await user.type(within(dialog).getByLabelText('邮箱'), account.email)
    await user.click(within(dialog).getByRole('tab', { name: '登录安全' }))
    await user.click(within(dialog).getByRole('radio', { name: '邮件' }).closest('label')!)
    await user.type(within(dialog).getByLabelText('登录白名单'), '192.0.2.1')
    // Cancel on the left, OK on the right: DOM order is kept (no row-reverse on the footer).
    expect(Array.from(dialog.querySelectorAll('.ant-modal-footer .ant-btn')).map((button) => button.textContent?.trim()))
      .toEqual(['关闭', '确定'])
    expect(baseStylesRaw).not.toMatch(/\.user-form-modal \.ant-modal-footer\s*\{[^}]*row-reverse/)
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('用户资料已保存，登录安全或二次实名尚未确认保存。请重试或关闭后重新读取。')).toBeInTheDocument()
    expect(screen.queryByText('用户创建成功')).not.toBeInTheDocument()
    expectMutationCacheNotToContain(queryClient, 'test-only-new-user-password')
    if (outcome === 'unknown') {
      await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
    } else {
      await user.click(within(dialog).getByRole('tab', { name: '基础信息' }))
      expect(within(dialog).getByLabelText('密码')).toHaveValue('')
      await user.click(within(dialog).getByRole('tab', { name: '登录安全' }))
      await user.click(within(dialog).getByRole('radio', { name: '无' }).closest('label')!)
      await user.click(within(dialog).getByRole('button', { name: '确定' }))
    }
    expect(await screen.findByText(outcome === 'unknown' ? '用户创建成功' : '用户更新成功')).toBeInTheDocument()
    expect(create).toHaveBeenCalledOnce()
    expect(update).not.toHaveBeenCalled()
    expect(reset).not.toHaveBeenCalled()
    expect(save).toHaveBeenCalledTimes(2)
    expect(save.mock.calls[1].slice(1, 3)).toEqual([account.id, account.scope_id])
    if (outcome === 'unknown') expect(save.mock.calls[1]).toEqual(save.mock.calls[0])
    else expect(save.mock.calls[1][4].idempotencyKey).not.toBe(save.mock.calls[0][4].idempotencyKey)
  })

  it('creates a tenant user and then requests secondary verification for it at revision 0 (FX57)', async () => {
    authenticateAdmin()
    const account = { ...managedUser, username: 'new-user', display_name: 'new-user', email: 'new@example.com', phone: null }
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const create = vi.spyOn(usersApi, 'create').mockResolvedValue(account)
    const saveSecurity = vi.spyOn(usersApi, 'updateLoginSecurity')
    const save = vi.spyOn(usersApi, 'updateSecondaryVerification').mockImplementation(async (_token, userID, scopeID, input) => ({
      user_id: userID, tenant_scope_id: scopeID, revision: 1, enabled: true, deadline: input.deadline,
      expiry_action: input.expiry_action, requested_at: '2026-10-17T00:00:00Z', completed: false, enforced_at: null,
    }))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />)
    await user.click(await screen.findByRole('button', { name: '新增用户' }))
    const dialog = await screen.findByRole('dialog', { name: '新增用户' })
    await user.type(within(dialog).getByLabelText('用户名'), account.username)
    await user.type(within(dialog).getByLabelText('密码'), 'test-only-new-user-password')
    await user.type(within(dialog).getByLabelText('邮箱'), account.email)
    await user.click(within(dialog).getByRole('tab', { name: '实名信息' }))
    const toggles = within(dialog).getAllByRole('switch').filter((item) => !item.hasAttribute('disabled'))
    await user.click(toggles[0])
    fireEvent.change(within(dialog).getByLabelText('截止时间'), { target: { value: '2026-11-01 12:00:00' } })
    await user.click(within(dialog).getByRole('radio', { name: '锁定网站' }).closest('label')!)
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('用户创建成功')).toBeInTheDocument()
    expect(within(dialog).queryByText('这些资料暂不能保存')).not.toBeInTheDocument()
    expect(create).toHaveBeenCalledOnce()
    expect(saveSecurity).not.toHaveBeenCalled()
    expect(save).toHaveBeenCalledOnce()
    expect(save).toHaveBeenCalledWith(expect.any(String), account.id, account.scope_id, {
      expected_revision: 0, enabled: true, deadline: new Date(2026, 10, 1, 12, 0, 0).toISOString().replace(/\.\d{3}Z$/, 'Z'),
      expiry_action: 'lock_sites',
    }, expect.any(Object))
  })

  it('does not send secondary verification when creating a user with it left off', async () => {
    authenticateAdmin()
    const account = { ...managedUser, username: 'new-user', display_name: 'new-user', email: 'new@example.com', phone: null }
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const create = vi.spyOn(usersApi, 'create').mockResolvedValue(account)
    const save = vi.spyOn(usersApi, 'updateSecondaryVerification')
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />)
    await user.click(await screen.findByRole('button', { name: '新增用户' }))
    const dialog = await screen.findByRole('dialog', { name: '新增用户' })
    await user.type(within(dialog).getByLabelText('用户名'), account.username)
    await user.type(within(dialog).getByLabelText('密码'), 'test-only-new-user-password')
    await user.type(within(dialog).getByLabelText('邮箱'), account.email)
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('用户创建成功')).toBeInTheDocument()
    expect(create).toHaveBeenCalledOnce()
    expect(save).not.toHaveBeenCalled()
  })

  // fix-fielderr-be: a refused email is marked under 邮箱, without the alert.
  it('marks a server-refused user field in place', async () => {
    authenticateAdmin()
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    vi.spyOn(usersApi, 'create').mockRejectedValueOnce(Object.assign(
      new ApiError('API request failed', 400, 'validation_error', 'req-user'), { field: 'email', reason: 'invalid_format' }))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />)
    await user.click(await screen.findByRole('button', { name: '新增用户' }))
    const dialog = await screen.findByRole('dialog', { name: '新增用户' })
    await user.type(within(dialog).getByLabelText('用户名'), 'new-user')
    await user.type(within(dialog).getByLabelText('密码'), 'test-only-new-user-password')
    await user.type(within(dialog).getByLabelText('邮箱'), 'new@example.com')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('格式不正确')).toBeInTheDocument()
    expect(dialog.querySelector('.identity-alert.ant-alert-error')).toBeNull()
  })

  it('resubmits only the rejected secondary verification after creating the user and saving login security', async () => {
    authenticateAdmin()
    const account = { ...managedUser, username: 'new-user', display_name: 'new-user', email: 'new@example.com', phone: null }
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const create = vi.spyOn(usersApi, 'create').mockResolvedValue(account)
    const update = vi.spyOn(usersApi, 'update')
    const saveSecurity = vi.spyOn(usersApi, 'updateLoginSecurity').mockResolvedValue({
      user_id: account.id, tenant_scope_id: account.scope_id, revision: 1, login_verification: 'email', login_allowlist: [] })
    const save = vi.spyOn(usersApi, 'updateSecondaryVerification')
      .mockRejectedValueOnce(new ApiError('invalid', 400, 'validation_error'))
      .mockImplementation(async (_token, userID, scopeID, input) => ({
        user_id: userID, tenant_scope_id: scopeID, revision: 1, enabled: true, deadline: input.deadline,
        expiry_action: input.expiry_action, requested_at: '2026-10-17T00:00:00Z', completed: false, enforced_at: null,
      }))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />)
    await user.click(await screen.findByRole('button', { name: '新增用户' }))
    const dialog = await screen.findByRole('dialog', { name: '新增用户' })
    await user.type(within(dialog).getByLabelText('用户名'), account.username)
    await user.type(within(dialog).getByLabelText('密码'), 'test-only-new-user-password')
    await user.type(within(dialog).getByLabelText('邮箱'), account.email)
    await user.click(within(dialog).getByRole('tab', { name: '实名信息' }))
    await user.click(within(dialog).getAllByRole('switch').filter((item) => !item.hasAttribute('disabled'))[0])
    await user.click(within(dialog).getByRole('tab', { name: '登录安全' }))
    await user.click(within(dialog).getByRole('radio', { name: '邮件' }).closest('label')!)
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('用户资料已保存，登录安全或二次实名尚未确认保存。请重试或关闭后重新读取。')).toBeInTheDocument()
    expect(screen.queryByText('用户创建成功')).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('用户更新成功')).toBeInTheDocument()
    expect(within(dialog).queryByText('这些资料暂不能保存')).not.toBeInTheDocument()
    expect(create).toHaveBeenCalledOnce()
    expect(update).not.toHaveBeenCalled()
    expect(saveSecurity).toHaveBeenCalledOnce()
    expect(save).toHaveBeenCalledTimes(2)
    expect(save.mock.calls[1].slice(1, 4)).toEqual([account.id, account.scope_id,
      { expected_revision: 0, enabled: true, deadline: null, expiry_action: 'none' }])
    expect(save.mock.calls[1][4].idempotencyKey).not.toBe(save.mock.calls[0][4].idempotencyKey)
  })

  it('does not replace an unread security policy with default values when loading fails', async () => {
    authenticateAdmin()
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData([{ ...managedUser, metadata: { remark: null, qq: null } }]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    vi.mocked(usersApi.getLoginSecurity).mockRejectedValue(new ApiError('unavailable', 503, 'login_security_unavailable'))
    const save = vi.spyOn(usersApi, 'updateLoginSecurity')
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />)
    await user.click(await screen.findByRole('button', { name: '编辑' }))
    expect(await screen.findByText('登录安全服务暂不可用，请稍后重试。')).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '编辑用户' })).not.toBeInTheDocument()
    expect(save).not.toHaveBeenCalled()
  })

  it('preserves an untouched hidden login policy while saving basic information', async () => {
    authenticateAdmin()
    const account = { ...managedUser, metadata: { remark: null, qq: null } }
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData([account]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    vi.mocked(usersApi.getLoginSecurity).mockResolvedValue({
      user_id: account.id, tenant_scope_id: account.scope_id, revision: 4,
      login_verification: 'email', login_allowlist: ['192.0.2.1'],
    })
    const update = vi.spyOn(usersApi, 'update').mockResolvedValue({ ...account, revision: 2 })
    const save = vi.spyOn(usersApi, 'updateLoginSecurity')
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />)
    await user.click(await screen.findByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑用户' })
    await user.type(within(dialog).getByLabelText('备注'), '只修改备注')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('用户更新成功')).toBeInTheDocument()
    expect(update).toHaveBeenCalledOnce()
    expect(save).not.toHaveBeenCalled()
  })

  it('keeps a definite channel rejection editable after saving the profile once', async () => {
    authenticateAdmin()
    const account = { ...managedUser, metadata: { remark: null, qq: null } }
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData([account]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const update = vi.spyOn(usersApi, 'update').mockResolvedValue({ ...account, revision: 2, email: 'new@example.com' })
    const save = vi.spyOn(usersApi, 'updateLoginSecurity')
      .mockRejectedValueOnce(new ApiError('disabled', 403, 'account_login_method_disabled'))
      .mockResolvedValue({ user_id: account.id, tenant_scope_id: account.scope_id, revision: 1,
        login_verification: 'sms', login_allowlist: [] })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />)
    await user.click(await screen.findByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑用户' })
    await user.clear(within(dialog).getByLabelText('邮箱'))
    await user.type(within(dialog).getByLabelText('邮箱'), 'new@example.com')
    await user.click(within(dialog).getByRole('tab', { name: '登录安全' }))
    await user.click(within(dialog).getByRole('radio', { name: '邮件' }).closest('label')!)
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('系统尚未启用该登录验证渠道，请检查系统设置。')).toBeInTheDocument()
    expect(within(dialog).getByRole('radio', { name: '邮件' })).toBeChecked()
    expect(within(dialog).getByLabelText('登录白名单')).toBeEnabled()
    await user.click(within(dialog).getByRole('radio', { name: '短信' }).closest('label')!)
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('用户更新成功')).toBeInTheDocument()
    expect(update).toHaveBeenCalledOnce()
    expect(save).toHaveBeenCalledTimes(2)
    expect(save.mock.calls[1][3]).toEqual({ expected_revision: 0, login_verification: 'sms', login_allowlist: [] })
    expect(save.mock.calls[1][4].idempotencyKey).not.toBe(save.mock.calls[0][4].idempotencyKey)
  })

  it('does not send a policy write after management permission is revoked during the profile save', async () => {
    authenticateAdmin()
    const account = { ...managedUser, metadata: { remark: null, qq: null } }
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData([account]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const pending = deferred<ManagedUser>()
    const update = vi.spyOn(usersApi, 'update').mockReturnValue(pending.promise)
    const save = vi.spyOn(usersApi, 'updateLoginSecurity')
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />)
    await user.click(await screen.findByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑用户' })
    await user.type(within(dialog).getByLabelText('备注'), '更新备注')
    await user.click(within(dialog).getByRole('tab', { name: '登录安全' }))
    await user.click(within(dialog).getByRole('radio', { name: '邮件' }).closest('label')!)
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    const actor = useSessionStore.getState().principal!
    act(() => useSessionStore.setState({ principal: { ...actor, permissions: ['identity.self.read'] } }))
    await act(async () => pending.resolve({ ...account, revision: 2 }))
    expect(save).not.toHaveBeenCalled()
    expect(screen.queryByText('用户更新成功')).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '编辑用户' })).not.toBeInTheDocument()
  })

  it('renders either verified identity and filters the full result set with pagination reset', async () => {
    authenticateAdmin()
    const personal = { ...managedUser, verification: { personal_verified: true, company_verified: false } }
    const company = { ...managedUser, id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', username: 'company',
      verification: { personal_verified: false, company_verified: true } }
    const list = vi.spyOn(usersApi, 'list').mockImplementation(async (_token, params) => listData(
      params.real_name_status === 'unverified' ? [{ ...managedUser, verification: { personal_verified: false, company_verified: false } }] : [personal, company], 25, params.page, params.limit,
    ))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />)
    expect(await screen.findAllByText('已实名')).toHaveLength(2)
    expect(list.mock.calls[0][1].include_verification).toBe(true)
    await user.click(await screen.findByTitle('2'))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1].page).toBe(2))
    for (const [label, value] of [['未实名', 'unverified'], ['已实名', 'verified'], ['所有实名状态', undefined]] as const) {
      await user.click(screen.getByRole('combobox', { name: '筛选实名状态' }))
      await user.click(await screen.findByText(label, { selector: '.ant-select-item-option-content' }))
      await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ page: 1, real_name_status: value }))
      if (value === 'unverified') expect((await screen.findAllByText('未实名')).some((item) => item.closest('.user-list-state-tag'))).toBe(true)
    }
  })

  it('does not turn an absent verification projection into an unverified identity', async () => {
    authenticateAdmin()
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData([{ ...managedUser, verification: undefined }]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    renderWithProviders(<UserListPage />)
    await screen.findByText('Alice')
    expect(screen.queryByText('未实名', { selector: '.user-list-state-tag' })).not.toBeInTheDocument()
    expect(screen.getByText('未提供', { selector: '.user-list-state-tag' })).toBeInTheDocument()
  })

  it.each([
    { personal_verified: true, company_verified: false },
    { personal_verified: false, company_verified: true },
  ])('preserves authoritative verification in the editor while saving only ordinary metadata %j', async (verification) => {
    authenticateAdmin()
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData([{ ...managedUser, verification }]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const update = vi.spyOn(usersApi, 'update').mockResolvedValue({ ...managedUser, revision: 2 })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />)
    await user.click(await screen.findByRole('button', { name: '编辑' }))
    const editor = await screen.findByRole('dialog', { name: '编辑用户' })
    await user.click(within(editor).getByRole('tab', { name: '实名信息' }))
    // ADMIN-CURRENT-07：只读认证结论，不再呈现不可保存的姓名/证件编辑框。
    expect(within(editor).getByText('实名认证结论（只读）')).toBeInTheDocument()
    for (const label of ['姓名', '身份证', '公司名称', '社会信用代码']) {
      expect(within(editor).queryByLabelText(label)).not.toBeInTheDocument()
    }
    for (const [label, checked] of [['个人实名', verification.personal_verified], ['企业实名', verification.company_verified]] as const) {
      const toggle = within(editor).getByRole('switch', { name: label })
      expect(toggle).toHaveAttribute('aria-checked', String(checked))
      expect(toggle).toBeDisabled()
    }
    await user.click(within(editor).getByRole('tab', { name: '基础信息' }))
    await user.type(within(editor).getByLabelText('备注'), '认证状态保持不变')
    await user.click(within(editor).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0][2]).toEqual({
      expected_revision: 1, display_name: managedUser.display_name, email: managedUser.email,
      phone: managedUser.phone, remark: '认证状态保持不变', qq: null, status: 'active',
      role: managedUser.role, group_id: null,
    })
  })

  it('renders metadata as plain text, edits both fields, and refetches after a legacy write receipt', async () => {
    authenticateAdmin()
    const before = { ...managedUser, metadata: { remark: '<b>原始备注</b>', qq: '001X' } }
    const after = { ...before, revision: 2, metadata: { remark: '保存备注\n第二行', qq: '000Ab' } }
    const list = vi.spyOn(usersApi, 'list').mockResolvedValueOnce(listData([before])).mockResolvedValue(listData([after]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const receipt = { ...managedUser, revision: 2 }
    delete receipt.metadata
    const update = vi.spyOn(usersApi, 'update').mockResolvedValue(receipt)
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])

    const remark = await screen.findByText('<b>原始备注</b>')
    expect(remark.querySelector('b')).toBeNull()
    expect(screen.getByText('001X')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const editor = await screen.findByRole('dialog', { name: '编辑用户' })
    expect(within(editor).getByLabelText('备注')).toHaveValue(before.metadata.remark)
    expect(within(editor).getByLabelText('QQ')).toHaveValue('001X')
    fireEvent.change(within(editor).getByLabelText('备注'), { target: { value: '  保存备注\n第二行  ' } })
    fireEvent.change(within(editor).getByLabelText('QQ'), { target: { value: '  000Ab  ' } })
    await user.click(within(editor).getByRole('button', { name: '确定' }))

    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0][2]).toMatchObject({ expected_revision: 1, remark: after.metadata.remark, qq: '000Ab' })
    expect(await screen.findByText('000Ab')).toBeInTheDocument()
    expect(list).toHaveBeenCalledTimes(2)
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const refreshed = await screen.findByRole('dialog', { name: '编辑用户' })
    expect(within(refreshed).getByLabelText('备注')).toHaveValue(after.metadata.remark)
    expect(within(refreshed).getByLabelText('QQ')).toHaveValue('000Ab')
    fireEvent.change(within(refreshed).getByLabelText('备注'), { target: { value: '  ' } })
    fireEvent.change(within(refreshed).getByLabelText('QQ'), { target: { value: '' } })
    await user.click(within(refreshed).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2))
    expect(update.mock.calls[1][2]).toMatchObject({ expected_revision: 2, remark: null, qq: null })
  }, 20_000)

  it('reads omitted metadata before opening a legacy user and keeps it when changing another field', async () => {
    authenticateAdmin()
    const legacy = { ...managedUser }
    delete legacy.metadata
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData([legacy]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const fresh = { ...managedUser, revision: 5, metadata: { remark: '真实备注', qq: '000123' } }
    const read = deferred<ManagedUser>()
    const get = vi.spyOn(usersApi, 'get').mockReturnValue(read.promise)
    const update = vi.spyOn(usersApi, 'update').mockResolvedValue(fresh)
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: '编辑' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增用户' })).toBeDisabled()
    await act(async () => read.resolve(fresh))
    const editor = await screen.findByRole('dialog', { name: '编辑用户' })
    expect(get).toHaveBeenCalledWith(expect.any(String), managedUser.id)
    expect(within(editor).getByLabelText('备注')).toHaveValue('真实备注')
    await user.click(within(editor).getByRole('switch', { name: '启用' }))
    await user.click(within(editor).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0][2]).toMatchObject({ expected_revision: 5, status: 'disabled', remark: '真实备注', qq: '000123' })
  })

  it.each(['missing metadata', 'permission denied'] as const)('blocks editing when the full read returns %s', async (outcome) => {
    authenticateAdmin()
    const legacy = { ...managedUser }
    delete legacy.metadata
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData([legacy]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const get = vi.spyOn(usersApi, 'get')
    if (outcome === 'missing metadata') get.mockResolvedValue(legacy)
    else get.mockRejectedValue(new ApiError('private metadata denied', 403, 'permission_denied'))
    const update = vi.spyOn(usersApi, 'update')
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: '编辑' }))
    await waitFor(() => expect(get).toHaveBeenCalledOnce())
    if (outcome === 'permission denied') expect(await screen.findByText('无权管理用户')).toBeInTheDocument()
    else expect(await screen.findByText('服务响应无效，请刷新后确认结果')).toBeInTheDocument()
    expect(pageDialogs()).toHaveLength(0)
    expect(update).not.toHaveBeenCalled()
    expect(document.body).not.toHaveTextContent('private metadata denied')
  })

  it('discards a delayed metadata read after the platform session changes', async () => {
    authenticateAdmin()
    const legacy = { ...managedUser }
    delete legacy.metadata
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData([legacy]))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const read = deferred<ManagedUser>()
    vi.spyOn(usersApi, 'get').mockReturnValue(read.promise)
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: '编辑' }))
    act(() => authenticateAdmin())
    await act(async () => read.resolve({ ...managedUser, metadata: { remark: '旧会话私有备注', qq: '00999' } }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('旧会话私有备注')
    expect(screen.getByRole('button', { name: '新增用户' })).toBeEnabled()
  })

  it('intersects independent user fields, resets pagination, and keys each filtered result', async () => {
    authenticateAdmin()
    const list = vi.spyOn(usersApi, 'list').mockImplementation(async (_token, params) => listData([managedUser], 45, params.page, params.limit))
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
    const user = userEvent.setup({ delay: null })
    renderUsersWithQueryClient(queryClient)
    await screen.findByText('Alice')
    await user.click(await screen.findByTitle('2'))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1].page).toBe(2))
    fireEvent.change(screen.getByLabelText('搜索用户'), { target: { value: 'alice' } })
    // fix-advfilter: 姓名/备注/邮箱/QQ/手机号 sit in 高级筛选; Enter in the panel applies.
    await user.click(screen.getByRole('button', { name: '高级筛选' }))
    fireEvent.change(screen.getByLabelText('按姓名筛选'), { target: { value: '  中文  ' } })
    fireEvent.change(screen.getByLabelText('按邮箱筛选'), { target: { value: '  %_@example  ' } })
    fireEvent.change(screen.getByLabelText('按手机号筛选'), { target: { value: '  +86001  ' } })
    fireEvent.change(screen.getByLabelText('按备注筛选'), { target: { value: '  50%_VIP  ' } })
    fireEvent.change(screen.getByLabelText('按QQ筛选'), { target: { value: '  000Ab  ' } })
    await user.click(screen.getByLabelText('按QQ筛选'))
    await user.keyboard('{Enter}')
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ page: 1, username: 'alice', display_name: '中文', email: '%_@example', phone: '+86001', remark: '50%_VIP', qq: '000Ab' }))
    expect(queryClient.getQueryCache().getAll().some((entry) => entry.queryKey.at(-2) === '50%_VIP' && entry.queryKey.at(-1) === '000Ab')).toBe(true)
    expect(screen.getByRole('button', { name: '高级筛选 · 5' })).toBeInTheDocument()
    expect(screen.getByRole('list', { name: '已启用的高级条件' })).toHaveTextContent('QQ：000Ab')
    fireEvent.change(screen.getByLabelText('按QQ筛选'), { target: { value: '001B' } })
    await user.click(screen.getByLabelText('按QQ筛选'))
    await user.keyboard('{Enter}')
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ page: 1, username: 'alice', display_name: '中文', email: '%_@example', phone: '+86001', remark: '50%_VIP', qq: '001B' }))
    expect(queryClient.getQueryCache().getAll().some((entry) => entry.queryKey.at(-2) === '50%_VIP' && entry.queryKey.at(-1) === '001B')).toBe(true)
  })

  it.each(['备注', 'QQ'])('does not discard a changed %s during password reset', async (field) => {
    authenticateAdmin()
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const update = vi.spyOn(usersApi, 'update')
    const reset = vi.spyOn(usersApi, 'resetPassword')
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const editor = await screen.findByRole('dialog', { name: '编辑用户' })
    fireEvent.change(within(editor).getByLabelText(field), { target: { value: '001changed' } })
    fireEvent.change(within(editor).getByLabelText('密码'), { target: { value: 'new-password-long-enough' } })
    await user.click(within(editor).getByRole('button', { name: '确定' }))
    expect(await within(editor).findByText('这些资料暂不能保存')).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '重置用户密码' })).not.toBeInTheDocument()
    expect(reset).not.toHaveBeenCalled()
    expect(update).not.toHaveBeenCalled()
  })

  it('validates Unicode metadata limits without UTF-16 truncation and saves exact allowed values', async () => {
    authenticateAdmin()
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const update = vi.spyOn(usersApi, 'update').mockResolvedValue(managedUser)
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const editor = await screen.findByRole('dialog', { name: '编辑用户' })
    const remark = within(editor).getByLabelText('备注')
    const qq = within(editor).getByLabelText('QQ')
    expect(remark).not.toHaveAttribute('maxlength')
    expect(qq).not.toHaveAttribute('maxlength')
    fireEvent.change(remark, { target: { value: '😀'.repeat(513) } })
    fireEvent.change(qq, { target: { value: '000\t01' } })
    await user.click(within(editor).getByRole('button', { name: '确定' }))
    expect(await within(editor).findByText('备注最多512个字符，可包含换行和制表符，不可包含其他控制字符')).toBeInTheDocument()
    expect(await within(editor).findByText('QQ最多32个字符，不可包含控制字符')).toBeInTheDocument()
    expect(update).not.toHaveBeenCalled()
    const allowedRemark = '😀'.repeat(509) + '\t\nX'
    const allowedQQ = '😀'.repeat(32)
    fireEvent.change(remark, { target: { value: allowedRemark } })
    fireEvent.change(qq, { target: { value: allowedQQ } })
    await user.click(within(editor).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0][2]).toMatchObject({ remark: allowedRemark, qq: allowedQQ })
  })

  it('matches the competitor row actions and switch signs in as the user directly without a form', async () => {
    authenticateAdmin()
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    vi.spyOn(usersApi, 'listGroups').mockImplementation(async (_token, page, limit) => ({
      items: [], page, limit, total: 0,
    }))
    const now = Date.now()
    const grantID = '018f3f2d-8f2a-7c4b-9a1f-0f8c4d0b6e21'
    const actorID = useSessionStore.getState().principal!.user_id
    const expiresAt = new Date(now + 15 * 60_000).toISOString()
    const createGrant = vi.spyOn(impersonationApi, 'createGrant').mockResolvedValue({
      grant: {
        id: grantID, tenant_id: managedUser.tenant_id, tenant_scope_id: managedUser.scope_id,
        actor_user_id: actorID, actor_scope_id: useSessionStore.getState().principal!.scope_id,
        subject_user_id: managedUser.id, created_at: new Date(now).toISOString(),
        expires_at: new Date(now + 120_000).toISOString(),
      },
      authorization_code: 'one-time-code',
      replayed: false,
    })
    const exchange = vi.spyOn(impersonationApi, 'exchange').mockResolvedValue({
      principal: principal({
        user_id: managedUser.id, scope_id: managedUser.scope_id, tenant_id: managedUser.tenant_id,
        scope_kind: 'tenant', username: managedUser.username, display_name: managedUser.display_name,
        roles: ['tenant_owner'], permissions: ['sites.read'],
      }),
      banner: {
        grant_id: grantID, actor_user_id: actorID, actor_display_name: 'admin',
        subject_user_id: managedUser.id, subject_display_name: managedUser.display_name,
        tenant_id: managedUser.tenant_id, expires_at: expiresAt,
      },
      expires_at: expiresAt,
      refreshable: false,
      replayed: false,
    })
    const user = userEvent.setup({ delay: null })

    renderWithProviders(
      <Routes>
        <Route path="/sys/user" element={<UserListPage />} />
        <Route path="/home" element={<LocationProbe />} />
      </Routes>,
      ['/sys/user'],
    )

    await screen.findByText('Alice')
    expect(screen.getByRole('button', { name: '切换' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '编辑' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '重置密码' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '禁用' })).not.toBeInTheDocument()

    const epochBeforeSwitch = useSessionStore.getState().sessionEpoch
    await user.click(screen.getByRole('button', { name: '切换' }))
    expect(await screen.findByText('/home')).toBeInTheDocument()
    // A14: entering impersonation is a new identity -> new epoch (SessionQueryBoundary clears the admin's cache).
    expect(useSessionStore.getState().sessionEpoch).toBeGreaterThan(epochBeforeSwitch)
    expect(createGrant).toHaveBeenCalledOnce()
    expect(createGrant.mock.calls[0][1]).toEqual({
      tenant_id: managedUser.tenant_id, tenant_scope_id: managedUser.scope_id, subject_user_id: managedUser.id,
    })
    expect(exchange).toHaveBeenCalledOnce()
    expect(exchange.mock.calls[0][0]).toEqual({
      tenant_id: managedUser.tenant_id, tenant_scope_id: managedUser.scope_id, authorization_code: 'one-time-code',
    })
    const current = useSessionStore.getState().principal
    expect(current?.user_id).toBe(managedUser.id)
    expect(current?.impersonation?.grant_id).toBe(grantID)
  })

  it('shows a stable message and stays on the list when switching is refused', async () => {
    authenticateAdmin()
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    vi.spyOn(usersApi, 'listGroups').mockImplementation(async (_token, page, limit) => ({
      items: [], page, limit, total: 0,
    }))
    vi.spyOn(impersonationApi, 'createGrant').mockRejectedValue(
      new ApiError('changed', 403, 'impersonation_principal_changed'),
    )
    const exchange = vi.spyOn(impersonationApi, 'exchange')
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])

    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: '切换' }))
    expect(await screen.findByText('该用户状态或权限已变化，无法切换')).toBeInTheDocument()
    expect(exchange).not.toHaveBeenCalled()
    expect(useSessionStore.getState().principal?.scope_kind).toBe('platform')
  })

  it.each([
    ['a platform principal without either management permission', principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: [],
    }), false],
    ['a tenant principal carrying identity.users.manage', principal({
      permissions: ['identity.users.manage'],
    }), false],
    ['a platform principal carrying a tenant id', principal({
      scope_kind: 'platform', tenant_id: '22222222-2222-4222-8222-222222222222',
      roles: ['platform_admin'], permissions: ['identity.users.manage'],
    }), false],
    ['a platform principal without a scope id', principal({
      scope_kind: 'platform', scope_id: '', tenant_id: null,
      roles: ['platform_admin'], permissions: ['identity.users.manage'],
    }), false],
    ['a platform principal without a user id', principal({
      scope_kind: 'platform', user_id: '', tenant_id: null,
      roles: ['platform_admin'], permissions: ['platform.admin'],
    }), false],
    ['a platform principal at session epoch zero', principal({
      scope_kind: 'platform', tenant_id: null,
      roles: ['platform_admin'], permissions: ['identity.users.manage'],
    }), true],
  ] as const)(
    'renders a local 403 and performs no reads or writes for %s',
    async (_case, actor, zeroEpoch) => {
    useSessionStore.getState().setSession(authResponse(actor), actor)
    if (zeroEpoch) useSessionStore.setState({ sessionEpoch: 0 })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const listSpy = vi.spyOn(usersApi, 'list')
    const createSpy = vi.spyOn(usersApi, 'create')
    const updateSpy = vi.spyOn(usersApi, 'update')

    renderWithProviders(<UserListPage />, ['/sys/user'])

    expect(await screen.findByText('无权管理用户')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少用户管理权限')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(listSpy).not.toHaveBeenCalled()
    expect(createSpy).not.toHaveBeenCalled()
    expect(updateSpy).not.toHaveBeenCalled()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新增用户' })).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    },
  )

  it('keeps filters, page two, editor, and token-free cache identity across a same-epoch token refresh', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'],
    })
    const oldToken = 'old-managed-user-access-token'
    const newToken = 'new-managed-user-access-token'
    const stableUser = { ...managedUser, display_name: 'Stable managed user' }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'http://cdnca.test')
      return Promise.resolve(listResponse(
        [stableUser],
        45,
        Number(url.searchParams.get('page')),
        Number(url.searchParams.get('limit')),
      ))
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    useSessionStore.getState().setSession({ ...authResponse(actor), access_token: oldToken }, actor)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const owner = ownerTuple(actor, sessionEpoch)
    const user = userEvent.setup({ delay: null })

    renderUsersWithQueryClient(queryClient)

    expect(await screen.findByText(stableUser.display_name)).toBeInTheDocument()
    await user.type(screen.getByLabelText('搜索用户'), 'stable')
    await user.keyboard('{Enter}')
    await user.click(await screen.findByTitle('2'))
    await waitFor(() => expect(document.querySelector('.ant-pagination-item-active')).toHaveAttribute('title', '2'))
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const editor = await waitFor(() => pageDialog('编辑用户'))
    const readsBeforeRefresh = fetchSpy.mock.calls.length

    await act(async () => {
      useSessionStore.getState().setSession({ ...authResponse(actor), access_token: newToken }, actor, 'refresh')
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(fetchSpy).toHaveBeenCalledTimes(readsBeforeRefresh)
    expect(screen.getByText(stableUser.display_name)).toBeInTheDocument()
    expect(pageDialog('编辑用户')).toBe(editor)
    expect(within(editor).getByLabelText('用户名')).toHaveValue(managedUser.username)
    expect(screen.getByLabelText('搜索用户')).toHaveValue('stable')

    expect(document.querySelector('.ant-pagination-item-active')).toHaveAttribute('title', '2')

    const activeKey = ['managed-users', ...owner, 2, 10, { username: 'stable', display_name: '', email: '', phone: '' }, undefined, undefined, undefined, undefined, '', '', ''] as const
    const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    expect(queryKeys).toContainEqual(activeKey)
    for (const queryKey of queryKeys) {
      const serializedKey = JSON.stringify(queryKey)
      expect(serializedKey).not.toContain(oldToken)
      expect(serializedKey).not.toContain(newToken)
    }
    expect(document.body.textContent).not.toContain(oldToken)
    expect(document.body.textContent).not.toContain(newToken)

    await queryClient.refetchQueries({ queryKey: activeKey, type: 'active' })
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(readsBeforeRefresh + 1))
    expect(new Headers(fetchSpy.mock.calls.at(-1)?.[1]?.headers).get('Authorization')).toBe(`Bearer ${newToken}`)
    expect(pageDialog('编辑用户')).toBeInTheDocument()
    expect(document.querySelector('.ant-pagination-item-active')).toHaveAttribute('title', '2')
  }, 20_000)

  it('keeps an unknown create retry across a token refresh without exposing its password to MutationCache', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['identity.users.manage'],
    })
    const oldToken = 'old-sensitive-user-access-token'
    const newToken = 'new-sensitive-user-access-token'
    const initialPassword = 'test-only-S3cret-value'
    let writes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_, init) => {
      if (init?.method === 'POST') {
        writes += 1
        if (writes === 1) return Promise.reject(new TypeError('response lost after write'))
        return Promise.resolve(new Response(JSON.stringify({
          ...managedUser, username: 'sensitive-user', display_name: 'Sensitive user',
        }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        }))
      }
      return Promise.resolve(listResponse())
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    useSessionStore.getState().setSession({ ...authResponse(actor), access_token: oldToken }, actor)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const owner = ownerTuple(actor, sessionEpoch)
    const user = userEvent.setup({ delay: null })

    renderUsersWithQueryClient(queryClient)
    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: '新增用户' }))
    const editor = await screen.findByRole('dialog', { name: '新增用户' })
    await user.type(within(editor).getByLabelText('用户名'), 'sensitive-user')
    await user.type(within(editor).getByLabelText('密码'), initialPassword)
    await user.type(within(editor).getByLabelText('邮箱'), 'sensitive-user@example.com')
    await user.click(within(editor).getByRole('button', { name: '确定' }))

    expect(await within(editor).findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(within(editor).getByLabelText('用户名')).toHaveValue('sensitive-user')
    expect(within(editor).getByLabelText('密码')).toHaveValue(initialPassword)
    expect(within(editor).getByLabelText('密码')).toBeDisabled()
    expectMutationCacheNotToContain(queryClient, initialPassword)
    const firstWrite = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')!

    await act(async () => {
      useSessionStore.getState().setSession({ ...authResponse(actor), access_token: newToken }, actor, 'refresh')
      await Promise.resolve()
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(screen.getByRole('dialog', { name: '新增用户' })).toBe(editor)
    expect(within(editor).getByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(within(editor).getByLabelText('用户名')).toHaveValue('sensitive-user')
    expect(within(editor).getByLabelText('密码')).toHaveValue(initialPassword)
    expectMutationCacheNotToContain(queryClient, initialPassword)
    expect(queryClient.getMutationCache().getAll().map((entry) => entry.options.mutationKey))
      .toContainEqual(['managed-users-write', ...owner])

    await user.click(within(editor).getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('用户创建成功')).toBeInTheDocument()

    const writeCalls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')
    expect(writeCalls).toHaveLength(2)
    expect(writeCalls[1][1]?.body).toBe(firstWrite[1]?.body)
    expect(new Headers(writeCalls[1][1]?.headers).get('Idempotency-Key')).toBe(
      new Headers(firstWrite[1]?.headers).get('Idempotency-Key'),
    )
    expect(new Headers(writeCalls[1][1]?.headers).get('X-Request-ID')).toBe(
      new Headers(firstWrite[1]?.headers).get('X-Request-ID'),
    )
    expect(new Headers(writeCalls[1][1]?.headers).get('Traceparent')).toBe(
      new Headers(firstWrite[1]?.headers).get('Traceparent'),
    )
    expect(new Headers(firstWrite[1]?.headers).get('Authorization')).toBe(`Bearer ${oldToken}`)
    expect(new Headers(writeCalls[1][1]?.headers).get('Authorization')).toBe(`Bearer ${newToken}`)
    expectMutationCacheNotToContain(queryClient, initialPassword)
    expect(JSON.stringify(queryClient.getMutationCache().getAll().map((entry) => entry.options.mutationKey)))
      .not.toContain('managed-user-access-token')
  }, 20_000)

  it('creates one target-bound step-up proof and resets the selected user password', async () => {
    authenticateAdmin()
    const actor = useSessionStore.getState().principal!
    useSessionStore.setState({ principal: { ...actor, permissions: [...actor.permissions, 'identity.self.read'] } })
    const mfaStatus = vi.spyOn(mfaApi, 'getStatus').mockResolvedValue({ status: 'inactive' })
    const secret = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    const enrollment = vi.spyOn(mfaApi, 'beginEnrollment').mockImplementation(async () => {
      mfaStatus.mockResolvedValue({
        status: 'enrollment_pending', credential_id: managedUser.id, method: 'totp',
        enrollment_expires_at: '2027-01-01T00:00:00Z',
      })
      return {
        credential_id: managedUser.id, secret, provisioning_uri: 'otpauth://test',
        expires_at: '2027-01-01T00:00:00Z', replayed: false,
      }
    })
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    vi.spyOn(usersApi, 'listGroups').mockImplementation(async (_token, page, limit) => ({
      items: [], page, limit, total: 0,
    }))
    const proof = vi.spyOn(mfaApi, 'createStepUpProof').mockResolvedValue({
      proof_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      token: 'opaque-reset-step-up-proof',
      method: 'totp',
      issued_at: '2026-07-22T08:00:00Z',
      expires_at: '2026-07-22T08:05:00Z',
      max_uses: 1,
      replayed: false,
    })
    const reset = vi.spyOn(usersApi, 'resetPassword').mockResolvedValue({ ...managedUser, revision: 2 })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    const user = userEvent.setup({ delay: null })

    renderUsersWithQueryClient(queryClient)
    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const editor = await screen.findByRole('dialog', { name: '编辑用户' })
    const newPassword = 'replacement-password-long-enough'
    await user.type(within(editor).getByLabelText('密码'), newPassword)
    await user.click(within(editor).getByRole('button', { name: '确定' }))
    const dialog = await screen.findByRole('dialog', { name: '重置 Alice 的密码' })
    expect(within(dialog).getByLabelText('新密码')).toHaveValue(newPassword)
    expect(within(dialog).getByLabelText('确认新密码')).toHaveValue(newPassword)
    expect(mfaStatus).not.toHaveBeenCalled()
    await user.click(within(dialog).getByRole('button', { name: '管理身份验证器' }))
    // rc-dialog uses the same title ID for every modal in its test environment.
    const setup = (await screen.findByText('管理身份验证器', { selector: '.ant-modal-title' }))
      .closest<HTMLElement>('[role="dialog"]')!
    expect(await within(setup).findByText('尚未配置身份验证器')).toBeInTheDocument()
    expect(proof).not.toHaveBeenCalled()
    expect(reset).not.toHaveBeenCalled()
    await user.click(within(setup).getByRole('button', { name: '设置身份验证器' }))
    const enrollmentDialog = (await screen.findByText('设置身份验证器', { selector: '.ant-modal-title' }))
      .closest<HTMLElement>('[role="dialog"]')!
    await user.click(within(enrollmentDialog).getByRole('button', { name: '确认' }))
    const secretInput = await screen.findByDisplayValue(secret)
    fireEvent.keyDown(secretInput, { key: 'Escape', code: 'Escape', keyCode: 27 })
    expect(screen.getByDisplayValue(secret)).toBeInTheDocument()
    expect(within(dialog).getByLabelText('新密码')).toHaveValue(newPassword)
    await user.click(screen.getByRole('button', { name: '我已安全保存' }))
    await user.click(within(setup).getByRole('button', { name: /close/i }))
    await waitFor(() => expect(screen.queryByText('管理身份验证器', { selector: '.ant-modal-title' })).not.toBeInTheDocument())
    expect(within(dialog).getByLabelText('新密码')).toHaveValue(newPassword)
    await user.click(within(dialog).getByRole('button', { name: '管理身份验证器' }))
    const reopenedSetup = (await screen.findByText('管理身份验证器', { selector: '.ant-modal-title' }))
      .closest<HTMLElement>('[role="dialog"]')!
    expect(await within(reopenedSetup).findByText('等待激活')).toBeInTheDocument()
    expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument()
    expect(enrollment).toHaveBeenCalledOnce()
    await user.click(within(reopenedSetup).getByRole('button', { name: /close/i }))
    await user.type(within(dialog).getByLabelText('MFA 验证码'), '123456')
    await user.click(within(dialog).getByRole('button', { name: '确认重置' }))

    expect(await screen.findByText('密码已重置，目标用户的现有会话已撤销')).toBeInTheDocument()
    expect(proof).toHaveBeenCalledWith(expect.any(String), {
      tenant_id: managedUser.tenant_id,
      audience: 'identity.user.password.reset',
      action: 'identity.user.password.reset',
      authentication: { method: 'totp', code: '123456' },
      ttl_seconds: 300,
      max_uses: 1,
    }, expect.any(Object))
    expect(reset).toHaveBeenCalledWith(expect.any(String), {
      user_id: managedUser.id,
      tenant_id: managedUser.tenant_id,
      tenant_scope_id: managedUser.scope_id,
      expected_revision: managedUser.revision,
      new_password: newPassword,
      step_up_token: 'opaque-reset-step-up-proof',
    }, expect.any(Object))
    expectMutationCacheNotToContain(queryClient, newPassword)
    expectMutationCacheNotToContain(queryClient, 'opaque-reset-step-up-proof')
  })

  it('retries an unknown password reset with the exact original request without issuing another proof', async () => {
    authenticateAdmin()
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    vi.spyOn(usersApi, 'listGroups').mockImplementation(async (_token, page, limit) => ({
      items: [], page, limit, total: 0,
    }))
    const proof = vi.spyOn(mfaApi, 'createStepUpProof').mockResolvedValue({
      proof_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      token: 'opaque-reset-retry-proof',
      method: 'totp',
      issued_at: '2026-07-22T08:00:00Z',
      expires_at: '2026-07-22T08:05:00Z',
      max_uses: 1,
      replayed: false,
    })
    const reset = vi.spyOn(usersApi, 'resetPassword')
      .mockRejectedValueOnce(new ApiError('private commit state', 503, 'managed_password_reset_unavailable'))
      .mockResolvedValueOnce({ ...managedUser, revision: 2 })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    const user = userEvent.setup({ delay: null })

    renderUsersWithQueryClient(queryClient)
    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const editor = await screen.findByRole('dialog', { name: '编辑用户' })
    await user.type(within(editor).getByLabelText('密码'), 'replacement-password-long-enough')
    await user.click(within(editor).getByRole('button', { name: '确定' }))
    const dialog = await screen.findByRole('dialog', { name: '重置 Alice 的密码' })
    expect(within(dialog).getByLabelText('新密码')).toHaveValue('replacement-password-long-enough')
    expect(within(dialog).getByLabelText('确认新密码')).toHaveValue('replacement-password-long-enough')
    await user.type(within(dialog).getByLabelText('MFA 验证码'), '123456')
    await user.click(within(dialog).getByRole('button', { name: '确认重置' }))

    expect(await within(dialog).findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(within(dialog).queryByText('private commit state')).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('密码已重置，目标用户的现有会话已撤销')).toBeInTheDocument()
    expect(proof).toHaveBeenCalledOnce()
    expect(reset).toHaveBeenCalledTimes(2)
    expect(reset.mock.calls[1][1]).toBe(reset.mock.calls[0][1])
    expect(reset.mock.calls[1][2]).toBe(reset.mock.calls[0][2])
    expectMutationCacheNotToContain(queryClient, 'replacement-password-long-enough')
    expectMutationCacheNotToContain(queryClient, 'opaque-reset-retry-proof')
  })

  it('turns an authorized list 403 into a terminal boundary that cannot be reawakened', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['identity.users.manage'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const listPrefix = ['managed-users', ...ownerTuple(actor, sessionEpoch)] as const
    const listSpy = vi.spyOn(usersApi, 'list')
      .mockResolvedValueOnce(listData())
      .mockRejectedValueOnce(new ApiError('private managed user role row', 403, 'permission_denied'))
      .mockResolvedValue(listData([{ ...managedUser, display_name: 'Forbidden late user' }]))
    const createSpy = vi.spyOn(usersApi, 'create').mockResolvedValue({
      ...managedUser, username: 'forbidden-write', display_name: 'Forbidden write',
    })
    const updateSpy = vi.spyOn(usersApi, 'update')
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup({ delay: null })
    onlineManager.setOnline(true)

    renderUsersWithQueryClient(queryClient)
    await screen.findByText('Alice')
    const addButton = screen.getByRole('button', { name: '新增用户' })
    await user.click(addButton)
    const editor = await screen.findByRole('dialog', { name: '新增用户' })
    await user.type(within(editor).getByLabelText('用户名'), 'forbidden-write')
    await user.type(within(editor).getByLabelText('密码'), 'strong-password-123')
    await user.type(within(editor).getByLabelText('邮箱'), 'forbidden-write@example.com')
    const confirmButton = within(editor).getByRole('button', { name: '确定' })

    await act(async () => {
      await queryClient.refetchQueries({ queryKey: listPrefix, type: 'active' })
    })

    expect(await screen.findByText('无权管理用户')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少用户管理权限')).toBeInTheDocument()
    expect(screen.queryByText('private managed user role row')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新增用户' })).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '新增用户' })).not.toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(screen.queryByText('Alice')).not.toBeInTheDocument()
    const terminalQueries = queryClient.getQueryCache().findAll({ queryKey: listPrefix })
    expect(terminalQueries.length).toBeGreaterThan(0)
    for (const terminalQuery of terminalQueries) expect(terminalQuery.isDisabled()).toBe(true)
    const readsAfterForbidden = listSpy.mock.calls.length

    fireEvent.click(addButton)
    fireEvent.click(confirmButton)
    await act(async () => {
      await queryClient.invalidateQueries({ queryKey: listPrefix })
      await queryClient.refetchQueries({ queryKey: listPrefix, type: 'active' })
      onlineManager.setOnline(false)
      onlineManager.setOnline(true)
      await Promise.resolve()
    })

    expect(listSpy).toHaveBeenCalledTimes(readsAfterForbidden)
    expect(createSpy).not.toHaveBeenCalled()
    expect(updateSpy).not.toHaveBeenCalled()
    expect(screen.getByText('无权管理用户')).toBeInTheDocument()
    expect(screen.queryByText('Forbidden late user')).not.toBeInTheDocument()
  }, 20_000)

  it('turns a current-owner write 403 into a terminal boundary that cannot be reawakened', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['identity.users.manage'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    const listPrefix = ['managed-users', ...ownerTuple(actor, sessionEpoch)] as const
    const listSpy = vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    const createSpy = vi.spyOn(usersApi, 'create').mockRejectedValue(
      new ApiError('private managed user write policy', 403, 'permission_denied'),
    )
    const updateSpy = vi.spyOn(usersApi, 'update')
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup({ delay: null })
    onlineManager.setOnline(true)

    renderUsersWithQueryClient(queryClient)
    await screen.findByText('Alice')
    const addButton = screen.getByRole('button', { name: '新增用户' })
    await user.click(addButton)
    const editor = await screen.findByRole('dialog', { name: '新增用户' })
    await user.type(within(editor).getByLabelText('用户名'), 'forbidden-write-user')
    await user.type(within(editor).getByLabelText('密码'), 'private-forbidden-password')
    await user.type(within(editor).getByLabelText('邮箱'), 'forbidden-write-user@example.com')
    const confirmButton = within(editor).getByRole('button', { name: '确定' })
    await user.click(confirmButton)

    expect(await screen.findByText('无权管理用户')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少用户管理权限')).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(/private managed user write policy|private-forbidden-password/)
    expect(screen.queryByRole('button', { name: '新增用户' })).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '新增用户' })).not.toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(screen.queryByText('Alice')).not.toBeInTheDocument()
    const terminalQueries = queryClient.getQueryCache().findAll({ queryKey: listPrefix })
    expect(terminalQueries.length).toBeGreaterThan(0)
    for (const terminalQuery of terminalQueries) expect(terminalQuery.isDisabled()).toBe(true)
    const readsAfterForbidden = listSpy.mock.calls.length
    const createsAfterForbidden = createSpy.mock.calls.length

    fireEvent.click(addButton)
    fireEvent.click(confirmButton)
    await act(async () => {
      await queryClient.invalidateQueries({ queryKey: listPrefix })
      await queryClient.refetchQueries({ queryKey: listPrefix, type: 'active' })
      onlineManager.setOnline(false)
      onlineManager.setOnline(true)
      await Promise.resolve()
    })

    expect(listSpy).toHaveBeenCalledTimes(readsAfterForbidden)
    expect(createSpy).toHaveBeenCalledTimes(createsAfterForbidden)
    expect(updateSpy).not.toHaveBeenCalled()
    expect(screen.getByText('无权管理用户')).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(/forbidden-write-user|Forbidden write user/)
  }, 20_000)

  it.each(['success', 'error'] as const)(
    'resets user state, caches, and uncertain writes for a new platform session and isolates a delayed old-session list %s',
    async (outcome) => {
    const platformA = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['identity.users.manage'],
    })
    const platformB = principal({
      user_id: '88888888-8888-4888-8888-888888888888',
      scope_id: '77777777-7777-4777-8777-777777777777',
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['identity.users.manage'],
    })
    const platformAUser = { ...managedUser, display_name: 'Platform A managed user' }
    const latePlatformAUser = {
      ...managedUser,
      id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      display_name: 'Late platform A managed user',
    }
    const platformBUser = {
      ...managedUser,
      id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
      scope_id: platformB.scope_id,
      display_name: 'Platform B managed user',
    }
    const latePlatformA = deferred<UserListResponse>()
    const pendingPlatformB = deferred<UserListResponse>()
    let delayPlatformA = false
    const listSpy = vi.spyOn(usersApi, 'list').mockImplementation((token, filters) => {
      if (token === 'platform-a-users-token') {
        if (delayPlatformA && filters.page === 2) return latePlatformA.promise
        return Promise.resolve(listData([platformAUser], 45, filters.page, filters.limit))
      }
      if (token === 'platform-b-users-token') return pendingPlatformB.promise
      throw new Error(`unexpected managed user list token ${token}`)
    })
    vi.spyOn(usersApi, 'create').mockRejectedValue(
      new ApiError('private managed user writer topology', 503, 'request_failed'),
    )
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    useSessionStore.getState().setSession(
      { ...authResponse(platformA), access_token: 'platform-a-users-token' },
      platformA,
    )
    const platformAEpoch = useSessionStore.getState().sessionEpoch
    const platformAOwner = ownerTuple(platformA, platformAEpoch)
    const user = userEvent.setup({ delay: null })

    renderUsersWithQueryClient(queryClient)

    expect(await screen.findByText(platformAUser.display_name)).toBeInTheDocument()
    await user.type(screen.getByLabelText('搜索用户'), 'platform-a')
    await user.keyboard('{Enter}')
    await user.click(await screen.findByTitle('2'))
    await waitFor(() => expect(document.querySelector('.ant-pagination-item-active')).toHaveAttribute('title', '2'))

    await user.click(screen.getByRole('button', { name: '新增用户' }))
    const editor = await screen.findByRole('dialog', { name: '新增用户' })
    await user.type(within(editor).getByLabelText('用户名'), 'unknown-user')
    await user.type(within(editor).getByLabelText('密码'), 'strong-password-123')
    await user.type(within(editor).getByLabelText('邮箱'), 'unknown-user@example.com')
    await user.click(within(editor).getByRole('button', { name: '确定' }))
    expect(await within(editor).findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()

    const platformAKey = [
      'managed-users', ...platformAOwner, 2, 10, { username: 'platform-a', display_name: '', email: '', phone: '' }, undefined, undefined, undefined, undefined, '', '', '',
    ] as const
    expect(queryClient.getMutationCache().getAll().map((entry) => entry.options.mutationKey))
      .toContainEqual(['managed-users-write', ...platformAOwner])
    delayPlatformA = true
    void queryClient.invalidateQueries({ queryKey: platformAKey })
    await waitFor(() => expect(listSpy.mock.calls.filter(([token, filters]) => (
      token === 'platform-a-users-token' && filters.page === 2
    ))).toHaveLength(2))

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(platformB), access_token: 'platform-b-users-token' },
        platformB,
      )
      await Promise.resolve()
    })
    const platformBEpoch = useSessionStore.getState().sessionEpoch
    const platformBOwner = ownerTuple(platformB, platformBEpoch)
    await waitFor(() => expect(listSpy.mock.calls.some(([token]) => token === 'platform-b-users-token')).toBe(true))

    expect(platformBEpoch).not.toBe(platformAEpoch)
    expect(screen.queryByText(platformAUser.display_name)).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '新增用户' })).not.toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByText('private managed user writer topology')).not.toBeInTheDocument()
    expect(screen.getByLabelText('搜索用户')).toHaveValue('')
    expect(screen.getByRole('combobox', { name: '筛选实名状态' }).closest('.ant-select')).toHaveTextContent('所有实名状态')
    expect(screen.getByRole('combobox', { name: '筛选用户组' }).closest('.ant-select')).toHaveTextContent('所有用户组')
    expect(document.querySelector('.identity-table-scroll')).toHaveAttribute('aria-busy', 'true')
    expect(listSpy.mock.calls.find(([token]) => token === 'platform-b-users-token')?.[1]).toEqual({
      page: 1, limit: 10, display_id: '', username: '', display_name: '', email: '', phone: '', status: undefined, role: undefined, group_id: undefined, remark: '', qq: '',
      include_verification: true, real_name_status: undefined, include_platform_admins: true,
    })

    const platformBData = listData([platformBUser], 1, 1, 10)
    await act(async () => pendingPlatformB.resolve(platformBData))
    expect(await screen.findByText(platformBUser.display_name)).toBeInTheDocument()

    const latePlatformAData = listData([latePlatformAUser], 45, 2, 10)
    await act(async () => {
      if (outcome === 'success') latePlatformA.resolve(latePlatformAData)
      else latePlatformA.reject(new ApiError('private old managed user list failure', 503, 'request_failed'))
      await Promise.allSettled([latePlatformA.promise])
    })
    await waitFor(() => expect(queryClient.getQueryData(platformAKey)).toBeUndefined())
    const platformBKey = ['managed-users', ...platformBOwner, 1, 10, { username: '', display_name: '', email: '', phone: '' }, undefined, undefined, undefined, undefined, '', '', ''] as const
    expect(queryClient.getQueryData(platformBKey)).toEqual(platformBData)
    expect(screen.getByText(platformBUser.display_name)).toBeInTheDocument()
    expect(screen.queryByText(latePlatformAUser.display_name)).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(/private old managed user|unknown-user|strong-password-123/)
    expect(queryClient.getQueryCache().getAll().some((entry) => entry.queryKey.slice(1, 6)
      .every((value, index) => value === platformAOwner[index]))).toBe(false)
    expect(queryClient.getMutationCache().getAll().some((entry) => entry.options.mutationKey?.slice(1, 6)
      .every((value, index) => value === platformAOwner[index]))).toBe(false)
    },
    20_000,
  )

  it.each(['success', 'error'] as const)(
    'removes old group reads and ignores their delayed %s settlement after a new platform session',
    async (outcome) => {
      const platformA = principal({
        scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['identity.users.manage'],
      })
      const platformB = principal({
        scope_kind: 'platform', scope_id: '77777777-7777-4777-8777-777777777777', tenant_id: null,
        user_id: '88888888-8888-4888-8888-888888888888',
        roles: ['platform_admin'], permissions: ['identity.users.manage'],
      })
      const oldGroups = deferred<{ items: UserGroup[]; page: number; limit: number; total: number }>()
      const currentGroup = {
        ...managedGroup,
        id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
        scope_id: platformB.scope_id,
        name: '当前平台用户组',
      }
      useSessionStore.getState().setSession(
        { ...authResponse(platformA), access_token: 'old-group-owner-token' }, platformA,
      )
      const platformAOwner = ownerTuple(platformA, useSessionStore.getState().sessionEpoch)
      vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
      vi.spyOn(usersApi, 'listGroups').mockImplementation(async (token, page, limit) => {
        if (token === 'old-group-owner-token') return oldGroups.promise
        return { items: [currentGroup], page, limit, total: 1 }
      })
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
      })
      const user = userEvent.setup({ delay: null })

      renderUsersWithQueryClient(queryClient)
      await screen.findByText('Alice')
      await user.click(screen.getByRole('tab', { name: '用户分组' }))
      await act(async () => {
        useSessionStore.getState().setSession(
          { ...authResponse(platformB), access_token: 'current-group-owner-token' }, platformB,
        )
        await Promise.resolve()
      })
      await screen.findByText('Alice')
      await user.click(screen.getByRole('tab', { name: '用户分组' }))
      expect(await screen.findByText(currentGroup.name)).toBeInTheDocument()

      await act(async () => {
        if (outcome === 'success') {
          oldGroups.resolve({ items: [{ ...managedGroup, name: '旧平台私有组' }], page: 1, limit: 100, total: 1 })
        } else {
          oldGroups.reject(new ApiError('private old group topology', 503, 'request_failed'))
        }
        await Promise.allSettled([oldGroups.promise])
      })

      expect(screen.getByText(currentGroup.name)).toBeInTheDocument()
      expect(document.body).not.toHaveTextContent(/旧平台私有组|private old group/)
      expect(queryClient.getQueryCache().getAll().some((entry) =>
        JSON.stringify(entry.queryKey).includes(JSON.stringify(platformAOwner)))).toBe(false)
    },
    20_000,
  )

  it.each(['success', 'error'] as const)(
    'removes an old group mutation and ignores its delayed %s settlement after a new platform session',
    async (outcome) => {
      const platformA = principal({
        scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['identity.users.manage'],
      })
      const platformB = principal({
        scope_kind: 'platform', scope_id: '77777777-7777-4777-8777-777777777777', tenant_id: null,
        user_id: '88888888-8888-4888-8888-888888888888',
        roles: ['platform_admin'], permissions: ['identity.users.manage'],
      })
      useSessionStore.getState().setSession(
        { ...authResponse(platformA), access_token: 'old-group-write-token' }, platformA,
      )
      const platformAOwnerKey = JSON.stringify(ownerTuple(platformA, useSessionStore.getState().sessionEpoch))
      vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
      vi.spyOn(usersApi, 'listGroups').mockImplementation(async (_token, page, limit) => ({
        items: [managedGroup], page, limit, total: 1,
      }))
      const delayedCreate = deferred<UserGroup>()
      const createGroup = vi.spyOn(usersApi, 'createGroup').mockReturnValue(delayedCreate.promise)
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
      })
      const user = userEvent.setup({ delay: null })

      renderUsersWithQueryClient(queryClient)
      await screen.findByText('Alice')
      await user.click(screen.getByRole('tab', { name: '用户分组' }))
      await screen.findByText(managedGroup.name)
      await user.click(screen.getByRole('button', { name: '添加用户组' }))
      const modal = await screen.findByRole('dialog', { name: '添加用户组' })
      await user.type(within(modal).getByLabelText('用户组名称'), '旧平台私有组')
      await user.click(within(modal).getByRole('button', { name: '确定' }))
      await waitFor(() => expect(createGroup).toHaveBeenCalledOnce())
      expect(queryClient.getMutationCache().getAll().map((entry) => entry.options.mutationKey))
        .toContainEqual(['managed-user-group-write', platformAOwnerKey])

      await act(async () => {
        useSessionStore.getState().setSession(
          { ...authResponse(platformB), access_token: 'current-group-write-token' }, platformB,
        )
        await Promise.resolve()
      })
      await screen.findByText('Alice')
      await waitFor(() => expect(queryClient.getMutationCache().getAll().some((entry) =>
        entry.options.mutationKey?.[0] === 'managed-user-group-write' &&
        entry.options.mutationKey?.[1] === platformAOwnerKey)).toBe(false))

      await act(async () => {
        if (outcome === 'success') delayedCreate.resolve({ ...managedGroup, name: '旧平台私有组' })
        else delayedCreate.reject(new ApiError('private old group write topology', 503, 'request_failed'))
        await Promise.allSettled([delayedCreate.promise])
      })

      expect(screen.getByText('Alice')).toBeInTheDocument()
      expect(document.body).not.toHaveTextContent(/旧平台私有组|private old group/)
      expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    },
    20_000,
  )

  it.each(['successful create', 'version conflict'] as const)(
    'invalidates only the current identity prefix after a %s',
    async (outcome) => {
      const actor = principal({
        scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['identity.users.manage'],
      })
      useSessionStore.getState().setSession(authResponse(actor), actor)
      const sessionEpoch = useSessionStore.getState().sessionEpoch
      const currentOwner = ownerTuple(actor, sessionEpoch)
      const currentPrefix = ['managed-users', ...currentOwner] as const
      const foreignOwner = [
        'platform', '99999999-9999-4999-8999-999999999999', null,
        '88888888-8888-4888-8888-888888888888', 999,
      ] as const
      const foreignKey = [
        'managed-users', ...foreignOwner, 1, 10, '', undefined, undefined, undefined, '', '', '',
      ] as const
      const foreignData = listData([{ ...managedUser, display_name: 'Foreign managed user' }])
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
      })
      queryClient.setQueryData(foreignKey, foreignData)
      vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
      const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
      if (outcome === 'successful create') {
        vi.spyOn(usersApi, 'create').mockResolvedValue({ ...managedUser, username: 'bob', display_name: 'Bob' })
      } else {
        vi.spyOn(usersApi, 'update').mockRejectedValue(
          new ApiError('private stale managed user revision', 409, 'version_conflict'),
        )
      }
      const user = userEvent.setup({ delay: null })

      renderUsersWithQueryClient(queryClient)
      expect(await screen.findByText('Alice')).toBeInTheDocument()

      if (outcome === 'successful create') {
        await user.click(screen.getByRole('button', { name: '新增用户' }))
        const editor = await screen.findByRole('dialog', { name: '新增用户' })
        await user.type(within(editor).getByLabelText('用户名'), 'bob')
        await user.type(within(editor).getByLabelText('密码'), 'strong-password-123')
        await user.type(within(editor).getByLabelText('邮箱'), 'bob@example.com')
        await user.click(within(editor).getByRole('button', { name: '确定' }))
        expect(await screen.findByText('用户创建成功')).toBeInTheDocument()
      } else {
        await user.click(screen.getByRole('button', { name: '编辑' }))
        const editor = await screen.findByRole('dialog', { name: '编辑用户' })
        await user.click(within(editor).getByRole('button', { name: '确定' }))
        expect(await screen.findByText('用户信息已发生变化，列表已刷新，请重新操作')).toBeInTheDocument()
        expect(screen.queryByText('private stale managed user revision')).not.toBeInTheDocument()
      }

      const managedUserInvalidations = invalidate.mock.calls
        .map(([filters]) => filters?.queryKey)
        .filter((queryKey) => queryKey?.[0] === 'managed-users')
      expect(managedUserInvalidations).toEqual([currentPrefix])
      expect(queryClient.getQueryData(foreignKey)).toEqual(foreignData)
      expect(queryClient.getQueryState(foreignKey)?.isInvalidated).toBe(false)
    },
    20_000,
  )

  it('rechecks live platform ownership and permission immediately before dispatching a write', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['identity.users.manage'],
    })
    const revoked = { ...actor, permissions: [] }
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    const createSpy = vi.spyOn(usersApi, 'create')
    const updateSpy = vi.spyOn(usersApi, 'update')
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: '新增用户' }))
    const editor = await screen.findByRole('dialog', { name: '新增用户' })
    await user.type(within(editor).getByLabelText('用户名'), 'permission-revoked-user')
    await user.type(within(editor).getByLabelText('密码'), 'strong-password-123')
    await user.type(within(editor).getByLabelText('邮箱'), 'permission-revoked@example.com')
    const staleConfirm = within(editor).getByRole('button', { name: '确定' })

    act(() => useSessionStore.getState().setSession(
      { ...authResponse(revoked), access_token: 'revoked-user-token' }, revoked, 'refresh',
    ))
    expect(screen.getByText('无权管理用户')).toBeInTheDocument()
    fireEvent.click(staleConfirm)
    await act(async () => { await Promise.resolve() })

    expect(createSpy).not.toHaveBeenCalled()
    expect(updateSpy).not.toHaveBeenCalled()
    expect(screen.queryByText('用户创建成功')).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('permission-revoked-user')
  })

  it.each(['success', 'error'] as const)(
    'removes an old owner mutation and ignores its delayed %s settlement after a new platform session',
    async (outcome) => {
      const platformA = principal({
        scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['identity.users.manage'],
      })
      const platformB = principal({
        scope_kind: 'platform', scope_id: '77777777-7777-4777-8777-777777777777', tenant_id: null,
        user_id: '88888888-8888-4888-8888-888888888888',
        roles: ['platform_admin'], permissions: ['identity.users.manage'],
      })
      const platformBUser = {
        ...managedUser,
        id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
        display_name: 'Current platform B user',
      }
      useSessionStore.getState().setSession(
        { ...authResponse(platformA), access_token: 'old-write-owner-token' }, platformA,
      )
      const platformAOwner = ownerTuple(platformA, useSessionStore.getState().sessionEpoch)
      vi.spyOn(usersApi, 'list').mockImplementation(async (token) => (
        listData(token === 'new-write-owner-token' ? [platformBUser] : [managedUser])
      ))
      const delayedCreate = deferred<ManagedUser>()
      const createSpy = vi.spyOn(usersApi, 'create').mockReturnValue(delayedCreate.promise)
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
      })
      const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
      const user = userEvent.setup({ delay: null })

      renderUsersWithQueryClient(queryClient)
      await screen.findByText('Alice')
      await user.click(screen.getByRole('button', { name: '新增用户' }))
      const editor = await screen.findByRole('dialog', { name: '新增用户' })
      await user.type(within(editor).getByLabelText('用户名'), 'old-owner-secret-user')
      await user.type(within(editor).getByLabelText('密码'), 'old-owner-secret-password')
      await user.type(within(editor).getByLabelText('邮箱'), 'old-owner@example.com')
      await user.click(within(editor).getByRole('button', { name: '确定' }))
      await waitFor(() => expect(createSpy).toHaveBeenCalledOnce())
      expect(queryClient.getMutationCache().getAll().map((entry) => entry.options.mutationKey))
        .toContainEqual(['managed-users-write', ...platformAOwner])

      await act(async () => {
        useSessionStore.getState().setSession(
          { ...authResponse(platformB), access_token: 'new-write-owner-token' }, platformB,
        )
        await Promise.resolve()
      })
      const platformBOwner = ownerTuple(platformB, useSessionStore.getState().sessionEpoch)
      expect(await screen.findByText(platformBUser.display_name)).toBeInTheDocument()
      await waitFor(() => expect(queryClient.getMutationCache().getAll().some((entry) =>
        entry.options.mutationKey?.slice(1, 6)
          .every((value, index) => value === platformAOwner[index]))).toBe(false))
      invalidate.mockClear()

      await act(async () => {
        if (outcome === 'success') {
          delayedCreate.resolve({ ...managedUser, username: 'old-owner-secret-user' })
        } else {
          delayedCreate.reject(new ApiError('private old owner mutation failure', 503, 'request_failed'))
        }
        await Promise.allSettled([delayedCreate.promise])
      })

      expect(screen.getByText(platformBUser.display_name)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: '新增用户' })).toBeEnabled()
      expect(screen.queryByText('用户创建成功')).not.toBeInTheDocument()
      expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
      expect(document.body).not.toHaveTextContent(/old-owner-secret|Old owner private|private old owner/)
      expect(invalidate).not.toHaveBeenCalled()
      expect(queryClient.getQueryCache().getAll().some((entry) => entry.queryKey.slice(1, 6)
        .every((value, index) => value === platformAOwner[index]))).toBe(false)
      expect(queryClient.getQueryCache().getAll().some((entry) => entry.queryKey.slice(1, 6)
        .every((value, index) => value === platformBOwner[index]))).toBe(true)
    },
    20_000,
  )

  it('loads, searches, and filters the tenant user table', async () => {
    authenticateAdmin()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])

    expect(await screen.findByText('Alice')).toBeInTheDocument()
    await user.type(screen.getByLabelText('搜索用户'), 'alice{Enter}')

    await waitFor(() => {
      const url = String(fetchSpy.mock.calls.at(-1)?.[0])
      expect(url).toContain('username=alice')
      expect(url).not.toContain('search=')
      expect(url).not.toContain('status=')
      expect(url).not.toContain('role=')
    })
  })

  it('creates a tenant user with a unique idempotent request', async () => {
    authenticateAdmin()
    const created = { ...managedUser, username: 'bob', display_name: 'Bob' }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_, init) => {
      if (init?.method === 'POST') {
        return new Response(JSON.stringify(created), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      return listResponse()
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')

    await user.click(screen.getByRole('button', { name: '新增用户' }))
    await user.type(screen.getByLabelText('用户名'), 'bob')
    await user.type(screen.getByLabelText('密码'), 'strong-password-123')
    await user.type(screen.getByLabelText('邮箱'), 'bob@example.com')
    await user.type(screen.getByLabelText('备注'), '创建备注')
    await user.type(screen.getByLabelText('QQ'), '000Ab')
    await user.click(screen.getByRole('button', { name: '确定' }))

    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
    const post = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')
    expect(post?.[0]).toBe('/v1/admin/users?include=user_metadata')
    expect(post?.[1]?.headers).toEqual(expect.objectContaining({ 'Idempotency-Key': expect.any(String) }))
    expect(JSON.parse(String(post?.[1]?.body))).toEqual(
      expect.objectContaining({
        username: 'bob', email: 'bob@example.com', display_name: 'bob@example.com', role: 'tenant_owner', remark: '创建备注', qq: '000Ab',
      }),
    )
  })

  // ui-leftover3 #3：主控授权锁定时写操作回 423 installation_locked，旧页面只写「请求失败」。
  it('explains an installation lock instead of a generic request failure when creating a user', async () => {
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'POST') {
        return new Response(JSON.stringify({ error: { code: 'installation_locked', message: 'read-only', request_id: 'req-lock-1', reason: 'lease_expired', until: null } }), {
          status: 423, headers: { 'Content-Type': 'application/json' },
        })
      }
      if (String(input).startsWith('/v1/installation-lock')) return new Response(JSON.stringify({ locked: false }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      return listResponse()
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: '新增用户' }))
    await user.type(screen.getByLabelText('用户名'), 'bob')
    await user.type(screen.getByLabelText('密码'), 'strong-password-123')
    await user.type(screen.getByLabelText('邮箱'), 'bob@example.com')
    await user.click(screen.getByRole('button', { name: '确定' }))
    expect(await screen.findByText(/主控授权已锁定，后台只读/)).toBeInTheDocument()
    expect(screen.getByText(/重新检查/)).toBeInTheDocument()
    expect(screen.queryByText(/^请求失败，请稍后重试/)).not.toBeInTheDocument()
  })

  it('matches the observed create-user tabs, defaults to a normal user, and blocks unsupported fields', async () => {
    authenticateAdmin()
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [], page: 1, limit: 100, total: 0 })
    const create = vi.spyOn(usersApi, 'create')
    const user = userEvent.setup({ delay: null })

    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: '新增用户' }))

    const editor = await screen.findByRole('dialog', { name: '新增用户' })
    expect(within(editor).getAllByRole('tab').map((tab) => tab.textContent)).toEqual([
      '基础信息', '实名信息', '登录安全',
    ])
    expect(within(editor).getByRole('radio', { name: '普通用户' })).toBeChecked()
    // Read-only members belong to the tenant's own member page, not to platform user creation.
    expect(within(editor).queryByRole('radio', { name: '只读成员' })).not.toBeInTheDocument()

    await user.type(within(editor).getByLabelText('邮箱'), 'bob@example.com')
    await user.type(within(editor).getByLabelText('用户名'), 'bob')
    await user.click(within(editor).getByRole('switch', { name: '启用' }))
    await user.type(within(editor).getByLabelText('密码'), 'strong-password-123')
    await user.click(within(editor).getByRole('button', { name: '确定' }))

    expect(await within(editor).findByText('这些资料暂不能保存')).toBeInTheDocument()
    expect(create).not.toHaveBeenCalled()
  })

  it('reuses the create idempotency key when the network result is unknown', async () => {
    authenticateAdmin()
    let postCount = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_, init) => {
      if (init?.method === 'POST') {
        postCount += 1
        if (postCount === 1) throw new TypeError('connection closed')
        return new Response(JSON.stringify({ ...managedUser, username: 'bob' }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      return listResponse()
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')

    await user.click(screen.getByRole('button', { name: '新增用户' }))
    await user.type(screen.getByLabelText('用户名'), 'bob')
    await user.type(screen.getByLabelText('密码'), 'strong-password-123')
    await user.type(screen.getByLabelText('邮箱'), 'bob@example.com')
    await user.click(screen.getByRole('button', { name: '确定' }))
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(screen.getByLabelText('用户名')).toBeDisabled()
    expect(screen.getByLabelText('密码')).toBeDisabled()
    expect(screen.getByRole('button', { name: '关闭并刷新' })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))

    await waitFor(() => expect(postCount).toBe(2))
    const keys = fetchSpy.mock.calls
      .filter(([, init]) => init?.method === 'POST')
      .map(([, init]) => (init?.headers as Record<string, string>)['Idempotency-Key'])
    expect(keys[0]).toBe(keys[1])
    const requestIds = fetchSpy.mock.calls
      .filter(([, init]) => init?.method === 'POST')
      .map(([, init]) => new Headers(init?.headers).get('X-Request-ID'))
    const traces = fetchSpy.mock.calls
      .filter(([, init]) => init?.method === 'POST')
      .map(([, init]) => new Headers(init?.headers).get('Traceparent'))
    expect(requestIds[0]).toBe(requestIds[1])
    expect(traces[0]).toBe(traces[1])
    const bodies = fetchSpy.mock.calls
      .filter(([, init]) => init?.method === 'POST')
      .map(([, init]) => init?.body)
    expect(bodies[0]).toBe(bodies[1])
  })

  it('preserves the revision when disabling a user through the competitor-aligned edit form', async () => {
    authenticateAdmin()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_, init) => {
      if (init?.method === 'PATCH') {
        return new Response(JSON.stringify({ ...managedUser, status: 'disabled', revision: 2 }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      return listResponse()
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')

    await user.click(screen.getByRole('button', { name: '编辑' }))
    const editor = await screen.findByRole('dialog', { name: '编辑用户' })
    await user.click(within(editor).getByRole('switch', { name: '启用' }))
    await user.click(within(editor).getByRole('button', { name: '确定' }))

    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(true))
    const patchCall = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')
    expect(JSON.parse(String(patchCall?.[1]?.body))).toEqual(
      expect.objectContaining({ expected_revision: 1, status: 'disabled' }),
    )
  })

  it('changes a tenant user type from the edit form', async () => {
    authenticateAdmin()
    const viewer = { ...managedUser, role: 'tenant_viewer' as const }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_, init) => {
      if (init?.method === 'PATCH') {
        return new Response(JSON.stringify({ ...viewer, role: 'tenant_owner', revision: 2 }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      return listResponse([viewer])
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')

    await user.click(screen.getByRole('button', { name: '编辑' }))
    const editor = await screen.findByRole('dialog', { name: '编辑用户' })
    expect(within(editor).getByRole('radio', { name: '只读成员' })).toBeChecked()
    await user.click(within(editor).getByText('普通用户'))
    await user.click(within(editor).getByRole('button', { name: '确定' }))

    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(true))
    const patchCall = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PATCH')
    expect(JSON.parse(String(patchCall?.[1]?.body))).toEqual(
      expect.objectContaining({ expected_revision: 1, role: 'tenant_owner', status: 'active' }),
    )
  })

  it('batch disables selected users with revisions and one stable request identity', async () => {
    authenticateAdmin()
    const updated = { ...managedUser, status: 'disabled' as const, revision: 2 }
    let writes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_, init) => {
      if (init?.method === 'PATCH') {
        writes += 1
        if (writes === 1) throw new TypeError('response lost after commit')
        return new Response(JSON.stringify({ items: [updated] }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      return listResponse()
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')

    const rowCheckboxes = screen.getAllByRole('checkbox')
    await user.click(rowCheckboxes[rowCheckboxes.length - 1])
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    await user.click(await screen.findByText('批量禁用'))
    expect(screen.getByText('批量禁用 1 个用户？')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '确认批量禁用' }))

    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(writes).toBe(2))
    const calls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')
    expect(JSON.parse(String(calls[0][1]?.body))[0]).not.toHaveProperty('remark')
    expect(JSON.parse(String(calls[0][1]?.body))[0]).not.toHaveProperty('qq')
    expect(JSON.parse(String(calls[0][1]?.body))).toEqual([expect.objectContaining({
      id: managedUser.id,
      expected_revision: 1,
      status: 'disabled',
    })])
    for (const name of ['Idempotency-Key', 'X-Request-ID', 'Traceparent']) {
      expect(new Headers(calls[1][1]?.headers).get(name)).toBe(new Headers(calls[0][1]?.headers).get(name))
    }
  })

  it('deletes one selected user with the immutable revision and retries an unknown outcome', async () => {
    authenticateAdmin()
    let deleteAttempts = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'DELETE') {
        deleteAttempts += 1
        if (deleteAttempts === 1) throw new TypeError('response lost after commit')
        return new Response(null, { status: 204 })
      }
      if (url.includes('/v1/admin/user-groups')) {
        return new Response(JSON.stringify({ items: [], page: 1, limit: 100, total: 0 }), {
          status: 200, headers: { 'Content-Type': 'application/json' },
        })
      }
      return deleteAttempts > 1 ? listResponse([], 0) : listResponse()
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')

    const rowCheckboxes = screen.getAllByRole('checkbox')
    await user.click(rowCheckboxes[rowCheckboxes.length - 1])
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    await user.click(await screen.findByText('删除'))
    expect(screen.getByText('删除用户？')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '确认删除' }))

    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    await user.click(screen.getAllByRole('button', { name: '使用同一请求重试' }).at(-1)!)
    await waitFor(() => expect(deleteAttempts).toBe(2))
    await waitFor(() => expect(screen.queryByText('Alice')).not.toBeInTheDocument())

    const deleteCalls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'DELETE')
    expect(JSON.parse(String(deleteCalls[0][1]?.body))).toEqual({ expected_revision: managedUser.revision })
    for (const name of ['Idempotency-Key', 'X-Request-ID', 'Traceparent']) {
      expect(new Headers(deleteCalls[1][1]?.headers).get(name)).toBe(new Headers(deleteCalls[0][1]?.headers).get(name))
    }
  })

  it('filters and assigns users with the independent platform group identity', async () => {
    authenticateAdmin()
    const listUsers = vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    vi.spyOn(usersApi, 'listGroups').mockImplementation(async (_token, page, limit) => ({
      items: [managedGroup], page, limit, total: 1,
    }))
    const updateUser = vi.spyOn(usersApi, 'update').mockResolvedValue({
      ...managedUser,
      group_id: managedGroup.id,
      group_name: managedGroup.name,
      revision: 2,
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')

    await user.click(screen.getByRole('combobox', { name: '筛选用户组' }))
    await user.click(await screen.findByText(managedGroup.name, { selector: '.ant-select-item-option-content' }))
    await waitFor(() => expect(listUsers.mock.calls.some(([, params]) => params.group_id === managedGroup.id)).toBe(true))

    await user.click(screen.getByRole('button', { name: '编辑' }))
    const modal = await screen.findByRole('dialog', { name: '编辑用户' })
    await user.click(within(modal).getByRole('combobox', { name: '用户分组' }))
    const groupOptions = await screen.findAllByText(managedGroup.name, { selector: '.ant-select-item-option-content' })
    await user.click(groupOptions[groupOptions.length - 1])
    await user.click(within(modal).getByRole('button', { name: '确定' }))

    await waitFor(() => expect(updateUser).toHaveBeenCalledOnce())
    expect(updateUser.mock.calls[0][2]).toEqual(expect.objectContaining({ group_id: managedGroup.id }))
  })

  it('renders group loading, recovers from a localized list error, and reaches the empty state', async () => {
    authenticateAdmin()
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    let panelReads = 0
    const firstPanelRead = deferred<{ items: UserGroup[]; page: number; limit: number; total: number }>()
    vi.spyOn(usersApi, 'listGroups').mockImplementation(async (_token, page, limit) => {
      if (limit === 100) return { items: [], page, limit, total: 0 }
      panelReads += 1
      if (panelReads === 1) return firstPanelRead.promise
      return { items: [], page, limit, total: 0 }
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')

    await user.click(screen.getByRole('tab', { name: '用户分组' }))
    expect(document.querySelector('.identity-groups .identity-table-scroll')).toHaveAttribute('aria-busy', 'true')
    await act(async () => firstPanelRead.reject(new ApiError('private group shard', 503, 'request_failed')))
    expect(await screen.findByText('用户组加载失败')).toBeInTheDocument()
    expect(screen.getByText('请求失败，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('private group shard')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无用户组')).toBeInTheDocument()
    expect(panelReads).toBe(2)
  })

  it('labels the group name field and explains an empty submit without sending it', async () => {
    authenticateAdmin()
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    vi.spyOn(usersApi, 'listGroups').mockImplementation(async (_token, page, limit) => ({ items: [], page, limit, total: 0 }))
    const createGroup = vi.spyOn(usersApi, 'createGroup')
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('tab', { name: '用户分组' }))
    await user.click(await screen.findByRole('button', { name: '添加用户组' }))
    const modal = await screen.findByRole('dialog', { name: '添加用户组' })
    expect(within(modal).getByText('用户组名称')).toBeInTheDocument()
    await user.click(within(modal).getByRole('button', { name: '确定' }))
    expect(await within(modal).findByText('请输入用户组名称')).toBeInTheDocument()
    expect(createGroup).not.toHaveBeenCalled()
  })

  it('retries an unknown group create with the exact immutable request and then refreshes', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['identity.users.manage'],
    })
    useSessionStore.getState().setSession(
      { ...authResponse(actor), access_token: 'old-group-retry-token' }, actor,
    )
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    let groups: UserGroup[] = []
    vi.spyOn(usersApi, 'listGroups').mockImplementation(async (_token, page, limit) => ({
      items: groups, page, limit, total: groups.length,
    }))
    const createGroup = vi.spyOn(usersApi, 'createGroup')
      .mockRejectedValueOnce(new ApiError('private commit topology', 503, 'request_failed'))
      .mockImplementationOnce(async (_token, name) => {
        const created = { ...managedGroup, name }
        groups = [created]
        return created
      })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('tab', { name: '用户分组' }))
    expect(await screen.findByText('暂无用户组')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '添加用户组' }))
    const modal = await screen.findByRole('dialog', { name: '添加用户组' })
    await user.type(within(modal).getByLabelText('用户组名称'), '运维组')
    await user.click(within(modal).getByRole('button', { name: '确定' }))
    expect(await within(modal).findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(within(modal).queryByText('private commit topology')).not.toBeInTheDocument()
    expect(within(modal).getByLabelText('用户组名称')).toBeDisabled()
    expect(within(modal).getByRole('button', { name: '关闭并刷新' })).toBeEnabled()

    await act(async () => {
      useSessionStore.getState().setSession(
        { ...authResponse(actor), access_token: 'new-group-retry-token' }, actor, 'refresh',
      )
      await Promise.resolve()
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(screen.getByRole('dialog', { name: '添加用户组' })).toBe(modal)

    await user.click(within(modal).getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('运维组')).toBeInTheDocument()
    expect(createGroup).toHaveBeenCalledTimes(2)
    expect(createGroup.mock.calls[0][0]).toBe('old-group-retry-token')
    expect(createGroup.mock.calls[1][0]).toBe('new-group-retry-token')
    expect(createGroup.mock.calls[1][1]).toBe(createGroup.mock.calls[0][1])
    expect(createGroup.mock.calls[1][2]).toBe(createGroup.mock.calls[0][2])
  })

  it('keeps group CAS and in-use failures localized and editable', async () => {
    authenticateAdmin()
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    vi.spyOn(usersApi, 'listGroups').mockImplementation(async (_token, page, limit) => ({
      items: [managedGroup], page, limit, total: 1,
    }))
    vi.spyOn(usersApi, 'updateGroup').mockRejectedValue(
      new ApiError('private stale group revision', 409, 'version_conflict'),
    )
    vi.spyOn(usersApi, 'deleteGroup').mockRejectedValue(
      new ApiError('private membership row', 409, 'user_group_in_use'),
    )
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('tab', { name: '用户分组' }))
    await screen.findByText(managedGroup.name)

    await user.click(screen.getByRole('button', { name: '编辑' }))
    const modal = await screen.findByRole('dialog', { name: '编辑用户组' })
    await user.clear(within(modal).getByLabelText('用户组名称'))
    await user.type(within(modal).getByLabelText('用户组名称'), '支持组')
    await user.click(within(modal).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('用户信息已发生变化，请刷新后重试')).toBeInTheDocument()
    expect(pageDialogs('编辑用户组')).toHaveLength(0)
    expect(screen.queryByText('private stale group revision')).not.toBeInTheDocument()
    await screen.findByText(managedGroup.name)

    await user.click(screen.getByRole('button', { name: '删除' }))
    await user.click(await screen.findByRole('button', { name: '确认删除' }))
    expect(await screen.findByText('用户组仍有成员，无法删除')).toBeInTheDocument()
    expect(screen.queryByText('private membership row')).not.toBeInTheDocument()
  })

  it('abandons an unknown group write without redispatch and refreshes authoritative state', async () => {
    authenticateAdmin()
    vi.spyOn(usersApi, 'list').mockResolvedValue(listData())
    const listGroups = vi.spyOn(usersApi, 'listGroups').mockImplementation(async (_token, page, limit) => ({
      items: [], page, limit, total: 0,
    }))
    const createGroup = vi.spyOn(usersApi, 'createGroup').mockRejectedValue(
      new ApiError('private lost group response', 503, 'request_failed'),
    )
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('tab', { name: '用户分组' }))
    await screen.findByText('暂无用户组')
    const readsBeforeWrite = listGroups.mock.calls.length

    await user.click(screen.getByRole('button', { name: '添加用户组' }))
    const modal = await screen.findByRole('dialog', { name: '添加用户组' })
    await user.type(within(modal).getByLabelText('用户组名称'), '待确认组')
    await user.click(within(modal).getByRole('button', { name: '确定' }))
    expect(await within(modal).findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    await user.click(within(modal).getByRole('button', { name: '关闭并刷新' }))

    await waitFor(() => expect(listGroups.mock.calls.length).toBeGreaterThan(readsBeforeWrite))
    expect(screen.queryByRole('dialog', { name: '添加用户组' })).not.toBeInTheDocument()
    expect(createGroup).toHaveBeenCalledOnce()
    expect(document.body).not.toHaveTextContent(/待确认组|private lost group response/)
  })

  it('renders permission denial separately from server errors', async () => {
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: { code: 'permission_denied', message: 'permission is required' } }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderWithProviders(<UserListPage />, ['/sys/user'])

    expect(await screen.findByText('无权管理用户')).toBeInTheDocument()
    expect(screen.getByText('当前账号缺少用户管理权限')).toBeInTheDocument()
    expect(screen.queryByText('permission is required')).not.toBeInTheDocument()
    expect(screen.queryByText('用户列表加载失败')).not.toBeInTheDocument()
  })
})

describe('UserListPage platform administrators', () => {
  const selfAdmin: PlatformAdministratorUser = {
    ...managedUser,
    id: '11111111-1111-4111-8111-111111111111',
    display_id: '2',
    scope_id: '22222222-2222-4222-8222-222222222222',
    tenant_id: null,
    username: 'admin',
    display_name: 'admin',
    email: 'admin@example.com',
    role: 'platform_owner',
  }
  const otherAdmin: PlatformAdministratorUser = {
    ...selfAdmin, id: '33333333-3333-4333-8333-333333333333', display_id: '3', username: 'ops', display_name: 'ops',
    email: 'ops@example.com', role: 'platform_admin',
  }

  function mockList() {
    const items = [managedUser, selfAdmin, otherAdmin]
    const list = vi.spyOn(usersApi, 'list').mockResolvedValue({ items, page: 1, limit: 10, total: items.length } as never)
    vi.spyOn(usersApi, 'listGroups').mockResolvedValue({ items: [managedGroup], page: 1, limit: 100, total: 1 })
    const security = vi.spyOn(usersApi, 'getLoginSecurity').mockImplementation(async (_token, userID, scopeID) => ({
      user_id: userID, tenant_scope_id: scopeID, revision: 0, login_verification: 'none', login_allowlist: [],
    }))
    return { list, security }
  }

  function rowOf(username: string): HTMLElement {
    return screen.getByText(username, { selector: '[title]' }).closest('tr') as HTMLElement
  }

  it('lists administrators with the administrator badge and keeps tenant rows unchanged', async () => {
    authenticateAdmin()
    const { list } = mockList()
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('admin@example.com')
    expect(list).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ include_platform_admins: true }))
    expect(within(rowOf('admin')).getByText('平台管理员')).toBeInTheDocument()
    expect(within(rowOf('admin')).getByText('我')).toBeInTheDocument()
    expect(within(rowOf('ops')).getByText('平台运维管理员')).toBeInTheDocument()
    expect(within(rowOf('alice')).getByText('普通用户')).toBeInTheDocument()
    expect(within(rowOf('alice')).getByRole('button', { name: '切换' })).toBeInTheDocument()
    expect(within(rowOf('admin')).queryByRole('button', { name: '切换' })).not.toBeInTheDocument()
    expect(screen.getByText('共 3 条')).toBeInTheDocument()
  })

  it('locks administrator type, group, password and login security in the editor', async () => {
    authenticateAdmin()
    const { security } = mockList()
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('admin@example.com')
    await user.click(within(rowOf('ops')).getByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑用户' })
    expect(security).not.toHaveBeenCalled()
    expect(within(dialog).getByText(/这是平台管理员账号/)).toBeInTheDocument()
    expect(within(dialog).getByPlaceholderText('请输入密码')).toBeDisabled()
    expect(within(dialog).getByRole('tab', { name: '登录安全' })).toHaveAttribute('aria-disabled', 'true')
    expect(within(dialog).getByRole('combobox')).toBeDisabled()
  })

  it('blocks deleting yourself and confirms before disabling yourself', async () => {
    authenticateAdmin()
    mockList()
    const update = vi.spyOn(usersApi, 'update').mockResolvedValue({ ...selfAdmin, status: 'disabled', revision: 2 })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('admin@example.com')
    await user.click(within(rowOf('admin')).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    expect((await screen.findByText('删除')).closest('li')).toHaveAttribute('aria-disabled', 'true')
    await user.keyboard('{Escape}')

    await user.click(within(rowOf('admin')).getByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑用户' })
    await user.click(within(dialog).getByRole('switch'))
    expect(within(dialog).getByText(/你正在禁用当前登录的管理员账号/)).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect((await screen.findAllByText('禁用自己的账号？')).length).toBeGreaterThan(0)
    expect(update).not.toHaveBeenCalled()
    const confirmButtons = await screen.findAllByRole('button', { name: '确认禁用自己' })
    expect(confirmButtons).toHaveLength(1)
    await user.click(confirmButtons[0])
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0][2]).toMatchObject({ status: 'disabled', role: 'platform_owner', group_id: null })
  })

  it('shows the protection error when the backend refuses an administrator change', async () => {
    authenticateAdmin()
    mockList()
    vi.spyOn(usersApi, 'update').mockRejectedValue(new ApiError('protected', 409, 'user_protected'))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('admin@example.com')
    await user.click(within(rowOf('ops')).getByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑用户' })
    await user.click(within(dialog).getByRole('switch'))
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText(/该操作被管理员保护规则拒绝/)).toBeInTheDocument()
  })
})
