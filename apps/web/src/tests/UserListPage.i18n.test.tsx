import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { usersApi, type ManagedUser, type UserGroup, type UserListResponse } from '../api/users'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import UserListPage from '../pages/UserListPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

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
  name: 'Operations',
  revision: 1,
  member_count: 2,
  created_at: '2026-07-22T08:00:00Z',
  updated_at: '2026-07-22T08:00:00Z',
}

function authenticateAdmin() {
  const admin = principal({
    scope_kind: 'platform',
    tenant_id: null,
    username: 'admin',
    display_name: 'admin',
    roles: ['platform_admin'],
    permissions: ['identity.users.manage'],
  })
  useSessionStore.getState().setSession(authResponse(admin), admin)
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function listResponse(items = [managedUser], total = items.length): Response {
  // 用户列表固定带 user_metadata / user_verification，响应里每行都有 metadata 与 verification。
  const body: UserListResponse = {
    items: items.map((item) => ({
      ...item, verification: { personal_verified: false, company_verified: false },
    })),
    page: 1, limit: 10, total,
  }
  return json(body)
}

async function fillCreateForm(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Add user' }))
  const dialog = await screen.findByRole('dialog', { name: 'Add user' })
  await user.type(within(dialog).getByLabelText('Username'), 'bob')
  await user.type(within(dialog).getByLabelText('Password'), 'strong-password-123')
  await user.type(within(dialog).getByLabelText('Email'), 'bob@example.com')
  return dialog
}

describe('UserListPage internationalization', () => {
  // 编辑弹窗打开时会读所选租户用户的登录安全设置和二次实名请求（GET .../login-security、.../secondary-verification）。
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

  it('renders qps-ploc loading and empty states through the existing users namespace', async () => {
    await changeLocale('qps-ploc')
    authenticateAdmin()
    let resolveList!: (value: Response) => void
    const pendingList = new Promise<Response>((resolve) => { resolveList = resolve })
    vi.spyOn(globalThis, 'fetch').mockReturnValue(pendingList)

    renderWithProviders(<UserListPage />, ['/sys/user'])

    expect(document.querySelector('.identity-table-scroll')).toHaveAttribute('aria-busy', 'true')
    await act(async () => resolveList(listResponse([])))
    expect(await screen.findByText('［暂~无~数~据~］')).toBeInTheDocument()
    expect(document.querySelector('.identity-table-scroll')).toHaveAttribute('aria-busy', 'false')
  })

  it('localizes an ordinary qps-ploc error and retries without exposing the raw server message', async () => {
    await changeLocale('qps-ploc')
    authenticateAdmin()
    let userReads = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      if (String(input).includes('/v1/admin/user-groups')) {
        return Promise.resolve(json({ items: [], page: 1, limit: 100, total: 0 }))
      }
      userReads += 1
      return Promise.resolve(userReads === 1
        ? json({ error: { code: 'directory_unavailable', message: 'private directory shard' } }, 503)
        : listResponse([]))
    })
    const user = userEvent.setup()

    renderWithProviders(<UserListPage />, ['/sys/user'])

    expect(await screen.findByText('［用~户~列~表~加~载~失~败~］')).toBeInTheDocument()
    expect(screen.getByText('［请~求~失~败~，~请~稍~后~重~试~］')).toBeInTheDocument()
    expect(screen.queryByText('private directory shard')).not.toBeInTheDocument()
    expect(screen.queryByText('［暂~无~数~据~］')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '［重~试~］' }))
    expect(await screen.findByText('［暂~无~数~据~］')).toBeInTheDocument()
    expect(userReads).toBe(2)
  })

  it('renders the local users qps-ploc 403 without mounting the table or issuing a request', async () => {
    await changeLocale('qps-ploc')
    const tenant = principal({ permissions: ['identity.users.manage'] })
    useSessionStore.getState().setSession(authResponse(tenant), tenant)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<UserListPage />, ['/sys/user'])

    expect(await screen.findByText('［无~权~管~理~用~户~］')).toBeInTheDocument()
    expect(screen.getByText('［当~前~账~号~缺~少~用~户~管~理~权~限~］')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('renders the table, filters, locale date, and form validation in English', async () => {
    await changeLocale('en-US')
    authenticateAdmin()
    // 每次新建 Response：搜索会再读一次列表，复用同一个 Response 第二次读到的是已消费的 body
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => listResponse([managedUser], 1000))
    const user = userEvent.setup()

    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')

    expect(screen.getByRole('columnheader', { name: 'User information' })).toBeInTheDocument()
    expect(screen.getByText('Customer')).toBeInTheDocument()
    expect(screen.getByText('07/22/2026, 16:00:00')).toBeInTheDocument()
    expect(screen.getByText('1,000 total')).toBeInTheDocument()
    expect(screen.getByLabelText('Search users')).toHaveAttribute('placeholder', 'Enter username')
    await user.type(screen.getByLabelText('Search users'), 'alice{Enter}')
    await waitFor(() => {
      const url = String(fetchSpy.mock.calls.at(-1)?.[0])
      // 搜索框按用户名精确筛选（username=），占位文案「请输入用户名」。
      expect(url).toContain('username=alice')
      expect(url).not.toContain('search=')
      expect(url).not.toContain('status=')
      expect(url).not.toContain('role=')
    })

    await user.click(screen.getByRole('button', { name: 'Add user' }))
    const dialog = await screen.findByRole('dialog', { name: 'Add user' })
    await user.click(within(dialog).getByRole('button', { name: 'Confirm' }))
    expect(await within(dialog).findByText('Enter an email address')).toBeInTheDocument()
    expect(await within(dialog).findByText('Enter a username')).toBeInTheDocument()
    expect(within(dialog).getByText('Enter an initial password')).toBeInTheDocument()
  })

  it.each([
    ['en-US', 'Edit', 'Password', 'Confirm', 'Reset password for Alice', 'New password'],
    ['qps-ploc', '［编~辑~］', '［密~码~］', '［确~定~］', '［重~置~ Alice 的~密~码~］', '［新~密~码~］'],
  ] as const)('renders the administrator password reset workflow in %s', async (
    locale, editAction, formPasswordLabel, confirmAction, title, passwordLabel,
  ) => {
    await changeLocale(locale)
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(
      String(input).includes('/v1/admin/user-groups')
        ? json({ items: [], page: 1, limit: 100, total: 0 })
        : listResponse(),
    ))
    const user = userEvent.setup()
    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: editAction }))
    const editor = await screen.findByRole('dialog')
    await user.type(within(editor).getByLabelText(formPasswordLabel), 'replacement-password-long-enough')
    await user.click(within(editor).getByRole('button', { name: confirmAction }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveAccessibleName(title)
    expect(within(dialog).getByLabelText(passwordLabel)).toHaveAttribute('type', 'password')
  })

  it('renders the user-group tab, table, and actions in English', async () => {
    await changeLocale('en-US')
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.includes('/v1/admin/user-groups')) {
        const parsed = new URL(url, 'http://cdnca.test')
        const limit = Number(parsed.searchParams.get('limit'))
        return json({ items: [managedGroup], page: 1, limit, total: 1 })
      }
      return listResponse()
    })
    const user = userEvent.setup()

    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('tab', { name: 'User groups' }))

    expect(await screen.findByText(managedGroup.name)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add user group' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Group name' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Members' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete' })).toBeDisabled()
  })

  it('localizes a qps-ploc user-group error and hides the raw server message', async () => {
    await changeLocale('qps-ploc')
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.includes('/v1/admin/user-groups')) {
        const parsed = new URL(url, 'http://cdnca.test')
        const limit = Number(parsed.searchParams.get('limit'))
        if (limit === 100) return json({ items: [], page: 1, limit, total: 0 })
        return json({ error: { code: 'directory_unavailable', message: 'private group replica' } }, 503)
      }
      return listResponse()
    })
    const user = userEvent.setup()

    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('tab', { name: '［用~户~分~组~］' }))

    expect(await screen.findByText('［用~户~组~加~载~失~败~］')).toBeInTheDocument()
    expect(screen.getByText('［请~求~失~败~，~请~稍~后~重~试~］')).toBeInTheDocument()
    expect(screen.queryByText('private group replica')).not.toBeInTheDocument()
  })

  it('creates a user successfully with English feedback', async () => {
    await changeLocale('en-US')
    authenticateAdmin()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_, init) => {
      if (init?.method === 'POST') {
        return Promise.resolve(json({ ...managedUser, username: 'bob', display_name: 'Bob' }, 201))
      }
      return Promise.resolve(listResponse())
    })
    const user = userEvent.setup()

    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    const dialog = await fillCreateForm(user)
    await user.click(within(dialog).getByRole('button', { name: 'Confirm' }))

    expect(await screen.findByText('User created')).toBeInTheDocument()
    const post = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')
    expect(post?.[1]?.headers).toEqual(expect.objectContaining({
      'Idempotency-Key': expect.stringMatching(/^create-user-/),
    }))
  })

  it('renders empty and locale-aware total states in English', async () => {
    await changeLocale('en-US')
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse([]))

    renderWithProviders(<UserListPage />, ['/sys/user'])
    expect(await screen.findByText('No data')).toBeInTheDocument()
    expect(screen.getByText('0 total')).toBeInTheDocument()
  })

  it('localizes list and forbidden errors without server message leakage', async () => {
    await changeLocale('en-US')
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({
      error: { code: 'directory_unavailable', message: 'internal replica topology' },
    }, 503))

    const first = renderWithProviders(<UserListPage />, ['/sys/user'])
    expect(await screen.findByText('Failed to load the user list')).toBeInTheDocument()
    expect(screen.getByText('Request failed. Try again later.')).toBeInTheDocument()
    expect(screen.queryByText('internal replica topology')).not.toBeInTheDocument()
    first.unmount()

    vi.restoreAllMocks()
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'permission_denied', message: 'internal permission rule' },
    }, 403))
    renderWithProviders(<UserListPage />, ['/sys/user'])
    expect(await screen.findByText('You cannot manage users')).toBeInTheDocument()
    expect(screen.getByText('Your account does not have user management permission')).toBeInTheDocument()
    expect(screen.queryByText('internal permission rule')).not.toBeInTheDocument()
  })

  it('localizes a stable write error and keeps the form editable', async () => {
    await changeLocale('en-US')
    authenticateAdmin()
    vi.spyOn(globalThis, 'fetch').mockImplementation((_, init) => {
      if (init?.method === 'POST') {
        return Promise.resolve(json({
          error: { code: 'username_conflict', message: 'internal conflicting user ID' },
        }, 409))
      }
      return Promise.resolve(listResponse())
    })
    const user = userEvent.setup()

    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    const dialog = await fillCreateForm(user)
    await user.click(within(dialog).getByRole('button', { name: 'Confirm' }))

    expect(await within(dialog).findByText('That username already exists. Choose another username.')).toBeInTheDocument()
    expect(within(dialog).queryByText('internal conflicting user ID')).not.toBeInTheDocument()
    expect(within(dialog).getByLabelText('Username')).toBeEnabled()
  })

  it('refreshes after a revision conflict and hides the server message', async () => {
    await changeLocale('en-US')
    authenticateAdmin()
    let reads = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((_, init) => {
      if (init?.method === 'PATCH') {
        return Promise.resolve(json({
          error: { code: 'version_conflict', message: 'internal stale revision' },
        }, 409))
      }
      reads += 1
      return Promise.resolve(listResponse([
        reads > 1 ? { ...managedUser, display_name: 'Alice Fresh', revision: 2 } : managedUser,
      ]))
    })
    const user = userEvent.setup()

    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    await user.click(screen.getByRole('button', { name: 'Edit' }))
    const editor = await screen.findByRole('dialog', { name: 'Edit user' })
    await user.click(within(editor).getByRole('switch', { name: 'Enabled' }))
    await user.click(within(editor).getByRole('button', { name: 'Confirm' }))

    expect(await screen.findByText('The user changed in another operation. The list has been refreshed; try again.')).toBeInTheDocument()
    expect(await screen.findByText('Alice Fresh')).toBeInTheDocument()
    expect(screen.queryByText('internal stale revision')).not.toBeInTheDocument()
  })

  it('locks an unknown write to the exact body and key before English retry', async () => {
    await changeLocale('en-US')
    authenticateAdmin()
    let posts = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_, init) => {
      if (init?.method === 'POST') {
        posts += 1
        if (posts === 1) {
          return Promise.resolve(json({
            error: { code: 'user_store_unavailable', message: 'internal primary database host' },
          }, 503))
        }
        return Promise.resolve(json({ ...managedUser, username: 'bob' }, 201))
      }
      return Promise.resolve(listResponse())
    })
    const user = userEvent.setup()

    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    const dialog = await fillCreateForm(user)
    await user.click(within(dialog).getByRole('button', { name: 'Confirm' }))

    expect(await within(dialog).findByText('Operation outcome unknown')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('Username')).toBeDisabled()
    expect(within(dialog).getByLabelText('Password')).toBeDisabled()
    expect(within(dialog).queryByText('internal primary database host')).not.toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Close and refresh' })).toBeEnabled()
    await user.click(within(dialog).getByRole('button', { name: 'Retry the same request' }))
    expect(await screen.findByText('User created')).toBeInTheDocument()

    const writes = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')
    expect(writes).toHaveLength(2)
    expect(writes[0][1]?.body).toBe(writes[1][1]?.body)
    expect((writes[0][1]?.headers as Record<string, string>)['Idempotency-Key']).toBe(
      (writes[1][1]?.headers as Record<string, string>)['Idempotency-Key'],
    )
  })

  it('closes an unknown modal and refreshes without sending a second write', async () => {
    await changeLocale('en-US')
    authenticateAdmin()
    let reads = 0
    let posts = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((_, init) => {
      if (init?.method === 'POST') {
        posts += 1
        return Promise.reject(new TypeError('connection lost'))
      }
      reads += 1
      return Promise.resolve(listResponse())
    })
    const user = userEvent.setup()

    renderWithProviders(<UserListPage />, ['/sys/user'])
    await screen.findByText('Alice')
    const dialog = await fillCreateForm(user)
    await user.click(within(dialog).getByRole('button', { name: 'Confirm' }))
    expect(await within(dialog).findByText('Operation outcome unknown')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Close and refresh' }))

    await waitFor(() => expect(reads).toBeGreaterThan(1))
    expect(screen.queryByRole('dialog', { name: 'Add user' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add user' })).toBeEnabled()
    expect(posts).toBe(1)
  })
})
