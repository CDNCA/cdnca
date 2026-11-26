import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ApiError, type Principal } from '../api/auth'
import { customRbacApi } from '../api/customRbac'
import { tenantMembersApi } from '../api/tenantMembers'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import CustomRolesPage from '../pages/CustomRolesPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const scopeID = '22222222-2222-4222-8222-222222222222'
const roleID = '33333333-3333-4333-8333-333333333333'
const userID = '44444444-4444-4444-8444-444444444444'
const grantID = '55555555-5555-4555-8555-555555555555'
const proof = 'a'.repeat(43)
const role = {
  id: roleID, name: '站点运维', current_revision: 3, permissions: ['sites.read'],
  created_at: '2026-08-08T08:00:00Z',
}
const grant = {
  id: grantID, role_id: roleID, role_revision: 3, subject_user_id: userID,
  granted_by_user_id: '66666666-6666-4666-8666-666666666666', granted_at: '2026-08-08T08:10:00Z',
}
const permissions = {
  data: [
    { name: 'sites.read', step_up_required: false },
    { name: 'sites.manage', step_up_required: true },
  ],
}

function tenantActor(overrides: Partial<Principal> = {}): Principal {
  return principal({
    user_id: '77777777-7777-4777-8777-777777777777', scope_id: scopeID,
    scope_kind: 'tenant', tenant_id: '88888888-8888-4888-8888-888888888888',
    roles: ['tenant_owner'], permissions: ['identity.roles.manage'], ...overrides,
  })
}

function authenticate(actor = tenantActor(), token = 'custom-rbac-token') {
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor)
}

function mockReads() {
  const permissionRead = vi.spyOn(customRbacApi, 'listPermissions').mockResolvedValue(permissions)
  const roleRead = vi.spyOn(customRbacApi, 'listRoles').mockResolvedValue({ data: [role], page: {} })
  const grantRead = vi.spyOn(customRbacApi, 'listGrants').mockResolvedValue({ data: [grant], page: {} })
  return { permissionRead, roleRead, grantRead }
}

async function openCreate(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: '新建角色' }))
  return screen.findByRole('dialog', { name: '新建自定义角色' })
}

describe('CustomRolesPage', () => {
  beforeEach(async () => {
    vi.restoreAllMocks()
    await i18n.changeLanguage('zh-CN')
    authenticate()
  })

  it.each([
    ['platform actor even with the permission', tenantActor({ scope_kind: 'platform', tenant_id: null })],
    ['tenant actor without identity.roles.manage', tenantActor({ permissions: [] })],
  ])('fails closed locally for %s with zero custom-RBAC calls', async (_case, actor) => {
    authenticate(actor)
    const calls = [
      vi.spyOn(customRbacApi, 'listPermissions'), vi.spyOn(customRbacApi, 'listRoles'),
      vi.spyOn(customRbacApi, 'listGrants'), vi.spyOn(customRbacApi, 'createRole'),
      vi.spyOn(customRbacApi, 'renameRole'), vi.spyOn(customRbacApi, 'publishRole'),
      vi.spyOn(customRbacApi, 'deactivateRole'), vi.spyOn(customRbacApi, 'assignGrant'),
      vi.spyOn(customRbacApi, 'revokeGrant'),
    ]

    renderWithProviders(<CustomRolesPage />, ['/sys/custom-roles'])

    expect(await screen.findByText('无权管理自定义角色')).toBeInTheDocument()
    for (const call of calls) expect(call).not.toHaveBeenCalled()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('renders loading, localized error and retry, then natural empty states', async () => {
    let reject!: (reason: unknown) => void
    const pending = new Promise<never>((_resolve, fail) => { reject = fail })
    vi.spyOn(customRbacApi, 'listPermissions').mockResolvedValue(permissions)
    const roles = vi.spyOn(customRbacApi, 'listRoles')
      .mockReturnValueOnce(pending)
      .mockResolvedValueOnce({ data: [], page: {} })
    vi.spyOn(customRbacApi, 'listGrants').mockResolvedValue({ data: [], page: {} })

    renderWithProviders(<CustomRolesPage />, ['/sys/custom-roles'])
    expect(screen.getByLabelText('正在加载自定义角色')).toBeInTheDocument()
    await act(async () => reject(new ApiError('private database topology', 503, 'custom_rbac_store_unavailable')))
    expect(await screen.findByText('自定义角色服务暂不可用，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('private database topology')).not.toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无自定义角色')).toBeInTheDocument()
    expect(screen.getByText('暂无用户角色授权')).toBeInTheDocument()
    expect(roles).toHaveBeenCalledTimes(2)
  })

  it('shows permission codes by their Chinese names and keeps the code as a tooltip (W4)', async () => {
    vi.spyOn(customRbacApi, 'listPermissions').mockResolvedValue(permissions)
    vi.spyOn(customRbacApi, 'listRoles').mockResolvedValue({ data: [role], page: {} })
    vi.spyOn(customRbacApi, 'listGrants').mockResolvedValue({ data: [], page: {} })
    renderWithProviders(<CustomRolesPage />, ['/sys/custom-roles'])
    await screen.findAllByText('站点运维')
    const names = screen.getAllByText('查看网站')
    expect(names.length).toBeGreaterThanOrEqual(1)
    expect(names.every((node) => node.closest('[title="sites.read"]'))).toBe(true)
    expect(screen.queryByText('sites.read')).not.toBeInTheDocument()
  })

  // 
  it('opens with the role list and grants first and keeps the permission catalog closed', async () => {
    mockReads()
    renderWithProviders(<CustomRolesPage />, ['/sys/custom-roles'])
    await screen.findAllByText('站点运维')
    const headings = screen.getAllByRole('heading', { level: 3 }).map((node) => node.textContent)
    expect(headings).toEqual(['自定义角色', '用户角色授权'])
    expect(screen.queryByText('可委派权限')).not.toBeInTheDocument()
    expect(screen.queryByText('管理网站')).not.toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: '管理网站' })).not.toBeInTheDocument()
    expect(screen.queryByText('需二次认证')).not.toBeInTheDocument()
    expect(screen.getAllByRole('table')).toHaveLength(2)
  })

  // 
  it('marks an empty name and no permission on their fields, focuses the first, and drops the repeated intro', async () => {
    mockReads()
    const create = vi.spyOn(customRbacApi, 'createRole')
    const user = userEvent.setup()
    renderWithProviders(<CustomRolesPage />, ['/sys/custom-roles'])
    await screen.findAllByText('站点运维')
    expect(screen.queryByText('管理自定义角色和用户角色授权。')).not.toBeInTheDocument()
    // One page of roles and grants: no dead pagination.
    expect(screen.queryByRole('group', { name: '角色分页' })).not.toBeInTheDocument()
    const dialog = await openCreate(user)
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    const name = within(dialog).getByRole('textbox', { name: '角色名称' })
    expect(name).toHaveAttribute('aria-invalid', 'true')
    expect(name).toHaveAccessibleDescription('请输入角色名称')
    expect(name).toHaveFocus()
    expect(within(dialog).getByRole('group', { name: '权限' })).toHaveAccessibleDescription('至少选择一项权限')
    expect(within(dialog).queryByText('请填写完整且有效的角色信息')).not.toBeInTheDocument()

    await user.type(name, '运维')
    expect(name).not.toHaveAttribute('aria-invalid')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(within(dialog).getAllByRole('checkbox')[0]).toHaveFocus()
    expect(create).not.toHaveBeenCalled()
  })

  it('finds a permission by name in the create picker and shows its step-up need once selected', async () => {
    mockReads()
    const create = vi.spyOn(customRbacApi, 'createRole').mockResolvedValue({ ...role, name: '网站管理员', permissions: ['sites.manage'] })
    const user = userEvent.setup()
    renderWithProviders(<CustomRolesPage />, ['/sys/custom-roles'])
    const dialog = await openCreate(user)
    expect(within(dialog).getByRole('group', { name: '网站与安全' })).toBeInTheDocument()
    await user.type(within(dialog).getByRole('searchbox', { name: '搜索权限' }), '管理')
    expect(within(dialog).queryByRole('checkbox', { name: '查看网站' })).not.toBeInTheDocument()
    expect(within(dialog).queryByText('需二次认证')).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('checkbox', { name: '管理网站' }))
    expect(within(dialog).getByRole('checkbox', { name: '管理网站 需二次认证' })).toBeChecked()
    expect(within(dialog).getByText('已选 1 项')).toBeInTheDocument()
    await user.clear(within(dialog).getByRole('searchbox', { name: '搜索权限' }))
    expect(within(dialog).getByRole('checkbox', { name: '查看网站' })).not.toBeChecked()
    await user.type(within(dialog).getByLabelText('角色名称'), '网站管理员')
    await user.type(within(dialog).getByLabelText('二次认证证明'), proof)
    await user.click(within(dialog).getByRole('button', { name: '保存' }))

    await waitFor(() => expect(create).toHaveBeenCalledWith('custom-rbac-token', {
      name: '网站管理员', permissions: ['sites.manage'],
    }, expect.objectContaining({ stepUpProof: proof })))
  })

  it('keeps role and grant cursors independent and resets role pagination when the lifecycle filter changes', async () => {
    vi.spyOn(customRbacApi, 'listPermissions').mockResolvedValue(permissions)
    const roles = vi.spyOn(customRbacApi, 'listRoles')
      .mockResolvedValueOnce({ data: [role], page: { next_cursor: 'role-next' } })
      .mockResolvedValue({ data: [role], page: {} })
    const grants = vi.spyOn(customRbacApi, 'listGrants')
      .mockResolvedValueOnce({ data: [grant], page: { next_cursor: 'grant-next' } })
      .mockResolvedValue({ data: [grant], page: {} })
    const user = userEvent.setup()

    renderWithProviders(<CustomRolesPage />, ['/sys/custom-roles'])
    await screen.findAllByText('站点运维')
    await user.click(within(screen.getByRole('group', { name: '角色分页' })).getByRole('button', { name: '下一页' }))
    await waitFor(() => expect(roles).toHaveBeenLastCalledWith('custom-rbac-token', {
      limit: 20, cursor: 'role-next', includeDeactivated: false,
    }))
    await user.click(within(screen.getByRole('group', { name: '授权分页' })).getByRole('button', { name: '下一页' }))
    await waitFor(() => expect(grants).toHaveBeenLastCalledWith('custom-rbac-token', {
      limit: 20, cursor: 'grant-next', state: 'active',
    }))
    await user.click(screen.getByRole('checkbox', { name: '包含已停用角色' }))
    await waitFor(() => expect(roles).toHaveBeenLastCalledWith('custom-rbac-token', {
      limit: 20, includeDeactivated: true,
    }))
  })

  it('creates a critical role with the selected permissions and bound step-up proof', async () => {
    mockReads()
    const create = vi.spyOn(customRbacApi, 'createRole').mockResolvedValue({ ...role, name: '安全运维', permissions: ['sites.manage'] })
    const user = userEvent.setup()
    renderWithProviders(<CustomRolesPage />, ['/sys/custom-roles'])
    const dialog = await openCreate(user)
    await user.type(within(dialog).getByLabelText('角色名称'), '安全运维')
    await user.click(within(dialog).getByRole('checkbox', { name: '管理网站' }))
    await user.type(within(dialog).getByLabelText('二次认证证明'), proof)
    await user.click(within(dialog).getByRole('button', { name: '保存' }))

    await waitFor(() => expect(create).toHaveBeenCalledWith('custom-rbac-token', {
      name: '安全运维', permissions: ['sites.manage'],
    }, expect.objectContaining({ idempotencyKey: expect.any(String), requestId: expect.any(String), traceparent: expect.any(String), stepUpProof: proof })))
    expect(document.body).not.toHaveTextContent(proof)
  })

  it('renames, publishes permission grant/revoke revisions, and deactivates with exact CAS', async () => {
    mockReads()
    const rename = vi.spyOn(customRbacApi, 'renameRole').mockResolvedValue({ ...role, name: '边缘运维', current_revision: 4 })
    const publish = vi.spyOn(customRbacApi, 'publishRole').mockResolvedValue({ ...role, permissions: ['sites.manage'], current_revision: 4 })
    const deactivate = vi.spyOn(customRbacApi, 'deactivateRole').mockResolvedValue({ ...role, deactivated_at: '2026-08-08T09:00:00Z', current_revision: 4 })
    const user = userEvent.setup()
    renderWithProviders(<CustomRolesPage />, ['/sys/custom-roles'])
    await screen.findAllByText('站点运维')

    await user.click(screen.getByRole('button', { name: '重命名' }))
    let dialog = await screen.findByRole('dialog', { name: '重命名角色' })
    await user.clear(within(dialog).getByLabelText('角色名称'))
    await user.type(within(dialog).getByLabelText('角色名称'), '边缘运维')
    await user.type(within(dialog).getByLabelText('二次认证证明'), proof)
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(rename).toHaveBeenCalledWith('custom-rbac-token', roleID, 3, { name: '边缘运维' }, expect.objectContaining({ stepUpProof: proof })))
    expect(document.body).not.toHaveTextContent(proof)

    await user.click(screen.getByRole('button', { name: '发布权限' }))
    dialog = await screen.findByRole('dialog', { name: '发布角色权限' })
    await user.click(within(dialog).getByRole('checkbox', { name: '查看网站' }))
    await user.click(within(dialog).getByRole('checkbox', { name: '管理网站' }))
    await user.type(within(dialog).getByLabelText('二次认证证明'), proof)
    await user.click(within(dialog).getByRole('button', { name: '发布' }))
    await waitFor(() => expect(publish).toHaveBeenCalledWith('custom-rbac-token', roleID, 3, { permissions: ['sites.manage'] }, expect.objectContaining({ stepUpProof: proof })))

    await user.click(screen.getByRole('button', { name: '停用角色' }))
    dialog = await screen.findByRole('dialog', { name: '停用自定义角色' })
    await user.type(within(dialog).getByLabelText('二次认证证明'), proof)
    await user.click(within(dialog).getByRole('button', { name: '确认停用' }))
    await waitFor(() => expect(deactivate).toHaveBeenCalledWith('custom-rbac-token', roleID, 3, expect.objectContaining({ stepUpProof: proof })))
  })

  it('assigns the current role revision to a tenant user and revokes the grant', async () => {
    mockReads()
    vi.spyOn(tenantMembersApi, 'list').mockResolvedValue([
      { user_id: userID, username: 'ops-li', display_name: '小李', email: 'li@example.com', status: 'active', role: 'tenant_viewer', owner: false, created_at: '2026-08-01T00:00:00Z', password_change_required: false },
      { user_id: '77777777-7777-4777-8777-777777777777', username: 'ops-old', display_name: '已停用成员', email: null, status: 'suspended', role: 'tenant_viewer', owner: false, created_at: '2026-08-01T00:00:00Z', password_change_required: false },
    ])
    const assign = vi.spyOn(customRbacApi, 'assignGrant').mockResolvedValue(grant)
    const revoke = vi.spyOn(customRbacApi, 'revokeGrant').mockResolvedValue({ id: '99999999-9999-4999-8999-999999999999', grant_id: grantID, revoked_by_user_id: roleID, revoked_at: '2026-08-08T09:00:00Z' })
    const user = userEvent.setup()
    renderWithProviders(<CustomRolesPage />, ['/sys/custom-roles'])
    await screen.findAllByText('站点运维')

    // W1/W2: grants show the member and role names, assignment picks a member.
    expect(await screen.findByText('小李（ops-li）')).toHaveAttribute('title', userID)
    await user.click(screen.getByRole('button', { name: '分配用户' }))
    let dialog = await screen.findByRole('dialog', { name: '分配自定义角色' })
    expect(within(dialog).queryByLabelText('用户 ID')).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('combobox', { name: '用户' }))
    await user.type(within(dialog).getByRole('combobox', { name: '用户' }), 'ops')
    expect(screen.queryByText(/已停用成员/)).not.toBeInTheDocument()
    await user.click([...document.querySelectorAll('.ant-select-item-option')].find((node) => node.textContent?.startsWith('小李'))!)
    await user.type(within(dialog).getByLabelText('二次认证证明'), proof)
    await user.click(within(dialog).getByRole('button', { name: '确认分配' }))
    await waitFor(() => expect(assign).toHaveBeenCalledWith('custom-rbac-token', 3, {
      role_id: roleID, subject_user_id: userID,
    }, expect.objectContaining({ stepUpProof: proof })))

    await user.click(screen.getByRole('button', { name: '撤销授权' }))
    dialog = await screen.findByRole('dialog', { name: '撤销用户角色授权' })
    await user.type(within(dialog).getByLabelText('二次认证证明'), proof)
    await user.click(within(dialog).getByRole('button', { name: '确认撤销' }))
    await waitFor(() => expect(revoke).toHaveBeenCalledWith('custom-rbac-token', grantID, expect.objectContaining({ stepUpProof: proof })))
  })

  // 已停用角色不显示会被拒的写入口，状态与历史授权照常可读
  it('hides the write actions of a deactivated role and keeps its state and grants readable', async () => {
    const inactiveID = '99999999-9999-4999-8999-999999999990'
    mockReads()
    vi.mocked(customRbacApi.listRoles).mockResolvedValue({ data: [role, { ...role, id: inactiveID, name: '旧角色', deactivated_at: '2026-08-08T09:00:00Z' }], page: {} })
    vi.mocked(customRbacApi.listGrants).mockResolvedValue({ data: [{ ...grant, role_id: inactiveID }], page: {} })
    renderWithProviders(<CustomRolesPage />, ['/sys/custom-roles'])

    const inactiveRow = (await screen.findAllByText('旧角色')).map((node) => node.closest('tr')!).find((row) => within(row).queryByText('已停用'))!
    expect(within(inactiveRow).getByText('已停用')).toBeInTheDocument()
    for (const name of ['分配用户', '重命名', '发布权限', '停用角色']) {
      expect(within(inactiveRow).queryByRole('button', { name })).not.toBeInTheDocument()
    }
    const activeRow = screen.getAllByText('站点运维').map((node) => node.closest('tr')!).find((row) => within(row).queryByText('生效中'))!
    expect(within(activeRow).getByRole('button', { name: '分配用户' })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: '撤销授权' })).toHaveLength(1)
  })

  it('closes, explains and refreshes when the role was deactivated before the assignment', async () => {
    const { roleRead } = mockReads()
    vi.spyOn(tenantMembersApi, 'list').mockResolvedValue([
      { user_id: userID, username: 'ops-li', display_name: '小李', email: 'li@example.com', status: 'active', role: 'tenant_viewer', owner: false, created_at: '2026-08-01T00:00:00Z', password_change_required: false },
    ])
    const assign = vi.spyOn(customRbacApi, 'assignGrant').mockImplementation(async () => {
      roleRead.mockResolvedValue({ data: [{ ...role, deactivated_at: '2026-08-08T09:00:00Z' }], page: {} })
      throw new ApiError('custom role is inactive', 409, 'custom_rbac_role_inactive')
    })
    const user = userEvent.setup()
    renderWithProviders(<CustomRolesPage />, ['/sys/custom-roles'])
    await screen.findAllByText('站点运维')

    await user.click(screen.getByRole('button', { name: '分配用户' }))
    const dialog = await screen.findByRole('dialog', { name: '分配自定义角色' })
    await user.click(within(dialog).getByRole('combobox', { name: '用户' }))
    await user.click([...document.querySelectorAll('.ant-select-item-option')].find((node) => node.textContent?.startsWith('小李'))!)
    await user.type(within(dialog).getByLabelText('二次认证证明'), proof)
    await user.click(within(dialog).getByRole('button', { name: '确认分配' }))

    await waitFor(() => expect(assign).toHaveBeenCalledOnce())
    expect(await screen.findByRole('alert')).toHaveTextContent('该角色已停用，不能再分配用户或修改，列表已刷新')
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '分配自定义角色' })).not.toBeInTheDocument())
    await waitFor(() => expect(screen.queryByRole('button', { name: '分配用户' })).not.toBeInTheDocument())
    expect(roleRead.mock.calls.length).toBeGreaterThan(1)
  })

  it.each([
    ['custom_rbac_revision_conflict', 409, '内容已被其他人修改，请刷新后再保存'],
    ['custom_rbac_step_up_required', 428, '此操作需要有效且未使用的二次认证证明'],
    ['custom_rbac_permission_not_delegable', 422, '所选权限不能委派给租户自定义角色'],
    ['custom_rbac_store_unavailable', 503, '自定义角色服务暂不可用，请稍后重试'],
  ])('maps stable error %s without rendering the server message', async (code, status, localized) => {
    mockReads()
    vi.spyOn(customRbacApi, 'createRole').mockRejectedValue(new ApiError('private authorization detail', status, code))
    const user = userEvent.setup()
    renderWithProviders(<CustomRolesPage />, ['/sys/custom-roles'])
    const dialog = await openCreate(user)
    await user.type(within(dialog).getByLabelText('角色名称'), '失败角色')
    await user.click(within(dialog).getByRole('checkbox', { name: '查看网站' }))
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(await within(dialog).findByText(localized)).toBeInTheDocument()
    expect(screen.queryByText('private authorization detail')).not.toBeInTheDocument()
  })

  it('retries an unknown write with the exact payload, proof and idempotency metadata, then abandons', async () => {
    const { roleRead } = mockReads()
    const create = vi.spyOn(customRbacApi, 'createRole').mockRejectedValue(new ApiError('private network detail', 503, 'custom_rbac_write_unknown'))
    const user = userEvent.setup()
    renderWithProviders(<CustomRolesPage />, ['/sys/custom-roles'])
    const dialog = await openCreate(user)
    await user.type(within(dialog).getByLabelText('角色名称'), '待确认角色')
    await user.click(within(dialog).getByRole('checkbox', { name: '管理网站' }))
    await user.type(within(dialog).getByLabelText('二次认证证明'), proof)
    await user.click(within(dialog).getByRole('button', { name: '保存' }))

    expect(await screen.findByText('操作结果待确认')).toBeInTheDocument()
    expect(screen.queryByText('private network detail')).not.toBeInTheDocument()
    const first = create.mock.calls[0]
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]).toEqual(first)
    await user.click(screen.getByRole('button', { name: '放弃并刷新' }))
    await waitFor(() => expect(roleRead.mock.calls.length).toBeGreaterThan(1))
    expect(create).toHaveBeenCalledTimes(2)
  })
})
