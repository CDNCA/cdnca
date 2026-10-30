import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import AnnouncementManagementPage from '../pages/AnnouncementManagementPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// OutcomeUnknown 的标题同时出现在恢复条和说明弹窗里，这里只认原位的恢复条。
const OUTCOME_BAR = { selector: '.cdnca-outcome-bar .ant-alert-message' }

describe('GlobalAnnouncementManagementPage', () => {
  it('uses the platform global endpoint without reading the tenant list', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
      permissions: ['announcements.manage'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [{
      id: '77777777-7777-4777-8777-777777777777', platform_scope_id: actor.scope_id,
      version: 1, revision: 1, status: 'draft', title: '全平台维护', body: '维护窗口',
      audience: { all_tenants: true, tenant_scope_ids: [], role_targets: [], user_targets: [] },
      withdrawal_visibility: 'retain', recipient_count: 0,
      created_at: '2026-08-08T00:00:00Z', state_changed_at: '2026-08-08T00:00:00Z',
    }] }), { status: 200, headers: { 'Content-Type': 'application/json' } }))

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])

    expect(await screen.findByText('全平台维护')).toBeInTheDocument()
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledOnce())
    expect(String(fetchSpy.mock.calls[0][0])).toBe('/v1/admin/announcements/global?limit=20')
    expect(fetchSpy.mock.calls.some(([url]) => String(url).startsWith('/v1/admin/announcements?'))).toBe(false)
  })

  it('opens the competitor-style editor as a centered modal', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
      permissions: ['announcements.manage'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [] }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }))

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    fireEvent.click(await screen.findByRole('button', { name: '新增公告' }))

    expect(await screen.findByRole('dialog')).toBeInTheDocument()
    expect(screen.getByText('基础信息')).toBeInTheDocument()
    expect(screen.getByText('展示状态')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '显示内容' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '跳转链接' })).toBeInTheDocument()
    expect(document.querySelector('.ant-drawer')).toBeNull()
    expect(document.querySelector('.ant-drawer-content')).toBeNull()
    expect(document.querySelector('.announcement-editor-modal .ant-modal-footer')).toBeInTheDocument()
  })

  // C32 (Codex ADM01): the audience section is a reachable advanced section
  // showing its current scope, not a 1px clipped region.
  it('shows the audience as a reachable advanced section with a summary', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
      permissions: ['announcements.manage'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [] }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }))
    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    fireEvent.click(await screen.findByRole('button', { name: '新增公告' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog.querySelector('.announcement-compat-hidden-fields')).toBeNull()
    const summary = within(dialog).getByText('高级受众：所有租户的全部活跃用户')
    expect(summary.closest('details')).not.toHaveAttribute('open')
    fireEvent.click(summary)
    expect(summary.closest('details')).toHaveAttribute('open')
    expect(within(dialog).getByText('撤回后的可见性')).toBeInTheDocument()
  })

  it('saves link and display settings and restores them when editing', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['announcements.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    let saved: Record<string, unknown> | null = null
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      if (init?.method === 'POST') {
        saved = { ...JSON.parse(String(init.body)), id: '77777777-7777-4777-8777-777777777777', platform_scope_id: actor.scope_id,
          version: 1, revision: 1, status: 'draft', recipient_count: 0,
          audience: { all_tenants: true, tenant_scope_ids: [], role_targets: [], user_targets: [] },
          created_at: '2026-09-25T00:00:00Z', state_changed_at: '2026-09-25T00:00:00Z' }
      }
      return new Response(JSON.stringify(init?.method === 'POST' ? saved : { items: saved ? [saved] : [] }), { status: init?.method === 'POST' ? 201 : 200, headers: { 'Content-Type': 'application/json' } })
    })
    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    fireEvent.click(await screen.findByRole('button', { name: '新增公告' }))
    const dialog = within(await screen.findByRole('dialog'))
    fireEvent.change(dialog.getByLabelText('标题'), { target: { value: '链接公告' } })
    fireEvent.click(dialog.getByRole('button', { name: '跳转链接' }))
    fireEvent.change(dialog.getByLabelText('链接'), { target: { value: 'https://example.com/notice' } })
    fireEvent.change(dialog.getByRole('spinbutton'), { target: { value: '0' } })
    fireEvent.click(dialog.getAllByRole('switch')[0])
    fireEvent.click(dialog.getAllByRole('switch')[1])
    fireEvent.click(dialog.getByRole('checkbox', { name: '加红' }))
    fireEvent.click(dialog.getByRole('checkbox', { name: '加粗' }))
    fireEvent.click(dialog.getByRole('button', { name: '确定' }))
    await waitFor(() => expect(saved).toMatchObject({ title: '链接公告', body: '', format: 'link', link_url: 'https://example.com/notice', sort_order: 0, visible: false, popup: true, red: true, bold: true }))
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1)
    fireEvent.click(await screen.findByRole('button', { name: '编辑' }))
    const reopened = within(await screen.findByRole('dialog'))
    expect(reopened.getByLabelText('链接')).toHaveValue('https://example.com/notice')
    expect(reopened.getAllByRole('switch')[0]).toHaveAttribute('aria-checked', 'false')
    expect(reopened.getAllByRole('switch')[1]).toHaveAttribute('aria-checked', 'true')
    expect(reopened.getByRole('checkbox', { name: '加红' })).toBeChecked()
  })

  // fix-fielderr-be4：服务端拒绝链接时标在链接框下，弹窗不关、不弹错误窗
  it('marks a server-refused link under its field without a dialog', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['announcements.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => init?.method === 'POST'
      ? new Response(JSON.stringify({ error: { code: 'validation_error', message: 'request fields are invalid', request_id: 'r', details: { field: 'link_url', reason: 'invalid' } } }), { status: 400, headers: { 'Content-Type': 'application/json' } })
      : new Response(JSON.stringify({ items: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    fireEvent.click(await screen.findByRole('button', { name: '新增公告' }))
    const dialog = within(await screen.findByRole('dialog'))
    fireEvent.change(dialog.getByLabelText('标题'), { target: { value: '链接公告' } })
    fireEvent.click(dialog.getByRole('button', { name: '跳转链接' }))
    fireEvent.change(dialog.getByLabelText('链接'), { target: { value: 'https://user@example.com/notice' } })
    fireEvent.click(dialog.getByRole('button', { name: '确定' }))
    const help = await dialog.findByText('填写的内容不符合要求')
    expect(help.closest('.ant-form-item')).toHaveClass('ant-form-item-has-error')
    expect(help.closest('.ant-form-item')).toContainElement(dialog.getByLabelText('链接'))
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('shows draft batch controls and updates visibility through the draft contract', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['announcements.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    let item = {
      id: '88888888-8888-4888-8888-888888888888', platform_scope_id: actor.scope_id,
      version: 1, revision: 1, status: 'draft' as const, title: '批量显示公告', body: '内容', format: 'content' as const, link_url: '',
      sort_order: 100, visible: true, popup: false, red: false, bold: false,
      audience: { all_tenants: true, tenant_scope_ids: [], role_targets: [], user_targets: [] },
      withdrawal_visibility: 'retain' as const, recipient_count: 0,
      created_at: '2026-09-25T00:00:00Z', state_changed_at: '2026-09-25T00:00:00Z',
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      if (init?.method === 'PATCH') {
        const body = JSON.parse(String(init.body)) as typeof item
        item = { ...item, ...body, revision: 2 }
        return new Response(JSON.stringify(item), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({ items: [item] }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    })

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    const row = await screen.findByText('批量显示公告')
    const rowCheckbox = within(row.closest('tr')!).getByRole('checkbox')
    fireEvent.click(rowCheckbox)
    expect(screen.getByRole('button', { name: '显示' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '隐藏' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '批量删除' })).toBeEnabled()

    fireEvent.click(screen.getByRole('button', { name: '隐藏' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, request]) => request?.method === 'PATCH')).toBe(true))
    const patchRequest = fetchSpy.mock.calls.find(([, request]) => request?.method === 'PATCH')?.[1]
    expect(JSON.parse(String(patchRequest?.body))).toMatchObject({ visible: false, expected_revision: 1 })
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, request]) => !request?.method).length).toBeGreaterThan(1))
    const updatedRow = within(screen.getByText('批量显示公告').closest('tr')!).getByRole('checkbox')
    fireEvent.click(updatedRow)
    fireEvent.click(screen.getByRole('button', { name: '显示' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, request]) => request?.method === 'PATCH')).toHaveLength(2))
    const showPatch = fetchSpy.mock.calls.filter(([, request]) => request?.method === 'PATCH')[1]?.[1]
    expect(JSON.parse(String(showPatch?.body))).toMatchObject({ visible: true, expected_revision: 2 })
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, request]) => !request?.method).length).toBeGreaterThan(2))
  })

  it('retries only the failed item after a partial batch failure', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['announcements.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const items = ['a', 'b'].map((suffix) => ({
      id: `88888888-8888-4888-8888-88888888888${suffix === 'a' ? '1' : '2'}`,
      platform_scope_id: actor.scope_id, version: 1, revision: 1, status: 'draft' as const,
      title: `批量${suffix}`, body: '内容', format: 'content' as const, link_url: '', sort_order: 100,
      visible: true, popup: false, red: false, bold: false,
      audience: { all_tenants: true, tenant_scope_ids: [], role_targets: [], user_targets: [] },
      withdrawal_visibility: 'retain' as const, recipient_count: 0,
      created_at: '2026-09-25T00:00:00Z', state_changed_at: '2026-09-25T00:00:00Z',
    }))
    let patchCount = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      if (init?.method === 'PATCH') {
        patchCount += 1
        if (patchCount === 2) return new Response(JSON.stringify({ error: { code: 'version_conflict' } }), { status: 409, headers: { 'Content-Type': 'application/json' } })
        const body = JSON.parse(String(init.body)) as Record<string, unknown>
        return new Response(JSON.stringify({ ...items[0], ...body, revision: 2 }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({ items }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    })

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    await screen.findByText('批量a')
    screen.getAllByRole('checkbox').slice(1).forEach((checkbox) => fireEvent.click(checkbox))
    fireEvent.click(screen.getByRole('button', { name: '隐藏' }))
    await screen.findByText('公告已被其他操作修改，请刷新后重试', OUTCOME_BAR)
    fireEvent.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(patchCount).toBe(3))
    const patchCalls = fetchSpy.mock.calls.filter(([, request]) => request?.method === 'PATCH')
    expect(String(patchCalls[1][0])).toContain(items[1].id)
    expect(String(patchCalls[2][0])).toContain(items[1].id)
    expect(String(patchCalls[0][0])).toContain(items[0].id)
    expect(patchCalls.map(([, request]) => new Headers(request?.headers).get('Idempotency-Key')?.length ?? 0).every((length) => length <= 128)).toBe(true)
  })

  it('locks a batch after an unknown result until the exact request is retried', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['announcements.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const item = {
      id: '88888888-8888-4888-8888-888888888888', platform_scope_id: actor.scope_id,
      version: 1, revision: 1, status: 'draft' as const, title: '未知结果公告', body: '内容', format: 'content' as const, link_url: '',
      sort_order: 100, visible: true, popup: false, red: false, bold: false,
      audience: { all_tenants: true, tenant_scope_ids: [], role_targets: [], user_targets: [] }, withdrawal_visibility: 'retain' as const,
      recipient_count: 0, created_at: '2026-09-25T00:00:00Z', state_changed_at: '2026-09-25T00:00:00Z',
    }
    let patchCount = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      if (init?.method === 'PATCH') {
        patchCount += 1
        if (patchCount === 1) throw new TypeError('outcome unknown')
        return new Response(JSON.stringify({ ...item, visible: false, revision: 2 }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({ items: [item] }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    })

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    await screen.findByText('未知结果公告')
    fireEvent.click(within(screen.getByText('未知结果公告').closest('tr')!).getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: '隐藏' }))
    await screen.findByText('操作结果待确认', OUTCOME_BAR)
    fireEvent.click(screen.getByRole('button', { name: '显示' }))
    expect(patchCount).toBe(1)
    fireEvent.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(patchCount).toBe(2))
    const patchCalls = fetchSpy.mock.calls.filter(([, request]) => request?.method === 'PATCH')
    expect(patchCalls[0][1]?.headers).toEqual(patchCalls[1][1]?.headers)
    expect(new Headers(patchCalls[0][1]?.headers).get('Idempotency-Key')?.length).toBeLessThanOrEqual(128)
  })

  it('renders a forbidden result and does not request data without the platform permission', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: [] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    expect(await screen.findByText('无权管理公告')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('stops a pending batch before the next PATCH when the session changes', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['announcements.manage'] })
    const nextActor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['announcements.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const items = ['a', 'b'].map((suffix) => ({
      id: `88888888-8888-4888-8888-88888888888${suffix === 'a' ? '3' : '4'}`,
      platform_scope_id: actor.scope_id, version: 1, revision: 1, status: 'draft' as const,
      title: `会话${suffix}`, body: '内容', format: 'content' as const, link_url: '', sort_order: 100,
      visible: true, popup: false, red: false, bold: false,
      audience: { all_tenants: true, tenant_scope_ids: [], role_targets: [], user_targets: [] }, withdrawal_visibility: 'retain' as const,
      recipient_count: 0, created_at: '2026-09-25T00:00:00Z', state_changed_at: '2026-09-25T00:00:00Z',
    }))
    let resolveFirst!: (value: Response) => void
    const firstPending = new Promise<Response>((resolve) => { resolveFirst = resolve })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      if (init?.method === 'PATCH') {
        if (String(_url).includes(items[0].id)) return firstPending
        return new Response(JSON.stringify({ ...items[1], visible: false, revision: 2 }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response(JSON.stringify({ items: useSessionStore.getState().principal?.scope_id === actor.scope_id ? items : [] }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    })

    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    await screen.findByText('会话a')
    screen.getAllByRole('checkbox').slice(1).forEach((checkbox) => fireEvent.click(checkbox))
    fireEvent.click(screen.getByRole('button', { name: '隐藏' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, request]) => request?.method === 'PATCH')).toHaveLength(1))
    useSessionStore.getState().setSession(authResponse(nextActor), nextActor)
    resolveFirst(new Response(JSON.stringify({ ...items[0], visible: false, revision: 2 }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(fetchSpy.mock.calls.filter(([, request]) => request?.method === 'PATCH')).toHaveLength(1)
  })

  it('clears selected rows when moving between pages', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['announcements.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const item = {
      id: '88888888-8888-4888-8888-888888888889', platform_scope_id: actor.scope_id, version: 1, revision: 1, status: 'draft' as const,
      title: '分页公告', body: '内容', format: 'content' as const, link_url: '', sort_order: 100, visible: true, popup: false, red: false, bold: false,
      audience: { all_tenants: true, tenant_scope_ids: [], role_targets: [], user_targets: [] }, withdrawal_visibility: 'retain' as const,
      recipient_count: 0, created_at: '2026-09-25T00:00:00Z', state_changed_at: '2026-09-25T00:00:00Z',
    }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      const secondPage = String(url).includes('cursor=next-page')
      return new Response(JSON.stringify(secondPage ? { items: [] } : { items: [item], next_cursor: 'next-page' }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    })
    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    await screen.findByText('分页公告')
    const checkbox = within(screen.getByText('分页公告').closest('tr')!).getByRole('checkbox')
    fireEvent.click(checkbox)
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    await waitFor(() => expect(screen.getByRole('button', { name: '显示' })).toBeDisabled())
    fireEvent.click(screen.getByRole('button', { name: '上一页' }))
    await waitFor(() => expect(within(screen.getByText('分页公告').closest('tr')!).getByRole('checkbox')).not.toBeChecked())
  })

  // C32 (Codex ADM01): tenants, roles and users are picked by name; stored
  // targets show by name (or as deleted); publishing previews the count.
  describe('C32 audience by name and recipient count', () => {
    const tenantA = '88888888-8888-4888-8888-888888888888'
    const roleID = '99999999-9999-4999-8999-999999999999'
    const userID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
    const goneTenant = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
    function platformActor() {
      const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['announcements.manage'] })
      useSessionStore.getState().setSession(authResponse(actor), actor)
      return actor
    }
    function item(scopeID: string, audience: object) {
      return {
        id: '77777777-7777-4777-8777-777777777777', platform_scope_id: scopeID, version: 1, revision: 2, status: 'draft', title: '定向公告', body: '正文',
        format: 'content', sort_order: 100, visible: true, popup: false, red: false, bold: false,
        audience: { all_tenants: false, tenant_scope_ids: [], role_targets: [], user_targets: [], ...audience },
        withdrawal_visibility: 'retain', recipient_count: 0, archived: false, lifecycle_revision: 1,
        created_at: '2026-08-08T00:00:00Z', state_changed_at: '2026-08-08T00:00:00Z',
      }
    }
    function directory(url: string) {
      const params = new URL(url, 'http://local').searchParams
      const kind = params.get('kind')
      if (kind === 'tenant') return { items: [{ id: tenantA, name: '甲公司', detail: '10001' }] }
      if (kind === 'role') return { items: [{ id: roleID, scope_id: tenantA, name: 'ops' }] }
      return { items: [{ id: userID, scope_id: tenantA, name: '李四', detail: 'lisi' }] }
    }

    it('picks tenants, then a tenant\'s roles and users, by name', async () => {
      const actor = platformActor()
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
        const url = String(input)
        if (url.startsWith('/v1/admin/announcements/global/audience-directory?')) return Promise.resolve(new Response(JSON.stringify(directory(url)), { status: 200, headers: { 'Content-Type': 'application/json' } }))
        if (init?.method === 'POST') return Promise.resolve(new Response(JSON.stringify(item(actor.scope_id, {})), { status: 201, headers: { 'Content-Type': 'application/json' } }))
        return Promise.resolve(new Response(JSON.stringify({ items: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      })
      const user = userEvent.setup()
      renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
      fireEvent.click(await screen.findByRole('button', { name: '新增公告' }))
      fireEvent.change(screen.getByLabelText('标题'), { target: { value: '定向公告' } })
      fireEvent.change(screen.getByLabelText('内容'), { target: { value: '正文' } })
      await user.click(screen.getByRole('combobox', { name: '受众范围' }))
      await user.click(await screen.findByText('指定租户、角色或用户', { selector: '.ant-select-item-option-content' }))
      expect(screen.getByRole('combobox', { name: '租户角色' })).toBeDisabled()

      await user.click(screen.getByRole('combobox', { name: '整个租户' }))
      await user.click(await screen.findByText('甲公司（10001）', { selector: '.ant-select-item-option-content' }))
      await user.click(screen.getByRole('combobox', { name: '在租户中选择' }))
      await user.click((await screen.findAllByText('甲公司（10001）', { selector: '.ant-select-item-option-content' })).at(-1)!)
      await waitFor(() => expect(screen.getByRole('combobox', { name: '租户角色' })).toBeEnabled())
      await user.click(screen.getByRole('combobox', { name: '租户角色' }))
      await user.click(await screen.findByText('甲公司（10001） / ops', { selector: '.ant-select-item-option-content' }))
      await user.click(screen.getByRole('combobox', { name: '租户用户' }))
      await user.click(await screen.findByText('甲公司（10001） / 李四（lisi）', { selector: '.ant-select-item-option-content' }))
      expect(screen.getByRole('dialog').textContent).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-/)
      expect(fetchSpy.mock.calls.some(([url]) => String(url).includes('kind=role') && String(url).includes(`scope_id=${tenantA}`))).toBe(true)

      fireEvent.click(screen.getByRole('button', { name: '确定' }))
      await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
      const body = JSON.parse(String(fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')![1]!.body))
      expect(body).toMatchObject({
        all_tenants: false, tenant_scope_ids: [tenantA],
        role_targets: [{ scope_id: tenantA, role_id: roleID }], user_targets: [{ scope_id: tenantA, user_id: userID }],
      })
      expect(body).not.toHaveProperty('target_tenant')
    })

    it('shows stored targets by name and missing ones as deleted, then previews the count', async () => {
      const actor = platformActor()
      const stored = item(actor.scope_id, { tenant_scope_ids: [tenantA, goneTenant], role_targets: [{ scope_id: tenantA, role_id: roleID }], user_targets: [{ scope_id: goneTenant, user_id: userID }] })
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
        const url = String(input)
        const reply = (value: unknown) => Promise.resolve(new Response(JSON.stringify(value), { status: 200, headers: { 'Content-Type': 'application/json' } }))
        if (url.startsWith('/v1/admin/announcements/global/audience-directory?')) return reply(directory(url))
        if (url.endsWith('/audience/count')) return reply({ announcement_id: stored.id, recipient_count: 0 })
        return reply({ items: [stored] })
      })
      const user = userEvent.setup()
      renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
      await user.click(await screen.findByRole('button', { name: '编辑' }))
      const dialog = await screen.findByRole('dialog')
      expect(await within(dialog).findByText('甲公司（10001）')).toBeInTheDocument()
      expect(within(dialog).getByText('甲公司（10001） / ops')).toBeInTheDocument()
      expect(within(dialog).getAllByText('已删除的对象')).toHaveLength(2)
      expect(dialog.textContent).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-/)
      fireEvent.click(within(dialog).getByRole('button', { name: '取消' }))

      fireEvent.click(screen.getByRole('button', { name: '立即发布' }))
      const confirm = (await screen.findByText('确认发布公告', { selector: '.ant-modal-title' })).closest('.ant-modal-content') as HTMLElement
      expect(await within(confirm).findByText('当前受众中没有活跃用户，无法发布。请先调整受众。')).toBeInTheDocument()
      expect(within(confirm).getByRole('button', { name: '确认' })).toBeDisabled()
      expect(fetchSpy.mock.calls.some(([url]) => String(url) === `/v1/admin/announcements/global/${stored.id}/audience/count`)).toBe(true)
    })
  })

  it('G2: a failed list shows only the error with a retry, not the empty state', async () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['announcements.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    let fail = true
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify(fail ? { error: { code: 'internal_error' } } : { items: [] }),
      { status: fail ? 500 : 200, headers: { 'Content-Type': 'application/json' } }))
    renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
    const failure = await screen.findByText('公告请求失败，请稍后重试', { selector: '.data-state-error span' })
    expect(screen.queryByText('暂无公告')).not.toBeInTheDocument()
    fail = false
    fireEvent.click(within(failure.closest('.data-state-error') as HTMLElement).getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无公告')).toBeInTheDocument()
  })
})
