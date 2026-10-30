import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useSessionStore } from '../auth/session'
import type { AdminSiteGroup } from '../api/siteGroups'
import type { ManagedUser } from '../api/users'
import i18n, { changeLocale } from '../i18n'
import SiteGroupsPage from '../pages/SiteGroupsPage'
import { siteGroupRetryStorageKey } from '../pages/siteGroupRetryRecord'
import { principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// antd 测试环境所有 Modal 的 aria-labelledby 都是 test-id，可访问名取的是 DOM 里第一个 test-id（常是反馈弹窗标题）；
// 业务弹窗按自身标题匹配，并排除反馈弹窗（.cdnca-feedback）
const pageDialogs = (name?: string) => screen.queryAllByRole('dialog')
  .filter((element) => !element.classList.contains('cdnca-feedback'))
  .filter((element) => name === undefined || element.querySelector('.ant-modal-title, .ant-drawer-title')?.textContent?.trim() === name)

const scopeID = '22222222-2222-4222-8222-222222222222'
const platformScope = '019a03a3-735a-7f99-a2f8-7986a8618b44'
const tenantScope = '019a03a3-735b-7ee2-bf40-8c6f92c26c77'
const createdID = '019a03a3-735c-7b8c-9cc2-8543d041c888'
const managedUser: ManagedUser = {
  id: '019a03a3-735c-7b8c-9cc2-8543d041c822', display_id: '27', scope_id: tenantScope, tenant_id: '019a03a3-735d-7c8c-9cc2-8543d041c811',
  username: 'tenant-a', display_name: 'Tenant A', email: null, phone: null, status: 'active', role: 'tenant_owner', group_id: null, group_name: null,
  revision: 1, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
}
const group: AdminSiteGroup = {
  id: '33333333-3333-4333-8333-333333333333', scope_id: tenantScope, name: '默认分组', remark: '真实备注', display_id: '7', revision: 3,
  user_state: 'resolved', user: { id: managedUser.id, display_id: managedUser.display_id, username: managedUser.username },
  created_at: '2026-09-26T08:00:00Z', updated_at: '2026-09-26T08:01:00Z',
}
function json(body: unknown, status = 200): Response { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }) }
function renderGroups(permissions = ['sites.read', 'sites.manage', 'identity.users.manage']) {
  useSessionStore.setState({ accessToken: 'access-token', expiresAt: Date.now() + 60_000, sessionEpoch: 1, status: 'authenticated', principal: principal({ scope_kind: 'platform', scope_id: platformScope, tenant_id: null, permissions }) })
  return renderWithProviders(<SiteGroupsPage />)
}
function groupRequests(calls: [RequestInfo | URL, RequestInit?][]) { return calls.filter(([input]) => /\/v1\/(?:admin\/)?site-groups/.test(String(input))) }
function siteGroupPageFixture(override?: (url: URL, init: RequestInit | undefined) => Response | undefined | Promise<Response | undefined>) {
  const state = { groups: [{ ...group }], users: [managedUser] }
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = new URL(String(input), 'https://fixture.invalid')
    const response = await override?.(url, init)
    if (response) return response
    if (url.pathname === '/v1/admin/users') return json({ items: state.users, total: state.users.length, page: Number(url.searchParams.get('page')), limit: 20 })
    if (init?.method === 'POST') {
      const body = JSON.parse(String(init.body))
      const saved = { ...group, id: createdID, display_id: '8', scope_id: body.target_scope_id, name: body.name, remark: body.remark ?? '', revision: 1 }
      state.groups.push(saved)
      return json(saved, 201)
    }
    const id = url.pathname.split('/')[3]
    const index = state.groups.findIndex((item) => item.id === id && item.scope_id === url.searchParams.get('scope_id'))
    if (init?.method === 'PATCH') {
      const body = JSON.parse(String(init.body))
      state.groups[index] = { ...state.groups[index], name: body.name, remark: body.remark ?? state.groups[index].remark, revision: body.expected_revision + 1 }
      return json(state.groups[index])
    }
    if (init?.method === 'DELETE') { state.groups.splice(index, 1); return new Response(null, { status: 204 }) }
    if (id && url.pathname.startsWith('/v1/site-groups/')) return index < 0 ? json({ error: { code: 'not_found', message: 'raw not found' } }, 404) : json(state.groups[index])
    const page = Number(url.searchParams.get('page')), limit = Number(url.searchParams.get('limit'))
    const eligible = url.pathname === '/v1/admin/site-groups' ? state.groups : state.groups.filter((item) => item.scope_id === url.searchParams.get('scope_id'))
    return json({ items: eligible.slice((page - 1) * limit, page * limit), total: eligible.length, page, limit })
  })
  return { state, fetchSpy }
}
async function siteGroupPageCreate(name = '网站分组A') {
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: i18n.t('siteGroups:actions.create') }))
  const dialog = screen.getByRole('dialog')
  const selector = within(dialog).queryByRole('combobox', { name: i18n.t('siteGroups:scope.user') })
  if (selector) { await user.click(selector); await user.click(await screen.findByText('tenant-a（27）', { selector: '.ant-select-item-option-content' })) }
  await user.type(within(dialog).getByLabelText(i18n.t('siteGroups:editor.name')), name)
  return { user, dialog }
}
beforeEach(() => sessionStorage.clear())

describe('SiteGroupsPage', () => {
  it.each(['zh-CN', 'qps-ploc'] as const)('shows the real global table; user selection is only inside create in %s', async (locale) => {
    await changeLocale(locale)
    const { fetchSpy } = siteGroupPageFixture()
    renderGroups()
    expect(await screen.findByText('真实备注')).toBeInTheDocument()
    for (const column of ['id', 'user', 'name', 'remark', 'actions']) expect(screen.getByRole('columnheader', { name: i18n.t(`siteGroups:columns.${column}`) })).toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: i18n.t('siteGroups:scope.user') })).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.map(([input]) => String(input))).toEqual(['/v1/admin/site-groups?page=1&limit=10'])
    await siteGroupPageCreate()
    expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('role=tenant_owner') && String(input).includes('status=active'))).toBe(true)
    expect(document.body.textContent).not.toContain(tenantScope)
    expect(document.body.textContent).not.toContain('access-token')
  })
  it('loads only tenant UUIDv7 groups without an internal scope input', async () => {
    const { fetchSpy } = siteGroupPageFixture()
    useSessionStore.setState({ accessToken: 'access-token', sessionEpoch: 1, status: 'authenticated', principal: principal({ scope_id: tenantScope, tenant_id: managedUser.tenant_id, permissions: ['sites.read'] }) })
    renderWithProviders(<SiteGroupsPage />)
    expect(await screen.findByText('默认分组')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledWith(`/v1/site-groups?scope_id=${tenantScope}&page=1&limit=10`, expect.anything())
    expect(screen.queryByRole('columnheader', { name: '用户' })).not.toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: '用户' })).not.toBeInTheDocument()
  })
  it('has no navigation of its own: the site list shell owns groups/defaults/DNS API/DNS check (SITE-CURRENT-07)', async () => {
    await changeLocale('zh-CN')
    siteGroupPageFixture()
    useSessionStore.setState({ accessToken: 'access-token', sessionEpoch: 1, status: 'authenticated', principal: principal({ scope_id: tenantScope, tenant_id: managedUser.tenant_id, permissions: ['sites.read', 'dns.read'] }) })
    renderWithProviders(<SiteGroupsPage />, ['/site/list'])
    expect(await screen.findByText('默认分组')).toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: '网站设置导航' })).not.toBeInTheDocument()
    for (const name of ['默认设置', 'DNS API', '解析检测']) expect(screen.queryByRole('button', { name })).not.toBeInTheDocument()
  })
  it('does not invent a tenant or read globally without directory permission', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderGroups(['sites.read', 'sites.manage'])
    expect(screen.getByText('无权查看网站分组')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新增分组' })).not.toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })
  it('keeps an empty owner directory explicit and never substitutes platform scope', async () => {
    const { state, fetchSpy } = siteGroupPageFixture(); state.users = []
    renderGroups()
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: '新增分组' })); await user.click(screen.getByRole('combobox', { name: '用户' }))
    expect(await screen.findByText('暂无可选用户')).toBeInTheDocument()
    expect(within(screen.getByRole('dialog')).getByRole('button', { name: '确定' })).toBeDisabled()
    expect(fetchSpy.mock.calls.some(([input]) => String(input).includes(`scope_id=${platformScope}`))).toBe(false)
  })
  it.each(['/v1/admin/users', '/v1/admin/site-groups'])('fails closed on a 403 from %s without raw errors', async (path) => {
    const { fetchSpy } = siteGroupPageFixture((url) => url.pathname === path ? json({ error: { code: 'permission_denied', message: 'secret raw denial' } }, 403) : undefined)
    renderGroups()
    if (path.endsWith('users')) await userEvent.setup().click(screen.getByRole('button', { name: '新增分组' }))
    expect(await screen.findByText('无权查看网站分组')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('secret raw denial')
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method)).toHaveLength(0)
  })
  it('creates remark and reads the exact selected resource before the global list', async () => {
    const { fetchSpy } = siteGroupPageFixture(); renderGroups()
    const { user, dialog } = await siteGroupPageCreate()
    await user.type(within(dialog).getByLabelText('备注'), '第一行\n第二行'); await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('分组操作已完成并回读确认')).toBeInTheDocument()
    const writes = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')
    expect(writes).toHaveLength(1)
    expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ target_scope_id: tenantScope, name: '网站分组A', remark: '第一行\n第二行' })
    expect(writes[0][1]?.headers).toEqual(expect.objectContaining({ Authorization: 'Bearer access-token', 'Idempotency-Key': expect.stringMatching(/^site-group-create-/) }))
    expect(groupRequests(fetchSpy.mock.calls).slice(-2).map(([url]) => String(url))).toEqual([`/v1/site-groups/${createdID}?scope_id=${tenantScope}`, '/v1/admin/site-groups?page=1&limit=10'])
    expect(sessionStorage.length).toBe(0)
  })
  // fix-fielderr-be4：服务端拒绝备注时标在备注框下，编辑弹窗不关、不弹错误窗
  it('marks a server-refused remark under its field and keeps the editor open', async () => {
    const { fetchSpy } = siteGroupPageFixture((_, init) => init?.method === 'POST'
      ? json({ error: { code: 'validation_error', message: 'raw', details: { field: 'remark', reason: 'too_long' } } }, 400) : undefined)
    renderGroups()
    const { user, dialog } = await siteGroupPageCreate()
    await user.type(within(dialog).getByLabelText('备注'), '备注'); await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('长度超过上限')).toBeInTheDocument()
    expect(within(dialog).getByText('长度超过上限').closest('.ant-form-item')).toHaveClass('ant-form-item-has-error')
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
    expect(pageDialogs()).toHaveLength(1)
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1)
    expect(sessionStorage.length).toBe(0)
  })
  it('rejects foreign rows in a tenant-scoped response rather than exposing names', async () => {
    siteGroupPageFixture((url) => url.pathname === '/v1/site-groups' ? json({ items: [{ ...group, scope_id: scopeID, name: '私有分组' }], total: 1, page: 1, limit: 10 }) : undefined)
    useSessionStore.setState({ accessToken: 'access-token', sessionEpoch: 1, status: 'authenticated', principal: principal({ scope_id: tenantScope, tenant_id: managedUser.tenant_id, permissions: ['sites.read'] }) })
    renderWithProviders(<SiteGroupsPage />)
    expect(await screen.findByText('网站分组加载失败，请稍后重试')).toBeInTheDocument(); expect(screen.queryByText('私有分组')).not.toBeInTheDocument()
  })
  it('labels missing and ambiguous owners without guessing', async () => {
    const { state } = siteGroupPageFixture()
    state.groups = [{ ...group, user: null, user_state: 'missing' }, { ...group, id: scopeID, display_id: '9', user: null, user_state: 'ambiguous' }]
    renderGroups()
    expect(await screen.findByText('所属用户缺失')).toBeInTheDocument(); expect(screen.getByText('所属用户不唯一')).toBeInTheDocument()
    expect(screen.queryByText('tenant-a（27）')).not.toBeInTheDocument()
  })
  it('drops late directory results after an epoch change', async () => {
    let resolve!: (response: Response) => void; let calls = 0
    siteGroupPageFixture((url) => url.pathname === '/v1/admin/users' ? ++calls === 1 ? new Promise<Response>((done) => { resolve = done }) : json({ items: [], total: 0, page: 1, limit: 20 }) : undefined)
    renderGroups(); const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: '新增分组' })); await waitFor(() => expect(calls).toBe(1))
    act(() => useSessionStore.setState({ sessionEpoch: 2 }))
    await act(async () => resolve(json({ items: [managedUser], total: 1, page: 1, limit: 20 })))
    await user.click(screen.getByRole('button', { name: '新增分组' })); await user.click(screen.getByRole('combobox', { name: '用户' }))
    expect(await screen.findByText('暂无可选用户')).toBeInTheDocument(); expect(screen.queryByText('tenant-a（27）', { selector: '.ant-select-item-option-content' })).not.toBeInTheDocument()
  })
  it('removes selected user and editor when directory permission is revoked', async () => {
    const { fetchSpy } = siteGroupPageFixture(); renderGroups(); await siteGroupPageCreate()
    act(() => useSessionStore.setState({ principal: { ...useSessionStore.getState().principal!, permissions: ['sites.read', 'sites.manage'] } }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.getByText('无权查看网站分组')).toBeInTheDocument(); expect(fetchSpy.mock.calls.filter(([, init]) => init?.method)).toHaveLength(0)
  })
  it('paginates owner search and clears a hidden selection without auto-selecting', async () => {
    const second = { ...managedUser, id: scopeID, display_id: '28', username: 'tenant-b', scope_id: scopeID }
    const { fetchSpy } = siteGroupPageFixture((url) => {
      if (url.pathname !== '/v1/admin/users') return undefined
      const page = Number(url.searchParams.get('page')), search = url.searchParams.get('search')
      return json({ items: page === 2 || search ? [second] : [managedUser], total: search ? 1 : 21, page, limit: 20 })
    })
    renderGroups(); const { user, dialog } = await siteGroupPageCreate(); const selector = within(dialog).getByRole('combobox', { name: '用户' })
    await user.click(selector); await user.click(await screen.findByRole('button', { name: '加载更多用户' }))
    expect(await screen.findByText('tenant-b（28）')).toBeInTheDocument()
    await user.type(selector, 'tenant-b'); await waitFor(() => expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('search=tenant-b'))).toBe(true))
    expect(within(dialog).getByRole('button', { name: '确定' })).toBeDisabled()
    await user.click(await screen.findByText('tenant-b（28）')); await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('分组操作已完成并回读确认')).toBeInTheDocument()
    expect(JSON.parse(String(fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')![1]?.body)).target_scope_id).toBe(scopeID)
  })
  it('does not read or report success after a write finishes following logout', async () => {
    let resolve!: (response: Response) => void
    const { fetchSpy } = siteGroupPageFixture((_url, init) => init?.method === 'POST' ? new Promise<Response>((done) => { resolve = done }) : undefined)
    renderGroups(); const { user, dialog } = await siteGroupPageCreate(); await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
    expect(screen.getByRole('combobox', { name: '用户' })).toBeDisabled(); act(() => useSessionStore.getState().clearSession())
    const count = fetchSpy.mock.calls.length
    await act(async () => resolve(json({ ...group, name: '网站分组A', remark: '', revision: 1 }, 201)))
    expect(fetchSpy).toHaveBeenCalledTimes(count); expect(screen.queryByText('分组操作已完成并回读确认')).not.toBeInTheDocument()
    expect(screen.getByText('无权查看网站分组')).toBeInTheDocument()
  })
  it.each(['exact', 'list'])('keeps acknowledged writes GET-only after %s readback failure and a new QueryClient', async (failure) => {
    let saved = false, fail = true
    const { fetchSpy } = siteGroupPageFixture((url, init) => {
      if (init?.method === 'POST') saved = true
      return !init?.method && saved && fail && (failure === 'exact' ? url.pathname.startsWith('/v1/site-groups/') : url.pathname === '/v1/admin/site-groups') ? json({ error: { code: 'unavailable', message: 'raw read failure' } }, 503) : undefined
    })
    const view = renderGroups(); const { user, dialog } = await siteGroupPageCreate(); await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await screen.findByRole('button', { name: '重试读取' }); await waitFor(() => expect(screen.getByRole('button', { name: '重试读取' })).not.toHaveClass('ant-btn-loading'))
    expect(screen.queryByText('分组操作已完成并回读确认')).not.toBeInTheDocument(); expect(within(dialog).getByRole('button', { name: '确定' })).toBeDisabled()
    view.unmount(); fail = false; renderGroups()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1)
    await user.click(await screen.findByRole('button', { name: '重试读取' }))
    expect(await screen.findByText('分组操作已完成并回读确认')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1); expect(document.body.textContent).not.toContain('raw read failure')
  })
  it.each([503, 200])('retains unknown body/key after %s, then 409/422 and a full remount', async (initialStatus) => {
    let writes = 0
    const { fetchSpy } = siteGroupPageFixture((_url, init) => {
      if (init?.method !== 'POST') return undefined
      const status = [initialStatus, 409, 422][writes++]
      return status ? json({ error: { code: status === 409 ? 'revision_conflict' : status === 422 ? 'validation_error' : 'result_unknown', message: 'raw unknown' } }, status) : undefined
    })
    const view = renderGroups(); const { user, dialog } = await siteGroupPageCreate('原始名称'); await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await screen.findByRole('button', { name: '重试原请求' }); await waitFor(() => expect(screen.getByRole('button', { name: '重试原请求' })).not.toHaveClass('ant-btn-loading'))
    expect(within(dialog).getByLabelText('名称')).toBeDisabled(); expect(within(dialog).getByRole('button', { name: '取消' })).toBeDisabled()
    view.unmount(); renderGroups(); expect(writes).toBe(1); act(() => useSessionStore.setState({ accessToken: 'refreshed-token' }))
    for (let retry = 0; retry < 3; retry += 1) {
      await user.click(await screen.findByRole('button', { name: '重试原请求' })); await waitFor(() => expect(writes).toBe(retry + 2))
      if (retry < 2) await waitFor(() => expect(screen.getByRole('button', { name: '重试原请求' })).not.toHaveClass('ant-btn-loading'))
    }
    expect(await screen.findByText('分组操作已完成并回读确认')).toBeInTheDocument()
    const requests = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')
    expect(new Set(requests.map(([, init]) => init?.body)).size).toBe(1); expect(new Set(requests.map(([, init]) => new Headers(init?.headers).get('Idempotency-Key'))).size).toBe(1)
    expect(new Headers(requests[1][1]?.headers).get('Authorization')).toBe('Bearer refreshed-token'); expect(document.body.textContent).not.toContain('raw unknown')
  })
  it('allows only one in-flight write for double confirmation', async () => {
    let resolve!: (response: Response) => void
    const { fetchSpy } = siteGroupPageFixture((_url, init) => init?.method === 'POST' ? new Promise<Response>((done) => { resolve = done }) : undefined)
    renderGroups(); const { user, dialog } = await siteGroupPageCreate('仅一次'); await user.dblClick(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1))
    await act(async () => resolve(json({ ...group, name: '仅一次', remark: '', revision: 1 }, 201)))
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1)
  })
  it.each([
    { scope_id: scopeID }, { revision: 2 }, { name: '不同名称' }, { remark: '不同备注' },
  ])('keeps a mismatched write acknowledgement unknown: %j', async (mismatch) => {
    const { fetchSpy } = siteGroupPageFixture((_url, init) => init?.method === 'POST'
      ? json({ ...group, id: createdID, name: '网站分组A', remark: '', revision: 1, ...mismatch }, 201) : undefined)
    renderGroups(); const { user, dialog } = await siteGroupPageCreate()
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(screen.getByRole('button', { name: '重试原请求' })).not.toHaveClass('ant-btn-loading'))
    expect(within(dialog).getByRole('button', { name: '确定' })).toBeDisabled()
    expect(fetchSpy.mock.calls.some(([url]) => String(url).startsWith('/v1/site-groups/'))).toBe(false)
    expect(screen.queryByText('分组操作已完成并回读确认')).not.toBeInTheDocument()
  })
  it('does not submit a draft canceled before asynchronous validation finishes', async () => {
    const { fetchSpy } = siteGroupPageFixture(); renderGroups(); const { dialog } = await siteGroupPageCreate()
    await act(async () => { fireEvent.click(within(dialog).getByRole('button', { name: '确定' })); fireEvent.click(within(dialog).getByRole('button', { name: '取消' })) })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(fetchSpy.mock.calls.filter(([, init]) => init?.method)).toHaveLength(0)
  })
  it.each(['rename', 'delete'] as const)('retains exact target and revision for unknown %s retry', async (action) => {
    let writes = 0
    const { fetchSpy } = siteGroupPageFixture((_url, init) => init?.method && ++writes === 1 ? json({ error: { code: 'result_unknown', message: 'unknown' } }, 503) : undefined)
    renderGroups(); const user = userEvent.setup(); const row = (await screen.findByText('默认分组')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: action === 'rename' ? '编辑' : '删除' }))
    if (action === 'rename') { await user.clear(screen.getByLabelText('名称')); await user.type(screen.getByLabelText('名称'), '已重命名') }
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: action === 'rename' ? '确定' : '删除' }))
    await user.click(await screen.findByRole('button', { name: '重试原请求' })); expect(await screen.findByText('分组操作已完成并回读确认')).toBeInTheDocument()
    const requests = fetchSpy.mock.calls.filter(([, init]) => init?.method)
    expect(requests).toHaveLength(2); expect(requests[1][0]).toBe(`/v1/site-groups/${group.id}?scope_id=${tenantScope}`)
    expect(requests[1][1]?.body).toBe(requests[0][1]?.body); expect(requests[1][1]?.headers).toEqual(requests[0][1]?.headers)
    expect(new Headers(requests[1][1]?.headers).get('If-Match')).toBe('"3"')
  })
  it('isolates an unknown request from another owner and restores only for its original owner', async () => {
    const { fetchSpy } = siteGroupPageFixture((_url, init) => init?.method ? json({ error: { code: 'result_unknown', message: 'unknown' } }, 503) : undefined)
    renderGroups(); const original = useSessionStore.getState().principal!; const { user, dialog } = await siteGroupPageCreate('原用户请求')
    await user.click(within(dialog).getByRole('button', { name: '确定' })); await screen.findByRole('button', { name: '重试原请求' })
    act(() => useSessionStore.setState({ principal: { ...original, user_id: scopeID }, sessionEpoch: 2 }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.queryByRole('button', { name: '重试原请求' })).not.toBeInTheDocument(); expect(screen.queryByText('原用户请求')).not.toBeInTheDocument()
    act(() => useSessionStore.setState({ principal: original, sessionEpoch: 3 }))
    expect(await screen.findByRole('button', { name: '重试原请求' })).toBeInTheDocument(); expect(fetchSpy.mock.calls.filter(([, init]) => init?.method)).toHaveLength(1)
  })
  it.each(['quota', 'corrupt'])('blocks writes when retry storage is %s', async (failure) => {
    const { fetchSpy } = siteGroupPageFixture()
    if (failure === 'quota') vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('quota') })
    else sessionStorage.setItem(siteGroupRetryStorageKey(['platform', platformScope, principal().user_id]), '{')
    renderGroups()
    if (failure === 'quota') { const { user, dialog } = await siteGroupPageCreate(); await user.click(within(dialog).getByRole('button', { name: '确定' })) }
    expect(await screen.findByText(i18n.t('siteGroups:errors.storage'))).toBeInTheDocument(); expect(fetchSpy.mock.calls.filter(([, init]) => init?.method)).toHaveLength(0)
  })
  it('distinguishes a concurrent later revision from exact synchronization', async () => {
    const { fetchSpy } = siteGroupPageFixture((url) => url.pathname.startsWith('/v1/site-groups/') ? json({ ...group, id: createdID, revision: 2, name: '后来版本', remark: 'later' }) : undefined)
    renderGroups(); const { user, dialog } = await siteGroupPageCreate(); await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText(i18n.t('siteGroups:messages.superseded'))).toBeInTheDocument(); expect(screen.queryByText('分组操作已完成并回读确认')).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method)).toHaveLength(1)
  })
  it('retains a later-version warning after failed list readback and a fresh QueryClient', async () => {
    let saved = false, failList = true
    const { fetchSpy } = siteGroupPageFixture((url, init) => {
      if (init?.method === 'POST') saved = true
      if (url.pathname.startsWith('/v1/site-groups/')) return json({ ...group, id: createdID, revision: 2, name: '后来版本', remark: 'later' })
      if (!init?.method && saved && failList && url.pathname === '/v1/admin/site-groups') return json({ error: { code: 'unavailable', message: 'read failure' } }, 503)
      return undefined
    })
    const view = renderGroups(); const { user, dialog } = await siteGroupPageCreate()
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(screen.getByRole('button', { name: '重试读取' })).not.toHaveClass('ant-btn-loading'))
    view.unmount(); failList = false; renderGroups()
    await user.click(await screen.findByRole('button', { name: '重试读取' }))
    expect(await screen.findByText(i18n.t('siteGroups:messages.superseded'))).toBeInTheDocument()
    expect(screen.queryByText('分组操作已完成并回读确认')).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method)).toHaveLength(1)
  })
  it.each(['mismatch', '403'])('stops a serial batch on %s readback before the next delete', async (failure) => {
    const { state, fetchSpy } = siteGroupPageFixture((url, init) => !init?.method && url.pathname.startsWith('/v1/site-groups/') ? failure === '403'
      ? json({ error: { code: 'permission_denied', message: 'hidden' } }, 403) : json(group) : undefined)
    state.groups.push({ ...group, id: scopeID, display_id: '8', name: '第二分组' })
    renderGroups(); const user = userEvent.setup(); await screen.findByText('第二分组')
    const bulkDelete = screen.getAllByRole('button', { name: '删除' })[0]
    expect(bulkDelete).toHaveClass('ant-btn-default', 'ant-btn-dangerous')
    expect(bulkDelete).not.toHaveClass('ant-btn-primary')
    await user.click(screen.getAllByRole('checkbox')[0]); await user.click(bulkDelete)
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'DELETE')).toHaveLength(0)
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: '删除' }))
    if (failure === '403') await screen.findByText('无权查看网站分组')
    else await waitFor(() => expect(screen.getByRole('button', { name: '重试读取' })).not.toHaveClass('ant-btn-loading'))
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'DELETE')).toHaveLength(1)
  })
  it('stops after an awaited batch read when write permission is revoked in the same epoch', async () => {
    let resolve!: (response: Response) => void
    const { state, fetchSpy } = siteGroupPageFixture((url, init) => !init?.method && url.pathname.startsWith('/v1/site-groups/')
      ? new Promise<Response>((done) => { resolve = done }) : undefined)
    state.groups.push({ ...group, id: scopeID, display_id: '8', name: '第二分组' })
    renderGroups(); const user = userEvent.setup(); await screen.findByText('第二分组')
    await user.click(screen.getAllByRole('checkbox')[0]); await user.click(screen.getAllByRole('button', { name: '删除' })[0])
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: '删除' }))
    await waitFor(() => expect(resolve).toBeTypeOf('function'))
    act(() => useSessionStore.setState({ principal: { ...useSessionStore.getState().principal!, permissions: ['sites.read', 'identity.users.manage'] } }))
    await act(async () => resolve(json({ error: { code: 'not_found', message: 'not found' } }, 404)))
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'DELETE')).toHaveLength(1)
    expect(pageDialogs()).toHaveLength(0)
    expect(screen.queryByText('分组操作已完成并回读确认')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增分组' })).toBeDisabled()
  })
  it('keeps a batch frozen across remount and sends remaining deletes only after manual recovery', async () => {
    let first = true
    const { state, fetchSpy } = siteGroupPageFixture((_url, init) => { if (init?.method === 'DELETE' && first) { first = false; return json({ error: { code: 'result_unknown', message: 'unknown' } }, 503) } return undefined })
    state.groups.push({ ...group, id: scopeID, display_id: '8', name: '第二分组' })
    const view = renderGroups(); const user = userEvent.setup(); await screen.findByText('第二分组')
    await user.click(screen.getAllByRole('checkbox')[0]); await user.click(screen.getAllByRole('button', { name: '删除' })[0]); await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: '删除' }))
    await waitFor(() => expect(screen.getByRole('button', { name: '重试原请求' })).not.toHaveClass('ant-btn-loading'))
    view.unmount(); renderGroups(); expect(fetchSpy.mock.calls.filter(([, init]) => init?.method)).toHaveLength(1)
    await user.click(screen.getByRole('button', { name: '重试原请求' })); expect(await screen.findByText('分组操作已完成并回读确认')).toBeInTheDocument()
    const writes = fetchSpy.mock.calls.filter(([, init]) => init?.method)
    expect(writes).toHaveLength(3); expect(writes[0][0]).toBe(writes[1][0]); expect(writes[0][1]?.headers).toEqual(writes[1][1]?.headers); expect(writes[2][0]).toContain(scopeID)
  })
  it('clears current-page selection on the next real page', async () => {
    const { state } = siteGroupPageFixture()
    state.groups = Array.from({ length: 11 }, (_, index) => ({ ...group, id: `${String(index).padStart(8, '0')}-3333-4333-8333-333333333333`, display_id: String(index + 1), name: `分组${index}` }))
    renderGroups(); const user = userEvent.setup(); await screen.findByText('分组0'); await user.click(screen.getAllByRole('checkbox')[0]); await user.click(screen.getByTitle('2'))
    expect(await screen.findByText('分组10')).toBeInTheDocument(); expect(screen.getAllByRole('button', { name: '删除' })[0]).toBeDisabled()
    expect(screen.getAllByRole('checkbox').every((checkbox) => !(checkbox as HTMLInputElement).checked)).toBe(true)
  })
  it('rejects malformed scope', async () => {
    siteGroupPageFixture()
    act(() => useSessionStore.setState({ accessToken: 'access-token', sessionEpoch: 1, status: 'authenticated', principal: principal({ scope_id: 'bad-scope', tenant_id: null, permissions: ['sites.read'] }) })); renderWithProviders(<SiteGroupsPage />)
    expect(screen.getByText('请先选择租户作用域')).toBeInTheDocument()
  })
})
