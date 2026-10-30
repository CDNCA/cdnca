import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CdncaProvider } from '@cdnca/ui'
import { ApiError } from '../api/auth'
import { streamGroupsApi, type StreamGroup, type StreamUserConfig } from '../api/streamGroups'
import { usersApi, type ManagedUser } from '../api/users'
import { useSessionStore } from '../auth/session'
import StreamGroupsPanel from '../pages/StreamGroupsPanel'
import StreamDefaultsPanel from '../pages/StreamDefaultsPanel'
import { authResponse, principal } from '../test/fixtures'

// 加载/请求失败从页内 Alert 改为 FeedbackWhen 居中弹窗（.cdnca-feedback）
const findFeedback = () => waitFor(() => { const element = document.querySelector<HTMLElement>('.cdnca-feedback'); if (!element) throw new Error('no feedback dialog'); return element })

const ownerID = '44444444-4444-4444-8444-444444444444'
const otherID = '55555555-5555-4555-8555-555555555555'
const group: StreamGroup = {
  id: '88888888-8888-4888-8888-888888888888', display_id: '1', scope_id: principal().scope_id,
  owner: { id: ownerID, display_name: '用户甲' }, name: '分组甲', remark: '', stream_count: 0,
  revision: 3, created_at: '', updated_at: '',
}
const config: StreamUserConfig = {
  id: group.id, display_id: '1', scope_id: group.scope_id, owner: group.owner,
  setting_name: 'listen_protocol', setting_value: 'tcp', scope_name: 'global', group: null, created_at: '',
}
const owner = { id: ownerID, scope_id: group.scope_id, display_name: '用户甲', username: 'owner-a' } as ManagedUser
const other = { ...owner, id: otherID, scope_id: otherID, display_name: '用户乙' }
function list<T>(items: T[], page = 1, total = items.length, limit = 10) { return { items, page, total, limit } }
function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}

const panels = [
  { kind: 'groups', add: '新增分组', created: '分组已创建', read: 'listGroups', create: 'createGroup', remove: 'removeGroup', item: group, key: 'stream-groups' },
  { kind: 'defaults', add: '新增设置', created: '默认设置已创建', read: 'listUserConfigs', create: 'createUserConfig', remove: 'removeUserConfig', item: config, key: 'stream-user-configs' },
] as const
type Panel = typeof panels[number]

function setup(panel: Panel, admin = false, permissions?: string[]) {
  const actor = principal({ scope_kind: admin ? 'platform' : 'tenant', permissions: permissions ?? ['streams.read', 'streams.manage', ...(admin ? ['identity.users.manage'] : [])] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  function PanelHost() {
    const state = useSessionStore()
    if (!state.principal || !state.accessToken) return null
    const props = { accessToken: state.accessToken, scopeKind: state.principal.scope_kind, scopeID: state.principal.scope_id,
      sessionEpoch: state.sessionEpoch, isAdmin: admin, lockWrites: false }
    const manage = state.principal.permissions.some((value) => ['streams.manage', 'platform.admin'].includes(value))
    return panel.kind === 'groups' ? <StreamGroupsPanel key={state.sessionEpoch} {...props} canManageGroups={manage} /> : <StreamDefaultsPanel key={state.sessionEpoch} {...props} canManageDefaults={manage} />
  }
  const tree = (visible: boolean) => <CdncaProvider><QueryClientProvider client={client}>{visible ? <PanelHost /> : null}</QueryClientProvider></CdncaProvider>
  const rendered = render(tree(true))
  return { ...rendered, show: (visible: boolean) => rendered.rerender(tree(visible)), user: userEvent.setup(), actor, client }
}

async function openCreate(panel: Panel, user: ReturnType<typeof userEvent.setup>) {
  await waitFor(() => expect(screen.getByRole('button', { name: panel.add })).toBeEnabled())
  await user.click(screen.getByRole('button', { name: panel.add }))
  const dialog = await screen.findByRole('dialog')
  if (panel.kind === 'groups') await user.type(within(dialog).getByRole('textbox', { name: '名称' }), '新增名称')
  return dialog
}

describe.each(panels)('$kind natural states and write recovery', (panel) => {
  beforeEach(() => {
    vi.spyOn(streamGroupsApi, 'listGroups').mockResolvedValue(list([group]))
    vi.spyOn(streamGroupsApi, 'listUserConfigs').mockResolvedValue(list([config]))
    vi.spyOn(usersApi, 'list').mockResolvedValue(list([owner]))
  })

  it('allows a platform.admin-only principal to read the panel', async () => {
    setup(panel, true, ['platform.admin'])
    await waitFor(() => expect(streamGroupsApi[panel.read]).toHaveBeenCalledOnce())
    expect(await screen.findByText('用户甲')).toBeInTheDocument()
  })

  it('retries failed reads and renders an empty result without raw errors', async () => {
    vi.mocked(streamGroupsApi[panel.read]).mockRejectedValueOnce(new ApiError('private raw response', 503, 'request_failed')).mockResolvedValueOnce(list([]))
    const { user } = setup(panel)
    expect(await findFeedback()).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private raw response')
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
  })

  it('freezes an unknown create and retries its exact body and key', async () => {
    const create = vi.spyOn(streamGroupsApi, panel.create).mockRejectedValueOnce(new ApiError('lost response', 0, 'network_error')).mockResolvedValue(panel.item as never)
    const { user } = setup(panel)
    const dialog = await openCreate(panel, user)
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(create).toHaveBeenCalledOnce())
    await waitFor(() => expect(screen.getByRole('button', { name: panel.add })).toBeDisabled())
    await user.click(screen.getByRole('button', { name: '按原请求重试' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]).toEqual(create.mock.calls[0])
    expect(await screen.findByText(panel.created)).toBeInTheDocument()
  })

  it('includes the selected owner tenant in administrator creates', async () => {
    const create = vi.spyOn(streamGroupsApi, panel.create).mockResolvedValue(panel.item as never)
    const { user } = setup(panel, true)
    const dialog = await openCreate(panel, user)
    await user.click(within(dialog).getByRole('combobox', { name: '用户' }))
    await user.click(await screen.findByText('用户甲', { selector: '.ant-select-item-option-content' }))
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(create).toHaveBeenCalledOnce())
    expect(create.mock.calls[0][1]).toMatchObject({ owner_id: owner.id, target_scope_id: owner.scope_id })
  })

  it.each([false, true])('preserves the request after leaving the panel (pending=%s)', async (pendingOnLeave) => {
    const pending = deferred<StreamGroup & StreamUserConfig>()
    const create = vi.spyOn(streamGroupsApi, panel.create)
    if (pendingOnLeave) create.mockReturnValueOnce(pending.promise)
    else create.mockRejectedValueOnce(new ApiError('lost response', 0, 'network_error'))
    create.mockResolvedValue(panel.item as never)
    const { user, show } = setup(panel)
    const dialog = await openCreate(panel, user)
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(create).toHaveBeenCalledOnce())
    if (!pendingOnLeave) await screen.findByRole('button', { name: '按原请求重试' })
    show(false)
    show(true)
    if (pendingOnLeave) {
      const retry = await screen.findByRole('button', { name: /按原请求重试/ })
      expect(retry).toBeDisabled()
      await user.click(retry)
      expect(create).toHaveBeenCalledOnce()
      await act(async () => pending.reject(new ApiError('lost response', 0, 'network_error')))
    }
    await waitFor(() => expect(screen.getByRole('button', { name: '按原请求重试' })).toBeEnabled())
    expect(screen.getByRole('button', { name: panel.add })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '按原请求重试' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]).toEqual(create.mock.calls[0])
  })

  it('blocks owner reads without user-management permission', async () => {
    const { user } = setup(panel, true, ['streams.read', 'streams.manage'])
    const dialog = await openCreate(panel, user)
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('当前账号无权读取归属用户列表')
    expect(usersApi.list).not.toHaveBeenCalled()
    expect(within(dialog).getByRole('button', { name: '确认' })).toBeDisabled()
  })

  it('returns to the last available page after deleting its final item', async () => {
    const read = vi.mocked(streamGroupsApi[panel.read]).mockResolvedValueOnce(list([panel.item], 1, 11) as never)
      .mockResolvedValueOnce(list([panel.item], 2, 11) as never).mockResolvedValueOnce(list([], 2, 10) as never)
      .mockResolvedValue(list([panel.item], 1, 10) as never)
    const remove = vi.spyOn(streamGroupsApi, panel.remove).mockResolvedValue(undefined)
    const { user } = setup(panel)
    await screen.findByText('用户甲')
    await user.click(screen.getByTitle('2'))
    await waitFor(() => expect(read).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(screen.getAllByRole('button', { name: '删除' })[1]).toBeEnabled())
    await user.click(screen.getAllByRole('button', { name: '删除' })[1])
    await user.click(await screen.findByRole('button', { name: '确认删除' }))
    await waitFor(() => expect(remove).toHaveBeenCalledOnce())
    await waitFor(() => expect(read).toHaveBeenCalledTimes(4))
    expect(read).toHaveBeenLastCalledWith(expect.any(String), { page: 1, limit: 10 })
  })

  it('hides stale data and prevents writes after a list 403', async () => {
    const read = vi.mocked(streamGroupsApi[panel.read])
    const { client, actor } = setup(panel)
    await screen.findByText('用户甲')
    read.mockRejectedValue(new ApiError('private response', 403, 'permission_denied'))
    await act(async () => { await client.invalidateQueries({ queryKey: [panel.key, actor.scope_kind, actor.scope_id] }) })
    await waitFor(() => expect(screen.queryByText('用户甲')).not.toBeInTheDocument())
    expect(screen.getByRole('button', { name: panel.add })).toBeDisabled()
    expect(read).toHaveBeenCalledTimes(2)
  })

  it('rejects blank group names or resets default values after cancel', async () => {
    const create = vi.spyOn(streamGroupsApi, panel.create)
    const { user } = setup(panel)
    const dialog = await openCreate(panel, user)
    if (panel.kind === 'groups') {
      await user.clear(within(dialog).getByRole('textbox', { name: '名称' }))
      await user.type(within(dialog).getByRole('textbox', { name: '名称' }), '   ')
      await user.click(within(dialog).getByRole('button', { name: '确认' }))
      expect(await screen.findByText('请输入分组名称')).toBeInTheDocument()
    } else {
      await user.click(within(dialog).getByRole('radio', { name: '转发分组' }).closest('label')!)
      await user.click(within(dialog).getByRole('button', { name: '取消' }))
      const fresh = await openCreate(panel, user)
      expect(within(fresh).getByRole('radio', { name: '全局' })).toBeChecked()
    }
    expect(create).not.toHaveBeenCalled()
  })

  it('discards late reads after access is revoked', async () => {
    const pending = deferred<ReturnType<typeof list<StreamGroup & StreamUserConfig>>>()
    vi.mocked(streamGroupsApi[panel.read]).mockReturnValueOnce(pending.promise)
    const { actor, client, unmount } = setup(panel)
    const epoch = useSessionStore.getState().sessionEpoch
    await waitFor(() => expect(streamGroupsApi[panel.read]).toHaveBeenCalledOnce())
    act(() => useSessionStore.getState().setSession(authResponse(actor), { ...actor, permissions: [] }, 'refresh'))
    unmount()
    await act(async () => pending.resolve(list([panel.item as StreamGroup & StreamUserConfig])))
    expect(client.getQueryData([panel.key, actor.scope_kind, actor.scope_id, epoch, 1, 10])).toBeUndefined()
  })

  it('suppresses late create results after a new login', async () => {
    const pending = deferred<StreamGroup & StreamUserConfig>()
    const create = vi.spyOn(streamGroupsApi, panel.create).mockReturnValue(pending.promise)
    const { user, actor } = setup(panel)
    const dialog = await openCreate(panel, user)
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(create).toHaveBeenCalledOnce())
    act(() => useSessionStore.getState().setSession(authResponse(actor), actor))
    await act(async () => pending.resolve(panel.item as StreamGroup & StreamUserConfig))
    expect(screen.queryByText(panel.created)).not.toBeInTheDocument()
  })

  it('retains an unknown request through temporary write-permission revocation', async () => {
    const pending = deferred<StreamGroup & StreamUserConfig>()
    const create = vi.spyOn(streamGroupsApi, panel.create).mockReturnValueOnce(pending.promise).mockResolvedValue(panel.item as never)
    const { user, actor } = setup(panel)
    const dialog = await openCreate(panel, user)
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(create).toHaveBeenCalledOnce())
    act(() => useSessionStore.getState().setSession(authResponse(actor), { ...actor, permissions: ['streams.read'] }, 'refresh'))
    await act(async () => pending.reject(new ApiError('lost response', 0, 'network_error')))
    expect(screen.queryByRole('button', { name: '按原请求重试' })).not.toBeInTheDocument()
    act(() => useSessionStore.getState().setSession(authResponse(actor), actor, 'refresh'))
    await user.click(await screen.findByRole('button', { name: '按原请求重试' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]).toEqual(create.mock.calls[0])
  })

  it('retains unknown delete outcomes while write permission is revoked', async () => {
    const pending = deferred<void>()
    const remove = vi.spyOn(streamGroupsApi, panel.remove).mockReturnValueOnce(pending.promise).mockResolvedValue(undefined)
    const { user, actor } = setup(panel)
    await screen.findByText('用户甲')
    await user.click(screen.getAllByRole('button', { name: '删除' })[1])
    await user.click(await screen.findByRole('button', { name: '确认删除' }))
    await waitFor(() => expect(remove).toHaveBeenCalledOnce())
    act(() => useSessionStore.getState().setSession(authResponse(actor), { ...actor, permissions: ['streams.read'] }, 'refresh'))
    await act(async () => pending.reject(new ApiError('lost response', 0, 'network_error')))
    act(() => useSessionStore.getState().setSession(authResponse(actor), actor, 'refresh'))
    await user.click(await screen.findByRole('button', { name: '按原请求重试' }))
    await waitFor(() => expect(remove).toHaveBeenCalledTimes(2))
    expect(remove.mock.calls[1]).toEqual(remove.mock.calls[0])
  })

  it('waits for every delete outcome, refreshes successes and retries only unknown items', async () => {
    const second = { ...panel.item, id: otherID, display_id: '2' }
    vi.mocked(streamGroupsApi[panel.read]).mockResolvedValueOnce(list([panel.item, second]) as never).mockResolvedValue(list([panel.item]) as never)
    const pending = deferred<void>()
    const remove = vi.spyOn(streamGroupsApi, panel.remove).mockRejectedValueOnce(new ApiError('lost response', 0, 'network_error')).mockReturnValueOnce(pending.promise).mockResolvedValue(undefined)
    const { user } = setup(panel)
    await screen.findAllByText('用户甲')
    await user.click(screen.getAllByRole('checkbox')[0])
    await user.click(screen.getAllByRole('button', { name: '删除' })[0])
    await user.click(await screen.findByRole('button', { name: '确认删除' }))
    await waitFor(() => expect(remove).toHaveBeenCalledTimes(2))
    expect(screen.getByRole('button', { name: panel.add })).toBeDisabled()
    await act(async () => pending.resolve())
    await waitFor(() => expect(streamGroupsApi[panel.read]).toHaveBeenCalledTimes(2))
    await user.click(await screen.findByRole('button', { name: '按原请求重试' }))
    await waitFor(() => expect(remove).toHaveBeenCalledTimes(3))
    expect(remove.mock.calls[2]).toEqual(remove.mock.calls[0])
    expect(remove.mock.calls[1][1].id).toBe(otherID)
  })

  it('does not delete after permission is revoked while confirmation is open', async () => {
    const remove = vi.spyOn(streamGroupsApi, panel.remove)
    const { user, actor } = setup(panel)
    await screen.findByText('用户甲')
    await user.click(screen.getAllByRole('button', { name: '删除' })[1])
    await screen.findByRole('button', { name: '确认删除' })
    act(() => useSessionStore.getState().setSession(authResponse(actor), { ...actor, permissions: ['streams.read'] }, 'refresh'))
    const confirm = screen.queryByRole('button', { name: '确认删除' })
    if (confirm) await user.click(confirm)
    expect(remove).not.toHaveBeenCalled()
  })

  it('loads owners beyond the first page and retries selector failures', async () => {
    vi.mocked(usersApi.list).mockRejectedValueOnce(new ApiError('raw owner error', 503, 'request_failed'))
      .mockResolvedValueOnce(list([owner], 1, 101, 100)).mockResolvedValueOnce(list([other], 2, 101, 100))
    const { user } = setup(panel, true)
    const dialog = await openCreate(panel, user)
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('用户列表加载失败')
    expect(dialog).not.toHaveTextContent('raw owner error')
    await user.click(within(dialog).getByRole('button', { name: '重试' }))
    await user.click(within(dialog).getByRole('combobox', { name: '用户' }))
    expect(await screen.findByText('用户乙', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    expect(usersApi.list).toHaveBeenLastCalledWith(expect.any(String), { page: 2, limit: 100 })
  })
})

describe('default group options', () => {
  it('loads every group page, filters by the selected owner tenant and clears a previous owner group', async () => {
    vi.spyOn(streamGroupsApi, 'listUserConfigs').mockResolvedValue(list([]))
    vi.spyOn(usersApi, 'list').mockResolvedValue(list([owner, other]))
    const otherGroup = { ...group, id: otherID, scope_id: otherID, name: '分组乙', owner: { id: otherID, display_name: '用户乙' } }
    const wrongOwnerGroup = { ...group, id: '99999999-9999-4999-8999-999999999999', name: '同租户其他用户分组', owner: otherGroup.owner }
    const read = vi.spyOn(streamGroupsApi, 'listGroups').mockImplementation(async (_, params) => params.page === 1 ? list([group, wrongOwnerGroup], 1, 101, 100) : list([otherGroup], 2, 101, 100))
    const create = vi.spyOn(streamGroupsApi, 'createUserConfig').mockResolvedValue(config)
    const { user } = setup(panels[1], true)
    const dialog = await openCreate(panels[1], user)
    await user.click(within(dialog).getByRole('combobox', { name: '用户' }))
    await user.click(await screen.findByText('用户甲', { selector: '.ant-select-item-option-content' }))
    await user.click(within(dialog).getByRole('radio', { name: '转发分组' }).closest('label')!)
    await user.click(within(dialog).getByRole('combobox', { name: '转发分组' }))
    await user.click(await screen.findByText('分组甲', { selector: '.ant-select-item-option-content' }))
    expect(screen.queryByText('分组乙', { selector: '.ant-select-item-option-content' })).not.toBeInTheDocument()
    expect(screen.queryByText('同租户其他用户分组', { selector: '.ant-select-item-option-content' })).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('combobox', { name: '用户' }))
    await user.click(await screen.findByText('用户乙', { selector: '.ant-select-item-option-content' }))
    expect(within(dialog).getByRole('combobox', { name: '转发分组' }).closest('.ant-select')).not.toHaveTextContent('分组甲')
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    expect(create).not.toHaveBeenCalled()
    await user.click(within(dialog).getByRole('combobox', { name: '转发分组' }))
    expect(await screen.findByText('分组乙', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    expect(screen.queryByText('分组甲', { selector: '.ant-select-item-option-content' })).not.toBeInTheDocument()
    expect(read).toHaveBeenCalledWith(expect.any(String), { page: 2, limit: 100 })
    await user.click(screen.getByText('分组乙', { selector: '.ant-select-item-option-content' }))
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(create).toHaveBeenCalledOnce())
    expect(create.mock.calls[0][1]).toMatchObject({ owner_id: otherID, target_scope_id: otherID, group_id: otherID })
  })

  it('retries group-option errors and saves a tenant default without an administrator target', async () => {
    vi.spyOn(streamGroupsApi, 'listUserConfigs').mockResolvedValue(list([]))
    const read = vi.spyOn(streamGroupsApi, 'listGroups').mockRejectedValueOnce(new ApiError('private group error', 503, 'request_failed'))
      .mockResolvedValue(list([{ ...group, owner: { id: principal().user_id, display_name: '当前用户' } }]))
    const create = vi.spyOn(streamGroupsApi, 'createUserConfig').mockResolvedValue(config)
    const { user } = setup(panels[1])
    const dialog = await openCreate(panels[1], user)
    await user.click(within(dialog).getByRole('radio', { name: '转发分组' }).closest('label')!)
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('分组列表加载失败')
    expect(dialog).not.toHaveTextContent('private group error')
    expect(within(dialog).getByRole('button', { name: '确认' })).toBeDisabled()
    await user.click(within(dialog).getByRole('button', { name: '重试' }))
    await waitFor(() => expect(within(dialog).getByRole('combobox', { name: '转发分组' })).toBeEnabled())
    await user.click(within(dialog).getByRole('combobox', { name: '转发分组' }))
    await user.click(await screen.findByText('分组甲', { selector: '.ant-select-item-option-content' }))
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(create).toHaveBeenCalledOnce())
    expect(create.mock.calls[0][1]).toEqual({ setting_name: 'listen_protocol', setting_value: 'tcp', scope_name: 'group', group_id: group.id })
    expect(read).toHaveBeenCalledTimes(2)
  })
})
