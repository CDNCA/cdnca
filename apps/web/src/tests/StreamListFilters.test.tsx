import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ApiError } from '../api/auth'
import { streamsApi } from '../api/streams'
import { streamGroupsApi, type StreamGroup } from '../api/streamGroups'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import StreamListPage from '../pages/StreamListPage'
import { stream } from './streamFixture'

const groupID = '88888888-8888-4888-8888-888888888888'
function authenticate(admin = true, permissions?: string[]) {
  const actor = principal({ scope_kind: admin ? 'platform' : 'tenant', permissions: permissions ?? (admin ? ['platform.admin'] : ['streams.read']) })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  return actor
}
async function setup() {
  const list = vi.spyOn(streamsApi, 'list').mockImplementation(async (_, params) => ({ items: [stream], total: 30, page: params.page, limit: params.limit }))
  renderWithProviders(<StreamListPage />, ['/stream/list'])
  await screen.findByText(stream.name)
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: /^高级筛选/ }))
  const panel = within(screen.getByRole('group', { name: '高级筛选' }))
  return { list, user, panel }
}

// fix-advfilter2：高级筛选展开状态记在 localStorage，各用例从收起开始。
beforeEach(() => { localStorage.removeItem('cdnca.advancedFilters.stream-list') })

describe('stream list precise filters', () => {
  it('preserves advanced source filters while replacing quick user and publication conditions', async () => {
    authenticate()
    const list = vi.spyOn(streamsApi, 'list').mockResolvedValue({ items: [stream], total: 1, page: 1, limit: 10 })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText(stream.name)
    const user = userEvent.setup()
    const chooseField = async (label: string) => {
      await user.click(screen.getByRole('combobox', { name: '搜索字段' }))
      await user.click(await screen.findByText(label, { selector: '.ant-select-item-option-content' }))
    }
    await user.click(screen.getByRole('button', { name: /^高级筛选/ }))
    const panel = within(screen.getByRole('group', { name: '高级筛选' }))
    await user.type(panel.getByRole('textbox', { name: '源IP' }), 'Origin_%')
    await user.click(panel.getByRole('button', { name: '应用' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual(expect.objectContaining({ upstream: 'Origin_%', page: 1 })))
    expect(list.mock.calls.at(-1)?.[1]).not.toHaveProperty('search')
    await chooseField('用户ID')
    // fix-livefilter：转发ID/用户ID 改为可按名称联想的 IdOrNameInput（role=combobox）。
    await user.type(screen.getByRole('combobox', { name: '搜索转发' }), '9223372036854775807')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual(expect.objectContaining({ owner_display_id: '9223372036854775807', upstream: 'Origin_%' })))
    await chooseField('发布状态')
    await user.click(screen.getByRole('combobox', { name: '搜索转发' }))
    await user.click(await screen.findByText('等待重试', { selector: '.ant-select-item-option-content' }))
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual(expect.objectContaining({ publication_state: 'retrying', upstream: 'Origin_%' })))
    expect(list.mock.calls.at(-1)?.[1]).not.toHaveProperty('owner_display_id')
    expect(panel.getByRole('combobox', { name: '用户ID' })).toHaveValue('')
    fireEvent.change(panel.getByRole('combobox', { name: '用户ID' }), { target: { value: '9223372036854775808' } })
    const calls = list.mock.calls.length
    await user.click(panel.getByRole('button', { name: '应用' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('用户编号')
    expect(list).toHaveBeenCalledTimes(calls)
    await user.click(screen.getByRole('button', { name: '重置' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 1, limit: 10 }))
  })

  it('combines the backend filters, loads later option pages, paginates and resets', async () => {
    authenticate()
    const groups = vi.spyOn(streamGroupsApi, 'listGroups').mockImplementation(async (_, { page }) => ({ items: page === 1 ? [{ id: stream.id, name: '第一页', scope_id: stream.scope_id } as StreamGroup] : [{ id: groupID, name: '筛选分组', scope_id: stream.scope_id } as StreamGroup], page, total: 101, limit: 100 }))
    const { list, user, panel } = await setup()
    expect(groups).not.toHaveBeenCalled()
    expect(panel.queryByRole('combobox', { name: '转发套餐' })).toBeNull()
    await user.click(screen.getByTitle('2'))
    await user.type(panel.getByLabelText('监听端口'), '18100')
    await user.type(panel.getByLabelText('源IP'), ' Origin_% ')
    await user.type(panel.getByLabelText('CNAME域名'), 'edge.example.net')
    await user.type(panel.getByLabelText('CNAME主机名'), 'tenant-edge')
    await user.type(panel.getByLabelText('转发ID'), '9223372036854775807')
    await user.click(panel.getByRole('combobox', { name: '转发分组' }))
    await user.click(await screen.findByText('筛选分组', { selector: '.ant-select-item-option-content' }))
    await waitFor(() => expect(panel.getByRole('combobox', { name: '转发分组' }).closest('.ant-select')).toHaveTextContent('筛选分组'))
    await user.click(panel.getByRole('button', { name: '应用' }))
    const expected = { page: 1, limit: 10, listen_port: 18100, upstream: 'Origin_%', cname_domain: 'edge.example.net', cname_hostname: 'tenant-edge', display_id: '9223372036854775807', group_id: groupID }
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining(expected)))
    expect(list.mock.calls.at(-1)?.[1]).not.toHaveProperty('search')
    await user.click(screen.getByTitle('2'))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual(expect.objectContaining({ ...expected, page: 2 })))
    await user.click(screen.getByRole('button', { name: '重置' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 1, limit: 10 }))
    expect(panel.getByLabelText('源IP')).toHaveValue('')
    expect(groups).toHaveBeenCalledTimes(2)
  })

  it.each([['监听端口', '65536'], ['监听端口', '0181'], ['转发ID', '0'], ['转发ID', '9223372036854775808'], ['源IP', 'x'.repeat(254)]])('rejects invalid %s without issuing a list request', async (label, value) => {
    authenticate()
    const { list, user, panel } = await setup()
    fireEvent.change(panel.getByLabelText(label), { target: { value } })
    await user.click(panel.getByRole('button', { name: '应用' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/端口|编号|源站/)
    expect(list).toHaveBeenCalledTimes(1)
  })

  it('shows localized option errors and allows an explicit retry', async () => {
    authenticate()
    const groups = vi.spyOn(streamGroupsApi, 'listGroups').mockRejectedValueOnce(new ApiError('raw failure', 403, 'permission_denied')).mockResolvedValue({ items: [{ id: groupID, name: '重试分组', scope_id: stream.scope_id } as StreamGroup], page: 1, limit: 100, total: 1 })
    const { user, panel } = await setup()
    await user.click(panel.getByRole('combobox', { name: '转发分组' }))
    await user.click(await screen.findByRole('button', { name: '重试' }))
    expect(await screen.findByText('重试分组', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    expect(groups).toHaveBeenCalledTimes(2)
    expect(document.body.textContent).not.toContain('raw failure')
  })

  it('discards late option responses when the session changes', async () => {
    authenticate()
    let resolve!: (value: Awaited<ReturnType<typeof streamGroupsApi.listGroups>>) => void
    vi.spyOn(streamGroupsApi, 'listGroups').mockReturnValue(new Promise((done) => { resolve = done }))
    const { user, panel } = await setup()
    await user.click(panel.getByRole('combobox', { name: '转发分组' }))
    act(() => { authenticate(false) })
    await act(async () => resolve({ items: [{ id: groupID, name: '旧会话分组', scope_id: stream.scope_id } as StreamGroup], page: 1, total: 1, limit: 100 }))
    expect(screen.queryByText('旧会话分组')).not.toBeInTheDocument()
  })
})
