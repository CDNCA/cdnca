import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { streamsApi } from '../api/streams'
import { streamGroupsApi, type StreamGroup } from '../api/streamGroups'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import { pseudoCN, zhCN } from '../i18n/resources'
import StreamListPage from '../pages/StreamListPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { stream } from './streamFixture'

async function setupQuickSearch() {
  const actor = principal({ scope_kind: 'platform', permissions: ['platform.admin'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  const list = vi.spyOn(streamsApi, 'list').mockImplementation(async (_, params) => ({ items: [stream], total: 30, page: params.page, limit: params.limit }))
  renderWithProviders(<StreamListPage />, ['/stream/list'])
  await screen.findByText(stream.name)
  const user = userEvent.setup()
  const chooseField = async (label: string) => {
    await user.click(screen.getByRole('combobox', { name: '搜索字段' }))
    await user.click(await screen.findByText(label, { selector: '.ant-select-item-option-content' }))
  }
  return { list, user, chooseField }
}

// fix-livefilter：转发ID/用户ID 快捷框是可按名称联想的 IdOrNameInput（role=combobox），其余字段仍是 textbox。
const quickInput = (label: string) => screen.getByRole(label === '转发ID' || label === '用户ID' ? 'combobox' : 'textbox', { name: '搜索转发' })

// fix-advfilter2：高级筛选展开状态记在 localStorage，各用例从收起开始。
beforeEach(() => { localStorage.removeItem('cdnca.advancedFilters.stream-list') })

describe('stream quick search', () => {
  it('waits for an explicit query before submitting a protocol choice', async () => {
    const { list, user, chooseField } = await setupQuickSearch()
    await chooseField('监听协议')
    await user.click(screen.getByRole('combobox', { name: '搜索转发' }))
    await user.click(await screen.findByText('UDP', { selector: '.ant-select-item-option-content' }))
    expect(list).toHaveBeenCalledTimes(1)
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1].protocol).toBe('udp'))
  })

  it('clears the previous quick condition and resets pagination when switching fields', async () => {
    const { list, user, chooseField } = await setupQuickSearch()
    await user.type(screen.getByRole('textbox', { name: '搜索转发' }), '18100')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1].listen_port).toBe(18100))
    await user.click(screen.getByTitle('2'))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1].page).toBe(2))
    await chooseField('源IP')
    expect(screen.getByRole('textbox', { name: '搜索转发' })).toHaveValue('')
    await user.type(screen.getByRole('textbox', { name: '搜索转发' }), '192.0')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual(expect.objectContaining({ upstream: '192.0', page: 1 })))
    expect(list.mock.calls.at(-1)?.[1].listen_port).toBeUndefined()
    await chooseField('监听端口')
    expect(screen.getByRole('textbox', { name: '搜索转发' })).toHaveValue('')
  })

  it.each([
    ['CNAME域名', 'edge.example.net', 'cname_domain'],
    ['CNAME主机名', 'tenant-edge', 'cname_hostname'],
  ] as const)('submits the real %s filter', async (label, value, field) => {
    const { list, user, chooseField } = await setupQuickSearch()
    await chooseField(label)
    await user.type(screen.getByRole('textbox', { name: '搜索转发' }), value)
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 1, limit: 10, [field]: value }))
  })

  it.each([
    ['监听端口', '65535', 'listen_port', 65535],
    ['源IP', ' Origin_% ', 'upstream', 'Origin_%'],
    ['转发ID', '9223372036854775807', 'display_id', '9223372036854775807'],
    ['用户ID', '9223372036854775807', 'owner_display_id', '9223372036854775807'],
  ] as const)('submits only the canonical %s field and clears it on an empty query', async (label, value, field, expected) => {
    const { list, user, chooseField } = await setupQuickSearch()
    await chooseField(label)
    fireEvent.change(quickInput(label), { target: { value } })
    expect(list).toHaveBeenCalledTimes(1)
    await user.keyboard('{Enter}')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 1, limit: 10, [field]: expected }))
    await user.clear(quickInput(label))
    await user.keyboard('{Enter}')
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 1, limit: 10 }))
  })

  it.each([
    ['监听端口', '0'], ['监听端口', '0181'], ['监听端口', '65536'], ['监听端口', '1e2'],
    ['转发ID', '0'], ['转发ID', '9223372036854775808'], ['用户ID', '01'], ['用户ID', '9223372036854775808'],
    ['源IP', 'x'.repeat(254)], ['源IP', 'origin\u0000host'],
  ])('rejects invalid quick %s without a list request', async (label, value) => {
    const { list, user, chooseField } = await setupQuickSearch()
    await chooseField(label)
    fireEvent.change(quickInput(label), { target: { value } })
    await user.click(screen.getByRole('button', { name: '查询' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/端口|编号|源站/)
    expect(list).toHaveBeenCalledTimes(1)
  })

  it('submits false explicitly and clears the enabled filter without changing drafts early', async () => {
    const { list, user, chooseField } = await setupQuickSearch()
    await chooseField('转发启用')
    await user.click(screen.getByRole('combobox', { name: '搜索转发' }))
    await user.click(await screen.findByText('已停用', { selector: '.ant-select-item-option-content' }))
    expect(list).toHaveBeenCalledTimes(1)
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 1, limit: 10, enabled: false }))
    const calls = list.mock.calls.length
    await user.click(screen.getByRole('combobox', { name: '搜索转发' }).closest('.ant-select')!.querySelector('.ant-select-clear')!)
    expect(list).toHaveBeenCalledTimes(calls)
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 1, limit: 10 }))
  })

  it('submits every real publication state without treating it as runtime health', async () => {
    const { list, user, chooseField } = await setupQuickSearch()
    await chooseField('发布状态')
    for (const state of ['unknown', 'pending', 'leased', 'retrying', 'reconciling', 'succeeded', 'failed', 'superseded'] as const) {
      const calls = list.mock.calls.length
      await user.click(screen.getByRole('combobox', { name: '搜索转发' }))
      await user.click(await screen.findByText(zhCN.streams.publication.states[state], { selector: '.ant-select-item-option-content' }))
      expect(list).toHaveBeenCalledTimes(calls)
      await user.click(screen.getByRole('button', { name: '查询' }))
      await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 1, limit: 10, publication_state: state }))
    }
  })

  it('keeps advanced AND filters through quick changes, pagination, page size and clearing', async () => {
    const groupID = '88888888-8888-4888-8888-888888888888'
    vi.spyOn(streamGroupsApi, 'listGroups').mockResolvedValue({ items: [{ id: groupID, name: '真实转发分组', scope_id: stream.scope_id } as StreamGroup], page: 1, limit: 100, total: 1 })
    const { list, user, chooseField } = await setupQuickSearch()
    await user.click(screen.getByRole('button', { name: /^高级筛选/ }))
    const panel = within(screen.getByRole('group', { name: '高级筛选' }))
    await user.click(panel.getByRole('combobox', { name: '转发分组' }))
    await user.click(await screen.findByText('真实转发分组', { selector: '.ant-select-item-option-content' }))
    await user.click(panel.getByRole('combobox', { name: '筛选协议' }))
    await user.click(await screen.findByText('UDP', { selector: '.ant-select-item-option-content' }))
    expect(list).toHaveBeenCalledTimes(1)
    await user.click(panel.getByRole('button', { name: '应用' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 1, limit: 10, protocol: 'udp', group_id: groupID }))
    await user.type(screen.getByRole('textbox', { name: '搜索转发' }), '18100')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await user.click(screen.getByTitle('2'))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 2, limit: 10, protocol: 'udp', group_id: groupID, listen_port: 18100 }))
    await chooseField('源IP')
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 1, limit: 10, protocol: 'udp', group_id: groupID }))
    await user.type(screen.getByRole('textbox', { name: '搜索转发' }), '192.0')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await user.click(screen.getByRole('combobox', { name: 'Page Size' }))
    await user.click(await screen.findByText('20 / page', { selector: '.ant-select-item-option-content' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 1, limit: 20, protocol: 'udp', group_id: groupID, upstream: '192.0' }))
    await user.clear(screen.getByRole('textbox', { name: '搜索转发' }))
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 1, limit: 20, protocol: 'udp', group_id: groupID }))
    await user.click(screen.getByRole('button', { name: '重置' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 1, limit: 20 }))
    expect(screen.getByRole('combobox', { name: '搜索字段' }).closest('.ant-select')).toHaveTextContent('监听端口')
  })

  it('merges equal values and blocks conflicts from either filter source until cleared', async () => {
    const { list, user } = await setupQuickSearch()
    await user.type(screen.getByRole('textbox', { name: '搜索转发' }), '18100')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await user.click(screen.getByRole('button', { name: /^高级筛选/ }))
    const panel = within(screen.getByRole('group', { name: '高级筛选' }))
    await user.type(panel.getByRole('textbox', { name: '监听端口' }), '18101')
    let calls = list.mock.calls.length
    await user.click(panel.getByRole('button', { name: '应用' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(zhCN.streams.filters.quickConflict)
    expect(list).toHaveBeenCalledTimes(calls)
    fireEvent.change(panel.getByRole('textbox', { name: '监听端口' }), { target: { value: '18100' } })
    await user.click(panel.getByRole('button', { name: '应用' }))
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(list.mock.calls.length).toBeGreaterThan(calls))
    expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 1, limit: 10, listen_port: 18100 })
    calls = list.mock.calls.length
    fireEvent.change(screen.getByRole('textbox', { name: '搜索转发' }), { target: { value: '18102' } })
    await user.click(screen.getByRole('button', { name: '查询' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(zhCN.streams.filters.quickConflict)
    expect(list).toHaveBeenCalledTimes(calls)
    await user.clear(panel.getByRole('textbox', { name: '监听端口' }))
    await user.click(panel.getByRole('button', { name: '应用' }))
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toEqual({ page: 1, limit: 10, listen_port: 18102 }))
  })

  it('renders validation and conflict errors from the pseudo locale without requesting', async () => {
    const { list, user } = await setupQuickSearch()
    await act(async () => changeLocale('qps-ploc'))
    const copy = (pseudoCN as unknown as typeof zhCN).streams
    fireEvent.change(screen.getByRole('textbox', { name: copy.filters.searchLabel }), { target: { value: '65536' } })
    await user.click(screen.getByRole('button', { name: copy.actions.search }))
    expect(await screen.findByRole('alert')).toHaveTextContent(copy.filters.invalidPort)
    expect(list).toHaveBeenCalledTimes(1)
    fireEvent.change(screen.getByRole('textbox', { name: copy.filters.searchLabel }), { target: { value: '18100' } })
    await user.click(screen.getByRole('button', { name: copy.actions.search }))
    await user.click(screen.getByRole('button', { name: /^高级筛选/ }))
    const panel = within(screen.getByRole('group', { name: '高级筛选' }))
    await user.type(panel.getByRole('textbox', { name: copy.filters.listenPortLabel }), '18101')
    const calls = list.mock.calls.length
    await user.click(panel.getByRole('button', { name: '应用' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(copy.filters.quickConflict)
    expect(copy.filters.quickConflict.length).toBeGreaterThan(zhCN.streams.filters.quickConflict.length)
    expect(list).toHaveBeenCalledTimes(calls)
  })
})
