import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CdncaProvider } from '@cdnca/ui'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { ApiError } from '../api/auth'
import { streamsApi, type Stream } from '../api/streams'
import { useSessionStore } from '../auth/session'
import StreamDetailPage from '../pages/StreamDetailPage'
import StreamListPage from '../pages/StreamListPage'
import { authResponse, principal } from '../test/fixtures'
import { stream } from './streamFixture'

// fix-l4flow3 L4-007：结果未知的写入保留原目标/请求体/修订/幂等键，离开再回来、关弹窗再打开都只能按原请求确认。
const second: Stream = { ...stream, id: '99999999-9999-4999-8999-999999999999', listen_port: 18101, name: 'Second forwarding' }
const unavailable = () => new ApiError('synthetic unavailable', 503, 'temporarily_unavailable')

function authenticate(admin = false) {
  const actor = principal({ scope_kind: admin ? 'platform' : 'tenant', permissions: ['streams.read', 'streams.manage'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function Navigation() {
  const navigate = useNavigate()
  return <nav aria-label="test navigation">
    <button type="button" onClick={() => navigate(`/stream/list/${stream.id}`)}>Go A</button>
    <button type="button" onClick={() => navigate(`/stream/list/${second.id}`)}>Go B</button>
    <button type="button" onClick={() => navigate('/stream/list')}>Go list</button>
  </nav>
}

function setup(path = `/stream/list/${stream.id}`) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } } })
  render(<CdncaProvider><QueryClientProvider client={client}>
    <MemoryRouter initialEntries={[path]}><Navigation /><Routes>
      <Route path="/stream/list" element={<StreamListPage />} />
      <Route path="/stream/list/:id" element={<StreamDetailPage />} />
    </Routes></MemoryRouter>
  </QueryClientProvider></CdncaProvider>)
  return client
}

async function detailLoaded(port = 18100) {
  await screen.findByRole('heading', { name: `端口 ${port}` })
  await waitFor(() => expect(screen.getByRole('button', { name: '保存' })).toBeEnabled())
}

async function openBatch(user: ReturnType<typeof userEvent.setup>, lines: string) {
  await screen.findByText('TCP gateway')
  await user.click(screen.getByRole('button', { name: '添加转发' }))
  const dialog = await screen.findByRole('dialog', { name: '添加转发' })
  await user.click(within(dialog).getByRole('tab', { name: '批量' }))
  fireEvent.change(within(dialog).getByLabelText('转发数据'), { target: { value: lines } })
  return dialog
}

afterEach(() => vi.restoreAllMocks())

describe('L4-007 结果未知时保留原请求', () => {
  it('restores the unknown detail save after navigating A → B → A and retries only the original request', async () => {
    authenticate()
    vi.spyOn(streamsApi, 'get').mockImplementation(async (_, id) => id === second.id ? second : stream)
    const update = vi.spyOn(streamsApi, 'update').mockRejectedValueOnce(unavailable()).mockResolvedValue({ ...stream, remark: 'Original request', revision: 2 })
    const user = userEvent.setup(); setup(); await detailLoaded()
    fireEvent.change(screen.getByLabelText('备注'), { target: { value: 'Original request' } })
    await user.click(screen.getByRole('button', { name: '保存' }))
    await screen.findByRole('button', { name: '按原请求重试' })
    const original = update.mock.calls[0]!
    await user.click(screen.getByRole('button', { name: 'Go B' })); await detailLoaded(18101)
    expect(screen.queryByRole('button', { name: '按原请求重试' })).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Go A' }))
    const retry = await screen.findByRole('button', { name: '按原请求重试' })
    expect(screen.getByRole('button', { name: '保存' })).toBeDisabled()
    expect(screen.getByLabelText('备注')).toBeDisabled()
    await user.click(retry)
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2))
    expect(update.mock.calls[1]).toEqual(original)
    await waitFor(() => expect(screen.queryByRole('button', { name: '按原请求重试' })).toBeNull())
  })

  it('keeps the current unknown retry when an earlier save from a previous visit succeeds late', async () => {
    authenticate()
    vi.spyOn(streamsApi, 'get').mockImplementation(async (_, id) => id === second.id ? second : stream)
    let resolveEarlier!: (item: Stream) => void
    const earlier = new Promise<Stream>((resolve) => { resolveEarlier = resolve })
    const update = vi.spyOn(streamsApi, 'update').mockReturnValueOnce(earlier).mockRejectedValueOnce(unavailable()).mockResolvedValue({ ...stream, revision: 3 })
    const user = userEvent.setup(); setup(); await detailLoaded()
    fireEvent.change(screen.getByLabelText('备注'), { target: { value: 'Earlier request' } })
    await user.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    await user.click(screen.getByRole('button', { name: 'Go B' })); await detailLoaded(18101)
    await user.click(screen.getByRole('button', { name: 'Go A' })); await detailLoaded()
    fireEvent.change(screen.getByLabelText('备注'), { target: { value: 'Current unknown request' } })
    await user.click(screen.getByRole('button', { name: '保存' }))
    await screen.findByRole('button', { name: '按原请求重试' })
    const current = update.mock.calls[1]!
    await act(async () => { resolveEarlier({ ...stream, remark: 'Earlier request', revision: 2 }); await earlier })
    await waitFor(() => expect(screen.getByRole('button', { name: '按原请求重试' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: '按原请求重试' }))
    await waitFor(() => expect(update).toHaveBeenCalledTimes(3))
    expect(update.mock.calls[2]).toEqual(current)
  })

  it('freezes a batch-create 503: inputs locked, confirm resends the original body and key', async () => {
    authenticate(); vi.spyOn(streamsApi, 'list').mockResolvedValue({ items: [stream], total: 1, page: 1, limit: 10 })
    const create = vi.spyOn(streamsApi, 'batchCreate').mockRejectedValueOnce(unavailable())
      .mockResolvedValue({ committed: true, created: 1, failed: 0, items: [{ line: 1, text: '18110|192.0.2.10|9000', status: 'created' }] })
    const user = userEvent.setup(); setup('/stream/list')
    const dialog = await openBatch(user, '18110|192.0.2.10|9000')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(create).toHaveBeenCalledOnce())
    expect(await within(dialog).findByText('提交结果尚未确认，点「确定」按原请求重试以核对结果')).toBeInTheDocument()
    await waitFor(() => expect(within(dialog).getByRole('button', { name: '确定' })).toBeEnabled())
    expect(within(dialog).getByLabelText('转发数据')).toBeDisabled()
    fireEvent.change(within(dialog).getByLabelText('转发数据'), { target: { value: '18111|192.0.2.11|9001' } })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]![1]).toEqual(create.mock.calls[0]![1])
    expect(create.mock.calls[1]![2]).toBe(create.mock.calls[0]![2])
  })

  it('keeps the batch-create unknown request across closing and reopening the dialog', async () => {
    authenticate(); vi.spyOn(streamsApi, 'list').mockResolvedValue({ items: [stream], total: 1, page: 1, limit: 10 })
    const create = vi.spyOn(streamsApi, 'batchCreate').mockRejectedValue(unavailable())
    const user = userEvent.setup(); setup('/stream/list')
    let dialog = await openBatch(user, '18110|192.0.2.10|9000')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(create).toHaveBeenCalledOnce())
    await waitFor(() => expect(within(dialog).getByRole('button', { name: '取消' })).toBeEnabled())
    await user.click(within(dialog).getByRole('button', { name: '取消' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '添加转发' })).toBeNull())
    dialog = await openBatch(user, '18112|192.0.2.12|9002')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]![1]).toEqual(create.mock.calls[0]![1])
    expect(create.mock.calls[1]![2]).toBe(create.mock.calls[0]![2])
  })

  it('confirms a platform status action after 503 with its original body and key', async () => {
    authenticate(true)
    vi.spyOn(streamsApi, 'list').mockResolvedValue({ items: [stream], total: 1, page: 1, limit: 10 })
    const action = vi.spyOn(streamsApi, 'batchAction').mockRejectedValueOnce(unavailable())
      .mockResolvedValue({ items: [{ id: stream.id, status: 'updated' }] })
    const user = userEvent.setup(); setup('/stream/list'); await screen.findByText('TCP gateway')
    await user.click(screen.getAllByRole('checkbox')[1]!)
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    await user.click(await screen.findByText('设置状态', { selector: '.ant-dropdown-menu-title-content' }))
    const dialog = await screen.findByRole('dialog', { name: '设置网站状态' })
    await user.click(within(dialog).getByRole('combobox', { name: '状态' }))
    await user.click(screen.getByText('锁定', { selector: '.ant-select-item-option-content' }))
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(action).toHaveBeenCalledOnce())
    expect(await screen.findByRole('button', { name: '重试' })).toBeInTheDocument()
    await waitFor(() => expect(within(dialog).getByRole('button', { name: '确定' })).toBeEnabled())
    expect(within(dialog).getByRole('combobox', { name: '状态' })).toBeDisabled()
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(action).toHaveBeenCalledTimes(2))
    expect(action.mock.calls[1]![1]).toEqual(action.mock.calls[0]![1])
    expect(action.mock.calls[1]![2]).toBe(action.mock.calls[0]![2])
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '设置网站状态' })).toBeNull())
  })

  // fix-smallbatch 5：CNAME 域名/CNAME 模式/线路分组弹窗与设置状态一致：结果未知时回显原选值并禁用，确定即原请求。
  it('shows the unknown CNAME mode request frozen in its dialog and confirms it with the original body and key', async () => {
    authenticate(true)
    vi.spyOn(streamsApi, 'list').mockResolvedValue({ items: [stream], total: 1, page: 1, limit: 10 })
    const action = vi.spyOn(streamsApi, 'batchAction').mockRejectedValueOnce(unavailable())
      .mockResolvedValue({ items: [{ id: stream.id, status: 'updated' }] })
    const user = userEvent.setup(); setup('/stream/list'); await screen.findByText('TCP gateway')
    await user.click(screen.getAllByRole('checkbox')[1]!)
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    await user.click(await screen.findByText('CNAME模式', { selector: '.ant-dropdown-menu-title-content' }))
    const dialog = await screen.findByRole('dialog', { name: '修改CNAME生成模式' })
    await user.click(within(dialog).getByRole('combobox', { name: '模式' }))
    await user.click(screen.getByText('按套餐生成', { selector: '.ant-select-item-option-content' }))
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(action).toHaveBeenCalledOnce())
    expect(await screen.findByRole('button', { name: '重试' })).toBeInTheDocument()
    await waitFor(() => expect(within(dialog).getByRole('button', { name: '确定' })).toBeEnabled())
    const mode = within(dialog).getByRole('combobox', { name: '模式' })
    expect(mode).toBeDisabled()
    expect(mode.closest('.ant-select')).toHaveTextContent('按套餐生成')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(action).toHaveBeenCalledTimes(2))
    expect(action.mock.calls[1]![1]).toEqual(action.mock.calls[0]![1])
    expect(action.mock.calls[1]![2]).toBe(action.mock.calls[0]![2])
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '修改CNAME生成模式' })).toBeNull())
  })

  it('restores an unknown list write after leaving the list and coming back', async () => {
    authenticate()
    vi.spyOn(streamsApi, 'list').mockResolvedValue({ items: [stream], total: 1, page: 1, limit: 10 })
    vi.spyOn(streamsApi, 'get').mockResolvedValue(second)
    const update = vi.spyOn(streamsApi, 'update').mockRejectedValueOnce(unavailable()).mockResolvedValue({ ...stream, enabled: false, revision: 2 })
    const user = userEvent.setup(); setup('/stream/list'); await screen.findByText('TCP gateway')
    await user.click(screen.getAllByRole('checkbox')[1]!)
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    await user.click(await screen.findByText('停用', { selector: '.ant-dropdown-menu-title-content' }))
    await user.click(await screen.findByRole('button', { name: /^确\s*[认定]$/u }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    await screen.findByRole('button', { name: '重试' })
    await user.click(screen.getByRole('button', { name: 'Go B' })); await detailLoaded(18101)
    await user.click(screen.getByRole('button', { name: 'Go list' })); await screen.findByText('TCP gateway')
    await user.click(await screen.findByRole('button', { name: '重试' }))
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2))
    expect(update.mock.calls[1]).toEqual(update.mock.calls[0])
  })
})
