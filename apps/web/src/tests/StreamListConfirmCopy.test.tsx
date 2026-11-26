import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { streamsApi, type Stream } from '../api/streams'
import { useSessionStore } from '../auth/session'
import StreamListPage from '../pages/StreamListPage'
import { streamFields } from '../pages/streamForm'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { stream } from './streamFixture'

// 停用/启用/删除确认框标题写出对象（TCP 18100），正文只写用户能观察到的后果，确认按钮与动作同名（删除为 danger），请求不变。
type TestUser = ReturnType<typeof userEvent.setup>

const disabledStream: Stream = { ...stream, enabled: false }
const extra = (index: number): Stream => ({
  ...stream,
  id: `99999999-9999-4999-8999-99999999990${index}`,
  display_id: String(index + 2),
  name: `Forward ${index}`,
  listen_port: 18101 + index,
  protocol: index === 0 ? 'udp' : 'tcp',
  revision: 10 + index,
})

function authenticate() {
  const actor = principal({ permissions: ['streams.read', 'streams.manage'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function setup(items: Stream[]) {
  authenticate()
  vi.spyOn(streamsApi, 'list').mockResolvedValue({ items, total: items.length, page: 1, limit: 10 })
  const update = vi.spyOn(streamsApi, 'update').mockImplementation(async (_token, id) => ({ ...items.find((item) => item.id === id)!, revision: 99 }))
  const remove = vi.spyOn(streamsApi, 'remove').mockResolvedValue(undefined)
  renderWithProviders(<StreamListPage />, ['/stream/list'])
  return { update, remove }
}

async function rowAction(user: TestUser, action: '启用' | '停用' | '删除') {
  await screen.findByText('TCP gateway')
  await user.click(screen.getByRole('button', { name: '转发操作菜单' }))
  await user.click(await screen.findByRole('menuitem', { name: action }))
}

async function batchAction(user: TestUser, count: number, action: '启用' | '停用' | '删除') {
  await screen.findByText('TCP gateway')
  const rows = screen.getAllByRole('row').slice(1, count + 1)
  for (const row of rows) await user.click(within(row).getByRole('checkbox'))
  await user.click(screen.getByRole('button', { name: '更多操作' }))
  await user.click(await screen.findByText(action, { selector: '.ant-dropdown-menu-title-content' }))
}

function expectNoImplementationCopy(dialog: HTMLElement) {
  expect(dialog.textContent).not.toMatch(/修订|幂等|意图|禁用/u)
}

// 确认按钮与动作同名，只有删除是 danger；不再出现泛化的「确认」。
function expectConfirmButton(dialog: HTMLElement, name: '停用' | '启用' | '删除', danger: boolean) {
  const button = within(dialog).getByRole('button', { name })
  expect(button).toHaveClass('ant-btn-primary')
  if (danger) expect(button).toHaveClass('ant-btn-dangerous')
  else expect(button).not.toHaveClass('ant-btn-dangerous')
  expect(within(dialog).queryByRole('button', { name: /^确认/u })).not.toBeInTheDocument()
}

describe('StreamListPage confirmation copy', () => {
  it('names the row and states the effect when disabling one forward', async () => {
    const { update } = setup([stream])
    const user = userEvent.setup({ delay: null })
    await rowAction(user, '停用')
    const dialog = await screen.findByRole('dialog', { name: '停用 TCP 18100' })
    expect(within(dialog).getByText(/停用后，节点上对应的监听端口不再接受新连接，已建立的连接不会立即断开/u)).toBeInTheDocument()
    expect(within(dialog).queryByText(/选中的转发/u)).not.toBeInTheDocument()
    expectNoImplementationCopy(dialog)
    expectConfirmButton(dialog, '停用', false)
    await user.click(within(dialog).getByRole('button', { name: '停用' }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0]!.slice(1, 3)).toEqual([stream.id, { ...streamFields(stream), enabled: false, expected_revision: stream.revision }])
  })

  it('names the row and states the effect when enabling one forward', async () => {
    const { update } = setup([disabledStream])
    const user = userEvent.setup({ delay: null })
    await rowAction(user, '启用')
    const dialog = await screen.findByRole('dialog', { name: '启用 TCP 18100' })
    expect(within(dialog).getByText('启用后，配置下发到节点，对应的监听端口开始接受新连接。')).toBeInTheDocument()
    expectNoImplementationCopy(dialog)
    expectConfirmButton(dialog, '启用', false)
    await user.click(within(dialog).getByRole('button', { name: '启用' }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0]!.slice(1, 3)).toEqual([stream.id, { ...streamFields(disabledStream), enabled: true, expected_revision: stream.revision }])
  })

  it('says deletion cannot be undone and sends the same delete request', async () => {
    const { remove } = setup([stream])
    const user = userEvent.setup({ delay: null })
    await rowAction(user, '删除')
    const dialog = await screen.findByRole('dialog', { name: '删除 TCP 18100' })
    expect(within(dialog).getByText(/^删除后无法恢复：.*端口释放后可以分配给其他转发。$/u)).toBeInTheDocument()
    expectNoImplementationCopy(dialog)
    expectConfirmButton(dialog, '删除', true)
    await user.click(within(dialog).getByRole('button', { name: '删除' }))
    await waitFor(() => expect(remove).toHaveBeenCalledOnce())
    expect(remove.mock.calls[0]![1]).toEqual(stream)
  })

  it('uses the row name for a single selected forward in the batch menu', async () => {
    const { update } = setup([stream])
    const user = userEvent.setup({ delay: null })
    await batchAction(user, 1, '停用')
    const dialog = await screen.findByRole('dialog', { name: '停用 TCP 18100' })
    expect(within(dialog).getByText(/^停用后，节点上对应的监听端口不再接受新连接/u)).toBeInTheDocument()
    expect(within(dialog).queryByText(/选中的转发/u)).not.toBeInTheDocument()
    expectNoImplementationCopy(dialog)
    expectConfirmButton(dialog, '停用', false)
    await user.click(within(dialog).getByRole('button', { name: '停用' }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0]!.slice(1, 3)).toEqual([stream.id, { ...streamFields(stream), enabled: false, expected_revision: stream.revision }])
  })

  it('lists every selected forward in a small batch', async () => {
    const second = extra(0)
    const { update } = setup([stream, second])
    const user = userEvent.setup({ delay: null })
    await batchAction(user, 2, '停用')
    const dialog = await screen.findByRole('dialog', { name: '停用选中的 2 条转发' })
    expect(within(dialog).getByText('选中的转发：TCP 18100、UDP 18101')).toBeInTheDocument()
    expect(within(dialog).getByText(/^停用后，节点上对应的监听端口不再接受新连接/u)).toBeInTheDocument()
    expectNoImplementationCopy(dialog)
    expectConfirmButton(dialog, '停用', false)
    await user.click(within(dialog).getByRole('button', { name: '停用' }))
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2))
    expect(update.mock.calls.map((call) => call.slice(1, 3))).toEqual([
      [stream.id, { ...streamFields(stream), enabled: false, expected_revision: stream.revision }],
      [second.id, { ...streamFields(second), enabled: false, expected_revision: second.revision }],
    ])
  })

  it('shows the first five and the total for a larger batch', async () => {
    const items = [stream, ...Array.from({ length: 6 }, (_, index) => extra(index))]
    setup(items)
    const user = userEvent.setup({ delay: null })
    await batchAction(user, 7, '删除')
    const dialog = await screen.findByRole('dialog', { name: '删除选中的 7 条转发' })
    expect(within(dialog).getByText('选中的转发：TCP 18100、UDP 18101、TCP 18102、TCP 18103、TCP 18104 等 7 条')).toBeInTheDocument()
    expect(within(dialog).getByText(/^删除后无法恢复：/u)).toBeInTheDocument()
    expectNoImplementationCopy(dialog)
    expectConfirmButton(dialog, '删除', true)
  })

  it('states the enable effect for a batch', async () => {
    setup([disabledStream, { ...extra(1), enabled: false }])
    const user = userEvent.setup({ delay: null })
    await batchAction(user, 2, '启用')
    const dialog = await screen.findByRole('dialog', { name: '启用选中的 2 条转发' })
    expect(within(dialog).getByText('启用后，配置下发到节点，对应的监听端口开始接受新连接。')).toBeInTheDocument()
    expect(within(dialog).getByText('选中的转发：TCP 18100、TCP 18102')).toBeInTheDocument()
    expectConfirmButton(dialog, '启用', false)
  })
})
