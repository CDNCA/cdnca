import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'
import { useSessionStore } from '../auth/session'
import StreamListPage from '../pages/StreamListPage'
import { resolveDraftDefaults } from '../pages/streamDraftDefaults'
import { parseListenPorts } from '../pages/streamForm'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { stream } from './streamFixture'

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const listResponse = () => json({ items: [stream], total: 1, page: 1, limit: 10 })
const groupID = '88888888-8888-4888-8888-888888888888'

// 普通用户：全局默认 udp + ip_hash；所选分组覆盖为 tcp。
function mockFetch() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = new URL(String(input), 'http://localhost')
    if (url.pathname === '/v1/user-configs/effective') {
      const grouped = url.searchParams.getAll('group_id').includes(groupID)
      return Promise.resolve(json({ protocol: grouped ? 'tcp' : 'udp', proxy_protocol_inbound: null, balance_way: 'ip_hash' }))
    }
    if (url.pathname === '/v1/stream-groups') {
      return Promise.resolve(json({ items: [{ id: groupID, display_id: '1', scope_id: stream.scope_id, owner: stream.owner, name: '默认值分组',
        remark: '', stream_count: 0, revision: 1, created_at: stream.created_at, updated_at: stream.updated_at }], total: 1, page: 1, limit: 100 }))
    }
    if (url.pathname === '/v1/streams/batch') return Promise.resolve(json({ committed: true, created: 1, failed: 0, items: [{ line: 1, text: '53|1.2.3.4|53', status: 'created' }] }))
    if (init?.method === 'POST') return Promise.resolve(json(stream, 201))
    return Promise.resolve(listResponse())
  })
}

beforeEach(() => {
  const user = principal({ permissions: ['streams.read', 'streams.manage', 'package_subscriptions.read'] })
  useSessionStore.getState().setSession(authResponse(user), user)
  useSessionStore.setState((state) => ({ principal: { ...state.principal!, scope_id: stream.scope_id, tenant_id: stream.scope_id, user_id: stream.owner!.id } }))
})
afterEach(() => vi.restoreAllMocks())

describe('L4-DEFAULT-01 新建草稿按默认设置预填', () => {
  it('falls back to tcp / rr / off when nothing is configured', () => {
    expect(resolveDraftDefaults(undefined)).toEqual({ protocol: 'tcp', balance_way: 'rr', proxy_protocol_inbound: false })
    expect(resolveDraftDefaults({ protocol: 'udp', balance_way: null, proxy_protocol_inbound: null }))
      .toEqual({ protocol: 'udp', balance_way: 'rr', proxy_protocol_inbound: false })
    expect(parseListenPorts('53 80/tcp', 'udp')).toEqual({ entries: [{ protocol: 'udp', port: 53 }, { protocol: 'tcp', port: 80 }] })
  })

  it('prefills protocol and balancing from the effective defaults, group overrides global, and a manual choice wins', async () => {
    const fetchSpy = mockFetch()
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: '添加转发' }))
    const dialog = await screen.findByRole('dialog', { name: '添加转发' })
    await waitFor(() => expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('/v1/user-configs/effective?type=stream'))).toBe(true))
    await user.type(within(dialog).getByLabelText('监听端口'), '5353')
    await user.type(within(dialog).getByLabelText('源地址:端口'), '192.0.2.11:53')
    await user.click(within(dialog).getByRole('button', { name: '展开更多' }))
    await user.click(within(dialog).getByText('源站设置'))
    // 全局默认 ip_hash 已选中；用户改回轮询后，切分组（协议变 tcp）不能把负载方式再改回默认。
    await waitFor(() => expect(within(dialog).getByRole('radio', { name: '定源' })).toBeChecked())
    await user.click(within(dialog).getByText('轮询'))
    await user.click(within(dialog).getByRole('combobox', { name: '所属分组' }))
    await user.click(await screen.findByText('默认值分组', { selector: '.ant-select-item-option-content' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([input]) => String(input).includes(`group_id=${groupID}`))).toBe(true))
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
    const body = JSON.parse(String(fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')![1]!.body))
    expect(body).toEqual(expect.objectContaining({ protocol: 'tcp', listen_port: 5353, balance_way: 'rr', proxy_protocol_inbound: false, group_ids: [groupID] }))
    expect(body).not.toHaveProperty('package_subscription_id')
  })

  it('sends the default protocol and balancing in the batch template and says so', async () => {
    const fetchSpy = mockFetch()
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: '添加转发' }))
    const dialog = await screen.findByRole('dialog', { name: '添加转发' })
    await user.click(within(dialog).getByRole('tab', { name: '批量' }))
    expect(await within(dialog).findByText('未写 /tcp 或 /udp 的端口按 UDP，负载方式为定源')).toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('转发数据'), '53|1.2.3.4|53')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('/v1/streams/batch'))).toBe(true))
    const body = JSON.parse(String(fetchSpy.mock.calls.find(([input]) => String(input).includes('/v1/streams/batch'))![1]!.body))
    expect(body.template).toEqual(expect.objectContaining({ protocol: 'udp', balance_way: 'ip_hash', proxy_protocol_inbound: false }))
    expect(body.template).not.toHaveProperty('package_subscription_id')
  })
})
