import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CdncaProvider } from '@cdnca/ui'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { ApiError } from '../api/auth'
import { streamsApi, type Stream } from '../api/streams'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import { enUS, pseudoCN, zhCN } from '../i18n/resources'
import StreamDetailPage from '../pages/StreamDetailPage'
import StreamListPage from '../pages/StreamListPage'
import { authResponse, principal } from '../test/fixtures'
import { stream } from './streamFixture'

function authenticate(permissions = ['streams.read', 'streams.manage']) {
  const actor = principal({ permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  return actor
}
function setup(path = `/stream/list/${stream.id}`, queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } } })) {
  render(<CdncaProvider><QueryClientProvider client={queryClient}>
    <MemoryRouter initialEntries={[path]}><Routes>
      <Route path="/stream/list" element={<StreamListPage />} />
      <Route path="/stream/list/:id" element={<StreamDetailPage />} />
    </Routes></MemoryRouter>
  </QueryClientProvider></CdncaProvider>)
  return queryClient
}
function reads(item = stream) { return vi.spyOn(streamsApi, 'get').mockResolvedValue(item) }
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>((next) => { resolve = next }); return { promise, resolve } }
async function loaded() { await screen.findByRole('heading', { name: '端口 18100' }) }
async function save(user: ReturnType<typeof userEvent.setup>) { await user.click(screen.getByRole('button', { name: '保存' })) }

describe('StreamDetailPage', () => {
  it('adds a real listener on the same stream and preserves unrelated drafts', async () => {
    authenticate(); reads()
    const update = vi.spyOn(streamsApi, 'update').mockImplementation(async (_token, _id, fields) => ({ ...stream, ...fields, revision: 2 }))
    const user = userEvent.setup(); setup(); await loaded()
    fireEvent.change(screen.getByLabelText('备注'), { target: { value: '未提交备注' } })
    await user.click(screen.getByRole('button', { name: '添加监听' }))
    fireEvent.change(screen.getByLabelText('监听端口'), { target: { value: '18101' } })
    await user.click(screen.getByRole('button', { name: '添加' }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0][1]).toBe(stream.id)
    expect(update.mock.calls[0][2]).toMatchObject({ listen_port: 18100, remark: '', expected_revision: 1,
      additional_listeners: [{ id: expect.stringMatching(/^[a-f0-9-]{36}$/), protocol: 'tcp', address: '*', port: 18101 }] })
    await waitFor(() => expect(screen.getByRole('button', { name: '保存' })).toBeEnabled())
    expect(screen.getByLabelText('备注')).toHaveValue('未提交备注')
  })

  it('refuses duplicate sockets before sending a listener write', async () => {
    authenticate(); reads()
    const update = vi.spyOn(streamsApi, 'update')
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getByRole('button', { name: '添加监听' }))
    fireEvent.change(screen.getByLabelText('监听端口'), { target: { value: '18100' } })
    await user.click(screen.getByRole('button', { name: '添加' }))
    expect(await screen.findByText('此端口和协议已存在')).toBeInTheDocument()
    expect(update).not.toHaveBeenCalled()
  })

  it('edits an extra listener with its existing identity and retries the exact unknown write', async () => {
    authenticate()
    const extra = { id: '88888888-8888-4888-8888-888888888888', protocol: 'tcp' as const, address: '*' as const, port: 18101 }
    reads({ ...stream, additional_listeners: [extra] })
    const update = vi.spyOn(streamsApi, 'update').mockRejectedValueOnce(new ApiError('lost', 502, 'invalid_response')).mockResolvedValue({ ...stream, additional_listeners: [{ ...extra, port: 18102 }], revision: 2 })
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getByRole('button', { name: '编辑监听 18101/TCP' }))
    fireEvent.change(screen.getByLabelText('监听端口'), { target: { value: '18102' } })
    await user.click(screen.getByRole('button', { name: '更新' }))
    await user.click(await screen.findByRole('button', { name: '按原请求重试' }))
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2))
    expect(update.mock.calls[0][2]).toMatchObject({ additional_listeners: [{ ...extra, port: 18102 }] })
    expect(update.mock.calls[1]).toEqual(update.mock.calls[0])
  })

  it('removes the primary socket atomically by promoting an existing extra socket', async () => {
    authenticate()
    const extra = { id: '88888888-8888-4888-8888-888888888888', protocol: 'tcp' as const, address: '*' as const, port: 18101 }
    reads({ ...stream, additional_listeners: [extra] })
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue({ ...stream, listen_port: 18101, additional_listeners: [], revision: 2 })
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getByRole('button', { name: '删除监听 18100/TCP' }))
    await user.click(await screen.findByRole('button', { name: '确认' }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0][2]).toMatchObject({ listen_port: 18101, protocol: 'tcp', additional_listeners: [], expected_revision: 1 })
  })

  const passthroughStream: Stream = { ...stream, tls_passthrough: true, server_names: ['app.example.com', '*.example.com'] }

  it('shows TLS passthrough and its SNI list read-only for a viewer', async () => {
    authenticate(['streams.read']); reads(passthroughStream)
    setup(); await loaded()
    expect(screen.getByRole('switch', { name: 'TLS 透传（按 SNI 分流）' })).toBeChecked()
    expect(screen.getByRole('switch', { name: 'TLS 透传（按 SNI 分流）' })).toBeDisabled()
    const names = screen.getByRole('combobox', { name: 'SNI 列表' }).closest('.ant-select')!
    expect(names).toHaveTextContent('app.example.com')
    expect(names).toHaveTextContent('*.example.com')
    expect(names).toHaveClass('ant-select-disabled')
  })

  it('saves normalized SNI edits on a passthrough stream', async () => {
    authenticate(); reads(passthroughStream)
    const update = vi.spyOn(streamsApi, 'update').mockImplementation(async (_token, _id, fields) => ({ ...passthroughStream, ...fields, revision: 2 }))
    const user = userEvent.setup(); setup(); await loaded()
    await user.type(screen.getByRole('combobox', { name: 'SNI 列表' }), 'API.example.org,')
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0][2]).toMatchObject({ tls_passthrough: true, server_names: ['app.example.com', '*.example.com', 'api.example.org'], expected_revision: 1 })
  })

  it('picks how the client address reaches the origin: off, PROXY v1 or TOA, one at a time', async () => {
    authenticate(); reads()
    const update = vi.spyOn(streamsApi, 'update').mockImplementation(async (_token, _id, fields) => ({ ...stream, ...fields, revision: 2 }))
    const user = userEvent.setup(); setup(); await loaded()
    expect(screen.getByRole('radio', { name: 'Proxy Protocol v1' })).toBeChecked()
    await user.click(screen.getByRole('radio', { name: 'TOA' }).closest('label')!)
    expect(screen.getByRole('radio', { name: 'TOA' })).toBeChecked()
    expect(screen.getByRole('radio', { name: 'Proxy Protocol v1' })).not.toBeChecked()
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0][2]).toMatchObject({ toa: true, proxy_protocol_v1: false })
  })

  it('saves a per-IP new connection rate next to the connection limit and enables burst and ban only with a rate', async () => {
    authenticate(); reads()
    const update = vi.spyOn(streamsApi, 'update').mockImplementation(async (_token, _id, fields) => ({ ...stream, ...fields, revision: 2 }))
    const user = userEvent.setup(); setup(); await loaded()
    const rate = screen.getByRole('spinbutton', { name: '单 IP 每秒新建连接数' })
    expect(rate).toHaveValue('0')
    expect(screen.getByRole('spinbutton', { name: '新建连接突发' })).toBeDisabled()
    expect(screen.getByRole('spinbutton', { name: '超限拉黑（秒）' })).toBeDisabled()
    await user.clear(rate); await user.type(rate, '20')
    const burst = screen.getByRole('spinbutton', { name: '新建连接突发' })
    await user.clear(burst); await user.type(burst, '5')
    const ban = screen.getByRole('spinbutton', { name: '超限拉黑（秒）' })
    await user.clear(ban); await user.type(ban, '60')
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0][2]).toMatchObject({ max_new_connections_per_client_per_second: 20, new_connection_burst: 5, new_connection_ban_seconds: 60 })
  })

  it('turns the session log on from the advanced settings', async () => {
    authenticate(); reads()
    const update = vi.spyOn(streamsApi, 'update').mockImplementation(async (_token, _id, fields) => ({ ...stream, ...fields, revision: 2 }))
    const user = userEvent.setup(); setup(); await loaded()
    const toggle = screen.getByRole('switch', { name: '会话日志' })
    expect(toggle).not.toBeChecked()
    await user.click(toggle)
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0][2]).toMatchObject({ session_log_enabled: true })
  })

  it('adds, reorders and removes guard rules with their conditions and ban threshold', async () => {
    authenticate()
    const existing = { id: '99999999-9999-4999-8999-999999999991', action: 'allow' as const, client_ip: { cidrs: ['192.0.2.0/24'] },
      geo: [{ field: 'asn' as const, values: ['13335'] }] }
    reads({ ...stream, guard_rules: [existing] })
    const update = vi.spyOn(streamsApi, 'update').mockImplementation(async (_token, _id, fields) => ({ ...stream, ...fields, revision: 2 }))
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getByRole('tab', { name: '访问控制' }))
    expect(screen.getByRole('heading', { name: '防护规则' })).toBeInTheDocument()
    expect(screen.getByText('另有 1 个通过接口设置的地理条件（ASN/省/市），保存时保留')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '添加规则' }))
    const second = screen.getByRole('group', { name: '规则 2' })
    await user.click(within(second).getByText('断开并拉黑'))
    fireEvent.change(within(second).getByLabelText('客户端 IP'), { target: { value: '203.0.113.0/24' } })
    fireEvent.change(within(second).getByLabelText('命中次数'), { target: { value: '5' } })
    // A threshold above 1 needs a window: refused until it is filled.
    await save(user)
    expect(await within(second).findByText('计数窗口须为 1 到 3600 秒')).toBeInTheDocument()
    expect(update).not.toHaveBeenCalled()
    fireEvent.change(within(second).getByLabelText('计数窗口（秒）'), { target: { value: '60' } })
    await user.click(screen.getByRole('button', { name: '上移规则 2' }))
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    const rules = update.mock.calls[0][2].guard_rules!
    expect(rules).toHaveLength(2)
    expect(rules[0]).toMatchObject({ action: 'ban', ban_seconds: 600, threshold: 5, window_seconds: 60, client_ip: { cidrs: ['203.0.113.0/24'] } })
    expect(rules[0].id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u)
    expect(rules[1]).toEqual(existing)
  })

  it('refuses a guard rule without any condition before writing', async () => {
    authenticate(); reads()
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue(stream)
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getByRole('tab', { name: '访问控制' }))
    await user.click(screen.getByRole('button', { name: '添加规则' }))
    await save(user)
    expect(await screen.findByText('请至少填写一个条件')).toBeInTheDocument()
    expect(update).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: '删除规则 1' }))
    await user.click(await screen.findByRole('button', { name: '确认' }))
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect('guard_rules' in update.mock.calls[0][2]).toBe(false)
  })

  it('refuses to enable TLS passthrough while an additional listener is UDP', async () => {
    authenticate()
    const udp = { id: '88888888-8888-4888-8888-888888888888', protocol: 'udp' as const, address: '*' as const, port: 18101 }
    reads({ ...stream, proxy_protocol_v1: false, additional_listeners: [udp] })
    const update = vi.spyOn(streamsApi, 'update')
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getByRole('switch', { name: 'TLS 透传（按 SNI 分流）' }))
    await user.type(screen.getByRole('combobox', { name: 'SNI 列表' }), 'app.example.com,')
    await save(user)
    expect(await screen.findByText('TLS 透传仅支持 TCP，主监听和附加监听都必须为 TCP')).toBeInTheDocument()
    expect(update).not.toHaveBeenCalled()
  })

  it('warns about PROXY on a passthrough port and maps the shared-port 409', async () => {
    authenticate(); reads(passthroughStream)
    const update = vi.spyOn(streamsApi, 'update').mockRejectedValue(new ApiError('raw backend text', 409, 'stream_shared_port_proxy_protocol'))
    const user = userEvent.setup(); setup(); await loaded()
    const warning = /端口有多个使用方时不能开启 PROXY 协议/
    expect(screen.getByText(warning)).toBeInTheDocument()
    expect(screen.queryByText(/服务端先发数据的协议在共享端口上会被断开/)).not.toBeInTheDocument()
    await user.click(screen.getByRole('radio', { name: '关闭' }).closest('label')!)
    await waitFor(() => expect(screen.queryByText(warning)).not.toBeInTheDocument())
    await user.click(screen.getByRole('radio', { name: 'Proxy Protocol v1' }).closest('label')!)
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(await screen.findByText('这个端口有多个使用方（转发或网站），不能开启 PROXY 协议（入站或出站）')).toBeInTheDocument()
    expect(screen.queryByText('raw backend text')).not.toBeInTheDocument()
  })

  it('shows the shared-port TCP notice only while passthrough is off', async () => {
    authenticate(); reads()
    const user = userEvent.setup(); setup(); await loaded()
    const notice = /服务端先发数据的协议在共享端口上会被断开/
    expect(screen.getByText(notice)).toBeInTheDocument()
    await user.click(screen.getByRole('switch', { name: 'TLS 透传（按 SNI 分流）' }))
    await waitFor(() => expect(screen.queryByText(notice)).not.toBeInTheDocument())
  })

  it('disables UDP in the listener editor of a passthrough stream', async () => {
    authenticate(); reads(passthroughStream)
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getByRole('button', { name: '添加监听' }))
    await user.click(screen.getByLabelText('协议'))
    expect((await screen.findByText('UDP', { selector: '.ant-select-item-option-content' })).closest('.ant-select-item-option')).toHaveClass('ant-select-item-option-disabled')
  })

  it('separates the static navigation title from the interpolated port heading', () => {
    for (const copy of [zhCN.streams.detail, enUS.streams.detail, (pseudoCN as unknown as typeof zhCN).streams.detail]) {
      expect(copy.title).not.toContain('{{port}}')
      expect(copy.portTitle).toContain('{{port}}')
    }
  })

  it('navigates from management to a standalone page and reads fresh detail facts', async () => {
    authenticate()
    vi.spyOn(streamsApi, 'list').mockResolvedValue({ items: [stream], total: 1, page: 1, limit: 10 })
    const get = reads({ ...stream, package_name: '正式套餐', package_expires_at: '2027-07-22T08:00:00Z' })
    const user = userEvent.setup()
    setup('/stream/list')
    expect(await screen.findByRole('link', { name: '管理' })).toHaveAttribute('href', `/stream/list/${stream.id}`)
    await user.click(screen.getByRole('link', { name: '管理' }))
    await loaded()
    expect(get).toHaveBeenCalledWith(expect.any(String), stream.id)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '基本配置' })).toHaveAttribute('aria-selected', 'true')
    // 社区版：详情页不显示套餐与套餐到期。
    expect(screen.queryByText('正式套餐')).not.toBeInTheDocument()
    expect(screen.queryByText(/2027/)).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: '返回转发列表' })).toHaveAttribute('href', '/stream/list')
  })

  it.each(['user', 'admin'])('restores tenant groups and saves full fields with revision for a %s', async (role) => {
    const actor = role === 'user' ? authenticate() : principal({ scope_kind: 'platform', tenant_id: null, permissions: ['platform.admin'] })
    if (role === 'admin') useSessionStore.getState().setSession(authResponse(actor), actor)
    const group = { id: '88888888-8888-4888-8888-888888888888', name: '已有分组', remark: '' }
    const next = { ...group, id: '99999999-9999-4999-8999-999999999999', name: '新分组' }
    const other = { ...next, id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', name: '其他租户分组', scope_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }
    const get = reads({ ...stream, groups: [group] })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [group, next, other].map((entry) => ({ scope_id: stream.scope_id, owner: stream.owner, display_id: '1', revision: 1, stream_count: 1, created_at: stream.created_at, updated_at: stream.updated_at, ...entry })), total: 3, page: 1, limit: 100 }), { status: 200 }))
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue(stream)
    const client = setup()
    const foreignKey = ['streams', 'tenant', 'foreign', 9]
    client.setQueryData(foreignKey, { items: [] })
    const user = userEvent.setup()
    await loaded()
    expect(screen.getByText('已有分组')).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: '所属分组' }))
    await user.click(await screen.findByText('新分组', { selector: '.ant-select-item-option-content' }))
    expect(screen.queryByText('其他租户分组')).not.toBeInTheDocument()
    await user.click(screen.getByRole('heading', { name: '端口 18100' }))
    await user.type(screen.getByLabelText('备注'), '测试备注')
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0]?.[2]).toMatchObject({ expected_revision: 1, group_ids: [group.id, next.id], remark: '测试备注', upstream_address: stream.upstream_address, dns_policy: stream.dns_policy, geo_policy: stream.geo_policy })
    expect(update.mock.calls[0]?.[2]).not.toHaveProperty('package_subscription_id')
    expect(update.mock.calls[0]?.[3]).toMatch(/^update-stream-/)
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
    expect(client.getQueryState(foreignKey)?.isInvalidated).toBe(false)
  })

  it('immediately saves only listener fields and retains other drafts for the next revision', async () => {
    authenticate()
    const next = { ...stream, listen_port: 18101, revision: 2 }
    const get = reads(); get.mockResolvedValueOnce(stream).mockResolvedValue(next)
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue(next)
    const user = userEvent.setup(); setup(); await loaded()
    const draft = '未保存备注'.repeat(60)
    fireEvent.change(screen.getByLabelText('备注'), { target: { value: draft } })
    fireEvent.change(screen.getByLabelText('回源端口'), { target: { value: '9001' } })
    await user.click(screen.getByRole('button', { name: '编辑监听端口和协议' }))
    fireEvent.change(screen.getByLabelText('监听端口'), { target: { value: '18101' } })
    await user.click(screen.getByRole('button', { name: '更新' }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0][2]).toMatchObject({ listen_port: 18101, expected_revision: 1, remark: stream.remark, upstream_port: stream.upstream_port })
    await screen.findByRole('heading', { name: '端口 18101' })
    await waitFor(() => expect(screen.getByRole('button', { name: '保存' })).toBeEnabled())
    expect(screen.getByLabelText('备注')).toHaveValue(draft)
    expect(screen.getByLabelText('回源端口')).toHaveValue('9001')
    fireEvent.change(screen.getByLabelText('备注'), { target: { value: '保留草稿' } })
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2))
    expect(update.mock.calls[1][2]).toMatchObject({ listen_port: 18101, expected_revision: 2, remark: '保留草稿', upstream_port: 9001 })
  })

  // 端口范围 / 跟随端口回源（tcp/udp v9）。
  it('saves a listen port range, refuses ranges over node ports and follows the client port to the origin', async () => {
    authenticate()
    const ranged = { ...stream, listen_port_end: 18199, revision: 2 }
    const get = reads(); get.mockResolvedValueOnce(stream).mockResolvedValue(ranged)
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue(ranged)
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getByRole('button', { name: '编辑监听端口和协议' }))
    fireEvent.change(screen.getByLabelText('结束端口'), { target: { value: '18500' } })
    await user.click(screen.getByRole('button', { name: '更新' }))
    expect(await screen.findByText('端口范围不能包含节点自用端口 80、443、18080、18443')).toBeInTheDocument()
    expect(update).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText('结束端口'), { target: { value: '18199' } })
    await user.click(screen.getByRole('button', { name: '更新' }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0][2]).toMatchObject({ listen_port: 18100, listen_port_end: 18199, expected_revision: 1 })
    expect(update.mock.calls[0][2]).not.toHaveProperty('upstream_follow_port')
    expect(await screen.findByRole('button', { name: '编辑监听端口和协议' })).toHaveTextContent('18100-18199/tcp')
    await waitFor(() => expect(screen.getByRole('button', { name: '保存' })).toBeEnabled())
    await user.click(screen.getByRole('switch', { name: '跟随端口回源' }))
    expect(screen.queryByLabelText('回源端口')).not.toBeVisible()
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2))
    expect(update.mock.calls[1][2]).toMatchObject({ listen_port_end: 18199, upstream_follow_port: true, upstream_port: 18100, expected_revision: 2 })
  })

  it('L4-001 edits the full origin pool in place and commits it with the page save in one revision', async () => {
    authenticate()
    const pooled: Stream = { ...stream, origins: [{ address: '192.0.2.10', weight: 7, down: false }, { address: '192.0.2.11', weight: 3, down: true }] }
    reads(pooled)
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue({ ...pooled, revision: 2 })
    const user = userEvent.setup(); setup(); await loaded()
    const addresses = screen.getAllByLabelText('源地址')
    expect(addresses.map((input) => (input as HTMLInputElement).value)).toEqual(['192.0.2.10', '192.0.2.11'])
    expect(screen.getAllByLabelText('权重').map((input) => (input as HTMLInputElement).value)).toEqual(['7', '3'])
    expect(screen.getByText('约 100%')).toBeInTheDocument()
    expect(screen.getByText('不分流量')).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    fireEvent.change(addresses[1]!, { target: { value: '192.0.2.21' } })
    await user.click(screen.getByRole('button', { name: '新增源站' }))
    fireEvent.change(screen.getAllByLabelText('源地址')[2]!, { target: { value: '192.0.2.22' } })
    fireEvent.change(screen.getAllByLabelText('权重')[2]!, { target: { value: '5' } })
    expect(update).not.toHaveBeenCalled()
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0]![2]).toMatchObject({
      upstream_address: '192.0.2.10', upstream_host: '', expected_revision: 1,
      origins: [{ address: '192.0.2.10', weight: 7, down: false }, { address: '192.0.2.21', weight: 3, down: true }, { address: '192.0.2.22', weight: 5, down: false }],
      dns_policy: { positive_min_ttl_seconds: 0, positive_max_ttl_seconds: 0, negative_ttl_seconds: 0, stale_if_error_seconds: 0 },
    })
  })

  it('L4-001 refuses a domain in a multi-origin pool and an all-offline pool before writing', async () => {
    authenticate(); reads()
    const update = vi.spyOn(streamsApi, 'update')
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getByRole('button', { name: '新增源站' }))
    fireEvent.change(screen.getAllByLabelText('源地址')[1]!, { target: { value: 'origin.example.com' } })
    await save(user)
    expect(await screen.findByText('多个源站时源地址只能是 IP')).toBeInTheDocument()
    await user.click(screen.getAllByRole('button', { name: '删除源站' })[1]!)
    await user.click(screen.getByRole('combobox', { name: '状态' }))
    await user.click(screen.getByText('下线', { selector: '.ant-select-item-option-content' }))
    await save(user)
    expect(await screen.findByText('至少保留一个上线的源站')).toBeInTheDocument()
    expect(update).not.toHaveBeenCalled()
  })

  it('L4-001 collapses a single online origin of weight 1 into the plain upstream fields', async () => {
    authenticate()
    reads({ ...stream, origins: [{ address: '192.0.2.10', weight: 1, down: false }, { address: '192.0.2.11', weight: 1, down: false }] })
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue({ ...stream, revision: 2 })
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getAllByRole('button', { name: '删除源站' })[0]!)
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0]![2]).toMatchObject({ upstream_address: '192.0.2.11', upstream_host: '' })
    expect(update.mock.calls[0]![2]).not.toHaveProperty('origins')
  })

  it('freezes an unknown local listener write and retries its exact request without losing drafts', async () => {
    authenticate(); reads()
    const update = vi.spyOn(streamsApi, 'update').mockRejectedValueOnce(new ApiError('lost', 502, 'invalid_response')).mockResolvedValue(stream)
    const user = userEvent.setup(); setup(); await loaded()
    fireEvent.change(screen.getByLabelText('备注'), { target: { value: '仍未提交' } })
    await user.click(screen.getByRole('button', { name: '编辑监听端口和协议' }))
    fireEvent.change(screen.getByLabelText('监听端口'), { target: { value: '18103' } })
    await user.click(screen.getByRole('button', { name: '更新' }))
    const retry = await screen.findByRole('button', { name: '按原请求重试' })
    expect(screen.getByRole('button', { name: '保存' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '刷新' })).toBeDisabled()
    await user.click(retry)
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2))
    expect(update.mock.calls[1]).toEqual(update.mock.calls[0])
    await waitFor(() => expect(screen.getByRole('button', { name: '保存' })).toBeEnabled())
    expect(screen.getByLabelText('备注')).toHaveValue('仍未提交')
  })

  it('keeps local drafts after conflict and rebases only after an explicit facts refresh', async () => {
    authenticate(); const get = reads()
    const update = vi.spyOn(streamsApi, 'update').mockRejectedValueOnce(new ApiError('conflict', 409, 'version_conflict')).mockResolvedValue(stream)
    const user = userEvent.setup(); setup(); await loaded()
    fireEvent.change(screen.getByLabelText('备注'), { target: { value: '保留备注' } })
    await user.click(screen.getByRole('button', { name: '编辑监听端口和协议' }))
    fireEvent.change(screen.getByLabelText('监听端口'), { target: { value: '18104' } })
    await user.click(screen.getByRole('button', { name: '更新' }))
    await screen.findByText('规则已被其他操作修改，请刷新后重试')
    expect(screen.getByRole('button', { name: '更新' })).toBeDisabled()
    get.mockResolvedValue({ ...stream, revision: 3, upstream_port: 9999 })
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(screen.getByRole('button', { name: '更新' })).toBeEnabled())
    expect(screen.getByLabelText('监听端口')).toHaveValue('18104')
    expect(screen.getByLabelText('备注')).toHaveValue('保留备注')
    expect(screen.getByLabelText('回源端口')).toHaveValue('9999')
    await user.click(screen.getByRole('button', { name: '更新' }))
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2))
    expect(update.mock.calls[1][2]).toMatchObject({ expected_revision: 3, listen_port: 18104, upstream_port: 9999, remark: stream.remark })
    expect(update.mock.calls[1][3]).not.toBe(update.mock.calls[0][3])
  })

  it('preserves a DNS draft leaf through conflict refresh without overwriting other refreshed DNS fields', async () => {
    authenticate()
    const domain: Stream = { ...stream, upstream_address: '', upstream_host: 'origin.example.com', dns_policy: { positive_min_ttl_seconds: 30, positive_max_ttl_seconds: 300, negative_ttl_seconds: 60, stale_if_error_seconds: 900, allow_private_addresses: false } }
    const next = { ...domain, revision: 2, dns_policy: { ...domain.dns_policy, positive_max_ttl_seconds: 500 } }
    const get = reads(domain)
    const update = vi.spyOn(streamsApi, 'update').mockRejectedValueOnce(new ApiError('conflict', 409, 'version_conflict')).mockResolvedValue({ ...next, revision: 3, listen_port: 18105 })
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getByText('高级设置与 DNS'))
    fireEvent.change(screen.getByLabelText('DNS 最小正缓存 TTL（秒）'), { target: { value: '31' } })
    await user.click(screen.getByRole('button', { name: '编辑监听端口和协议' }))
    fireEvent.change(screen.getByLabelText('监听端口'), { target: { value: '18105' } })
    await user.click(screen.getByRole('button', { name: '更新' }))
    await screen.findByText('规则已被其他操作修改，请刷新后重试')
    get.mockResolvedValue(next)
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(screen.getByRole('button', { name: '更新' })).toBeEnabled())
    expect(screen.getByLabelText('DNS 最小正缓存 TTL（秒）')).toHaveValue('31')
    expect(screen.getByLabelText('DNS 最大正缓存 TTL（秒）')).toHaveValue('500')
    get.mockResolvedValue({ ...next, revision: 3, listen_port: 18105 })
    await user.click(screen.getByRole('button', { name: '更新' }))
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2))
    expect(update.mock.calls[1][2]).toMatchObject({ expected_revision: 2, dns_policy: { positive_min_ttl_seconds: 30, positive_max_ttl_seconds: 500 } })
    await waitFor(() => expect(screen.getByRole('button', { name: '保存' })).toBeEnabled())
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledTimes(3))
    expect(update.mock.calls[2][2]).toMatchObject({ expected_revision: 3, dns_policy: { positive_min_ttl_seconds: 31, positive_max_ttl_seconds: 500 } })
  })

  it('changes a hostname origin in place while keeping a DNS draft for later editing', async () => {
    authenticate()
    const domain: Stream = { ...stream, upstream_address: '', upstream_host: 'origin.example.com', origins: [{ address: 'origin.example.com', weight: 1, down: false }], dns_policy: { positive_min_ttl_seconds: 30, positive_max_ttl_seconds: 300, negative_ttl_seconds: 60, stale_if_error_seconds: 900, allow_private_addresses: false } }
    reads(domain)
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue({ ...domain, upstream_host: 'next.example.com', revision: 2 })
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getByText('高级设置与 DNS'))
    fireEvent.change(screen.getByLabelText('DNS 最小正缓存 TTL（秒）'), { target: { value: '31' } })
    fireEvent.change(screen.getByLabelText('源地址'), { target: { value: 'next.example.com' } })
    expect(update).not.toHaveBeenCalled()
    expect(screen.getByLabelText('DNS 最小正缓存 TTL（秒）')).toHaveValue('31')
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0]![2]).toMatchObject({ upstream_host: 'next.example.com', upstream_address: '', dns_policy: { positive_min_ttl_seconds: 31 } })
    expect(update.mock.calls[0]![2]).not.toHaveProperty('origins')
  })

  it('serializes rapid local and whole-page writes while preserving drafts', async () => {
    authenticate(); reads()
    const pending = deferred<Stream>()
    const update = vi.spyOn(streamsApi, 'update').mockReturnValue(pending.promise)
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getByRole('button', { name: '编辑监听端口和协议' }))
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: '更新' }))
      fireEvent.click(screen.getByRole('button', { name: '更新' }))
      fireEvent.click(screen.getByRole('button', { name: /保存/ }))
    })
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(screen.getByRole('button', { name: /保存/ })).toBeDisabled()
    await act(async () => pending.resolve(stream))
  })

  it('immediately updates the listener and normalizes persisted UDP proxy dependencies', async () => {
    authenticate(); reads({ ...stream, proxy_protocol_inbound: true, geo_policy: { ...stream.geo_policy, enabled: true, trusted_proxy_cidrs: ['192.0.2.0/24'] } })
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue(stream)
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getByRole('button', { name: '编辑监听端口和协议' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('监听端口'), { target: { value: '18101' } })
    await user.click(screen.getByRole('combobox', { name: '协议' }))
    await user.click(screen.getByText('UDP', { selector: '.ant-select-item-option-content' }))
    await user.click(screen.getByRole('button', { name: '更新' }))
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0]?.[2]).toMatchObject({ protocol: 'udp', listen_port: 18101, proxy_protocol_v1: false, proxy_protocol_inbound: false, geo_policy: { enabled: true, trusted_proxy_cidrs: [] } })
  })

  it.each(['::::', '2001:db8:00000::1'])('rejects malformed IPv6 %s in the origin pool without writing', async (address) => {
    authenticate(); reads()
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue(stream)
    const user = userEvent.setup(); setup(); await loaded()
    fireEvent.change(screen.getByLabelText('源地址'), { target: { value: address } })
    await save(user)
    expect(await screen.findByText('请输入有效的 IPv4 或 IPv6 地址')).toBeInTheDocument()
    expect(update).not.toHaveBeenCalled()
  })

  it('saves a valid IPv6 origin and source-affinity balancing', async () => {
    authenticate(); reads()
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue({ ...stream, upstream_address: '2001:db8::1', revision: 2 })
    const user = userEvent.setup(); setup(); await loaded()
    fireEvent.change(screen.getByLabelText('源地址'), { target: { value: '2001:db8::1' } })
    fireEvent.click(screen.getByRole('radio', { name: '定源' }))
    fireEvent.change(screen.getByLabelText('回源端口'), { target: { value: '9001' } })
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0]?.[2]).toMatchObject({ upstream_address: '2001:db8::1', upstream_port: 9001, balance_way: 'ip_hash' })
  })

  it('keeps the origin pool, ACL and IPv6 listening on a whole-page save', async () => {
    authenticate()
    const pooled: Stream = { ...stream, listen_ipv6: true,
      origins: [{ address: '192.0.2.10', weight: 2, down: false }, { address: '192.0.2.11', weight: 1, down: true }],
      acl: { default_action: 'deny', rules: [{ cidr: '198.51.100.0/24', action: 'allow' }] } }
    reads(pooled)
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue({ ...pooled, revision: 2 })
    const user = userEvent.setup(); setup(); await loaded()
    fireEvent.change(screen.getByLabelText('备注'), { target: { value: '只改备注' } })
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0]?.[2]).toMatchObject({ remark: '只改备注', listen_ipv6: true, origins: pooled.origins, acl: pooled.acl })
  })

  it('L4-002 shows the ACL first in the access tab, edits it and puts IPv6 in the listener box', async () => {
    authenticate()
    const guarded: Stream = { ...stream, listen_ipv6: true, acl: { default_action: 'deny', rules: [{ cidr: '198.51.100.0/24', action: 'allow' }] } }
    reads(guarded)
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue({ ...guarded, revision: 2 })
    const user = userEvent.setup(); setup(); await loaded()
    expect(screen.getByRole('switch', { name: 'IPv6开启' })).toBeChecked()
    await user.click(screen.getByRole('tab', { name: '访问控制' }))
    const panel = screen.getByRole('tabpanel', { name: '访问控制' })
    expect(within(panel).getAllByRole('heading', { level: 2 }).map((heading) => heading.textContent)).toEqual(['IP 访问控制', '区域屏蔽', '防护规则'])
    expect(within(panel).getByRole('radio', { name: '拒绝' })).toBeChecked()
    expect(within(panel).getByLabelText('IP')).toHaveValue('198.51.100.0/24')
    await user.click(within(panel).getByRole('button', { name: '新增规则' }))
    fireEvent.change(within(panel).getAllByLabelText('IP')[1]!, { target: { value: 'bad' } })
    await save(user)
    expect(await within(panel).findByText('请输入有效的 IP 或网段')).toBeInTheDocument()
    fireEvent.change(within(panel).getAllByLabelText('IP')[1]!, { target: { value: '203.0.113.7' } })
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0]![2]).toMatchObject({ listen_ipv6: true, acl: { default_action: 'deny', rules: [{ cidr: '198.51.100.0/24', action: 'allow' }, { cidr: '203.0.113.7', action: 'deny' }] } })
  })

  it('L4-002 clears ACL and IPv6 from the request when they are turned back to the defaults', async () => {
    authenticate()
    const guarded: Stream = { ...stream, listen_ipv6: true, acl: { default_action: 'deny', rules: [{ cidr: '198.51.100.0/24', action: 'allow' }] } }
    reads(guarded)
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue({ ...stream, revision: 2 })
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getByRole('switch', { name: 'IPv6开启' }))
    await user.click(screen.getByRole('tab', { name: '访问控制' }))
    fireEvent.click(screen.getByRole('radio', { name: '允许' }))
    await user.click(screen.getByRole('button', { name: '删除规则' }))
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0]![2]).not.toHaveProperty('acl')
    expect(update.mock.calls[0]![2]).not.toHaveProperty('listen_ipv6')
  })

  it('L4-008 shows operation status and configuration sync side by side and links a failed sync to its publication', async () => {
    authenticate()
    reads({ ...stream, admin_status: 'locked', sync_state: 'failed', publish_intent: { ...stream.publish_intent, state: 'failed' } })
    const user = userEvent.setup(); setup(); await loaded()
    const facts = document.querySelector('.stream-detail-facts')!
    expect(within(facts as HTMLElement).getByText('运营状态').nextElementSibling).toHaveTextContent('锁定')
    expect(within(facts as HTMLElement).getByText('配置同步').nextElementSibling).toHaveTextContent('同步失败')
    expect(screen.getByRole('switch', { name: '启用转发' })).toBeChecked()
    await user.click(within(facts as HTMLElement).getByRole('button', { name: '发布详情' }))
    const dialog = await screen.findByRole('dialog', { name: '发布详情' })
    expect(within(dialog).getByText(stream.publish_intent.id)).toBeInTheDocument()
  })

  it('L4-008 hides the publication link while sync is done and shows a package problem as the operation status', async () => {
    authenticate(); reads({ ...stream, eligibility_state: 'ineligible' })
    setup(); await loaded()
    const facts = document.querySelector('.stream-detail-facts') as HTMLElement
    expect(within(facts).getByText('运营状态').nextElementSibling).toHaveTextContent('套餐不可用')
    expect(within(facts).getByText('配置同步').nextElementSibling).toHaveTextContent('已同步')
    expect(within(facts).queryByRole('button', { name: '发布详情' })).toBeNull()
  })

  it('preserves domain DNS and geo configuration across the two tabs', async () => {
    authenticate()
    const domain: Stream = { ...stream, upstream_address: '', upstream_host: 'origin.example.com', dns_policy: { positive_min_ttl_seconds: 30, positive_max_ttl_seconds: 300, negative_ttl_seconds: 60, stale_if_error_seconds: 900, allow_private_addresses: false }, geo_policy: { enabled: true, unknown_region_action: 'block', trusted_proxy_cidrs: ['192.0.2.0/24'], blocked_regions: ['DE'], region_cidrs: [{ region: 'DE', cidrs: ['203.0.113.0/24'] }] }, proxy_protocol_inbound: true }
    reads(domain)
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue(domain)
    const user = userEvent.setup(); setup(); await loaded()
    await user.click(screen.getByText('高级设置与 DNS'))
    expect(screen.getByLabelText('DNS 最小正缓存 TTL（秒）')).toHaveValue('30')
    fireEvent.change(screen.getByLabelText('DNS 最小正缓存 TTL（秒）'), { target: { value: '31' } })
    await user.click(screen.getByRole('tab', { name: '访问控制' }))
    expect(screen.getByLabelText('地区 CIDR 映射')).toHaveValue('DE=203.0.113.0/24')
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0]?.[2]).toMatchObject({ upstream_host: domain.upstream_host, geo_policy: domain.geo_policy, dns_policy: { ...domain.dns_policy, positive_min_ttl_seconds: 31 }, proxy_protocol_inbound: true })
  })

  it('freezes an unknown update and retries with the identical body and idempotency key', async () => {
    authenticate(); reads()
    const update = vi.spyOn(streamsApi, 'update').mockRejectedValueOnce(new ApiError('lost response', 502, 'invalid_response')).mockResolvedValue(stream)
    const user = userEvent.setup(); setup(); await loaded(); await save(user)
    const retry = await screen.findByRole('button', { name: '按原请求重试' })
    expect(screen.getByRole('button', { name: '保存' })).toBeDisabled()
    expect(screen.getByLabelText('备注')).toBeDisabled()
    expect(screen.getByRole('button', { name: '刷新' })).toBeDisabled()
    await user.click(retry)
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2))
    expect(update.mock.calls[1]).toEqual(update.mock.calls[0])
    expect(await screen.findByText('转发规则已更新，发布意图下发状态待确认')).toBeInTheDocument()
  })

  it('recovers a version conflict only after refreshing facts and uses the new revision', async () => {
    authenticate()
    const get = reads()
    const update = vi.spyOn(streamsApi, 'update').mockRejectedValueOnce(new ApiError('secret backend text', 409, 'version_conflict')).mockResolvedValue(stream)
    const user = userEvent.setup(); setup(); await loaded(); await save(user)
    expect(await screen.findByText('规则已被其他操作修改，请刷新后重试')).toBeInTheDocument()
    expect(screen.queryByText('secret backend text')).not.toBeInTheDocument()
    get.mockResolvedValue({ ...stream, revision: 2 })
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(screen.getByRole('button', { name: '保存' })).toBeEnabled())
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2))
    expect(update.mock.calls[1]?.[2].expected_revision).toBe(2)
    expect(update.mock.calls[1]?.[3]).not.toBe(update.mock.calls[0]?.[3])
  })

  it('keeps a read-only viewer readable without write controls', async () => {
    authenticate(['streams.read']); reads()
    const update = vi.spyOn(streamsApi, 'update')
    setup(); await loaded()
    expect(screen.queryByRole('button', { name: '保存' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '编辑' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新增源站' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('源地址')).toBeDisabled()
    expect(screen.getByRole('combobox', { name: '所属分组' })).toBeDisabled()
    expect(update).not.toHaveBeenCalled()
  })

  it.each([403, 404, 500])('handles detail GET %s without writable stale facts', async (status) => {
    authenticate()
    vi.spyOn(streamsApi, 'get').mockRejectedValue(new ApiError('raw secret error', status, status === 403 ? 'permission_denied' : 'not_found'))
    const update = vi.spyOn(streamsApi, 'update')
    setup()
    expect(await screen.findByText(status === 403 ? '无权查看转发列表' : status === 404 ? '转发规则不存在' : '转发配置加载失败，请刷新重试')).toBeInTheDocument()
    expect(screen.queryByText('raw secret error')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '保存' })).not.toBeInTheDocument()
    expect(update).not.toHaveBeenCalled()
  })

  it('locks every write control after the server denies an update', async () => {
    authenticate(); reads()
    const update = vi.spyOn(streamsApi, 'update').mockRejectedValue(new ApiError('denied', 403, 'permission_denied'))
    const user = userEvent.setup(); setup(); await loaded(); await save(user)
    await waitFor(() => expect(screen.queryByRole('button', { name: '保存' })).not.toBeInTheDocument())
    expect(screen.getByLabelText('备注')).toBeDisabled()
    expect(update).toHaveBeenCalledOnce()
  })

  it.each(['revoke', 'switch'])('rejects a validation completion after session %s', async (mode) => {
    authenticate(); reads()
    const update = vi.spyOn(streamsApi, 'update')
    setup(); await loaded()
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: '保存' }))
      const next = principal(mode === 'revoke' ? { permissions: ['streams.read'] } : { scope_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', permissions: ['streams.read', 'streams.manage'] })
      useSessionStore.getState().setSession(authResponse(next), next, mode === 'revoke' ? 'refresh' : undefined)
      await Promise.resolve()
    })
    expect(update).not.toHaveBeenCalled()
  })

  it('discards a late tenant GET and preserves another tenant cache', async () => {
    const actor = authenticate()
    const epoch = useSessionStore.getState().sessionEpoch
    const late = deferred<Stream>()
    vi.spyOn(streamsApi, 'get').mockReturnValueOnce(late.promise).mockResolvedValue({ ...stream, listen_port: 19000 })
    const client = setup()
    const next = principal({ scope_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', permissions: ['streams.read', 'streams.manage'] })
    act(() => useSessionStore.getState().setSession(authResponse(next), next))
    await screen.findByRole('heading', { name: '端口 19000' })
    await act(async () => { late.resolve(stream); await Promise.resolve() })
    expect(screen.queryByRole('heading', { name: '端口 18100' })).not.toBeInTheDocument()
    expect(client.getQueryData(['stream-detail', actor.scope_kind, actor.scope_id, epoch, stream.id])).toBeUndefined()
  })

  it('keeps same-epoch edits while refreshing the access token and writes with the new token', async () => {
    const actor = authenticate(); const get = reads()
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue(stream)
    const user = userEvent.setup(); const client = setup(); await loaded()
    await user.type(screen.getByLabelText('备注'), '保留编辑')
    act(() => useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'new-token' }, actor, 'refresh'))
    expect(get).toHaveBeenCalledOnce()
    expect(screen.getByLabelText('备注')).toHaveValue('保留编辑')
    await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    expect(update.mock.calls[0]?.[0]).toBe('new-token')
    expect(JSON.stringify(client.getQueryCache().getAll().map((q) => q.queryKey))).not.toContain('new-token')
  })

  it('blocks save during a fresh read and restores saving when it settles', async () => {
    authenticate(); const get = reads()
    const update = vi.spyOn(streamsApi, 'update').mockResolvedValue(stream)
    const user = userEvent.setup(); setup(); await loaded()
    const pending = deferred<Stream>(); get.mockReturnValueOnce(pending.promise)
    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(screen.getByRole('button', { name: '保存' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: '保存' }))
    expect(update).not.toHaveBeenCalled()
    await act(async () => { pending.resolve(stream); await Promise.resolve() })
    await waitFor(() => expect(screen.getByRole('button', { name: '保存' })).toBeEnabled())
  })

  it('removes stale detail fields when a refresh returns 403', async () => {
    authenticate(); const get = reads()
    const update = vi.spyOn(streamsApi, 'update')
    const user = userEvent.setup(); setup(); await loaded()
    get.mockRejectedValue(new ApiError('permission denied', 403, 'permission_denied'))
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await screen.findByText('无权查看转发列表')
    expect(screen.queryByRole('button', { name: '保存' })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('备注')).not.toBeInTheDocument()
    expect(update).not.toHaveBeenCalled()
  })

  it('ignores a late update result after a tenant switch', async () => {
    authenticate(); reads()
    const pending = deferred<Stream>()
    const update = vi.spyOn(streamsApi, 'update').mockReturnValue(pending.promise)
    const user = userEvent.setup(); setup(); await loaded(); await save(user)
    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    const next = principal({ scope_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', permissions: ['streams.read'] })
    act(() => useSessionStore.getState().setSession(authResponse(next), next))
    await act(async () => { pending.resolve(stream); await Promise.resolve() })
    expect(screen.queryByText('转发规则已更新，发布意图下发状态待确认')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '保存' })).not.toBeInTheDocument()
  })

  it.each([
    ['en-US', enUS.streams],
    ['qps-ploc', (pseudoCN as unknown as typeof zhCN).streams],
  ] as const)('renders detail, origin pool and access tab using %s', async (locale, copy) => {
    await changeLocale(locale); authenticate(); reads()
    const user = userEvent.setup(); setup()
    await screen.findByRole('tab', { name: copy.detail.basic })
    expect(await screen.findByLabelText(copy.origins.address)).toHaveValue(stream.upstream_address)
    expect(screen.getByText(copy.detail.operationStatus)).toBeInTheDocument()
    expect(screen.getByText(copy.detail.syncStatus)).toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: copy.detail.access }))
    expect(screen.getByRole('heading', { name: copy.detail.acl })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: copy.detail.geo })).toBeInTheDocument()
  })
})
