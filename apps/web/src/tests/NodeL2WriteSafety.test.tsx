import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { useState } from 'react'

import { useSessionStore } from '../auth/session'
import NodeL2TopologyPage from '../pages/NodeL2TopologyPage'
import NodeL2NodesPage from '../pages/NodeL2NodesPage'
import { principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// 结果未知改为 OutcomeUnknown 后，弹窗标题与原位恢复条（或表单内 Alert）同文案；断言原位提示
const OUTCOME_BAR = '.ant-alert-message'

type Page = 'inventory' | 'nodes'
const scopeID = '22222222-2222-4222-8222-222222222222'
const userID = '11111111-1111-4111-8111-111111111111'
const configID = '33333333-3333-4333-8333-333333333333'
const nodeID = '44444444-4444-4444-8444-444444444444'
const candidateID = '55555555-5555-4555-8555-555555555555'

function L2SafetyHarness({ page, capture }: { page: Page; capture?: (client: QueryClient) => void }) {
  const client = useQueryClient()
  capture?.(client)
  const [visible, setVisible] = useState(true)
  return <><button onClick={() => setVisible((value) => !value)}>{visible ? '隐藏页面' : '返回页面'}</button>{visible ? <Routes>
    <Route path="/" element={<NodeL2TopologyPage />} />
    <Route path="/node/l2-config/node/:id" element={page === 'nodes' ? <NodeL2NodesPage /> : null} />
  </Routes> : null}</>
}

function l2RetrySafetyFixture(page: Page) {
  const config = { id: configID, display_id: '3', tenant_scope_id: scopeID, revision: 3,
    name: '配置 A', region: 'cn-east', remark: '', mode: 'cache', load_method: 'rr' }
  const node = { id: nodeID, display_id: '4', tenant_scope_id: scopeID, revision: 4,
    config_id: configID, node_id: nodeID, name: '节点 A', ip_address: '192.0.2.4',
    admin_state: 'active', online_status: 'online', enabled: true, weight: 80,
    sort: 1, condition_id: null, condition_name: null }
  const candidate = { node_id: candidateID, name: '候选 A', ip_address: '192.0.2.5',
    display_id: '5', admin_state: 'active', online_status: 'online' }
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json' },
  })
  const read = (input: RequestInfo | URL) => {
    const url = String(input)
    if (url === '/v1/l2-configs') return json({ items: [config] })
    if (url.startsWith('/v1/l2-configs/')) return json(config)
    if (url.includes('available=true')) return json({ items: [candidate] })
    if (url.startsWith('/v1/l2-nodes?')) return json({ items: [node] })
    if (url === '/v1/l2-conds') return json({ items: [] })
    throw new Error(`Unexpected read ${url}`)
  }
  return {
    config, node, candidate, json, read,
    mount: (capture?: (client: QueryClient) => void) => renderWithProviders(
      <L2SafetyHarness page={page} capture={capture} />,
      [page === 'nodes' ? `/node/l2-config/node/${configID}` : '/'],
    ),
    submit: async (user: ReturnType<typeof userEvent.setup>) => {
      if (page === 'inventory') {
        const row = (await screen.findByText('配置 A')).closest('tr')!
        await user.click(within(row).getByRole('button', { name: '编辑' }))
      } else await user.click(await screen.findByRole('button', { name: '编辑 节点 A' }))
      await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '确定' }))
    },
    success: (input: RequestInit) => json({ ...(page === 'inventory' ? config : node),
      ...JSON.parse(String(input.body)), revision: 5 }),
    storageKey: `cdnca:l2-retry:tenant:${scopeID}:${userID}:${page === 'inventory' ? 'inventory' : configID}`,
  }
}

beforeEach(() => {
  sessionStorage.clear()
  useSessionStore.setState({ accessToken: 'private-access-token', sessionEpoch: 7,
    status: 'authenticated', principal: principal({ permissions: ['node_scheduling.read', 'node_scheduling.manage'] }) })
})

describe.each(['inventory', 'nodes'] as const)('L2 %s write safety', (page) => {
  it('retains an unresolved write after unmount and remount with the same QueryClient', async () => {
    const f = l2RetrySafetyFixture(page)
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') throw new TypeError('lost response')
      return f.read(url)
    })
    const user = userEvent.setup()
    f.mount()
    await f.submit(user)
    await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })
    await user.click(screen.getByRole('button', { name: '隐藏页面' }))
    await user.click(screen.getByRole('button', { name: '返回页面' }))
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
  })

  it('keeps invalid successful responses locked across a new QueryClient and retries exact bytes', async () => {
    const f = l2RetrySafetyFixture(page)
    let writes = 0
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') return ++writes === 1 ? f.json({}) : f.success(init)
      return f.read(url)
    })
    const user = userEvent.setup()
    const first = f.mount()
    await f.submit(user)
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(sessionStorage.getItem(f.storageKey)).not.toContain('private-access-token')
    first.unmount()
    f.mount()
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(writes).toBe(1)
    act(() => useSessionStore.setState({ accessToken: 'rotated-token' }))
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('L2 配置已保存')).toBeInTheDocument()
    const calls = fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')
    expect(calls).toHaveLength(2)
    expect(calls[1]![1]?.body).toBe(calls[0]![1]?.body)
    for (const header of ['If-Match', 'Idempotency-Key', 'X-Request-ID'])
      expect(new Headers(calls[1]![1]?.headers).get(header)).toBe(new Headers(calls[0]![1]?.headers).get(header))
    expect(new Headers(calls[1]![1]?.headers).get('Authorization')).toBe('Bearer rotated-token')
  })

  it.each([409, 422])('keeps a 503 outcome sticky when exact replay returns %s', async (status) => {
    const f = l2RetrySafetyFixture(page)
    let writes = 0
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') return f.json({ error: { code: 'private', message: 'must not display' } }, ++writes === 1 ? 503 : status)
      return f.read(url)
    })
    const user = userEvent.setup()
    f.mount()
    await f.submit(user)
    await user.click(await screen.findByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(writes).toBe(2))
    await waitFor(() => expect(screen.getByRole('button', { name: '使用同一请求重试' })).not.toHaveClass('ant-btn-loading'))
    expect(screen.getByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(screen.queryByText('must not display')).not.toBeInTheDocument()
    const calls = fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')
    expect(calls[1]![1]?.body).toBe(calls[0]![1]?.body)
    expect(new Headers(calls[1]![1]?.headers).get('Idempotency-Key')).toBe(new Headers(calls[0]![1]?.headers).get('Idempotency-Key'))
  })

  it('stops before a write when the retry record cannot be persisted', async () => {
    const f = l2RetrySafetyFixture(page)
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => init?.method === 'PUT' ? f.success(init) : f.read(url))
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('quota') })
    f.mount()
    await f.submit(userEvent.setup())
    expect(await screen.findByText('写入保护记录不可用')).toBeInTheDocument()
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(0)
  })

  it('blocks the current page if storage becomes unavailable after the server accepts a write', async () => {
    const f = l2RetrySafetyFixture(page)
    let stopStorage: (() => void) | undefined
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') {
        const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('storage disabled') })
        stopStorage = () => set.mockRestore()
        return f.success(init)
      }
      return f.read(url)
    })
    const user = userEvent.setup()
    const first = f.mount()
    await f.submit(user)
    expect(await screen.findByText('写入保护记录不可用')).toBeInTheDocument()
    expect(screen.queryByText('L2 配置已保存')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    const record = JSON.parse(sessionStorage.getItem(f.storageKey)!)
    expect(record.phase).toBe('unknown')
    stopStorage?.()
    first.unmount()
    f.mount()
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(sessionStorage.getItem(f.storageKey)).toBe(JSON.stringify(record))
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
  })

  it('denies an exact retry after live manage permission is removed', async () => {
    const f = l2RetrySafetyFixture(page)
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') throw new TypeError('lost response')
      return f.read(url)
    })
    const user = userEvent.setup()
    f.mount()
    await f.submit(user)
    await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })
    act(() => useSessionStore.setState({ principal: principal({ permissions: ['node_scheduling.read'] }) }))
    expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
    expect(sessionStorage.getItem(f.storageKey)).not.toBeNull()
  })

  it('does not resend a frozen request when its durable record becomes corrupted', async () => {
    const f = l2RetrySafetyFixture(page)
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') throw new TypeError('lost response')
      return f.read(url)
    })
    const user = userEvent.setup()
    f.mount()
    await f.submit(user)
    await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })
    sessionStorage.setItem(f.storageKey, '{')
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('写入保护记录不可用')).toBeInTheDocument()
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
  })

  it('keeps corrupted persisted records fail-closed instead of silently replacing them', async () => {
    const f = l2RetrySafetyFixture(page)
    sessionStorage.setItem(f.storageKey, '{')
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => f.read(url))
    f.mount()
    expect(await screen.findByText('写入保护记录不可用')).toBeInTheDocument()
    expect(sessionStorage.getItem(f.storageKey)).toBe('{')
    expect(fetch.mock.calls.some(([, init]) => init?.method)).toBe(false)
  })

  it('restores confirmed-write readback failure as GET-only recovery after a new QueryClient', async () => {
    const f = l2RetrySafetyFixture(page)
    let writes = 0
    let recovered = false
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') { writes += 1; return f.success(init) }
      return writes && !recovered ? f.json({ error: { code: 'private', message: 'private read' } }, 503) : f.read(url)
    })
    const user = userEvent.setup()
    const first = f.mount()
    await f.submit(user)
    expect(await screen.findByText('写入已确认，回读尚未完成')).toBeInTheDocument()
    expect(screen.queryByText('L2 配置已保存')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    first.unmount()
    f.mount()
    expect(await screen.findByText('写入已确认，回读尚未完成')).toBeInTheDocument()
    recovered = true
    await user.click(screen.getByRole('button', { name: '重试读取' }))
    expect(await screen.findByText('L2 配置已保存')).toBeInTheDocument()
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
    expect(sessionStorage.getItem(f.storageKey)).toBeNull()
  })

  it('does not clear an accepted write or publish late readback after switching owners', async () => {
    const f = l2RetrySafetyFixture(page)
    let wrote = false
    let readbackRequested = false
    let release!: (value: Response) => void
    const pending = new Promise<Response>((resolve) => { release = resolve })
    const foreignScope = '88888888-8888-4888-8888-888888888888'
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') { wrote = true; return f.success(init) }
      const otherOwner = new Headers(init?.headers).get('Authorization') === 'Bearer other-owner'
      if (wrote && !otherOwner) { readbackRequested = true; return pending }
      const response = f.read(url)
      if (!otherOwner) return response
      const body = await response.json()
      for (const resource of body.items ?? [body]) if ('tenant_scope_id' in resource) resource.tenant_scope_id = foreignScope
      return f.json(body)
    })
    const user = userEvent.setup()
    f.mount()
    await f.submit(user)
    await waitFor(() => expect(readbackRequested).toBe(true))
    expect(JSON.parse(sessionStorage.getItem(f.storageKey)!).phase).toBe('readback')
    act(() => useSessionStore.setState({ accessToken: 'other-owner', sessionEpoch: 8,
      principal: principal({ scope_id: foreignScope, tenant_id: foreignScope, permissions: ['node_scheduling.read', 'node_scheduling.manage'] }) }))
    if (page === 'nodes') await screen.findByRole('button', { name: '编辑 节点 A' })
    else await screen.findByText('配置 A')
    await act(async () => { release(page === 'nodes' ? f.json(f.config) : f.json({ items: [f.config] })) })
    expect(screen.queryByText('L2 配置已保存')).not.toBeInTheDocument()
    expect(screen.queryByText('写入已确认，回读尚未完成')).not.toBeInTheDocument()
    expect(JSON.parse(sessionStorage.getItem(f.storageKey)!).phase).toBe('readback')
  })
})

describe('L2 node selection and asynchronous denial', () => {

  it('an inventory read 403 stops the next delete in an in-flight batch', async () => {
    const f = l2RetrySafetyFixture('inventory')
    let client!: QueryClient
    let denyReads = false
    let release!: (value: Response) => void
    const pending = new Promise<Response>((resolve) => { release = resolve })
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'DELETE') return pending
      if (denyReads) return f.json({ error: { code: 'node_scheduling_permission_denied' } }, 403)
      if (String(url) === '/v1/l2-configs') return f.json({ items: [f.config, { ...f.config, id: nodeID, name: '配置 B' }] })
      return f.read(url)
    })
    const user = userEvent.setup()
    f.mount((value) => { client = value })
    await screen.findByText('配置 B')
    await user.click(screen.getAllByRole('checkbox')[0]!)
    await user.click(screen.getAllByRole('button', { name: '删除' })[0]!)
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetch.mock.calls.filter(([, init]) => init?.method === 'DELETE')).toHaveLength(1))
    denyReads = true
    await act(async () => { await client.invalidateQueries() })
    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()
    await act(async () => { release(new Response(null, { status: 204 })) })
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'DELETE')).toHaveLength(1)
    expect(screen.queryByText('L2 配置已保存')).not.toBeInTheDocument()
  })

  it.each(['success', 'error', 'forbidden'] as const)('does not publish an old-owner write %s into a different current owner', async (settlement) => {
    const f = l2RetrySafetyFixture('nodes')
    let release!: (value: Response) => void
    const pending = new Promise<Response>((resolve) => { release = resolve })
    const foreignScope = '88888888-8888-4888-8888-888888888888'
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') return pending
      const response = f.read(url)
      if (new Headers(init?.headers).get('Authorization') !== 'Bearer other-owner') return response
      const body = await response.json()
      for (const resource of body.items ?? [body]) if ('tenant_scope_id' in resource) resource.tenant_scope_id = foreignScope
      return f.json(body)
    })
    const user = userEvent.setup()
    f.mount()
    await f.submit(user)
    await waitFor(() => expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1))
    act(() => useSessionStore.setState({ accessToken: 'other-owner', sessionEpoch: 8,
      principal: principal({ scope_id: foreignScope, tenant_id: foreignScope, permissions: ['node_scheduling.read', 'node_scheduling.manage'] }) }))
    expect(await screen.findByRole('button', { name: '编辑 节点 A' })).toBeEnabled()
    await act(async () => {
      release(settlement === 'success' ? f.json({ ...f.node, revision: 5 }) : f.json({ error: { code: 'private', message: 'old private failure' } }, settlement === 'forbidden' ? 403 : 503))
    })
    expect(screen.queryByText('L2 配置已保存')).not.toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByText('无权查看节点调度配置')).not.toBeInTheDocument()
    expect(screen.queryByText('old private failure')).not.toBeInTheDocument()
    expect(sessionStorage.getItem(f.storageKey)).not.toBeNull()
  })

  it('clears selected candidates when a new search hides them', async () => {
    const f = l2RetrySafetyFixture('nodes')
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => String(url).includes('available=true')
      ? f.json({ items: [f.candidate, { ...f.candidate, node_id: '66666666-6666-4666-8666-666666666666', name: '候选 B' }] }) : f.read(url))
    const user = userEvent.setup()
    f.mount()
    const row = (await screen.findByText('候选 A')).closest('tr')!
    await user.click(within(row).getByRole('checkbox'))
    expect(screen.getByRole('button', { name: '批量添加' })).toBeEnabled()
    await user.type(screen.getByRole('searchbox', { name: '搜索未添加节点' }), '候选 B')
    expect(screen.queryByText('候选 A')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '批量添加' })).toBeDisabled()
    fireEvent.change(screen.getByRole('searchbox', { name: '搜索未添加节点' }), { target: { value: '' } })
    expect(within(screen.getByText('候选 A').closest('tr')!).getByRole('checkbox')).not.toBeChecked()
  })

  it('a read 403 synchronously stops the next operation of an in-flight batch', async () => {
    const f = l2RetrySafetyFixture('nodes')
    let client!: QueryClient
    let denyReads = false
    let release!: (value: Response) => void
    const pending = new Promise<Response>((resolve) => { release = resolve })
    const second = { ...f.node, id: '77777777-7777-4777-8777-777777777777', name: '节点 B' }
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') return pending
      if (denyReads) return f.json({ error: { code: 'node_scheduling_permission_denied' } }, 403)
      if (String(url).startsWith('/v1/l2-nodes?') && !String(url).includes('available=true')) return f.json({ items: [f.node, second] })
      return f.read(url)
    })
    const user = userEvent.setup()
    f.mount((value) => { client = value })
    await screen.findByText('节点 B')
    const configured = screen.getByRole('heading', { name: '已配置的L2节点' }).closest('section')!
    await user.click(within(configured).getAllByRole('checkbox')[0]!)
    await user.click(screen.getByRole('button', { name: '禁用' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1))
    denyReads = true
    await act(async () => { await client.invalidateQueries() })
    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()
    await act(async () => { release(f.json({ ...f.node, enabled: false, revision: 5 })); await Promise.resolve() })
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
    expect(screen.queryByText('L2 配置已保存')).not.toBeInTheDocument()
  })
})
