import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { useState } from 'react'

import type { NodeLineGroup } from '../api/nodeScheduling'
import type { NodeInventoryItem } from '../api/nodes'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import NodeLineResolutionPage from '../pages/NodeLineResolutionPage'
import { nodeManagementSettingsFixture, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// antd 测试环境所有 Modal 的 aria-labelledby 都是 test-id，可访问名取的是 DOM 里第一个 test-id（常是反馈弹窗标题）；
// 业务弹窗按自身标题匹配，并排除反馈弹窗（.cdnca-feedback）
const pageDialogs = (name?: string) => screen.queryAllByRole('dialog')
  .filter((element) => !element.classList.contains('cdnca-feedback'))
  .filter((element) => name === undefined || element.querySelector('.ant-modal-title, .ant-drawer-title')?.textContent?.trim() === name)

// 结果未知改为 OutcomeUnknown 后，弹窗标题与原位恢复条（或表单内 Alert）同文案；断言原位提示
const OUTCOME_BAR = '.ant-alert-message'

const scopeID = '22222222-2222-4222-8222-222222222222'
const userID = '11111111-1111-4111-8111-111111111111'
const groupID = '33333333-3333-4333-8333-333333333333'
const nodeID = '44444444-4444-4444-8444-444444444444'
const candidateID = '55555555-5555-4555-8555-555555555555'
const storageKey = `cdnca:line-resolution-retry:tenant:${scopeID}:${userID}:${scopeID}:${groupID}`

function LineResolutionSafetyHarness({ capture }: { capture?: (client: QueryClient) => void }) {
  const client = useQueryClient()
  capture?.(client)
  const [visible, setVisible] = useState(true)
  return <><button onClick={() => setVisible((value) => !value)}>{visible ? '隐藏页面' : '返回页面'}</button>{visible ? <Routes>
    <Route path="/node/line-group/line/:id" element={<NodeLineResolutionPage />} />
  </Routes> : null}</>
}

function lineResolutionSafetyFixture() {
  const group: NodeLineGroup = {
    id: groupID, display_id: '3', tenant_scope_id: scopeID, revision: 7, name: '线路 A', region: 'cn-east',
    resolved_value: 'line-a', ipv4_resolved_value: 'v4-line-a', l2_config_id: null,
    failover_mode: 'primary_offline', note: '', sort_order: 100,
    health_policy: { probe_interval_ms: 10000, probe_timeout_ms: 3000, failure_threshold: 3,
      recovery_threshold: 3, failure_debounce_ms: 0, recovery_debounce_ms: 0 },
    endpoints: [{ id: nodeID, node_id: nodeID, address: '192.0.2.4', port: 8443, region: 'cn-east',
      carrier: '', priority: 0, weight: 80, enabled: true,
      health: { status: 'healthy', consecutive_successes: 3, consecutive_failures: 0, last_sequence: 1,
        last_changed_at: '2026-10-09T00:00:00Z', row_revision: 1 } }],
    configuration_digest: 'a'.repeat(64), created_by_user_id: userID,
    created_at: '2026-10-09T00:00:00Z', sealed_at: '2026-10-09T00:00:00Z',
  }
  const inventory: NodeInventoryItem[] = [nodeID, candidateID].map((id, index) => ({
    id, display_id: String(index + 1), name: index ? '候选 B' : '节点 A', description: '', region: 'cn-east',
    ipv4: index ? '192.0.2.5' : '192.0.2.4', admin_state: 'active', revision: 1,
    management_settings: nodeManagementSettingsFixture(), created_at: group.created_at, updated_at: group.created_at,
    presence: { status: 'online', projection_freshness: 'fresh', lease_signal: 'present' },
  }))
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json' },
  })
  const revisions = new Map<number, NodeLineGroup>([[group.revision, structuredClone(group)]])
  const read = (input: RequestInfo | URL) => {
    const path = String(input).split('?')[0]
    if (path === '/v1/nodes') return json({ items: inventory })
    if (path === '/v1/node-line-groups') return json({ items: [group] })
    if (path === `/v1/node-line-groups/${groupID}`) return json(group)
    const revision = path.match(new RegExp(`^/v1/node-line-groups/${groupID}/revisions/(\\d+)$`))
    if (revision) return json(revisions.get(Number(revision[1])))
    throw new Error(`Unexpected read ${path}`)
  }
  return { group, inventory, json, read,
    mount: (capture?: (client: QueryClient) => void) => renderWithProviders(
      <LineResolutionSafetyHarness capture={capture} />, [`/node/line-group/line/${groupID}`]),
    submit: async (user: ReturnType<typeof userEvent.setup>) => {
      const row = (await screen.findByText('192.0.2.4')).closest('tr')!
      await user.click(within(row).getByRole('checkbox'))
      await user.click(screen.getByRole('button', { name: i18n.t('nodeScheduling:lineDetail.actions.disable') }))
      await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: i18n.t('nodeL2Topology:actions.confirm') }))
    },
    success: (init: RequestInit) => {
      const input = JSON.parse(String(init.body))
      Object.assign(group, input, { revision: 8, configuration_digest: 'b'.repeat(64),
        endpoints: input.endpoints.map((endpoint: NodeLineGroup['endpoints'][number]) => ({ ...endpoint,
          health: { status: 'unknown', consecutive_successes: 0, consecutive_failures: 0, last_sequence: 0,
            last_observed_at: null, last_changed_at: group.created_at, row_revision: 1 } })) })
      revisions.set(group.revision, structuredClone(group))
      return json({ group, replayed: false })
    },
  }
}

beforeEach(() => {
  sessionStorage.clear()
  useSessionStore.setState({ accessToken: 'private-line-token', sessionEpoch: 7, status: 'authenticated',
    principal: principal({ permissions: ['node_scheduling.read', 'node_scheduling.manage', 'nodes.read'] }) })
})

describe('line resolution retry safety', () => {
  it.each([
    ['wrong revision', (group: NodeLineGroup) => { group.revision = 7 }],
    ['skipped revision', (group: NodeLineGroup) => { group.revision = 9 }],
    ['wrong digest', (group: NodeLineGroup) => { group.configuration_digest = 'not-a-digest' }],
    ['wrong endpoint structure', (group: NodeLineGroup) => { group.endpoints[0]!.weight = 0 }],
  ] as const)('keeps a PUT with %s unknown without starting accepted-version reads', async (_, mutate) => {
    const f = lineResolutionSafetyFixture()
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method !== 'PUT') return f.read(url)
      const body = await f.success(init).json()
      mutate(body.group)
      return f.json(body)
    })
    f.mount()
    await f.submit(userEvent.setup())
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(screen.queryByText('解析配置已保存')).not.toBeInTheDocument()
    expect(fetch.mock.calls.some(([url]) => String(url).includes('/revisions/'))).toBe(false)
    expect(JSON.parse(sessionStorage.getItem(storageKey)!).phase).toBe('unknown')
  })

  it.each(['revision', 'digest', 'scope', 'structure'])('retains GET-only recovery when the accepted revision has a wrong %s', async (kind) => {
    const f = lineResolutionSafetyFixture()
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') return f.success(init)
      if (!String(url).includes('/revisions/')) return f.read(url)
      const body = await f.read(url).json()
      if (kind === 'revision') body.revision = 9
      if (kind === 'digest') body.configuration_digest = 'c'.repeat(64)
      if (kind === 'scope') body.tenant_scope_id = candidateID
      if (kind === 'structure') body.endpoints[0].health.row_revision = 0
      return f.json(body)
    })
    f.mount()
    await f.submit(userEvent.setup())
    expect(await screen.findByText('写入已确认，回读尚未完成')).toBeInTheDocument()
    expect(screen.queryByText('解析配置已保存')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '重试读取' }))
    await waitFor(() => expect(fetch.mock.calls.filter(([url]) => String(url).includes('/revisions/'))).toHaveLength(2))
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
    expect(JSON.parse(sessionStorage.getItem(storageKey)!)).toMatchObject({ version: 2, phase: 'readback',
      accepted: { revision: 8, configurationDigest: 'b'.repeat(64) } })
  })

  it.each(['zh-CN', 'qps-ploc'])('verifies the accepted immutable revision before current/list and reports a later current without overwriting it in %s', async (locale) => {
    await i18n.changeLanguage(locale)
    const f = lineResolutionSafetyFixture()
    const afterWrite: string[] = []
    let wrote = false
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') {
        wrote = true
        const response = f.success(init)
        Object.assign(f.group, { revision: 9, configuration_digest: 'c'.repeat(64), name: '后续线路名称' })
        return response
      }
      if (wrote) afterWrite.push(String(url).split('?')[0]!)
      return f.read(url)
    })
    f.mount()
    await f.submit(userEvent.setup())
    expect(await screen.findByText(locale === 'zh-CN' ? '本次版本已保存，当前已有后续版本' : '［本次版本已保存，当前已有后续版本］')).toBeInTheDocument()
    expect(screen.queryByText('解析配置已保存')).not.toBeInTheDocument()
    expect(afterWrite).toEqual([`/v1/node-line-groups/${groupID}/revisions/8`, `/v1/node-line-groups/${groupID}`, '/v1/node-line-groups'])
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
    expect(sessionStorage.getItem(storageKey)).toBeNull()
  })

  it('stops accepted-version readback immediately on 403 without fetching current/list or clearing its record', async () => {
    const f = lineResolutionSafetyFixture()
    const afterWrite: string[] = []
    let wrote = false
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') { wrote = true; return f.success(init) }
      if (wrote) {
        afterWrite.push(String(url))
        return f.json({ error: { code: 'node_scheduling_permission_denied' } }, 403)
      }
      return f.read(url)
    })
    f.mount()
    await f.submit(userEvent.setup())
    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()
    expect(afterWrite).toEqual([`/v1/node-line-groups/${groupID}/revisions/8`])
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
    expect(JSON.parse(sessionStorage.getItem(storageKey)!).accepted.revision).toBe(8)
  })

  it('restores a lost response after remount without resending or storing the token', async () => {
    const f = lineResolutionSafetyFixture()
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') throw new TypeError('lost response')
      return f.read(url)
    })
    const user = userEvent.setup()
    const first = f.mount()
    await f.submit(user)
    await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })
    expect(sessionStorage.getItem(storageKey)).not.toBeNull()
    expect(sessionStorage.getItem(storageKey)).not.toContain('private-line-token')
    await user.click(screen.getByRole('button', { name: '隐藏页面' }))
    await user.click(screen.getByRole('button', { name: '返回页面' }))
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    first.unmount()
    act(() => useSessionStore.setState({ sessionEpoch: 8 }))
    f.mount()
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
  })

  it('keeps invalid successful responses unknown and replays exact bytes with the live token', async () => {
    const f = lineResolutionSafetyFixture()
    let writes = 0
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) =>
      init?.method === 'PUT' ? (++writes === 1 ? f.json({ group: {} }) : f.success(init)) : f.read(url))
    const user = userEvent.setup()
    f.mount()
    await f.submit(user)
    expect(await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    act(() => useSessionStore.setState({ accessToken: 'rotated-line-token' }))
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('解析配置已保存')).toBeInTheDocument()
    const calls = fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')
    expect(calls).toHaveLength(2)
    expect(calls[1]![1]?.body).toBe(calls[0]![1]?.body)
    for (const header of ['If-Match', 'Idempotency-Key', 'X-Request-ID'])
      expect(new Headers(calls[1]![1]?.headers).get(header)).toBe(new Headers(calls[0]![1]?.headers).get(header))
    expect(new Headers(calls[1]![1]?.headers).get('Authorization')).toBe('Bearer rotated-line-token')
    expect(sessionStorage.getItem(storageKey)).toBeNull()
  })

  it.each([409, 422])('keeps a 503 outcome sticky when exact replay returns %s', async (status) => {
    const f = lineResolutionSafetyFixture()
    let writes = 0
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => init?.method === 'PUT'
      ? f.json({ error: { code: 'private', message: 'do not display' } }, ++writes === 1 ? 503 : status) : f.read(url))
    const user = userEvent.setup()
    f.mount()
    await f.submit(user)
    await user.click(await screen.findByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(writes).toBe(2))
    await waitFor(() => expect(screen.getByRole('button', { name: '使用同一请求重试' })).not.toHaveClass('ant-btn-loading'))
    expect(screen.getByText('操作结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(screen.queryByText('do not display')).not.toBeInTheDocument()
    const calls = fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')
    expect(calls[1]![1]?.body).toBe(calls[0]![1]?.body)
    expect(new Headers(calls[1]![1]?.headers).get('Idempotency-Key')).toBe(new Headers(calls[0]![1]?.headers).get('Idempotency-Key'))
  })

  it('blocks writes when storage cannot persist and read back the original request', async () => {
    const f = lineResolutionSafetyFixture()
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => init?.method === 'PUT' ? f.success(init) : f.read(url))
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => undefined)
    f.mount()
    await f.submit(userEvent.setup())
    expect(await screen.findByText('写入保护记录不可用')).toBeInTheDocument()
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(0)
  })

  it('restores a confirmed write with failed readback as GET-only recovery', async () => {
    const f = lineResolutionSafetyFixture()
    let writes = 0
    let recovered = false
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') { writes += 1; return f.success(init) }
      return writes && !recovered ? f.json({ error: { code: 'unavailable' } }, 503) : f.read(url)
    })
    const user = userEvent.setup()
    const first = f.mount()
    await f.submit(user)
    expect(await screen.findByText('写入已确认，回读尚未完成')).toBeInTheDocument()
    expect(screen.queryByText('解析配置已保存')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    first.unmount()
    f.mount()
    expect(await screen.findByText('写入已确认，回读尚未完成')).toBeInTheDocument()
    recovered = true
    await user.click(screen.getByRole('button', { name: '重试读取' }))
    expect(await screen.findByText('解析配置已保存')).toBeInTheDocument()
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
    expect(sessionStorage.getItem(storageKey)).toBeNull()
  })

  it.each(['unknown', 'readback'] as const)('restores legacy %s without guessing accepted evidence', async (phase) => {
    const f = lineResolutionSafetyFixture()
    let writes = 0
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') {
        if (++writes === 1) throw new TypeError('lost response')
        return f.success(init)
      }
      return f.read(url)
    })
    const user = userEvent.setup()
    const first = f.mount()
    await f.submit(user)
    await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })
    const record = JSON.parse(sessionStorage.getItem(storageKey)!)
    delete record.accepted
    record.version = 1
    record.phase = phase
    const raw = JSON.stringify(record)
    sessionStorage.setItem(storageKey, raw)
    first.unmount()
    f.mount()
    if (phase === 'unknown') {
      await user.click(await screen.findByRole('button', { name: '使用同一请求重试' }))
      expect(await screen.findByText('解析配置已保存')).toBeInTheDocument()
      const calls = fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')
      expect(calls).toHaveLength(2)
      expect(calls[1]![1]?.body).toBe(calls[0]![1]?.body)
      expect(new Headers(calls[1]![1]?.headers).get('Idempotency-Key')).toBe(new Headers(calls[0]![1]?.headers).get('Idempotency-Key'))
    } else {
      expect(await screen.findByText('历史保存记录缺少版本证据')).toBeInTheDocument()
      const reads = fetch.mock.calls.length
      await user.click(screen.getByRole('button', { name: '重试读取' }))
      await waitFor(() => expect(fetch.mock.calls.length).toBe(reads + 2))
      expect(fetch.mock.calls.slice(reads).every(([, init]) => !init?.method || init.method === 'GET')).toBe(true)
      expect(fetch.mock.calls.some(([url]) => String(url).includes('/revisions/'))).toBe(false)
      expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
      expect(screen.queryByText('解析配置已保存')).not.toBeInTheDocument()
      expect(sessionStorage.getItem(storageKey)).toBe(raw)
    }
  })

  it.each(['current-behind', 'current-digest', 'list-behind', 'list-digest'] as const)('keeps accepted evidence when %s contradicts the immutable readback', async (kind) => {
    const f = lineResolutionSafetyFixture()
    let wrote = false
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') { wrote = true; return f.success(init) }
      const response = f.read(url)
      if (!wrote || String(url).includes('/revisions/')) return response
      const body = await response.json()
      const target = kind.startsWith('current-') ? body : body.items?.[0]
      if (target?.id === groupID) {
        if (kind.endsWith('behind')) target.revision = 7
        else target.configuration_digest = 'c'.repeat(64)
      }
      return f.json(body)
    })
    f.mount()
    await f.submit(userEvent.setup())
    await waitFor(() => expect(fetch.mock.calls.some(([url]) => String(url).includes('/revisions/8'))).toBe(true))
    expect(screen.getByText('写入已确认，回读尚未完成')).toBeInTheDocument()
    expect(screen.queryByText('解析配置已保存')).not.toBeInTheDocument()
    expect(JSON.parse(sessionStorage.getItem(storageKey)!).accepted.revision).toBe(8)
  })

  it('stops the readback chain when read permission is revoked while the exact revision is pending', async () => {
    const f = lineResolutionSafetyFixture()
    let release!: (response: Response) => void
    const pending = new Promise<Response>((resolve) => { release = resolve })
    let wrote = false
    const afterWrite: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') { wrote = true; return f.success(init) }
      if (wrote) afterWrite.push(String(url))
      return String(url).includes('/revisions/') ? pending : f.read(url)
    })
    f.mount()
    await f.submit(userEvent.setup())
    await waitFor(() => expect(afterWrite).toHaveLength(1))
    act(() => useSessionStore.setState({ principal: principal({ permissions: ['nodes.read'] }) }))
    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()
    await act(async () => release(f.read(`/v1/node-line-groups/${groupID}/revisions/8`)))
    expect(afterWrite).toHaveLength(1)
    expect(screen.queryByText('解析配置已保存')).not.toBeInTheDocument()
    expect(JSON.parse(sessionStorage.getItem(storageKey)!).accepted.revision).toBe(8)
  })

  it('does not let a read 403 and late write repopulate an invalidated owner', async () => {
    const f = lineResolutionSafetyFixture()
    let client!: QueryClient
    let deny = false
    let release!: (value: Response) => void
    const pending = new Promise<Response>((resolve) => { release = resolve })
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') return pending
      return deny ? f.json({ error: { code: 'node_scheduling_permission_denied' } }, 403) : f.read(url)
    })
    const user = userEvent.setup()
    f.mount((value) => { client = value })
    await f.submit(user)
    await waitFor(() => expect(fetch.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(true))
    deny = true
    await act(async () => { await client.invalidateQueries() })
    await screen.findByText('无权查看节点调度配置')
    await act(async () => { release(f.success(fetch.mock.calls.find(([, init]) => init?.method === 'PUT')![1]!)) })
    expect(screen.queryByText('解析配置已保存')).not.toBeInTheDocument()
    expect(client.getQueryCache().getAll().filter((query) => query.queryKey[0] === 'line-resolution' && query.state.data)).toHaveLength(0)
    expect(sessionStorage.getItem(storageKey)).not.toBeNull()
  })

  it('clears hidden selection rather than reviving it when the filter is removed', async () => {
    const f = lineResolutionSafetyFixture()
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => f.read(url))
    const user = userEvent.setup()
    f.mount()
    await user.click(within((await screen.findByText('候选 B')).closest('tr')!).getByRole('checkbox'))
    fireEvent.change(screen.getByRole('searchbox', { name: '搜索可添加 IP' }), { target: { value: 'missing' } })
    await user.click(screen.getByRole('button', { name: '批量添加' }))
    expect(await screen.findByText('请选择节点!')).toBeInTheDocument()
    expect(pageDialogs()).toHaveLength(0)
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(false)
    fireEvent.change(screen.getByRole('searchbox', { name: '搜索可添加 IP' }), { target: { value: '' } })
    expect(within(screen.getByText('候选 B').closest('tr')!).getByRole('checkbox')).not.toBeChecked()
    await user.click(within(screen.getByText('192.0.2.4').closest('tr')!).getByRole('checkbox'))
    fireEvent.change(screen.getByRole('searchbox', { name: '搜索已配置 IP' }), { target: { value: 'missing' } })
    fireEvent.change(screen.getByRole('searchbox', { name: '搜索已配置 IP' }), { target: { value: '' } })
    expect(within(screen.getByText('192.0.2.4').closest('tr')!).getByRole('checkbox')).not.toBeChecked()
  })

  it.each(['mount', 'retry'] as const)('fails closed on a corrupted protection record at %s', async (when) => {
    const f = lineResolutionSafetyFixture()
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') throw new TypeError('lost response')
      return f.read(url)
    })
    const user = userEvent.setup()
    if (when === 'mount') sessionStorage.setItem(storageKey, '{')
    f.mount()
    if (when === 'retry') {
      await f.submit(user)
      await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })
      sessionStorage.setItem(storageKey, '{')
      await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    }
    expect(await screen.findByText('写入保护记录不可用')).toBeInTheDocument()
    expect(sessionStorage.getItem(storageKey)).toBe('{')
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(when === 'mount' ? 0 : 1)
  })

  it.each(['set', 'remove'] as const)('does not unlock an accepted write when storage %s fails', async (operation) => {
    const f = lineResolutionSafetyFixture()
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') {
        vi.spyOn(Storage.prototype, operation === 'set' ? 'setItem' : 'removeItem').mockImplementation(() => { throw new Error('storage denied') })
        return f.success(init)
      }
      return f.read(url)
    })
    const user = userEvent.setup()
    f.mount()
    await f.submit(user)
    expect(await screen.findByText('写入保护记录不可用')).toBeInTheDocument()
    expect(screen.queryByText('解析配置已保存')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(JSON.parse(sessionStorage.getItem(storageKey)!).phase).toBe(operation === 'set' ? 'unknown' : 'readback')
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
  })

  it('keeps an exact retry disabled when live manage permission is revoked', async () => {
    const f = lineResolutionSafetyFixture()
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') throw new TypeError('lost response')
      return f.read(url)
    })
    const user = userEvent.setup()
    f.mount()
    await f.submit(user)
    await screen.findByText('操作结果待确认', { selector: OUTCOME_BAR })
    act(() => useSessionStore.setState({ principal: principal({ permissions: ['node_scheduling.read', 'nodes.read'] }) }))
    const retry = screen.getByRole('button', { name: '使用同一请求重试' })
    expect(retry).toBeDisabled()
    await user.click(retry)
    expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
    expect(sessionStorage.getItem(storageKey)).not.toBeNull()
  })

  it('clears a first definitive rejection instead of treating it as an unknown write', async () => {
    const f = lineResolutionSafetyFixture()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => init?.method === 'PUT'
      ? f.json({ error: { code: 'node_scheduling_revision_conflict' } }, 409) : f.read(url))
    f.mount()
    await f.submit(userEvent.setup())
    expect(await screen.findByText('线路配置保存失败')).toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(sessionStorage.getItem(storageKey)).toBeNull()
  })

  it.each(['success', 'error', 'forbidden'] as const)('isolates an old-owner late write %s and keeps its original record', async (settlement) => {
    const f = lineResolutionSafetyFixture()
    const foreignScope = '88888888-8888-4888-8888-888888888888'
    let release!: (value: Response) => void
    const pending = new Promise<Response>((resolve) => { release = resolve })
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') return pending
      const response = f.read(url)
      if (new Headers(init?.headers).get('Authorization') !== 'Bearer other-line-owner') return response
      const body = await response.json()
      for (const item of body.items ?? [body]) if ('tenant_scope_id' in item) item.tenant_scope_id = foreignScope
      return f.json(body)
    })
    const user = userEvent.setup()
    f.mount()
    await f.submit(user)
    await waitFor(() => expect(fetch.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(true))
    act(() => useSessionStore.setState({ accessToken: 'other-line-owner', sessionEpoch: 8,
      principal: principal({ scope_id: foreignScope, tenant_id: foreignScope, permissions: ['node_scheduling.read', 'node_scheduling.manage', 'nodes.read'] }) }))
    await screen.findByText('192.0.2.4')
    await act(async () => release(settlement === 'success'
      ? f.success(fetch.mock.calls.find(([, init]) => init?.method === 'PUT')![1]!)
      : f.json({ error: { code: 'private', message: 'old private error' } }, settlement === 'forbidden' ? 403 : 503)))
    expect(screen.queryByText('解析配置已保存')).not.toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByText('无权查看节点调度配置')).not.toBeInTheDocument()
    expect(screen.queryByText('old private error')).not.toBeInTheDocument()
    expect(JSON.parse(sessionStorage.getItem(storageKey)!).phase).toBe('unknown')
  })

  it('preserves confirmed-write recovery when the readback completes after an epoch change', async () => {
    const f = lineResolutionSafetyFixture()
    let wrote = false
    let requested = false
    let release!: (value: Response) => void
    const pending = new Promise<Response>((resolve) => { release = resolve })
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') { wrote = true; return f.success(init) }
      if (wrote && new Headers(init?.headers).get('Authorization') === 'Bearer private-line-token') {
        requested = true
        return pending
      }
      return f.read(url)
    })
    const user = userEvent.setup()
    f.mount()
    await f.submit(user)
    await waitFor(() => expect(requested).toBe(true))
    act(() => useSessionStore.setState({ accessToken: 'new-epoch-token', sessionEpoch: 8 }))
    await screen.findByText('写入已确认，回读尚未完成')
    await act(async () => release(f.json(f.group)))
    expect(screen.queryByText('解析配置已保存')).not.toBeInTheDocument()
    expect(JSON.parse(sessionStorage.getItem(storageKey)!).phase).toBe('readback')
  })

  it('does not issue a second write on repeated confirm before the first response', async () => {
    const f = lineResolutionSafetyFixture()
    let release!: (value: Response) => void
    const pending = new Promise<Response>((resolve) => { release = resolve })
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => init?.method === 'PUT' ? pending : f.read(url))
    const user = userEvent.setup()
    f.mount()
    await user.click(within((await screen.findByText('192.0.2.4')).closest('tr')!).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '禁用' }))
    const confirm = within(await screen.findByRole('dialog')).getByRole('button', { name: '确定' })
    fireEvent.click(confirm)
    fireEvent.click(confirm)
    await waitFor(() => expect(fetch.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1))
    await act(async () => release(f.success(fetch.mock.calls.find(([, init]) => init?.method === 'PUT')![1]!)))
    expect(await screen.findByText('解析配置已保存')).toBeInTheDocument()
  })
})

describe('line resolution nodes without a region (D8)', () => {
  it('says how many nodes are left out only because they have no region and links to setting it', async () => {
    const f = lineResolutionSafetyFixture()
    f.inventory.push(...['66666666-6666-4666-8666-666666666666', '77777777-7777-4777-8777-777777777777'].map((id, index) => ({
      ...f.inventory[1]!, id, display_id: String(10 + index), name: `未分区 ${index}`, region: '', ipv4: `192.0.2.${60 + index}`,
    })), { ...f.inventory[1]!, id: '88888888-8888-4888-8888-888888888888', display_id: '20', name: '待初始化', region: '',
      ipv4: '192.0.2.70', admin_state: 'pending' })
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => f.read(url))
    f.mount()
    const notice = await screen.findByText('有 2 个节点未设置区域，未列入此处；设置区域后才能加入本线路分组。')
    expect(within(notice.closest('.ant-alert')!).getByRole('link', { name: '去设置' })).toHaveAttribute('href', '/node/list?region=unset')
    expect(screen.queryByText('192.0.2.60')).not.toBeInTheDocument()
    expect(screen.getByText('192.0.2.5')).toBeInTheDocument()
  })

  it('shows no notice when every node has a region', async () => {
    const f = lineResolutionSafetyFixture()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => f.read(url))
    f.mount()
    expect(await screen.findByText('192.0.2.5')).toBeInTheDocument()
    expect(screen.queryByText(/个节点未设置区域/)).not.toBeInTheDocument()
  })
})

describe('line resolution table status columns (NET-UX-5, fz-x2b published)', () => {
  it('shows enabled, primary/standby and probe state of each configured IP', async () => {
    const f = lineResolutionSafetyFixture()
    const base = f.group.endpoints[0]!
    f.group.endpoints = [
      { ...base, published: true },
      { ...base, id: candidateID, node_id: candidateID, address: '192.0.2.5', priority: 1, published: false,
        health: { ...base.health, status: 'unknown' } },
      { ...base, id: '66666666-6666-4666-8666-666666666666', address: '192.0.2.6', enabled: false,
        health: { ...base.health, status: 'unhealthy' } },
    ]
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => f.read(url))
    f.mount()
    const cells = async (address: string) => Array.from((await screen.findByText(address)).closest('tr')!
      .querySelectorAll('td')).map((cell) => cell.textContent)
    const headers = screen.getAllByRole('columnheader').map((header) => header.textContent)
    expect(headers).toEqual(expect.arrayContaining(['启用', '主备', '探测', '解析']))
    expect(await cells('192.0.2.4')).toEqual(expect.arrayContaining(['已启用', '主', '正常', '生效']))
    expect(await cells('192.0.2.5')).toEqual(expect.arrayContaining(['已启用', '备', '未探测', '未生效']))
    // No published field (unknown) renders the placeholder, never a guess.
    expect((await cells('192.0.2.6')).filter((text) => text === '—')).toHaveLength(2)
    expect(await cells('192.0.2.6')).toEqual(expect.arrayContaining(['已禁用', '—', '异常']))
  })
})
