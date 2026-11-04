import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import { nodeMonitoringApi } from '../api/nodeMonitoring'
import { nodeInstallationTicketsApi } from '../api/nodeInstallationTickets'
import { useSessionStore } from '../auth/session'
import NodeListPage from '../pages/NodeListPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// 节点重装（机器重置）后：
// 1. 正常（active）但 agent 不在线的节点，状态列显示“离线”而不是“正常”；
// 2. 区域列在“线路组(N个)”之外单独显示节点所在的隐藏市场供货组；
// 3. 删除被拒（node_in_use）时说明被哪个线路组/供货组/L2/任务占用。

const scopeID = '22222222-2222-4222-8222-222222222222'
const supplyGroupID = '018f0000-0000-7000-8000-0000000000aa'

const base: NodeInventoryItem = {
  id: '018f0000-0000-7000-8000-000000000001',
  display_id: '1',
  name: 'edge-online',
  description: '',
  region: '华东',
  ipv4: '192.0.2.11',
  admin_state: 'active',
  management_settings: {
    schema_version: 1, sort: 100, node_type: 'L1', cache_directory: '', cache_limit_gb: 0, log_directory: '',
    ip_location: { country: '', province: '', city: '', isp: '', country_code: '' },
    auto_disable: {
      bandwidth_limit: 0, bandwidth_unit: 'Mbps', traffic_enabled: false, traffic_from_day: 1, traffic_from_time: '00:00:00',
      traffic_total_gb: 500, traffic_types: ['outbound'], excluded_interfaces: '', disabled_periods: '',
    },
    secondary_ips: [], external_probe: true,
  },
  revision: 3,
  created_at: '2026-11-04T08:00:00Z',
  updated_at: '2026-11-04T09:00:00Z',
  presence: {
    status: 'online', last_heartbeat_at: '2026-11-04T08:59:55Z', agent_version: '1.0.35', session_epoch: 1,
    heartbeat_sequence: 1, projection_freshness: 'fresh', lease_signal: 'present',
  },
}
const offline: NodeInventoryItem = {
  ...base, id: '018f0000-0000-7000-8000-000000000002', display_id: '2', name: 'edge-reset', ipv4: '11.0.0.118',
  presence: { status: 'offline', last_heartbeat_at: '2026-11-04T07:00:00Z', session_epoch: 1, heartbeat_sequence: 9,
    projection_freshness: 'stale', lease_signal: 'absent' },
  market_supply_groups: [{ id: supplyGroupID, name: '香港 BGP' }],
}
const never: NodeInventoryItem = {
  ...base, id: '018f0000-0000-7000-8000-000000000003', display_id: '3', name: 'edge-never', ipv4: '192.0.2.13',
  presence: { status: 'unknown', projection_freshness: 'never', lease_signal: 'absent' },
}
const disabledOffline: NodeInventoryItem = {
  ...offline, id: '018f0000-0000-7000-8000-000000000004', display_id: '4', name: 'edge-disabled', ipv4: '192.0.2.14',
  admin_state: 'disabled', market_supply_groups: undefined,
}

function json(body: unknown, status = 200): Response {
  if (typeof body === 'object' && body !== null && 'items' in body) body = { ...body, order: 'management_sort_desc' }
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function authenticate() {
  const admin = principal({
    scope_kind: 'platform', scope_id: scopeID, tenant_id: null, username: 'admin', display_name: 'admin',
    roles: ['platform_owner'], permissions: ['nodes.read', 'nodes.manage', 'node_scheduling.read'],
  })
  useSessionStore.getState().setSession(authResponse(admin), admin)
}

const inUseReasons = [
  { kind: 'market_supply', id: supplyGroupID, name: '香港 BGP', group_nodes: 1, normal_subscriptions: 2 },
  { kind: 'line_group', id: '018f0000-0000-7000-8000-0000000000bb', name: '华东 A 组' },
  { kind: 'l2', id: '018f0000-0000-7000-8000-0000000000cc', name: 'L2 回源' },
  { kind: 'cache_operation', count: 3 },
]

function serve(items: NodeInventoryItem[]) {
  const ordered = [...items].sort((left, right) => Number(right.display_id) - Number(left.display_id))
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = String(input)
    if (url.startsWith('/v1/node-line-groups')) return Promise.resolve(json({ items: [] }))
    if (init?.method === 'PATCH') {
      return Promise.resolve(json({ error: { code: 'node_in_use', message: 'internal', request_id: 'r-1', details: { reasons: inUseReasons } } }, 409))
    }
    if (url === '/v1/nodes/batch-admin-state' && init?.method === 'POST') {
      return Promise.resolve(json({ items: [{ id: offline.id, status: 'failed', error: { code: 'node_in_use', reasons: inUseReasons } }] }))
    }
    return Promise.resolve(json({ items: ordered }))
  })
}

beforeEach(() => {
  sessionStorage.clear()
  vi.spyOn(nodesApi, 'getLatestMetricsBatch').mockImplementation(async (_token, ids) => ({
    observed_at: '2026-11-04T10:00:00Z', items: [], not_reported_node_ids: [...ids],
  }))
  vi.spyOn(nodeMonitoringApi, 'getLatest').mockImplementation(async (_token, ids) => ({
    schema_version: 1, observed_at: '2026-11-04T10:00:00Z',
    configuration: { state: 'unconfigured', head_revision: 0, active_revision: null, activated_at: null, policy: null },
    items: ids.map((node_id) => ({ node_id, sample: null, freshness: 'not_reported', revision_state: 'unknown', delivery_state: 'serving', stale_after_ms: null })),
  }))
  vi.spyOn(nodeInstallationTicketsApi, 'get').mockImplementation(async (_token, ids) => ({
    observed_at: '2026-11-04T10:00:00Z',
    items: ids.map((node_id) => ({ node_id, state: 'unknown', issued_at: null, not_after: null, days_left: null, reported_at: null })),
  }))
})

const stateCell = (row: HTMLElement) => row.querySelector('.node-state-cell') as HTMLElement

describe('node list in-use and presence', () => {
  it('shows an active node whose agent is not online as offline', async () => {
    authenticate()
    serve([base, offline, never, disabledOffline])
    renderWithProviders(<NodeListPage />)

    const online = (await screen.findByText('edge-online')).closest('tr')!
    expect(within(stateCell(online)).getByText('正常')).toBeInTheDocument()
    expect(stateCell(online)).not.toHaveAttribute('data-offline')
    for (const name of ['edge-reset', 'edge-never']) {
      const row = screen.getByText(name).closest('tr')!
      expect(within(stateCell(row)).getByText('离线')).toBeInTheDocument()
      expect(within(stateCell(row)).queryByText('正常')).not.toBeInTheDocument()
      expect(stateCell(row)).toHaveAttribute('data-offline', 'true')
      // The details keep both states.
      expect(stateCell(row)).toHaveAttribute('title', expect.stringContaining('管理状态: 已启用'))
    }
    // Other admin states keep their own label.
    const disabled = screen.getByText('edge-disabled').closest('tr')!
    expect(within(stateCell(disabled)).getByText('已禁用')).toBeInTheDocument()
    expect(stateCell(disabled)).not.toHaveAttribute('data-offline')
  })

  it('counts the hidden market supply groups apart from line groups', async () => {
    authenticate()
    serve([base, offline])
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)

    const row = (await screen.findByText('edge-reset')).closest('tr')!
    const region = row.querySelector('.node-region-cell') as HTMLElement
    expect(within(region).getByRole('link', { name: '线路组(0个)' })).toBeInTheDocument()
    const supply = within(region).getByText('市场供货(1)')
    await user.hover(supply)
    expect(await screen.findByText(/该节点在节点市场供货组中：香港 BGP。供货组不在线路组列表显示/)).toBeInTheDocument()
    const plain = screen.getByText('edge-online').closest('tr')!
    expect(within(plain.querySelector('.node-region-cell') as HTMLElement).queryByText(/市场供货/)).not.toBeInTheDocument()
  })

  it('names what holds a node whose deletion is refused', async () => {
    authenticate()
    const fetchSpy = serve([offline])
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)

    const row = (await screen.findByText('edge-reset')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '更多' }))
    await user.click(await screen.findByRole('menuitem', { name: '删除' }))
    const dialog = await screen.findByRole('dialog', { name: '删除节点 edge-reset？' })
    expect(dialog).toHaveTextContent('仍被线路分组（含节点市场供货组）、L2 配置使用或有未完成缓存任务的节点不能删除')
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(true))
    const expected = '节点仍被占用，不能删除：线路组：华东 A 组；' +
      '节点市场供货组「香港 BGP」：该供货组有 2 个有效订阅，不能移除最后一个节点；请先在供货组里换上其它节点；' +
      'L2 配置：L2 回源；3 个未完成的缓存任务，请等待结束'
    expect(await screen.findByText(expected)).toBeInTheDocument()
    expect(screen.queryByText('internal')).not.toBeInTheDocument()
  })

  it('names what holds each node a batch deletion refused', async () => {
    authenticate()
    serve([offline])
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)

    const row = (await screen.findByText('edge-reset')).closest('tr')!
    await user.click(within(row).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    await user.click(await screen.findByRole('menuitem', { name: '删除节点' }))
    const dialog = await screen.findByRole('dialog', { name: '删除 1 个节点' })
    expect(dialog).toHaveTextContent('含节点市场供货组')
    await user.click(within(dialog).getByRole('button', { name: '删除 1 个节点' }))
    const results = await screen.findByRole('dialog', { name: '批量操作结果' })
    expect(results).toHaveTextContent('节点市场供货组「香港 BGP」：该供货组有 2 个有效订阅，不能移除最后一个节点')
    expect(results).toHaveTextContent('线路组：华东 A 组')
  })
})
