import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { NodeLineGroup } from '../api/nodeScheduling'
import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import { nodeMonitoringApi } from '../api/nodeMonitoring'
import { useSessionStore } from '../auth/session'
import { lineResolutionPath, nodeJoinState } from '../components/nodeJoin'
import NodeListPage from '../pages/NodeListPage'
import { regionCatalogQuery } from '../pages/NodeRegionSelect'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// 节点初始化后心跳在线不等于已进线路组、已进入 DNS 解析。
// 完成态按可回读状态（presence、线路组端点、端点 published）分三步，缺哪步给就地入口；
// 改区域受线路组约束时在表单处列出约束线路组。

const scopeID = '22222222-2222-4222-8222-222222222222'
const groupID = '018f0000-0000-7000-8000-0000000000aa'

const base: NodeInventoryItem = {
  id: '018f0000-0000-7000-8000-000000000001',
  display_id: '1',
  name: 'edge-85',
  description: '',
  region: '华东',
  ipv4: '192.0.2.85',
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
  created_at: '2026-11-20T08:00:00Z',
  updated_at: '2026-11-20T09:00:00Z',
  presence: {
    status: 'online', last_heartbeat_at: '2026-11-20T08:59:55Z', agent_version: '1.0.35', session_epoch: 1,
    heartbeat_sequence: 1, projection_freshness: 'fresh', lease_signal: 'present',
  },
}

function lineGroup(name: string, region: string, endpoints: Array<{ nodeID: string; published?: boolean }>) {
  return {
    id: groupID, display_id: '1', tenant_scope_id: scopeID, revision: 1, name, region, resolved_value: 'line-1',
    note: '', sort_order: 100,
    health_policy: { probe_interval_ms: 10_000, probe_timeout_ms: 3_000, failure_threshold: 3, recovery_threshold: 3, failure_debounce_ms: 0, recovery_debounce_ms: 0 },
    endpoints: endpoints.map((endpoint, index) => ({
      id: `018f0000-0000-7000-8000-00000000010${index}`, node_id: endpoint.nodeID, address: `192.0.2.${100 + index}`, port: 80,
      region, carrier: '', priority: 0, weight: 1, enabled: true,
      health: { status: 'healthy', consecutive_successes: 1, consecutive_failures: 0, last_sequence: 1, row_revision: 1 },
      ...(endpoint.published === undefined ? {} : { published: endpoint.published }),
    })),
    configuration_digest: 'a'.repeat(64), created_by_user_id: '018f0000-0000-7000-8000-0000000000ff',
    created_at: '2026-11-20T08:00:00Z', sealed_at: '2026-11-20T08:00:01Z',
  }
}

function json(body: unknown, status = 200): Response {
  if (typeof body === 'object' && body !== null && 'items' in body) body = { ...body, order: 'management_sort_desc' }
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function authenticate() {
  const admin = principal({
    scope_kind: 'platform', scope_id: scopeID, tenant_id: null, username: 'admin', display_name: 'admin',
    roles: ['platform_owner'], permissions: ['nodes.read', 'nodes.manage', 'regions.read', 'node_scheduling.read'],
  })
  useSessionStore.getState().setSession(authResponse(admin), admin)
}

function serve(items: NodeInventoryItem[], groups: unknown[]) {
  const current = new Map(items.map((item) => [item.id, item]))
  const patches: Array<Record<string, unknown>> = []
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = String(input)
    if (url.startsWith('/v1/regions')) return Promise.resolve(json({ count: 1, data: [] }))
    if (url.startsWith('/v1/node-line-groups')) return Promise.resolve(json({ items: groups }))
    const node = /^\/v1\/nodes\/([^/?]+)$/.exec(url)
    if (node && init?.method === 'PATCH') {
      const id = decodeURIComponent(node[1]!)
      const body = JSON.parse(String(init.body)) as Record<string, unknown>
      patches.push(body)
      const next = { ...current.get(id)!, ...body, revision: current.get(id)!.revision + 1 } as NodeInventoryItem
      current.set(id, next)
      return Promise.resolve(json({ ...next, presence: undefined }))
    }
    if (node) return Promise.resolve(json(current.get(decodeURIComponent(node[1]!))))
    const status = new URL(url, 'https://test.invalid').searchParams.get('status')
    return Promise.resolve(json({ items: [...current.values()]
      .filter((item) => status ? item.admin_state === status : item.admin_state !== 'pending') }))
  })
  return patches
}

beforeEach(() => {
  sessionStorage.clear()
  vi.spyOn(nodesApi, 'getLatestMetricsBatch').mockImplementation(async (_token, ids) => ({
    observed_at: '2026-11-20T10:00:00Z', items: [], not_reported_node_ids: [...ids],
  }))
  vi.spyOn(nodeMonitoringApi, 'getLatest').mockImplementation(async (_token, ids) => ({
    schema_version: 1, observed_at: '2026-11-20T10:00:00Z',
    configuration: { state: 'unconfigured', head_revision: 0, active_revision: null, activated_at: null, policy: null },
    items: ids.map((node_id) => ({ node_id, sample: null, freshness: 'not_reported', revision_state: 'unknown', delivery_state: 'serving', stale_after_ms: null })),
  }))
})

describe('node join progress (首装验收 04)', () => {
  it('tells connected, in a line group and in DNS apart from read-back state', () => {
    const group = (endpoints: Array<{ nodeID: string; published?: boolean }>, region = '华东') =>
      lineGroup('华东 A 组', region, endpoints) as unknown as NodeLineGroup
    expect(nodeJoinState(base, [group([])])).toMatchObject({ connected: true, inLineGroup: false, inDNS: false, target: { id: groupID } })
    expect(nodeJoinState(base, [group([], '华南')])).toMatchObject({ inLineGroup: false, target: null })
    expect(nodeJoinState(base, [group([{ nodeID: base.id }])])).toMatchObject({ inLineGroup: true, inDNS: false })
    expect(nodeJoinState(base, [group([{ nodeID: base.id, published: false }])])).toMatchObject({ inLineGroup: true, inDNS: false })
    expect(nodeJoinState(base, [group([{ nodeID: base.id, published: true }])])).toMatchObject({ inLineGroup: true, inDNS: true })
    expect(nodeJoinState({ ...base, presence: { ...base.presence, status: 'offline' } }, [])).toMatchObject({ connected: false })
    expect(lineResolutionPath(groupID, base.id)).toBe(`/node/line-group/line/${groupID}?node=${base.id}`)
  })

  it('shows the join progress after initializing, with a link that preselects the node in its line group', async () => {
    authenticate()
    const pending = { ...base, id: '018f0000-0000-7000-8000-000000000009', display_id: '9', name: 'edge-pending', admin_state: 'pending' as const }
    const patches = serve([pending], [lineGroup('华东 A 组', '华东', [])])
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />, ['/node/list'])
    await user.click(await screen.findByRole('tab', { name: '待初始化' }))
    const row = (await screen.findByRole('button', { name: '初始化' })).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '初始化' }))
    const confirm = await screen.findByRole('dialog', { name: '初始化节点 edge-pending？' })
    expect(within(confirm).getByText(/在线路分组「配置解析」加入节点 IP 后，节点才进入 DNS 解析/)).toBeInTheDocument()
    await user.click(within(confirm).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(patches).toEqual([{ admin_state: 'active' }]))

    const done = await screen.findByRole('dialog', { name: '节点 edge-pending 已初始化' })
    const progress = within(done).getByTestId('node-join-progress')
    expect(within(progress).getByText('已连接')).toBeInTheDocument()
    expect(within(progress).getByText('已进线路组')).toBeInTheDocument()
    expect(within(progress).getByText('已进入 DNS 解析')).toBeInTheDocument()
    expect(within(progress).getByRole('link', { name: '去「华东 A 组」配置解析' }))
      .toHaveAttribute('href', `/node/line-group/line/${groupID}?node=${pending.id}`)
  })

  it('lists the line groups that keep the node in its region next to the region field', async () => {
    authenticate()
    serve([{ ...base, region: '' }], [lineGroup('华东 A 组', '华东', [{ nodeID: base.id }])])
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />, ['/node/list'])
    await user.click(await screen.findByRole('button', { name: base.name }))
    const dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    const locks = await within(dialog).findByTestId('node-region-locks')
    expect(locks).toHaveTextContent('先从这些线路分组移出才能改区域')
    expect(within(locks).getByRole('link', { name: '华东 A 组' })).toHaveAttribute('href', `/node/line-group/line/${groupID}`)
  })

  it('refetches every region picker after a region write', () => {
    for (const key of [['node-region-catalog', 'owner'], ['node-line-groups', 'o', 'region-catalog'], ['node-l2-topology', 'o', 'regions'],
      ['package-resource-names', 'o'], ['package-resource-options', 'o'], ['stream-line-filter-options', 's', 'region'],
      ['configuration-override-targets', 1, 'region', ''], ['configuration-override-target-names', 1]]) {
      expect(regionCatalogQuery(key), JSON.stringify(key)).toBe(true)
    }
    for (const key of [['nodes', 'o'], ['node-line-groups', 'o', 'platform', 's'], ['stream-line-filter-options', 's', 'line_group'],
      ['configuration-override-targets', 1, 'node', '']]) {
      expect(regionCatalogQuery(key), JSON.stringify(key)).toBe(false)
    }
  })
})
