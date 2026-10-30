import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import { nodeMonitoringApi } from '../api/nodeMonitoring'
import { useSessionStore } from '../auth/session'
import NodeListPage from '../pages/NodeListPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// D8: a node registered by the install script has no region, so no line group
// (which only takes catalogued regions) could ever add it. The node list must
// let an administrator set the region: in the edit dialog, when initializing,
// and for several nodes at once.

const scopeID = '22222222-2222-4222-8222-222222222222'

const base: NodeInventoryItem = {
  id: '018f0000-0000-7000-8000-000000000001',
  display_id: '1',
  name: 'edge-85',
  description: '',
  region: '',
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
  created_at: '2026-10-22T08:00:00Z',
  updated_at: '2026-10-22T09:00:00Z',
  presence: {
    status: 'online', last_heartbeat_at: '2026-10-22T08:59:55Z', agent_version: '1.0.35', session_epoch: 1,
    heartbeat_sequence: 1, projection_freshness: 'fresh', lease_signal: 'present',
  },
}
const second: NodeInventoryItem = { ...base, id: '018f0000-0000-7000-8000-000000000002', display_id: '2', name: 'edge-78', ipv4: '192.0.2.78' }

function region(id: string, name: string) {
  return { id, name, code: `region-${id}`, country_code: '', province_code: '', description: '', l2_check_port: 80, sort: 100, revision: 1, created_at: '2026-10-22T08:00:00Z', updated_at: '2026-10-22T08:00:00Z' }
}

function json(body: unknown, status = 200): Response {
  if (typeof body === 'object' && body !== null && 'items' in body) body = { ...body, order: 'management_sort_desc' }
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function authenticate() {
  const admin = principal({
    scope_kind: 'platform', scope_id: scopeID, tenant_id: null, username: 'admin', display_name: 'admin',
    roles: ['platform_owner'], permissions: ['nodes.read', 'nodes.manage', 'regions.read'],
  })
  useSessionStore.getState().setSession(authResponse(admin), admin)
}

interface Backend {
  patches: Array<{ id: string; body: Record<string, unknown>; ifMatch: string | null }>
}

function serve(items: NodeInventoryItem[], regions: Array<ReturnType<typeof region>>, patchStatus?: (id: string) => Response | undefined): Backend {
  const backend: Backend = { patches: [] }
  const current = new Map(items.map((item) => [item.id, item]))
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = String(input)
    if (url.startsWith('/v1/regions')) return Promise.resolve(json({ count: regions.length, data: regions }))
    const patched = /^\/v1\/nodes\/([^/?]+)$/.exec(url)
    if (patched && init?.method === 'PATCH') {
      const id = decodeURIComponent(patched[1]!)
      const body = JSON.parse(String(init.body)) as Record<string, unknown>
      backend.patches.push({ id, body, ifMatch: new Headers(init.headers).get('If-Match') })
      const refused = patchStatus?.(id)
      if (refused) return Promise.resolve(refused)
      const next = { ...current.get(id)!, ...body, revision: current.get(id)!.revision + 1 } as NodeInventoryItem
      current.set(id, next)
      return Promise.resolve(json({ ...next, presence: undefined }))
    }
    if (patched) return Promise.resolve(json(current.get(decodeURIComponent(patched[1]!))))
    const status = new URL(url, 'https://test.invalid').searchParams.get('status')
    // The list contract orders equal sorts by display ID, descending.
    return Promise.resolve(json({ items: [...current.values()]
      .filter((item) => status ? item.admin_state === status : item.admin_state !== 'pending')
      .sort((left, right) => Number(right.display_id) - Number(left.display_id)) }))
  })
  return backend
}

beforeEach(() => {
  sessionStorage.clear()
  vi.spyOn(nodesApi, 'getLatestMetricsBatch').mockImplementation(async (_token, ids) => ({
    observed_at: '2026-10-22T10:00:00Z', items: [], not_reported_node_ids: [...ids],
  }))
  vi.spyOn(nodeMonitoringApi, 'getLatest').mockImplementation(async (_token, ids) => ({
    schema_version: 1, observed_at: '2026-10-22T10:00:00Z',
    configuration: { state: 'unconfigured', head_revision: 0, active_revision: null, activated_at: null, policy: null },
    items: ids.map((node_id) => ({ node_id, sample: null, freshness: 'not_reported', revision_state: 'unknown', delivery_state: 'serving', stale_after_ms: null })),
  }))
})

async function chooseRegion(user: ReturnType<typeof userEvent.setup>, combobox: HTMLElement, name: string) {
  await user.click(combobox)
  const options = await screen.findAllByRole('option', { name })
  await user.click(options.at(-1)!)
}

describe('node region (D8)', () => {
  it('edits the region in the basic tab with the region catalog and saves it through PATCH', async () => {
    authenticate()
    const backend = serve([base], [region('1', '默认区域'), region('2', '华南')])
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />, ['/node/list'])

    await user.click(await screen.findByRole('button', { name: base.name }))
    const dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    const field = within(dialog).getByRole('combobox', { name: '区域' })
    await chooseRegion(user, field, '华南')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(backend.patches).toHaveLength(1))
    expect(backend.patches[0]).toMatchObject({ id: base.id, body: { region: '华南' }, ifMatch: '"3"' })
  })

  it('offers the same catalog in the add-node form instead of free text', async () => {
    authenticate()
    serve([], [region('1', '默认区域')])
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />, ['/node/list'])
    await screen.findByText('暂无节点')
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    await user.click(await screen.findByRole('menuitem', { name: '高级注册' }))
    const dialog = await screen.findByRole('dialog', { name: '添加节点' })
    await user.click(within(dialog).getByRole('combobox', { name: '区域' }))
    expect((await screen.findAllByRole('option', { name: '默认区域' })).length).toBeGreaterThan(0)
  })

  it('marks nodes without a region and sets the region of several selected nodes at once', async () => {
    authenticate()
    const backend = serve([base, second], [region('1', '华东'), region('2', '华南')])
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />, ['/node/list'])

    const row = (await screen.findByRole('button', { name: base.name })).closest('tr')!
    expect(await within(row).findByText('未设置区域')).toBeInTheDocument()
    for (const item of [base, second]) {
      const itemRow = screen.getByRole('button', { name: item.name }).closest('tr')!
      await user.click(within(itemRow).getByRole('checkbox'))
    }
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    await user.click(await screen.findByRole('menuitem', { name: '批量设置区域' }))
    const dialog = await screen.findByRole('dialog', { name: '批量设置区域（2 个节点）' })
    await chooseRegion(user, within(dialog).getByRole('combobox', { name: '区域' }), '华东')
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(backend.patches).toHaveLength(2))
    expect(backend.patches.map((patch) => [patch.id, patch.body, patch.ifMatch]).sort()).toEqual([
      [base.id, { region: '华东' }, '"3"'], [second.id, { region: '华东' }, '"3"'],
    ].sort())
    expect(await within(dialog).findAllByText('已更新')).toHaveLength(2)
  })

  it('reports a node a line group of another region still uses instead of a generic failure', async () => {
    authenticate()
    const backend = serve([base, second], [region('1', '华东')], (id) => id === second.id
      ? json({ error: { code: 'node_region_in_use', message: 'node is used by a line group of another region' } }, 409)
      : undefined)
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />, ['/node/list'])

    for (const item of [base, second]) {
      const itemRow = (await screen.findByRole('button', { name: item.name })).closest('tr')!
      await user.click(within(itemRow).getByRole('checkbox'))
    }
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    await user.click(await screen.findByRole('menuitem', { name: '批量设置区域' }))
    const dialog = await screen.findByRole('dialog', { name: '批量设置区域（2 个节点）' })
    await chooseRegion(user, within(dialog).getByRole('combobox', { name: '区域' }), '华东')
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(backend.patches).toHaveLength(2))
    expect(await within(dialog).findByText('已更新')).toBeInTheDocument()
    expect(await within(dialog).findByText(/仍在其他区域的线路分组中/)).toBeInTheDocument()
  })

  it('chooses the region while initializing a pending node when the catalog has several regions', async () => {
    authenticate()
    const pending = { ...base, id: '018f0000-0000-7000-8000-000000000009', display_id: '9', name: 'edge-pending', admin_state: 'pending' as const }
    const backend = serve([pending], [region('1', '华东'), region('2', '华南')])
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />, ['/node/list'])
    await user.click(await screen.findByRole('tab', { name: '待初始化' }))
    const row = (await screen.findByRole('button', { name: '初始化' })).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '初始化' }))
    const confirm = await screen.findByRole('dialog', { name: '初始化节点 edge-pending？' })
    await chooseRegion(user, within(confirm).getByRole('combobox', { name: '区域' }), '华南')
    await user.click(within(confirm).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(backend.patches).toEqual([
      { id: pending.id, body: { admin_state: 'active', region: '华南' }, ifMatch: '"3"' },
    ]))
  })

  it('opens the list filtered to nodes without a region from the line-resolution link', async () => {
    authenticate()
    serve([base, { ...second, region: '华东' }], [region('1', '华东')])
    renderWithProviders(<NodeListPage />, ['/node/list?region=unset'])
    expect(await screen.findByRole('button', { name: base.name })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: second.name })).not.toBeInTheDocument()
  })
})
