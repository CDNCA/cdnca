import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import { nodeMonitoringApi } from '../api/nodeMonitoring'
import { useSessionStore } from '../auth/session'
import NodeListPage from '../pages/NodeListPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// fix-fielderr-be2：节点创建/编辑被拒且能定位字段时，弹窗不关、原因标在对应标签页的字段下，不弹提示。

const scopeID = '22222222-2222-4222-8222-222222222222'
const node: NodeInventoryItem = {
  id: '018f0000-0000-7000-8000-000000000001',
  display_id: '1',
  name: 'Edge Shanghai',
  description: 'primary edge',
  region: 'CN-East',
  ipv4: '192.0.2.10',
  ipv6: '2001:db8::10',
  admin_state: 'active',
  management_settings: {
    schema_version: 1,
    sort: 100,
    node_type: 'L1',
    cache_directory: '/www/server/cdnca/cache',
    cache_limit_gb: 500,
    log_directory: '/www/server/cdnca/logs',
    ip_location: { country: '中国', province: '上海', city: '上海', isp: '电信', country_code: 'CN' },
    auto_disable: {
      bandwidth_limit: 0,
      bandwidth_unit: 'Mbps',
      traffic_enabled: true,
      traffic_from_day: 1,
      traffic_from_time: '00:00:00',
      traffic_total_gb: 500,
      traffic_types: ['outbound'],
      excluded_interfaces: '',
      disabled_periods: '',
    },
    secondary_ips: [],
    external_probe: true,
  },
  revision: 4,
  created_at: '2026-07-22T08:00:00Z',
  updated_at: '2026-07-22T09:00:00Z',
  presence: {
    status: 'online',
    last_heartbeat_at: '2026-07-22T08:59:55Z',
    agent_version: '2.4.1',
    session_epoch: 7,
    heartbeat_sequence: 11,
    projection_freshness: 'fresh',
    lease_signal: 'present',
  },
}

beforeEach(() => {
  sessionStorage.clear()
  vi.spyOn(nodesApi, 'getLatestMetricsBatch').mockImplementation(async (_token, ids) => ({
    observed_at: '2026-10-10T10:00:00Z', items: [], not_reported_node_ids: [...ids],
  }))
  vi.spyOn(nodeMonitoringApi, 'getLatest').mockImplementation(async (_token, ids) => ({
    schema_version: 1, observed_at: '2026-10-10T10:00:00Z',
    configuration: { state: 'unconfigured', head_revision: 0, active_revision: null, activated_at: null, policy: null },
    items: ids.map((node_id) => ({ node_id, sample: null, freshness: 'not_reported', revision_state: 'unknown', delivery_state: 'serving', stale_after_ms: null })),
  }))
  const admin = principal({ scope_kind: 'platform', scope_id: scopeID, tenant_id: null, roles: ['platform_owner'],
    permissions: ['nodes.read', 'nodes.manage', 'regions.read', 'regions.manage'] })
  useSessionStore.getState().setSession(authResponse(admin), admin)
})

function json(body: unknown, status = 200, filters: { status?: string } = {}): Response {
  if (typeof body === 'object' && body !== null && 'items' in body && Array.isArray(body.items) &&
    body.items.every((item) => item && 'management_settings' in item && 'presence' in item)) {
    const items = [...body.items as NodeInventoryItem[]].sort((a, b) => b.management_settings.sort - a.management_settings.sort ||
      (BigInt(a.display_id) > BigInt(b.display_id) ? -1 : BigInt(a.display_id) < BigInt(b.display_id) ? 1 : b.id.localeCompare(a.id)))
    const last = items.at(-1)
    const next = 'next_cursor' in body && body.next_cursor !== undefined && last ? `nso1.${btoa(JSON.stringify({
      version: 1, scope_id: scopeID, order: 'management_sort_desc', status: filters.status ?? '', presence: '', search: '',
      last_sort: last.management_settings.sort, last_display_id: last.display_id, last_id: last.id,
    })).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')}` : undefined
    body = { ...body, order: 'management_sort_desc', items, ...(next ? { next_cursor: next } : {}) }
  }
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function refusal(field: string, reason: string) {
  return json({ error: { code: 'validation_error', message: 'invalid', request_id: 'req-node', details: { field, reason } } }, 400)
}

describe('node form field refusals (fix-fielderr-be2)', () => {
  it('keeps the create form open with the refused field marked', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => Promise.resolve(
      String(input) === '/v1/nodes' && init?.method === 'POST' ? refusal('ipv4', 'invalid_format') : json({ items: [node] })))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await screen.findByText('Edge Shanghai')
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    await user.click(await screen.findByRole('menuitem', { name: '高级注册' }))
    const dialog = await screen.findByRole('dialog', { name: '添加节点' })
    fireEvent.change(within(dialog).getByLabelText('节点名称'), { target: { value: 'Edge Guangzhou' } })
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    const item = (await within(dialog).findByText('格式不正确')).closest('.ant-form-item')
    expect(item?.querySelector('input')?.id).toContain('ipv4')
    expect(dialog.querySelector('.node-modal-alert.ant-alert-error')).toBeNull()
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
  })

  it('keeps the edit form open, switches to the refused field tab and marks it', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => Promise.resolve(
      init?.method === 'PATCH' ? refusal('management_settings.secondary_ips[0]', 'duplicate') : json({ items: [node] })))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<NodeListPage />)
    await user.click(await screen.findByRole('button', { name: node.name }))
    const dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    // The stored sub-IP the server refuses (e.g. now used elsewhere) is saved with the basic tab.
    fireEvent.change(within(dialog).getByLabelText('排序'), { target: { value: '0' } })
    await user.click(within(dialog).getAllByRole('button', { name: '确定' }).find((button) => button.closest('.ant-tabs-tabpane-active'))!)
    const item = (await within(dialog).findByText('与已有内容重复')).closest('.ant-form-item')
    expect(item?.textContent).toContain('子IP')
    await waitFor(() => expect(within(dialog).getByRole('tab', { name: '添加子IP' })).toHaveAttribute('aria-selected', 'true'))
    expect(dialog.querySelector('.node-modal-alert.ant-alert-error')).toBeNull()
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
    expect(sessionStorage.length).toBe(0)
  })
})
