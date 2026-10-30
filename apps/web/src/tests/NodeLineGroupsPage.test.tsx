import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import userEvent from '@testing-library/user-event'

import type { L2Config, NodeLineGroup, NodeLineGroupSnapshotInput } from '../api/nodeScheduling'
import { useSessionStore } from '../auth/session'
import NodeLineGroupsPage from '../pages/NodeLineGroupsPage'
import LineGroupSnapshotModal from '../pages/node-scheduling/LineGroupSnapshotModal'
import {
  enUSNodeScheduling,
  pseudoNodeScheduling,
  zhCNNodeScheduling,
} from '../pages/node-scheduling/messages'
import nodeSchedulingCSS from '../pages/NodeSchedulingPage.css?raw'
import nodeLineGroupsRawCSS from '../pages/NodeLineGroupsPage.css?raw'
import { principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { defaultLookCSS } from '../test/defaultLookCSS'

// esc-ui-b 起线路组页按授权模块显示攻击自动升级区块，会多读一次 GET /v1/modules（与外壳共用缓存）。
// 本文件只核对线路组自身的请求序列。
vi.mock('../components/useGrantedModules', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../components/useGrantedModules')>()),
  useGrantedModules: () => [],
}))

const nodeLineGroupsCSS = defaultLookCSS(nodeLineGroupsRawCSS)

const groupID = '11111111-1111-4111-8111-111111111111'
const group: NodeLineGroup = {
  id: groupID,
  display_id: '7',
  tenant_scope_id: '22222222-2222-4222-8222-222222222222',
  revision: 7,
  name: '华东主线路',
  region: 'cn-east',
  resolved_value: 'line-east',
  ipv4_resolved_value: 'v4-line-east',
  l2_config_id: null,
  failover_mode: 'primary_offline',
  note: '华东线路备注',
  sort_order: 100,
  health_policy: {
    probe_interval_ms: 10_000,
    probe_timeout_ms: 3_000,
    failure_threshold: 3,
    recovery_threshold: 3,
    failure_debounce_ms: 0,
    recovery_debounce_ms: 0,
  },
  endpoints: [{
    id: '33333333-3333-4333-8333-333333333333',
    node_id: '44444444-4444-4444-8444-444444444444',
    address: '192.0.2.10',
    port: 443,
    region: 'cn-east',
    carrier: 'telecom',
    priority: 0,
    weight: 80,
    enabled: true,
    health: {
      status: 'healthy',
      consecutive_successes: 3,
      consecutive_failures: 0,
      last_sequence: 12,
      last_changed_at: '2026-07-28T08:00:00Z',
      row_revision: 4,
    },
  }],
  statistics: { node_count: 1, site_count: 3, forward_count: 1 },
  configuration_digest: 'a'.repeat(64),
  created_by_user_id: '55555555-5555-4555-8555-555555555555',
  created_at: '2026-07-28T08:00:00Z',
  sealed_at: '2026-07-28T08:00:01Z',
}

const l2Group: NodeLineGroup = {
  ...group,
  id: '66666666-6666-4666-8666-666666666666',
  display_id: '8',
  name: '华东 L2 配置',
  resolved_value: 'line-east-l2',
  ipv4_resolved_value: 'v4-line-east-l2',
  endpoints: [],
}

const l2Config: L2Config = {
  id: '66666666-6666-4666-8666-666666666666', display_id: '3', tenant_scope_id: group.tenant_scope_id, revision: 1,
  name: '华东 L2 配置', region: '', remark: '', mode: 'global', load_method: 'url_hash',
  created_at: '2026-10-25T00:00:00Z', updated_at: '2026-10-25T00:00:00Z',
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, reject, resolve }
}

function authenticate(
  permissions = ['node_scheduling.read', 'node_scheduling.manage'],
  roles = ['tenant_owner'],
  overrides: Parameters<typeof principal>[0] = {},
) {
  useSessionStore.setState({
    accessToken: 'access-token',
    expiresAt: Date.now() + 60_000,
    principal: principal({ permissions, roles, ...overrides }),
    status: 'authenticated',
  })
}

function QueryClientCapture({ onCapture }: { onCapture: (client: QueryClient) => void }) {
  onCapture(useQueryClient())
  return null
}

async function submitValidCreate(user: ReturnType<typeof userEvent.setup>, name: string) {
  await user.click(screen.getByRole('button', { name: '新增分组' }))
  const dialog = await screen.findByRole('dialog', { name: '新增线路分组' })
  expect(within(dialog).getByText('默认')).toBeInTheDocument()
  await user.type(within(dialog).getByLabelText('名称：'), name)
  await user.type(within(dialog).getByLabelText('解析值：'), 'line-north')
  await user.type(within(dialog).getByLabelText('备注：'), '华北线路备注')
  await user.click(within(dialog).getByRole('button', { name: '确定' }))
  return dialog
}

describe('NodeLineGroupsPage', () => {
  // live-site D2: on a fresh install every line group had the empty region,
  // so the create dialog offered only 「默认」 and packages (which require a
  // catalogued region) could never select a main line group.
  it('offers catalogued regions when creating a line group', async () => {
    const platformScopeID = '77777777-7777-4777-8777-777777777777'
    authenticate(['node_scheduling.read', 'node_scheduling.manage', 'regions.read'], ['platform_admin'], {
      scope_kind: 'platform', scope_id: platformScopeID, tenant_id: null,
    })
    useSessionStore.setState({ sessionEpoch: 1 })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/regions')) {
        return Promise.resolve(json({ count: 1, data: [{ id: '1', name: '默认区域', code: 'region-1', country_code: '', province_code: '', description: '', l2_check_port: 80,
          sort: 100, revision: 1, created_at: '2026-10-22T02:41:17Z', updated_at: '2026-10-22T02:41:17Z' }] }))
      }
      if (init?.method === 'POST') {
        const body = JSON.parse(String(init.body)) as NodeLineGroupSnapshotInput
        return Promise.resolve(json({ group: { ...group, ...body, tenant_scope_id: platformScopeID, revision: 1, endpoints: [] },
          replayed: false }, 201))
      }
      return Promise.resolve(json({ items: [] }))
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeLineGroupsPage />)
    await user.click(await screen.findByRole('button', { name: '新增分组' }))
    const dialog = await screen.findByRole('dialog', { name: '新增线路分组' })
    await user.click(within(dialog).getByRole('combobox', { name: /区域/ }))
    await user.click(await screen.findByTitle('默认区域'))
    await user.type(within(dialog).getByLabelText('名称：'), '测试线路')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1))
    const createCall = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')
    expect(JSON.parse(String(createCall?.[1]?.body))).toMatchObject({ region: '默认区域' })
  })

  // fix-fielderr-be: a 400 naming resolved_value keeps the dialog open and marks 解析值.
  it('marks a server-refused line group field in the open dialog', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'POST') {
        return Promise.resolve(json({ error: { code: 'node_scheduling_invalid_request', message: 'request is invalid',
          request_id: 'req-line', details: { field: 'resolved_value', reason: 'invalid_format' } } }, 400))
      }
      return Promise.resolve(json({ items: [] }))
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeLineGroupsPage />)
    await screen.findByRole('button', { name: '新增分组' })
    const dialog = await submitValidCreate(user, '华北')
    expect(await within(dialog).findByText('格式不正确')).toBeInTheDocument()
    expect(screen.getByRole('dialog', { name: '新增线路分组' })).toBeInTheDocument()
  })

  it('keeps the reference editor metadata-only and preserves the runtime snapshot on edit', async () => {
    authenticate()
    useSessionStore.setState({ sessionEpoch: 1 })
    const editableGroup = {
      ...group,
      l2_config_id: l2Group.id,
      failover_mode: 'online_less_than_backup_count' as const,
    }
    // L2回源配置 is an L2 topology configuration (/v1/l2-configs, migration
    // 497), never another line group: l2Group is listed as a line group only
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => Promise.resolve(
      init?.method === 'PUT'
        ? json({ group: { ...editableGroup, revision: 8 }, replayed: false })
        : String(input).startsWith('/v1/l2-configs')
          ? json({ items: [
            { ...l2Config, id: l2Group.id },
            { ...l2Config, id: '99999999-9999-4999-8999-999999999999', name: '华南 L2 配置', region: 'cn-south' },
          ] })
          : json({ items: [editableGroup, { ...l2Group, name: '另一条线路' }] }),
    ))
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    const editableRow = screen.getByText('华东主线路').closest('tr')!
    expect(await within(editableRow).findByText('华东 L2 配置')).toBeInTheDocument()
    await user.click(within(editableRow).getByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑线路分组' })
    expect(dialog).toHaveClass('node-line-groups-modal', 'node-line-groups-modal-edit')
    expect(within(dialog).queryByLabelText('区域：')).not.toBeInTheDocument()
    expect(within(dialog).getByLabelText('解析值：')).toHaveValue('line-east')
    expect(within(dialog).getByLabelText('IPv4解析值：')).toHaveValue('v4-line-east')
    expect(within(dialog).getByLabelText('备注：')).toHaveValue('华东线路备注')
    expect(within(dialog).getByLabelText('排序：')).toHaveValue('100')
    expect(dialog.querySelector('.ant-select-selection-item')).toHaveTextContent('华东 L2 配置')
    // 互相跳转: the field links to 节点管理 > L2配置; another region's
    // configuration and the other line group are not offered
    expect(within(dialog).getByRole('link', { name: '管理 L2配置' })).toHaveAttribute('href', '/node/l2-config')
    await user.click(within(dialog).getByRole('combobox', { name: 'L2回源配置：' }))
    const options = await screen.findByRole('listbox')
    expect(within(options.parentElement!).queryByTitle('华南 L2 配置')).not.toBeInTheDocument()
    expect(within(options.parentElement!).queryByTitle('另一条线路')).not.toBeInTheDocument()
    expect(within(options.parentElement!).getByTitle('华东 L2 配置')).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(within(dialog).getByRole('radio', { name: '在线IP数少于备用IP数时' })).toBeChecked()
    expect(within(dialog).queryByLabelText('L2 节点 ID')).not.toBeInTheDocument()
    expect(within(dialog).queryByLabelText('IP 地址')).not.toBeInTheDocument()
    expect(within(dialog).queryByLabelText('探测间隔（毫秒）')).not.toBeInTheDocument()
    expect(within(dialog).queryByRole('switch', { name: '高级设置' })).not.toBeInTheDocument()
    expect(Array.from(dialog.querySelectorAll('.ant-modal-footer .ant-btn')).map((button) => button.textContent?.trim()))
      .toEqual(['取消', '确定'])

    await user.clear(within(dialog).getByLabelText('备注：'))
    await user.type(within(dialog).getByLabelText('备注：'), '更新后的备注')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1))
    expect(JSON.parse(String(fetchSpy.mock.calls.find(([, init]) => init?.method === 'PUT')?.[1]?.body))).toMatchObject({
      region: 'cn-east',
      resolved_value: 'line-east',
      ipv4_resolved_value: 'v4-line-east',
      l2_config_id: l2Group.id,
      failover_mode: 'online_less_than_backup_count',
      note: '更新后的备注',
      sort_order: 100,
      health_policy: group.health_policy,
      endpoints: group.endpoints.map((endpoint) => ({
        id: endpoint.id,
        node_id: endpoint.node_id,
        address: endpoint.address,
        port: endpoint.port,
        region: endpoint.region,
        carrier: endpoint.carrier,
        priority: endpoint.priority,
        weight: endpoint.weight,
        enabled: endpoint.enabled,
      })),
    })
  })

  it('keeps the advanced endpoint editor for the L2 topology mode', async () => {
    renderWithProviders(
      <LineGroupSnapshotModal
        item={null}
        open
        pending={false}
        titleKey="titles.createTopology"
        onCancel={() => undefined}
        onSubmit={() => undefined}
      />,
    )

    const dialog = await screen.findByRole('dialog', { name: '新增 L2 配置' })
    expect(within(dialog).getByLabelText('L2 节点 ID')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('IP 地址')).toBeInTheDocument()
    expect(within(dialog).getByRole('switch', { name: '高级设置' })).toBeInTheDocument()
    expect(within(dialog).queryByLabelText('备注')).not.toBeInTheDocument()
  })

  it('ships the default region label in every node-scheduling locale bundle', () => {
    expect(zhCNNodeScheduling.values.defaultRegion).toBe('默认')
    expect(enUSNodeScheduling.values.defaultRegion).toBe('Default')
    expect((pseudoNodeScheduling.values as Record<string, string>).defaultRegion).toContain('默默认认')
  })

  it('does not query or expose writes without node_scheduling.read', async () => {
    authenticate([])
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<NodeLineGroupsPage />)

    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新增分组' })).not.toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('does not treat platform.admin as node-scheduling read authority', async () => {
    authenticate(['platform.admin'], ['platform_admin'], {
      scope_kind: 'platform',
      scope_id: 'platform',
      tenant_id: null,
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<NodeLineGroupsPage />)

    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新增分组' })).not.toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('lets a platform administrator list, create, and edit its own line groups without a target picker round trip', async () => {
    const platformScopeID = '77777777-7777-4777-8777-777777777777'
    const createdGroupID = '88888888-8888-4888-8888-888888888888'
    let items: NodeLineGroup[] = [{ ...group, tenant_scope_id: platformScopeID, name: '平台自有线路' }]
    authenticate(['node_scheduling.read', 'node_scheduling.manage'], ['platform_admin'], {
      scope_kind: 'platform', scope_id: platformScopeID, tenant_id: null,
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (init?.method === 'POST') {
        const body = JSON.parse(String(init.body)) as NodeLineGroupSnapshotInput
        const created: NodeLineGroup = {
          ...group,
          ...body,
          id: createdGroupID,
          display_id: '8',
          tenant_scope_id: platformScopeID,
          revision: 1,
          endpoints: [],
        }
        items = [...items, created]
        return Promise.resolve(json({ group: created, replayed: false }, 201))
      }
      if (init?.method === 'PUT') {
        const body = JSON.parse(String(init.body)) as NodeLineGroupSnapshotInput
        items = items.map((item) => item.id === groupID ? {
          ...item,
          ...body,
          revision: item.revision + 1,
          endpoints: item.endpoints.map((endpoint, index) => ({
            ...endpoint,
            ...body.endpoints[index],
          })),
        } : item)
        return Promise.resolve(json({ group: items.find((item) => item.id === groupID), replayed: false }))
      }
      expect(url).toContain(`target_scope_id=${platformScopeID}`)
      return Promise.resolve(json({ items }))
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)

    expect(await screen.findByText('平台自有线路')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增分组' })).toBeEnabled()
    expect(fetchSpy).toHaveBeenCalledTimes(1)

    await submitValidCreate(user, '平台新增线路')
    expect(await screen.findByText('平台新增线路')).toBeInTheDocument()
    const createCall = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')
    expect(String(createCall?.[0])).toBe('/v1/node-line-groups')
    expect(new Headers(createCall?.[1]?.headers).get('If-Match')).toBe('"0"')

    const originalRow = screen.getByText('平台自有线路').closest('tr')!
    await user.click(within(originalRow).getByRole('button', { name: '编辑' }))
    const editDialog = await screen.findByRole('dialog', { name: '编辑线路分组' })
    const name = within(editDialog).getByLabelText('名称：')
    await user.clear(name)
    await user.type(name, '平台线路已编辑')
    await user.click(within(editDialog).getByRole('button', { name: '确定' }))

    expect(await screen.findByText('平台线路已编辑')).toBeInTheDocument()
    const updateCall = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PUT')
    expect(String(updateCall?.[0])).toBe(`/v1/node-line-groups/${groupID}`)
    expect(new Headers(updateCall?.[1]?.headers).get('If-Match')).toBe('"7"')
  })

  it('supports platform self-scope single and batch deletion without exposing tenant targeting', async () => {
    const platformScopeID = '77777777-7777-4777-8777-777777777777'
    const second = { ...group, id: '88888888-8888-4888-8888-888888888888', display_id: '8', name: '平台线路二', revision: 8 }
    const third = { ...group, id: '99999999-9999-4999-8999-999999999998', display_id: '9', name: '平台线路三', revision: 9 }
    let items: NodeLineGroup[] = [{ ...group, tenant_scope_id: platformScopeID, name: '平台线路一' }, second, third]
    authenticate(['node_scheduling.read', 'node_scheduling.manage'], ['platform_admin'], {
      scope_kind: 'platform', scope_id: platformScopeID, tenant_id: null,
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (init?.method === 'DELETE') {
        const id = decodeURIComponent(url.split('/').pop() ?? '')
        items = items.filter((item) => item.id !== id)
        return Promise.resolve(new Response(null, { status: 204 }))
      }
      return Promise.resolve(json({ items }))
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('平台线路一')).toBeInTheDocument()

    // fix-feedbackui2: batch delete with nothing selected warns in place, no dialog.
    await user.click(document.querySelector<HTMLElement>('.node-line-delete-action')!)
    expect(await screen.findByText('请选择线路分组!', { selector: '.cdnca-inline-notice-warning .cdnca-inline-notice-text' })).toBeInTheDocument()
    expect(document.querySelector('.cdnca-feedback')).toBeNull()

    const firstRow = screen.getByText('平台线路一').closest('tr')!
    await user.click(within(firstRow).getByRole('button', { name: '删除线路分组' }))
    let deleteDialog = await screen.findByRole('dialog', { name: '删除确认' })
    expect(deleteDialog).toHaveTextContent('是否删除线路分组 id:7')
    expect(Array.from(deleteDialog.querySelectorAll('.ant-modal-footer .ant-btn')).map((button) => button.textContent?.trim()))
      .toEqual(['取消', '确定'])
    await user.click(within(deleteDialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'DELETE')).toHaveLength(1))
    expect(screen.queryByText('平台线路一')).not.toBeInTheDocument()

    const secondRow = await screen.findByText('平台线路二').then((element) => element.closest('tr')!)
    const thirdRow = screen.getByText('平台线路三').closest('tr')!
    await user.click(within(secondRow).getByRole('checkbox'))
    await user.click(within(thirdRow).getByRole('checkbox'))
    const bulkDelete = within(screen.getByRole('toolbar', { name: '线路分组操作' })).getByRole('button', { name: '删除' })
    expect(bulkDelete).toBeEnabled()
    await user.click(bulkDelete)
    deleteDialog = await screen.findByRole('dialog', { name: '删除确认' })
    expect(deleteDialog).toHaveTextContent('是否删除线路分组 id:8,9')
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'DELETE')).toHaveLength(1)
    expect(Array.from(deleteDialog.querySelectorAll('.ant-modal-footer .ant-btn')).map((button) => button.textContent?.trim()))
      .toEqual(['取消', '确定'])
    await user.click(within(deleteDialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'DELETE')).toHaveLength(3))
    expect(await screen.findByText('暂无线路分组')).toBeInTheDocument()

    const deleteCalls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'DELETE')
    expect(deleteCalls.map(([, init]) => new Headers(init?.headers).get('If-Match'))).toEqual(['"7"', '"8"', '"9"'])
    expect(deleteCalls.every(([, init]) => Boolean(new Headers(init?.headers).get('Idempotency-Key')))).toBe(true)

    expect(screen.queryByRole('button', { name: '读取租户' })).not.toBeInTheDocument()
    const listCalls = fetchSpy.mock.calls.filter(([, init]) => !init?.method)
    expect(listCalls.length).toBeGreaterThan(0)
    expect(listCalls.every(([input]) => String(input).includes(`target_scope_id=${platformScopeID}`))).toBe(true)
  })

  it('lets a platform administrator set and unset the platform default line group (fix-nopkg)', async () => {
    const platformScopeID = '77777777-7777-4777-8777-777777777777'
    let items: NodeLineGroup[] = [{ ...group, tenant_scope_id: platformScopeID, name: '平台线路一', is_platform_default: false }]
    authenticate(['node_scheduling.read', 'node_scheduling.manage'], ['platform_admin'], {
      scope_kind: 'platform', scope_id: platformScopeID, tenant_id: null,
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (init?.method === 'POST' && url.endsWith('/platform-default')) {
        const body = JSON.parse(String(init.body)) as { is_platform_default: boolean }
        items = items.map((item) => ({ ...item, is_platform_default: body.is_platform_default }))
        return Promise.resolve(json({ group: items[0] }))
      }
      return Promise.resolve(json({ items }))
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    const row = await screen.findByText('平台线路一').then((element) => element.closest('tr')!)
    expect(within(row).queryByTestId('line-group-platform-default')).not.toBeInTheDocument()
    await user.click(within(row).getByRole('button', { name: '设为平台默认' }))
    expect(await screen.findByTestId('line-group-platform-default')).toHaveTextContent('平台默认')
    const calls = fetchSpy.mock.calls.filter(([input, init]) => init?.method === 'POST' && String(input).endsWith('/platform-default'))
    expect(calls).toHaveLength(1)
    expect(String(calls[0][0])).toContain(`/v1/node-line-groups/${groupID}/platform-default`)
    expect(JSON.parse(String(calls[0][1]?.body))).toEqual({ is_platform_default: true })
    expect(new Headers(calls[0][1]?.headers).get('Idempotency-Key')).toBeTruthy()

    const updatedRow = screen.getByText('平台线路一').closest('tr')!
    await user.click(within(updatedRow).getByRole('button', { name: '取消平台默认' }))
    await waitFor(() => expect(screen.queryByTestId('line-group-platform-default')).not.toBeInTheDocument())
  })

  it('shows which address family is resolving to backup IPs and since when (fix-backupnotify)', async () => {
    authenticate(['node_scheduling.read', 'node_scheduling.manage'])
    useSessionStore.setState({ sessionEpoch: 1 })
    const active: NodeLineGroup = {
      ...group,
      backup_states: [
        { address_family: 4, state: 'backup_active', backup_addresses: ['192.0.2.20', '192.0.2.21'], changed_at: '2026-10-27T06:00:00Z' },
        { address_family: 6, state: 'normal', backup_addresses: [], changed_at: '2026-10-27T05:00:00Z' },
      ],
    }
    const normal: NodeLineGroup = {
      ...group, id: '99999999-9999-4999-8999-999999999999', display_id: '9', name: '华北线路',
      backup_states: [{ address_family: 4, state: 'normal', backup_addresses: [], changed_at: '2026-10-27T07:00:00Z' }],
    }
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(json({ items: [active, normal] })))
    const user = userEvent.setup()
    renderWithProviders(<NodeLineGroupsPage />)
    const row = await screen.findByText(group.name).then((element) => element.closest('tr')!)
    const tag = within(row).getByTestId('line-group-backup-active')
    expect(tag).toHaveTextContent('IPv4 备用 IP 中')
    expect(tag).toHaveAccessibleName(/IPv4 主 IP 不可用，正在解析备用 IP 192\.0\.2\.20、192\.0\.2\.21，启用于 2026\/10\/27 14:00:00/)
    await user.hover(tag)
    expect(await screen.findByRole('tooltip')).toHaveTextContent('启用于 2026/10/27 14:00:00')
    const normalRow = screen.getByText('华北线路').closest('tr')!
    expect(within(normalRow).queryByTestId('line-group-backup-active')).not.toBeInTheDocument()
  })

  it('accepts and rejects backup state shapes in the line group response (fix-backupnotify)', async () => {
    const { validateNodeLineGroupResponse } = await import('../api/nodeScheduling')
    const valid = { ...group, backup_states: [{ address_family: 6, state: 'backup_active', backup_addresses: ['2001:db8::20'], changed_at: '2026-10-27T06:00:00Z' }] }
    expect(validateNodeLineGroupResponse(valid).backup_states?.[0].address_family).toBe(6)
    for (const bad of [
      [{ address_family: 5, state: 'normal', backup_addresses: [], changed_at: '2026-10-27T06:00:00Z' }],
      [{ address_family: 4, state: 'failover', backup_addresses: [], changed_at: '2026-10-27T06:00:00Z' }],
      [{ address_family: 4, state: 'backup_active', backup_addresses: ['not-an-ip'], changed_at: '2026-10-27T06:00:00Z' }],
      [{ address_family: 4, state: 'normal', backup_addresses: [], changed_at: '2026-10-27T06:00:00Z', extra: true }],
    ]) expect(() => validateNodeLineGroupResponse({ ...group, backup_states: bad })).toThrow('Invalid line group response')
  })

  it('does not offer the platform default action to a tenant (fix-nopkg)', async () => {
    authenticate(['node_scheduling.read', 'node_scheduling.manage'])
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(json({ items: [group] })))
    renderWithProviders(<NodeLineGroupsPage />)
    const row = await screen.findByText(group.name).then((element) => element.closest('tr')!)
    expect(within(row).queryByRole('button', { name: '设为平台默认' })).not.toBeInTheDocument()
  })

  it.each([
    ['a tenant with no user ID', {
      scope_kind: 'tenant' as const,
      scope_id: '22222222-2222-4222-8222-222222222222',
      tenant_id: '22222222-2222-4222-8222-222222222222',
      user_id: '',
    }],
    ['a platform principal carrying a tenant ID', {
      scope_kind: 'platform' as const,
      scope_id: 'platform',
      tenant_id: '22222222-2222-4222-8222-222222222222',
    }],
    ['a platform principal with no scope ID', {
      scope_kind: 'platform' as const,
      scope_id: '',
      tenant_id: null,
    }],
  ])('fails closed with zero requests for %s', async (_caseName, overrides) => {
    authenticate(['node_scheduling.read', 'node_scheduling.manage'], ['tenant_owner'], overrides)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<NodeLineGroupsPage />)

    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('fails closed with zero requests for a zero session epoch', async () => {
    authenticate()
    useSessionStore.setState({ sessionEpoch: 0 })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<NodeLineGroupsPage />)

    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('keeps the table mounted while loading and for an empty fact set', async () => {
    authenticate()
    let resolveList!: (response: Response) => void
    vi.spyOn(globalThis, 'fetch').mockReturnValue(new Promise((resolve) => { resolveList = resolve }))

    renderWithProviders(<NodeLineGroupsPage />)

    const table = screen.getByTestId('node-line-groups-table')
    expect(table).toHaveClass('node-line-groups-table-scroll')
    expect(table.querySelector('.ant-table-content')).toBeInTheDocument()
    expect(table).toHaveAttribute('aria-busy', 'true')
    await act(async () => resolveList(json({ items: [] })))
    expect(await screen.findByText('暂无线路分组')).toBeInTheDocument()
    expect(table).toHaveAttribute('aria-busy', 'false')
  })

  it('uses one QueryClient without exposing cached facts or frozen writes across tenant sessions', async () => {
    const tenantA = '22222222-2222-4222-8222-222222222222'
    const tenantB = '66666666-6666-4666-8666-666666666666'
    const tenantAGroup = { ...group, tenant_scope_id: tenantA, name: '租户 A 线路' }
    const tenantBGroup = { ...group, tenant_scope_id: tenantB, name: '租户 B 线路' }
    authenticate(undefined, undefined, { user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' })
    useSessionStore.setState({ accessToken: 'tenant-a-token' })
    let queryClient!: QueryClient
    let resolveTenantB!: (response: Response) => void
    let tenantBRequested = false
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      const authorization = new Headers(init?.headers).get('Authorization')
      if (init?.method === 'PUT') {
        expect(authorization).toBe('Bearer tenant-a-token')
        return Promise.reject(new TypeError('connection reset'))
      }
      if (authorization === 'Bearer tenant-a-token') return Promise.resolve(json({ items: [tenantAGroup] }))
      if (authorization === 'Bearer tenant-b-token') {
        tenantBRequested = true
        return new Promise((resolve) => { resolveTenantB = resolve })
      }
      throw new Error(`unexpected authorization: ${authorization}`)
    })
    const user = userEvent.setup()

    renderWithProviders(<>
      <NodeLineGroupsPage />
      <QueryClientCapture onCapture={(client) => { queryClient = client }} />
    </>)
    expect(await screen.findByText('租户 A 线路')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '编辑' }))
    await user.click(within(await screen.findByRole('dialog', { name: '编辑线路分组' })).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    const tenantAQueryKeys = queryClient.getQueryCache().getAll().map((entry) => JSON.stringify(entry.queryKey))
    expect(tenantAQueryKeys.some((key) => key.includes(tenantA))).toBe(true)
    expect(tenantAQueryKeys.some((key) => key.includes('tenant-a-token'))).toBe(false)

    act(() => useSessionStore.setState({
      accessToken: 'tenant-b-token',
      expiresAt: Date.now() + 60_000,
      principal: principal({
        user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        scope_id: tenantB,
        tenant_id: tenantB,
        permissions: ['node_scheduling.read', 'node_scheduling.manage'],
        roles: ['tenant_owner'],
      }),
      status: 'authenticated',
    }))

    await waitFor(() => expect(tenantBRequested).toBe(true))
    expect(screen.queryByText('租户 A 线路')).not.toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()

    await act(async () => resolveTenantB(json({ items: [tenantBGroup] })))
    expect(await screen.findByText('租户 B 线路')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
    const queryKeys = queryClient.getQueryCache().getAll().map((entry) => JSON.stringify(entry.queryKey))
    expect(queryKeys.some((key) => key.includes(tenantB))).toBe(true)
    expect(queryKeys.some((key) => key.includes('tenant-b-token'))).toBe(false)
  })

  it('scopes query and mutation caches to the complete token-free session owner', async () => {
    const scopeID = '22222222-2222-4222-8222-222222222222'
    const tenantID = '2a2a2a2a-2a2a-4a2a-8a2a-2a2a2a2a2a2a'
    const userID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
    authenticate(undefined, undefined, { user_id: userID })
    useSessionStore.setState({ accessToken: 'cache-secret-token' })
    const sessionEpoch = useSessionStore.getState().sessionEpoch
    let queryClient!: QueryClient
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => init?.method === 'PUT'
      ? Promise.reject(new TypeError('connection reset'))
      : Promise.resolve(json({ items: [group] })))
    const user = userEvent.setup()

    renderWithProviders(<>
      <NodeLineGroupsPage />
      <QueryClientCapture onCapture={(client) => { queryClient = client }} />
    </>)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '编辑' }))
    await user.click(within(await screen.findByRole('dialog', { name: '编辑线路分组' })).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()

    const expectedQueryKey = [
      'node-line-groups', 'tenant', scopeID, tenantID, userID, sessionEpoch, 'tenant', '',
    ]
    expect(queryClient.getQueryCache().find({ queryKey: expectedQueryKey, exact: true })).toBeDefined()
    const mutations = queryClient.getMutationCache().getAll()
    expect(mutations).toHaveLength(1)
    expect(mutations[0].options.mutationKey).toEqual([
      'node-line-groups-write', 'tenant', scopeID, tenantID, userID, sessionEpoch, 'tenant', '',
    ])
    const cachedState = JSON.stringify({
      mutations: mutations.map((mutation) => ({ key: mutation.options.mutationKey, state: mutation.state })),
      queries: queryClient.getQueryCache().getAll().map((query) => ({ key: query.queryKey, state: query.state })),
    })
    expect(cachedState).not.toContain('cache-secret-token')
    expect(document.body.textContent).not.toContain('cache-secret-token')
  })

  it('retains the frozen original request across a same-principal token rotation', async () => {
    authenticate(undefined, undefined, { user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' })
    useSessionStore.setState({ accessToken: 'token-before-refresh' })
    let writes = 0
    const groups = Array.from({ length: 11 }, (_, index) => ({
      ...group,
      id: `${String(index + 1).padStart(8, '0')}-1111-4111-8111-111111111111`,
      name: `令牌轮换线路 ${index + 1}`,
    }))
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'PUT') {
        writes += 1
        return writes === 1
          ? Promise.reject(new TypeError('connection reset'))
          : Promise.resolve(json({ group: { ...group, name: '令牌轮换线路', revision: 8 }, replayed: true }))
      }
      return Promise.resolve(json({ items: groups }))
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('令牌轮换线路 1')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('令牌轮换线路 11')).toBeInTheDocument()
    await user.type(screen.getByLabelText('搜索当前列表'), '保留筛选草稿')
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑线路分组' })
    const name = within(dialog).getByLabelText('名称：')
    await user.clear(name)
    await user.type(name, '令牌轮换线路')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()

    act(() => useSessionStore.setState({
      accessToken: 'token-after-refresh',
      expiresAt: Date.now() + 60_000,
    }))

    expect(screen.getByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.getByLabelText('搜索当前列表')).toHaveValue('保留筛选草稿')
    expect(screen.getByText('2', { selector: '.node-scheduling-page-number' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增分组' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '编辑' })).toBeDisabled()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)

    await user.click(screen.getByRole('button', { name: '刷新并对账' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([input, init]) => !init?.method && !String(input).startsWith('/v1/l2-configs'))).toHaveLength(2))
    const listHeaders = new Headers(fetchSpy.mock.calls.filter(([input, init]) => !init?.method && !String(input).startsWith('/v1/l2-configs'))[1][1]?.headers)
    expect(listHeaders.get('Authorization')).toBe('Bearer token-after-refresh')
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('线路组新版本已保存')).toBeInTheDocument()
    const calls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')
    expect(calls).toHaveLength(2)
    expect(calls[0][1]?.body).toBe(calls[1][1]?.body)
    const firstHeaders = new Headers(calls[0][1]?.headers)
    const retryHeaders = new Headers(calls[1][1]?.headers)
    expect(firstHeaders.get('Authorization')).toBe('Bearer token-before-refresh')
    expect(retryHeaders.get('Authorization')).toBe('Bearer token-after-refresh')
    for (const name of ['If-Match', 'Idempotency-Key', 'X-Request-ID']) {
      expect(retryHeaders.get(name)).toBe(firstHeaders.get(name))
    }
    expect(firstHeaders.get('If-Match')).toBe('"7"')
    expect(firstHeaders.get('Idempotency-Key')).toBeTruthy()
    expect(firstHeaders.get('X-Request-ID')).toBe(firstHeaders.get('Idempotency-Key'))
  })

  it.each(['success', 'error'] as const)(
    'resets local state and ignores a delayed old-session write %s',
    async (settlement) => {
      const oldUserID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
      authenticate(undefined, undefined, { user_id: oldUserID })
      useSessionStore.setState({ accessToken: 'old-session-token' })
      const oldEpoch = useSessionStore.getState().sessionEpoch
      const pendingWrite = deferred<Response>()
      let queryClient!: QueryClient
      const groups = Array.from({ length: 11 }, (_, index) => ({
        ...group,
        id: `${String(index + 1).padStart(8, '0')}-1111-4111-8111-111111111111`,
        name: `旧会话线路 ${index + 1}`,
      }))
      vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
        const authorization = new Headers(init?.headers).get('Authorization')
        if (init?.method === 'PUT') return pendingWrite.promise
        if (authorization === 'Bearer old-session-token') return Promise.resolve(json({ items: groups }))
        if (authorization === 'Bearer new-session-token') return Promise.resolve(json({ items: [{ ...group, name: '新会话线路' }] }))
        throw new Error(`unexpected authorization: ${authorization}`)
      })
      const user = userEvent.setup()

      renderWithProviders(<>
        <NodeLineGroupsPage />
        <QueryClientCapture onCapture={(client) => { queryClient = client }} />
      </>)
      expect(await screen.findByText('旧会话线路 1')).toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: '下一页' }))
      await user.type(screen.getByLabelText('搜索当前列表'), '旧筛选')
      await user.click(screen.getByRole('button', { name: '编辑' }))
      const dialog = await screen.findByRole('dialog', { name: '编辑线路分组' })
      await user.click(within(dialog).getByRole('button', { name: '确定' }))

      act(() => useSessionStore.setState({
        accessToken: 'new-session-token',
        expiresAt: Date.now() + 60_000,
        sessionEpoch: oldEpoch + 1,
      }))

      expect(await screen.findByText('新会话线路')).toBeInTheDocument()
      expect(screen.getByLabelText('搜索当前列表')).toHaveValue('')
      expect(screen.getByText('1', { selector: '.node-scheduling-page-number' })).toBeInTheDocument()
      expect(screen.queryByRole('dialog', { name: '编辑线路分组' })).not.toBeInTheDocument()
      expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()

      await act(async () => {
        pendingWrite.resolve(settlement === 'success'
          ? json({ group: { ...group, name: '旧响应敏感线路', revision: 8 }, replayed: false })
          : json({ error: { code: 'node_scheduling_permission_denied', message: 'old private denial' } }, 403))
        await Promise.resolve()
        await Promise.resolve()
      })

      expect(screen.getByText('新会话线路')).toBeInTheDocument()
      expect(screen.queryByText('旧响应敏感线路')).not.toBeInTheDocument()
      expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
      expect(screen.queryByText('线路组新版本已保存')).not.toBeInTheDocument()
      expect(screen.queryByText('old private denial')).not.toBeInTheDocument()
      await waitFor(() => {
        const oldOwner = ['tenant', group.tenant_scope_id, group.tenant_scope_id, oldUserID, oldEpoch]
        const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
        const mutationKeys = queryClient.getMutationCache().getAll().map((mutation) => mutation.options.mutationKey ?? [])
        expect(queryKeys.some((key) => oldOwner.every((value, index) => key[index + 1] === value))).toBe(false)
        expect(mutationKeys.some((key) => oldOwner.every((value, index) => key[index + 1] === value))).toBe(false)
      })
    },
  )

  it.each(['success', 'forbidden'] as const)(
    'ignores a delayed old-owner list %s after the current session renders',
    async (settlement) => {
      const tenantA = '22222222-2222-4222-8222-222222222222'
      const tenantB = '66666666-6666-4666-8666-666666666666'
      authenticate(undefined, undefined, { user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' })
      useSessionStore.setState({ accessToken: 'old-list-token' })
      const oldEpoch = useSessionStore.getState().sessionEpoch
      const pendingList = deferred<Response>()
      let queryClient!: QueryClient
      vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
        const authorization = new Headers(init?.headers).get('Authorization')
        if (authorization === 'Bearer old-list-token') return pendingList.promise
        if (authorization === 'Bearer current-list-token') {
          return Promise.resolve(json({ items: [{ ...group, tenant_scope_id: tenantB, name: '当前租户线路' }] }))
        }
        throw new Error(`unexpected authorization: ${authorization}`)
      })

      renderWithProviders(<>
        <NodeLineGroupsPage />
        <QueryClientCapture onCapture={(client) => { queryClient = client }} />
      </>)
      await waitFor(() => expect(globalThis.fetch).toHaveBeenCalledTimes(1))

      act(() => useSessionStore.setState({
        accessToken: 'current-list-token',
        expiresAt: Date.now() + 60_000,
        principal: principal({
          user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
          scope_id: tenantB,
          tenant_id: tenantB,
          permissions: ['node_scheduling.read', 'node_scheduling.manage'],
          roles: ['tenant_owner'],
        }),
        sessionEpoch: oldEpoch + 1,
        status: 'authenticated',
      }))
      expect(await screen.findByText('当前租户线路')).toBeInTheDocument()

      await act(async () => {
        pendingList.resolve(settlement === 'success'
          ? json({ items: [{ ...group, tenant_scope_id: tenantA, name: '旧租户敏感线路' }] })
          : json({ error: { code: 'node_scheduling_permission_denied', message: 'old private list denial' } }, 403))
        await Promise.resolve()
        await Promise.resolve()
      })

      expect(screen.getByText('当前租户线路')).toBeInTheDocument()
      expect(screen.queryByText('旧租户敏感线路')).not.toBeInTheDocument()
      expect(screen.queryByText('无权查看节点调度配置')).not.toBeInTheDocument()
      const oldOwner = ['tenant', tenantA, tenantA, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', oldEpoch]
      const cachedQueries = queryClient.getQueryCache().getAll()
      expect(cachedQueries.some((query) => oldOwner.every((value, index) => query.queryKey[index + 1] === value))).toBe(false)
      expect(JSON.stringify(cachedQueries.map((query) => query.state.data))).not.toContain('旧租户敏感线路')
    },
  )

  it('keeps a current-owner list 403 terminal across a token refresh', async () => {
    authenticate(['node_scheduling.read'])
    useSessionStore.setState({ accessToken: 'denied-list-token' })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'node_scheduling_permission_denied', message: 'private list denial' },
    }, 403))

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()
    expect(screen.queryByText('private list denial')).not.toBeInTheDocument()

    act(() => useSessionStore.setState({
      accessToken: 'refreshed-denied-list-token',
      expiresAt: Date.now() + 60_000,
    }))
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(screen.getByText('无权查看节点调度配置')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('keeps a current-owner mutation 403 terminal across a token refresh', async () => {
    authenticate()
    useSessionStore.setState({ accessToken: 'denied-write-token' })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => Promise.resolve(
      init?.method === 'PUT'
        ? json({ error: { code: 'node_scheduling_permission_denied', message: 'private write denial' } }, 403)
        : json({ items: [group] }),
    ))
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '编辑' }))
    await user.click(within(await screen.findByRole('dialog', { name: '编辑线路分组' })).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('线路配置保存失败')).toBeInTheDocument()
    expect(screen.queryByText('private write denial')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()

    act(() => useSessionStore.setState({
      accessToken: 'refreshed-denied-write-token', expiresAt: Date.now() + 60_000,
    }))
    await act(async () => { await Promise.resolve() })

    expect(screen.getByText('线路配置保存失败')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
  })

  it('keeps an unknown request frozen but denies exact retry while live manage permission is absent', async () => {
    authenticate(undefined, undefined, { user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' })
    useSessionStore.setState({ accessToken: 'token-before-downgrade' })
    let writes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'PUT') {
        writes += 1
        return writes === 1
          ? Promise.reject(new TypeError('connection reset'))
          : Promise.resolve(json({ group: { ...group, revision: 8 }, replayed: true }))
      }
      return Promise.resolve(json({ items: [group] }))
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '编辑' }))
    await user.click(within(await screen.findByRole('dialog', { name: '编辑线路分组' })).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()

    const currentPrincipal = useSessionStore.getState().principal!
    act(() => useSessionStore.setState({
      accessToken: 'token-after-downgrade',
      principal: { ...currentPrincipal, permissions: ['node_scheduling.read'], roles: ['tenant_viewer'] },
    }))

    expect(screen.getByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    const retry = screen.getByRole('button', { name: '使用同一请求重试' })
    expect(retry).toBeDisabled()
    await user.click(retry)
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)

    act(() => useSessionStore.setState({
      accessToken: 'token-after-restore',
      principal: {
        ...currentPrincipal,
        permissions: ['node_scheduling.read', 'node_scheduling.manage'],
        roles: ['tenant_owner'],
      },
    }))

    expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('线路组新版本已保存')).toBeInTheDocument()
    const calls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')
    expect(calls).toHaveLength(2)
    expect(calls[0][1]?.body).toBe(calls[1][1]?.body)
    const firstHeaders = new Headers(calls[0][1]?.headers)
    const retryHeaders = new Headers(calls[1][1]?.headers)
    expect(firstHeaders.get('Authorization')).toBe('Bearer token-before-downgrade')
    expect(retryHeaders.get('Authorization')).toBe('Bearer token-after-restore')
    for (const name of ['If-Match', 'Idempotency-Key', 'X-Request-ID']) {
      expect(retryHeaders.get(name)).toBe(firstHeaders.get(name))
    }
    expect(firstHeaders.get('If-Match')).toBe('"7"')
    expect(firstHeaders.get('Idempotency-Key')).toBeTruthy()
    expect(firstHeaders.get('X-Request-ID')).toBe(firstHeaders.get('Idempotency-Key'))
  })

  it('keeps the page bounded while the complete table scrolls inside it', async () => {
    authenticate()
    useSessionStore.setState({ sessionEpoch: 1 })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [group] }))

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()

    const page = screen.getByRole('region', { name: '线路分组' })
    const outer = screen.getByTestId('node-line-groups-table')
    const inner = outer.querySelector('.ant-table-content')
    const actionHeader = within(outer).getByRole('columnheader', { name: '操作' })
    expect(page).toContainElement(outer)
    expect(outer).toHaveClass('node-line-groups-table-scroll')
    expect(outer.querySelectorAll('.ant-table-content')).toHaveLength(1)
    expect(inner).toHaveStyle({ overflowX: 'auto' })
    expect(actionHeader).not.toHaveClass('ant-table-cell-fix-right')

    const mobileCSS = nodeSchedulingCSS.slice(nodeSchedulingCSS.indexOf('@media (max-width: 767px)'))
    expect(mobileCSS).toMatch(/\.node-line-groups-table-scroll\s*\{\s*overflow-x:\s*clip;/)
    expect(mobileCSS).toMatch(/\.node-line-groups-table-scroll > \.ant-table-wrapper,[\s\S]*?max-width:\s*100%;/)
    expect(mobileCSS).toMatch(/\.node-scheduling-table-scroll \.ant-table-cell-fix-right\s*\{\s*position:\s*static !important;/)
    expect(mobileCSS).toMatch(/\.node-scheduling-alert \.ant-alert-action\s*\{[\s\S]*?flex:\s*0 0 100%;/)
    expect(mobileCSS).toMatch(/\.node-scheduling-alert \.ant-alert-action \.node-scheduling-toolbar\s*\{\s*margin:\s*8px 0 0;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-table-scroll\s*\{[\s\S]*?max-width:\s*100%;[\s\S]*?overflow-x:\s*hidden;/)
    expect(nodeLineGroupsCSS).toMatch(/\.ant-table-content\s*\{[\s\S]*?overflow-x:\s*auto !important;/)
    expect(nodeLineGroupsCSS).toMatch(/@media \(max-width: 767px\)[\s\S]*?\.node-line-groups-table-scroll\s*\{[\s\S]*?overflow-x:\s*hidden;/)
    expect(nodeLineGroupsCSS).not.toContain('min-width: 1050px;')
  })

  it('localizes list failures, hides server messages, and retries in the same table shell', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({
        error: { code: 'node_scheduling_unavailable', message: 'private scheduler database', request_id: 'req-list' },
      }, 503))
      .mockResolvedValueOnce(json({ items: [] }))
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)

    expect(await screen.findByText('节点调度配置加载失败')).toBeInTheDocument()
    expect(screen.getByText(/节点调度服务暂不可用/)).toBeInTheDocument()
    expect(screen.queryByText('private scheduler database')).not.toBeInTheDocument()
    expect(screen.getByTestId('node-line-groups-table')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无线路分组')).toBeInTheDocument()
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('filters and paginates the real returned line-group facts on the client', async () => {
    authenticate()
    const groups = Array.from({ length: 11 }, (_, index) => ({
      ...group,
      id: `${String(index + 1).padStart(8, '0')}-1111-4111-8111-111111111111`,
      name: index === 10 ? '华南备用线路' : `华东线路 ${index + 1}`,
    }))
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: groups }))
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)

    expect(await screen.findByText('华东线路 1')).toBeInTheDocument()
    expect(screen.queryByText('华南备用线路')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('华南备用线路')).toBeInTheDocument()

    await user.type(screen.getByLabelText('搜索当前列表'), '192.0.2.10')
    await user.click(screen.getByRole('button', { name: '查询' }))
    expect(screen.getByText('1', { selector: '.node-scheduling-page-number' })).toBeInTheDocument()
  })

  it('validates the full snapshot and retries an unknown edit with identical bytes and headers', async () => {
    authenticate()
    let writes = 0
    let reads = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'PUT') {
        writes += 1
        return writes === 1
          ? Promise.reject(new TypeError('connection reset'))
          : Promise.resolve(json({ group: { ...group, name: '华东主线路新版', revision: 8 }, replayed: true }))
      }
      reads += 1
      if (reads === 2) return Promise.reject(new TypeError('reconcile unavailable'))
      return Promise.resolve(json({ items: [group] }))
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '新增分组' }))
    const createDialog = await screen.findByRole('dialog', { name: '新增线路分组' })
    const createName = within(createDialog).getByLabelText('名称：')
    await user.type(createName, '   ')
    await user.click(within(createDialog).getByRole('button', { name: '确定' }))
    expect(await within(createName.closest('.ant-form-item')!).findByText('名称长度必须为 1 到 128 个字符')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0)
    await user.click(within(createDialog).getByRole('button', { name: '取消' }))

    await user.click(screen.getByRole('button', { name: '编辑' }))
    const editDialog = await screen.findByRole('dialog', { name: '编辑线路分组' })
    const name = within(editDialog).getByLabelText('名称：')
    await user.clear(name)
    await user.type(name, '华东主线路新版')
    await user.click(within(editDialog).getByRole('button', { name: '确定' }))

    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增分组' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '刷新并对账' }))
    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增分组' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('线路组新版本已保存')).toBeInTheDocument()

    const calls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')
    expect(calls).toHaveLength(2)
    expect(calls[0][1]?.body).toBe(calls[1][1]?.body)
    expect(calls[0][1]?.headers).toEqual(calls[1][1]?.headers)
    expect(calls[0][1]?.headers).toEqual(expect.objectContaining({
      'If-Match': '"7"',
      'Idempotency-Key': expect.any(String),
      'X-Request-ID': expect.any(String),
    }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => !init?.method).length).toBeGreaterThan(1))
  })

  it.each([
    ['an uppercase resolved value', '解析值：', 'Line-North', '解析值必须留空或使用 1 到 63 位小写字母、数字和连字符，且首尾不能为连字符'],
    ['an overlong resolved value', '解析值：', 'a'.repeat(64), '解析值必须留空或使用 1 到 63 位小写字母、数字和连字符，且首尾不能为连字符'],
    ['an overlong note', '备注：', '备'.repeat(513), '备注不能超过 512 个字符且不能包含控制字符'],
    ['a note containing a control character', '备注：', '备注\u0007', '备注不能超过 512 个字符且不能包含控制字符'],
    ['a zero sort order', '排序：', '0', '排序必须为 1 到 2147483647'],
    ['a sort order above int32', '排序：', '2147483648', '排序必须为 1 到 2147483647'],
  ])('rejects %s before submission', async (_caseName, fieldLabel, value, errorMessage) => {
    authenticate()
    useSessionStore.setState({ sessionEpoch: 1 })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [group] }))
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑线路分组' })
    const field = within(dialog).getByLabelText(fieldLabel)
    if (fieldLabel === '排序：') {
      await user.clear(field)
      await user.type(field, value)
      fireEvent.blur(field)
    } else {
      fireEvent.change(field, { target: { value } })
    }
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    expect(await within(field.closest('.ant-form-item')!).findByText(errorMessage)).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(0)
  })

  it('creates an empty line group through the scheduling API with revision zero metadata', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => Promise.resolve(
      init?.method === 'POST'
        ? json({ group: { ...group, name: '华北新线路', revision: 1 }, replayed: false })
        : json({ items: [group] }),
    ))
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    await submitValidCreate(user, '华北新线路')

    expect(await screen.findByText('线路组已创建')).toBeInTheDocument()
    const calls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')
    expect(calls).toHaveLength(1)
    expect(JSON.parse(String(calls[0][1]?.body))).toMatchObject({
      name: '华北新线路',
      region: '',
      resolved_value: 'line-north',
      ipv4_resolved_value: '',
      l2_config_id: null,
      failover_mode: 'primary_offline',
      note: '华北线路备注',
      sort_order: 100,
      health_policy: {
        probe_interval_ms: 10_000,
        probe_timeout_ms: 3_000,
        failure_threshold: 3,
        recovery_threshold: 3,
        failure_debounce_ms: 0,
        recovery_debounce_ms: 0,
      },
      endpoints: [],
    })
    const headers = new Headers(calls[0][1]?.headers)
    expect(headers.get('Authorization')).toBe('Bearer access-token')
    expect(headers.get('If-Match')).toBe('"0"')
    expect(headers.get('Idempotency-Key')).toBeTruthy()
    expect(headers.get('X-Request-ID')).toBe(headers.get('Idempotency-Key'))
  })

  it('tells what to do next after creating an empty line group, and not after one with IPs (UX-LG-EMPTY-01)', async () => {
    authenticate()
    useSessionStore.setState({ sessionEpoch: 1 })
    const created = { ...group, id: '12121212-1212-4121-8121-121212121212', name: '华北新线路', revision: 1, endpoints: [] }
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => Promise.resolve(
      init?.method === 'POST' ? json({ group: created, replayed: false }) : json({ items: [group] }),
    ))
    const user = userEvent.setup()
    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    expect(screen.queryByTestId('node-line-groups-empty-next')).not.toBeInTheDocument()
    await submitValidCreate(user, '华北新线路')
    const hint = await screen.findByTestId('node-line-groups-empty-next')
    expect(hint).toHaveTextContent('线路组「华北新线路」已创建，还没有节点 IP')
    expect(hint).toHaveTextContent('下一步：点「配置解析」添加节点 IP')
    // 社区版没有攻击自动升级，不提等级与授权。
    expect(hint).not.toHaveTextContent('线路组等级与授权')
    expect(within(hint).getByRole('button', { name: '配置解析' })).toBeInTheDocument()
  })

  it('shows a localized deterministic create failure and releases the create loading state', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => Promise.resolve(
      init?.method === 'POST'
        ? json({
          error: {
            code: 'node_scheduling_invalid_request',
            message: 'private create topology detail',
            request_id: 'req-create-400',
          },
        }, 400)
        : json({ items: [group] }),
    ))
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    await submitValidCreate(user, '华北失败线路')

    expect(await screen.findByText('线路配置保存失败')).toBeInTheDocument()
    expect(screen.getByText(/请求字段、拓扑或前置条件无效/)).toBeInTheDocument()
    expect(screen.queryByText('private create topology detail')).not.toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '新增线路分组' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增分组' })).toBeEnabled()
    const calls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')
    expect(calls).toHaveLength(1)
    expect(new Headers(calls[0][1]?.headers).get('If-Match')).toBe('"0"')
  })

  it('freezes an unknown create and retries the exact POST with the same zero revision precondition', async () => {
    authenticate()
    useSessionStore.setState({ accessToken: 'create-token-before-refresh' })
    let writes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'POST') {
        writes += 1
        return writes === 1
          ? Promise.reject(new TypeError('connection reset'))
          : Promise.resolve(json({ group: { ...group, name: '华北待确认线路', revision: 1 }, replayed: true }))
      }
      return Promise.resolve(json({ items: [group] }))
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    await submitValidCreate(user, '华北待确认线路')

    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    const add = screen.getByRole('button', { name: '新增分组' })
    expect(add).toBeDisabled()
    expect(screen.getByRole('button', { name: '编辑' })).toBeDisabled()
    await user.click(add)
    expect(screen.queryByRole('dialog', { name: '新增线路分组' })).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1)

    act(() => useSessionStore.setState({ accessToken: 'create-token-after-refresh' }))
    expect(screen.getByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('线路组已创建')).toBeInTheDocument()

    const calls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')
    expect(calls).toHaveLength(2)
    expect(calls[0][1]?.body).toBe(calls[1][1]?.body)
    const firstHeaders = new Headers(calls[0][1]?.headers)
    const retryHeaders = new Headers(calls[1][1]?.headers)
    expect(firstHeaders.get('Authorization')).toBe('Bearer create-token-before-refresh')
    expect(retryHeaders.get('Authorization')).toBe('Bearer create-token-after-refresh')
    for (const name of ['Idempotency-Key', 'X-Request-ID']) {
      expect(retryHeaders.get(name)).toBe(firstHeaders.get(name))
    }
    expect(firstHeaders.get('If-Match')).toBe('"0"')
    expect(retryHeaders.get('If-Match')).toBe('"0"')
    expect(firstHeaders.get('Idempotency-Key')).toBeTruthy()
    expect(firstHeaders.get('X-Request-ID')).toBe(firstHeaders.get('Idempotency-Key'))
  })

  it('keeps an old-revision unknown attempt frozen after both failed and successful list reconciliation', async () => {
    authenticate()
    let reads = 0
    let writes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'PUT') {
        writes += 1
        return writes === 1
          ? Promise.reject(new TypeError('connection reset'))
          : Promise.resolve(json({ group: { ...group, revision: 8 }, replayed: true }))
      }
      reads += 1
      return reads === 2
        ? Promise.reject(new TypeError('reconcile unavailable'))
        : Promise.resolve(json({ items: [group] }))
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑线路分组' })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '刷新并对账' }))
    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增分组' })).toBeDisabled()

    await user.click(screen.getByRole('button', { name: '刷新并对账' }))
    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增分组' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeEnabled()
    await waitFor(() => expect(screen.getByText('刷新并对账').closest('button')).not.toHaveClass('ant-btn-loading'))
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)

    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('线路组新版本已保存')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(2)
  })

  it('settles a first successful old-revision reconciliation after an HTTP 500 write outcome', async () => {
    authenticate()
    let writes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'PUT') {
        writes += 1
        return writes === 1
          ? Promise.resolve(json({ error: { code: 'node_scheduling_unavailable', message: 'unknown write' } }, 500))
          : Promise.resolve(json({ group: { ...group, revision: 8 }, replayed: true }))
      }
      return Promise.resolve(json({ items: [group] }))
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑线路分组' })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('操作结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '刷新并对账' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([input, init]) => !init?.method && !String(input).startsWith('/v1/l2-configs'))).toHaveLength(2))
    expect(screen.getByText('刷新并对账').closest('button')).not.toHaveClass('ant-btn-loading')
    expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '新增分组' })).toBeDisabled()
  })

  it.each([
    [400, 'node_scheduling_invalid_request', '请求字段、拓扑或前置条件无效'],
    [403, 'node_scheduling_permission_denied', '当前账号没有执行此操作的权限'],
    [409, 'node_scheduling_name_conflict', '线路组名称已存在'],
    [409, 'node_scheduling_reference_conflict', '线路组正被其他活动配置引用，请先解除引用'],
    [412, 'node_scheduling_revision_conflict', '线路组已被其他操作修改，请刷新后重试'],
    [500, 'node_scheduling_invalid_request', '请求字段、拓扑或前置条件无效'],
  ])('shows a localized deterministic write failure for HTTP %i', async (status, code, localizedMessage) => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => Promise.resolve(
      init?.method === 'PUT'
        ? json({ error: { code, message: 'private control-plane detail', request_id: `req-${status}` } }, status)
        : json({ items: [group] }),
    ))
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑线路分组' })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    expect(await screen.findByText('线路配置保存失败')).toBeInTheDocument()
    expect(screen.getByText(new RegExp(localizedMessage))).toBeInTheDocument()
    expect(screen.queryByText('private control-plane detail')).not.toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '编辑线路分组' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增分组' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '编辑' })).toBeEnabled()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
  })

  it.each([
    ['tenant_owner', ['node_scheduling.read', 'node_scheduling.manage'], true],
    ['tenant_admin', ['node_scheduling.read', 'node_scheduling.manage'], true],
    ['tenant_viewer', ['node_scheduling.read'], false],
    ['tenant_member', ['node_scheduling.read'], false],
  ])('uses live permissions for %s write controls', async (role, permissions, canWrite) => {
    authenticate(permissions, [role])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [group] }))

    renderWithProviders(<NodeLineGroupsPage />)

    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    if (canWrite) {
      expect(screen.getByRole('button', { name: '新增分组' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: '编辑' })).toBeInTheDocument()
    } else {
      expect(screen.queryByRole('button', { name: '新增分组' })).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: '编辑' })).not.toBeInTheDocument()
    }
  })

  it.each([
    ['U+FEFF', '\ufeff'],
    ['boundary Unicode White_Space', '\u00a0华东主线路\u3000'],
  ])('preserves the original control-free name for %s', async (_caseName, submittedName) => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => Promise.resolve(
      init?.method === 'PUT'
        ? json({ group: { ...group, name: submittedName, revision: 8 }, replayed: false })
        : json({ items: [group] }),
    ))
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑线路分组' })
    fireEvent.change(within(dialog).getByLabelText('名称：'), { target: { value: submittedName } })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1))
    const call = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PUT')
    expect(JSON.parse(String(call?.[1]?.body)).name).toBe(submittedName)
  })

  it('rejects control U+0085 in a line-group label before submission', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [group] }))
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑线路分组' })
    const name = within(dialog).getByLabelText('名称：')
    fireEvent.change(name, { target: { value: '\u0085' } })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    expect(await within(name.closest('.ant-form-item')!).findByText('名称长度必须为 1 到 128 个字符')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(0)
  })

  it('keeps the observed compact toolbar and table geometry contract', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [group] }))

    renderWithProviders(<NodeLineGroupsPage />)

    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    const actionToolbar = screen.getByRole('toolbar', { name: '线路分组操作' })
    const filterToolbar = screen.getByRole('search', { name: '线路分组筛选' })
    expect(actionToolbar).toContainElement(screen.getByRole('button', { name: '新增分组' }))
    expect(actionToolbar).toContainElement(screen.getByRole('button', { name: '删除' }))
    expect(screen.queryByRole('button', { name: '读取租户' })).not.toBeInTheDocument()
    const searchInput = screen.getByPlaceholderText('填名称或解析值搜索')
    const searchButton = screen.getByRole('button', { name: '查询' })
    expect(filterToolbar).toContainElement(screen.getByRole('combobox', { name: '区域' }))
    expect(filterToolbar).toHaveTextContent('所有区域')
    expect(filterToolbar.querySelector('.ant-select-arrow .node-line-reference-icon-down')).toBeInTheDocument()
    expect(filterToolbar).toContainElement(searchInput)
    expect(searchInput.closest('.ant-input-affix-wrapper')).toContainElement(searchButton)
    expect(screen.getByRole('button', { name: '清除' })).toBeInTheDocument()
    const addButton = screen.getByRole('button', { name: '新增分组' })
    const deleteButton = screen.getByRole('button', { name: '删除' })
    expect(addButton).toHaveTextContent('新增分组')
    expect(addButton).toHaveClass('ant-btn-primary', 'node-line-primary-action')
    expect(addButton.querySelector('.node-line-reference-icon-add')).toBeInTheDocument()
    expect(deleteButton).toHaveClass('ant-btn-default', 'ant-btn-dangerous', 'node-line-delete-action')
    expect(deleteButton).not.toHaveClass('ant-btn-primary')
    expect(deleteButton.querySelector('.node-line-reference-icon-trash')).toBeInTheDocument()
    expect(deleteButton).toBeEnabled()
    fireEvent.click(deleteButton)
    expect(await screen.findByText('请选择线路分组!')).toBeInTheDocument()

    const table = screen.getByRole('table')
    expect(within(table).getAllByRole('columnheader').map((cell) => cell.textContent?.trim()))
      .toEqual(['', 'ID', '名称', '区域', '解析值', '统计', 'L2回源配置', '排序', '操作'])
    expect(within(table).getByText('7')).toHaveAttribute('title', groupID)
    expect(within(table).getByText('line-east（IPv4: v4-line-east）')).toBeInTheDocument()
    expect(within(table).queryByText('192.0.2.10:443')).not.toBeInTheDocument()
    expect(within(table).getByText('节点数(1个) 网站数(3个) 转发数(1个)')).toBeInTheDocument()
    expect(within(table).getByText('100')).toBeInTheDocument()
    expect(within(table).getByRole('button', { name: '配置解析' })).toBeInTheDocument()
    expect(within(table).getByRole('button', { name: '编辑' })).toBeInTheDocument()
    expect(within(table).getByRole('button', { name: '删除线路分组' })).toBeEnabled()
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false)

    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-filter-toolbar\s*\{[\s\S]*?display:\s*grid;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-page \.node-scheduling-toolbar-actions,[\s\S]*?\.node-line-groups-page \.node-scheduling-toolbar-filters\s*\{[\s\S]*?display:\s*flex;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-page \.node-line-search\s*\{[\s\S]*?display:\s*block;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-page > h1\s*\{[\s\S]*?position:\s*absolute;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-page \.ant-table-thead > tr > th\s*\{[\s\S]*?padding:\s*8px 12px !important;[\s\S]*?font-weight:\s*600;/)
    expect(nodeLineGroupsCSS).toContain('padding: 18px 20px 20px;')
    expect(nodeLineGroupsCSS).toContain('border-radius: 10px;')
    expect(nodeLineGroupsCSS).toContain('0 1px 3px rgb(15 23 42 / 4%), 0 12px 28px rgb(15 23 42 / 6%)')
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-filter-toolbar\s*\{[\s\S]*?gap:\s*10px;[\s\S]*?margin-bottom:\s*12px;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-primary-action\s*\{[\s\S]*?width:\s*106px;[\s\S]*?min-width:\s*106px;[\s\S]*?padding-inline:\s*15px !important;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-delete-action\s*\{[\s\S]*?width:\s*92px;[\s\S]*?min-width:\s*92px;[\s\S]*?padding-inline:\s*15px !important;/)
    expect(nodeLineGroupsCSS).not.toMatch(/\.node-line-delete-action[^{]*\{[^}]*background/)
    expect(nodeLineGroupsCSS).toContain('margin-top: 16px;')
    expect(nodeLineGroupsCSS).toContain('margin: 24px !important;')
    expect(nodeLineGroupsCSS).toContain('max-width: calc(100vw - 32px);')
    expect(nodeLineGroupsCSS).toContain('.node-line-groups-modal .ant-modal-content')
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-modal \.ant-modal-content\s*\{[\s\S]*?padding:\s*0;[\s\S]*?border-radius:\s*6px;[\s\S]*?box-shadow:\s*0 4px 12px rgb\(0 0 0 \/ 15%\);/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-modal \.ant-modal-body\s*\{[\s\S]*?padding:\s*22px 24px 8px;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-modal \.ant-form-item-label\s*\{[\s\S]*?flex:\s*0 0 100px;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-modal \.ant-form-item-control\s*\{[\s\S]*?max-width:\s*372px;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-modal \.ant-modal-footer\s*\{[\s\S]*?padding:\s*12px 24px 18px;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-group-confirm\s*\{[\s\S]*?width:\s*78px;[\s\S]*?height:\s*32px;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-group-cancel\s*\{[\s\S]*?width:\s*60px;[\s\S]*?height:\s*32px;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-page \.ant-table-tbody > tr > td\s*\{[\s\S]*?height:\s*48px;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-page \.ant-table-placeholder > td\s*\{[\s\S]*?height:\s*48px;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-page \.node-line-group-statistics\s*\{[\s\S]*?display:\s*block;[\s\S]*?line-height:\s*48px;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-page \.node-line-group-actions \.ant-btn\s*\{[\s\S]*?border:\s*0;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-page \.node-scheduling-alert \.ant-alert-message\s*\{[\s\S]*?font-size:\s*14px;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-groups-page \.ant-select-arrow\s*\{[\s\S]*?inset-block-start:\s*50% !important;[\s\S]*?margin:\s*0 !important;[\s\S]*?transform:\s*translateY\(-50%\) !important;/)
    expect(nodeLineGroupsCSS).toMatch(/\.node-line-clear\s*\{[\s\S]*?width:\s*34px;[\s\S]*?color:\s*var\(--cdnca-color-primary\);/)
    const mobileLineGroupsCSS = nodeLineGroupsCSS.slice(nodeLineGroupsCSS.indexOf('@media (max-width: 767px)'))
    expect(mobileLineGroupsCSS).toMatch(/\.node-scheduling-toolbar-filters\s*\{[\s\S]*?flex-direction:\s*column;/)
    expect(mobileLineGroupsCSS).toMatch(/\.node-line-groups-region\s*\{[\s\S]*?width:\s*190px !important;[\s\S]*?flex:\s*0 0 32px;/)
    expect(mobileLineGroupsCSS).toMatch(/\.node-line-search\s*\{[\s\S]*?width:\s*197px;[\s\S]*?flex:\s*0 0 32px;/)
    expect(mobileLineGroupsCSS).not.toMatch(/\.node-line-group-col-addresses,[\s\S]*?\.node-line-group-col-sort\s*\{\s*display:\s*none;/)
    expect(mobileLineGroupsCSS).toMatch(/\.node-line-groups-table-scroll > \.ant-table-wrapper\s*\{[\s\S]*?width:\s*100%;[\s\S]*?max-width:\s*100%;/)
    // fix-dblscroll：表格宽度只来自 scroll.x，CSS 不再把 .ant-table 撑到 1050px。
    expect(mobileLineGroupsCSS).not.toMatch(/\.node-line-groups-table-scroll \.ant-table\s*\{[\s\S]*?width:\s*1050px;/)
  })

  it('clears the submitted and draft filters and keeps the region and page-size selects interactive', async () => {
    authenticate()
    const secondGroup: NodeLineGroup = {
      ...group,
      id: '77777777-7777-4777-8777-777777777777',
      display_id: '8',
      name: '华北备用线路',
      region: 'cn-north',
      resolved_value: 'line-north',
      ipv4_resolved_value: undefined,
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [group, secondGroup] }))
    const user = userEvent.setup()

    renderWithProviders(<NodeLineGroupsPage />)
    expect(await screen.findByText('华东主线路')).toBeInTheDocument()
    expect(screen.getByText('华北备用线路')).toBeInTheDocument()

    await user.click(screen.getByRole('combobox', { name: '区域' }))
    await user.click(await screen.findByText('cn-north', { selector: '.ant-select-item-option-content' }))
    expect(screen.queryByText('华东主线路')).not.toBeInTheDocument()
    expect(screen.getByText('华北备用线路')).toBeInTheDocument()

    await user.type(screen.getByLabelText('搜索当前列表'), '不存在')
    await user.click(screen.getByRole('button', { name: '查询' }))
    expect(await screen.findByText('当前列表无匹配线路分组')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '清除' }))
    expect(screen.getByLabelText('搜索当前列表')).toHaveValue('')
    expect(screen.getByRole('combobox', { name: '区域' }).closest('.ant-select')).toHaveTextContent('所有区域')
    expect(screen.getByText('华东主线路')).toBeInTheDocument()
    expect(screen.getByText('华北备用线路')).toBeInTheDocument()

    await user.click(screen.getByRole('combobox', { name: '每页数量' }))
    await user.click(await screen.findByText('20 条/页', { selector: '.ant-select-item-option-content' }))
    expect(screen.getByRole('combobox', { name: '每页数量' }).closest('.ant-select')).toHaveTextContent('20 条/页')
  })
})
