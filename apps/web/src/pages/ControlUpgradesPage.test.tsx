import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { ControlUpgradeRolloutDetail, ControlUpgradeRolloutSummary, MaintenanceUpgradeStatus, MaintenanceUpgradeNode } from '../api/controlUpgrades'
import { nativeControlUpgradesApi } from '../api/controlUpgrades.native'
import { nativePublicationFixture, nativeStatusFixture } from '../api/controlUpgrades.native.fixtures'
import { useSessionStore } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import { enUS, zhCN } from '../i18n/resources'
import { authResponse, nodeManagementSettingsFixture, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import ControlUpgradesPage from './ControlUpgradesPage'

// antd 在 jsdom 下所有弹窗共用 aria-labelledby="test-id"，常驻的反馈弹窗（useFeedback/OutcomeUnknown）
// 挂在前面时会抢走其他弹窗的可访问名；按可见标题找当前可见的弹窗/抽屉。
const dialogsNamed = (name: string | RegExp) => screen.queryAllByRole('dialog').filter((node) => {
  const title = node.querySelector('.ant-modal-title, .ant-modal-confirm-title, .ant-drawer-title')?.textContent?.trim() ?? ''
  return typeof name === 'string' ? title === name : name.test(title)
})
const queryDialog = (name: string | RegExp) => {
  const found = dialogsNamed(name)
  if (found.length > 1) throw new Error(`multiple dialogs named ${String(name)}`)
  return found[0] ?? null
}
const getDialog = (name: string | RegExp) => {
  const found = queryDialog(name)
  if (!found) throw new Error(`no dialog named ${String(name)}`)
  return found
}
const findDialog = (name: string | RegExp, options?: { timeout?: number }) => waitFor(() => getDialog(name), options)

const ids = {
  plan: '00000000-0000-4000-8000-000000000010',
  installation: '00000000-0000-4000-8000-000000000011',
  parentGrant: '00000000-0000-4000-8000-000000000012',
  artifact: '00000000-0000-4000-8000-000000000013',
  rollbackArtifact: '00000000-0000-4000-8000-000000000014',
  nodeA: '00000000-0000-4000-8000-000000000021',
  nodeB: '00000000-0000-4000-8000-000000000022',
  nodeC: '00000000-0000-4000-8000-000000000023',
  batch: '00000000-0000-4000-8000-000000000031',
  status: '00000000-0000-4000-8000-000000000051',
  command: '00000000-0000-4000-8000-000000000061',
}

function authenticate(permissions = [
  'control.upgrades.read',
  'control.upgrades.manage',
  'control.upgrades.check',
]) {
  const actor = principal({
    scope_kind: 'platform',
    tenant_id: null,
    roles: ['platform_owner'],
    permissions,
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function rollout(overrides: Partial<ControlUpgradeRolloutSummary> = {}): ControlUpgradeRolloutSummary {
  return {
    id: ids.plan,
    schema_version: 2,
    installation_id: ids.installation,
    component: 'edge-agent',
    current_version: '1.4.0',
    target_version: '1.5.0',
    state: 'queued',
    completion: '',
    revision: '1',
    automatic_rollback: true,
    parent_grant_id: ids.parentGrant,
    artifact_id: ids.artifact,
    artifact_sha256: 'A'.repeat(43),
    artifact_size_bytes: 1024,
    rollback_artifact_id: ids.rollbackArtifact,
    rollback_artifact_sha256: `${'B'.repeat(42)}E`,
    rollback_artifact_size_bytes: 900,
    active_batch: -1,
    total_nodes: 2,
    pending_nodes: 2,
    dispatched_nodes: 0,
    healthy_nodes: 0,
    failed_nodes: 0,
    rolled_back_nodes: 0,
    blockers: [],
    created_at: '2026-08-05T01:00:00Z',
    updated_at: '2026-08-05T01:00:00Z',
    ...overrides,
  }
}

// The node section reads the 10 most recent rollout plans to project progress.
// The maintenance tab stays mounted once opened (P0-b A04), so its backup
// panel reads control-backup even in tests about other tabs.
const emptyBackupStatus = { data: { keys_ready: false, agent_installed: false, migration_ready: false, freeze: null, bundles: [], runs: [], settings: null, revision: 0 } }

function listResponse(...items: ControlUpgradeRolloutSummary[]) {
  const data = items.map((item) => Object.fromEntries(Object.entries(item)
    .filter(([key]) => !['batches', 'nodes', 'events', 'status_receipts'].includes(key))) as unknown as ControlUpgradeRolloutSummary)
  return { data, page: 1, page_size: 10, total: data.length }
}

function rolloutDetail(nodeIDs: string[], overrides: Partial<ControlUpgradeRolloutDetail> = {}): ControlUpgradeRolloutDetail {
  const nodes = overrides.nodes ?? nodeIDs.map((id) => ({ node_id: id, agent_version: '2.0.0', protocol_version: 1, state: 'pending' as const, dispatch_revision: '0' }))
  const count = (state: string) => nodes.filter((node) => node.state === state).length
  return {
    ...rollout({ total_nodes: nodes.length, pending_nodes: count('pending'), dispatched_nodes: count('dispatched'),
      healthy_nodes: count('healthy'), failed_nodes: count('failed'), rolled_back_nodes: count('rolled_back'),
      current_version: '2.0.0', target_version: '2.1.0' }),
    batches: [{ id: ids.batch, group_id: 'canary', canary: true, node_ids: [...nodeIDs].sort() }],
    nodes, events: [], status_receipts: [],
    ...overrides,
  }
}

function leafPaths(value: unknown, prefix = ''): string[] {
  if (!value || typeof value !== 'object') return [prefix]
  return Object.entries(value).flatMap(([key, child]) => leafPaths(child, prefix ? `${prefix}.${key}` : key))
}

function maintenanceStatus(overrides: Partial<MaintenanceUpgradeStatus> = {}): MaintenanceUpgradeStatus {
  return {
    schema: 'cdnca.maintenance-upgrade-status/v1',
    observed_at: new Date().toISOString(),
    control: {
      component: 'control-api', current_version: '3.4.0', configured_version_matches: true,
      authorization: { state: 'valid', reason: 'eligible', channel: 'stable' },
      candidate: { state: 'available', reason: 'upgrade_available', version: '3.5.0', expires_at: new Date(Date.now() + 60000).toISOString() },
      runtime: { ready: false, reason: 'control_upgrade_execution_unavailable' },
    },
    nodes: [],
    ...overrides,
  }
}

function inventoryNode(index: number) {
  return {
    id: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
    display_id: String(index), name: `Node ${index}`, description: '', region: 'CN-East',
    admin_state: 'active', management_settings: nodeManagementSettingsFixture(), revision: 1,
    created_at: '2026-08-01T08:00:00Z', updated_at: '2026-08-01T09:00:00Z',
    presence: { status: 'online', projection_freshness: 'fresh', lease_signal: 'present', agent_version: '8.8.8',
      session_epoch: 1, heartbeat_sequence: 1, last_heartbeat_at: '2026-08-01T09:00:00Z', projected_at: '2026-08-01T09:00:00Z' },
  }
}

function nodeUpgrade(nodeID: string, overrides: Partial<MaintenanceUpgradeNode> = {}): MaintenanceUpgradeNode {
  return {
    node_id: nodeID, current_version: '2.0.0',
    candidate: { state: 'available', reason: 'upgrade_available', version: '2.1.0', expires_at: new Date(Date.now() + 60000).toISOString() },
    runtime: { ready: true, reason: 'ready' }, reason: 'eligible', eligible: true,
    ...overrides,
  }
}

describe('ControlUpgradesPage', () => {
  it('compacts only the healthy current-version state while keeping details and idle signed actions reachable', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage'])
    const data = maintenanceStatus()
    data.control.candidate = { ...data.control.candidate, state: 'up_to_date', reason: 'same_version', version: '3.4.0' }
    data.control.runtime = { ready: true, reason: 'ready' }
    vi.spyOn(nativeControlUpgradesApi, 'status').mockImplementation(async () => nativeStatusFixture())
    const publish = vi.spyOn(nativeControlUpgradesApi, 'publish')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(json(
      String(input).startsWith('/v1/admin/maintenance-upgrade-status') ? { data } : listResponse(),
    )))
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const summary = screen.getByRole('heading', { name: '主控升级' }).closest('section')!
    await within(summary).findByText('当前已经是最新版本')
    await waitFor(() => expect(within(summary).queryByRole('button', { name: '升级主控' })).not.toBeInTheDocument())
    expect(summary.querySelector('.maintenance-current-status .lucide-circle-check')).not.toBeNull()
    expect(within(summary).queryByText('满足升级资格')).not.toBeInTheDocument()
    expect(within(summary).queryByText('运行条件已就绪')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '升级主控' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新建发布计划' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '高级发布计划' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '刷新主控发布状态' })).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('/control-upgrade-rollouts'))).toBe(false)
    expect(publish).not.toHaveBeenCalled()
    await userEvent.click(within(summary).getByRole('button', { name: '版本详情' }))
    const details = await findDialog('版本详情')
    expect(within(details).getByText('满足升级资格')).toBeInTheDocument()
    expect(within(details).getByText('运行条件已就绪')).toBeInTheDocument()
  })

  it.each(['mismatch', 'unconfirmed', 'runtime', 'unknown', 'expired', 'denied', 'runner'] as const)(
    'keeps the reference three-column layout without internal diagnostics when %s needs attention', async (condition) => {
      authenticate(['control.upgrades.read', 'control.upgrades.manage'])
      const data = maintenanceStatus()
      data.control.candidate = { ...data.control.candidate, state: 'up_to_date', reason: 'same_version', version: '3.4.0' }
      data.control.runtime = { ready: true, reason: 'ready' }
      if (condition === 'mismatch') data.control.configured_version_matches = false
      if (condition === 'unconfirmed') data.control.configured_version_matches = null
      if (condition === 'runtime') data.control.runtime = { ready: false, reason: 'control_upgrade_draining' }
      if (condition === 'runner') data.control.runtime = { ready: false, reason: 'control_upgrade_runner_unconfirmed' }
      if (condition === 'unknown') data.control.runtime.reason = 'future_reason'
      if (condition === 'expired') data.control.candidate.expires_at = '2000-01-01T00:00:00Z'
      if (condition === 'denied') {
        data.control.authorization = { state: 'denied', reason: 'entitlement_state_denied' }
        data.control.candidate = { state: 'unavailable', reason: 'entitlement_state_denied', version: null, expires_at: null }
      }
      vi.spyOn(nativeControlUpgradesApi, 'status').mockImplementation(async () => nativeStatusFixture())
      vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(json(
        String(input).startsWith('/v1/admin/maintenance-upgrade-status') ? { data } : listResponse(),
      )))
      renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
      const summary = screen.getByRole('heading', { name: '主控升级' }).closest('section')!
      await within(summary).findAllByText('3.4.0')
      expect(summary.querySelector('.maintenance-stat-grid')?.children).toHaveLength(3)
      expect(summary.children).toHaveLength(2)
      expect(summary.querySelector('.maintenance-control-status')).toBeNull()
      expect(within(summary).queryByRole('button', { name: '升级主控' })).not.toBeInTheDocument()
      expect(within(summary).queryByRole('button', { name: '刷新主控发布状态' })).not.toBeInTheDocument()
      // ui-leftover3 #2：候选不可用（denied）时写出用户可读的原因与下一步，其余情况不露内部诊断。
      if (condition === 'denied') expect(summary).toHaveTextContent('当前授权状态不允许升级')
      else expect(summary).not.toHaveTextContent(/授权状态|满足升级资格|签名计划服务|执行器|配置版本与运行版本不一致/)
      expect(summary).not.toHaveTextContent(/满足升级资格|签名计划服务|执行器|配置版本与运行版本不一致/)
      expect(summary.querySelector('.maintenance-current-status')).toBeNull()
      expect(within(summary).queryByText('当前已经是最新版本')).not.toBeInTheDocument()
      if (condition === 'unknown') expect(summary).not.toHaveTextContent('future_reason')
      await userEvent.click(within(summary).getByRole('button', { name: '版本详情' }))
      const details = await findDialog('版本详情')
      if (condition === 'mismatch') expect(within(details).getByText('配置版本与运行版本不一致')).toBeInTheDocument()
      if (condition === 'runner') expect(within(details).getByText('签名计划服务已接入，独立升级执行器状态待确认')).toBeInTheDocument()
    },
  )

  it('keeps expired status compact without exposing signed actions on the main card', async () => {
    vi.useFakeTimers()
    authenticate(['control.upgrades.read', 'control.upgrades.manage'])
    const data = maintenanceStatus()
    data.control.candidate = { state: 'up_to_date', reason: 'same_version', version: '3.4.0', expires_at: new Date(Date.now() + 2000).toISOString() }
    data.control.runtime = { ready: true, reason: 'ready' }
    vi.spyOn(nativeControlUpgradesApi, 'status').mockImplementation(async () => nativeStatusFixture())
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(json(
      String(input).startsWith('/v1/admin/maintenance-upgrade-status') ? { data } : listResponse(),
    )))
    const view = renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    try {
      await act(async () => { await vi.advanceTimersByTimeAsync(50) })
      const summary = screen.getByRole('heading', { name: '主控升级' }).closest('section')!
      expect(summary.querySelector('.maintenance-control-status')).toBeNull()
      expect(within(summary).queryByRole('button', { name: '升级主控' })).not.toBeInTheDocument()
      await act(async () => { await vi.advanceTimersByTimeAsync(2000) })
      expect(within(summary).getAllByText('版本未确认')).toHaveLength(1)
      expect(within(summary).getByText('发布候选已过期，请刷新')).toBeInTheDocument()
      expect(summary.querySelector('.maintenance-control-status')).toBeNull()
      expect(within(summary).queryByRole('button', { name: '升级主控' })).not.toBeInTheDocument()
      expect(summary.children).toHaveLength(2)
    } finally {
      view.unmount()
      vi.useRealTimers()
    }
  })

  it('marks only healthy current-version nodes as not needing an upgrade', async () => {
    authenticate(['control.upgrades.read', 'nodes.read'])
    const nodes = [inventoryNode(1), inventoryNode(2)]
    const statuses = nodes.map((node, index) => nodeUpgrade(node.id, {
      candidate: { state: 'up_to_date', reason: 'same_version', version: '2.0.0', expires_at: new Date(Date.now() + 60000).toISOString() },
      reason: index ? 'node_offline' : 'same_version', eligible: false,
    }))
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: nodes }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.has('node_id') ? statuses : [] }) }))
      return Promise.resolve(json(listResponse()))
    })
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const healthy = (await screen.findByText(nodes[0].name)).closest('tr')!
    expect((await within(healthy).findByText('不需要升级')).closest('.ant-tag')).toHaveClass('maintenance-current-status')
    expect(healthy.querySelector('.lucide-circle-check')).not.toBeNull()
    const offline = screen.getByText(nodes[1].name).closest('tr')!
    expect(within(offline).getByText('节点不在线')).toBeInTheDocument()
    expect(offline.querySelector('.maintenance-current-status')).toBeNull()
  })

  it('keeps build provenance in accessible details without hiding upgrade blockers', async () => {
    authenticate(['control.upgrades.read'])
    const data = maintenanceStatus()
    data.control.build = {
      source_commit: 'a'.repeat(40), source_tree: 'b'.repeat(40),
      built_at: '2026-10-08T01:02:03Z', binary_sha256: 'c'.repeat(64),
    }
    data.control.authorization = { state: 'unavailable', reason: 'entitlement_unavailable' }
    data.control.candidate = { state: 'unavailable', reason: 'entitlement_unavailable', version: null, expires_at: null }
    data.control.runtime = { ready: false, reason: 'control_upgrade_plan_writer_unconfigured' }
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(json(
      String(input).startsWith('/v1/admin/maintenance-upgrade-status') ? { data } : listResponse(),
    )))
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const summary = screen.getByRole('heading', { name: '主控升级' }).closest('section')!
    expect(await within(summary).findByText('3.4.0')).toBeInTheDocument()
    expect(screen.queryByText('a'.repeat(40))).not.toBeInTheDocument()
    expect(summary).not.toHaveTextContent(/签名升级计划/)
    expect(within(summary).getByText('暂未取得有效授权')).toBeInTheDocument()
    expect(within(summary).queryByRole('button', { name: '升级主控' })).not.toBeInTheDocument()
    await userEvent.click(within(summary).getByRole('button', { name: '版本详情' }))
    const details = await findDialog('版本详情')
    expect(within(details).getByText('尚未启用签名升级计划发布服务')).toBeInTheDocument()
    expect(within(details).getByText('暂未取得有效授权')).toBeInTheDocument()
    expect(within(details).getByText('a'.repeat(40))).toBeInTheDocument()
    expect(within(details).getByText('b'.repeat(40))).toBeInTheDocument()
    expect(within(details).getByText('c'.repeat(64))).toBeInTheDocument()
    expect(within(details).getByText('2026/10/08 09:02:03')).toBeInTheDocument()
  })

  it('does not render the advanced rollout plan section or read the rollout list', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'control.upgrades.check', 'nodes.read', 'nodes.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(json(
      String(input).startsWith('/v1/admin/maintenance-upgrade-status') ? { data: maintenanceStatus() } : listResponse(),
    )))
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    expect(await screen.findByText('3.4.0')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '高级发布计划' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新建发布计划' })).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: '发布计划' })).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: '资格检查' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: '安装新节点' })).toHaveAttribute('href', '/dashboard/node/list')
    const rolloutReads = fetchSpy.mock.calls.map(([input]) => String(input)).filter((input) => input.includes('/control-upgrade-rollouts'))
    expect(rolloutReads.every((input) => input === '/v1/admin/control-upgrade-rollouts?page=1&page_size=10')).toBe(true)
    expect(screen.queryByText('可创建预检计划')).not.toBeInTheDocument()
  })

  it('offers the signed master upgrade inside the version cell only when a newer version is available', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage'])
    const data = maintenanceStatus()
    data.control.runtime = { ready: true, reason: 'ready' }
    vi.spyOn(nativeControlUpgradesApi, 'status').mockImplementation(async () => nativeStatusFixture())
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(json(
      String(input).startsWith('/v1/admin/maintenance-upgrade-status') ? { data } : listResponse(),
    )))
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const summary = screen.getByRole('heading', { name: '主控升级' }).closest('section')!
    expect(await within(summary).findByText('3.5.0')).toBeInTheDocument()
    const upgrade = await within(summary).findByRole('button', { name: '升级主控' })
    await waitFor(() => expect(upgrade).toBeEnabled())
    expect(within(summary).queryByRole('button', { name: '刷新主控发布状态' })).not.toBeInTheDocument()
    await userEvent.click(upgrade)
    expect(await findDialog('升级主控')).toBeInTheDocument()
  })

  it('shows the node install command section and copies the reusable registration command without creating a node', async () => {
    authenticate(['control.upgrades.read', 'nodes.read', 'nodes.manage'])
    Object.assign(window, { __CDNCA_NODE_UPGRADE_TRUST_SHA256__: 'cd'.repeat(32) })
    const key = `nrk1.${'ab'.repeat(16)}.${'K'.repeat(43)}`
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes/registration-credential') return Promise.resolve(json({ key_id: 'ab'.repeat(16), credential: key, issued_at: '2026-10-14T08:00:00Z' }))
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: [] }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus() }))
      return Promise.resolve(json(listResponse()))
    })
    const user = userEvent.setup()
    const clipboard = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const section = (await screen.findByRole('heading', { name: '节点安装命令' })).closest('section')!
    expect(within(section).getByText('复制后在节点服务器执行')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '重装与恢复现有节点' })).not.toBeInTheDocument()
    await user.click(await within(section).findByRole('button', { name: '复制安装命令' }))
    await waitFor(() => expect(clipboard).toHaveBeenCalledOnce())
    expect(clipboard.mock.calls[0][0]).toMatch(/^\(f=\$\(mktemp\) .*curl --proto '=https' --proto-redir '=https' -fsSL -o "\$f" '[^']+\/downloads\/install-node\.sh'; .*; printf '%s\\n' 'nrk1\.[0-9a-f]{32}\.K{43}' \| bash "\$f" --control-plane '[^']+' --registration-key-stdin\)$/)
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
  })

  it('hides the node install command from accounts without node management', async () => {
    authenticate(['control.upgrades.read', 'nodes.read'])
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: [] }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus() }))
      return Promise.resolve(json(listResponse()))
    })
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const section = (await screen.findByRole('heading', { name: '节点安装命令' })).closest('section')!
    expect(within(section).queryByRole('button', { name: '复制安装命令' })).not.toBeInTheDocument()
  })

  it('does not present an edge-agent rollout as the control-plane version or release candidate', async () => {
    authenticate(['control.upgrades.read'])
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(json(
      String(input).startsWith('/v1/admin/maintenance-upgrade-status') ? { data: maintenanceStatus() } : listResponse(rollout({
        component: 'edge-agent', current_version: '7.4.0', target_version: '7.5.0', state: 'completed', completion: 'upgraded',
      })),
    )))
    const fetchSpy = vi.mocked(globalThis.fetch)
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const controlSummary = screen.getByRole('heading', { name: '主控升级' }).closest('section')!
    expect(await within(controlSummary).findByText('3.4.0')).toBeInTheDocument()
    expect(within(controlSummary).getByText('3.5.0')).toBeInTheDocument()
    expect(controlSummary).not.toHaveTextContent('7.4.0')
    expect(controlSummary).not.toHaveTextContent('7.5.0')
    expect(controlSummary).not.toHaveTextContent('主控升级执行器未就绪')
    expect(within(controlSummary).getByRole('button', { name: '升级主控' })).toBeDisabled()
    expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('/control-upgrade-rollouts'))).toBe(false)
  })

  it('refreshes control facts from the node section without reading rollout plans', async () => {
    authenticate(['control.upgrades.read'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus() }))
      return Promise.resolve(json(listResponse()))
    })
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    await screen.findByText('3.4.0')
    expect(fetchSpy.mock.calls.filter(([input]) => String(input) === '/v1/admin/maintenance-upgrade-status')).toHaveLength(1)
    await user.click(screen.getAllByRole('button', { name: '刷新' }).at(-1)!)
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([input]) => String(input) === '/v1/admin/maintenance-upgrade-status')).toHaveLength(2))
    expect(fetchSpy.mock.calls.some(([input]) => String(input).startsWith('/v1/nodes'))).toBe(false)
    expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('/control-upgrade-rollouts'))).toBe(false)
  })

  it('upgrades a node through a plain confirmation using one canary, batch size one and automatic rollback', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read'])
    const nodes = [inventoryNode(1), inventoryNode(2)]
    const queued = rolloutDetail([nodes[0].id], { revision: '1' })
    const started = rolloutDetail([nodes[0].id], { revision: '2', state: 'canary', active_batch: 0,
      nodes: [{ node_id: nodes[0].id, agent_version: '2.0.0', protocol_version: 1, state: 'dispatched', dispatch_revision: '2' }] })
    let plans: ControlUpgradeRolloutDetail[] = []
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: nodes }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.getAll('node_id').map((id) => nodeUpgrade(id)) }) }))
      if (url.pathname === '/v1/admin/control-upgrade-rollouts' && init?.method === 'POST') { plans = [queued]; return Promise.resolve(json({ data: queued, replayed: false }, 201)) }
      if (url.pathname.endsWith('/start') && init?.method === 'POST') { plans = [started]; return Promise.resolve(json({ data: started, replayed: false })) }
      if (url.pathname === `/v1/admin/control-upgrade-rollouts/${ids.plan}`) return Promise.resolve(json({ data: plans[0] }))
      return Promise.resolve(json(listResponse(...plans)))
    })
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const row = (await screen.findByText('Node 1')).closest('tr')!
    expect(await within(row).findByText('可升级')).toBeInTheDocument()
    await waitFor(() => expect(within(row).getByRole('button', { name: '升级' })).toBeEnabled())
    await user.click(within(row).getByRole('button', { name: '升级' }))
    const dialog = await findDialog('升级节点')
    expect(dialog).toHaveTextContent('Node 1')
    expect(dialog).toHaveTextContent('2.1.0')
    expect(dialog).not.toHaveTextContent(/金丝雀|批次|自动回滚开关/)
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('已开始升级节点')).toBeInTheDocument()
    const posts = fetchSpy.mock.calls.filter(([, request]) => request?.method === 'POST')
    expect(posts.map(([input]) => String(input))).toEqual(['/v1/admin/control-upgrade-rollouts', `/v1/admin/control-upgrade-rollouts/${ids.plan}/start`])
    expect(JSON.parse(String(posts[0][1]!.body))).toEqual({
      schema: 'cdnca.control-upgrade-rollout.create/v1', node_ids: [nodes[0].id], canary_node_ids: [nodes[0].id], batch_size: 1, automatic_rollback: true,
    })
    expect(JSON.parse(String(posts[1][1]!.body))).toEqual({ expected_revision: '1', reason: 'operator_upgrade' })
    expect(await within(row).findByText('升级中')).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: '升级' })).toBeDisabled()
  })

  it('upgrades a selected batch with the first selected node as canary', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read'])
    const nodes = [inventoryNode(1), inventoryNode(2)]
    const plan = rolloutDetail(nodes.map((node) => node.id), { state: 'canary', revision: '2' })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: nodes }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.getAll('node_id').map((id) => nodeUpgrade(id)) }) }))
      if (url.pathname === '/v1/admin/control-upgrade-rollouts' && init?.method === 'POST') return Promise.resolve(json({ data: plan, replayed: true }, 201))
      return Promise.resolve(json(listResponse()))
    })
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    for (const name of ['Node 2', 'Node 1']) await user.click(within((await screen.findByText(name)).closest('tr')!).getByRole('checkbox'))
    const batch = screen.getByRole('button', { name: '升级节点（2）' })
    await waitFor(() => expect(batch).toBeEnabled())
    await user.click(batch)
    await user.click(within(await findDialog('升级节点')).getByRole('button', { name: '确定' }))
    await screen.findByText('已开始升级节点')
    const posts = fetchSpy.mock.calls.filter(([, request]) => request?.method === 'POST')
    // A replayed create that already left the queue is not started again.
    expect(posts).toHaveLength(1)
    const body = JSON.parse(String(posts[0][1]!.body))
    expect(body.node_ids).toEqual(nodes.map((node) => node.id).sort())
    expect(body.canary_node_ids).toHaveLength(1)
    expect(body.node_ids).toContain(body.canary_node_ids[0])
    expect(body.batch_size).toBe(1)
  })

  it('enables the batch upgrade button when upgradable nodes exist with no selection', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read'])
    const nodes = [inventoryNode(1), inventoryNode(2)]
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: nodes }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.getAll('node_id').map((id) => nodeUpgrade(id)) }) }))
      return Promise.resolve(json(listResponse()))
    })
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const button = await screen.findByRole('button', { name: '升级节点' })
    await waitFor(() => expect(button).toBeEnabled())
  })

  it('upgrades only selected nodes when a subset is checked', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read'])
    const nodes = [inventoryNode(1), inventoryNode(2), inventoryNode(3)]
    const plan = rolloutDetail([nodes[0].id], { revision: '1' })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: nodes }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.getAll('node_id').map((id) => nodeUpgrade(id)) }) }))
      if (url.pathname === '/v1/admin/control-upgrade-rollouts' && init?.method === 'POST') return Promise.resolve(json({ data: plan, replayed: false }, 201))
      if (url.pathname.endsWith('/start') && init?.method === 'POST') return Promise.resolve(json({ data: { ...plan, state: 'canary', revision: '2' }, replayed: false }))
      return Promise.resolve(json(listResponse()))
    })
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    // select only Node 1
    await user.click(within((await screen.findByText('Node 1')).closest('tr')!).getByRole('checkbox'))
    const batch = screen.getByRole('button', { name: '升级节点（1）' })
    await waitFor(() => expect(batch).toBeEnabled())
    await user.click(batch)
    await user.click(within(await findDialog('升级节点')).getByRole('button', { name: '确定' }))
    await screen.findByText('已开始升级节点')
    const posts = fetchSpy.mock.calls.filter(([, request]) => request?.method === 'POST')
    expect(posts).toHaveLength(2)
    const body = JSON.parse(String(posts[0][1]!.body))
    // only the selected node should be in the plan
    expect(body.node_ids).toEqual([nodes[0].id])
  })

  it('projects real rollout node states as plain statuses and fails closed when they cannot be read', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read'])
    const nodes = [inventoryNode(1), inventoryNode(2), inventoryNode(3)]
    const plan = rolloutDetail(nodes.slice(0, 2).map((node) => node.id), { state: 'canary', revision: '3', nodes: [
      { node_id: nodes[0].id, agent_version: '2.0.0', protocol_version: 1, state: 'dispatched', dispatch_revision: '2' },
      { node_id: nodes[1].id, agent_version: '2.0.0', protocol_version: 1, state: 'pending', dispatch_revision: '0' },
    ] })
    const failed = rolloutDetail([nodes[2].id], { id: '00000000-0000-4000-8000-000000000019', state: 'completed', completion: 'rolled_back', nodes: [
      { node_id: nodes[2].id, agent_version: '2.0.0', protocol_version: 1, state: 'rolled_back', dispatch_revision: '3' },
    ] })
    let broken = false
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: nodes }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.getAll('node_id').map((id) => nodeUpgrade(id)) }) }))
      if (broken) return Promise.resolve(json({ error: { code: 'unavailable', message: 'private' } }, 503))
      if (url.pathname.endsWith(failed.id)) return Promise.resolve(json({ data: failed }))
      if (url.pathname.endsWith(ids.plan)) return Promise.resolve(json({ data: plan }))
      return Promise.resolve(json(listResponse(plan, failed)))
    })
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const row = async (name: string) => (await screen.findByText(name)).closest('tr')!
    expect(await within(await row('Node 1')).findByText('升级中')).toBeInTheDocument()
    expect(within(await row('Node 2')).getByText('等待升级')).toBeInTheDocument()
    expect(within(await row('Node 3')).getByText('升级失败，已回滚')).toBeInTheDocument()
    for (const name of ['Node 1', 'Node 2']) expect(within(await row(name)).getByRole('button', { name: '升级' })).toBeDisabled()
    await waitFor(() => expect(within(screen.getByText('Node 3').closest('tr')!).getByRole('button', { name: '升级' })).toBeEnabled())
    broken = true
    await user.click(within(screen.getByRole('heading', { name: '节点升级' }).closest('section')!).getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('节点升级任务读取失败，升级已暂时禁用；请刷新重试。')).toBeInTheDocument()
    expect(within(await row('Node 3')).getByRole('button', { name: '升级' })).toBeDisabled()
    expect(screen.queryByText('private')).not.toBeInTheDocument()
  })

  it('shows the node and master upgrade logs as plain chronological text', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read'])
    const nodes = [inventoryNode(1)]
    const plan = rolloutDetail([nodes[0].id], { state: 'canary', revision: '2', events: [{
      id: '00000000-0000-4000-8000-0000000000e1', revision: '2', from: 'queued', to: 'canary', action: 'start',
      reason: 'operator_start', batch_id: ids.batch, node_id: '', occurred_at: '2026-10-14T08:01:00Z',
    }], nodes: [{ node_id: nodes[0].id, agent_version: '2.0.0', protocol_version: 1, state: 'dispatched', dispatch_revision: '2' }] })
    const native = { ...nativeStatusFixture(), publication_revision: 1, publication: nativePublicationFixture(),
      execution: { state: 'running', phase: 'drained', receipt: null, history: [{ phase: 'verified', at: 1780000001 }] } }
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: nodes }))
      if (url.pathname === '/v1/admin/control-upgrade-plan/run-log') return Promise.resolve(json({
        schema: 'cdnca.native-control-upgrade-runlog/v1', observed_at: '2026-10-14T08:00:00Z', state: 'unavailable', run_log: null }))
      if (url.pathname === '/v1/admin/control-upgrade-plan') return Promise.resolve(json(native))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.getAll('node_id').map((id) => nodeUpgrade(id)) }) }))
      if (url.pathname.endsWith(ids.plan)) return Promise.resolve(json({ data: plan }))
      return Promise.resolve(json(listResponse(plan)))
    })
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const row = (await screen.findByText('Node 1')).closest('tr')!
    expect(await within(row).findByText('升级中')).toBeInTheDocument()
    await user.click(within(row).getByRole('button', { name: '日志' }))
    const nodeLog = await findDialog('节点升级日志')
    const nodeText = (within(nodeLog).getByLabelText('日志内容 脚本日志') as HTMLTextAreaElement).value
    expect(nodeText).toContain('[INFO]')
    expect(nodeText).toContain('创建升级任务 2.0.0 → 2.1.0')
    expect(nodeText).toContain('开始执行升级任务 (operator_start)')
    await user.click(within(nodeLog).getByRole('button', { name: 'Close' }))
    await user.click(screen.getByRole('button', { name: '查看日志' }))
    const masterLog = await findDialog('主控升级日志')
    await waitFor(() => expect((within(masterLog).getByLabelText('日志内容 脚本日志') as HTMLTextAreaElement).value).toContain('[INFO] 开始升级 1.0.0 → 1.1.0'))
    expect((within(masterLog).getByLabelText('日志内容 脚本日志') as HTMLTextAreaElement).value).toMatch(/\[INFO\] \[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \S/)
  })

  it('shows the master script log and program log tabs from the runner run log', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read'])
    const publication = nativePublicationFixture()
    const native = { ...nativeStatusFixture(), publication_revision: 1, publication,
      execution: { state: 'running', phase: 'activated', receipt: null, history: [{ phase: 'verified', at: 1780000001 }] } }
    const runLog = { schema: 'cdnca.control-plane-upgrade-runlog/v1', plan_id: publication.plan_id, sequence: publication.release_sequence,
      started_at: 1780000000, attempts: 1, dropped: 0, entries: [
        { at: 1780000000, level: 'info', event: 'run_started', version: '1.1.0', attempt: 1 },
        { at: 1780000002, level: 'error', event: 'artifact_download_failed', reason: 'network_error', host: 'dl.example.com', duration_ms: 1500 },
      ], programs: [{ unit: 'cdnca-control-api.service', captured_at: 1780000003, trigger: 'run_failed', lines: ['control-api ready token=[REDACTED]'] }] }
    let runLogResponse: 'available' | 'unavailable' | 'missing' = 'available'
    const urls: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      urls.push(url.pathname)
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: [] }))
      if (url.pathname === '/v1/admin/control-upgrade-plan/run-log') {
        if (runLogResponse === 'missing') return Promise.resolve(json({ error: { code: 'not_found' } }, 404))
        return Promise.resolve(json({ schema: 'cdnca.native-control-upgrade-runlog/v1', observed_at: '2026-10-14T08:00:00Z',
          state: runLogResponse, run_log: runLogResponse === 'available' ? runLog : null }))
      }
      if (url.pathname === '/v1/admin/control-upgrade-plan') return Promise.resolve(json(native))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus({ nodes: [] }) }))
      return Promise.resolve(json({ data: [], page: 1, page_size: 20, total: 0 }))
    })
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    await user.click(await screen.findByRole('button', { name: '查看日志' }))
    const dialog = await findDialog('主控升级日志')
    const scriptBox = () => within(dialog).getByLabelText('日志内容 脚本日志') as HTMLTextAreaElement
    await waitFor(() => expect(scriptBox().value).toContain('开始升级主控到 1.1.0'))
    expect(scriptBox().value).toMatch(/\[ERROR\] \[[\d-]+ [\d:]+\] 下载升级包失败：网络连接失败，将自动重试/)
    expect(scriptBox()).toHaveAttribute('readonly')
    expect(within(dialog).getByRole('button', { name: /复制/ })).toBeEnabled()
    await user.click(within(dialog).getByRole('tab', { name: '程序日志' }))
    const programBox = within(dialog).getByLabelText('日志内容 程序日志') as HTMLTextAreaElement
    expect(programBox.value).toContain('===== cdnca-control-api.service（')
    expect(programBox.value).toContain('control-api ready token=[REDACTED]')
    await user.click(within(dialog).getByRole('button', { name: 'Close' }))
    // No step log for this run yet: the phase records are shown.
    runLogResponse = 'unavailable'
    await user.click(screen.getByRole('button', { name: '查看日志' }))
    const fallback = await findDialog('主控升级日志')
    await waitFor(() => expect((within(fallback).getByLabelText('日志内容 脚本日志') as HTMLTextAreaElement).value).toContain('[INFO] 开始升级 1.0.0 → 1.1.0'))
    expect(within(fallback).getByText('本次执行暂未读到逐步日志，以下仅为阶段记录。')).toBeInTheDocument()
    expect(within(fallback).queryByText('升级日志读取失败，请刷新重试。')).not.toBeInTheDocument()
    await user.click(within(fallback).getByRole('tab', { name: '程序日志' }))
    expect((within(fallback).getByLabelText('日志内容 程序日志') as HTMLTextAreaElement).value).toContain('暂无程序日志')
    await user.click(within(fallback).getByRole('button', { name: 'Close' }))
    // A failed run-log read (no such route) is a read failure, not a fallback.
    runLogResponse = 'missing'
    await user.click(screen.getByRole('button', { name: '查看日志' }))
    const failed = await findDialog('主控升级日志')
    expect(await within(failed).findByText('升级日志读取失败，请刷新重试。')).toBeInTheDocument()
    expect(within(failed).queryByText('本次执行暂未读到逐步日志，以下仅为阶段记录。')).not.toBeInTheDocument()
    expect(urls.filter((path) => path.endsWith('/run-log')).length).toBeGreaterThanOrEqual(3)
  })

  it('retries an unknown start outcome with the same request and never creates a second plan', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read'])
    const node = inventoryNode(1)
    const queued = rolloutDetail([node.id], { revision: '1' })
    let starts = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: [node] }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.getAll('node_id').map((id) => nodeUpgrade(id)) }) }))
      if (url.pathname === '/v1/admin/control-upgrade-rollouts' && init?.method === 'POST') return Promise.resolve(json({ data: queued, replayed: false }, 201))
      if (url.pathname.endsWith('/start')) {
        starts += 1
        return starts === 1 ? Promise.reject(new TypeError('connection lost after commit'))
          : Promise.resolve(json({ data: { ...queued, state: 'canary', revision: '2' }, replayed: true }))
      }
      if (url.pathname.endsWith(ids.plan)) return Promise.resolve(json({ data: queued }))
      return Promise.resolve(json(listResponse()))
    })
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const row = (await screen.findByText('Node 1')).closest('tr')!
    await waitFor(() => expect(within(row).getByRole('button', { name: '升级' })).toBeEnabled())
    await user.click(within(row).getByRole('button', { name: '升级' }))
    await user.click(within(await findDialog('升级节点')).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('升级请求结果待确认，请使用同一请求重试，不会重复创建升级任务。', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: '升级' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('已开始升级节点')).toBeInTheDocument()
    const posts = fetchSpy.mock.calls.filter(([, request]) => request?.method === 'POST')
    expect(posts.filter(([input]) => String(input) === '/v1/admin/control-upgrade-rollouts')).toHaveLength(1)
    const startCalls = posts.filter(([input]) => String(input).endsWith('/start'))
    expect(startCalls).toHaveLength(2)
    expect(startCalls[1][1]?.headers).toEqual(startCalls[0][1]?.headers)
    expect(startCalls[1][1]?.body).toBe(startCalls[0][1]?.body)
  })

  it('loads more than 100 nodes and obtains each page status without reusing a historical target', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read'])
    const first = Array.from({ length: 100 }, (_, index) => inventoryNode(index + 1))
    const second = inventoryNode(101)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json(url.searchParams.has('cursor') ? { items: [second] } : { items: first, next_cursor: first.at(-1)!.id }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.getAll('node_id').map((id) => nodeUpgrade(id)) }) }))
      return Promise.resolve(json(listResponse()))
    })
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    await screen.findByText('Node 100')
    await user.click(screen.getByRole('button', { name: '加载更多节点' }))
    const row = (await screen.findByText('Node 101')).closest('tr')!
    expect(await within(row).findByText('2.1.0')).toBeInTheDocument()
    expect(within(row).getByText('2.0.0')).toBeInTheDocument()
    expect(row).not.toHaveTextContent('8.8.8')
    expect(within(row).getByRole('button', { name: '升级' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: '加载更多节点' })).not.toBeInTheDocument()
    const requests = fetchSpy.mock.calls.map(([input]) => new URL(String(input), 'https://test.invalid')).filter((url) => url.pathname.endsWith('/maintenance-upgrade-status'))
    expect(requests.map((url) => url.searchParams.getAll('node_id').length)).toEqual([0, 100, 1])
    await user.click(within(row).getByRole('button', { name: '升级' }))
    const dialog = await findDialog('升级节点')
    expect(dialog).toHaveTextContent(second.name)
    expect(dialog).not.toHaveTextContent(/金丝雀|批次|节点 ID/)
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
  })

  it('sorts numeric node IDs across every loaded cursor page without losing selection or the upgrade target', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read'])
    const first = [{ ...inventoryNode(1), display_id: '10', name: 'Node 10' }, { ...inventoryNode(2), display_id: '9007199254740993', name: 'Node 3' }, { ...inventoryNode(3), display_id: '2', name: 'Node 2' }]
    const second = [{ ...inventoryNode(4), display_id: '9007199254740992' }, { ...inventoryNode(5), display_id: '1', name: 'Node 1' }]
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json(url.searchParams.has('cursor') ? { items: second } : { items: first, next_cursor: first.at(-1)!.id }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.getAll('node_id').map((id) => nodeUpgrade(id)) }) }))
      return Promise.resolve(json(listResponse()))
    })
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const section = screen.getByRole('heading', { name: '节点升级' }).closest('section')!
    const names = () => [...section.querySelectorAll('tbody tr[data-row-key]')].map((row) => row.querySelector('td:nth-child(3)')!.textContent)
    const selected = (await within(section).findByText('Node 2')).closest('tr')!
    await user.click(within(selected).getByRole('checkbox'))
    await user.click(within(section).getByRole('columnheader', { name: /节点ID/ }))
    expect(names()).toEqual(['Node 2', 'Node 10', 'Node 3'])
    expect(within(section).getByRole('columnheader', { name: /节点ID/ })).toHaveAttribute('aria-sort', 'ascending')
    expect(screen.getByLabelText('节点版本摘要')).toHaveTextContent('已加载节点 3')
    await user.click(within(section).getByRole('button', { name: '加载更多节点' }))
    await within(section).findByText('Node 1')
    expect(names()).toEqual(['Node 1', 'Node 2', 'Node 10', 'Node 4', 'Node 3'])
    expect(screen.getByLabelText('节点版本摘要')).toHaveTextContent('节点数 5')
    await user.click(within(section).getByRole('columnheader', { name: /节点ID/ }))
    expect(names()).toEqual(['Node 3', 'Node 4', 'Node 10', 'Node 2', 'Node 1'])
    expect(within(section).getByRole('columnheader', { name: /节点ID/ })).toHaveAttribute('aria-sort', 'descending')
    const sameNode = within(section).getByText('Node 2').closest('tr')!
    expect(within(sameNode).getByRole('checkbox')).toBeChecked()
    await user.click(within(sameNode).getByRole('button', { name: '升级' }))
    expect(await findDialog('升级节点')).toHaveTextContent(first[2].name)
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
  })

  it('sorts displayed node states stably while retaining unknown and disabled upgrade guards', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read'])
    const nodes = [{ ...inventoryNode(1), name: 'Node 4' }, inventoryNode(2), inventoryNode(3), { ...inventoryNode(4), name: 'Node 1' }]
    const statuses = [nodeUpgrade(nodes[0].id), nodeUpgrade(nodes[1].id, { eligible: false, reason: 'node_offline' }), nodeUpgrade(nodes[2].id)]
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: nodes }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.has('node_id') ? statuses : [] }) }))
      return Promise.resolve(json(listResponse()))
    })
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const section = screen.getByRole('heading', { name: '节点升级' }).closest('section')!
    await within(section).findByText('节点不在线')
    const original = [...section.querySelectorAll('tbody tr[data-row-key]')].map((row) => ({ name: row.querySelector('td:nth-child(3)')!.textContent, status: row.querySelector('.ant-tag')!.textContent! }))
    const names = () => [...section.querySelectorAll('tbody tr[data-row-key]')].map((row) => row.querySelector('td:nth-child(3)')!.textContent)
    const collator = new Intl.Collator('zh-CN')
    await user.click(within(section).getByRole('columnheader', { name: /状态/ }))
    expect(within(section).getByRole('columnheader', { name: /状态/ })).toHaveAttribute('aria-sort', 'ascending')
    expect(names()).toEqual([...original].sort((a, b) => collator.compare(a.status, b.status)).map((row) => row.name))
    await user.click(within(section).getByRole('columnheader', { name: /状态/ }))
    expect(names()).toEqual([...original].sort((a, b) => collator.compare(b.status, a.status)).map((row) => row.name))
    expect(names().filter((name) => name === 'Node 4' || name === 'Node 3')).toEqual(['Node 4', 'Node 3'])
    for (const name of ['Node 2', 'Node 1']) expect(within(within(section).getByText(name).closest('tr')!).getByRole('button', { name: '升级' })).toBeDisabled()
    expect(within(section).getByText('节点升级状态未确认')).toBeInTheDocument()
  })

  it('stops a repeated cursor without hiding the already loaded inventory', async () => {
    authenticate(['control.upgrades.read', 'nodes.read'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: [inventoryNode(1)], next_cursor: inventoryNode(1).id }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus() }))
      return Promise.resolve(json(listResponse()))
    })
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    await userEvent.click(await screen.findByRole('button', { name: '加载更多节点' }))
    expect(await screen.findByText('节点分页游标重复，已停止加载；请刷新重试。')).toBeInTheDocument()
    expect(screen.getByText('Node 1')).toBeInTheDocument()
    expect(screen.getAllByText('Node 1')).toHaveLength(1)
    expect(screen.queryByRole('button', { name: '加载更多节点' })).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([input]) => String(input).startsWith('/v1/nodes?'))).toHaveLength(2)
  })

  it.each(['same', 'mixed', 'missing', 'expired', 'partial'] as const)('summarizes the required node version honestly for %s candidates', async (condition) => {
    authenticate(['control.upgrades.read', 'nodes.read'])
    const nodes = [inventoryNode(1), inventoryNode(2)]
    const statuses = nodes.map((node) => nodeUpgrade(node.id))
    if (condition === 'mixed') statuses[1].candidate.version = '2.2.0'
    if (condition === 'missing') statuses.pop()
    if (condition === 'expired') statuses[1].candidate.expires_at = '2000-01-01T00:00:00Z'
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: nodes, ...(condition === 'partial' ? { next_cursor: nodes[1].id } : {}) }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.has('node_id') ? statuses : [] }) }))
      return Promise.resolve(json(listResponse()))
    })
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    await screen.findByText('Node 2')
    const summary = screen.getByLabelText('节点版本摘要')
    await waitFor(() => expect(summary).toHaveTextContent(condition === 'same' ? '要求版本 2.1.0' : condition === 'mixed' ? '要求版本 按节点查看' : '要求版本 版本未确认'))
    expect(summary).toHaveTextContent(condition === 'partial' ? '已加载节点 2' : '节点数 2')
    expect(summary).not.toHaveTextContent('1.5.0')
  })

  it.each(['expired', 'unavailable', 'older', 'runtime', 'unknown', 'missing'] as const)('disables node upgrade for %s status', async (condition) => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read'])
    const node = inventoryNode(1)
    const status = nodeUpgrade(node.id)
    if (condition === 'expired') status.candidate.expires_at = '2000-01-01T00:00:00Z'
    if (condition === 'unavailable') { status.candidate = { state: 'unavailable', reason: 'artifact_unavailable', version: null, expires_at: null }; status.eligible = false }
    if (condition === 'older') { status.candidate = { ...status.candidate, state: 'rollback_required', reason: 'target_is_older', version: '1.9.0' }; status.eligible = false; status.reason = 'target_is_older' }
    if (condition === 'runtime') { status.runtime = { ready: false, reason: 'node_upgrade_runtime_unavailable' }; status.eligible = false }
    if (condition === 'unknown') status.candidate.reason = 'future_reason'
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: [node] }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.has('node_id') && condition !== 'missing' ? [status] : [] }) }))
      return Promise.resolve(json(listResponse()))
    })
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const row = (await screen.findByText(node.name)).closest('tr')!
    const labels = { expired: '发布候选已过期，请刷新', unavailable: '发布制品不可用', older: '目标版本较低，需回滚流程', runtime: '节点升级执行器未就绪', unknown: '状态未确认，暂不可升级', missing: '节点升级状态未确认' }
    expect(await within(row).findByText(labels[condition])).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: '升级' })).toBeDisabled()
    expect(row).not.toHaveTextContent('future_reason')
    await userEvent.click(within(row).getByRole('checkbox'))
    expect(screen.getByRole('button', { name: '升级节点（1）' })).toBeDisabled()
  })

  it.each([
    ['node_disabled', '节点未启用'],
    ['node_offline', '节点不在线'],
    ['node_capability_unavailable', '节点能力尚未确认'],
    ['version_unavailable', '运行版本尚未确认'],
  ] as const)('preserves the primary %s blocker across candidate and runtime states', async (reason, label) => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read'])
    const available = nodeUpgrade(ids.nodeA).candidate
    const candidates: MaintenanceUpgradeNode['candidate'][] = reason === 'version_unavailable'
      ? [{ state: 'unavailable', reason, version: null, expires_at: null }]
      : [
        available,
        { ...available, state: 'up_to_date', reason: 'same_version', version: '2.0.0' },
        { ...available, state: 'rollback_required', reason: 'target_is_older', version: '1.9.0' },
        { state: 'unavailable', reason: 'target_unset', version: null, expires_at: available.expires_at },
        { ...available, expires_at: '2000-01-01T00:00:00Z' },
      ]
    const combinations = candidates.flatMap((candidate) => [
      { candidate, runtime: { ready: true, reason: 'ready' } },
      { candidate, runtime: { ready: false, reason: 'node_upgrade_runtime_unavailable' } },
    ])
    const nodes = combinations.map((_, index) => inventoryNode(index + 1))
    const statuses = nodes.map((node, index) => nodeUpgrade(node.id, {
      ...combinations[index], current_version: reason === 'version_unavailable' ? null : '2.0.0', reason, eligible: false,
    }))
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: nodes }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.has('node_id') ? statuses : [] }) }))
      return Promise.resolve(json(listResponse()))
    })
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    for (const node of nodes) {
      const row = (await screen.findByText(node.name)).closest('tr')!
      expect(await within(row).findByText(label)).toBeInTheDocument()
      expect(within(row).getByRole('button', { name: '升级' })).toBeDisabled()
      expect(row).not.toHaveTextContent('可升级')
    }
    await userEvent.click(within(screen.getByText(nodes[0].name).closest('tr')!).getByRole('checkbox'))
    expect(screen.getByRole('button', { name: '升级节点（1）' })).toBeDisabled()
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
  })

  it('clears cached node eligibility when status refresh fails while keeping inventory visible', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read'])
    let offline = false
    const node = inventoryNode(1)
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: [node] }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) {
        if (offline) return Promise.reject(new TypeError('private network detail'))
        return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.has('node_id') ? [nodeUpgrade(node.id)] : [] }) }))
      }
      return Promise.resolve(json(listResponse()))
    })
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const row = (await screen.findByText(node.name)).closest('tr')!
    expect(await within(row).findByText('可升级')).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: '升级' })).toBeEnabled()
    offline = true
    const section = screen.getByRole('heading', { name: '节点升级' }).closest('section')!
    await userEvent.click(within(section).getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('部分节点升级状态读取失败，相关升级已禁用。')).toBeInTheDocument()
    expect(screen.getByText(node.name)).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: '升级' })).toBeDisabled()
    expect(row).not.toHaveTextContent('2.1.0')
    expect(screen.queryByText('3.5.0')).not.toBeInTheDocument()
    expect(screen.queryByText('private network detail')).not.toBeInTheDocument()
  })

  it('does not show the current version as latest when there is no candidate', async () => {
    authenticate(['control.upgrades.read'])
    const data = maintenanceStatus()
    data.control.candidate = { state: 'unavailable', reason: 'target_unset', version: null, expires_at: null }
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(json(String(input).endsWith('/maintenance-upgrade-status') ? { data } : listResponse())))
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const section = screen.getByRole('heading', { name: '主控升级' }).closest('section')!
    expect(await within(section).findByText('3.4.0')).toBeInTheDocument()
    expect(within(section).getAllByText('3.4.0')).toHaveLength(1)
    expect(within(section).getAllByText('版本未确认')).toHaveLength(1)
    expect(within(section).getByText('尚无发布候选')).toBeInTheDocument()
    expect(within(section).queryByText('当前已经是最新版本')).not.toBeInTheDocument()
  })

  // ui-leftover3 #2：候选不可用时「版本升级」只写「版本未确认」，把后端给的原因丢了；
  // 正确做法是写出原因和下一步，让运维知道是哪一环没就绪。
  it.each([
    ['target_unset', '尚无发布候选', '授权端'],
    ['candidate_service_unconfigured', '尚未配置发布候选服务', 'LICENSE_SERVICE_URL'],
    ['protocol_unavailable', '升级协议版本尚未确认', 'CONTROL_UPGRADE_PROTOCOL_VERSION'],
    ['candidate_service_unavailable', '发布候选服务暂不可用', '连接'],
  ])('explains why the master version is unconfirmed (%s)', async (reason, label, hint) => {
    authenticate(['control.upgrades.read'])
    const data = maintenanceStatus()
    data.control.candidate = { state: 'unavailable', reason: reason as MaintenanceUpgradeStatus['control']['candidate']['reason'], version: null, expires_at: null }
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(json(String(input).endsWith('/maintenance-upgrade-status') ? { data } : listResponse())))
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const section = screen.getByRole('heading', { name: '主控升级' }).closest('section')!
    expect(await within(section).findByText(label)).toBeInTheDocument()
    expect(section).toHaveTextContent(hint)
  })

  it.each([403, 503])('keeps unavailable status visible without borrowing rollout versions on HTTP %s', async (status) => {
    authenticate(['control.upgrades.read'])
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(String(input).endsWith('/maintenance-upgrade-status')
      ? json({ error: { code: status === 403 ? 'permission_denied' : 'unavailable', message: 'raw server error' } }, status)
      : json(listResponse())))
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    expect(await screen.findByText(status === 403 ? '无权读取维护升级状态' : '升级状态读取失败，请刷新重试。')).toBeInTheDocument()
    const section = screen.getByRole('heading', { name: '主控升级' }).closest('section')!
    expect(section).not.toHaveTextContent('1.4.0')
    expect(section).not.toHaveTextContent('raw server error')
  })

  it('refreshes control and node candidates before expiry and rejects stale eligibility after a failed poll', async () => {
    vi.useFakeTimers()
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read'])
    const node = inventoryNode(1)
    let unavailable = false
    let controlReads = 0
    let nodeReads = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(json({ items: [node] }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) {
        if (url.searchParams.has('node_id')) nodeReads += 1
        else controlReads += 1
        if (unavailable) return Promise.resolve(json({ error: { code: 'unavailable', message: 'private failure' } }, 503))
        return Promise.resolve(json({ data: maintenanceStatus({ nodes: url.searchParams.has('node_id') ? [nodeUpgrade(node.id)] : [] }) }))
      }
      return Promise.resolve(json(listResponse()))
    })
    const view = renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    try {
      await act(async () => { await vi.advanceTimersByTimeAsync(50) })
      const row = screen.getByText(node.name).closest('tr')!
      expect(controlReads).toBe(1)
      expect(nodeReads).toBe(1)
      await act(async () => { await vi.advanceTimersByTimeAsync(61000) })
      expect(controlReads).toBeGreaterThanOrEqual(3)
      expect(nodeReads).toBeGreaterThanOrEqual(3)
      expect(screen.getByText('3.5.0')).toBeInTheDocument()
      expect(within(row).getByText('2.1.0')).toBeInTheDocument()
      expect(within(row).getByRole('button', { name: '升级' })).toBeEnabled()
      unavailable = true
      await act(async () => { await vi.advanceTimersByTimeAsync(30000) })
      expect(screen.getByText('部分节点升级状态读取失败，相关升级已禁用。')).toBeInTheDocument()
      expect(screen.queryByText('3.5.0')).not.toBeInTheDocument()
      expect(within(row).queryByText('2.1.0')).not.toBeInTheDocument()
      expect(within(row).getByRole('button', { name: '升级' })).toBeDisabled()
      expect(screen.queryByText('private failure')).not.toBeInTheDocument()
      expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
      view.unmount()
      const reads = fetchSpy.mock.calls.length
      await act(async () => { await vi.advanceTimersByTimeAsync(60000) })
      expect(fetchSpy).toHaveBeenCalledTimes(reads)
    } finally {
      view.unmount()
      vi.useRealTimers()
    }
  })

  it('polls only the control status without node read permission', async () => {
    vi.useFakeTimers()
    authenticate(['control.upgrades.read'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(json(
      String(input).endsWith('/maintenance-upgrade-status') ? { data: maintenanceStatus() } : listResponse(),
    )))
    const view = renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    try {
      await act(async () => { await vi.advanceTimersByTimeAsync(61000) })
      const statusCalls = fetchSpy.mock.calls.filter(([input]) => String(input).includes('/maintenance-upgrade-status'))
      expect(statusCalls.length).toBeGreaterThanOrEqual(3)
      expect(statusCalls.every(([input]) => !String(input).includes('node_id='))).toBe(true)
      expect(fetchSpy.mock.calls.some(([input]) => String(input).startsWith('/v1/nodes'))).toBe(false)
      expect(screen.getByText('3.5.0')).toBeInTheDocument()
    } finally {
      view.unmount()
      vi.useRealTimers()
    }
  })

  it('expires displayed candidates without waiting for another user action', async () => {
    vi.useFakeTimers()
    authenticate(['control.upgrades.read'])
    const data = maintenanceStatus()
    data.control.candidate.expires_at = new Date(Date.now() + 600).toISOString()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(json(String(input).endsWith('/maintenance-upgrade-status') ? { data } : listResponse())))
    const view = renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    try {
      await act(async () => { await vi.advanceTimersByTimeAsync(50) })
      expect(screen.getByText('3.5.0')).toBeInTheDocument()
      await act(async () => { await vi.advanceTimersByTimeAsync(600) })
      const summary = screen.getByRole('heading', { name: '主控升级' }).closest('section')!
      expect(within(summary).getAllByText('版本未确认')).toHaveLength(1)
      expect(within(summary).getByText('发布候选已过期，请刷新')).toBeInTheDocument()
      expect(screen.queryByText('3.5.0')).not.toBeInTheDocument()
    } finally {
      view.unmount()
      vi.useRealTimers()
    }
  })

  const backupStatus = {
    keys_ready: true, signer_fingerprint: 'SHA256:' + 'A'.repeat(43), recipient: 'age1test', agent_installed: true, migration_ready: true, freeze: null,
    bundles: [{ backup_id: '20261017T030000Z-abcdefgh', reason: 'manual', created_at: '2026-10-17T03:00:05Z', version: '1.0.35', schema_version: 302,
      bytes: 10485760, signer_fingerprint: 'SHA256:' + 'A'.repeat(43), signature_ok: true, components: ['config'] }],
    runs: [{ id: '20261017T030000Z-0123456789ab', kind: 'backup', reason: 'manual', state: 'succeeded', requested_at: '2026-10-17T03:00:00Z', backup_id: '20261017T030000Z-abcdefgh', log: ['freeze'] }],
    settings: { schedule: { enabled: false, weekdays: [0, 1, 2, 3, 4, 5, 6], hour: 4, minute: 0 }, keep_local: 7, keep_remote: 14, targets: [] },
  }
  function backupFetch(calls: Array<[string, RequestInit | undefined]>) {
    return (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      calls.push([url, init])
      if (url.includes('/v1/admin/control-backup/backups/20261017T030000Z-abcdefgh/restore-commands')) {
        return Promise.resolve(json({ data: { backup_id: '20261017T030000Z-abcdefgh', signer_fingerprint: backupStatus.signer_fingerprint, version: '1.0.35', commands: ['# step', 'control-api native-backup restore --bundle x'] } }))
      }
      if (url.includes('/v1/admin/control-backup/migrations')) return Promise.resolve(json({ data: { ...backupStatus.runs[0], kind: 'migrate', state: 'queued' } }, 202))
      if (url.includes('/v1/admin/control-backup/backups') && init?.method === 'POST') return Promise.resolve(json({ data: { ...backupStatus.runs[0], state: 'queued' } }, 202))
      if (url.includes('/v1/admin/control-backup')) return Promise.resolve(json({ data: backupStatus }))
      return Promise.resolve(json(listResponse()))
    }
  }

  it('lists native backups, shows restore commands and queues a backup only after confirmation', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage'])
    const calls: Array<[string, RequestInit | undefined]> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(backupFetch(calls))
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    await user.click(await screen.findByRole('tab', { name: '维护操作' }))
    expect((await screen.findAllByText('20261017T030000Z-abcdefgh', { selector: 'td' })).length).toBe(2)
    expect(screen.getByText(backupStatus.signer_fingerprint)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '恢复' }))
    expect(await screen.findByText(/control-api native-backup restore --bundle x/)).toBeInTheDocument()
    await user.keyboard('{Escape}')
    await user.click(screen.getByRole('button', { name: '立即备份' }))
    expect(calls.some(([url, init]) => url.endsWith('/v1/admin/control-backup/backups') && init?.method === 'POST')).toBe(false)
    expect(await screen.findByText(/管理后台暂时不可用/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /确\s*定|OK/ }))
    await waitFor(() => expect(calls.some(([url, init]) => url.endsWith('/v1/admin/control-backup/backups') && init?.method === 'POST')).toBe(true))
    // The node settings section is unchanged.
    expect(screen.getByRole('heading', { name: '节点设置' })).toBeInTheDocument()
  })

  it('submits a migration only with a pinned host key and the typed host confirmation', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage'])
    const calls: Array<[string, RequestInit | undefined]> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(backupFetch(calls))
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    await user.click(await screen.findByRole('tab', { name: '维护操作' }))
    await screen.findAllByText('20261017T030000Z-abcdefgh', { selector: 'td' })
    fireEvent.change(screen.getByLabelText('新主控 IP 或域名'), { target: { value: '203.0.113.9' } })
    fireEvent.change(screen.getByLabelText('密码', { selector: 'input[type="password"]' }), { target: { value: 'ssh-secret' } })
    fireEvent.change(screen.getByLabelText('输入新主控地址确认'), { target: { value: 'wrong' } })
    await user.click(screen.getByRole('button', { name: '开始迁移' }))
    await waitFor(() => expect(screen.getByText('请先获取并核对主机指纹')).toBeInTheDocument())
    expect(calls.some(([url]) => url.includes('/migrations'))).toBe(false)
    fireEvent.change(screen.getByLabelText('主机指纹'), { target: { value: 'SHA256:' + 'B'.repeat(43) } })
    fireEvent.change(screen.getByLabelText('输入新主控地址确认'), { target: { value: '203.0.113.9' } })
    await user.click(screen.getByRole('button', { name: '开始迁移' }))
    await waitFor(() => expect(calls.some(([url]) => url.includes('/migrations'))).toBe(true))
    const body = JSON.parse(String(calls.find(([url]) => url.includes('/migrations'))![1]!.body))
    expect(body).toMatchObject({ host: '203.0.113.9', port: 22, user: 'root', password: 'ssh-secret', confirm: '203.0.113.9' })
  })

  it('A07: without node permissions lists the other entry points, offers no draft form or dead button', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(json(String(input).includes('/v1/admin/control-backup') ? emptyBackupStatus : listResponse())))
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])

    await user.click(await screen.findByRole('tab', { name: '维护操作' }))
    const section = screen.getByRole('heading', { name: '节点设置' }).closest('section')!
    expect(within(section).getByText('其他节点设置：')).toBeInTheDocument()
    expect(within(section).queryByText(/本版不提供/)).not.toBeInTheDocument()
    expect(within(section).getByText(/节点 Agent 直接上报主控，不再使用 Elasticsearch \/ filebeat/)).toBeInTheDocument()
    expect(within(section).queryByRole('heading', { name: '更换主控连接地址' })).not.toBeInTheDocument()
    expect(within(section).queryAllByRole('checkbox')).toHaveLength(0)
    expect(within(section).queryAllByRole('textbox')).toHaveLength(0)
    expect(within(section).queryByRole('button', { name: '创建设置任务' })).not.toBeInTheDocument()
    expect(within(section).queryByText(/filebeat=|es_ip=|master_ip=/)).not.toBeInTheDocument()
    expect(within(section).getByRole('link', { name: '网关管理' })).toHaveAttribute('href', '/dashboard/sys/gateways')
    expect(within(section).getByRole('link', { name: '节点列表' })).toHaveAttribute('href', '/dashboard/node/list')
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
  })

  it('fix-nodegw: node settings sends a new Gateway address with MFA and shows each node state with retry', async () => {
    authenticate(['control.upgrades.read', 'control.upgrades.manage', 'nodes.read', 'nodes.manage'])
    const changeID = '9b2f6a0e-1111-4c2a-8f00-000000000001'
    const change = { id: changeID, address: 'gateway.cdnca.com:9443', server_name: 'gateway.cdnca.com', target_kind: 'all',
      node_count: 3, counts: { pending: 0, probing: 1, switched: 1, failed: 1, superseded: 0 }, created_at: '2026-10-28T03:00:00Z',
      created_by_user_id: '9b2f6a0e-1111-4c2a-8f00-000000000009' }
    const detail = { ...change, nodes: [
      { node_id: 'n1', display_id: '1', name: 'hk-1', region: 'hk', state: 'switched', attempts: 1, active_address: 'gateway.cdnca.com:9443', updated_at: '2026-10-28T03:01:00Z' },
      { node_id: 'n2', display_id: '2', name: 'hk-2', region: 'hk', state: 'probing', attempts: 1, updated_at: '2026-10-28T03:01:00Z' },
      { node_id: 'n3', display_id: '3', name: 'sg-1', region: 'sg', state: 'failed', error_code: 'dial_failed', attempts: 1, active_address: 'old.cdnca.com:443', updated_at: '2026-10-28T03:01:00Z' },
    ] }
    const calls: Array<[string, RequestInit | undefined]> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      calls.push([url, init])
      if (url.includes('/v1/admin/control-backup')) return Promise.resolve(json(emptyBackupStatus))
      if (url.includes('/step-up-proofs')) return Promise.resolve(json({ token: 's'.repeat(43) }, 201))
      if (url.endsWith(`/node-gateway-address-changes/${changeID}/retry`)) return Promise.resolve(json({ retried: 1 }))
      if (url.endsWith(`/node-gateway-address-changes/${changeID}`)) return Promise.resolve(json(detail))
      if (url.endsWith('/node-gateway-address-changes') && init?.method === 'POST') return Promise.resolve(json({ ...change, id: 'new', counts: { pending: 3, probing: 0, switched: 0, failed: 0, superseded: 0 } }, 201))
      if (url.endsWith('/node-gateway-address-changes')) return Promise.resolve(json({ items: [change] }))
      if (url.includes('/v1/nodes')) return Promise.resolve(json({ items: [] }))
      return Promise.resolve(json(listResponse()))
    })
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    await user.click(await screen.findByRole('tab', { name: '维护操作' }))
    const panel = (await screen.findByRole('heading', { name: '更换主控连接地址' })).closest('section')!
    expect(await within(panel).findByText('全部节点切换完成前，请保持旧地址可用。')).toBeInTheDocument()
    expect(within(panel).getByText('1/3 已切换')).toBeInTheDocument()

    await user.click(within(panel).getByText('gateway.cdnca.com:9443'))
    expect(await within(panel).findByText('连不上新地址，或证书/SNI 校验未通过')).toBeInTheDocument()
    expect(within(panel).getByText('探测中')).toBeInTheDocument()
    expect(within(panel).getByText('已切换')).toBeInTheDocument()
    const retryButton = within(panel).getByRole('button', { name: '重试失败节点' })
    expect(retryButton).toBeDisabled()
    await user.type(within(panel).getByLabelText('输入验证码后重试'), '654321')
    await user.click(retryButton)
    await waitFor(() => expect(calls.some(([url]) => url.endsWith('/retry'))).toBe(true))
    expect(JSON.parse(String(calls.find(([url]) => url.endsWith('/retry'))![1]!.body))).toEqual({ step_up_token: 's'.repeat(43) })

    await user.type(within(panel).getByLabelText('新连接地址'), 'gateway.cdnca.com')
    await user.type(within(panel).getByLabelText('两步验证码'), '123456')
    await user.click(within(panel).getByRole('button', { name: '下发新地址' }))
    expect(await within(panel).findByText('请输入 主机:端口，端口 1–65535')).toBeInTheDocument()
    expect(calls.some(([url, init]) => url.endsWith('/node-gateway-address-changes') && init?.method === 'POST')).toBe(false)
    await user.type(within(panel).getByLabelText('新连接地址'), ':9443')
    await user.click(within(panel).getByRole('button', { name: '下发新地址' }))
    await waitFor(() => expect(calls.some(([url, init]) => url.endsWith('/node-gateway-address-changes') && init?.method === 'POST')).toBe(true))
    const proof = calls.filter(([url]) => url.includes('/step-up-proofs')).at(-1)!
    expect(JSON.parse(String(proof[1]!.body))).toMatchObject({ audience: 'node-gateway-address', action: 'node.gateway_address.change',
      authentication: { method: 'totp', code: '123456' } })
    const created = calls.find(([url, init]) => url.endsWith('/node-gateway-address-changes') && init?.method === 'POST')!
    expect(JSON.parse(String(created[1]!.body))).toEqual({ address: 'gateway.cdnca.com:9443', server_name: '', target_kind: 'all',
      step_up_token: 's'.repeat(43) })
  })

  it('fix-nodegw: a read-only node viewer sees the change history but no form', async () => {
    authenticate(['control.upgrades.read', 'nodes.read'])
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/v1/admin/control-backup')) return Promise.resolve(json(emptyBackupStatus))
      if (url.endsWith('/node-gateway-address-changes')) return Promise.resolve(json({ items: [] }))
      if (url.includes('/v1/nodes')) return Promise.resolve(json({ items: [] }))
      return Promise.resolve(json(listResponse()))
    })
    const user = userEvent.setup()
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    await user.click(await screen.findByRole('tab', { name: '维护操作' }))
    const panel = (await screen.findByRole('heading', { name: '更换主控连接地址' })).closest('section')!
    expect(within(panel).getByText('当前账号只能查看，不能下发新地址。')).toBeInTheDocument()
    expect(await within(panel).findByText('还没有更换过主控连接地址。')).toBeInTheDocument()
    expect(within(panel).queryByRole('button', { name: '下发新地址' })).not.toBeInTheDocument()
  })

  it.each([
    ['en-US', 'Maintenance actions', 'Control backup and migration', 'Gateway management'],
    ['zh-TW', '維護操作', '主控備份與遷移', '網關管理'],
  ] as const)('renders the maintenance panel in %s', async (locale, tab, title, gatewayLink) => {
    await changeLocale(locale)
    authenticate(['control.upgrades.read', 'control.upgrades.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(json(String(input).includes('/v1/admin/control-backup') ? emptyBackupStatus : listResponse())))
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])

    await userEvent.click(await screen.findByRole('tab', { name: tab }))
    expect(screen.getByRole('heading', { name: title })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: gatewayLink })).toBeInTheDocument()
    expect(fetchSpy.mock.calls.every(([, init]) => init?.method === undefined)).toBe(true)
  })

  it('fails closed before requests when the platform session lacks rollout read permission', () => {
    authenticate(['control.upgrades.check'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])

    expect(screen.getByText('无权查看升级计划')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('keeps English leaves complete and inherits the expanded pseudo locale', async () => {
    expect(leafPaths(enUS.controlUpgrades).sort()).toEqual(leafPaths(zhCN.controlUpgrades).sort())
    const maintenanceKeys = leafPaths(i18n.getResourceBundle('zh-CN', 'maintenanceUpgrade')).sort()
    expect(leafPaths(i18n.getResourceBundle('en-US', 'maintenanceUpgrade')).sort()).toEqual(maintenanceKeys)
    for (const key of maintenanceKeys) {
      expect(i18n.getFixedT('qps-ploc', 'maintenanceUpgrade')(key)).toMatch(/^［.+］$/)
    }
    authenticate(['control.upgrades.read'])
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(json(String(input).includes('/v1/admin/control-backup') ? emptyBackupStatus : { data: [], page: 1, page_size: 20, total: 0 })))
    await changeLocale('qps-ploc')
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])

    expect(screen.getByRole('heading', { name: /［.*维~护~升~级~.*］/ })).toBeInTheDocument()
    expect(await screen.findByRole('heading', { name: /［.*主~控~升~级~.*］/ })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: /［.*维~护~操~作~.*］/ }))
    expect(screen.getByRole('heading', { name: /［.*迁~移~主~控~.*］/ })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /［.*网~关~管~理~.*］/ })).toBeInTheDocument()
    const backupKeys = leafPaths(i18n.getResourceBundle('zh-CN', 'controlBackup')).sort()
    expect(leafPaths(i18n.getResourceBundle('en-US', 'controlBackup')).sort()).toEqual(backupKeys)
  })

  it('G2: a failed node list shows only the error with a retry, not "no nodes"', async () => {
    authenticate(['control.upgrades.read', 'nodes.read'])
    let fail = true
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/nodes') return Promise.resolve(fail ? json({ error: { code: 'internal_error' } }, 500) : json({ items: [] }))
      if (url.pathname.endsWith('/maintenance-upgrade-status')) return Promise.resolve(json({ data: maintenanceStatus() }))
      return Promise.resolve(json(listResponse()))
    })
    renderWithProviders(<ControlUpgradesPage />, ['/sys/op'])
    const failure = await screen.findByText('节点版本读取失败，请稍后重试。', { selector: '.data-state-error span' })
    expect(screen.queryByText('暂无节点')).not.toBeInTheDocument()
    fail = false
    fireEvent.click(within(failure.closest('.data-state-error') as HTMLElement).getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无节点')).toBeInTheDocument()
  })
})
