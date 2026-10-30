import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'

import type { L2Config, L2Node, L2NodeCandidate, NodeLineGroup } from '../api/nodeScheduling'
import type { NodeInventoryItem } from '../api/nodes'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import NodeL2TopologyDetailPage from '../pages/NodeL2TopologyDetailPage'
import detailCSS from '../pages/NodeL2TopologyDetailPage.css?raw'
import { nodeManagementSettingsFixture, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// OutcomeUnknown 的标题同时出现在恢复条和说明弹窗里，这里只认原位的恢复条。
const OUTCOME_BAR = { selector: '.cdnca-outcome-bar .ant-alert-message' }

const groupID = '11111111-1111-4111-8111-111111111111'
const scopeID = '22222222-2222-4222-8222-222222222222'
const foreignScope = '99999999-9999-4999-8999-999999999999'
const nodeID = '44444444-4444-4444-8444-444444444444'
const availableID = '66666666-6666-4666-8666-666666666666'
const group: NodeLineGroup = {
  id: groupID,
  display_id: '7',
  tenant_scope_id: scopeID,
  revision: 7,
  name: '华东线路',
  region: 'cn-east',
  resolved_value: 'line-east',
  ipv4_resolved_value: 'v4-line-east',
  l2_config_id: null,
  failover_mode: 'primary_offline',
  note: '',
  sort_order: 100,
  health_policy: {
    probe_interval_ms: 10_000,
    probe_timeout_ms: 3_000,
    failure_threshold: 3,
    recovery_threshold: 3,
    failure_debounce_ms: 0,
    recovery_debounce_ms: 0,
  },
  endpoints: [
    {
      id: '33333333-3333-4333-8333-333333333333',
      display_id: '42',
      node_id: nodeID,
      address: '192.0.2.10',
      port: 443,
      region: 'cn-east',
      carrier: '',
      priority: 0,
      sort_order: 100,
      weight: 80,
      enabled: true,
      health: {
        status: 'healthy',
        consecutive_successes: 3,
        consecutive_failures: 0,
        last_sequence: 8,
        last_changed_at: '2026-10-09T00:00:00Z',
        row_revision: 2,
      },
    },
  ],
  configuration_digest: 'a'.repeat(64),
  created_by_user_id: nodeID,
  created_at: '2026-10-09T00:00:00Z',
  sealed_at: '2026-10-09T00:00:00Z',
}
const inventory: NodeInventoryItem[] = [nodeID, availableID].map((id, index) => ({
  id,
  display_id: String(index + 1),
  name: `节点${index + 1}`,
  description: '',
  region: 'cn-east',
  ipv4: index ? '192.0.2.20' : '192.0.2.10',
  admin_state: 'active',
  revision: 1,
  management_settings: nodeManagementSettingsFixture(),
  created_at: '2026-10-09T00:00:00Z',
  updated_at: '2026-10-09T00:00:00Z',
  presence: { status: 'online', projection_freshness: 'fresh', lease_signal: 'present' },
}))
const config: L2Config = {
  id: groupID,
  display_id: '7',
  tenant_scope_id: scopeID,
  revision: 3,
  name: '华东L2',
  region: 'cn-east',
  remark: '',
  mode: 'cache',
  load_method: 'rr',
  created_at: '2026-10-09T00:00:00Z',
  updated_at: '2026-10-09T00:00:00Z',
}
const l2Node: L2Node = {
  id: '77777777-7777-4777-8777-777777777777',
  display_id: '3',
  tenant_scope_id: scopeID,
  revision: 4,
  config_id: groupID,
  node_id: nodeID,
  name: '已配置节点',
  ip_address: '192.0.2.10',
  admin_state: 'active',
  online_status: 'online',
  enabled: true,
  weight: 80,
  sort: 1,
  condition_id: null,
  condition_name: null,
}
const candidate: L2NodeCandidate = {
  node_id: availableID,
  display_id: '4',
  name: '可用节点',
  ip_address: '192.0.2.20',
  admin_state: 'active',
  online_status: 'online',
}

beforeEach(() => sessionStorage.clear())

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise
  })
  return { promise, resolve }
}

function authenticate(
  permissions = ['node_scheduling.read', 'node_scheduling.manage', 'nodes.read'],
) {
  useSessionStore.setState({
    accessToken: 'access-token',
    sessionEpoch: 7,
    expiresAt: Date.now() + 60_000,
    principal: principal({ permissions }),
    status: 'authenticated',
  })
}

function QueryClientCapture({ onCapture }: { onCapture: (client: QueryClient) => void }) {
  onCapture(useQueryClient())
  return null
}

function renderDetail(onQueryClient?: (client: QueryClient) => void) {
  return renderWithProviders(
    <>
      {onQueryClient ? <QueryClientCapture onCapture={onQueryClient} /> : null}
      <Routes>
        <Route path="/node/l2-config/node/:id" element={<NodeL2TopologyDetailPage />} />
      </Routes>
    </>,
    [`/node/l2-config/node/${groupID}`],
  )
}

function renderLineDetail(search = '', onQueryClient?: (client: QueryClient) => void) {
  return renderWithProviders(
    <>
      {onQueryClient ? <QueryClientCapture onCapture={onQueryClient} /> : null}
      <Routes>
        <Route path="/node/line-group" element={<h1>线路分组列表</h1>} />
        <Route path="/node/line-group/line/:id" element={<NodeL2TopologyDetailPage />} />
      </Routes>
    </>,
    [`/node/line-group/line/${groupID}${search}`],
  )
}

function lineRead(input: RequestInfo | URL, item = group) {
  const url = String(input)
  if (url.startsWith('/v1/nodes?')) return json({ items: inventory })
  if (url.split('?')[0] === '/v1/node-line-groups') return json({ items: [item] })
  return json(item)
}

function l2Read(input: RequestInfo | URL, item = config) {
  const url = String(input)
  if (url === '/v1/l2-configs') return json({ items: [item] })
  if (url.startsWith('/v1/l2-configs/')) return json(item)
  if (url.includes('available=true')) return json({ items: [candidate] })
  if (url.startsWith('/v1/l2-nodes?')) return json({ items: [l2Node] })
  if (url === '/v1/l2-conds') return json({ items: [] })
  throw new Error(`Unexpected read ${url}`)
}

async function selectConfiguredLine(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByText('192.0.2.10')
  const checkboxes = within(screen.getByTestId('configured-line-ip-table-scroll')).getAllByRole(
    'checkbox',
  )
  await user.click(checkboxes.at(-1)!)
}

async function disableLine(user: ReturnType<typeof userEvent.setup>) {
  await selectConfiguredLine(user)
  await user.click(screen.getByRole('button', { name: '禁用' }))
  await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '确定' }))
}

describe('canonical line resolution', () => {
  beforeEach(() => authenticate())

  it('labels and routes the back action to line groups, not L2 configuration', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => lineRead(input))
    const user = userEvent.setup()
    renderLineDetail()
    await screen.findByText('节点1')
    expect(screen.queryByRole('button', { name: '返回 L2 配置' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '返回' }))
    expect(await screen.findByRole('heading', { name: '线路分组列表' })).toBeInTheDocument()
  })

  it('loads real inventory and group endpoints into two equal-width panes without L2 snapshot calls', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) => lineRead(input))
    renderLineDetail()
    expect(await screen.findByText('节点2')).toBeInTheDocument()
    expect(await screen.findByText('节点1')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '区域' })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '分组' })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '当前线路' })).toBeInTheDocument()
    expect(
      within(screen.getByTestId('configured-line-ip-table-scroll'))
        .getAllByRole('columnheader')
        .map((cell) => cell.textContent?.trim()),
    ).toEqual(['', 'ID', '名称', 'IP地址', '在线状态', '启用', '主备', '探测', '解析', '权重', '排序'])
    expect(screen.getByTitle(group.endpoints[0]!.id)).toHaveTextContent('42')
    expect(detailCSS).toContain('grid-template-columns: minmax(0, 1fr) minmax(0, 1fr)')
    expect(detailCSS).toContain('@media (max-width: 767px)')
    expect(detailCSS).toContain('.node-line-resolution-detail-page .node-scheduling-alert {\n    display: block;')
    expect(
      fetchSpy.mock.calls.some(([url]) =>
        /l2-configs|target-snapshots|decisions/.test(String(url)),
      ),
    ).toBe(false)
  })

  it.each([
    ['zh-CN', '返回', '区域:', '分组:', '暂无数据', '请选择节点!', '请选择IP!'],
    ['qps-ploc', '［返回］', '［区域:］', '［分组:］', '［暂无数据］', '［请选择节点!］', '［请选择IP!］'],
  ])('matches the observed empty resolution state and no-selection feedback in %s', async (locale, back, region, groupLabel, empty, nodesWarning, ipsWarning) => {
    await i18n.changeLanguage(locale)
    const t = i18n.getFixedT(locale, 'nodeScheduling')
    const l2T = i18n.getFixedT(locale, 'nodeL2Topology')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      String(input).startsWith('/v1/nodes?') ? json({ items: [] }) : lineRead(input, { ...group, endpoints: [] }),
    )
    const user = userEvent.setup()
    renderLineDetail()
    await waitFor(() => expect(screen.getByRole('button', { name: t('lineDetail.actions.batchAdd') })).toBeEnabled())
    expect(screen.getByRole('button', { name: back })).toBeInTheDocument()
    expect(screen.getByText(region)).toBeInTheDocument()
    expect(screen.getByText(groupLabel)).toBeInTheDocument()
    expect(screen.getAllByText(empty)).toHaveLength(2)
    // The no-selection warning is a feedback dialog (useFeedback().warning); no
    // editor dialog opens. Acknowledge it before the next action.
    const ackText = /^(知道了|Got it)$/
    const expectOnlyWarning = async (warning: string) => {
      const feedback = (await screen.findByText(warning, { selector: '.cdnca-feedback-title span' })).closest('[role="dialog"]') as HTMLElement
      expect(feedback).toHaveClass('cdnca-feedback-warning')
      expect(screen.getAllByRole('dialog')).toEqual([feedback])
      await user.click(within(feedback).getByRole('button', { name: ackText }))
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    }
    for (const action of ['batchAdd', 'batchStandby']) {
      await user.click(screen.getByRole('button', { name: t(`lineDetail.actions.${action}`) }))
      await expectOnlyWarning(nodesWarning)
    }
    for (const action of ['enable', 'disable', 'delete']) {
      await user.click(screen.getByRole('button', { name: t(`lineDetail.actions.${action}`) }))
      await expectOnlyWarning(ipsWarning)
    }
    await user.click(screen.getByRole('button', { name: t('lineDetail.actions.more') }))
    expect(await screen.findAllByRole('menuitem')).toHaveLength(6)
    await user.click(screen.getByRole('menuitem', { name: l2T('line.weight') }))
    await expectOnlyWarning(ipsWarning)
    expect(fetchSpy.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true)
    expect(sessionStorage.length).toBe(0)
  })

  it('keeps both search icons inside the fields and filters and clears without a submit action', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => lineRead(input))
    const user = userEvent.setup()
    renderLineDetail()
    await screen.findByText('节点2')
    for (const name of ['搜索可添加 IP', '搜索已配置 IP']) {
      const search = screen.getByRole('searchbox', { name })
      expect(search.closest('.ant-input-affix-wrapper')).toHaveClass('node-line-resolution-search')
      expect(search.closest('.ant-input-affix-wrapper')?.querySelector('.ant-input-suffix svg')).not.toBeNull()
      expect(search.closest('.ant-input-group-wrapper')).toBeNull()
    }
    await user.type(screen.getByRole('searchbox', { name: '搜索可添加 IP' }), 'not-a-node')
    expect(screen.queryByText('节点2')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '清除' }))
    expect(screen.getByRole('searchbox', { name: '搜索可添加 IP' })).toHaveValue('')
    expect(await screen.findByText('节点2')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true)
  })

  it('keeps empty-table sizing, header separators and current-line width scoped to the resolution page', () => {
    expect(detailCSS).toMatch(/\.node-line-resolution-detail-page \.node-line-resolution-table-scroll \.ant-table-tbody > \.ant-table-placeholder > td\s*\{[^}]*height: 48px;[^}]*padding: 0 !important;/)
    expect(detailCSS).toMatch(/\.node-line-resolution-detail-page \.node-line-resolution-table-scroll \.ant-table-placeholder \.ant-table-expanded-row-fixed\s*\{[^}]*padding: 0;[^}]*margin: 0;/)
    expect(detailCSS).toMatch(/\.node-line-resolution-detail-page \.node-line-resolution-table-scroll \.ant-table-thead > tr > th::before\s*\{[^}]*display: none;/)
    expect(detailCSS).toMatch(/\.node-line-resolution-panes h2 \.ant-select\s*\{[^}]*width: 220px;[^}]*flex: 0 1 220px;/)
    expect(detailCSS).not.toMatch(/\.node-line-resolution-table-scroll\s*\{[^}]*overflow-x: auto;/)
    expect(detailCSS).toContain('grid-template-columns: minmax(0, 1fr)')
  })

  it.each(['online', 'offline', 'unknown'] as const)('renders %s as a truthful compact presence icon and text, not a tag', async (status) => {
    const items = inventory.map((item) => ({ ...item, presence: { ...item.presence, status } }))
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      String(input).startsWith('/v1/nodes?') ? json({ items }) : lineRead(input),
    )
    renderLineDetail()
    const row = (await screen.findByText('192.0.2.10')).closest('tr')!
    const text = within(row).getByText(i18n.t(`nodeL2Topology:nodes.${status}`))
    expect(text).toHaveClass('node-line-resolution-presence', `is-${status}`)
    expect(text.closest('.ant-tag')).toBeNull()
    expect(text.querySelector('svg')).toHaveAttribute('aria-hidden', 'true')
    expect(text.querySelector('svg')?.getAttribute('class')).toContain(status === 'online' ? 'lucide-circle-check' : status === 'offline' ? 'lucide-circle-x' : 'lucide-circle-question-mark')
    expect(within(row).getByText('42')).toBeInTheDocument()
    expect(within(row).getByText('100')).toBeInTheDocument()
  })

  it('uses fixed local column allocation with the persisted endpoint display ID and sort value', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => lineRead(input))
    renderLineDetail()
    await screen.findByText('192.0.2.10')
    const available = screen.getByTestId('available-line-ip-table-scroll')
    const configured = screen.getByTestId('configured-line-ip-table-scroll')
    expect(within(available).getByRole('table')).toHaveStyle({ tableLayout: 'fixed' })
    expect(within(configured).getByRole('table')).toHaveStyle({ tableLayout: 'fixed' })
    expect(available.querySelector('col')).toHaveStyle({ width: '50px' })
    expect(configured.querySelector('col')).toHaveStyle({ width: '44px' })
    expect(configured.querySelectorAll('col')[3]).toHaveStyle({ width: '220px' })
    expect(screen.getByTitle(group.endpoints[0]!.id)).toHaveTextContent('42')
    expect(screen.getByText('100')).toBeInTheDocument()
    expect(screen.getByText('节点1').closest('td')).toHaveClass('node-line-resolution-name')
    expect(screen.getByText('192.0.2.10').closest('td')).toHaveClass('node-line-resolution-address')
    expect(detailCSS).toMatch(/\.node-line-resolution-detail-page \.node-line-resolution-table-scroll td\.node-line-resolution-name,\s*\.node-line-resolution-detail-page \.node-line-resolution-table-scroll td\.node-line-resolution-address\s*\{[^}]*white-space: normal;[^}]*overflow-wrap: anywhere;/)
  })

  it('keeps observed return/tool spacing and enabled delete/presence colors page-scoped', () => {
    expect(detailCSS).toMatch(/\.node-line-resolution-detail-page\s*\{[^}]*padding: 18px 20px 20px;/)
    expect(detailCSS).toMatch(/\.node-line-resolution-navigation > \.ant-btn\s*\{[^}]*padding-inline: 2px;[^}]*margin-inline-end: 26px;/)
    expect(detailCSS).toMatch(/\.node-line-resolution-actions\s*\{[^}]*margin-inline-start: -8px;/)
    expect(detailCSS).toMatch(/\.node-line-resolution-actions \.ant-btn-link\s*\{[^}]*padding-inline: 0;/)
    expect(detailCSS).toMatch(/\.node-line-resolution-actions \.line-delete:not\(:disabled\)\s*\{[^}]*background: var\(--cdnca-color-error\);[^}]*border-color: var\(--cdnca-color-error\);/)
    expect(detailCSS).toMatch(/\.node-line-resolution-presence\s*\{[^}]*color: var\(--cdnca-color-text-secondary\);/)
    expect(detailCSS).toMatch(/\.node-line-resolution-presence\.is-online > svg\s*\{[^}]*fill: var\(--cdnca-color-success\);/)
  })

  it.each([
    ['启用', 'lucide-play'],
    ['禁用', 'lucide-pause'],
  ])('renders the %s action with the observed filled library icon', async function lineActionFilledIconTest(name, iconClass) {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => lineRead(input))
    renderLineDetail()
    await screen.findByText('192.0.2.10')
    const icon = screen.getByRole('button', { name }).querySelector('svg')
    expect(icon).toHaveClass(iconClass)
    expect(icon).toHaveAttribute('fill', 'currentColor')
    expect(icon).toHaveAttribute('stroke-width', '0')
    expect(icon).toHaveAttribute('aria-hidden', 'true')
  })

  it('does not turn unreadable node inventory into an actionable empty selection', async () => {
    authenticate(['node_scheduling.read', 'node_scheduling.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => lineRead(input))
    const user = userEvent.setup()
    renderLineDetail()
    await screen.findByText('192.0.2.10')
    for (const name of ['批量添加', '批量备用']) {
      expect(screen.getByRole('button', { name })).toBeDisabled()
      await user.click(screen.getByRole('button', { name }))
    }
    expect(screen.queryByText('请选择节点!')).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([input]) => String(input).startsWith('/v1/nodes'))).toBe(false)
    expect(fetchSpy.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true)
  })

  it('keeps action buttons and menu disabled while pending and after an uncertain result', async () => {
    const pending = deferred<Response>()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) =>
      init?.method === 'PUT' ? pending.promise : lineRead(input),
    )
    const user = userEvent.setup()
    renderLineDetail()
    await disableLine(user)
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1))
    for (const name of ['批量添加', '批量备用', '启用', '禁用', '删除', '更多操作'])
      expect(screen.getByRole('button', { name })).toBeDisabled()
    await act(async () => pending.resolve(json({ error: { code: 'unavailable' } }, 503)))
    await screen.findByText('操作结果待确认', OUTCOME_BAR)
    // OutcomeUnknown opens its explanation dialog; the disabled actions must not open any other one.
    const explanation = (await screen.findByText('操作结果待确认', { selector: '.cdnca-feedback-title span' })).closest('[role="dialog"]')
    for (const name of ['批量添加', '批量备用', '启用', '禁用', '删除', '更多操作']) {
      expect(screen.getByRole('button', { name })).toBeDisabled()
      await user.click(screen.getByRole('button', { name }))
    }
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
    expect(screen.getAllByRole('dialog')).toEqual([explanation])
  })

  it('writes selected endpoint enabled state with If-Match and preserves unrelated snapshot fields', async () => {
    let current = structuredClone(group)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'PUT') {
        const snapshot = JSON.parse(String(init.body))
        current = { ...current, ...snapshot, revision: 8, configuration_digest: 'b'.repeat(64),
          endpoints: snapshot.endpoints.map((endpoint: NodeLineGroup['endpoints'][number]) => ({ ...endpoint,
            health: { status: 'unknown', consecutive_successes: 0, consecutive_failures: 0,
              last_sequence: 0, last_observed_at: null, last_changed_at: group.created_at, row_revision: 1 } })) }
        return json({ group: current, replayed: false })
      }
      return lineRead(input, current)
    })
    renderLineDetail()
    await disableLine(userEvent.setup())
    expect(await screen.findByText('解析配置已保存')).toBeInTheDocument()
    const write = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PUT')!
    expect(String(write[0])).toBe(`/v1/node-line-groups/${groupID}`)
    const body = JSON.parse(String(write[1]?.body))
    expect(body.endpoints[0]).toMatchObject({
      id: group.endpoints[0]!.id,
      enabled: false,
      weight: 80,
      priority: 0,
      port: 443,
    })
    expect(body.health_policy).toEqual(group.health_policy)
    expect(body.endpoints[0]).not.toHaveProperty('display_id')
    expect(new Headers(write[1]?.headers).get('If-Match')).toBe('"7"')
    expect(new Headers(write[1]?.headers).get('Idempotency-Key')).toBeTruthy()
  })

  it('paginates and filters persisted line endpoints without inventing another resource', async () => {
    const endpoints = Array.from({ length: 11 }, (_, index) => ({
      ...group.endpoints[0]!,
      id: `33333333-3333-4333-8333-${String(index + 1).padStart(12, '0')}`,
      display_id: String(index + 42),
      address: `192.0.2.${index + 10}`,
    }))
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      lineRead(input, { ...group, endpoints }),
    )
    const user = userEvent.setup()
    renderLineDetail()
    const table = screen.getByTestId('configured-line-ip-table-scroll')
    await within(table).findByText('192.0.2.10')
    expect(within(table).queryByText('192.0.2.20')).not.toBeInTheDocument()
    await user.click(table.querySelector<HTMLButtonElement>('.ant-pagination-next button')!)
    expect(await within(table).findByText('192.0.2.20')).toBeInTheDocument()
    expect(within(table).getByTitle(endpoints[10]!.id)).toHaveTextContent('52')
    await user.type(screen.getByLabelText('搜索已配置 IP'), '192.0.2.20')
    expect(await within(table).findByTitle(endpoints[10]!.id)).toHaveTextContent('52')
    await user.clear(screen.getByLabelText('搜索已配置 IP'))
    await user.type(screen.getByLabelText('搜索已配置 IP'), '192.0.2.10')
    expect(await within(table).findByText('192.0.2.10')).toBeInTheDocument()
    expect(within(table).getByTitle(endpoints[0]!.id)).toHaveTextContent('42')
    expect(within(table).queryByText('192.0.2.20')).not.toBeInTheDocument()
  })

  it('does not fabricate a row ID for a legacy receipt without display metadata', async () => {
    const legacy = structuredClone(group)
    delete legacy.endpoints[0]!.display_id
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => lineRead(input, legacy))
    renderLineDetail()
    expect(await screen.findByTitle(group.endpoints[0]!.id)).toHaveTextContent(i18n.t('nodeScheduling:values.unavailable'))
  })

  it('adds selected real inventory addresses without requiring internal IDs', async () => {
    let current = structuredClone(group)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'PUT') {
        const snapshot = JSON.parse(String(init.body))
        current = { ...current, ...snapshot, revision: 8, configuration_digest: 'b'.repeat(64),
          endpoints: snapshot.endpoints.map((endpoint: NodeLineGroup['endpoints'][number]) => ({ ...endpoint,
            health: { status: 'unknown', consecutive_successes: 0, consecutive_failures: 0,
              last_sequence: 0, last_observed_at: null, last_changed_at: group.created_at, row_revision: 1 } })) }
        return json({ group: current, replayed: false })
      }
      return lineRead(input, current)
    })
    const user = userEvent.setup()
    renderLineDetail()
    await screen.findByText('节点2')
    await user.click(
      within(screen.getByTestId('available-line-ip-table-scroll')).getAllByRole('checkbox').at(-1)!,
    )
    await user.click(screen.getByRole('button', { name: '批量添加' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).queryByRole('textbox')).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() =>
      expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(true),
    )
    const body = JSON.parse(
      String(fetchSpy.mock.calls.find(([, init]) => init?.method === 'PUT')![1]?.body),
    )
    expect(body.endpoints).toHaveLength(2)
    expect(body.endpoints[1]).toMatchObject({
      node_id: availableID,
      address: '192.0.2.20',
      enabled: true,
    })
    expect(await screen.findByText('解析配置已保存')).toBeInTheDocument()
  })

  it('shows all six observed more actions and persists endpoint sort values', async () => {
    let current = structuredClone(group)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'PUT') {
        const snapshot = JSON.parse(String(init.body))
        current = { ...current, ...snapshot, revision: current.revision + 1, configuration_digest: 'b'.repeat(64),
          endpoints: snapshot.endpoints.map((endpoint: NodeLineGroup['endpoints'][number]) => ({ ...endpoint,
            health: { status: 'unknown', consecutive_successes: 0, consecutive_failures: 0,
              last_sequence: 0, last_observed_at: null, last_changed_at: group.created_at, row_revision: 1 } })) }
        return json({ group: current, replayed: false })
      }
      return lineRead(input, current)
    })
    const user = userEvent.setup()
    renderLineDetail()
    await selectConfiguredLine(user)
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    const items = await screen.findAllByRole('menuitem')
    expect(items.map((item) => item.textContent)).toEqual([
      '备用IP',
      '取消备用IP',
      '设置权重',
      '备用默认解析',
      '取消备用默认解析',
      '修改排序',
    ])
    for (const label of ['备用默认解析', '取消备用默认解析'])
      expect(screen.getByRole('menuitem', { name: label })).toHaveAttribute('aria-disabled', 'true')
    await user.click(screen.getByRole('menuitem', { name: '设置权重' }))
    const dialog = await screen.findByRole('dialog', { name: '请输入权重值' })
    fireEvent.change(within(dialog).getByRole('spinbutton'), { target: { value: '0' } })
    expect(within(dialog).getByRole('button', { name: '确定' })).toBeDisabled()
    await user.click(within(dialog).getByRole('button', { name: '取消' }))
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    await user.click(screen.getByRole('menuitem', { name: '修改排序' }))
    const sortDialog = await screen.findByRole('dialog', { name: '请输入排序值' })
    // 卡 52：契约最小为 1（服务端拒绝显式 0），输入框下限同为 1，0 无法提交。
    expect(within(sortDialog).getByRole('spinbutton')).toHaveAttribute('aria-valuemin', '1')
    expect(within(sortDialog).getByText('排序为 1 至 999999 的整数，备用IP按排序值从小到大依次启用。')).toBeInTheDocument()
    fireEvent.change(within(sortDialog).getByRole('spinbutton'), { target: { value: '20' } })
    await user.click(within(sortDialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(true))
    expect(JSON.parse(String(fetchSpy.mock.calls.find(([, init]) => init?.method === 'PUT')![1]?.body)).endpoints[0]).toMatchObject({ sort_order: 20 })
  })

  it('preserves exact unknown write bytes across a same-owner token rotation without putting tokens in caches', async () => {
    let writes = 0
    let current = structuredClone(group)
    let client!: QueryClient
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'PUT') {
        if (++writes === 1) throw new TypeError('connection reset')
        const snapshot = JSON.parse(String(init.body))
        current = { ...current, ...snapshot, revision: 8, configuration_digest: 'b'.repeat(64),
          endpoints: snapshot.endpoints.map((endpoint: NodeLineGroup['endpoints'][number]) => ({ ...endpoint,
            health: { status: 'unknown', consecutive_successes: 0, consecutive_failures: 0,
              last_sequence: 0, last_observed_at: null, last_changed_at: group.created_at, row_revision: 1 } })) }
        return json({ group: current, replayed: true })
      }
      return lineRead(input, current)
    })
    const user = userEvent.setup()
    renderLineDetail('', (value) => {
      client = value
    })
    await disableLine(user)
    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    expect(
      JSON.stringify(
        client
          .getQueryCache()
          .getAll()
          .map((query) => query.queryKey),
      ),
    ).not.toContain('access-token')
    act(() => useSessionStore.setState({ accessToken: 'rotated-token' }))
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('解析配置已保存')).toBeInTheDocument()
    const calls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')
    expect(calls).toHaveLength(2)
    expect(calls[1]![1]?.body).toBe(calls[0]![1]?.body)
    for (const header of ['If-Match', 'Idempotency-Key', 'X-Request-ID'])
      expect(new Headers(calls[1]![1]?.headers).get(header)).toBe(
        new Headers(calls[0]![1]?.headers).get(header),
      )
    expect(new Headers(calls[1]![1]?.headers).get('Authorization')).toBe('Bearer rotated-token')
  })

  it('shows a conflict without offering an unknown-result replay or leaking server detail', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) =>
      init?.method === 'PUT'
        ? json(
            { error: { code: 'node_scheduling_revision_conflict', message: 'private conflict' } },
            409,
          )
        : lineRead(input),
    )
    renderLineDetail()
    await disableLine(userEvent.setup())
    expect(await screen.findByText('线路组已被其他操作修改，请刷新后重试')).toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(screen.queryByText('private conflict')).not.toBeInTheDocument()
  })

  it.each(['success', 'error', 'forbidden'] as const)(
    'restores the stable owner retry while ignoring delayed old-session write %s',
    async (settlement) => {
      const pending = deferred<Response>()
      vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) =>
        init?.method === 'PUT' ? pending.promise : lineRead(input),
      )
      renderLineDetail()
      await disableLine(userEvent.setup())
      const recordKey = `cdnca:line-resolution-retry:tenant:${scopeID}:${principal().user_id}:${scopeID}:${groupID}`
      const originalRecord = sessionStorage.getItem(recordKey)
      expect(originalRecord).not.toBeNull()
      expect(JSON.parse(originalRecord!).phase).toBe('unknown')
      act(() => useSessionStore.setState({ accessToken: 'next-session', sessionEpoch: 8 }))
      await screen.findByText('192.0.2.10')
      expect(screen.getByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
      await act(async () =>
        pending.resolve(
          settlement === 'success'
            ? json({ group, replayed: false })
            : json(
                { error: { code: 'private', message: 'old secret' } },
                settlement === 'forbidden' ? 403 : 500,
              ),
        ),
      )
      expect(screen.queryByText('解析配置已保存')).not.toBeInTheDocument()
      expect(screen.getByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
      expect(sessionStorage.getItem(recordKey)).toBe(originalRecord)
      expect(screen.queryByText('无权查看节点调度配置')).not.toBeInTheDocument()
      expect(screen.queryByText('old secret')).not.toBeInTheDocument()
    },
  )

  it('keeps an explicitly targeted foreign tenant read-only for a platform principal', async () => {
    useSessionStore.setState({
      principal: principal({
        scope_kind: 'platform',
        scope_id: foreignScope,
        tenant_id: null,
        permissions: ['platform.admin'],
      }),
    })
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) => lineRead(input))
    renderLineDetail(`?target_scope_id=${scopeID}`)
    await screen.findByText('192.0.2.10')
    expect(screen.getByRole('button', { name: '批量添加' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '禁用' })).toBeDisabled()
    expect(fetchSpy.mock.calls.some(([url]) => String(url).startsWith('/v1/nodes'))).toBe(false)
  })

  it.each([
    ['namecom', true],
    ['cloudflare', true],
    ['dnspod_cn', false],
  ])('with DNS provider %s the carrier line selector is disabled: %s', async (providerType, unsupported) => {
    useSessionStore.setState({
      principal: principal({
        scope_kind: 'platform',
        scope_id: scopeID,
        tenant_id: null,
        permissions: ['node_scheduling.read', 'node_scheduling.manage', 'nodes.read', 'dns.read'],
      }),
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      String(input) === '/v1/dns/platform-config'
        ? json({ provider_type: providerType, identifiers: {}, secret_saved: true, ttl: 600, ip_weight: false,
          weight_supported: false, version: 1, sync: { tenants: 0 }, last_error: null })
        : lineRead(input))
    renderLineDetail(`?target_scope_id=${scopeID}`)
    await screen.findByText('192.0.2.10')
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url) === '/v1/dns/platform-config')).toBe(true))
    const selector = screen.getByRole('combobox', { name: '当前线路' })
    if (unsupported) {
      // The notice names the configured provider, not a fixed one (NET-03).
      expect(await screen.findByText(new RegExp(`当前 DNS 服务商为 ${providerType === 'namecom' ? 'Name\\.com' : 'Cloudflare'}`))).toBeInTheDocument()
      await waitFor(() => expect(selector).toBeDisabled())
    } else {
      expect(screen.queryByText(/该服务商不支持按运营商分线路/)).not.toBeInTheDocument()
      expect(selector).not.toBeDisabled()
      // An empty group can start any carrier line (NET-02).
      const user = userEvent.setup()
      await user.click(selector)
      for (const line of ['默认', '电信', '联通', '移动']) {
        expect(await screen.findByRole('option', { name: line })).toBeInTheDocument()
      }
    }
  })

  it('offers an IP already on the default line again on a carrier line and submits both (NET-02)', async () => {
    useSessionStore.setState({
      principal: principal({
        scope_kind: 'platform',
        scope_id: scopeID,
        tenant_id: null,
        permissions: ['node_scheduling.read', 'node_scheduling.manage', 'nodes.read', 'dns.read'],
      }),
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (String(input) === '/v1/dns/platform-config')
        return json({ provider_type: 'dnspod_cn', identifiers: {}, secret_saved: true, ttl: 600, ip_weight: false,
          weight_supported: false, version: 1, sync: { tenants: 0 }, last_error: null })
      if (init?.method === 'PUT') return new Response(null, { status: 503 })
      return lineRead(input)
    })
    const user = userEvent.setup()
    renderLineDetail(`?target_scope_id=${scopeID}`)
    await screen.findByText('192.0.2.10')
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url) === '/v1/dns/platform-config')).toBe(true))
    // 默认线路下 192.0.2.10 已配置，只剩 192.0.2.20 可添加。
    expect(screen.getAllByText('192.0.2.10')).toHaveLength(1)
    await user.click(screen.getByRole('combobox', { name: '当前线路' }))
    await user.click(await screen.findByRole('option', { name: '电信' }))
    // 电信线路下同一 IP 重新可添加；已配置表格只显示电信线路（为空）。
    await waitFor(() => expect(screen.getAllByText('192.0.2.10')).toHaveLength(1))
    const row = screen.getByText('192.0.2.10').closest('tr')!
    expect(row.querySelector('.node-line-resolution-name')).toHaveTextContent('节点1')
    expect(screen.queryByText('42')).not.toBeInTheDocument()
    await user.click(within(row).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '批量添加' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(true))
    const body = JSON.parse(String(fetchSpy.mock.calls.find(([, init]) => init?.method === 'PUT')![1]!.body))
    expect(body.endpoints.filter((endpoint: { address: string }) => endpoint.address === '192.0.2.10')
      .map((endpoint: { carrier: string }) => endpoint.carrier).sort()).toEqual(['', '电信'])
  })

  it('offers no new carrier line while the DNS configuration cannot be read', async () => {
    useSessionStore.setState({
      principal: principal({
        scope_kind: 'platform',
        scope_id: scopeID,
        tenant_id: null,
        permissions: ['node_scheduling.read', 'node_scheduling.manage', 'nodes.read', 'dns.read'],
      }),
    })
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      String(input) === '/v1/dns/platform-config'
        ? json({ error: { code: 'internal_error', message: 'x' } }, 500)
        : lineRead(input))
    const user = userEvent.setup()
    renderLineDetail(`?target_scope_id=${scopeID}`)
    expect(await screen.findByText(/DNS 配置读取失败，暂不能判断服务商是否支持运营商线路/)).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: '当前线路' }))
    expect(await screen.findByRole('option', { name: '默认' })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: '电信' })).not.toBeInTheDocument()
  })

  it('rejects a foreign resource response and never renders it', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      lineRead(input, { ...group, tenant_scope_id: foreignScope, name: 'foreign secret' }),
    )
    renderLineDetail()
    expect((await screen.findAllByText('节点调度配置加载失败')).length).toBeGreaterThan(0)
    expect(screen.queryByText('foreign secret')).not.toBeInTheDocument()
  })

  it('clears inventory facts immediately when nodes.read is revoked', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => lineRead(input))
    let client!: QueryClient
    renderLineDetail('', (value) => {
      client = value
    })
    expect(await screen.findByText('节点2')).toBeInTheDocument()
    act(() =>
      useSessionStore.setState({
        principal: principal({ permissions: ['node_scheduling.read', 'node_scheduling.manage'] }),
      }),
    )
    expect(screen.queryByText('节点2')).not.toBeInTheDocument()
    expect(screen.queryByText('节点1')).not.toBeInTheDocument()
    await waitFor(() =>
      expect(
        client
          .getQueryCache()
          .getAll()
          .some((item) => item.queryKey.at(-1) === 'nodes' && item.state.data),
      ).toBe(false),
    )
  })
})

describe('canonical L2 node resources', () => {
  beforeEach(() => authenticate())

  it('loads config, available/configured nodes and conditions from real L2 resources', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) => l2Read(input))
    renderDetail()
    expect(await screen.findByText('可用节点')).toBeInTheDocument()
    expect(await screen.findByText('已配置节点')).toBeInTheDocument()
    expect(screen.queryByLabelText(/UUID|L1 节点/)).not.toBeInTheDocument()
    expect(
      fetchSpy.mock.calls.some(([url]) => /node-line-groups|target-snapshots/.test(String(url))),
    ).toBe(false)
    expect(fetchSpy.mock.calls.some(([url]) => String(url).includes('available=true'))).toBe(true)
  })

  it('adds selected nodes with exact config binding and no internal identifier entry', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input, init) =>
        init?.method === 'POST'
          ? json({ items: [{ ...l2Node, node_id: availableID }] })
          : l2Read(input),
      )
    const user = userEvent.setup()
    renderDetail()
    const candidateRow = (await screen.findByText('可用节点')).closest('tr')!
    await user.click(within(candidateRow).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '批量添加' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('combobox', { name: 'L2条件' })).toBeInTheDocument()
    expect(within(dialog).queryByRole('textbox')).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('L2 配置已保存')).toBeInTheDocument()
    const write = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')!
    expect(String(write[0])).toBe('/v1/l2-nodes')
    expect(JSON.parse(String(write[1]?.body))).toEqual({
      config_id: groupID,
      node_ids: [availableID],
      condition_id: null,
    })
    expect(new Headers(write[1]?.headers).get('If-Match')).toBe('"0"')
  })

  it('edits and replays a node update with its resource revision across token refresh', async () => {
    let writes = 0
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'PUT') {
        if (++writes === 1) throw new TypeError('connection lost')
        return json({ ...l2Node, ...JSON.parse(String(init.body)), revision: 5 })
      }
      return l2Read(input)
    })
    const user = userEvent.setup()
    renderDetail()
    await user.click(await screen.findByRole('button', { name: '编辑 已配置节点' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑节点' })
    fireEvent.change(within(dialog).getByRole('spinbutton', { name: '权重' }), {
      target: { value: '70' },
    })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    act(() => useSessionStore.setState({ accessToken: 'new-token' }))
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('L2 配置已保存')).toBeInTheDocument()
    const calls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')
    expect(calls).toHaveLength(2)
    expect(String(calls[0]![0])).toBe(`/v1/l2-nodes/${l2Node.id}`)
    expect(calls[1]![1]?.body).toBe(calls[0]![1]?.body)
    expect(JSON.parse(String(calls[0]![1]?.body))).toEqual({
      condition_id: null,
      enabled: true,
      weight: 70,
      sort: 1,
    })
    expect(new Headers(calls[0]![1]?.headers).get('If-Match')).toBe('"4"')
    expect(new Headers(calls[1]![1]?.headers).get('Idempotency-Key')).toBe(
      new Headers(calls[0]![1]?.headers).get('Idempotency-Key'),
    )
    expect(new Headers(calls[1]![1]?.headers).get('Authorization')).toBe('Bearer new-token')
  })

  it('makes a current-owner 403 terminal across invalidation and token rotation', async () => {
    let client!: QueryClient
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(
        json({ error: { code: 'node_scheduling_permission_denied', message: 'private' } }, 403),
      )
    renderDetail((value) => {
      client = value
    })
    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()
    act(() => useSessionStore.setState({ accessToken: 'new-token' }))
    await act(async () => {
      await client.invalidateQueries()
      window.dispatchEvent(new Event('focus'))
      window.dispatchEvent(new Event('online'))
    })
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('saves selected node enabled state using each resource revision', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input, init) =>
        init?.method === 'PUT'
          ? json({ ...l2Node, ...JSON.parse(String(init.body)), revision: 5 })
          : l2Read(input),
      )
    const user = userEvent.setup()
    renderDetail()
    const row = (await screen.findByText('已配置节点')).closest('tr')!
    await user.click(within(row).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '禁用' }))
    await user.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: '确定' }),
    )
    expect(await screen.findByText('L2 配置已保存')).toBeInTheDocument()
    const write = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PUT')!
    expect(JSON.parse(String(write[1]?.body))).toEqual({
      condition_id: null,
      enabled: false,
      weight: 80,
      sort: 1,
    })
    expect(new Headers(write[1]?.headers).get('If-Match')).toBe('"4"')
  })

  it.each(['success', 'error', 'forbidden'] as const)(
    'ignores an old-session L2 read %s and removes old cache',
    async (settlement) => {
      const pending = deferred<Response>()
      let client!: QueryClient
      vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) =>
        new Headers(init?.headers).get('Authorization') === 'Bearer access-token'
          ? pending.promise
          : l2Read(input, { ...config, name: '新会话配置' }),
      )
      renderDetail((value) => {
        client = value
      })
      act(() => useSessionStore.setState({ accessToken: 'next-session', sessionEpoch: 8 }))
      expect(await screen.findByText('新会话配置')).toBeInTheDocument()
      await act(async () =>
        pending.resolve(
          settlement === 'success'
            ? json({ ...config, name: '旧会话秘密' })
            : json(
                { error: { code: 'private', message: '旧会话秘密' } },
                settlement === 'forbidden' ? 403 : 500,
              ),
        ),
      )
      expect(screen.queryByText('旧会话秘密')).not.toBeInTheDocument()
      expect(screen.queryByText('无权查看节点调度配置')).not.toBeInTheDocument()
      expect(
        client
          .getQueryCache()
          .getAll()
          .some((query) => JSON.stringify(query.queryKey).includes(',7]')),
      ).toBe(false)
    },
  )

  it('denies missing read permission without any request', async () => {
    authenticate(['node_scheduling.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderDetail()
    expect(await screen.findByText('无权查看节点调度配置')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('stops an open editor from writing after manage permission is revoked', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) => l2Read(input))
    const user = userEvent.setup()
    renderDetail()
    await user.click(await screen.findByRole('button', { name: '编辑 已配置节点' }))
    act(() =>
      useSessionStore.setState({ principal: principal({ permissions: ['node_scheduling.read'] }) }),
    )
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: '确定' }))
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(false)
  })
})
