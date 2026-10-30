import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { NodeInventoryItem } from '../api/nodes'
import { nodeMonitoringApi } from '../api/nodeMonitoring'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import NodeListPage from '../pages/NodeListPage'
import { authResponse, nodeManagementSettingsFixture, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// antd 测试环境里所有弹窗的 aria-labelledby 都是 test-id，同时开着 feedback 弹窗时按 name 查会串到别的弹窗；按标题文字找所属弹窗。
const DIALOG_TITLE = { selector: '.ant-modal-title, .ant-drawer-title' }
async function findDialogTitled(title: string | RegExp): Promise<HTMLElement> {
  return (await screen.findByText(title, DIALOG_TITLE)).closest('[role="dialog"]') as HTMLElement
}

beforeEach(() => {
  sessionStorage.clear()
  vi.spyOn(nodeMonitoringApi, 'getLatest').mockImplementation(async (_token, ids) => ({
    schema_version: 1, observed_at: '2026-10-10T10:00:00Z',
    configuration: { state: 'unconfigured', head_revision: 0, active_revision: null, activated_at: null, policy: null },
    items: ids.map((node_id) => ({ node_id, sample: null, freshness: 'not_reported', revision_state: 'unknown', delivery_state: 'serving', stale_after_ms: null })),
  }))
})

const node: NodeInventoryItem = {
  id: '018f0000-0000-7000-8000-000000000001',
  display_id: '1',
  name: 'Edge Shanghai',
  description: 'primary edge',
  region: 'CN-East',
  ipv4: '192.0.2.10',
  ipv6: '2001:db8::10',
  admin_state: 'disabled',
  management_settings: nodeManagementSettingsFixture(),
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

function authenticate() {
  const admin = principal({
    scope_kind: 'platform',
    tenant_id: null,
    username: 'admin',
    display_name: 'admin',
    roles: ['platform_owner'],
    permissions: ['nodes.read', 'nodes.manage'],
  })
  useSessionStore.getState().setSession(authResponse(admin), admin)
}

function json(body: unknown, status = 200): Response {
  if (typeof body === 'object' && body !== null && 'items' in body && Array.isArray(body.items) &&
    body.items.every((item) => item && 'management_settings' in item && 'presence' in item)) {
    body = { ...body, order: 'management_sort_desc' }
  }
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

async function chooseOpenOption(user: ReturnType<typeof userEvent.setup>, label: string) {
  const candidates = await screen.findAllByText(label)
  const option = candidates.find((candidate) => candidate.closest('.ant-select-item-option, .ant-dropdown-menu-item'))
  if (!option) throw new Error(`open option not found: ${label}`)
  await user.click(option)
}

async function openBatchAction(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'More actions' }))
  await user.click(await screen.findByRole('menuitem', { name: 'Batch status' }))
}

async function openRowStatus(user: ReturnType<typeof userEvent.setup>, row: HTMLElement) {
  await user.click(within(row).getByRole('button', { name: 'More' }))
  const candidates = await screen.findAllByText('Status')
  const item = candidates.find((candidate) => candidate.closest('.ant-dropdown-menu-submenu-title, .ant-dropdown-menu-item'))
  if (!item) throw new Error('row status action not found')
  await user.click(item)
}

describe('node automatic IP internationalization', function nodeNetworkStatusLocale() {
  it.each([
    // 2026-10-14 安装弹窗改为所有节点共用的注册命令，说明文案随之改为“所有节点使用同一条命令”。
    ['en-US', 'Latest source verified', 'Current IP conflicts with report', 'Every node uses the same command'],
    ['qps-ploc', '［最~近~来~源~核~验~一~致~］', '［当~前~ I~P~ 与~报~告~冲~突~］', '所~有~节~点~使~用~同~一~条~命~令~'],
  ] as const)('localizes independent source states and installation guidance in %s', async (locale, verified, conflict, installation) => {
    await changeLocale(locale)
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [{ ...node,
      network_inventory: { schema_version: 1, ipv4_state: 'verified', ipv6_state: 'address_conflict', received_at: '2026-07-22T08:59:55Z' },
    }] }))
    const user = userEvent.setup()
    renderWithProviders(<NodeListPage />)
    const row = (await screen.findByRole('button', { name: node.name })).closest('tr')!
    expect(within(row).getByRole('note', { name: (name) => name.includes(verified) })).toBeInTheDocument()
    expect(within(row).getByRole('note', { name: (name) => name.includes(conflict) })).toBeInTheDocument()
    expect(row).not.toHaveTextContent(verified)
    expect(row).not.toHaveTextContent('address_conflict')
    expect(row).not.toHaveTextContent('network.states.')
    const notes = within(row).getAllByRole('note')
    await user.hover(notes[0]!)
    expect(await screen.findByRole('tooltip')).not.toHaveTextContent('receivedAt')
    await user.unhover(notes[0]!)
    const installName = locale === 'en-US' ? 'Install node' : '［安~装~节~点~］'
    await user.click(screen.getByRole('button', { name: installName }))
    expect(await findDialogTitled(installName)).toHaveTextContent(installation)
  })
})

describe('NodeListPage internationalization', () => {
  it.each([
    ['en-US', 'Default'],
    ['qps-ploc', '［默~认~］'],
  ] as const)('renders the default region and zero sort in %s', async (locale, label) => {
    await changeLocale(locale)
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [{ ...node, region: '',
      management_settings: { ...node.management_settings, sort: 0 } }] }))
    renderWithProviders(<NodeListPage />)
    const row = (await screen.findByRole('button', { name: node.name })).closest('tr')!
    expect(within(row).getByText(label)).toBeInTheDocument()
    expect(within(row).getByRole('cell', { name: '0' })).toBeInTheDocument()
    expect(row).not.toHaveTextContent('region.default')
  })

  it('renders the inventory controls, states, and create form in English', async () => {
    await changeLocale('en-US')
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [node] }))
    const user = userEvent.setup()

    renderWithProviders(<NodeListPage />)

    expect(await screen.findByRole('columnheader', { name: 'Name' })).toBeInTheDocument()
    await screen.findByText('Edge Shanghai')
    expect(screen.getByRole('columnheader', { name: /^Monitoring/ })).toBeInTheDocument()
    expect(screen.getByLabelText('Search nodes on this page')).toHaveAttribute(
      'placeholder',
      'Name, IP address, region, or description on this page',
    )
    expect(screen.getByRole('combobox', { name: 'Filter by node status' })).toBeInTheDocument()
    expect(screen.getByText('Disabled')).toBeInTheDocument()
    const row = screen.getByText('Edge Shanghai').closest('tr')!
    const monitor = row.querySelector('.node-monitor-cell') as HTMLElement
    expect(await within(monitor).findByRole('link', { name: 'Not configured' })).toHaveAttribute('href', '/node/monitor-setting')
    expect(within(monitor).queryByRole('link', { name: '[Logs]' })).not.toBeInTheDocument()
    expect(within(row).getByRole('link', { name: 'View tasks' })).toHaveTextContent('[Tasks]')
    expect(monitor).not.toHaveAttribute('title', expect.stringContaining('Presence: Online'))
    expect(row.querySelector('.node-state-cell')).toHaveAttribute('title', expect.stringContaining('Presence: Online'))
    expect(row.querySelector('.node-state-cell')).toHaveAttribute('title', expect.stringContaining('Projection: Projection fresh'))
    expect(row.querySelector('.node-state-cell')).toHaveAttribute('title', expect.stringContaining('Lease: Lease valid'))
    expect(within(row).queryByText('Online')).not.toBeInTheDocument()
    expect(within(row).queryByText('Projection fresh · Lease valid')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Install node' }))
    const installDialog = await findDialogTitled('Install node')
    expect(within(installDialog).getByRole('button', { name: 'Copy installation command' })).toBeInTheDocument()
    expect(within(installDialog).queryByRole('link', { name: 'Open Maintenance upgrades' })).not.toBeInTheDocument()
    await user.click(within(installDialog).getByRole('button', { name: 'Close' }))
    await user.click(screen.getByRole('button', { name: 'More actions' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Advanced registration' }))
    const dialog = await screen.findByRole('dialog', { name: 'Add node' })
    expect(within(dialog).getByLabelText('Node name')).toHaveAttribute('placeholder', 'For example: Shanghai edge node')
    // The region is picked from the region catalog (D8), not typed.
    expect(within(dialog).getByRole('combobox', { name: 'Region' })).toBeInTheDocument()
    expect(within(dialog).getByText('Select a region')).toBeInTheDocument()
    expect(within(dialog).getByText('Issue a one-time enrollment token')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Save' })).toBeInTheDocument()
  })

  it('localizes the five-tab node editor and canonical detail route', async () => {
    await changeLocale('en-US')
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [node] }))
    const user = userEvent.setup()

    renderWithProviders(<NodeListPage />)
    const nameButton = await screen.findByRole('button', { name: 'Edge Shanghai' })
    const row = nameButton.closest('tr')!
    await user.click(within(row).getByRole('button', { name: 'More' }))
    expect(await screen.findByRole('link', { name: 'Advanced details' }))
      .toHaveAttribute('href', `/node/list/${node.id}`)
    await user.keyboard('{Escape}')
    await user.click(nameButton)

    const dialog = await screen.findByRole('dialog', { name: 'Edit node' })
    expect(within(dialog).getAllByRole('tab').map((tab) => tab.textContent)).toEqual([
      'Basic settings', 'Node settings', 'IP location', 'Automatic disable', 'Add secondary IPs',
    ])
    expect(within(dialog).queryByRole('link', { name: 'Advanced details' })).not.toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Confirm' })).toBeInTheDocument()
  })

  it('maps stable server error codes and hides the original server message', async () => {
    await changeLocale('en-US')
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'PATCH') {
        return Promise.resolve(json({
          error: { code: 'node_identity_required', message: 'internal server wording' },
        }, 409))
      }
      return Promise.resolve(json({ items: [node] }))
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeListPage />)
    await screen.findByText('Edge Shanghai')

    await openRowStatus(user, screen.getByText('Edge Shanghai').closest('tr')!)
    await chooseOpenOption(user, 'Enable (enrollment required)')
    const confirm = await screen.findByRole('dialog', { name: /Set Edge Shanghai to Enabled/ })
    await user.click(within(confirm).getByRole('button', { name: 'Confirm' }))

    expect(await screen.findByText('The node has not completed registration or its certificate is no longer valid, so it cannot be initialized or enabled. Run the install command on the node first.')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('internal server wording')).not.toBeInTheDocument())
  })

  it('localizes stable error codes in batch item results', async () => {
    await changeLocale('en-US')
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (String(input) === '/v1/nodes/batch-admin-state' && init?.method === 'POST') {
        return Promise.resolve(json({
          items: [{ id: node.id, status: 'failed', error: { code: 'version_conflict' } }],
        }))
      }
      return Promise.resolve(json({ items: [node] }))
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeListPage />)
    await screen.findByText('Edge Shanghai')

    await user.click(screen.getByRole('checkbox', { name: 'Edge Shanghai' }))
    await openBatchAction(user)
    const dialog = await screen.findByRole('dialog', { name: 'Change status for 1 nodes' })
    await user.click(within(dialog).getByRole('button', { name: 'Confirm change' }))

    const result = await screen.findByRole('dialog', { name: 'Batch operation results' })
    expect(within(result).getByTitle(node.id)).toHaveTextContent(node.display_id)
    expect(result).not.toHaveTextContent(node.id)
    expect(within(result).getByText('Another operation modified this node. The list has been refreshed; try again.')).toBeInTheDocument()
    expect(within(result).queryByText('version_conflict')).not.toBeInTheDocument()
  })
})
