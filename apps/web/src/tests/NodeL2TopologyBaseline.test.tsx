import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { L2Config } from '../api/nodeScheduling'
import { useSessionStore } from '../auth/session'
import NodeL2TopologyPage from '../pages/NodeL2TopologyPage'
import nodeL2TopologyCSS from '../pages/NodeL2TopologyPage.css?raw'
import { principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const tenantID = '22222222-2222-4222-8222-222222222222'

beforeEach(() => sessionStorage.clear())

const group: L2Config = {
  id: '11111111-1111-4111-8111-111111111111',
  display_id: '1',
  tenant_scope_id: tenantID,
  revision: 1,
  name: '华东 L2 配置',
  region: '华东',
  remark: '',
  mode: 'cache',
  load_method: 'rr',
  created_at: '2026-08-28T00:00:00Z',
  updated_at: '2026-08-28T00:00:01Z',
}

function authenticate() {
  useSessionStore.setState({
    accessToken: 'access-token',
    expiresAt: Date.now() + 60_000,
    sessionEpoch: 1,
    principal: principal({
      scope_kind: 'tenant',
      scope_id: tenantID,
      tenant_id: tenantID,
      roles: ['tenant_owner'],
      permissions: ['node_scheduling.read', 'node_scheduling.manage'],
    }),
    status: 'authenticated',
  })
}

function json(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function openSelect(combobox: HTMLElement) {
  fireEvent.mouseDown(combobox.closest('.ant-select')!.querySelector('.ant-select-selector')!)
}

function visibleDropdown(className: string): HTMLElement {
  const dropdown = document.querySelector(`.${className}:not(.ant-select-dropdown-hidden)`)
  expect(dropdown).not.toBeNull()
  return dropdown as HTMLElement
}

describe('NodeL2TopologyPage competitor baseline', () => {
  it('keeps the empty fixed box within the table without hiding real horizontal scrolling', () => {
    expect(nodeL2TopologyCSS).toMatch(/\.ant-table-tbody > \.ant-table-placeholder > td\s*\{[^}]*padding: 0 !important;/)
    expect(nodeL2TopologyCSS).toMatch(/\.ant-table-placeholder \.ant-table-expanded-row-fixed\s*\{[^}]*padding: 0;[^}]*margin: 0;/)
    expect(nodeL2TopologyCSS).toMatch(/\.ant-table-content\s*\{\s*overflow-x: auto !important;/)
  })

  it('keeps condition table spacing above Ant Design small table defaults', () => {
    expect(nodeL2TopologyCSS).toMatch(/\.node-l2-condition-modal \.ant-table-wrapper \.ant-table-thead > tr > th,\s*\.node-l2-condition-modal \.ant-table-wrapper \.ant-table-tbody > tr > td\s*\{\s*padding: 12px 10px !important;/)
  })

  it('reads condition rules as one sentence in the list and while editing (UX-L2-RULE-01)', async () => {
    authenticate()
    const condition = {
      id: '33333333-3333-4333-8333-333333333333', display_id: '3', tenant_scope_id: '22222222-2222-4222-8222-222222222222',
      revision: 2, name: '华东 HTTPS', remark: '', created_at: '2026-07-28T08:00:00Z', updated_at: '2026-07-28T08:00:01Z',
      rules: [{ field: 'host', operator: 'eq', value: 'a.example.test' }, { field: 'protocol', operator: 'eq', value: 'https' }],
    }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
      json({ items: String(url).includes('/v1/l2-conds') ? [condition] : [] }))
    const user = userEvent.setup()
    renderWithProviders(<NodeL2TopologyPage />, ['/node/l2-config'])
    await user.click(screen.getByRole('tab', { name: 'L2条件' }))
    const summary = '域名 等于「a.example.test」 且 协议 等于「https」'
    expect(await screen.findByText(summary)).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '规则' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByTestId('l2-condition-preview')).toHaveTextContent(`匹配：${summary}`)
  })

  it('uses four equal columns in the condition rule editor', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [] })) // 每次新建 Response：条件页签会再读一次
    const user = userEvent.setup()
    renderWithProviders(<NodeL2TopologyPage />, ['/node/l2-config'])
    await user.click(screen.getByRole('tab', { name: 'L2条件' }))
    await user.click(screen.getByRole('button', { name: '新增条件' }))
    const table = within(await screen.findByRole('dialog')).getByRole('table')
    const columns = [...table.querySelectorAll('col')]
    expect(columns).toHaveLength(4)
    for (const column of columns) expect(column).toHaveStyle({ width: '25%' })
  })

  it.each([true, false])('uses equal baseline data columns with a separate action area (manage=%s)', async function l2TableGeometryRegression(canManage) {
    authenticate()
    if (!canManage) useSessionStore.setState({ principal: principal({ permissions: ['node_scheduling.read'] }) })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))
    renderWithProviders(<NodeL2TopologyPage />, ['/node/l2-config'])
    await screen.findByText('暂无数据')
    const table = within(screen.getByTestId('node-l2-topology-table')).getByRole('table')
    expect(table).toHaveStyle({ tableLayout: 'fixed' })
    const columns = [...table.querySelectorAll('col')].slice(canManage ? 1 : 0, canManage ? 6 : 5)
    expect(columns).toHaveLength(5)
    for (const column of columns)
      expect(column).toHaveStyle({ width: canManage ? 'calc((100% - 60px) * 0.16)' : '16%' })
    expect(within(table).getByRole('columnheader', { name: '操作' })).toHaveStyle({ textAlign: 'center' })
  })

  it('keeps long configuration names intact and wraps only configuration rows and actions', async () => {
    authenticate()
    const name = '华东跨区域节点缓存配置名称'.repeat(4)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [{ ...group, name }] }))
    renderWithProviders(<NodeL2TopologyPage />, ['/node/l2-config'])
    expect(await screen.findByRole('cell', { name })).toHaveTextContent(name)
    expect(nodeL2TopologyCSS).toMatch(/\.node-l2-configuration-table \.ant-table-tbody > tr:not\(\.ant-table-placeholder\) > td\s*\{[^}]*line-height: 21px;[^}]*white-space: normal;[^}]*overflow-wrap: anywhere;/)
    expect(nodeL2TopologyCSS).toMatch(/\.node-l2-configuration-table \.node-l2-row-actions\s*\{\s*flex-wrap: wrap;/)
    const table = within(screen.getByTestId('node-l2-topology-table')).getByRole('table')
    expect(table).toHaveStyle({ width: '730px', minWidth: '100%' })
  })

  it('keeps disabled node action buttons out of enabled semantic colors', () => {
    expect(nodeL2TopologyCSS).toMatch(/\.node-l2-nodes-panes \.l2-enable:not\(:disabled\)\s*\{\s*background: var\(--cdnca-color-success\);/)
    expect(nodeL2TopologyCSS).toMatch(/\.node-l2-nodes-panes \.l2-disable:not\(:disabled\)\s*\{\s*background: var\(--cdnca-color-warning\);/)
    expect(nodeL2TopologyCSS).not.toMatch(/\.node-l2-nodes-panes \.l2-(?:enable|disable)\s*\{/)
  })

  it('preserves modal dividers and leaves the three-row rule field taller than single-line inputs', () => {
    expect(nodeL2TopologyCSS).toMatch(/\.node-l2-topology-create-modal \.ant-modal-content\s*\{\s*padding: 0;/)
    expect(nodeL2TopologyCSS).toMatch(/\.node-l2-topology-create-modal \.ant-modal-header\s*\{[^}]*border-bottom: 1px solid var\(--cdnca-color-border-secondary\);/)
    expect(nodeL2TopologyCSS).toMatch(/\.node-l2-topology-create-modal \.ant-modal-footer\s*\{[^}]*border-top: 1px solid var\(--cdnca-color-border-secondary\);/)
    expect(nodeL2TopologyCSS).toMatch(/\.node-l2-topology-create-modal input\.ant-input\s*\{\s*height: 32px;/)
    expect(nodeL2TopologyCSS).not.toMatch(/\.node-l2-topology-create-modal \.ant-input\s*\{\s*height: 32px;/)
  })

  it('locks the title, toolbar, six columns, region and page-size popup order and geometry', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      items: [group, {
        ...group,
        id: '66666666-6666-4666-8666-666666666666',
        name: '华南 L2 配置',
        region: '华南',
      }],
    }))
    const user = userEvent.setup()

    renderWithProviders(<NodeL2TopologyPage />, ['/node/l2-config'])

    expect(await screen.findByRole('heading', { name: 'L2 配置' })).toBeInTheDocument()
    // 互相跳转 (NET-10): the line groups pick these configurations
    expect(screen.getByRole('link', { name: '前往线路分组' })).toHaveAttribute('href', '/node/line-group')
    expect(await screen.findByText('华东 L2 配置')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增配置' })).toBeInTheDocument()
    expect(within(screen.getByRole('toolbar')).getByRole('button', { name: '删除' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: '更多操作' })).not.toBeInTheDocument()
    expect(screen.getAllByRole('columnheader').map((item) => item.textContent?.trim()).filter(Boolean))
      .toEqual(['ID', '名称', '区域', '模式', '负载方式', '操作'])

    const region = screen.getByRole('combobox', { name: '区域' })
    expect(region.closest('.ant-select')).toHaveTextContent('全部区域')
    openSelect(region)
    expect(within(visibleDropdown('node-l2-topology-region-popup')).getAllByRole('option')
      .map((item) => item.textContent?.trim())).toEqual(['默认', '华东', '华南'])
    await user.click(within(visibleDropdown('node-l2-topology-region-popup')).getByRole('option', { name: '华东' }))
    expect(region.closest('.ant-select')).toHaveTextContent('华东')

    const pageSize = screen.getByRole('combobox', { name: '每页数量' })
    expect(pageSize.closest('.ant-select')).toHaveTextContent('10 条/页')
    openSelect(pageSize)
    expect(within(visibleDropdown('node-l2-topology-page-size-popup')).getAllByRole('option')
      .map((item) => item.textContent?.trim())).toEqual(['10 条/页', '20 条/页', '50 条/页'])

    expect(nodeL2TopologyCSS).toContain('.node-l2-topology-select-popup')
    expect(nodeL2TopologyCSS).toContain('.node-l2-topology-region-popup')
    expect(nodeL2TopologyCSS).toContain('.node-l2-topology-page-size-popup')
    expect(nodeL2TopologyCSS).toContain('max-height: 200px;')
  })

  it('renders the short display ID while keeping the internal UUID out of the cell text', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [group] }))

    renderWithProviders(<NodeL2TopologyPage />, ['/node/l2-config'])

    const id = await screen.findByText(group.display_id, { selector: '.resource-id__primary' })
    expect(id).toHaveTextContent(group.display_id)
    expect(id.closest('.resource-id')).toHaveAttribute('title', group.display_id)
    expect(id.closest('.resource-id')).not.toHaveTextContent(group.id)
    expect(id.closest('.resource-id')).not.toHaveStyle({ textOverflow: 'ellipsis' })
  })

  it('matches the canonical create form and blocks invalid submission without a write', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))
    const user = userEvent.setup()

    renderWithProviders(<NodeL2TopologyPage />, ['/node/l2-config'])
    await screen.findByText('暂无数据')
    await user.click(screen.getByRole('button', { name: '新增配置' }))

    const dialog = await screen.findByRole('dialog', { name: '新增L2配置' })
    expect(within(dialog).getByRole('textbox', { name: '名称' })).toHaveAttribute('placeholder', '请输入L2配置名称')
    expect(within(dialog).queryByLabelText('L2 节点 ID')).not.toBeInTheDocument()
    expect(within(dialog).queryByLabelText('IP 地址')).not.toBeInTheDocument()
    expect(within(dialog).getByRole('radio', { name: '缓存' })).toBeChecked()
    expect(within(dialog).getByRole('button', { name: '确定' })).toBeInTheDocument()

    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(within(dialog).getByRole('textbox', { name: '名称' })).toHaveAttribute('aria-invalid', 'true')
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0)
  })

  it('confirms human-readable names and deletes through the real revision contract', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => init?.method === 'DELETE'
      ? new Response(null, { status: 204 }) : json({ items: [group] }))
    const user = userEvent.setup()

    renderWithProviders(<NodeL2TopologyPage />, ['/node/l2-config'])
    await screen.findByText('华东 L2 配置')
    const checkboxes = screen.getAllByRole('checkbox')
    await user.click(checkboxes[checkboxes.length - 1]!)
    await user.click(screen.getAllByRole('button', { name: '删除' })[0]!)

    const confirmation = await screen.findByRole('dialog', { name: '删除确认' })
    expect(within(confirmation).getByText(`是否删除 ${group.name}？`)).toBeInTheDocument()
    expect(within(confirmation).queryByText(group.id)).not.toBeInTheDocument()
    await user.click(within(confirmation).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'DELETE')).toHaveLength(1))
    const write = fetchSpy.mock.calls.find(([, init]) => init?.method === 'DELETE')!
    expect(String(write[0])).toBe(`/v1/l2-configs/${group.id}`)
    expect(new Headers(write[1]?.headers).get('If-Match')).toBe('"1"')
    expect(new Headers(write[1]?.headers).get('Idempotency-Key')).toBeTruthy()
  })

  it('W1 distinguishes condition and configuration required-name messages', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [] })) // 每次新建 Response：条件页签会再读一次
    const user = userEvent.setup()

    renderWithProviders(<NodeL2TopologyPage />, ['/node/l2-config'])
    await screen.findByText('暂无数据')
    await user.click(screen.getByRole('button', { name: '新增配置' }))
    const configDialog = await screen.findByRole('dialog', { name: '新增L2配置' })
    await user.click(within(configDialog).getByRole('button', { name: '确定' }))
    expect(await within(configDialog).findByText('请输入L2配置名称')).toBeInTheDocument()
    await user.click(within(configDialog).getByRole('button', { name: /取\s*消/ }))

    await user.click(screen.getByRole('tab', { name: 'L2条件' }))
    await user.click(screen.getByRole('button', { name: '新增条件' }))
    const conditionDialog = await screen.findByRole('dialog', { name: '新增条件' })
    await user.click(within(conditionDialog).getByRole('button', { name: '确定' }))
    expect(await within(conditionDialog).findByText('请输入L2条件名称')).toBeInTheDocument()
    expect(within(conditionDialog).queryByText('请输入L2配置名称')).not.toBeInTheDocument()
  })

  it('W2 reports a successful delete as deleted rather than saved', async () => {
    authenticate()
    let deleted = false
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      if (init?.method === 'DELETE') {
        deleted = true
        return new Response(null, { status: 204 })
      }
      return json({ items: deleted ? [] : [group] })
    })
    const user = userEvent.setup()

    renderWithProviders(<NodeL2TopologyPage />, ['/node/l2-config'])
    await screen.findByText('华东 L2 配置')
    const checkboxes = screen.getAllByRole('checkbox')
    await user.click(checkboxes[checkboxes.length - 1]!)
    await user.click(screen.getAllByRole('button', { name: '删除' })[0]!)
    const confirmation = await screen.findByRole('dialog', { name: '删除确认' })
    await user.click(within(confirmation).getByRole('button', { name: '确定' }))

    expect(await screen.findByText('已删除')).toBeInTheDocument()
    expect(screen.queryByText('L2 配置已保存')).not.toBeInTheDocument()
  })

  it('keeps the canonical mode and load controls without internal node identifiers', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))
    const user = userEvent.setup()

    renderWithProviders(<NodeL2TopologyPage />, ['/node/l2-config'])
    await screen.findByText('暂无数据')
    await user.click(screen.getByRole('button', { name: '新增配置' }))

    const dialog = await screen.findByRole('dialog', { name: '新增L2配置' })
    expect(within(dialog).getByLabelText('名称')).toBeInTheDocument()
    expect(within(dialog).queryByLabelText(/UUID|节点 ID|作用域/)).not.toBeInTheDocument()
    expect(within(dialog).getByRole('radio', { name: '缓存' })).toBeChecked()
    expect(within(dialog).getByRole('radio', { name: '轮询' })).toBeChecked()
  })
})
