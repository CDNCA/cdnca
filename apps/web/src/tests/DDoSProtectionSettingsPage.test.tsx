import { fireEvent, screen, waitFor, within } from '@testing-library/react'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import DDoSProtectionSettingsPage, { fromFormValues, toFormValues } from '../pages/DDoSProtectionSettingsPage'
import { getBreadcrumbLabels, isImplementedPath } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import type { DDoSProtectionConfiguration } from '../api/systemConfiguration'

const sha = 'a'.repeat(64)
const stored: DDoSProtectionConfiguration = {
  max_connections_per_ip: 200, new_connections_per_second: 50, new_connections_per_minute: 0, rate_ban_seconds: 600,
  max_connections_per_port: 0, allow_networks: ['192.0.2.0/24'], cc_kernel_ban: 'exclusive_ports',
  empty_connection: { idle_seconds: 10, threshold: 20, window_seconds: 60, ban_seconds: 1800 },
}

function documentBody(value: DDoSProtectionConfiguration, revision: number, status: string, active: number,
  pending: string[] = revision > active ? ['ddos_protection'] : []) {
  return {
    schema: 'cdnca.system-configuration/v2', category: 'ddos_protection', head_revision: revision,
    active_revision: active, revision, status, snapshot_sha256: sha, pending_categories: pending, value,
  }
}

function authenticate(permissions: string[]) {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function json(body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json', ...headers } })
}

describe('DDoS protection settings', () => {
  it('round-trips the form values', () => {
    expect(fromFormValues(toFormValues(stored))).toEqual(stored)
    const { empty_connection: _, ...withoutEmpty } = stored
    expect(fromFormValues({ ...toFormValues(stored), empty_enabled: false })).toEqual(withoutEmpty)
    expect(fromFormValues({ ...toFormValues(stored), allow_networks: ' 198.51.100.1 \n\n2001:db8::/48 ' }).allow_networks)
      .toEqual(['198.51.100.1', '2001:db8::/48'])
  })

  it('round-trips the packet filters in canonical order and keeps types while the switch is off', () => {
    const flags: DDoSProtectionConfiguration = { ...stored, tcp_flag_filter: true, tcp_flag_types: ['null', 'xmas', 'syn_fin', 'syn_rst'], drop_invalid: true }
    expect(fromFormValues(toFormValues(flags))).toEqual(flags)
    expect(fromFormValues({ ...toFormValues(flags), tcp_flag_types: ['all', 'fin', 'null'] }).tcp_flag_types).toEqual(['null', 'fin', 'all'])
    const off = fromFormValues({ ...toFormValues(flags), tcp_flag_filter: false, drop_invalid: false })
    expect(off.tcp_flag_filter).toBeUndefined()
    expect(off.drop_invalid).toBeUndefined()
    expect(off.tcp_flag_types).toEqual(['null', 'xmas', 'syn_fin', 'syn_rst'])
    expect(fromFormValues({ ...toFormValues(stored), tcp_flag_types: [] })).toEqual(stored)
  })

  it('saves the TCP flag types and drop invalid, and refuses the filter without a type', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    const flags: DDoSProtectionConfiguration = { ...stored, tcp_flag_filter: true, tcp_flag_types: ['null', 'xmas', 'syn_fin', 'syn_rst'], drop_invalid: true }
    const puts: unknown[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      if (init?.method === 'PUT') {
        const body = JSON.parse(String(init.body)) as { value: DDoSProtectionConfiguration }
        puts.push(body)
        return json(documentBody(body.value, 4, 'draft', 3), { ETag: '"4"' })
      }
      return String(input).endsWith('/categories/ddos_protection')
        ? json(documentBody(flags, 3, 'active', 3), { ETag: '"3"' }) : new Response('{}', { status: 404 })
    })
    renderWithProviders(<DDoSProtectionSettingsPage />)
    expect(await screen.findByText('已启用 #3')).toBeInTheDocument()
    expect(screen.getByText(/孤立 FIN 默认关闭/)).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: 'NULL（无任何标志）' })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: '孤立 FIN（不属于已有连接）' })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'ALL（六个标志全置）' })).not.toBeChecked()
    fireEvent.click(screen.getByRole('checkbox', { name: '孤立 FIN（不属于已有连接）' }))
    fireEvent.click(screen.getByRole('switch', { name: '丢弃无效连接' }))
    fireEvent.click(screen.getByRole('button', { name: /保存/ }))
    expect(await screen.findByText('草稿 #4，未启用')).toBeInTheDocument()
    const { drop_invalid: _, ...withoutInvalid } = flags
    expect(puts[0]).toEqual({ value: { ...withoutInvalid, tcp_flag_types: ['null', 'xmas', 'syn_fin', 'syn_rst', 'fin'] } })

    for (const kind of ['NULL（无任何标志）', 'Xmas（FIN+PSH+URG）', 'SYN+FIN', 'SYN+RST', '孤立 FIN（不属于已有连接）']) {
      fireEvent.click(screen.getByRole('checkbox', { name: kind }))
    }
    fireEvent.click(screen.getByRole('button', { name: /保存/ }))
    expect(await screen.findByText('开启异形包过滤时至少选择一种类型')).toBeInTheDocument()
    expect(puts).toHaveLength(1)
  })

  it('is an admin route under node management', () => {
    expect(isImplementedPath('admin', '/node/ddos-protection', ['system_configuration.read'])).toBe(true)
    expect(isImplementedPath('admin', '/node/ddos-protection', ['nodes.read'])).toBe(false)
    expect(getBreadcrumbLabels('admin', '/node/ddos-protection')).toEqual(['首页', '节点管理', '连接防护'])
  })

  it('loads, saves a draft, checks and activates it', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    const requests: Array<{ url: string, method: string, body: unknown }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      requests.push({ url, method, body: init?.body ? JSON.parse(String(init.body)) : null })
      if (url.endsWith('/categories/ddos_protection') && method === 'GET') {
        return json(documentBody(stored, 3, 'active', 3), { ETag: '"3"' })
      }
      if (url.endsWith('/categories/ddos_protection') && method === 'PUT') {
        const { value } = JSON.parse(String(init?.body)) as { value: DDoSProtectionConfiguration }
        return json(documentBody(value, 4, 'draft', 3), { ETag: '"4"' })
      }
      if (url.endsWith('/revisions/4/preflight')) {
        return json({ revision: 4, status: 'validated', snapshot_sha256: sha, replayed: false }, { ETag: '"4"' })
      }
      if (url.endsWith('/revisions/4/activate')) {
        return json({ revision: 4, status: 'active', snapshot_sha256: sha, replayed: false }, { ETag: '"4"' })
      }
      return new Response('{}', { status: 404 })
    })
    renderWithProviders(<DDoSProtectionSettingsPage />)

    expect(await screen.findByText('已启用 #3')).toBeInTheDocument()
    const perIP = screen.getByLabelText('单客户端并发连接上限')
    expect(perIP).toHaveValue('200')
    fireEvent.change(perIP, { target: { value: '300' } })
    fireEvent.click(screen.getByRole('button', { name: /保存/ }))
    expect(await screen.findByText('草稿 #4，未启用')).toBeInTheDocument()
    const put = requests.find((request) => request.method === 'PUT')
    expect(put?.body).toEqual({ value: { ...stored, max_connections_per_ip: 300 } })

    fireEvent.click(screen.getByRole('button', { name: /检查/ }))
    expect(await screen.findByText('已检查 #4，待启用')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /启用并下发/ }))
    expect(await screen.findByText('已启用 #4')).toBeInTheDocument()
    // GET /v1/modules is the module entitlement query of the 智能自动 section (AD-17), not part of this flow
    expect(requests.filter((request) => !request.url.endsWith('/v1/modules'))
      .map((request) => `${request.method} ${request.url.replace(/^.*\/v1/, '')}`)).toEqual([
      'GET /admin/system-configuration/categories/ddos_protection',
      'PUT /admin/system-configuration/categories/ddos_protection',
      'POST /admin/system-configuration/revisions/4/preflight',
      'POST /admin/system-configuration/revisions/4/activate',
    ])
    // Only this category is pending: no confirmation, and the confirmed set is sent.
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByTestId('pending-categories-notice')).not.toBeInTheDocument()
    expect(requests.find((request) => request.url.endsWith('/preflight'))?.body)
      .toEqual({ snapshot_sha256: sha, expected_pending_categories: ['ddos_protection'] })
    expect(requests.find((request) => request.url.endsWith('/activate'))?.body)
      .toEqual({ expected_pending_categories: ['ddos_protection'] })
  })

  it('confirms other pending categories before activating and reports a stale confirmation', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    const pending = ['node_monitoring', 'ddos_protection']
    const activations: unknown[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (url.endsWith('/categories/ddos_protection')) {
        return json(documentBody(stored, 5, 'validated', 3, pending), { ETag: '"5"' })
      }
      if (url.endsWith('/revisions/5/activate')) {
        activations.push(JSON.parse(String(init?.body)))
        return new Response(JSON.stringify({ error: { code: 'system_configuration_pending_categories_changed', message: 'changed' } }),
          { status: 409, headers: { 'Content-Type': 'application/json' } })
      }
      return new Response('{}', { status: 404 })
    })
    renderWithProviders(<DDoSProtectionSettingsPage />)

    const notice = await screen.findByTestId('pending-categories-notice')
    expect(notice).toHaveTextContent('一并生效：节点监控')
    expect(screen.getByText('去查看：节点监控')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /启用并下发/ }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('本次还会一并生效：节点监控')
    expect(activations).toHaveLength(0)
    fireEvent.click(screen.getByRole('button', { name: '确认并继续' }))
    expect(await screen.findByText('将一并生效的配置分类已变化，请刷新后重新确认')).toBeInTheDocument()
    expect(activations).toEqual([{ expected_pending_categories: pending }])
  })

  it('summarizes the revision, counts unsaved changes and discards them without a request (redesign-b)', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      json(documentBody(stored, 4, 'draft', 3), { ETag: '"4"' }))
    renderWithProviders(<DDoSProtectionSettingsPage />)
    expect(await screen.findByText('草稿 #4，未启用')).toBeInTheDocument()
    const summary = screen.getByRole('region', { name: '本页摘要' })
    expect(within(summary).getByRole('button', { name: /单客户端并发连接上限\s*200/ })).toBeInTheDocument()
    expect(within(summary).getByRole('button', { name: /新建速率\s*50\/秒/ })).toBeInTheDocument()
    expect(within(summary).getByRole('button', { name: /单端口总并发连接上限\s*关闭/ })).toBeInTheDocument()
    expect(within(summary).getByRole('button', { name: /白名单\s*1 条/ })).toBeInTheDocument()

    const bar = screen.getByTestId('ddos-savebar')
    expect(within(bar).getByRole('list', { name: '生效步骤' }).querySelector('[aria-current="step"]')).toHaveTextContent('检查')
    expect(bar).toHaveTextContent('没有未保存的修改')
    fireEvent.change(screen.getByLabelText('单客户端并发连接上限'), { target: { value: '300' } })
    fireEvent.change(screen.getByLabelText('白名单地址或网段（每行一个）'), { target: { value: ' 192.0.2.0/24 \n' } })
    expect(await within(bar).findByText('共 1 项修改')).toBeInTheDocument()
    expect(bar).toHaveClass('is-dirty')
    const before = fetchSpy.mock.calls.length
    fireEvent.click(within(bar).getByRole('button', { name: '放弃修改' }))
    await waitFor(() => expect(screen.getByLabelText('单客户端并发连接上限')).toHaveValue('200'))
    expect(bar).toHaveTextContent('没有未保存的修改')
    expect(fetchSpy.mock.calls.length).toBe(before)
  })

  it('refuses a ban without a rate and a malformed allow list line before saving', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      json(documentBody(stored, 3, 'active', 3), { ETag: '"3"' }))
    renderWithProviders(<DDoSProtectionSettingsPage />)
    expect(await screen.findByText('已启用 #3')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('每秒新建连接上限'), { target: { value: '0' } })
    fireEvent.change(screen.getByLabelText('白名单地址或网段（每行一个）'), { target: { value: '192.0.2.0/24\nexample.com' } })
    fireEvent.click(screen.getByRole('button', { name: /保存/ }))
    expect(await screen.findByText('设置封禁时长时至少要开启一个新建速率限制')).toBeInTheDocument()
    expect(await screen.findByText('白名单第 2 行不是合法的 IP 地址或网段')).toBeInTheDocument()
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([input]) => !String(input).endsWith('/v1/modules'))).toHaveLength(1))
  })

  it('shows the global baseline, the port group overrides and the node receipts as separate layers', async () => {
    authenticate(['system_configuration.read', 'nodes.read'])
    const nodeID = '018f0000-0000-7000-8000-000000000001'
    const failedID = '018f0000-0000-7000-8000-000000000002'
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.includes('/categories/ddos_protection')) return json(documentBody(stored, 3, 'active', 3), { ETag: '"3"' })
      if (url.includes('/v1/nodes/metrics/latest')) return json({ observed_at: '2026-10-26T00:00:00Z', items: [], not_reported_node_ids: [nodeID, failedID] })
      if (url.includes('/v1/nodes?')) return json({ items: [] })
      return json({ items: [] })
    })
    const { nodesApi } = await import('../api/nodes')
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [
      { id: nodeID, name: '上海一号' }, { id: failedID, name: '广州二号' },
    ] as never })
    vi.spyOn(nodesApi, 'getLatestMetricsBatch').mockResolvedValue({
      observed_at: '2026-10-26T00:00:00Z',
      items: [{ node_id: failedID, known: true, observed_at: '2026-10-26T00:00:00Z',
        telemetry: { ddos_protection: { state: 'unavailable', reason: 'nft_missing' } } }] as never,
      not_reported_node_ids: [nodeID],
    })
    renderWithProviders(<DDoSProtectionSettingsPage />)
    expect(await screen.findByTestId('ddos-global-baseline')).toHaveTextContent('全局基础防护')
    const receipts = await screen.findByTestId('ddos-node-receipts')
    const shanghai = (await within(receipts).findByText('上海一号')).closest('tr')!
    expect(within(shanghai).getByText('未上报')).toBeInTheDocument()
    const guangzhou = within(receipts).getByText('广州二号').closest('tr')!
    expect(within(guangzhou).getByText('不可用')).toBeInTheDocument()
    expect(within(guangzhou).getByText('节点没有安装 nftables')).toBeInTheDocument()
  })

  it('shows the port group override receipts per node and port group (fz-x11)', async () => {
    authenticate(['system_configuration.read', 'nodes.read'])
    const ids = ['018f0000-0000-7000-8000-000000000011', '018f0000-0000-7000-8000-000000000012', '018f0000-0000-7000-8000-000000000013']
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.includes('/categories/ddos_protection')) return json(documentBody(stored, 3, 'active', 3), { ETag: '"3"' })
      return json({ items: [] })
    })
    const { nodesApi } = await import('../api/nodes')
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [
      { id: ids[0], name: '新节点' }, { id: ids[1], name: '旧节点' }, { id: ids[2], name: '空节点' },
    ] as never })
    vi.spyOn(nodesApi, 'getLatestMetricsBatch').mockResolvedValue({
      observed_at: '2026-10-26T00:00:00Z',
      items: [
        { node_id: ids[0], known: true, observed_at: '2026-10-26T00:00:00Z', telemetry_detail: true,
          telemetry: { port_group_overrides: [
            { port_group_id: 'stream-1', state: 'applied' },
            { port_group_id: 'web-tcp', state: 'inactive', reason: 'shared_ports' },
          ] } },
        { node_id: ids[1], known: true, observed_at: '2026-10-26T00:00:00Z', telemetry: {} },
        { node_id: ids[2], known: true, observed_at: '2026-10-26T00:00:00Z', telemetry_detail: true, telemetry: {} },
      ] as never,
      not_reported_node_ids: [],
    })
    renderWithProviders(<DDoSProtectionSettingsPage />)
    const receipts = await screen.findByTestId('ddos-node-receipts')
    const fresh = (await within(receipts).findByText('新节点')).closest('tr')!
    expect(within(fresh).getByTestId('port-group-override-stream-1')).toHaveTextContent('stream-1 已生效')
    expect(within(fresh).getByTestId('port-group-override-web-tcp')).toHaveTextContent('网站端口组 未生效网站端口多租户共用')
    const old = within(receipts).getByText('旧节点').closest('tr')!
    expect(within(old).getByTestId('port-group-version-not-reported')).toHaveTextContent('节点版本未上报')
    const empty = within(receipts).getByText('空节点').closest('tr')!
    expect(within(empty).getByText('无端口组')).toBeInTheDocument()
  })

  it('hides the node receipts without nodes.read', async () => {
    authenticate(['system_configuration.read'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(documentBody(stored, 3, 'active', 3), { ETag: '"3"' }))
    renderWithProviders(<DDoSProtectionSettingsPage />)
    expect(await screen.findByTestId('ddos-global-baseline')).toBeInTheDocument()
    expect(screen.queryByTestId('ddos-node-receipts')).not.toBeInTheDocument()
    // No node inventory / metrics request without nodes.read.
    expect(fetchSpy.mock.calls.some(([input]) => String(input).includes('/v1/nodes'))).toBe(false)
  })

  it('stacks CC under empty connections in the left column and lays the number fields out in one row (fix-ddoscompact)', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(documentBody(stored, 3, 'active', 3), { ETag: '"3"' }))
    const { container } = renderWithProviders(<DDoSProtectionSettingsPage />)
    expect(await screen.findByText('已启用 #3')).toBeInTheDocument()
    const columns = [...container.querySelectorAll('.ddos-v2-grid > .ddos-v2-col')]
      .map((column) => [...column.querySelectorAll(':scope > .ddos-v2-section')].map((section) => section.id))
    expect(columns).toEqual([
      ['ddos-section-client', 'ddos-section-port', 'ddos-section-empty', 'ddos-section-cc'],
      ['ddos-section-packets', 'ddos-section-allow'],
    ])
    // the four per-client and four empty connection fields each sit in one four-field row; units are input suffixes
    for (const id of ['ddos-section-client', 'ddos-section-empty']) {
      const fields = container.querySelector(`#${id} .ddos-v2-fields`)!
      expect(fields).toHaveClass('is-four')
      expect(fields.querySelectorAll('.ant-input-number')).toHaveLength(4)
    }
    expect(screen.getByLabelText('超速封禁时长')).toHaveValue('600')
    expect(screen.getByLabelText('封禁时长')).toHaveValue('1800')
    expect(container.querySelectorAll('#ddos-section-empty .ant-input-number-suffix')).toHaveLength(4)
  })

  it('gives the four-field rows short labels with the full name in a tooltip and on the input (fix-ddoscompact2)', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(documentBody(stored, 3, 'active', 3), { ETag: '"3"' }))
    const { container } = renderWithProviders(<DDoSProtectionSettingsPage />)
    expect(await screen.findByText('已启用 #3')).toBeInTheDocument()
    const rows = {
      'ddos-section-client': [['并发连接', '单客户端并发连接上限'], ['每秒新建', '每秒新建连接上限'], ['每分新建', '每分钟新建连接上限'], ['超速封禁', '超速封禁时长']],
      'ddos-section-empty': [['空闲时长', '无数据判定时间'], ['触发次数', '窗口内空连接次数'], ['统计窗口', '统计窗口'], ['封禁时长', '封禁时长']],
    }
    for (const [id, expected] of Object.entries(rows)) {
      const items = [...container.querySelectorAll(`#${id} .ddos-v2-fields.is-four > .ant-form-item`)]
      expect(items.map((item) => item.querySelector('.ant-form-item-label > label')?.textContent)).toEqual(expected.map(([short]) => short))
      // a short label fits a quarter of a 1200px column (about 93px) with the required mark and the help icon: four characters
      for (const [short] of expected) expect(short.length).toBeLessThanOrEqual(4)
      for (const item of items) expect(item.querySelector('.ant-form-item-tooltip')).not.toBeNull()
      expect(items.map((item) => item.querySelector('input')?.getAttribute('aria-label'))).toEqual(expected.map(([, full]) => full))
    }
    // the page summary still names a limit in full
    expect(within(screen.getByRole('region', { name: '本页摘要' })).getByRole('button', { name: /单客户端并发连接上限\s*200/ })).toBeInTheDocument()
  })

  it('lays four fields in one row from 900px, the two-column 1200–1439px range included (fix-ddoscompact2)', () => {
    const css = Object.values(import.meta.glob('../pages/DDoSProtectionV2.css', { eager: true, import: 'default', query: '?raw' }))[0] as string
    const media = (query: string) => {
      const start = css.indexOf(`@media ${query} {`)
      if (start < 0) return ''
      let depth = 0
      for (let i = css.indexOf('{', start); i < css.length; i++) {
        if (css[i] === '{') depth++
        else if (css[i] === '}' && --depth === 0) return css.slice(start, i + 1)
      }
      return ''
    }
    expect(media('(min-width: 900px)')).toMatch(/\.ddos-v2-fields\.is-four\s*\{[^}]*grid-template-columns:\s*repeat\(4,/)
    // no width range above 900px drops back to two per row
    expect(css).not.toMatch(/max-width:\s*1199px\)\s*\{[^@]*is-four/)
    const tight = media('(min-width: 1200px) and (max-width: 1439px)')
    expect(tight).toMatch(/\.ddos-v2-fields\.is-four\s*\{[^}]*gap:/)
    // an input without a unit suffix keeps its own padding, so the digits do not touch the border
    expect(tight).toMatch(/\.is-four \.ant-input-number-input\s*\{[^}]*padding-inline:\s*8px/)
    expect(tight).toMatch(/\.is-four \.ant-input-number-affix-wrapper \.ant-input-number-input\s*\{[^}]*padding-inline:\s*0/)
  })

  it('puts a switch next to its label and the help under both, over antd vertical layout (fix-ddoscompact)', () => {
    const css = Object.values(import.meta.glob('../pages/DDoSProtectionV2.css', { eager: true, import: 'default', query: '?raw' }))[0] as string
    const rule = (selector: string) => new RegExp(`${selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\{([^}]*)\\}`).exec(css)?.[1] ?? ''
    // antd .ant-form-item-vertical gives the control width: 100%, which wraps the switch under its label
    expect(rule('.ddos-v2 .ddos-v2-switch .ant-form-item-row')).toMatch(/display:\s*grid/)
    expect(rule('.ddos-v2 .ddos-v2-switch .ant-form-item-control')).toMatch(/display:\s*contents/)
    expect(rule('.ddos-v2 .ddos-v2-switch .ant-form-item-additional')).toMatch(/grid-column:\s*1\s*\/\s*-1/)
    expect(rule('.ddos-v2 .ddos-v2-fields.is-four')).toMatch(/grid-template-columns/)
  })

  it('is read only without manage permission and 403 without read', async () => {
    authenticate(['system_configuration.read'])
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(documentBody(stored, 3, 'active', 3), { ETag: '"3"' }))
    renderWithProviders(<DDoSProtectionSettingsPage />)
    expect(await screen.findByText('已启用 #3')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /保存/ })).toBeNull()

    authenticate(['nodes.read'])
    renderWithProviders(<AppRoutes />, ['/node/ddos-protection'])
    expect(await screen.findByText('无权访问')).toBeInTheDocument()
  })
})
