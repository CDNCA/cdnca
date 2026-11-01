import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from 'i18next'
import { vi } from 'vitest'

import type { NodeLineGroup } from '../api/nodeScheduling'
import { validateSmartSchedule } from '../api/smartSchedule'
import { useSessionStore } from '../auth/session'
import NodeLineGroupsPage from '../pages/NodeLineGroupsPage'
import SmartScheduleDrawer from '../pages/node-scheduling/SmartScheduleDrawer'
import { enUSNodeScheduling, zhCNNodeScheduling } from '../pages/node-scheduling/messages'
import { principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

vi.mock('../components/useGrantedModules', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../components/useGrantedModules')>()),
  useGrantedModules: () => [],
}))

// 线路组「智能调度」抽屉。
const groupID = '11111111-1111-4111-8111-111111111111'
const group = {
  id: groupID, display_id: '7', tenant_scope_id: '22222222-2222-4222-8222-222222222222', revision: 7, name: '华东主线路',
  region: '', resolved_value: 'line-east', l2_config_id: null, failover_mode: 'primary_offline', note: '', sort_order: 100,
  health_policy: { probe_interval_ms: 10_000, probe_timeout_ms: 3_000, failure_threshold: 3, recovery_threshold: 3, failure_debounce_ms: 0, recovery_debounce_ms: 0 },
  endpoints: [], statistics: { node_count: 2, site_count: 3, forward_count: 0 }, configuration_digest: 'a'.repeat(64),
  created_by_user_id: '55555555-5555-4555-8555-555555555555', created_at: '2026-10-31T00:00:00Z', sealed_at: '2026-10-31T00:00:01Z',
} as unknown as NodeLineGroup

const schedule = {
  enabled: true, top_n: 2, granularity: 'province_carrier', latency_window_minutes: 15, max_load_percent: 85, fallback: 'carrier_then_default',
  province_lines_supported: true, revision: 3,
  probe_source: { dnspup: true, peer_nodes: false },
  lines: [
    { scope: 'mobile', dns_line: 'cmcc', source: 'latency', selected: [{ address: '198.51.100.20', endpoint_id: 'e3', latency_ms: 40, healthy: true, load_percent: 30 }], updated_at: '2026-10-31T04:00:00Z' },
    { scope: 'unicom', dns_line: '联通', source: 'static', selected: [{ address: '203.0.113.5', endpoint_id: 'e4', latency_ms: null, healthy: true, load_percent: null }], updated_at: '2026-10-31T04:00:00Z' },
    {
      scope: '广东:telecom', dns_line: 'cn_telecom_guangdong', source: 'latency',
      selected: [
        { address: '192.0.2.10', endpoint_id: 'e1', latency_ms: 18.4, healthy: true, load_percent: 41 },
        { address: '192.0.2.11', endpoint_id: 'e2', latency_ms: 26, healthy: true, load_percent: 62 },
      ],
      updated_at: '2026-10-31T04:00:00Z',
    },
    { scope: '西藏:mobile', dns_line: 'cn_mobile_xizang', source: 'fallback', selected: [], fallback_from: 'province_carrier', updated_at: '2026-10-31T04:00:00Z' },
  ],
}

const matrix = {
  rows: [
    { province: '广东', carrier: 'telecom', endpoint_id: 'e2', address: '192.0.2.11', p50_ms: 26, samples: 120, last_at: '2026-10-31T04:00:00Z' },
    { province: '广东', carrier: 'telecom', endpoint_id: 'e1', address: '192.0.2.10', p50_ms: 18, samples: 118, last_at: '2026-10-31T04:00:00Z' },
    { province: '北京', carrier: 'unicom', endpoint_id: 'e1', address: '192.0.2.10', p50_ms: 31, samples: 90, last_at: '2026-10-31T04:00:00Z' },
  ],
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function stubFetch(body: unknown = schedule) {
  const calls: Array<{ method: string; url: string; body?: string; headers: Record<string, string> }> = []
  const current = { value: body }
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ method: init?.method ?? 'GET', url, body: init?.body as string | undefined, headers: (init?.headers ?? {}) as Record<string, string> })
    if (url.includes('/latency-matrix')) return json(matrix)
    if (url.includes('/smart-schedule')) {
      if (init?.method === 'PUT') {
        current.value = { ...(current.value as object), ...JSON.parse(init.body as string) }
        return new Response(null, { status: 204 })
      }
      return json(current.value)
    }
    return json({ items: [group] })
  }))
  return calls
}

function renderDrawer(canManage = true) {
  return renderWithProviders(
    <SmartScheduleDrawer group={group} scope={{ kind: 'tenant' }} accessToken={() => 'token'} canManage={canManage} onClose={() => undefined} />,
  )
}

describe('SmartScheduleDrawer', () => {
  afterEach(async () => {
    vi.unstubAllGlobals()
    await i18n.changeLanguage('zh-CN')
  })

  it('opens from the line-group row for a read-only account and explains how it works', async () => {
    useSessionStore.setState({
      accessToken: 'access-token', expiresAt: Date.now() + 60_000, status: 'authenticated', sessionEpoch: 1,
      principal: principal({ permissions: ['node_scheduling.read'], roles: ['tenant_viewer'] }),
    })
    const calls = stubFetch()
    renderWithProviders(<NodeLineGroupsPage />)
    await userEvent.click(await screen.findByRole('button', { name: '华东主线路 的智能调度' }))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText(/省份运营商 → 同运营商全国 → 默认线路/)).toBeInTheDocument()
    expect(within(drawer).getByText(/故障或超出最大负载时自动摘除/)).toBeInTheDocument()
    expect(await within(drawer).findByText('当前账号只有查看权限，不能修改智能调度设置。')).toBeInTheDocument()
    expect(within(drawer).getByRole('switch')).toBeDisabled()
    expect(within(drawer).queryByRole('button', { name: '保存' })).not.toBeInTheDocument()
    expect(calls.some((call) => call.url.endsWith(`/v1/node-line-groups/${groupID}/smart-schedule`))).toBe(true)
  })

  it('lists each line with selected nodes, latency, health, load and where a fallback came from', async () => {
    stubFetch()
    renderDrawer()
    const lines = await screen.findAllByTestId('smart-schedule-line')
    // 按省份顺序：运营商全国线路在前，然后 广东（44）→ 西藏（54）。
    expect(lines.map((line) => line.querySelector('strong')?.textContent)).toEqual(['联通', '移动', '广东电信', '西藏移动'])
    expect(within(lines[2]).getByText('192.0.2.10')).toBeInTheDocument()
    expect(within(lines[2]).getByText('18 ms')).toBeInTheDocument()
    expect(within(lines[2]).getByText('负载 41%')).toBeInTheDocument()
    expect(within(lines[2]).getAllByText('健康')).toHaveLength(2)
    // static 线路：延迟与负载为 null 时显示「—」，并标注无延迟数据
    expect(within(lines[0]).getByText('延迟 —')).toHaveAccessibleName('无延迟数据')
    expect(within(lines[0]).getByText('负载 —')).toHaveAccessibleName('无近 5 分钟负载数据')
    expect(within(lines[0]).getByText('无延迟数据')).toBeInTheDocument()
    // fallback_from=province_carrier：省份线路不写，由同运营商全国线路回答
    expect(within(lines[3]).getByText('回退到移动')).toBeInTheDocument()
    expect(within(lines[3]).getByText('没有可用节点')).toBeInTheDocument()
    expect(screen.getByTestId('smart-schedule-probe-sources')).toHaveTextContent('延迟数据来源：dnspup 探测')
  })

  it('warns when there is no probe source', async () => {
    stubFetch({ ...schedule, probe_source: { dnspup: false, peer_nodes: false } })
    renderDrawer()
    expect(await screen.findByTestId('smart-schedule-no-probe')).toHaveTextContent('启用 dnspup 探测插件或对端节点探测后才能按延迟选点')
  })

  it('greys out province granularity when the DNS provider has no province lines', async () => {
    stubFetch({ ...schedule, granularity: 'carrier', province_lines_supported: false })
    renderDrawer()
    const province = await screen.findByRole('radio', { name: '按省份+运营商' })
    expect(province).toBeDisabled()
    expect(screen.getByTestId('smart-schedule-granularity-help')).toHaveTextContent('当前 DNS 服务商不支持省份线路')
  })

  it('saves the settings with PUT and reloads them', async () => {
    const calls = stubFetch({ ...schedule, enabled: false, granularity: 'carrier', top_n: 3 })
    const user = userEvent.setup()
    renderDrawer()
    expect(await screen.findByText('智能调度未开启，各线路按现有解析配置。')).toBeInTheDocument()
    await user.click(screen.getByRole('switch'))
    await user.click(screen.getByText('按省份+运营商'))
    expect(screen.getByRole('radio', { name: '按省份+运营商' })).toBeChecked()
    const topN = screen.getByLabelText('每条线路选点数')
    await user.clear(topN)
    await user.type(topN, '5')
    const maxLoad = screen.getByLabelText('最大负载')
    await user.clear(maxLoad)
    await user.type(maxLoad, '70')
    await user.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(calls.filter((call) => call.method === 'PUT')).toHaveLength(1))
    const put = calls.find((call) => call.method === 'PUT')!
    expect(put.url).toMatch(new RegExp(`/v1/node-line-groups/${groupID}/smart-schedule$`))
    expect(put.headers['Idempotency-Key']).toMatch(/\S{8,}/)
    expect(put.headers['X-Request-ID']).toMatch(/^smart-schedule-save-/)
    expect(put.headers['If-Match']).toBeUndefined()
    expect(JSON.parse(put.body!)).toEqual({ enabled: true, top_n: 5, granularity: 'province_carrier', latency_window_minutes: 15, max_load_percent: 70 })
    expect(await screen.findByText('智能调度设置已保存')).toBeInTheDocument()
    await waitFor(() => expect(calls.filter((call) => call.method === 'GET' && call.url.endsWith('/smart-schedule'))).toHaveLength(2))
  })

  it('shows the latency matrix sorted by p50 and filters it', async () => {
    const calls = stubFetch()
    const user = userEvent.setup()
    renderDrawer()
    await user.click(await screen.findByRole('tab', { name: '延迟矩阵' }))
    const table = await screen.findByTestId('smart-schedule-matrix')
    expect(calls.some((call) => call.url.endsWith(`/v1/node-line-groups/${groupID}/latency-matrix?window=15`))).toBe(true)
    const rows = within(table).getAllByRole('row')
    // 表头 + 北京 + 广东（按 GB/T 2260 顺序）
    expect(rows.map((row) => within(row).queryByRole('rowheader')?.textContent ?? '')).toEqual(['', '北京', '广东'])
    const guangdong = within(rows[2]).getAllByRole('listitem').map((item) => item.querySelector('code')?.textContent)
    expect(guangdong).toEqual(['192.0.2.10', '192.0.2.11'])
    await user.type(screen.getByLabelText('节点'), '192.0.2.11')
    await waitFor(() => expect(within(screen.getByTestId('smart-schedule-matrix')).getAllByRole('row')).toHaveLength(2))
    await user.clear(screen.getByLabelText('节点'))
    await user.type(screen.getByLabelText('节点'), '203.0.113.9')
    expect(await screen.findByText('没有符合筛选条件的延迟数据。')).toBeInTheDocument()
  })

  it('renders English line names and province names', async () => {
    await i18n.changeLanguage('en-US')
    stubFetch()
    renderDrawer()
    const lines = await screen.findAllByTestId('smart-schedule-line')
    expect(lines.map((line) => line.querySelector('strong')?.textContent)).toEqual(['Unicom', 'Mobile', 'Guangdong Telecom', 'Tibet Mobile'])
    expect(screen.getByText('Falls back to Mobile')).toBeInTheDocument()
  })
})

describe('smart schedule contract', () => {
  it('has the same message keys in Chinese and English', () => {
    const keys = (tree: object, prefix = ''): string[] => Object.entries(tree).flatMap(([key, value]) =>
      typeof value === 'string' ? [`${prefix}${key}`] : keys(value, `${prefix}${key}.`))
    expect(keys(enUSNodeScheduling.smartSchedule)).toEqual(keys(zhCNNodeScheduling.smartSchedule))
  })

  it('rejects a malformed response and defaults province support to true', () => {
    expect(() => validateSmartSchedule({ enabled: 'yes' })).toThrow()
    const rest: Record<string, unknown> = { ...schedule }
    delete rest.province_lines_supported
    expect(validateSmartSchedule(rest).province_lines_supported).toBe(true)
    expect(() => validateSmartSchedule({ ...rest, granularity: 'city' })).toThrow()
  })
})
