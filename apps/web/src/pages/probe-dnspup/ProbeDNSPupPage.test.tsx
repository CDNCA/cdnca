import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { probeDNSPupMessages } from '../../i18n/probeDNSPup'
import { authResponse, nodeManagementSettingsFixture, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import ProbeDNSPupPage from './ProbeDNSPupPage'

function json(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, headers: new Headers({ 'content-type': 'application/json' }),
    text: vi.fn().mockResolvedValue(JSON.stringify(body)), json: vi.fn().mockResolvedValue(body) } as unknown as Response
}

// Obviously fake credentials.
const status = {
  licensed: true, enabled: true, active: true, base_url: 'https://api.dnspup.example', api_key: 'dnp_key_fake_probe_0000',
  secret_configured: true, secret_fingerprint: '0123456789abcdef', source_domain: '',
  origin_sources: ['node', 'dnspup', 'controller'], edge_sources: ['node', 'dnspup'], revision: 2,
  settings_updated_at: '2026-10-20T02:00:00Z', account_checked_at: '2026-10-20T02:00:00Z', async_capable: true,
  monthly_limit: 10000, monthly_used: 42, account_error_code: '', paused_until: null, pause_reason: '', pause_code: '',
}

type Fetch = (path: string, init?: RequestInit) => Promise<Response>

beforeEach(async () => {
  await changeLocale('zh-CN')
  const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['system.probe_dnspup.manage'] })
  useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'probe-dnspup-token' }, admin)
})
afterEach(() => vi.unstubAllGlobals())

// A node as the node list returns it (the matrix and override pickers read /v1/nodes).
const listedNode = { id: '', display_id: '', name: '', description: '', region: 'CN-East', ipv4: '192.0.2.10',
  admin_state: 'active', management_settings: nodeManagementSettingsFixture(), revision: 1,
  created_at: '2026-08-01T08:00:00Z', updated_at: '2026-08-01T09:00:00Z',
  presence: { status: 'online', last_heartbeat_at: '2026-08-01T08:59:55Z', agent_version: '2.4.1', session_epoch: 1, heartbeat_sequence: 1,
    projection_freshness: 'fresh', lease_signal: 'present', projected_at: '2026-08-01T08:59:56Z' } }

describe('ProbeDNSPupPage', () => {
  it('keeps every locale structurally complete', () => {
    const keys = (tree: object, prefix = ''): string[] => Object.entries(tree).flatMap(([k, v]) =>
      typeof v === 'string' ? [`${prefix}${k}`] : keys(v as object, `${prefix}${k}.`))
    expect(keys(probeDNSPupMessages['en-US'])).toEqual(keys(probeDNSPupMessages['zh-CN']))
  })

  it('shows quota and source order and saves without resending the stored secret', async () => {
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path === '/v1/admin/probe-dnspup' && !init?.method) return json(status)
      if (path === '/v1/admin/probe-dnspup' && init?.method === 'PUT') return json({ ...status, revision: 3 })
      return json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<ProbeDNSPupPage />)
    expect(await screen.findByDisplayValue('dnp_key_fake_probe_0000')).toBeInTheDocument()
    expect(screen.getByText('42 / 10000')).toBeInTheDocument()
    expect(screen.getByText('使用中')).toBeInTheDocument()
    expect(screen.getAllByText('dnspup 检测点').length).toBeGreaterThan(0)
    expect(screen.getByText(/已配置（指纹 0123456789abcdef）/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(true))
    const [, init] = fetchMock.mock.calls.find(([, call]) => call?.method === 'PUT')!
    expect(JSON.parse(String(init?.body))).toEqual({ enabled: true, base_url: status.base_url, api_key: status.api_key,
      source_domain: '', origin_sources: ['node', 'dnspup', 'controller'], edge_sources: ['node', 'dnspup'] })
    expect(new Headers(init?.headers).get('Idempotency-Key')).toBeTruthy()
  })

  it('rotates the key by sending a new secret and reports the capability test', async () => {
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path === '/v1/admin/probe-dnspup' && !init?.method) return json(status)
      if (path === '/v1/admin/probe-dnspup/tests') return json({ ok: false, http_status: 200, async_capable: false,
        http_allowed: true, tcping_allowed: true, monthly_limit: 10, monthly_used: 1, allowed_tools: ['http'], error_code: 'async_unavailable' })
      if (path === '/v1/admin/probe-dnspup' && init?.method === 'PUT') return json({ ...status, secret_fingerprint: 'fedcba9876543210' })
      return json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<ProbeDNSPupPage />)
    await screen.findByDisplayValue('dnp_key_fake_probe_0000')
    fireEvent.change(screen.getByLabelText('API Secret'), { target: { value: 'dnp_secret_fake_rotated_000000' } })
    fireEvent.click(screen.getByRole('button', { name: '测试连接与能力' }))
    expect(await screen.findByText(/dnspup 未开放异步拨测/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(true))
    const [, init] = fetchMock.mock.calls.find(([, call]) => call?.method === 'PUT')!
    expect(JSON.parse(String(init?.body)).api_secret).toBe('dnp_secret_fake_rotated_000000')
  })

  // 账户状态是「连接与来源」分区顶上的一行状态条；清除已保存的 Secret 改成 Secret 下方的复选框，保存时发空串。
  // 启用中清除 Secret 等于启用却没有 Secret（主控答 invalid_input），先停用才能清除。
  it('shows the account strip in the connection section and clears the stored secret from the checkbox', async () => {
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path === '/v1/admin/probe-dnspup' && !init?.method) return json(status)
      if (path === '/v1/admin/probe-dnspup' && init?.method === 'PUT') return json({ ...status, secret_configured: false })
      return json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<ProbeDNSPupPage />)
    await screen.findByDisplayValue('dnp_key_fake_probe_0000')
    const section = screen.getByRole('heading', { name: '连接与来源' }).closest('section')!
    expect(within(section).getByText('运行状态')).toBeInTheDocument()
    expect(within(section).getByText('42 / 10000')).toBeInTheDocument()
    expect(within(section).getByRole('switch', { name: '启用 dnspup 拨测' })).toBeChecked()
    fireEvent.click(within(section).getByRole('checkbox', { name: '清除已保存的 Secret' }))
    fireEvent.click(within(section).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(screen.getByLabelText('API Secret').closest('.ant-form-item')).toHaveClass('ant-form-item-has-error'))
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(false)
    fireEvent.click(within(section).getByRole('switch', { name: '启用 dnspup 拨测' }))
    fireEvent.click(within(section).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(true))
    const [, init] = fetchMock.mock.calls.find(([, call]) => call?.method === 'PUT')!
    expect(JSON.parse(String(init?.body))).toMatchObject({ enabled: false, api_secret: '' })
  })

  it('shows the pause and is view-only without the licence module', async () => {
    vi.stubGlobal('fetch', vi.fn<Fetch>(async () => json({ ...status, licensed: false, active: false,
      paused_until: '2026-10-20T03:00:00Z', pause_reason: 'quota_exceeded', pause_code: 'quota_exceeded' })))
    renderWithProviders(<ProbeDNSPupPage />)
    expect(await screen.findByText(/当前授权不含「dnspup 拨测」模块/)).toBeInTheDocument()
    expect(screen.getByText(/本月额度已用完/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '测试连接与能力' })).toBeDisabled()
  })

  // probe-node：节点可用性拨测设置 + 按请求估算的日/月消耗与 dnspup 余额并列。
  it('edits node availability probing and shows the estimate next to the balance', async () => {
    const node = {
      interval_seconds: 300, groups: ['telecom', 'unicom', 'mobile'], points_per_group: 3, failure_percent: 50,
      failure_rounds: 3, recovery_rounds: 1, low_balance: 1000, revision: 1, plugin_active: true, licensed: true,
      budget_state: 'normal', effective_interval_seconds: 300, monthly_limit: 10000, monthly_used: 42,
      account_checked_at: '2026-10-20T02:00:00Z', paused_until: null, balance_unit: 'request', max_addresses_per_round: 50,
      estimate: { addresses: 10, checkpoints_per_round: 9, rounds_per_day: 288, requests_per_day: 2880, requests_per_month: 86400 },
    }
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path === '/v1/admin/probe-dnspup' && !init?.method) return json(status)
      if (path === '/v1/admin/probe-dnspup/node-monitoring' && !init?.method) return json(node)
      if (path === '/v1/admin/probe-dnspup/node-monitoring' && init?.method === 'PUT') return json({ ...node, ...JSON.parse(String(init.body)), revision: 2 })
      return json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<ProbeDNSPupPage />)
    expect(await screen.findByText('每天约 2,880 次 · 每月约 86,400 次')).toBeInTheDocument()
    expect(screen.getByText('剩余 9,958 / 10,000 次')).toBeInTheDocument()
    expect(screen.getByText(/dnspup 按请求计量/)).toBeInTheDocument()
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '拨测频率' }))
    fireEvent.click(await screen.findByTitle('每 1 分钟'))
    expect(await screen.findByText('每天约 14,400 次 · 每月约 432,000 次')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '保存节点拨测设置' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([path, call]) => path.endsWith('/node-monitoring') && call?.method === 'PUT')).toBe(true))
    const [, init] = fetchMock.mock.calls.find(([path, call]) => path.endsWith('/node-monitoring') && call?.method === 'PUT')!
    expect(JSON.parse(String(init?.body))).toEqual({ interval_seconds: 60, groups: ['telecom', 'unicom', 'mobile'], points_per_group: 3,
      failure_percent: 50, failure_rounds: 3, recovery_rounds: 1, low_balance: 1000, probe_type: 'tcping', selection: null,
      line_alert_min_points: 3, line_alert_rounds: 2, auto_diagnose: true })
    expect(new Headers(init?.headers).get('Idempotency-Key')).toBeTruthy()
  })

  // 停用提示只列当前成立的原因。
  it.each([
    [{ enabled: false, secret_configured: false }, 'dnspup 拨测未启用，节点只由本机探测判定。'],
    [{ licensed: false, enabled: false }, 'dnspup 拨测未授权，节点只由本机探测判定。'],
    [{ paused_until: '2026-10-21T00:00:00Z', pause_reason: 'quota_exceeded', pause_code: 'q' }, 'dnspup 拨测已暂停，节点只由本机探测判定。'],
    [{ secret_configured: false }, 'dnspup 拨测未配置 Key，节点只由本机探测判定。'],
  ])('names the one reason node probing is not in use (%o)', async (connection, text) => {
    const node = {
      interval_seconds: 300, groups: ['telecom'], points_per_group: 3, failure_percent: 50, failure_rounds: 3, recovery_rounds: 1,
      low_balance: 1000, revision: 1, plugin_active: false, licensed: true, budget_state: 'normal', effective_interval_seconds: 300,
      monthly_limit: 100, monthly_used: 0, account_checked_at: null, paused_until: null, balance_unit: 'request',
      max_addresses_per_round: 50, estimate: { addresses: 0, checkpoints_per_round: 3, rounds_per_day: 288, requests_per_day: 0, requests_per_month: 0 },
    }
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => path.endsWith('/node-monitoring') ? json(node)
      : path === '/v1/admin/probe-dnspup' ? json({ ...status, ...connection }) : json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)))
    renderWithProviders(<ProbeDNSPupPage />)
    expect(await screen.findByText(text)).toBeInTheDocument()
    expect(screen.queryByText(/未授权、未启用/)).toBeNull()
  })

  it('warns when the balance is low or used up for node probing', async () => {
    const node = {
      interval_seconds: 300, groups: ['telecom'], points_per_group: 3, failure_percent: 50, failure_rounds: 3, recovery_rounds: 1,
      low_balance: 1000, revision: 1, plugin_active: true, licensed: true, budget_state: 'exhausted', effective_interval_seconds: 0,
      monthly_limit: 100, monthly_used: 100, account_checked_at: null, paused_until: null, balance_unit: 'request',
      max_addresses_per_round: 50, estimate: { addresses: 0, checkpoints_per_round: 3, rounds_per_day: 288, requests_per_day: 0, requests_per_month: 0 },
    }
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => path.endsWith('/node-monitoring') ? json(node)
      : path === '/v1/admin/probe-dnspup' ? json(status) : json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)))
    renderWithProviders(<ProbeDNSPupPage />)
    expect(await screen.findByText(/额度已用完：已停止 dnspup 节点拨测/)).toBeInTheDocument()
  })

  // 拨测未启用时用途行写原因、不写「正常」，也不说账户不限额。
  it('shows why the purposes are idle while probing is off and hides the account quota line', async () => {
    const gate = { stopped: false, factor: 1, daily_average: 0, projected_monthly: 0 }
    const purposes = { monthly_limit: 0, monthly_used: 0, projected_monthly: 0, purposes: [
      { purpose: 'node_availability', class: 1, enabled: true, monthly_cap: 0, interval_seconds: 0, used_this_month: 0, gate },
      { purpose: 'origin_failover', class: 2, enabled: true, monthly_cap: 0, interval_seconds: 0, used_this_month: 0, gate },
    ] }
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => {
      if (path === '/v1/admin/probe-dnspup') return json({ ...status, enabled: false, active: false, secret_configured: false })
      if (path === '/v1/admin/probe-dnspup/purposes') return json(purposes)
      if (path.endsWith('/overrides')) return json({ items: [] })
      if (path.startsWith('/v1/nodes?')) return json({ items: [] })
      if (path === '/v1/admin/probe-dnspup/edge-subjects') return json({ items: [] })
      return json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)
    }))
    renderWithProviders(<ProbeDNSPupPage />)
    const table = (await screen.findByRole('columnheader', { name: '额度状态' })).closest('table') as HTMLElement
    expect(await within(table).findAllByText('dnspup 拨测未启用')).toHaveLength(2)
    expect(within(table).queryByText('正常')).toBeNull()
    expect(screen.queryByText(/账户不限额/)).toBeNull()
    // the configured switches keep their saved values
    expect(screen.getByRole('switch', { name: '回源切换 启用' })).toBeChecked()
  })

  it('shows per purpose usage and degrade state, and the area × carrier matrix with failure categories', async () => {
    const gate = { stopped: false, factor: 1, daily_average: 10, projected_monthly: 300 }
    const purposes = { monthly_limit: 10000, monthly_used: 4200, projected_monthly: 9300, purposes: [
      { purpose: 'node_availability', class: 1, enabled: true, monthly_cap: 0, interval_seconds: 0, used_this_month: 3000,
        gate: { ...gate, projected_monthly: 9000 } },
      { purpose: 'origin_failover', class: 2, enabled: true, monthly_cap: 0, interval_seconds: 0, used_this_month: 100,
        gate: { ...gate, factor: 3, reason: 'account_slowdown' } },
      // cdncaCE has no aggregated edge: its row is not shown but is saved back as read.
      { purpose: 'edge_health', class: 2, enabled: true, monthly_cap: 0, interval_seconds: 0, used_this_month: 0, gate },
      { purpose: 'diagnose', class: 3, enabled: true, monthly_cap: 300, interval_seconds: 0, used_this_month: 300,
        gate: { ...gate, stopped: true, reason: 'monthly_cap', projected_monthly: 0 } },
    ] }
    const matrixNode = '018f0000-0000-7000-8000-0000000000e1'
    const matrix = { subject: 'node', id: matrixNode, window: '24h', series: [{ at: '2026-11-05T00:00:00Z', total: 4, availability: 0.5, avg_latency_ms: 30 }],
      cells: [{ area: '广东', carrier: 'mobile', total: 6, ok: 1, availability: 1 / 6, avg_latency_ms: 40, top_failure: 'timeout' },
        { area: '北京', carrier: 'edu', total: 2, ok: 2, availability: 1, avg_latency_ms: 12 }] }
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path === '/v1/admin/probe-dnspup') return json(status)
      if (path === '/v1/admin/probe-dnspup/purposes' && !init?.method) return json(purposes)
      if (path === '/v1/admin/probe-dnspup/purposes') return json(purposes)
      if (path.startsWith('/v1/admin/probe-dnspup/matrix?')) return json(matrix)
      if (path.endsWith('/overrides')) return json({ items: [] })
      if (path.startsWith('/v1/nodes?')) return json({ items: [{ ...listedNode, id: matrixNode, display_id: '1', name: 'node-a' }] })
      if (path === '/v1/admin/probe-dnspup/edge-subjects') return json({ items: [] })
      return json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<ProbeDNSPupPage />)
    expect(await screen.findByText('账户本月 4,200 / 10,000 次，各用途预计合计 9,300 次')).toBeInTheDocument()
    expect(screen.getByText('已降频 ×3')).toBeInTheDocument()
    expect(screen.getByText(/已停用 · 达到月上限/)).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: '节点可用性 启用' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: '保存用途设置' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([path, call]) => path.endsWith('/purposes') && call?.method === 'PUT')).toBe(true))
    const [, put] = fetchMock.mock.calls.find(([path, call]) => path.endsWith('/purposes') && call?.method === 'PUT')!
    expect(JSON.parse(String(put?.body)).purposes).toContainEqual({ purpose: 'diagnose', enabled: true, monthly_cap: 300, interval_seconds: 0 })
    expect(JSON.parse(String(put?.body)).purposes).toContainEqual({ purpose: 'edge_health', enabled: true, monthly_cap: 0, interval_seconds: 0 })
    expect(screen.queryByText('聚合边缘候选')).toBeNull()
    // 按节点名或显示编号选节点，请求仍带节点 UUID。
    expect(screen.getByRole('button', { name: '查看' })).toBeDisabled()
    const matrixPicker = screen.getByRole('combobox', { name: '矩阵节点' })
    fireEvent.change(matrixPicker, { target: { value: 'qa' } })
    fireEvent.click(await screen.findByText('node-a (ID 1)', { selector: '.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content' }))
    fireEvent.click(screen.getByRole('button', { name: '查看' }))
    expect(await screen.findByText('超时')).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '教育网' })).toBeInTheDocument()
    expect(screen.getByText('16.7% · 40 ms')).toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([path]) => path === `/v1/admin/probe-dnspup/matrix?subject=node&id=${matrixNode}&window=24h`)).toBe(true)

  })

  it('keeps the hidden aggregated edge candidates probe type as stored', async () => {
    // The community edition has no aggregated edge: no probe type column, and saving sends edge_health's stored type back.
    const gate = { stopped: false, factor: 1, daily_average: 0, projected_monthly: 0 }
    const purposes = { monthly_limit: 0, monthly_used: 0, projected_monthly: 0, purposes: [
      { purpose: 'node_availability', class: 1, enabled: true, monthly_cap: 0, interval_seconds: 0, used_this_month: 0, gate },
      { purpose: 'edge_health', class: 2, enabled: true, monthly_cap: 0, interval_seconds: 0, probe_type: 'https', used_this_month: 0, gate },
    ] }
    const fetchMock = vi.fn<Fetch>(async (path) => {
      if (path === '/v1/admin/probe-dnspup') return json(status)
      if (path === '/v1/admin/probe-dnspup/purposes') return json(purposes)
      if (path.endsWith('/overrides')) return json({ items: [] })
      return json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<ProbeDNSPupPage />)
    const save = await screen.findByRole('button', { name: '保存用途设置' })
    await waitFor(() => expect(save).toBeEnabled())
    expect(screen.queryByRole('combobox', { name: /拨测类型/ })).not.toBeInTheDocument()
    expect(screen.queryByText('聚合边缘候选改用 HTTPS 拨测')).not.toBeInTheDocument()
    fireEvent.click(save)
    await waitFor(() => expect(fetchMock.mock.calls.some(([path, call]) => path.endsWith('/purposes') && call?.method === 'PUT')).toBe(true))
    const [, put] = fetchMock.mock.calls.find(([path, call]) => path.endsWith('/purposes') && call?.method === 'PUT')!
    expect(JSON.parse(String(put?.body)).purposes).toEqual([
      { purpose: 'node_availability', enabled: true, monthly_cap: 0, interval_seconds: 0 },
      { purpose: 'edge_health', enabled: true, monthly_cap: 0, interval_seconds: 0, probe_type: 'https' },
    ])
  })

  it('picks override subjects from the node and line group lists and shows names', async () => {
    const nodeID = '018f0000-0000-7000-8000-000000000001'
    const groupID = '018f0000-0000-7000-8000-0000000000a1'
    const tenantScopeID = '018f0000-0000-7000-8000-0000000000b1'
    const node = { id: nodeID, display_id: '17', name: '上海一号', description: '', region: 'CN-East', ipv4: '192.0.2.10',
      admin_state: 'active', management_settings: nodeManagementSettingsFixture(), revision: 1,
      created_at: '2026-08-01T08:00:00Z', updated_at: '2026-08-01T09:00:00Z',
      presence: { status: 'online', last_heartbeat_at: '2026-08-01T08:59:55Z', agent_version: '2.4.1', session_epoch: 1, heartbeat_sequence: 1,
        projection_freshness: 'fresh', lease_signal: 'present', projected_at: '2026-08-01T08:59:56Z' } }
    const overrides = { items: [{ id: 'o1', subject_kind: 'line_group', tenant_scope_id: tenantScopeID, line_group_id: groupID,
      subject_name: '电信组', probe_type: 'ping', selection: null, revision: 1 }] }
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path === '/v1/admin/probe-dnspup') return json(status)
      if (path.endsWith('/overrides') && !init?.method) return json(overrides)
      if (path.endsWith('/overrides')) return json(overrides.items[0])
      if (path.startsWith('/v1/nodes?')) return json({ items: [node] })
      if (path.startsWith('/v1/node-line-groups?')) return json({ items: [{ id: groupID, display_id: '5', tenant_scope_id: tenantScopeID, name: '电信组' }] })
      return json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<ProbeDNSPupPage />)
    expect(await screen.findByText(groupID)).toBeInTheDocument()
    expect(screen.getAllByText('电信组').length).toBeGreaterThan(0)
    fireEvent.click(screen.getByRole('button', { name: '添加覆盖' }))
    const nodeSelect = await screen.findByRole('combobox', { name: '节点' })
    fireEvent.change(nodeSelect, { target: { value: '上海' } })
    fireEvent.click(await screen.findByText('上海一号 (ID 17)', { selector: '.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([path]) => path === '/v1/nodes?limit=50&search=%E4%B8%8A%E6%B5%B7')).toBe(true))
    fireEvent.click(screen.getByRole('button', { name: '保存覆盖' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([path, call]) => path.endsWith('/overrides') && call?.method === 'PUT')).toBe(true))
    const [, put] = fetchMock.mock.calls.find(([path, call]) => path.endsWith('/overrides') && call?.method === 'PUT')!
    expect(JSON.parse(String(put?.body))).toEqual({ node_id: nodeID })

    fireEvent.click(screen.getByRole('button', { name: '添加覆盖' }))
    fireEvent.mouseDown(within((await screen.findByRole('button', { name: '保存覆盖' })).closest('form')!).getByRole('combobox', { name: '对象' }))
    fireEvent.click(await screen.findByText('线路组', { selector: '.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content' }))
    const groupSelect = await screen.findByRole('combobox', { name: '线路组' })
    fireEvent.mouseDown(groupSelect)
    fireEvent.click(await screen.findByText('电信组 (ID 5)', { selector: '.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content' }))
    fireEvent.click(screen.getByRole('button', { name: '保存覆盖' }))
    await waitFor(() => expect(fetchMock.mock.calls.filter(([path, call]) => path.endsWith('/overrides') && call?.method === 'PUT')).toHaveLength(2))
    const [, second] = fetchMock.mock.calls.filter(([path, call]) => path.endsWith('/overrides') && call?.method === 'PUT')[1]
    expect(JSON.parse(String(second?.body))).toEqual({ tenant_scope_id: tenantScopeID, line_group_id: groupID })
    expect(fetchMock.mock.calls.some(([path]) => path.startsWith('/v1/node-line-groups?target_scope_id='))).toBe(true)
  })

  // 触发按钮带展开状态与收起名称，表单有取消，取消后焦点回到触发按钮且不发写请求。
  it('opens and cancels the override form from a disclosure button', async () => {
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path === '/v1/admin/probe-dnspup') return json(status)
      if (path.endsWith('/overrides') && !init?.method) return json({ items: [] })
      if (path.startsWith('/v1/nodes?')) return json({ items: [] })
      return json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<ProbeDNSPupPage />)
    const trigger = await screen.findByRole('button', { name: '添加覆盖' })
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(trigger)
    const opened = await screen.findByRole('button', { name: '收起添加覆盖' })
    expect(opened).toHaveAttribute('aria-expanded', 'true')
    const form = screen.getByRole('button', { name: '保存覆盖' }).closest('form')!
    expect(opened).toHaveAttribute('aria-controls', form.id)
    await waitFor(() => expect(within(form).getByRole('combobox', { name: '对象' })).toHaveFocus())
    fireEvent.click(within(form).getByRole('button', { name: '取消' }))
    expect(screen.queryByRole('button', { name: '保存覆盖' })).toBeNull()
    expect(screen.getByRole('button', { name: '添加覆盖' })).toHaveFocus()
    expect(fetchMock.mock.calls.some(([, call]) => call?.method === 'PUT')).toBe(false)
  })

  // cleanup-1107 ⑦: a tenant's own line group can be overridden from the page again (pick the tenant, then its
  // groups), and the list names subjects by display ID rather than by UUID.
  it('overrides a tenant line group after picking the tenant and lists subjects by display ID', async () => {
    const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['custom'],
      permissions: ['system.probe_dnspup.manage', 'identity.users.manage'] })
    useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'probe-dnspup-token' }, admin)
    const groupID = '018f0000-0000-7000-8000-0000000000c1'
    const tenantScopeID = '66666666-6666-4666-8666-666666666666'
    const user = { id: '55555555-5555-4555-8555-555555555555', display_id: '1024', scope_id: tenantScopeID,
      tenant_id: tenantScopeID, username: 'jason', display_name: 'jason', email: 'jason@example.com', phone: null, status: 'active',
      role: 'tenant_owner', group_id: null, group_name: null, revision: 1, created_at: '2026-10-27T00:00:00Z', updated_at: '2026-10-27T00:00:00Z' }
    const overrides = { items: [{ id: 'o2', subject_kind: 'line_group', tenant_scope_id: tenantScopeID, line_group_id: groupID,
      subject_name: '租户电信组', subject_display_id: 9, probe_type: 'ping', selection: null, revision: 1 }] }
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path === '/v1/admin/probe-dnspup') return json(status)
      if (path.endsWith('/overrides') && !init?.method) return json(overrides)
      if (path.endsWith('/overrides')) return json(overrides.items[0])
      if (path.startsWith('/v1/nodes?')) return json({ items: [] })
      if (path.startsWith('/v1/admin/users?')) return json({ items: [user], page: 1, limit: 20, total: 1 })
      if (path === `/v1/node-line-groups?target_scope_id=${tenantScopeID}`) {
        return json({ items: [{ id: groupID, display_id: '9', tenant_scope_id: tenantScopeID, name: '租户电信组' }] })
      }
      if (path.startsWith('/v1/node-line-groups?')) return json({ items: [] })
      return json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<ProbeDNSPupPage />)
    expect(await screen.findByText('ID 9')).toBeInTheDocument()
    expect(screen.queryByText(groupID)).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: '添加覆盖' }))
    const form = (await screen.findByRole('button', { name: '保存覆盖' })).closest('form')!
    fireEvent.mouseDown(within(form).getByRole('combobox', { name: '对象' }))
    fireEvent.click(await screen.findByText('线路组', { selector: '.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content' }))
    fireEvent.click(await screen.findByRole('radio', { name: '租户线路组' }))
    const tenantPicker = await screen.findByRole('combobox', { name: '租户' })
    fireEvent.mouseDown(tenantPicker)
    fireEvent.change(tenantPicker, { target: { value: '1024' } })
    await waitFor(() => expect(fetchMock.mock.calls.some(([path]) => path.startsWith('/v1/admin/users?') && path.includes('display_id=1024'))).toBe(true))
    fireEvent.click(await screen.findByText('jason（1024） · jason@example.com'))
    fireEvent.mouseDown(await screen.findByRole('combobox', { name: '线路组' }))
    fireEvent.click(await screen.findByText('租户电信组 (ID 9)', { selector: '.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content' }))
    fireEvent.click(screen.getByRole('button', { name: '保存覆盖' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([path, call]) => path.endsWith('/overrides') && call?.method === 'PUT')).toBe(true))
    const [, put] = fetchMock.mock.calls.find(([path, call]) => path.endsWith('/overrides') && call?.method === 'PUT')!
    expect(JSON.parse(String(put?.body))).toEqual({ tenant_scope_id: tenantScopeID, line_group_id: groupID })
  })

  // a disabled source saves with the key cleared (the stored secret is cleared
  // with it); the key pair is required only while enabled, the connection test always needs the key.
  it('saves a disabled source without credentials and asks for the key only when enabled or testing', async () => {
    const disabled = { ...status, enabled: false, active: false }
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path === '/v1/admin/probe-dnspup' && !init?.method) return json(disabled)
      if (path === '/v1/admin/probe-dnspup' && init?.method === 'PUT') return json({ ...disabled, api_key: '', secret_configured: false })
      return json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<ProbeDNSPupPage />)
    const key = await screen.findByDisplayValue('dnp_key_fake_probe_0000')
    fireEvent.change(key, { target: { value: '' } })
    fireEvent.click(screen.getByRole('button', { name: '测试连接与能力' }))
    await waitFor(() => expect(screen.getByLabelText('API Key').closest('.ant-form-item')).toHaveClass('ant-form-item-has-error'))
    expect(fetchMock.mock.calls.some(([path]) => path.endsWith('/tests'))).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(true))
    const [, init] = fetchMock.mock.calls.find(([, call]) => call?.method === 'PUT')!
    expect(JSON.parse(String(init?.body))).toMatchObject({ enabled: false, api_key: '', api_secret: '' })
    fireEvent.click(screen.getByRole('switch', { name: '启用 dnspup 拨测' }))
    fireEvent.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(screen.getByLabelText('API Key').closest('.ant-form-item')).toHaveClass('ant-form-item-has-error'))
    expect(fetchMock.mock.calls.filter(([, call]) => call?.method === 'PUT')).toHaveLength(1)
  })

  // the control plane's 401 is the console sign-in (the form stays filled); only
  // dnspup's own refusal of the key pair shows the key wording.
  it('tells an expired console sign-in from a dnspup key refusal', async () => {
    const node = {
      interval_seconds: 300, groups: ['telecom'], points_per_group: 3, failure_percent: 50, failure_rounds: 3, recovery_rounds: 1,
      low_balance: 1000, revision: 1, plugin_active: true, licensed: true, budget_state: 'normal', effective_interval_seconds: 300,
      monthly_limit: 100, monthly_used: 1, account_checked_at: null, paused_until: null, balance_unit: 'request',
      max_addresses_per_round: 50, estimate: { addresses: 1, checkpoints_per_round: 3, rounds_per_day: 288, requests_per_day: 288, requests_per_month: 8640 },
    }
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path === '/v1/admin/probe-dnspup' && !init?.method) return json(status)
      if (path === '/v1/admin/probe-dnspup/node-monitoring' && !init?.method) return json(node)
      if (path === '/v1/admin/probe-dnspup/node-monitoring') return json({ error: { code: 'unauthorized', message: 'x', request_id: 'r' } }, 401)
      if (path === '/v1/admin/probe-dnspup/tests') return json({ ok: false, http_status: 401, async_capable: false, http_allowed: false,
        tcping_allowed: false, monthly_limit: 0, monthly_used: 0, allowed_tools: [], error_code: 'unauthorized' })
      return json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<ProbeDNSPupPage />)
    await screen.findByText('每天约 288 次 · 每月约 8,640 次')
    fireEvent.click(screen.getByRole('button', { name: '保存节点拨测设置' }))
    expect(await screen.findByText('登录已失效，请重新登录后重试，已填内容会保留')).toBeInTheDocument()
    expect(screen.queryByText(/Key 或 Secret 无效/)).toBeNull()
    expect(screen.getByDisplayValue('dnp_key_fake_probe_0000')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '测试连接与能力' }))
    expect(await screen.findByText(/测试未通过：Key 或 Secret 无效、已停用或已到期/)).toBeInTheDocument()
  })

  // a finished mtr is a hop table per checkpoint (the 1132 live answer), the raw JSON
  // folded in the diagnostic details; ?diagnosis=<id> reads the submitted task back without starting a new one.
  it('shows a finished mtr as hop tables and restores it from the task ID', async () => {
    const id = '58d29ad5-eb81-4f2d-8d09-b18f6b67300f'
    const traces = [{ isp: '海外', city: '美国', node: '美国洛杉矶', nodeId: 'node-1734ee76a854', region: '海外', status: '', available: true,
      trace: { node: '美国洛杉矶', nodeId: 'node-1734ee76a854', target: '203.0.113.4', complete: true, sequence: 100, targetIp: '203.0.113.4',
        hops: [
          { as: '--', ip: '192.168.90.1', geo: '--', hop: 1, ptr: '--', loss: '0%', sent: 100, status: 'ok', agentPtr: '--', latestMs: 1,
            averageMs: 1, fastestMs: 1, originAsn: '--', slowestMs: 30 },
          { as: '--', ip: '--', geo: '--', hop: 2, ptr: '--', loss: '100%', sent: 100, status: 'slow', agentPtr: '--', latestMs: 0,
            lossKind: 'icmp_rate_limit', averageMs: 0, fastestMs: 0, slowestMs: 0 },
          { as: 'AS3257', ip: '198.51.100.58', geo: '美国/弗吉尼亚州/麦克林', hop: 4, ptr: 'ae10-501.cr7-lax2.ip4.gtt.net', loss: '0%',
            sent: 100, status: 'ok', agentPtr: 'ae10-501.cr7-lax2.ip4.gtt.net', serverPtr: 'ae10-501.cr7-lax2.ip4.gtt.net', averageMs: 4 },
          { as: 'AS152194', ip: '203.0.113.4', geo: '中国/香港特别行政区', hop: 9, ptr: '--', loss: '5%', sent: 100, status: 'slow',
            agentPtr: '--', latestMs: 149, lossKind: 'path_loss', averageMs: 150, fastestMs: 148, originAsn: 'AS152194', slowestMs: 182 },
        ] } }]
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path === '/v1/admin/probe-dnspup') return json(status)
      if (path === `/v1/admin/probe-dnspup/diagnoses/${id}`) return json({ id, status: 'completed', type: 'mtr', target: '203.0.113.4',
        created_at: '2026-11-23T10:55:54Z', results: [], traces })
      if (path === '/v1/admin/probe-dnspup/diagnoses' && init?.method === 'POST') return json({ id: 'x', status: 'pending' }, 202)
      if (path.endsWith('/overrides')) return json({ items: [] })
      return json({ error: { code: 'not_found', message: 'x', request_id: 'r' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<ProbeDNSPupPage />, [`/?diagnosis=${id}`])
    expect(await screen.findByText('排障完成')).toBeInTheDocument()
    const trace = screen.getByTestId('mtr-trace-0')
    expect(within(trace).getByText('美国洛杉矶 · 海外')).toBeInTheDocument()
    expect(within(trace).getByText('已完成')).toBeInTheDocument()
    for (const header of ['跳数', 'IP / 主机名', '平均延迟（ms）', '丢包率', '发送次数']) {
      expect(within(trace).getByRole('columnheader', { name: header })).toBeInTheDocument()
    }
    expect(within(trace).getByText('ae10-501.cr7-lax2.ip4.gtt.net')).toBeInTheDocument()
    expect(within(trace).getByText('100%')).toBeInTheDocument()
    expect(within(trace).getByText('5%')).toBeInTheDocument()
    expect(within(trace).getByText('150')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /诊断详情/ })).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText(/"lossKind"/)).toBeNull()
    expect(fetchMock.mock.calls.some(([path, call]) => path.endsWith('/diagnoses') && call?.method === 'POST')).toBe(false)
  })

  it('shows a 403 page without the permission', async () => {
    vi.stubGlobal('fetch', vi.fn<Fetch>(async () => json({ error: { code: 'permission_denied', message: 'x', request_id: 'r' } }, 403)))
    renderWithProviders(<ProbeDNSPupPage />)
    expect(await screen.findByText('需要 dnspup 拨测管理权限')).toBeInTheDocument()
  })
})
