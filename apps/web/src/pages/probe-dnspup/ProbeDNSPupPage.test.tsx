import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { probeDNSPupMessages } from '../../i18n/probeDNSPup'
import { authResponse, nodeManagementSettingsFixture, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import ProbeDNSPupPage from './ProbeDNSPupPage'

function json(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, text: vi.fn().mockResolvedValue(JSON.stringify(body)),
    json: vi.fn().mockResolvedValue(body) } as unknown as Response
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
    const matrix = { subject: 'node', id: 'node-1', window: '24h', series: [{ at: '2026-11-05T00:00:00Z', total: 4, availability: 0.5, avg_latency_ms: 30 }],
      cells: [{ area: '广东', carrier: 'mobile', total: 6, ok: 1, availability: 1 / 6, avg_latency_ms: 40, top_failure: 'timeout' },
        { area: '北京', carrier: 'edu', total: 2, ok: 2, availability: 1, avg_latency_ms: 12 }] }
    const fetchMock = vi.fn<Fetch>(async (path, init) => {
      if (path === '/v1/admin/probe-dnspup') return json(status)
      if (path === '/v1/admin/probe-dnspup/purposes' && !init?.method) return json(purposes)
      if (path === '/v1/admin/probe-dnspup/purposes') return json(purposes)
      if (path.startsWith('/v1/admin/probe-dnspup/matrix?')) return json(matrix)
      if (path.endsWith('/overrides')) return json({ items: [] })
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
    fireEvent.change(screen.getByRole('textbox', { name: '节点 ID' }), { target: { value: 'node-1' } })
    fireEvent.click(screen.getByRole('button', { name: '查看' }))
    expect(await screen.findByText('超时')).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: '教育网' })).toBeInTheDocument()
    expect(screen.getByText('16.7% · 40 ms')).toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([path]) => path === '/v1/admin/probe-dnspup/matrix?subject=node&id=node-1&window=24h')).toBe(true)
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

  it('shows a 403 page without the permission', async () => {
    vi.stubGlobal('fetch', vi.fn<Fetch>(async () => json({ error: { code: 'permission_denied', message: 'x', request_id: 'r' } }, 403)))
    renderWithProviders(<ProbeDNSPupPage />)
    expect(await screen.findByText('需要 dnspup 拨测管理权限')).toBeInTheDocument()
  })
})
