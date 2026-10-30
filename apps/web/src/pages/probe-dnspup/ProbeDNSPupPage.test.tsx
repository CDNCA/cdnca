import { fireEvent, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { probeDNSPupMessages } from '../../i18n/probeDNSPup'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import ProbeDNSPupPage from './ProbeDNSPupPage'

function json(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, text: vi.fn().mockResolvedValue(JSON.stringify(body)) } as unknown as Response
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
      failure_percent: 50, failure_rounds: 3, recovery_rounds: 1, low_balance: 1000 })
    expect(new Headers(init?.headers).get('Idempotency-Key')).toBeTruthy()
  })

  it('warns when the balance is low or used up for node probing', async () => {
    const node = {
      interval_seconds: 300, groups: ['telecom'], points_per_group: 3, failure_percent: 50, failure_rounds: 3, recovery_rounds: 1,
      low_balance: 1000, revision: 1, plugin_active: true, licensed: true, budget_state: 'exhausted', effective_interval_seconds: 0,
      monthly_limit: 100, monthly_used: 100, account_checked_at: null, paused_until: null, balance_unit: 'request',
      max_addresses_per_round: 50, estimate: { addresses: 0, checkpoints_per_round: 3, rounds_per_day: 288, requests_per_day: 0, requests_per_month: 0 },
    }
    vi.stubGlobal('fetch', vi.fn<Fetch>(async (path) => json(path.endsWith('/node-monitoring') ? node : status)))
    renderWithProviders(<ProbeDNSPupPage />)
    expect(await screen.findByText(/额度已用完：已停止 dnspup 节点拨测/)).toBeInTheDocument()
  })

  it('shows a 403 page without the permission', async () => {
    vi.stubGlobal('fetch', vi.fn<Fetch>(async () => json({ error: { code: 'permission_denied', message: 'x', request_id: 'r' } }, 403)))
    renderWithProviders(<ProbeDNSPupPage />)
    expect(await screen.findByText('需要 dnspup 拨测管理权限')).toBeInTheDocument()
  })
})
