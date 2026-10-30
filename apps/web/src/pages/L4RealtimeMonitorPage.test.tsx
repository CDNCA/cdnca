import { screen } from '@testing-library/react'
import { vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import L4RealtimeMonitorPage from './L4RealtimeMonitorPage'

const tenantID = '018f0000-0000-7000-8000-000000000010'

function authenticateTenant(permissions = ['sites.read']) {
  const actor = principal({
    scope_kind: 'tenant',
    scope_id: tenantID,
    tenant_id: tenantID,
    permissions,
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function authenticateAdmin() {
  const actor = principal({
    scope_kind: 'platform',
    scope_id: 'platform',
    tenant_id: null,
    roles: ['platform_admin'],
    permissions: ['platform.admin'],
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

// Echoes the requested window (the default "today" is sent as a custom window ending now).
function realtimeResponse(input: RequestInfo | URL) {
  const url = new URL(String(input), 'https://cdnca.test')
  const to = url.searchParams.get('to') ?? '2026-09-15T03:00:00Z'
  return new Response(JSON.stringify({
    version: 'l4-realtime/v1',
    meta: {
      range: url.searchParams.get('range') ?? '1h', timezone: 'UTC', from: url.searchParams.get('from') ?? '2026-09-15T02:00:00Z', to,
      snapshot: { at: to, source_watermark: 9, finalized_through: to },
    },
    totals: { sessions: 7, bytes_up: 1024, bytes_down: 2048, errors: 1 },
    rows: [{
      bucket: '2026-09-15T02:59:00Z',
      node_id: '018f0000-0000-7000-8000-000000000020',
      site_id: '018f0000-0000-7000-8000-000000000030',
      stream_id: '018f0000-0000-7000-8000-000000000040',
      listener_id: '018f0000-0000-7000-8000-000000000050',
      protocol: 'tcp', listen_port: 443, sessions: 7, bytes_up: 1024, bytes_down: 2048, errors: 1,
    }],
  }), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

describe('L4RealtimeMonitorPage access and locale', () => {
  beforeEach(async () => {
    await changeLocale('zh-CN')
    useSessionStore.getState().clearSession()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('fails closed before authentication and does not fetch', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<L4RealtimeMonitorPage />, ['/monitor/stream/realtime'])
    expect(await screen.findByText('无权查看四层实时监控')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('rejects a tenant without the required permission', async () => {
    authenticateTenant([])
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<L4RealtimeMonitorPage />, ['/monitor/stream/realtime'])
    expect(await screen.findByText('无权查看四层实时监控')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('uses the same canonical page when a legacy mode query is present', async () => {
    authenticateTenant()
    renderWithProviders(<L4RealtimeMonitorPage />, ['/monitor/stream/realtime?mode=advanced'])
    expect(await screen.findByRole('tab', { name: '带宽流量', selected: true })).toBeInTheDocument()
    expect(screen.getAllByRole('tab')).toHaveLength(2)
    expect(screen.queryByRole('tab', { name: '明细' })).not.toBeInTheDocument()
  })

  it('renders the namespace in pseudo locale', async () => {
    await changeLocale('qps-ploc')
    authenticateTenant()
    renderWithProviders(<L4RealtimeMonitorPage />, ['/monitor/stream/realtime'])
    expect(await screen.findByRole('heading', { name: '［四层转发实时监控］' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '［带宽流量］' })).toBeInTheDocument()
  })

  it('loads the platform-wide realtime feed by default and renders returned traffic', async () => {
    authenticateAdmin()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(String(input).includes('/l4-realtime')
      ? realtimeResponse(input) : new Response('{}', { status: 503, headers: { 'Content-Type': 'application/json' } })))

    renderWithProviders(<L4RealtimeMonitorPage />, ['/monitor/stream/realtime'])

    expect((await screen.findAllByText('3 KB')).length).toBeGreaterThan(0)
    const url = new URL(String(fetchSpy.mock.calls.find((call) => String(call[0]).includes('/l4-realtime'))?.[0]), 'https://cdnca.test')
    expect(url.pathname).toBe('/v1/admin/analytics/l4-realtime')
    // fix-rangecompact：默认今天，以 custom 窗口（今天 00:00 至当前）发送。
    expect(url.searchParams.get('range')).toBe('custom')
    expect(new Date(url.searchParams.get('from')!).getTime()).toBe(new Date(new Date(url.searchParams.get('to')!).setHours(0, 0, 0, 0)).getTime())
    expect(url.searchParams.has('tenant_id')).toBe(false)
  })
})
