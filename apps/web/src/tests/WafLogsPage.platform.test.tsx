import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { useSessionStore } from '../auth/session'
import WafLogsPage from '../pages/WafLogsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const tenantId = '018f0000-0000-7000-8000-000000000010'

function overview(input: RequestInfo | URL): Response {
  const url = new URL(String(input), 'http://cdnca.test')
  return new Response(JSON.stringify({
    data: {
      attacks: 3, blocked: 2, intercepted: 1, observed: 0, auto_blocked: 0, clients: 2, trend: [],
      attack_types: [{ key: 'sqli', count: 3 }], top_domains: [{ key: 'a.example.test', count: 3 }],
      top_clients: [], top_countries: [], top_provinces: [], top_carriers: [], top_uris: [],
    },
    meta: { from: url.searchParams.get('from'), to: url.searchParams.get('to'), timezone: 'UTC', metric_version: 1 },
  }), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

// stats-platform-l7：WAF 日志进入即按全平台加载，不带租户也不要求先填筛选。
describe('WafLogsPage platform scope', () => {
  it('loads the platform-wide overview on entry without a tenant or other filter', async () => {
    const actor = principal({ scope_kind: 'platform', scope_id: 'platform', tenant_id: null, permissions: ['sites.read', 'platform.admin'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(overview(input)))
    renderWithProviders(<WafLogsPage />)

    await waitFor(() => expect(fetchSpy).toHaveBeenCalled())
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'http://cdnca.test')
    expect(url.pathname).toBe('/v1/admin/analytics/waf-overview')
    for (const key of ['tenant_id', 'site_id', 'node_id', 'domain']) expect(url.searchParams.has(key)).toBe(false)
    expect((await screen.findAllByText('a.example.test')).length).toBeGreaterThan(0)
  })

  it('keeps a tenant on its own route without naming a tenant', async () => {
    const actor = principal({ scope_kind: 'tenant', scope_id: tenantId, tenant_id: tenantId, permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(overview(input)))
    renderWithProviders(<WafLogsPage />)

    await waitFor(() => expect(fetchSpy).toHaveBeenCalled())
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'http://cdnca.test')
    expect(url.pathname).toBe('/v1/analytics/waf-overview')
    expect(url.searchParams.has('tenant_id')).toBe(false)
  })

  // fix-rangepicker：概览与日志明细都用共享时间范围组件（快捷项 + 自定义），概览保持整点、最多 31 天。
  it('queries a quick range on the hour and a custom range from the shared picker', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: new Date(2026, 9, 28, 10, 20) })
    const actor = principal({ scope_kind: 'tenant', scope_id: tenantId, tenant_id: tenantId, permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(overview(input)))
    const user = userEvent.setup()
    renderWithProviders(<WafLogsPage />)
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1))
    const window = (call: number) => {
      const url = new URL(String(fetchSpy.mock.calls[call][0]), 'http://cdnca.test')
      return [url.searchParams.get('from'), url.searchParams.get('to')]
    }
    expect(window(0)).toEqual([new Date(2026, 9, 28).toISOString(), new Date(2026, 9, 29).toISOString()])
    const range = screen.getByRole('group', { name: '时间范围' })
    expect(within(range).getByRole('radio', { name: '今天' })).toBeChecked()
    expect(within(range).getByRole('radio', { name: '近30天' })).toBeInTheDocument()

    // fix-rangecompact：快捷项统一为今天/近7天/近30天；整点精度下近7天止于当前小时末。
    await user.click(within(range).getByText('近7天'))
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
    expect(window(1)).toEqual([new Date(2026, 9, 21, 11).toISOString(), new Date(2026, 9, 28, 11).toISOString()])

    await user.click(within(range).getByText('自定义'))
    await user.click(screen.getByRole('textbox', { name: '选择时间范围' }))
    await user.click(screen.getAllByRole('button', { name: '2026-10-20' })[0])
    await user.click(screen.getAllByRole('button', { name: '2026-10-21' })[0])
    await user.click(screen.getByRole('button', { name: '选择时间' }))
    // Whole hours only.
    expect(screen.queryByRole('group', { name: '开始时间分钟' })).not.toBeInTheDocument()
    await user.click(within(screen.getByRole('group', { name: '结束时间小时' })).getByRole('button', { name: '08' }))
    expect(screen.queryByRole('button', { name: '清空' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '确定' }))
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(3))
    expect(window(2)).toEqual([new Date(2026, 9, 20).toISOString(), new Date(2026, 9, 21, 8).toISOString()])
    vi.useRealTimers()
  })

  it('replaces the two start/end inputs of the log details with the shared picker', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: new Date(2026, 9, 28, 10, 20) })
    const actor = principal({ scope_kind: 'tenant', scope_id: tenantId, tenant_id: tenantId, permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'http://cdnca.test')
      if (url.pathname.endsWith('/block-events')) {
        return Promise.resolve(new Response(JSON.stringify({ data: [], meta: { limit: 50, next_cursor: null } }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      }
      return Promise.resolve(overview(input))
    })
    const blockCalls = () => fetchSpy.mock.calls.map(([input]) => new URL(String(input), 'http://cdnca.test')).filter((url) => url.pathname.endsWith('/block-events'))
    const user = userEvent.setup()
    renderWithProviders(<WafLogsPage />)
    await user.click(await screen.findByRole('tab', { name: '日志明细' }))
    await waitFor(() => expect(blockCalls()).toHaveLength(1))
    const panel = screen.getByRole('tabpanel')
    expect(within(panel).queryByLabelText('开始时间')).not.toBeInTheDocument()
    expect(within(panel).queryByLabelText('结束时间')).not.toBeInTheDocument()
    const range = within(panel).getByRole('group', { name: '时间范围' })
    await user.click(within(range).getByText('近7天'))
    await user.click(within(panel).getByRole('button', { name: '查询' }))
    await waitFor(() => expect(blockCalls()).toHaveLength(2))
    expect([blockCalls()[1].searchParams.get('from'), blockCalls()[1].searchParams.get('to')])
      .toEqual([new Date(2026, 9, 21, 10, 20).toISOString(), new Date(2026, 9, 28, 10, 20).toISOString()])
    vi.useRealTimers()
  })
})
