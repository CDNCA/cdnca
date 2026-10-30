import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { DashboardAnalyticsOverview } from '../api/dashboard'
import { l4RealtimeApi } from '../api/l4Realtime'
import { useSessionStore } from '../auth/session'
import { DashboardAnalyticsView } from '../components/DashboardOverview'
import L4RealtimeMonitorPage from '../pages/L4RealtimeMonitorPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const renderer = vi.hoisted(() => ({ setOption: vi.fn() }))
vi.mock('../components/echartsRuntime', () => ({
  init: () => ({ setOption: renderer.setOption, resize: vi.fn(), dispose: vi.fn() }),
}))

const summary: DashboardAnalyticsOverview['summary'] = {
  metric_version: 1, request_count: '2', request_bytes: '0', response_bytes: '512', total_bytes: '512',
  average_bandwidth_bps: 500, status_2xx: '2', status_3xx: '0', status_4xx: '0', status_5xx: '0', security_events: '0',
}

describe('analytics minimum display units', () => {
  it.each(['default', 'admin'] as const)('uses Kbps without rescaling chart data in the %s dashboard', async (variant) => {
    renderer.setOption.mockClear()
    renderWithProviders(<DashboardAnalyticsView variant={variant} mode="trend" locale="zh-CN" analytics={{
      summary, trend: [{ ...summary, hour: '2026-09-26T01:00:00Z' }], top: [],
    }} />)
    await waitFor(() => expect(renderer.setOption).toHaveBeenCalled())
    const option = renderer.setOption.mock.calls.at(-1)![0]
    expect(option.series[0].data).toEqual([500])
    expect(option.yAxis.axisLabel.formatter(500)).toBe('0.5 Kbps')
    expect(option.tooltip.valueFormatter(0)).toBe('0 Kbps')
    expect(option.tooltip.valueFormatter(1_000_000)).toBe('1 Mbps')
  })

  it('uses KB in the traffic trend without changing byte samples', async () => {
    renderWithProviders(<DashboardAnalyticsView variant="admin" mode="trend" locale="zh-CN" analytics={{
      summary, trend: [{ ...summary, hour: '2026-09-26T01:00:00Z' }], top: [],
    }} />)
    await userEvent.setup().click(screen.getByRole('tab', { name: '流量' }))
    await waitFor(() => expect(renderer.setOption.mock.calls.at(-1)![0].series[0].data).toEqual([512]))
    expect(renderer.setOption.mock.calls.at(-1)![0].yAxis.axisLabel.formatter(512)).toBe('0.5 KB')
  })

  it.each(['default', 'admin'] as const)('uses KB in %s rankings while retaining large integer precision', (variant) => {
    renderWithProviders(<DashboardAnalyticsView variant={variant} mode="rankings" locale="zh-CN" analytics={{
      summary, trend: [], top: [{ dimension: 'domain', snapshot_at: '2026-09-26T01:00:00Z', items: [
        { key: 'small.example.test', request_count: '2', response_bytes: '512' },
        { key: 'large.example.test', request_count: '2', response_bytes: '9223372036854775807' },
      ] }],
    }} />)
    expect(screen.getByText('0.5 KB')).toBeInTheDocument()
    expect(screen.getByText('8 EB')).toBeInTheDocument()
  })

  it('shows domain ranks as host:port and URL ranks as scheme://host:port/path (AUDIT-FINAL-1027 P8)', async () => {
    renderWithProviders(<DashboardAnalyticsView variant="admin" mode="rankings" locale="zh-CN" analytics={{
      summary, trend: [], top: [], top_extended: [
        { dimension: 'domain', snapshot_at: '2026-09-26T01:00:00Z', items: [
          { key: 'www.example.test:8080', request_count: '2', response_bytes: '1', host: 'www.example.test', port: 8080 }] },
        { dimension: 'url', snapshot_at: '2026-09-26T01:00:00Z', items: [
          { key: 'www.example.test:443/a?b', request_count: '2', response_bytes: '1', host: 'www.example.test', port: 443, path: '/a?b', scheme: 'https' },
          { key: 'old.example.test/x', request_count: '1', response_bytes: '1', host: 'old.example.test', path: '/x' }] },
        { dimension: 'ip', snapshot_at: '2026-09-26T01:00:00Z', items: [] },
        { dimension: 'region', snapshot_at: '2026-09-26T01:00:00Z', items: [] },
        { dimension: 'carrier', snapshot_at: '2026-09-26T01:00:00Z', items: [] },
      ],
    }} />)
    expect(screen.getByText('www.example.test:8080')).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('tab', { name: 'URL' }))
    expect(await screen.findByText('https://www.example.test:443/a?b')).toBeInTheDocument()
    expect(screen.getByText('old.example.test/x')).toBeInTheDocument()
  })

  it('uses Kbps and KB for layer-4 chart labels and traffic ranking', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(l4RealtimeApi, 'read').mockResolvedValue({
      version: 'l4-realtime/v1',
      meta: { range: '1h', timezone: 'UTC', from: '2026-09-26T01:00:00Z', to: '2026-09-26T02:00:00Z', snapshot: { source_watermark: 1, finalized_through: '2026-09-26T02:00:00Z' } },
      totals: { sessions: 1, bytes_up: 256, bytes_down: 256, errors: 0 },
      rows: [{ bucket: '2026-09-26T01:00:00Z', node_id: 'node', site_id: 'site', stream_id: 'stream', listener_id: 'listener', protocol: 'tcp', listen_port: 443, sessions: 1, bytes_up: 256, bytes_down: 256, errors: 0 }],
    })
    renderWithProviders(<L4RealtimeMonitorPage />)
    expect(await within(screen.getByRole('region', { name: '流量' })).findAllByText('0.5 KB')).not.toHaveLength(0)
    expect(within(screen.getByRole('region', { name: '带宽' })).getAllByText('0.07 Kbps')).not.toHaveLength(0)
    await userEvent.setup().click(screen.getByRole('tab', { name: '端口排行' }))
    expect(await screen.findByText('0.5 KB')).toBeInTheDocument()
  })
})
