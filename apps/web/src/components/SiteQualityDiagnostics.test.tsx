import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import SiteQualityDiagnostics from './SiteQualityDiagnostics'
import { renderWithProviders } from '../test/render'

const siteID = '018f0000-0000-7000-8000-000000000002'
const tenantID = '018f0000-0000-7000-8000-000000000001'
const filters = {
  from: '2026-08-08T01:00:00.000Z',
  to: '2026-08-08T02:00:00.000Z',
  siteId: siteID,
}

function diagnosticResponse(cursor: string | null, suffix: string) {
  return new Response(JSON.stringify({
    items: [{
      event_id: `event-${suffix}`,
      occurred_at: '2026-08-08T01:59:00.000Z',
      site_id: siteID,
      node_id: '018f0000-0000-7000-8000-000000000003',
      category: 'config_mismatch',
      cause_code: 'upstream_reported_config_mismatch',
      action_code: 'reconcile_config',
      status_code: 530,
      config_version_id: '018f0000-0000-7000-8000-000000000006',
      installation_id: '018f0000-0000-7000-8000-000000000007',
      request_id: `request-${suffix}`,
      task_id: '018f0000-0000-7000-8000-000000000009',
      trace_id: `trace-${suffix}`,
    }],
    next_cursor: cursor,
    snapshot: {
      at: '2026-08-08T02:00:00.000Z',
      source_watermark: 42,
      finalized_through: '2026-08-08T02:00:00.000Z',
      expires_at: '2026-08-08T02:05:00.000Z',
    },
  }), { headers: { 'Content-Type': 'application/json' } })
}

describe('SiteQualityDiagnostics', () => {
  it('renders redacted identity, finalized evidence, and exact snapshot cursor pages', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'http://cdnca.test')
      return Promise.resolve(url.searchParams.has('cursor')
        ? diagnosticResponse(null, 'second')
        : diagnosticResponse('c2lnbmVkLWN1cnNvcg', 'first'))
    })
    const user = userEvent.setup()

    renderWithProviders(<SiteQualityDiagnostics accessToken="token" audience="tenant" filters={filters} />)

    expect(await screen.findByText('request-first')).toBeInTheDocument()
    expect(screen.getByText('配置失配')).toBeInTheDocument()
    expect(screen.getByText('上游明确报告配置失配')).toBeInTheDocument()
    expect(screen.getByText('对齐配置版本')).toBeInTheDocument()
    expect(screen.getByText(/42/)).toBeInTheDocument()
    expect(screen.queryByText(/cdn\.example/)).not.toBeInTheDocument()
    expect(screen.queryByText(/authorization/i)).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('request-second')).toBeInTheDocument()
    const secondURL = new URL(String(fetchSpy.mock.calls[1][0]), 'http://cdnca.test')
    expect(secondURL.pathname).toBe('/v1/analytics/site-quality-diagnostics')
    expect(secondURL.searchParams.get('cursor')).toBe('c2lnbmVkLWN1cnNvcg')
  })

  it('uses the platform route and surfaces forbidden without raw server text', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      error: { code: 'quality_diagnostics_permission_denied', message: 'clickhouse password secret', request_id: 'request-1' },
    }), { status: 403, headers: { 'Content-Type': 'application/json' } }))

    renderWithProviders(<SiteQualityDiagnostics accessToken="token" audience="admin" filters={{ ...filters, tenantId: tenantID }} />)

    expect(await screen.findByText('无权查看质量诊断')).toBeInTheDocument()
    expect(screen.queryByText(/clickhouse password secret/i)).not.toBeInTheDocument()
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'http://cdnca.test')
    expect(url.pathname).toBe('/v1/admin/analytics/site-quality-diagnostics')
    expect(url.searchParams.get('tenant_id')).toBe(tenantID)
  })

  it('shows loading, empty, and stable dependency errors', async () => {
    let resolveRequest!: (response: Response) => void
    vi.spyOn(globalThis, 'fetch').mockReturnValue(new Promise((resolve) => { resolveRequest = resolve }))
    const { unmount } = renderWithProviders(
      <SiteQualityDiagnostics accessToken="token" audience="tenant" filters={{ ...filters, category: 'edge_530' }} />,
    )
    expect(screen.getByLabelText('正在加载质量诊断')).toBeInTheDocument()
    resolveRequest(new Response(JSON.stringify({
      items: [], next_cursor: null,
      snapshot: {
        at: '2026-08-08T02:00:00.000Z', source_watermark: 42,
        finalized_through: '2026-08-08T02:00:00.000Z', expires_at: '2026-08-08T02:05:00.000Z',
      },
    }), { headers: { 'Content-Type': 'application/json' } }))
    expect(await screen.findByText('当前范围内没有诊断事件')).toBeInTheDocument()
    unmount()

    vi.restoreAllMocks()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      error: { code: 'quality_diagnostics_unavailable', message: 'raw dependency detail', request_id: 'request-2' },
    }), { status: 503, headers: { 'Content-Type': 'application/json' } }))
    renderWithProviders(<SiteQualityDiagnostics accessToken="token" audience="tenant" filters={filters} />)
    expect(await screen.findByText('诊断证据暂不可用，请稍后重试。')).toBeInTheDocument()
    expect(screen.queryByText(/raw dependency detail/i)).not.toBeInTheDocument()
  })
})
