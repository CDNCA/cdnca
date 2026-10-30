import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'

import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import SiteAnalysisPage from '../pages/SiteAnalysisPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// The ranking's first column was "维度值" for every
// tab; it is named after the dimension, and client IPs never show ::ffff:.
const tenantId = '018f0000-0000-7000-8000-000000000010'
const snapshot = '2026-07-22T10:15:00Z'
const zeroSummary = {
  metric_version: 1, request_count: 0, request_bytes: 0, response_bytes: 0, total_bytes: 0, average_bandwidth_bps: 0,
  status_2xx: 0, status_3xx: 0, status_4xx: 0, status_5xx: 0, security_events: 0, security_event_rows: 0,
  cache_hit_requests: 0, cache_hit_bytes: 0, unique_client_ips: 0,
}
const longIPv6 = '2001:db8:85a3:1234:5678:8a2e:370:7334'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function mockAnalytics() {
  const actor = principal({ scope_kind: 'tenant', scope_id: tenantId, tenant_id: tenantId, permissions: ['sites.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
    const url = new URL(String(input), 'http://cdnca.test')
    const meta = { from: url.searchParams.get('from'), to: url.searchParams.get('to'), timezone: 'UTC', metric_version: 1 }
    if (url.pathname.endsWith('/summary')) return Promise.resolve(json({ data: zeroSummary, meta }))
    const dimension = url.pathname.split('/').at(-1)!
    const rows: Record<string, unknown>[] = dimension === 'ip'
      ? [{ key: '::ffff:203.0.113.61' }, { key: longIPv6 }]
      : dimension === 'domain'
        ? [{ key: 'x.example:8080', host: 'x.example', port: 8080 }, { key: 'x.example', host: 'x.example', port: 0 }]
        : dimension === 'url'
          ? [
              { key: 'x.example:443/a?b', host: 'x.example', port: 443, path: '/a', scheme: 'https' },
              { key: 'x.example:8080/a', host: 'x.example', port: 8080, path: '/a', scheme: 'http' },
              { key: 'y.example/z', host: 'y.example', port: 0, path: '/z' },
            ]
          : [{ key: 'x.example' }]
    return Promise.resolve(json({
      data: rows.map((row, index) => ({ ...row, request_count: 5 - index, response_bytes: 500 - index })),
      dimension, page: { snapshot_at: snapshot, source: 'history' }, meta,
    }))
  })
}

function SearchProbe() {
  return <output data-testid="search">{useLocation().search}</output>
}

function firstColumnTitle(): string {
  return within(screen.getByRole('table')).getAllByRole('columnheader')[1]!.textContent ?? ''
}

describe('SiteAnalysisPage ranking first column', () => {
  it('names the first column after each dimension (zh-CN)', async () => {
    mockAnalytics()
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />)
    await screen.findByText('x.example:8080')
    // Expected rank tab and column names.
    const expected: [string, string][] = [
      ['域名排行', '域名'], ['热门URL', 'URL'], ['TLS指纹', 'TLS指纹'], ['Top客户端IP', '客户端IP'],
      ['国家排行', '国家'], ['省份排行', '省份'], ['运营商排行', '运营商'], ['浏览器分布', '浏览器'],
      ['操作系统分布', '操作系统'], ['热门Referer', '来源'],
    ]
    for (const [tab, title] of expected) {
      await user.click(screen.getByRole('tab', { name: tab }))
      expect(firstColumnTitle(), tab).toBe(title)
    }
    expect(screen.queryByText('维度值')).not.toBeInTheDocument()
  })

  it('shows IPv4 clients without ::ffff: and keeps long IPv6 in a monospace, ellipsized cell with the full text on hover', async () => {
    mockAnalytics()
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />)
    await screen.findByText('x.example')
    await user.click(screen.getByRole('tab', { name: 'Top客户端IP' }))
    const ipv4 = await screen.findByText('203.0.113.61')
    expect(screen.queryByText(/::ffff:/)).not.toBeInTheDocument()
    const ipv6 = screen.getByText(longIPv6)
    for (const cell of [ipv4, ipv6]) {
      expect(cell).toHaveClass('analytics-rank-key', 'analytics-rank-key-ip')
      expect(cell).toHaveAttribute('title', cell.textContent)
    }
  })

  it('shows domains as host:port and hot URLs as scheme://host:port/path', async () => {
    mockAnalytics()
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />)
    expect(await screen.findByText('x.example:8080')).toHaveAttribute('title', 'x.example:8080')
    expect(screen.getByText('x.example')).toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: '热门URL' }))
    expect(await screen.findByText('https://x.example:443/a')).toHaveAttribute('title', 'https://x.example:443/a')
    expect(screen.getByText('http://x.example:8080/a')).toBeInTheDocument()
    // Without a known scheme or port the address keeps what is known.
    expect(screen.getByText('y.example/z')).toBeInTheDocument()
  })

  it.each([
    ['域名排行', 'x.example:8080', { host: 'x.example', uri_path: null }],
    ['热门URL', 'https://x.example:443/a', { host: 'x.example', uri_path: '/a' }],
  ] as const)('opens the access log of %s filtered by host and path', async (tab, row, want) => {
    mockAnalytics()
    const user = userEvent.setup()
    renderWithProviders(
      <Routes>
        <Route path="/" element={<SiteAnalysisPage />} />
        <Route path="/monitor/site/access-log" element={<SearchProbe />} />
      </Routes>,
    )
    await screen.findByText('x.example:8080')
    await user.click(screen.getByRole('tab', { name: tab }))
    await user.click(within((await screen.findByText(row)).closest('tr')!).getByRole('button', { name: '查看日志' }))
    const search = new URLSearchParams(await screen.findByTestId('search').then((node) => node.textContent ?? ''))
    expect({ host: search.get('host'), uri_path: search.get('uri_path') }).toEqual(want)
    expect(search.get('domain')).toBeNull()
  })

  it.each([
    ['a network error', () => Promise.reject(new TypeError('fetch failed'))],
    ['a 502', () => Promise.resolve(json({ error: { code: 'bad_gateway', message: 'x' } }, 502))],
  ] as const)('retries the ranking once after %s before showing an error', async (_name, fail) => {
    const actor = principal({ scope_kind: 'tenant', scope_id: tenantId, tenant_id: tenantId, permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    let rankReads = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'http://cdnca.test')
      const meta = { from: url.searchParams.get('from'), to: url.searchParams.get('to'), timezone: 'UTC', metric_version: 1 }
      if (url.pathname.endsWith('/summary')) return Promise.resolve(json({ data: zeroSummary, meta }))
      rankReads += 1
      if (rankReads === 1) return fail()
      return Promise.resolve(json({
        data: [{ key: 'r.example', host: 'r.example', port: 0, request_count: 1, response_bytes: 1 }],
        dimension: 'domain', page: { snapshot_at: snapshot, source: 'history' }, meta,
      }))
    })
    renderWithProviders(<SiteAnalysisPage />)
    expect(await screen.findByText('r.example', undefined, { timeout: 4000 })).toBeInTheDocument()
    expect(rankReads).toBe(2)
    expect(screen.queryByText('监控数据加载失败，请稍后重试。')).not.toBeInTheDocument()
  })

  it.each([400, 403])('does not retry a %d ranking refusal', async (status) => {
    const actor = principal({ scope_kind: 'tenant', scope_id: tenantId, tenant_id: tenantId, permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    let rankReads = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'http://cdnca.test')
      const meta = { from: url.searchParams.get('from'), to: url.searchParams.get('to'), timezone: 'UTC', metric_version: 1 }
      if (url.pathname.endsWith('/summary')) return Promise.resolve(json({ data: zeroSummary, meta }))
      rankReads += 1
      return Promise.resolve(json({ error: { code: status === 400 ? 'analytics_invalid_request' : 'forbidden', message: 'x' } }, status))
    })
    renderWithProviders(<SiteAnalysisPage />)
    await waitFor(() => expect(rankReads).toBe(1))
    await new Promise((resolve) => setTimeout(resolve, 1500))
    expect(rankReads).toBe(1)
  })

  it('uses English column names in en-US', async () => {
    await changeLocale('en-US')
    mockAnalytics()
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />)
    await screen.findByText('x.example')
    expect(firstColumnTitle()).toBe('Domain')
    await user.click(screen.getByRole('tab', { name: 'Client IPs' }))
    expect(firstColumnTitle()).toBe('Client IP')
    await user.click(screen.getByRole('tab', { name: 'Referrers' }))
    expect(firstColumnTitle()).toBe('Referrer')
  })
})
