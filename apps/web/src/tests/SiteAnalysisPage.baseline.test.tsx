import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useLocation } from 'react-router-dom'

import { useSessionStore } from '../auth/session'
import SiteAnalysisPage from '../pages/SiteAnalysisPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const analysisCSS = Object.values(import.meta.glob('../pages/SiteAnalysisPage.css', {
  eager: true,
  import: 'default',
  query: '?raw',
}))[0] as string

function authenticate() {
  const actor = principal({ permissions: ['sites.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

// The page also reads the range summary (/summary); these tests count the
// ranking reads only.
function rankCalls(spy: { mock: { calls: Parameters<typeof fetch>[] } }): Parameters<typeof fetch>[] {
  return spy.mock.calls.filter(([input]) => new URL(String(input), 'http://cdnca.test').pathname.includes('/top/'))
}

function rankResponse(input: RequestInfo | URL): Response {
  const url = new URL(String(input), 'http://cdnca.test')
  return new Response(JSON.stringify({
    // 域名排行行带地址部分 host（fix-telemetry2 TEL-UX-DRILL 按 host 下钻）。
    data: [{ key: 'cdn.example.test', host: 'cdn.example.test', request_count: 20, response_bytes: 2048 }],
    dimension: url.pathname.split('/').at(-1),
    page: { snapshot_at: '2026-08-29T00:00:00Z', source: 'history' },
    meta: {
      from: url.searchParams.get('from'),
      to: url.searchParams.get('to'),
      timezone: 'UTC',
      metric_version: 1,
    },
  }), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="analysis-location">{`${location.pathname}${location.search}`}</output>
}

describe('SiteAnalysisPage element-level baseline', () => {
  it('keeps compact reference toolbar geometry', () => {
    expect(analysisCSS).toContain('.analytics-analysis-page .analytics-analysis-refresh-action')
    expect(analysisCSS).toMatch(/\.analytics-analysis-refresh-action[\s\S]*width: 60px;[\s\S]*min-width: 60px;/)
    expect(analysisCSS).toContain('.analytics-analysis-page .analytics-analysis-search-input')
    expect(analysisCSS).toMatch(/\.analytics-analysis-search-input[\s\S]*width: 320px;/)
    expect(analysisCSS).toMatch(/\.analytics-analysis-search-type[\s\S]*width: 96px;[\s\S]*min-width: 96px;/)
  })

  it('exposes all three observed search modes, queries server ports, and safely retains unsupported CC tags', async () => {
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(rankResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<SiteAnalysisPage />, ['/monitor/site/analysis'])

    await screen.findByText('cdn.example.test')
    expect(rankCalls(fetchSpy)).toHaveLength(1)
    const toolbar = document.querySelector('.analytics-analysis-page .analytics-filter-bar')
    expect(toolbar?.querySelector('.analytics-analysis-search-input')).toBeInTheDocument()
    expect(toolbar?.querySelector('.analytics-analysis-search-input .ant-input-group-addon:first-child .analytics-analysis-search-type')).toBeInTheDocument()
    expect(toolbar?.querySelector('.analytics-analysis-refresh-action')).toBeInTheDocument()
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '统计维度' }))
    expect(await screen.findByRole('option', { name: '域名' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: '服务器端口' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: '攻击请求' })).toBeInTheDocument()

    await user.click(screen.getByRole('option', { name: '服务器端口' }))
    const port = screen.getByPlaceholderText('输入端口，如 80 或 443')
    await user.type(port, '443')
    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(screen.getByText('服务器端口：443')).toBeInTheDocument()
    await waitFor(() => expect(rankCalls(fetchSpy)).toHaveLength(2))
    const portURL = new URL(String(rankCalls(fetchSpy).at(-1)![0]), 'http://cdnca.test')
    expect(portURL.searchParams.get('listen_port')).toBe('443')
    expect(screen.queryByText(/当前版本不支持此筛选条件/)).not.toBeInTheDocument()

    const portTag = screen.getByText('服务器端口：443').closest('.ant-tag')
    expect(portTag).not.toBeNull()
    await user.click(within(portTag as HTMLElement).getByLabelText('Close'))
    expect(screen.queryByText('服务器端口：443')).not.toBeInTheDocument()
    await waitFor(() => expect(rankCalls(fetchSpy)).toHaveLength(3))
    expect(new URL(String(rankCalls(fetchSpy).at(-1)![0]), 'http://cdnca.test').searchParams.has('listen_port')).toBe(false)

    fireEvent.mouseDown(screen.getByRole('combobox', { name: '统计维度' }))
    await user.click(screen.getByRole('option', { name: '攻击请求' }))
    expect(screen.getAllByText('攻击请求').some((element) => element.closest('.ant-tag'))).toBe(true)
    expect(screen.getByText(/当前版本不支持此筛选条件/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '清除' }))
    expect(screen.queryByRole('button', { name: '清除' })).not.toBeInTheDocument()
    expect(rankCalls(fetchSpy)).toHaveLength(3)
  })

  it('uses a confirmable range popup, real sortable metrics, and a log drill-down', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(rankResponse(input)))
    const user = userEvent.setup()
    renderWithProviders(<><SiteAnalysisPage /><LocationProbe /></>, ['/monitor/site/analysis'])

    await screen.findByText('cdn.example.test')
    const table = screen.getByTestId('analytics-rank-table-scroll')
    expect(table.querySelectorAll('.ant-table-column-has-sorters')).toHaveLength(2)
    expect(within(table).getAllByTitle('当前版本暂不支持回源监控。')).not.toHaveLength(0)
    expect(within(table).getByRole('button', { name: '查看日志' })).toBeInTheDocument()

    // fix-rangepicker：自定义是共享组件的「选择时间范围」框，点开为双月面板。
    await user.click(screen.getByText('自定义'))
    await user.click(screen.getByRole('textbox', { name: '选择时间范围' }))
    expect(document.querySelectorAll('.cdnca-time-range-month')).toHaveLength(2)
    const confirm = screen.getByRole('button', { name: '确定' })
    expect(confirm).toBeInTheDocument()
    await user.click(confirm)

    await user.click(within(table).getByRole('button', { name: '查看日志' }))
    await waitFor(() => expect(screen.getByTestId('analysis-location').textContent).toMatch(
      /^\/monitor\/site\/access-log\?.*host=cdn\.example\.test/,
    ))
  })
})
