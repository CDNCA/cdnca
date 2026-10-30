import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'

import { vi } from 'vitest'

import CCStatsPanel from '../pages/security/CCStatsPanel'

vi.mock('../components/echartsRuntime', () => ({
  init: () => ({ setOption: vi.fn(), resize: vi.fn(), dispose: vi.fn() }),
}))

const siteID = '22222222-2222-4222-8222-222222222222'
const tenantID = '11111111-1111-4111-8111-111111111111'
const ruleID = '33333333-3333-4333-8333-333333333333'
const counts = { matched: 9, triggered: 3, challenged: 1, blocked: 2, passed: 4, ja4_unavailable: 0 }

function renderPanel(props: { siteID: string | null; tenantScopeID?: string | null; admin?: boolean }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={client}>
    <CCStatsPanel accessToken="token" siteID={props.siteID} tenantScopeID={props.tenantScopeID ?? null} admin={props.admin ?? false} />
  </QueryClientProvider>)
}

afterEach(() => vi.unstubAllGlobals())

describe('CCStatsPanel', () => {
  it('asks for a site', () => {
    renderPanel({ siteID: null })
    expect(screen.getByText('请从网站的防护设置进入，查看该网站的 CC 规则统计。')).toBeInTheDocument()
  })

  it('needs the tenant scope for platform admins', () => {
    renderPanel({ siteID, admin: true })
    expect(screen.getByText(/平台管理员查看时需要网站所属的租户/)).toBeInTheDocument()
  })

  it('shows per-rule totals and top lists', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      tenant_scope_id: tenantID, range: '1h', site_id: siteID, from: '2026-10-19T13:38:00Z', to: '2026-10-19T14:38:00Z',
      step_seconds: 60, series: [{ at: '2026-10-19T14:00:00Z', ...counts }],
      rules: [{ rule_id: ruleID, policy_id: 'p', ...counts }, { rule_id: null, policy_id: 'p', ...counts, matched: 0 }],
      top_clients: [{ value: '198.51.100.7', count: 3 }], top_paths: [{ value: '/login', count: 3 }],
    }), { status: 200, headers: { 'Content-Type': 'application/json' } })))
    renderPanel({ siteID })
    await waitFor(() => expect(screen.getByText('198.51.100.7')).toBeInTheDocument())
    expect(screen.getByText('/login')).toBeInTheDocument()
    expect(screen.getByText(ruleID)).toBeInTheDocument()
    expect(screen.getByText('网站级（验证失败封禁）')).toBeInTheDocument()
    expect(screen.getByRole('img', { name: 'CC 规则趋势图' })).toBeInTheDocument()
  })

  it('shows the empty state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      tenant_scope_id: tenantID, range: '1h', site_id: siteID, from: '2026-10-19T13:38:00Z', to: '2026-10-19T14:38:00Z',
      step_seconds: 60, series: [], rules: [], top_clients: [], top_paths: [],
    }), { status: 200, headers: { 'Content-Type': 'application/json' } })))
    renderPanel({ siteID })
    await waitFor(() => expect(screen.getByText('这段时间没有 CC 规则活动')).toBeInTheDocument())
  })
})
