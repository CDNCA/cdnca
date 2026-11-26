import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useLocation } from 'react-router-dom'

import { ApiError } from '../api/auth'
import { sitesApi, type SiteDetail, type SiteListResponse } from '../api/sites'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { clearFilterUrlMemory } from './filterUrl'
import RumReportPage from './RumReportPage'

const siteID = '33333333-3333-4333-8333-333333333333'
const scopeID = '22222222-2222-4222-8222-222222222222'

function Location() {
  const location = useLocation()
  return <output data-testid="location">{location.search}</output>
}

function authenticateAdmin() {
  const actor = principal({ scope_kind: 'platform', scope_id: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function mockReads() {
  vi.spyOn(sitesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 100 } as unknown as SiteListResponse)
  const calls: string[] = []
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    calls.push(String(input).replace(/^https?:\/\/[^/]+/, ''))
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } })
  })
  return calls
}

beforeEach(() => clearFilterUrlMemory())

// 已生效网站与时间写进 URL，刷新后按同一网站与范围取数。
describe('RumReportPage URL state', () => {
  it('reopens the linked site and range and queries the report with them', async () => {
    authenticateAdmin()
    const calls = mockReads()
    const detail = vi.spyOn(sitesApi, 'detail').mockResolvedValue({ id: siteID, scope_id: scopeID, basic: { domains: ['qa21.example.com'] } } as unknown as SiteDetail)
    renderWithProviders(<><RumReportPage /><Location /></>, [`/?site_id=${siteID}&range=7d`])
    expect(await screen.findByText('qa21.example.com')).toBeInTheDocument()
    expect(detail).toHaveBeenCalledWith(expect.any(String), siteID)
    expect(screen.getByRole('radio', { name: '近 7 天' })).toBeChecked()
    await waitFor(() => expect(calls.some((call) => call.startsWith('/v1/admin/analytics/rum?') &&
      call.includes(`site_id=${siteID}`) && call.includes('range=7d') && call.includes(`tenant_scope_id=${scopeID}`))).toBe(true))

    const user = userEvent.setup()
    await user.click(screen.getByText('近 24 小时'))
    await waitFor(() => expect(screen.getByTestId('location').textContent).toBe(`?site_id=${siteID}`))
    await user.click(screen.getByText('近 30 天'))
    await waitFor(() => expect(screen.getByTestId('location').textContent).toBe(`?site_id=${siteID}&range=30d`))
  })

  it('falls back to picking a site when the linked one is gone, and ignores an unknown range', async () => {
    authenticateAdmin()
    mockReads()
    vi.spyOn(sitesApi, 'detail').mockRejectedValue(new ApiError('not found', 404, 'not_found'))
    renderWithProviders(<><RumReportPage /><Location /></>, [`/?site_id=${siteID}&range=90d`])
    expect(await screen.findByText('选择一个网站查看它的真实用户体验数据。')).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: '近 24 小时' })).toBeChecked()
    await waitFor(() => expect(screen.getByTestId('location').textContent).toBe(''))
  })
})
