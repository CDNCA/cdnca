import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { sitesApi, type SiteListResponse } from '../api/sites'
import { usersApi } from '../api/users'
import { useSessionStore } from '../auth/session'
import CCCoordinationPage from '../pages/CCCoordinationPage'
import { clearFilterUrlMemory } from '../pages/filterUrl'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const tenantId = '018f0000-0000-7000-8000-000000000010'
const siteId = '018f0000-0000-7000-8000-000000000020'

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

function jsonStatus(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('CCCoordinationPage', () => {
  it('binds cross-node CC listing and false-positive release to the exact site and generation', async () => {
    const actor = principal({ permissions: ['sites.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const stateId = '018f0000-0000-7000-8000-000000000051'
    const state = {
      id: stateId,
      tenant_scope_id: tenantId,
      tenant_id: tenantId,
      site_id: siteId,
      source_cc_policy_id: '018f0000-0000-7000-8000-000000000052',
      rule_id: '018f0000-0000-7000-8000-000000000053',
      client_cidr: '192.0.2.11/32',
      host: 'cdn.example.test',
      path: '/login',
      method: 'POST',
      listen_port: 443,
      protocol: 'https',
      request_class: 'standard',
      generation: 7,
      state: 'blocked',
      reason_code: 'cc_cross_node_threshold_reached',
      hit_count: 22,
      node_count: 2,
      current_policy_version: 8,
      lkg_policy_version: 7,
      expires_at: '2026-08-07T09:00:00Z',
      release_hold_until: '2026-08-08T08:00:00Z',
      updated_at: '2026-08-07T08:00:00Z',
    } as const
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://cdnca.test')
      if (url.pathname.endsWith('/cc-coordination')) return Promise.resolve(json({ items: [state] }))
      if (url.pathname.endsWith(`/${stateId}/release`)) {
        return Promise.resolve(new Response(JSON.stringify({
          state: { ...state, generation: 8, state: 'release_pending', reason_code: 'false_positive_confirmed' },
          replayed: false,
        }), { status: 202, headers: { 'Content-Type': 'application/json' } }))
      }
      return Promise.resolve(jsonStatus({ error: { code: 'unexpected_route' } }, 500))
    })
    const user = userEvent.setup()
    renderWithProviders(<CCCoordinationPage />)

    // Loads every site of the tenant on entry; site is an optional filter.
    expect(await screen.findByText('192.0.2.11/32')).toBeInTheDocument()
    const initialURL = new URL(String(fetchSpy.mock.calls[0][0]), 'https://cdnca.test')
    expect(initialURL.searchParams.has('site_id')).toBe(false)
    expect(initialURL.searchParams.has('tenant_id')).toBe(false)
    vi.spyOn(sitesApi, 'list').mockResolvedValue({ items: [{ id: siteId, display_id: '7', domain: 'cdn.example.test', owner: null }], total: 1, page: 1, limit: 10 } as unknown as SiteListResponse)
    const site = screen.getByRole('combobox', { name: '站点' })
    await user.click(site)
    await user.type(site, 'cdn')
    await user.click(await screen.findByTitle('cdn.example.test（7）'))
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([input]) => String(input).includes('/cc-coordination?'))).toHaveLength(2))
    expect(screen.getByText('POST cdn.example.test:443/login')).toBeInTheDocument()
    const listCall = fetchSpy.mock.calls.filter(([input]) => String(input).includes('/cc-coordination?')).at(-1)
    expect(listCall).toBeDefined()
    const listURL = new URL(String(listCall![0]), 'https://cdnca.test')
    expect(listURL.pathname).toBe('/v1/analytics/logs/cc-coordination')
    expect(listURL.searchParams.get('site_id')).toBe(siteId)
    expect(listURL.searchParams.get('limit')).toBe('50')
    expect(listURL.searchParams.has('tenant_id')).toBe(false)

    await user.click(screen.getByRole('button', { name: '解除' }))
    expect(await screen.findByRole('dialog')).toHaveTextContent('代次 7')
    await user.click(screen.getByRole('button', { name: '确认解除' }))
    expect(await screen.findByText('误报解除已受理，新代次为 8。')).toBeInTheDocument()

    const releaseCall = fetchSpy.mock.calls.find(([input]) => String(input).includes(`/${stateId}/release?`))
    expect(releaseCall).toBeDefined()
    const releaseURL = new URL(String(releaseCall![0]), 'https://cdnca.test')
    expect(releaseURL.pathname).toBe(`/v1/analytics/logs/cc-coordination/${stateId}/release`)
    expect(releaseURL.searchParams.get('site_id')).toBe(siteId)
    const releaseInit = releaseCall![1]!
    const headers = new Headers(releaseInit.headers)
    expect(headers.get('Idempotency-Key')).toMatch(/^cc-release-/)
    expect(headers.get('X-Request-ID')).toMatch(/^cc-request-/)
    expect(JSON.parse(String(releaseInit.body))).toEqual({
      reason_code: 'false_positive_confirmed', expected_generation: 7,
    })
  })

  // stats-platform-l7：平台运营进入即列全平台状态（不带租户/站点），解除时用该行自己的租户与站点。
  it('lists every tenant platform-wide on entry and releases with the row\'s own tenant and site', async () => {
    const actor = principal({
      scope_kind: 'platform', scope_id: 'platform', tenant_id: null,
      permissions: ['sites.read', 'platform.admin', 'security_policies.manage'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const otherTenant = '018f0000-0000-7000-8000-000000000060'
    const row = (id: string, tenant: string, updated: string) => ({
      id, tenant_scope_id: tenant, tenant_id: tenant, site_id: siteId,
      source_cc_policy_id: '018f0000-0000-7000-8000-000000000052', rule_id: '018f0000-0000-7000-8000-000000000053',
      client_cidr: `192.0.2.${id.endsWith('1') ? 11 : 12}/32`, host: 'cdn.example.test', path: '/login', method: 'POST',
      listen_port: 443, protocol: 'https', request_class: 'standard', generation: 7, state: 'blocked',
      reason_code: 'cc_cross_node_threshold_reached', hit_count: 22, node_count: 2, current_policy_version: 8,
      lkg_policy_version: 7, expires_at: '2026-08-07T09:00:00Z', release_hold_until: '2026-08-08T08:00:00Z', updated_at: updated,
    })
    const newer = row('018f0000-0000-7000-8000-000000000071', otherTenant, '2026-08-07T08:30:00Z')
    const older = row('018f0000-0000-7000-8000-000000000072', tenantId, '2026-08-07T08:00:00Z')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://cdnca.test')
      if (url.pathname.endsWith('/cc-coordination')) return Promise.resolve(json({ items: [newer, older] }))
      if (url.pathname.endsWith('/release')) {
        return Promise.resolve(new Response(JSON.stringify({ state: { ...newer, generation: 8, state: 'release_pending',
          reason_code: 'false_positive_confirmed' }, replayed: false }), { status: 202, headers: { 'Content-Type': 'application/json' } }))
      }
      return Promise.resolve(jsonStatus({ error: { code: 'unexpected_route' } }, 500))
    })
    const user = userEvent.setup()
    renderWithProviders(<CCCoordinationPage />)

    expect(await screen.findByText('192.0.2.11/32')).toBeInTheDocument()
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'https://cdnca.test')
    expect(url.pathname).toBe('/v1/admin/analytics/logs/cc-coordination')
    expect(url.searchParams.has('tenant_id')).toBe(false)
    expect(url.searchParams.has('site_id')).toBe(false)
    const cells = screen.getAllByText(/^192\.0\.2\.1[12]\/32$/).map((cell) => cell.textContent)
    expect(cells).toEqual(['192.0.2.11/32', '192.0.2.12/32'])

    await user.click(screen.getAllByRole('button', { name: '解除' })[0])
    await user.click(await screen.findByRole('button', { name: '确认解除' }))
    expect(await screen.findByText('误报解除已受理，新代次为 8。')).toBeInTheDocument()
    const releaseCall = fetchSpy.mock.calls.find(([input]) => String(input).includes('/release?'))
    const releaseURL = new URL(String(releaseCall![0]), 'https://cdnca.test')
    expect(releaseURL.pathname).toBe('/v1/admin/analytics/logs/cc-coordination/018f0000-0000-7000-8000-000000000071/release')
    expect(releaseURL.searchParams.get('tenant_id')).toBe(otherTenant)
    expect(releaseURL.searchParams.get('site_id')).toBe(siteId)
  })

  // 已生效的租户与站点在 URL 里，刷新后首条请求原样带上；
  // 链接里的站点不属于该租户或值无效时不查询，错误挂在字段上并给焦点。
  const platformActor = () => {
    clearFilterUrlMemory()
    const actor = principal({ scope_kind: 'platform', scope_id: 'platform', tenant_id: null, permissions: ['sites.read', 'platform.admin'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
  }
  const ownerID = '018f0000-0000-7000-8000-000000000090'
  const coordinationCalls = (spy: { mock: { calls: unknown[][] } }) => spy.mock.calls.map(([input]) => new URL(String(input), 'https://cdnca.test'))
    .filter((url) => url.pathname.endsWith('/cc-coordination'))

  it('reads the linked tenant and site on the first request', async () => {
    platformActor()
    vi.spyOn(sitesApi, 'list').mockResolvedValue({ items: [{ id: siteId, display_id: '7', domain: 'cdn.example.test', owner: { id: ownerID, display_name: 'QA' } }], total: 1, page: 1, limit: 1 } as unknown as SiteListResponse)
    vi.spyOn(usersApi, 'get').mockResolvedValue({ id: ownerID, tenant_id: tenantId } as unknown as Awaited<ReturnType<typeof usersApi.get>>)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(json({ items: [] })))
    renderWithProviders(<CCCoordinationPage />, [`/monitor/site/cc-coordination?tenant_id=${tenantId}&site_id=${siteId}`])

    await waitFor(() => expect(coordinationCalls(fetchSpy)).toHaveLength(1))
    expect(coordinationCalls(fetchSpy)[0].searchParams.get('tenant_id')).toBe(tenantId)
    expect(coordinationCalls(fetchSpy)[0].searchParams.get('site_id')).toBe(siteId)
  })

  it('does not widen to the platform when the linked site is outside the tenant or invalid', async () => {
    platformActor()
    vi.spyOn(sitesApi, 'list').mockResolvedValue({ items: [{ id: siteId, display_id: '7', domain: 'cdn.example.test', owner: { id: ownerID, display_name: 'QA' } }], total: 1, page: 1, limit: 1 } as unknown as SiteListResponse)
    vi.spyOn(usersApi, 'get').mockResolvedValue({ id: ownerID, tenant_id: '018f0000-0000-7000-8000-000000000099' } as unknown as Awaited<ReturnType<typeof usersApi.get>>)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(json({ items: [] })))
    const view = renderWithProviders(<CCCoordinationPage />, [`/monitor/site/cc-coordination?tenant_id=${tenantId}&site_id=${siteId}`])

    const site = await screen.findByRole('combobox', { name: '站点' })
    await waitFor(() => expect(site).toHaveAccessibleDescription('该站点不属于所选租户，请重新选择站点。'))
    expect(site).toHaveAttribute('aria-invalid', 'true')
    await waitFor(() => expect(site).toHaveFocus())
    expect(coordinationCalls(fetchSpy)).toHaveLength(0)
    view.unmount()

    renderWithProviders(<CCCoordinationPage />, ['/monitor/site/cc-coordination?tenant_id=not-a-uuid'])
    const tenant = await screen.findByRole('combobox', { name: '租户' })
    expect(tenant).toHaveAccessibleDescription('链接里的租户无效，请重新选择租户。')
    await waitFor(() => expect(tenant).toHaveFocus())
    expect(coordinationCalls(fetchSpy)).toHaveLength(0)
  })
})
