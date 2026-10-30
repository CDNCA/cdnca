import { ApiError } from './auth'
import { getCCSiteStats, parseCCSiteStats, type CCSiteStats } from './ccStats'

const siteID = '22222222-2222-4222-8222-222222222222'
const tenantID = '11111111-1111-4111-8111-111111111111'
const ruleID = '33333333-3333-4333-8333-333333333333'
const counts = { matched: 9, triggered: 3, challenged: 1, blocked: 2, passed: 4, ja4_unavailable: 0 }
const body: CCSiteStats = {
  tenant_scope_id: tenantID, range: '1h', site_id: siteID, from: '2026-10-19T13:38:00Z', to: '2026-10-19T14:38:00Z',
  step_seconds: 60, series: [{ at: '2026-10-19T14:00:00Z', ...counts }],
  rules: [{ rule_id: ruleID, policy_id: 'p', ...counts }, { rule_id: null, policy_id: 'p', ...counts }],
  top_clients: [{ value: '198.51.100.7', count: 3 }], top_paths: [{ value: '/a', count: 3 }],
}

function respond(status: number, value: unknown) {
  return vi.fn().mockResolvedValue(new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }))
}

afterEach(() => vi.unstubAllGlobals())

describe('ccStats API', () => {
  it('reads the tenant route and validates the body', async () => {
    const fetchMock = respond(200, body)
    vi.stubGlobal('fetch', fetchMock)
    await expect(getCCSiteStats('token', { siteID, range: '1h' })).resolves.toEqual(body)
    expect(String(fetchMock.mock.calls[0][0])).toBe(`/v1/security/cc-stats?site_id=${siteID}&range=1h`)
  })

  it('reads the admin route with the tenant scope', async () => {
    const fetchMock = respond(200, { ...body, range: '24h', step_seconds: 900 })
    vi.stubGlobal('fetch', fetchMock)
    await getCCSiteStats('token', { siteID, range: '24h', tenantScopeID: tenantID })
    expect(String(fetchMock.mock.calls[0][0])).toBe(`/v1/admin/security/cc-stats?site_id=${siteID}&range=24h&tenant_scope_id=${tenantID}`)
  })

  it('maps API errors and rejects bad bodies', async () => {
    vi.stubGlobal('fetch', respond(404, { error: { code: 'cc_stats_site_not_found', request_id: 'r1' } }))
    await expect(getCCSiteStats('token', { siteID, range: '1h' })).rejects.toMatchObject({ status: 404, code: 'cc_stats_site_not_found' })
    expect(() => parseCCSiteStats({ ...body, site_id: tenantID }, siteID)).toThrow(ApiError)
    expect(() => parseCCSiteStats({ ...body, step_seconds: 30 }, siteID)).toThrow(ApiError)
    expect(() => parseCCSiteStats({ ...body, rules: [{ ...counts, rule_id: 'x', policy_id: 'p' }] }, siteID)).toThrow(ApiError)
    expect(() => parseCCSiteStats({ ...body, series: [{ at: 'no', ...counts }] }, siteID)).toThrow(ApiError)
    await expect(getCCSiteStats('token', { siteID: 'nope', range: '1h' })).rejects.toMatchObject({ code: 'invalid_request' })
  })
})
