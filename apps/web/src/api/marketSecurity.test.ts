import { listMarketSecurityLogs, parseMarketSecurityPage } from './marketSecurity'

const site = '018f0000-0000-7000-8000-000000000020'
const tenant = '018f0000-0000-7000-8000-000000000010'
const row = {
  site_id: site, supply_id: '018f0000-0000-7000-8000-000000000050', leaf_ref: '0a1b2c3d', occurred_at: '2026-07-28T07:58:00Z',
  client_ip: '198.51.100.7', host: 'a.example.test', path: '/', action: 'block', detector: '', rule_id: '', cursor: 'c',
}

describe('marketSecurity API', () => {
  it('builds tenant and admin requests', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ data: [row], meta: {} })))
    await listMarketSecurityLogs('token', 'tenant', { from: '2026-07-28T00:00:00.000Z', to: '2026-07-29T00:00:00.000Z', siteId: site }, 10)
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      `/v1/analytics/market-security?from=2026-07-28T00%3A00%3A00.000Z&to=2026-07-29T00%3A00%3A00.000Z&limit=10&site_id=${site}`)
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ data: [], meta: { next_cursor: 'n' } })))
    const page = await listMarketSecurityLogs('token', 'admin', { from: 'a', to: 'b', tenantId: tenant }, 5, 'c')
    expect(String(fetchMock.mock.calls[1][0])).toContain(`/v1/admin/analytics/market-security?from=a&to=b&limit=5&tenant_id=${tenant}&cursor=c`)
    expect(page.meta.next_cursor).toBe('n')
  })

  it('rejects malformed requests and responses', async () => {
    await expect(listMarketSecurityLogs('token', 'admin', { from: 'a', to: 'b' }, 5)).rejects.toMatchObject({ status: 400 })
    expect(() => parseMarketSecurityPage({ data: [{ ...row, site_id: 'x' }], meta: {} })).toThrow()
    expect(() => parseMarketSecurityPage({ data: [{ ...row, cursor: '' }], meta: {} })).toThrow()
    expect(parseMarketSecurityPage({ data: [row], meta: {} }).data).toHaveLength(1)
  })
})
