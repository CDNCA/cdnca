import { siteDiagnosticsApi } from './siteDiagnostics'

const filters = {
  from: '2026-08-08T01:00:00.000Z', to: '2026-08-08T02:00:00.000Z',
  siteId: '018f0000-0000-7000-8000-000000000002', limit: 20,
}

function response() {
  return {
    data: {
      items: [{
        event_id: 'event-1', occurred_at: '2026-08-08T01:59:00.000Z', site_id: filters.siteId,
        node_id: '018f0000-0000-7000-8000-000000000003', request_id: 'request-1', trace_id: 'trace-1',
        config_version_id: 'config-1', host: 'cdn.example.test', uri_path: '/health', status_code: 502,
        category: 'upstream_5xx', reason_code: 'status_5xx_with_upstream_result',
      }],
      next_cursor: 'c2lnbmVkLWN1cnNvcg', snapshot_at: '2026-08-08T01:59:59.000Z',
    },
    meta: { from: filters.from, to: filters.to, timezone: 'UTC' },
  }
}

describe('siteDiagnosticsApi', () => {
  it('uses authenticated tenant scope and accepts strict diagnostic identity', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(response())))
    const result = await siteDiagnosticsApi.read('token', 'tenant', filters)
    expect(result.data.items[0].config_version_id).toBe('config-1')
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'http://cdnca.test')
    expect(url.pathname).toBe('/v1/analytics/site-quality-diagnostics')
    expect(url.searchParams.has('tenant_id')).toBe(false)
  })

  it.each(['node_id', 'request_id', 'trace_id', 'config_version_id'] as const)('rejects missing %s', async (field) => {
    const value = response()
    value.data.items[0][field] = ''
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(value)))
    await expect(siteDiagnosticsApi.read('token', 'tenant', filters)).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('requires an explicit tenant for the platform route', async () => {
    await expect(siteDiagnosticsApi.read('token', 'admin', filters)).rejects.toMatchObject({ status: 400 })
  })
})
