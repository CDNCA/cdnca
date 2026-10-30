import { qualityDiagnosticsApi, type QualityDiagnosticsCategory } from './qualityDiagnostics'

const tenantID = '018f0000-0000-7000-8000-000000000001'
const siteID = '018f0000-0000-7000-8000-000000000002'
const nodeID = '018f0000-0000-7000-8000-000000000003'
const filters = {
  from: '2026-08-08T01:00:00.000Z',
  to: '2026-08-08T02:00:00.000Z',
  siteId: siteID,
  nodeId: nodeID,
  limit: 20,
}

const diagnosticCases = [
  ['upstream_5xx', 'upstream_failure', 'inspect_upstream', 502],
  ['edge_530', 'edge_status_530', 'inspect_edge_route', 530],
  ['no_host', 'host_missing', 'configure_host', 400],
  ['config_mismatch', 'upstream_reported_config_mismatch', 'reconcile_config', 530],
] as const

function response(audience: 'admin' | 'tenant' = 'tenant') {
  const value: Record<string, unknown> = {
    items: diagnosticCases.map(([category, cause, action, status], index) => ({
      event_id: `event-${index}`,
      occurred_at: `2026-08-08T01:5${9 - index}:00.000Z`,
      site_id: siteID,
      node_id: nodeID,
      category,
      cause_code: cause,
      action_code: action,
      status_code: status,
      config_version_id: '018f0000-0000-7000-8000-000000000006',
      installation_id: '018f0000-0000-7000-8000-000000000007',
      request_id: `request-${index}`,
      task_id: index === 0 ? '018f0000-0000-7000-8000-000000000009' : null,
      trace_id: `trace-${index}`,
    })),
    next_cursor: 'c2lnbmVkLWN1cnNvcg',
    snapshot: {
      at: '2026-08-08T02:00:00.000Z',
      source_watermark: 42,
      finalized_through: '2026-08-08T02:00:00.000Z',
      expires_at: '2026-08-08T02:05:00.000Z',
    },
  }
  if (audience === 'admin') value.effective_tenant_id = tenantID
  return value
}

describe('qualityDiagnosticsApi', () => {
  it('uses the tenant route and accepts all four redacted diagnostic categories', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(response())))

    const result = await qualityDiagnosticsApi.read('token', 'tenant', filters)

    expect(result.items.map((item) => item.category)).toEqual(diagnosticCases.map(([category]) => category))
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'http://cdnca.test')
    expect(url.pathname).toBe('/v1/analytics/site-quality-diagnostics')
    expect(url.searchParams.has('tenant_id')).toBe(false)
    expect(url.searchParams.get('site_id')).toBe(siteID)
    expect(url.searchParams.get('node_id')).toBe(nodeID)
  })

  it('uses the admin route and binds tenant, category, filter, and opaque cursor', async () => {
    const value = response('admin')
    value.items = (value.items as Array<{ category: QualityDiagnosticsCategory }>).filter((item) => item.category === 'edge_530')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(value)))

    const result = await qualityDiagnosticsApi.read('token', 'admin', {
      ...filters, tenantId: tenantID, category: 'edge_530', cursor: 'c2lnbmVkLWN1cnNvcg',
    })

    expect(result.effective_tenant_id).toBe(tenantID)
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'http://cdnca.test')
    expect(url.pathname).toBe('/v1/admin/analytics/site-quality-diagnostics')
    expect(url.searchParams.get('tenant_id')).toBe(tenantID)
    expect(url.searchParams.get('category')).toBe('edge_530')
    expect(url.searchParams.get('cursor')).toBe('c2lnbmVkLWN1cnNvcg')
  })

  it.each(['request_headers', 'response_body', 'server_error'])('rejects forbidden %s response fields', async (field) => {
    const value = response()
    ;(value.items as Array<Record<string, unknown>>)[0][field] = 'secret-value'
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(value)))

    await expect(qualityDiagnosticsApi.read('token', 'tenant', filters))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('rejects mismatched snapshots, filters, ordering, and admin effective tenant identity', async () => {
    const invalid = [
      (() => { const value = response(); (value.snapshot as Record<string, unknown>).finalized_through = filters.from; return value })(),
      (() => { const value = response(); (value.items as Array<Record<string, unknown>>)[0].site_id = tenantID; return value })(),
      (() => { const value = response(); (value.items as Array<Record<string, unknown>>).reverse(); return value })(),
      (() => { const value = response('admin'); value.effective_tenant_id = siteID; return value })(),
    ]

    for (const [index, value] of invalid.entries()) {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify(value)))
      await expect(qualityDiagnosticsApi.read('token', index === 3 ? 'admin' : 'tenant', {
        ...filters, ...(index === 3 ? { tenantId: tenantID } : {}),
      })).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
    }
  })
})
