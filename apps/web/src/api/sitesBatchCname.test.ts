import { sitesApi, type SiteDetail } from './sites'

const siteID = '11111111-1111-4111-8111-111111111111'
const taskID = '22222222-2222-4222-8222-222222222222'
const input = {
  action: 'regenerate_cname' as const,
  items: [{ id: siteID, expected_version: 7 }],
}

function queuedSite(overrides: Partial<SiteDetail['basic']> = {}): SiteDetail {
  return {
    id: siteID,
    version: 8,
    owner: null,
    created_at: '2026-08-08T00:00:00Z',
    updated_at: '2026-08-08T00:01:00Z',
    lock: { locked: false, reason: null, locked_at: null, operator: null },
    listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' },
    origin_pool: {
      origins: [{ host: '192.0.2.10', port: 80, weight: 1, enabled: true }],
      balance_method: 'round_robin',
      failover_tries: 1,
      connect_timeout_ms: 3_000,
      read_timeout_ms: 30_000,
    },
    basic: {
      package_id: null,
      package_name: null,
      group_id: null,
      group_name: null,
      domains: ['www.example.com'],
      http_enabled: true,
      http_listen_ports: ['80'],
      https_listen_ports: [],
      ipv6_enabled: false,
      tls_protocols: ['TLSv1.2', 'TLSv1.3'],
      origins: ['192.0.2.10:80'],
      cname: 'edge.example.net',
      cname_state: 'pending',
      cname_task_id: taskID,
      cname_current_revision: 3,
      cname_lkg_revision: 2,
      https_enabled: false,
      enabled: true,
      status: 'active',
      sync_status: 'pending',
      is_default: false,
      ...overrides,
    },
  }
}

function json(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('sitesApi CNAME regeneration batch contract', () => {
  it('accepts only an ordered queued result with a durable task identity', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      items: [{ id: siteID, status: 'queued', site: queuedSite() }],
    }))

    const result = await sitesApi.batchAction('tenant-token', input, 'dns-03-key')

    expect(result.items).toEqual([{ id: siteID, status: 'queued', site: queuedSite() }])
    expect(fetchSpy).toHaveBeenCalledWith('/v1/sites/batch-action', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify(input),
      headers: expect.objectContaining({
        Authorization: 'Bearer tenant-token',
        'Idempotency-Key': 'dns-03-key',
      }),
    }))
  })

  it.each([
    ['missing task identity', { id: siteID, status: 'queued', site: queuedSite({ cname_task_id: null }) }],
    ['non-pending CNAME state', { id: siteID, status: 'queued', site: queuedSite({ cname_state: 'failed' }) }],
    ['updated instead of queued', { id: siteID, status: 'updated', site: queuedSite() }],
    ['queued for a non-regeneration action', { id: siteID, status: 'queued', site: queuedSite() }, 'enable'],
  ])('rejects %s', async (_name, item, action = 'regenerate_cname') => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [item] }))

    await expect(sitesApi.batchAction('tenant-token', {
      ...input,
      action: action as typeof input.action,
    }, 'dns-03-key')).rejects.toEqual(expect.objectContaining({
      code: 'invalid_response',
      status: 502,
    }))
  })
})
