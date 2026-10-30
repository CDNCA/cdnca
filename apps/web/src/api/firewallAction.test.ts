import { afterEach, describe, expect, it, vi } from 'vitest'

import { firewallActionApi, type FirewallActionPolicy } from './firewallAction'

const policy: FirewallActionPolicy = {
  id: '33333333-3333-4333-8333-333333333333', tenant_scope_id: '11111111-1111-4111-8111-111111111111',
  site_id: '22222222-2222-4222-8222-222222222222', normal_action: 'return_page', escalated_action: 'nftables',
  engage_threshold: 100, recover_threshold: 20, recovery_windows: 3, block_networks: ['198.51.100.0/24'],
  trusted_proxies: ['192.0.2.0/24'], trusted_crawlers: [{ name: 'search', networks: ['203.0.113.0/24'], user_agent_prefixes: ['SearchBot/'] }],
  return_page: { status: 429, content_type: 'text/plain; charset=utf-8', body: 'Request limited' },
  revision: 4, active_revision: 3, lkg_revision: 3, deployment_state: 'failed', host_escalation: 'owned', document_sha256: 'a'.repeat(64),
  created_at: '2026-08-08T00:00:00Z', updated_at: '2026-08-08T00:00:00Z',
}

describe('firewallActionApi', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('accepts the exact policy contract and sends CAS metadata', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(policy), { status: 200 }))
    vi.stubGlobal('fetch', fetch)
    await expect(firewallActionApi.put('token', { scopeId: policy.tenant_scope_id, siteId: policy.site_id, expectedRevision: 4, policy })).resolves.toEqual(policy)
    expect(fetch).toHaveBeenCalledWith(expect.stringContaining('/v1/firewall-actions/policy?'), expect.objectContaining({ method: 'PUT', headers: expect.objectContaining({ 'If-Match': '"4"' }) }))
  })

  it('rejects malformed threshold and crawler response shapes', async () => {
    for (const malformed of [
      { ...policy, recovery_windows: undefined },
      { ...policy, trusted_crawlers: [{ ...policy.trusted_crawlers[0], unknown: true }] },
      { ...policy, deployment_state: 'active', lkg_revision: 9 },
    ]) {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(malformed), { status: 200 })))
      await expect(firewallActionApi.get('token', policy.tenant_scope_id, policy.site_id)).rejects.toMatchObject({ code: 'invalid_response' })
    }
  })
})
