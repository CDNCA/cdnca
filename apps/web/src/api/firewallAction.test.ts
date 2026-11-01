import { afterEach, describe, expect, it, vi } from 'vitest'

import { firewallActionApi, type FirewallActionPolicy } from './firewallAction'

const policy: FirewallActionPolicy = {
  id: '33333333-3333-4333-8333-333333333333', tenant_scope_id: '11111111-1111-4111-8111-111111111111',
  site_id: '22222222-2222-4222-8222-222222222222', normal_action: 'return_page', escalated_action: 'nftables',
  engage_threshold: 100, recover_threshold: 20, recovery_windows: 3, block_networks: ['198.51.100.0/24'],
  trusted_proxies: ['192.0.2.0/24'], trusted_crawlers: [{ name: 'search', networks: ['203.0.113.0/24'], user_agent_prefixes: ['SearchBot/'] }],
  return_page: { status: 429, content_type: 'text/plain; charset=utf-8', body: 'Request limited' },
  revision: 4, active_revision: 3, lkg_revision: 3, deployment_state: 'failed', enabled: true, host_escalation: 'owned', document_sha256: 'a'.repeat(64),
  created_at: '2026-08-08T00:00:00Z', updated_at: '2026-08-08T00:00:00Z', inherited: false, source: 'site', delivered: true,
}

// fw-default 契约 §3：没有自有策略的站点 GET 返回继承视图（不再 404）。
const inheritedSystem: FirewallActionPolicy = {
  ...policy, revision: 0, active_revision: 0, lkg_revision: 0, deployment_state: 'inherited', inherited: true,
  source: 'system_default', delivered: false, created_at: null, updated_at: null,
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

  it('accepts the inherited views of the fw-default contract and rejects inconsistent ones', async () => {
    const inheritedTenant = { ...inheritedSystem, revision: 3, source: 'tenant_default', delivered: true,
      created_at: '2026-10-31T00:00:00Z', updated_at: '2026-10-31T00:00:00Z' }
    for (const view of [inheritedSystem, inheritedTenant, { ...policy, enabled: false, delivered: false }]) {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(view), { status: 200 })))
      await expect(firewallActionApi.get('token', policy.tenant_scope_id, policy.site_id)).resolves.toEqual(view)
    }
    for (const malformed of [
      { ...inheritedSystem, delivered: true }, { ...inheritedSystem, lkg_revision: 1 }, { ...inheritedSystem, deployment_state: 'active' },
      { ...inheritedTenant, updated_at: null }, { ...policy, source: 'tenant_default' }, { ...policy, revision: 0 },
      { ...policy, enabled: false }, { ...policy, deployment_state: 'inherited' },
    ]) {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(malformed), { status: 200 })))
      await expect(firewallActionApi.get('token', policy.tenant_scope_id, policy.site_id)).rejects.toMatchObject({ code: 'invalid_response' })
    }
  })

  it('restores inheritance with DELETE and reads / writes the tenant default', async () => {
    const del = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ...inheritedSystem, revision: 5 }), { status: 200 }))
    vi.stubGlobal('fetch', del)
    await expect(firewallActionApi.inherit('token', { scopeId: policy.tenant_scope_id, siteId: policy.site_id, expectedRevision: 4 }))
      .resolves.toMatchObject({ inherited: true, revision: 5 })
    expect(del).toHaveBeenCalledWith(expect.stringContaining('/v1/firewall-actions/policy?'), expect.objectContaining({
      method: 'DELETE', headers: expect.objectContaining({ 'If-Match': '"4"' }) }))
    const systemDefault = { tenant_scope_id: policy.tenant_scope_id, source: 'system_default', revision: 0, normal_action: 'return_page',
      escalated_action: 'nftables', engage_threshold: 100, recover_threshold: 20, recovery_windows: 3, block_networks: ['198.51.100.0/24'],
      trusted_proxies: [], trusted_crawlers: [], return_page: policy.return_page, inheriting_site_count: 12, updated_at: null }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(systemDefault), { status: 200 })))
    await expect(firewallActionApi.getDefault('token', policy.tenant_scope_id)).resolves.toMatchObject({ inheriting_site_count: 12 })
    const saved = { ...systemDefault, source: 'tenant_default', revision: 1, engage_threshold: 300, updated_at: '2026-10-31T00:00:00Z' }
    const put = vi.fn().mockResolvedValue(new Response(JSON.stringify(saved), { status: 200 }))
    vi.stubGlobal('fetch', put)
    await expect(firewallActionApi.putDefault('token', { scopeId: policy.tenant_scope_id, expectedRevision: 0, policy: { ...policy, engage_threshold: 300 } }))
      .resolves.toMatchObject({ revision: 1, source: 'tenant_default' })
    const [url, init] = put.mock.calls[0]!
    expect(url).toContain(`/v1/firewall-actions/default?target_scope_id=${policy.tenant_scope_id}`)
    expect(init).toMatchObject({ method: 'PUT', headers: expect.objectContaining({ 'If-Match': '"0"' }) })
    // Only the 9 policy fields are sent.
    expect(Object.keys(JSON.parse(String(init.body))).sort()).toEqual(['block_networks', 'engage_threshold', 'escalated_action', 'normal_action',
      'recover_threshold', 'recovery_windows', 'return_page', 'trusted_crawlers', 'trusted_proxies'])
    for (const malformed of [{ ...systemDefault, revision: 1 }, { ...saved, updated_at: null }, { ...saved, extra: 1 }]) {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(malformed), { status: 200 })))
      await expect(firewallActionApi.getDefault('token', policy.tenant_scope_id)).rejects.toMatchObject({ code: 'invalid_response' })
    }
  })

  // autodefense-ux2 / 迁移 608：启停走 PATCH {"enabled"}，If-Match 当前 revision；响应必须带 enabled。
  it('switches the policy with PATCH and requires the enabled field', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ...policy, enabled: false, delivered: false }), { status: 200 }))
    vi.stubGlobal('fetch', fetch)
    await expect(firewallActionApi.setEnabled('token', { scopeId: policy.tenant_scope_id, siteId: policy.site_id, expectedRevision: 4, enabled: false }))
      .resolves.toMatchObject({ enabled: false })
    expect(fetch).toHaveBeenCalledWith(expect.stringContaining('/v1/firewall-actions/policy?'), expect.objectContaining({
      method: 'PATCH', body: '{"enabled":false}', headers: expect.objectContaining({ 'If-Match': '"4"' }) }))
    const withoutEnabled: Partial<FirewallActionPolicy> = { ...policy }
    delete withoutEnabled.enabled
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(withoutEnabled), { status: 200 })))
    await expect(firewallActionApi.get('token', policy.tenant_scope_id, policy.site_id)).rejects.toMatchObject({ code: 'invalid_response' })
  })
})
