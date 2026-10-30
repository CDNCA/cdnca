import { afterEach, describe, expect, it, vi } from 'vitest'

import { firewallApi } from './firewall'

const policy = {
  id: '11111111-1111-4111-8111-111111111111', tenant_scope_id: '22222222-2222-4222-8222-222222222222',
  enabled: true, default_action: 'allow' as const, revision: 4, active_revision: 3, deployment_state: 'active' as const,
  rules: [{ id: '33333333-3333-4333-8333-333333333333', priority: 1, action: 'deny' as const,
    cidrs: ['198.51.100.0/24'], protocol: 'tcp' as const, port_start: 443, port_end: 443,
    site_ids: ['44444444-4444-4444-8444-444444444444'], expires_at: '2030-01-02T03:04:05Z' }],
  updated_at: '2026-08-07T00:00:00Z',
}

afterEach(() => vi.unstubAllGlobals())

describe('firewallApi', () => {
  it('accepts contract rule scope and expiry fields', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(policy), { status: 200 })))
    await expect(firewallApi.get('token', policy.tenant_scope_id)).resolves.toEqual(policy)
  })

  it.each([
    ['invalid site ID', { site_ids: ['not-a-uuid'] }],
    ['duplicate site IDs', { site_ids: ['44444444-4444-4444-8444-444444444444', '44444444-4444-4444-8444-444444444444'] }],
    ['out-of-range port', { port_start: 65536 }],
    ['invalid expiry', { expires_at: 'tomorrow' }],
  ])('rejects %s in a policy response', async (_label, patch) => {
    const rule = { ...policy.rules[0], ...patch }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ ...policy, rules: [rule] }), { status: 200 })))
    await expect(firewallApi.get('token', policy.tenant_scope_id)).rejects.toMatchObject({ code: 'invalid_response' })
  })
})
