import { beforeEach, describe, expect, it, vi } from 'vitest'

import { sitesApi, type SiteBasicConfig } from './sites'

const siteID = '55555555-5555-4555-8555-555555555555'

function basic(ipv6Enabled: boolean): SiteBasicConfig {
  return {
    package_id: null,
    package_name: null,
    group_id: null,
    group_name: null,
    domains: ['listener.example.test'],
    http_enabled: true,
    http_listen_ports: ['80'],
    https_listen_ports: ['443'],
    tls_protocols: ['TLSv1.2', 'TLSv1.3'],
    origins: ['192.0.2.10'],
    cname: '',
    ipv6_enabled: ipv6Enabled,
    https_enabled: true,
    enabled: true,
    status: 'active',
    sync_status: 'pending',
    is_default: false,
  }
}

function detail(listenerState?: unknown) {
  return {
    id: siteID,
    version: 7,
    owner: null,
    created_at: '2026-08-08T00:00:00Z',
    updated_at: '2026-08-08T00:00:00Z',
    lock: { locked: false, reason: null, locked_at: null, operator: null },
    basic: basic(true),
    listener_state: listenerState,
    origin_pool: {
      origins: [{ host: '192.0.2.10', port: 80, weight: 1, enabled: true }],
      balance_method: 'round_robin',
      failover_tries: 1,
      connect_timeout_ms: 1_000,
      read_timeout_ms: 5_000,
    },
  }
}

function response(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

beforeEach(() => vi.restoreAllMocks())

describe('site IPv6 desired/runtime contract', () => {
  it('accepts only a typed runtime state matching the desired fact', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(detail()))
      .mockResolvedValueOnce(response(detail({ ipv6_desired_enabled: false, ipv6_runtime_state: 'active' })))
      .mockResolvedValueOnce(response(detail({ ipv6_desired_enabled: true, ipv6_runtime_state: 'unknown' })))
      .mockResolvedValueOnce(response(detail({ ipv6_desired_enabled: true, ipv6_runtime_state: 'pending' })))
    vi.stubGlobal('fetch', fetchMock)

    for (let index = 0; index < 3; index += 1) {
      await expect(sitesApi.detail('token', siteID)).rejects.toMatchObject({ code: 'invalid_response' })
    }
    await expect(sitesApi.detail('token', siteID)).resolves.toMatchObject({
      basic: { ipv6_enabled: true },
      listener_state: { ipv6_desired_enabled: true, ipv6_runtime_state: 'pending' },
    })
  })
})
