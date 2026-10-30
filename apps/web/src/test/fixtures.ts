import type { AuthResponse, Principal } from '../api/auth'
import type { NodeManagementSettings } from '../api/nodes'

export function nodeManagementSettingsFixture(): NodeManagementSettings {
  return {
    schema_version: 1,
    sort: 100,
    node_type: 'L1',
    cache_directory: '',
    cache_limit_gb: 0,
    log_directory: '',
    ip_location: { country: '', province: '', city: '', isp: '', country_code: '' },
    auto_disable: {
      bandwidth_limit: 0,
      bandwidth_unit: 'Mbps',
      traffic_enabled: true,
      traffic_from_day: 1,
      traffic_from_time: '00:00:00',
      traffic_total_gb: 500,
      traffic_types: ['outbound'],
      excluded_interfaces: '',
      disabled_periods: '',
    },
    secondary_ips: [],
    external_probe: true,
  }
}

export function principal(overrides: Partial<Principal> = {}): Principal {
  return {
    user_id: '11111111-1111-4111-8111-111111111111',
    scope_id: '22222222-2222-4222-8222-222222222222',
    scope_kind: 'tenant',
    // 真实租户的 tenants.id 与 access_scopes.id 是两个独立 UUID（001_identity），夹具故意不同。
    tenant_id: '2a2a2a2a-2a2a-4a2a-8a2a-2a2a2a2a2a2a',
    username: 'jason',
    display_name: 'jason',
    roles: ['tenant_owner'],
    permissions: ['identity.self.read'],
    ...overrides,
  }
}

export function authResponse(user: Principal): AuthResponse {
  return {
    access_token: 'memory-only-access-token',
    token_type: 'Bearer',
    expires_in: 900,
    principal: user,
  }
}
