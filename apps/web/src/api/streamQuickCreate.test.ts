import type { Stream } from './streams'
import {
  buildQuickStreamAttempt,
  parseQuickStreamEntries,
  quickStreamTemplate,
} from './streamQuickCreate'

const fullStream = {
  id: '11111111-1111-4111-8111-111111111111',
  display_id: '1',
  scope_id: '22222222-2222-4222-8222-222222222222',
  eligibility_state: 'eligible',
  owner: { id: '33333333-3333-4333-8333-333333333333', display_name: 'owner' },
  package_subscription_id: '44444444-4444-4444-8444-444444444444',
  name: 'TCP gateway',
  remark: 'primary',
  protocol: 'tcp',
  listen_address: '*',
  listen_port: 18080,
  upstream_address: '192.0.2.10',
  upstream_host: '',
  upstream_port: 9000,
  dns_policy: {
    positive_min_ttl_seconds: 30,
    positive_max_ttl_seconds: 300,
    negative_ttl_seconds: 30,
    stale_if_error_seconds: 120,
    allow_private_addresses: false,
  },
  geo_policy: {
    enabled: false,
    unknown_region_action: 'allow',
    trusted_proxy_cidrs: [],
    blocked_regions: [],
    region_cidrs: [],
  },
  connect_timeout_ms: 3000,
  response_timeout_ms: 30000,
  max_connections_per_client: 100,
  proxy_protocol_inbound: false,
  proxy_protocol_v1: true,
  balance_way: 'rr',
  groups: [],
  enabled: true,
  tls_passthrough: false,
  server_names: [],
  max_new_connections_per_client_per_second: 0,
  new_connection_burst: 0,
  new_connection_ban_seconds: 0,
  toa: false,
  session_log_enabled: false,
  revision: 7,
  publish_intent: {
    id: '66666666-6666-4666-8666-666666666666',
    version: 1,
    operation: 'create',
    desired_state: 'enabled',
    resource_revision: 7,
    configuration_source_revision: 41,
    runtime_spec: {
      id: 'stream_1', protocol: 'tcp', listen_port: 18080,
      origins: [{ host: '192.0.2.10', port: 9000, weight: 1 }],
      connect_timeout_ms: 3000, response_timeout_ms: 30000, proxy_protocol_v1: true,
    },
    state: 'pending',
    automatic_request_id: null,
    publication_id: null,
    rollout_id: null,
    created_at: '2026-08-08T00:00:00Z',
  },
  created_at: '2026-08-08T00:00:00Z',
  updated_at: '2026-08-08T00:00:00Z',
} as unknown as Stream

describe('stream quick create contract', () => {
  it('parses English/Chinese separators and produces a canonical protocol/port order', () => {
    expect(parseQuickStreamEntries('99/udp， 88/tcp\n443 53/udp')).toEqual({
      entries: [
        { protocol: 'tcp', listen_port: 88 },
        { protocol: 'tcp', listen_port: 443 },
        { protocol: 'udp', listen_port: 53 },
        { protocol: 'udp', listen_port: 99 },
      ],
      rows: [
        { raw: '99/udp', entry: { protocol: 'udp', listen_port: 99 }, error: null },
        { raw: '88/tcp', entry: { protocol: 'tcp', listen_port: 88 }, error: null },
        { raw: '443', entry: { protocol: 'tcp', listen_port: 443 }, error: null },
        { raw: '53/udp', entry: { protocol: 'udp', listen_port: 53 }, error: null },
      ],
      error: null,
    })
  })

  it('keeps valid rows while rejecting invalid, duplicate, and occupied entries individually', () => {
    expect(parseQuickStreamEntries('88/tcp, 0/tcp, invalid, 88, 53/udp', [
      { protocol: 'udp', listen_port: 53 },
    ])).toEqual({
      entries: [{ protocol: 'tcp', listen_port: 88 }],
      rows: [
        { raw: '88/tcp', entry: { protocol: 'tcp', listen_port: 88 }, error: null },
        { raw: '0/tcp', entry: null, error: 'port_range' },
        { raw: 'invalid', entry: null, error: 'invalid_entry' },
        { raw: '88', entry: { protocol: 'tcp', listen_port: 88 }, error: 'duplicate' },
        { raw: '53/udp', entry: { protocol: 'udp', listen_port: 53 }, error: 'conflict' },
      ],
      error: 'port_range',
    })
  })

  it('rejects an empty list with no preview rows', () => {
    expect(parseQuickStreamEntries('')).toEqual({ entries: [], rows: [], error: 'empty' })
  })

  it('copies the complete frozen service contract and binds platform ownership', () => {
    const template = quickStreamTemplate(fullStream)
    expect(template).not.toBeNull()
    const attempt = buildQuickStreamAttempt(
      template!,
      { protocol: 'tcp', listen_port: 18443 },
      'platform',
      'quick-stream-fixed-key',
    )

    expect(attempt).toEqual({
      key: 'quick-stream-fixed-key',
      template_id: fullStream.id,
      template_revision: 7,
      input: expect.objectContaining({
        target_scope_id: fullStream.scope_id,
        owner_id: fullStream.owner?.id,
              name: 'TCP gateway-tcp-18443',
        protocol: 'tcp',
        listen_port: 18443,
        upstream_address: '192.0.2.10',
        upstream_host: '',
        max_connections_per_client: 100,
        proxy_protocol_inbound: false,
        proxy_protocol_v1: true,
      }),
    })
  })

  it('fails closed when a list item lacks fields required by the mounted create service', () => {
    const redactedTenantTemplate = quickStreamTemplate({ ...fullStream, owner: null } as Stream)
    expect(redactedTenantTemplate).not.toBeNull()
    expect(() => buildQuickStreamAttempt(
      redactedTenantTemplate!, { protocol: 'tcp', listen_port: 18443 }, 'platform', 'platform-key',
    )).toThrow(/scope or protocol/)
    // 社区版：转发不绑定套餐，没有套餐订阅也能作为快捷新建模板，且新建请求不带它。
    const withoutPackage = quickStreamTemplate({ ...fullStream, package_subscription_id: undefined } as unknown as Stream)
    expect(withoutPackage).not.toBeNull()
    expect(withoutPackage!.fields).not.toHaveProperty('package_subscription_id')
    expect(quickStreamTemplate({ ...fullStream, server_names: undefined } as unknown as Stream)).toBeNull()
  })

  it('copies TLS passthrough server names to each quick-created port', () => {
    const template = quickStreamTemplate({ ...fullStream, tls_passthrough: true, server_names: ['app.example.com'] } as Stream)
    const attempt = buildQuickStreamAttempt(template!, { protocol: 'tcp', listen_port: 18443 }, 'tenant', 'tenant-key')
    expect(attempt.input).toMatchObject({ listen_port: 18443, tls_passthrough: true, server_names: ['app.example.com'] })
  })
})
