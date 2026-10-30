import { vi } from 'vitest'

import { streamsApi, validStreamServerName, type CreateStreamRequest, type Stream, type StreamRuntimeSpecV2, type UpdateStreamRequest } from '../api/streams'

const fields: CreateStreamRequest = {
  name: 'TCP gateway',
  remark: '',
  protocol: 'tcp',
  listen_address: '*',
  listen_port: 18100,
  upstream_address: '192.0.2.10',
  upstream_host: '',
  upstream_port: 9000,
  dns_policy: {
    positive_min_ttl_seconds: 0,
    positive_max_ttl_seconds: 0,
    negative_ttl_seconds: 0,
    stale_if_error_seconds: 0,
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
  enabled: true,
  tls_passthrough: false,
  server_names: [],
  max_new_connections_per_client_per_second: 0,
  new_connection_burst: 0,
  new_connection_ban_seconds: 0,
  toa: false,
  session_log_enabled: false,
}

const stream: Stream = {
  ...fields,
  package_subscription_id: '44444444-4444-4444-8444-444444444444',
  groups: [],
  id: '11111111-1111-4111-8111-111111111111',
  display_id: '1',
  scope_id: '22222222-2222-4222-8222-222222222222',
  eligibility_state: 'eligible',
  origins: [{ address: '192.0.2.10', weight: 1, down: false }],
  listen_ipv6: false,
  acl: { default_action: 'allow', rules: [] },
  admin_status: 'normal',
  line: { region_id: null, region_name: '', node_group_id: null, node_group_name: '', backup_node_group_id: null, backup_node_group_name: '' },
  overrides: { cname_domain: null, cname_mode: null, region_id: null, node_group_id: null, backup_node_group_id: null },
  sync_state: 'done',
  owner: null,
  revision: 3,
  publish_intent: {
    id: '33333333-3333-4333-8333-333333333333',
    version: 4,
    operation: 'update',
    desired_state: 'enabled',
    resource_revision: 3,
    configuration_source_revision: 41,
    // A stream belongs to no website (迁移 506): the v2 runtime names tenant and stream only.
    runtime_spec: {
      schema_version: 'cdnca.edge.l4/v2',
      tenant_id: '22222222-2222-4222-8222-222222222222',
      stream_id: '11111111-1111-4111-8111-111111111111',
      revision: 3,
      listener: { protocol: 'tcp', address: '*', port: 18100 },
      endpoint: { address: '192.0.2.10', port: 9000 },
      dns: { positive_min_ttl_seconds: 0, positive_max_ttl_seconds: 0, negative_ttl_seconds: 0, stale_if_error_seconds: 0, allow_private_addresses: false },
      geo: {
        enabled: false, tenant_id: '22222222-2222-4222-8222-222222222222', stream_id: '11111111-1111-4111-8111-111111111111', revision: 3,
        unknown_region_action: 'allow', trusted_proxy_cidrs: [], blocked_regions: [], region_cidrs: [],
      },
      connect_timeout_ms: 3000,
      response_timeout_ms: 30000,
      max_connections_per_client: 100,
      drain_timeout_ms: 30000,
      proxy_protocol_inbound: false,
      proxy_protocol_outbound: true,
    },
    state: 'unknown',
    automatic_request_id: null,
    publication_id: null,
    rollout_id: null,
    created_at: '2026-07-22T08:00:00Z',
  },
  created_at: '2026-07-22T08:00:00Z',
  updated_at: '2026-07-22T08:05:00Z',
}

const modernStream = {
  ...stream,
  package_subscription_id: '44444444-4444-4444-8444-444444444444',
  remark: 'Main TCP entry',
  upstream_address: '',
  upstream_host: 'origin.example.test',
  dns_policy: {
    positive_min_ttl_seconds: 5,
    positive_max_ttl_seconds: 300,
    negative_ttl_seconds: 30,
    stale_if_error_seconds: 900,
    allow_private_addresses: false,
  },
  geo_policy: {
    enabled: true,
    unknown_region_action: 'block',
    trusted_proxy_cidrs: ['192.0.2.0/24'],
    blocked_regions: ['cn-bj'],
    region_cidrs: [{ region: 'cn-bj', cidrs: ['198.51.100.0/24'] }],
  },
  max_connections_per_client: 100,
  proxy_protocol_inbound: true,
  publish_intent: {
    ...stream.publish_intent,
    publication_id: '66666666-6666-4666-8666-666666666666',
    rollout_id: '77777777-7777-4777-8777-777777777777',
    runtime_spec: {
      schema_version: 'cdnca.edge.l4/v2',
      tenant_id: stream.scope_id,
      stream_id: stream.id,
      revision: stream.revision,
      listener: { protocol: 'tcp', address: '*', port: 18100 },
      endpoint: { host: 'origin.example.test', port: 9000 },
      dns: {
        positive_min_ttl_seconds: 5,
        positive_max_ttl_seconds: 300,
        negative_ttl_seconds: 30,
        stale_if_error_seconds: 900,
        allow_private_addresses: false,
      },
      geo: {
        enabled: true,
        tenant_id: stream.scope_id,
        stream_id: stream.id,
        revision: stream.revision,
        unknown_region_action: 'block',
        trusted_proxy_cidrs: ['192.0.2.0/24'],
        blocked_regions: ['cn-bj'],
        region_cidrs: [{ region: 'cn-bj', cidrs: ['198.51.100.0/24'] }],
      },
      connect_timeout_ms: 3000,
      response_timeout_ms: 30000,
      max_connections_per_client: 100,
      drain_timeout_ms: 30000,
      proxy_protocol_inbound: true,
      proxy_protocol_outbound: true,
    },
  },
} as unknown as Stream

describe('streamsApi', () => {
  const extra = { id: '88888888-8888-4888-8888-888888888888', protocol: 'tcp', address: '*', port: 18101 }

  it('reads additional listeners only when the immutable intent agrees', async () => {
    const item = { ...modernStream, additional_listeners: [extra], publish_intent: { ...modernStream.publish_intent,
      runtime_spec: { ...modernStream.publish_intent.runtime_spec, additional_listeners: [extra] } } }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(item)))
    expect(await streamsApi.get('token', item.id)).toMatchObject({ additional_listeners: [extra] })
  })

  it.each([
    null, [{ ...extra, id: stream.id }], [extra, extra], [{ ...extra, port: stream.listen_port }],
    [{ ...extra, port: 0 }], [{ ...extra, address: '127.0.0.1' }], [{ ...extra, protocol: 'udp' }],
  ])('rejects invalid additional listener identities, sockets and UDP with PROXY: %j', async (listeners) => {
    const item = { ...modernStream, additional_listeners: listeners, publish_intent: { ...modernStream.publish_intent,
      runtime_spec: { ...modernStream.publish_intent.runtime_spec, additional_listeners: listeners } } }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(item)))
    await expect(streamsApi.get('token', item.id)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('rejects a resource whose extra listeners are absent from its publication intent', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...modernStream, additional_listeners: [extra] })))
    await expect(streamsApi.get('token', modernStream.id)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  const passthrough = (names: unknown = ['app.example.com', '*.example.com'], runtime: Record<string, unknown> = { tls_passthrough: true, server_names: names }, overrides: Record<string, unknown> = {}) => ({
    ...modernStream, tls_passthrough: true, server_names: names, ...overrides,
    publish_intent: { ...modernStream.publish_intent, runtime_spec: { ...modernStream.publish_intent.runtime_spec, ...runtime } },
  })

  it('reads TLS passthrough when the runtime intent carries the same server names in any order', async () => {
    const item = passthrough(['app.example.com', '*.example.com'], { tls_passthrough: true, server_names: ['*.example.com', 'app.example.com'] })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(item)))
    expect(await streamsApi.get('token', item.id)).toMatchObject({ tls_passthrough: true, server_names: ['app.example.com', '*.example.com'] })
  })

  it('reads a plain stream whose runtime intent omits both passthrough fields', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(modernStream)))
    expect(await streamsApi.get('token', modernStream.id)).toMatchObject({ tls_passthrough: false, server_names: [] })
  })

  it.each([
    ['runtime omits passthrough', passthrough(undefined, {})],
    ['runtime server names differ', passthrough(undefined, { tls_passthrough: true, server_names: ['app.example.com'] })],
    ['runtime has passthrough the resource lacks', { ...modernStream, publish_intent: { ...modernStream.publish_intent,
      runtime_spec: { ...modernStream.publish_intent.runtime_spec, tls_passthrough: true, server_names: ['app.example.com'] } } }],
    ['runtime has names without passthrough', { ...modernStream, publish_intent: { ...modernStream.publish_intent,
      runtime_spec: { ...modernStream.publish_intent.runtime_spec, server_names: [] } } }],
    ['runtime passthrough is false instead of absent', { ...modernStream, publish_intent: { ...modernStream.publish_intent,
      runtime_spec: { ...modernStream.publish_intent.runtime_spec, tls_passthrough: false } } }],
    ['resource omits passthrough', { ...modernStream, tls_passthrough: undefined }],
    ['resource omits server names', { ...modernStream, server_names: undefined }],
    ['passthrough without names', passthrough([])],
    ['names without passthrough', { ...modernStream, server_names: ['app.example.com'] }],
    ['duplicate names', passthrough(['app.example.com', 'app.example.com'])],
    ['invalid name', passthrough(['*.com'])],
    ['too many names', passthrough(Array.from({ length: 33 }, (_, index) => `h${index}.example.com`))],
  ])('rejects inconsistent TLS passthrough facts: %s', async (_name, item) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(item)))
    await expect(streamsApi.get('token', modernStream.id)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  // 无 PROXY、无区域限制的现代转发：切到 UDP 本身合法，只剩透传规则会失败。
  const plainGeo = { enabled: false, unknown_region_action: 'allow', trusted_proxy_cidrs: [], blocked_regions: [], region_cidrs: [] }
  const plain = (overrides: Record<string, unknown>, runtime: Record<string, unknown>) => ({
    ...modernStream, geo_policy: plainGeo, proxy_protocol_inbound: false, proxy_protocol_v1: false, ...overrides,
    publish_intent: { ...modernStream.publish_intent, runtime_spec: { ...modernStream.publish_intent.runtime_spec,
      geo: { ...(modernStream.publish_intent.runtime_spec as StreamRuntimeSpecV2).geo, ...plainGeo }, proxy_protocol_inbound: false, proxy_protocol_outbound: false, ...runtime } },
  })
  const udp = { ...extra, protocol: 'udp' }
  const tls = { tls_passthrough: true, server_names: ['app.example.com'] }

  it.each([
    ['UDP primary listener', { protocol: 'udp' }, { listener: { protocol: 'udp', address: '*', port: 18100 } }],
    ['UDP additional listener', { additional_listeners: [udp] }, { additional_listeners: [udp] }],
  ])('accepts a plain %s but rejects it with TLS passthrough', async (_name, overrides, runtime) => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(plain(overrides, runtime))))
      .mockResolvedValueOnce(new Response(JSON.stringify(plain({ ...overrides, ...tls }, { ...runtime, ...tls }))))
    await expect(streamsApi.get('token', modernStream.id)).resolves.toMatchObject({ tls_passthrough: false })
    await expect(streamsApi.get('token', modernStream.id)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  const limited = (runtime: unknown = { rate_per_second: 20, burst: 5, ban_seconds: 60 }, overrides: Record<string, unknown> = {}) => ({
    ...modernStream, max_new_connections_per_client_per_second: 20, new_connection_burst: 5, new_connection_ban_seconds: 60, ...overrides,
    publish_intent: { ...modernStream.publish_intent, runtime_spec: { ...modernStream.publish_intent.runtime_spec, new_conn_rate: runtime } },
  })

  it('reads a new connection rate when the runtime intent carries the same rate', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(limited())))
    expect(await streamsApi.get('token', modernStream.id))
      .toMatchObject({ max_new_connections_per_client_per_second: 20, new_connection_burst: 5, new_connection_ban_seconds: 60 })
  })

  it.each([
    ['runtime omits the rate', { ...modernStream, max_new_connections_per_client_per_second: 20, new_connection_burst: 5, new_connection_ban_seconds: 60 }],
    ['runtime rate differs', limited({ rate_per_second: 10, burst: 5, ban_seconds: 60 })],
    ['runtime ban differs', limited({ rate_per_second: 20, burst: 5, ban_seconds: 0 })],
    ['runtime rate has an extra key', limited({ rate_per_second: 20, burst: 5, ban_seconds: 60, x: 1 })],
    ['runtime rate on an unlimited stream', limited({ rate_per_second: 20, burst: 5, ban_seconds: 60 },
      { max_new_connections_per_client_per_second: 0, new_connection_burst: 0, new_connection_ban_seconds: 0 })],
    ['resource omits the rate', { ...modernStream, max_new_connections_per_client_per_second: undefined }],
    ['burst without a rate', { ...modernStream, new_connection_burst: 5 }],
    ['ban without a rate', { ...modernStream, new_connection_ban_seconds: 60 }],
    ['rate over the bound', limited({ rate_per_second: 100001, burst: 5, ban_seconds: 60 }, { max_new_connections_per_client_per_second: 100001 })],
    ['ban over the bound', limited({ rate_per_second: 20, burst: 5, ban_seconds: 86401 }, { new_connection_ban_seconds: 86401 })],
  ])('rejects an inconsistent new connection rate: %s', async (_, item) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(item)))
    await expect(streamsApi.get('token', modernStream.id)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  // 回源携带客户端 IP = TOA：资源与发布意图一致才可读；TOA 与 PROXY、UDP 互斥。
  it('reads TOA only when the runtime intent carries toa: true', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(plain({ toa: true }, { toa: true }))))
      .mockResolvedValueOnce(new Response(JSON.stringify(plain({}, {}))))
    await expect(streamsApi.get('token', modernStream.id)).resolves.toMatchObject({ toa: true, proxy_protocol_v1: false })
    await expect(streamsApi.get('token', modernStream.id)).resolves.toMatchObject({ toa: false })
  })

  it.each([
    ['runtime omits toa', plain({ toa: true }, {})],
    ['runtime toa on a plain stream', plain({}, { toa: true })],
    ['runtime toa false', plain({ toa: true }, { toa: false })],
    ['resource omits toa', plain({ toa: undefined }, {})],
    ['toa with outbound PROXY', plain({ toa: true, proxy_protocol_v1: true }, { toa: true, proxy_protocol_outbound: true })],
    ['toa on UDP', plain({ toa: true, protocol: 'udp' }, { toa: true, listener: { protocol: 'udp', address: '*', port: 18100 } })],
  ])('rejects inconsistent TOA facts: %s', async (_name, item) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(item)))
    await expect(streamsApi.get('token', modernStream.id)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  const logged = (runtime: unknown = true, overrides: Record<string, unknown> = {}) => ({
    ...modernStream, session_log_enabled: true, ...overrides,
    publish_intent: { ...modernStream.publish_intent, runtime_spec: { ...modernStream.publish_intent.runtime_spec, session_log: runtime } },
  })

  it('reads a session log when the runtime intent carries it', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(logged())))
    expect(await streamsApi.get('token', modernStream.id)).toMatchObject({ session_log_enabled: true })
  })

  it.each([
    ['runtime omits it', { ...modernStream, session_log_enabled: true }],
    ['runtime false', logged(false)],
    ['runtime on an unlogged stream', logged(true, { session_log_enabled: false })],
    ['resource omits it', { ...modernStream, session_log_enabled: undefined }],
  ])('rejects an inconsistent session log: %s', async (_, item) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(item)))
    await expect(streamsApi.get('token', modernStream.id)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  // 端口范围 / 跟随端口回源（tcp/udp v9）：资源与发布意图一致才可读。
  const ranged = (runtime: { port_end?: unknown; follow_port?: unknown } = { port_end: 18199, follow_port: true }, overrides: Record<string, unknown> = {}) => {
    const spec = modernStream.publish_intent.runtime_spec as unknown as StreamRuntimeSpecV2
    return {
      ...modernStream, listen_port_end: 18199, upstream_follow_port: true, upstream_port: spec.listener.port, ...overrides,
      publish_intent: { ...modernStream.publish_intent, runtime_spec: { ...spec,
        listener: { ...spec.listener, ...(runtime.port_end === undefined ? {} : { port_end: runtime.port_end }) },
        endpoint: { ...spec.endpoint, port: spec.listener.port, ...(runtime.follow_port === undefined ? {} : { follow_port: runtime.follow_port }) } } },
    }
  }

  it('reads a port range with follow-port when the runtime intent carries both', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(ranged())))
    expect(await streamsApi.get('token', modernStream.id)).toMatchObject({ listen_port_end: 18199, upstream_follow_port: true })
  })

  it.each([
    ['runtime omits port_end', ranged({ follow_port: true })],
    ['runtime omits follow_port', ranged({ port_end: 18199 })],
    ['runtime range on a single port', ranged({ port_end: 18199 }, { listen_port_end: 0, upstream_follow_port: false })],
    ['range over 1000 ports', ranged({ port_end: 19100, follow_port: true }, { listen_port_end: 19100 })],
    ['end below start', ranged({ port_end: 18000, follow_port: true }, { listen_port_end: 18000 })],
  ])('rejects inconsistent port range facts: %s', async (_name, item) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(item)))
    await expect(streamsApi.get('token', modernStream.id)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  // 防护规则（tcp/udp v10）：资源与发布意图逐条一致才可读；没有规则时意图里不出现。
  const guardRules = [
    { id: '99999999-9999-4999-8999-999999999991', action: 'ban', ban_seconds: 600, threshold: 5, window_seconds: 60,
      client_ip: { cidrs: ['203.0.113.0/24'] } },
    { id: '99999999-9999-4999-8999-999999999992', action: 'drop', first_packet: { match: 'prefix_hex', value: '16030100' },
      geo: [{ field: 'tag', values: ['idc:global'] }] },
  ]
  const guarded = (runtime: unknown = guardRules, overrides: Record<string, unknown> = {}) => ({
    ...modernStream, guard_rules: guardRules, ...overrides,
    publish_intent: { ...modernStream.publish_intent, runtime_spec: { ...modernStream.publish_intent.runtime_spec,
      ...(runtime === 'omit' ? {} : { guard_rules: runtime }) } },
  })

  it('reads guard rules when the runtime intent carries the same rules', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(guarded())))
    expect((await streamsApi.get('token', modernStream.id)).guard_rules).toEqual(guardRules)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...modernStream, guard_rules: [] })))
    expect((await streamsApi.get('token', modernStream.id)).guard_rules).toEqual([])
  })

  it.each([
    ['runtime omits them', guarded('omit')],
    ['runtime reordered', guarded([...guardRules].reverse())],
    ['runtime rules on an unguarded stream', guarded(guardRules, { guard_rules: [] })],
    ['ban without threshold', guarded([{ ...guardRules[0], threshold: undefined }], { guard_rules: [{ ...guardRules[0], threshold: undefined }] })],
    ['rule without condition', guarded([{ id: guardRules[0].id, action: 'drop' }], { guard_rules: [{ id: guardRules[0].id, action: 'drop' }] })],
    ['unknown key', guarded([{ ...guardRules[1], note: 'x' }], { guard_rules: [{ ...guardRules[1], note: 'x' }] })],
  ])('rejects inconsistent guard rules: %s', async (_name, item) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(item)))
    await expect(streamsApi.get('token', modernStream.id)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('keeps where a port conflict is for the form', async () => {
    const { streamPortConflict } = await import('../api/streams')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ error: {
      code: 'stream_port_conflict', message: 'raw', request_id: 'r1',
      details: { protocol: 'tcp', port: 20000, port_end: 20010, with: 'stream', name: 'game' },
    } }), { status: 409 }))
    const error = await streamsApi.create('token', fields, 'key').catch((caught: unknown) => caught)
    expect(error).toMatchObject({ status: 409, code: 'stream_port_conflict' })
    expect(streamPortConflict(error as never)).toEqual({ protocol: 'tcp', port: 20000, port_end: 20010, with: 'stream', name: 'game' })
  })

  it.each([
    ['a.example.com', true], ['*.example.com', true], ['x-1.b2.example.com', true], [`${'a'.repeat(63)}.example.com`, true],
    ['*.com', false], ['*', false], ['example', false], ['a.*.example.com', false], ['a*.example.com', false],
    ['A.example.com', false], ['example.com.', false], ['-a.example.com', false], ['a-.example.com', false],
    [`${'a'.repeat(64)}.example.com`, false], [`${Array.from({ length: 127 }, () => 'a').join('.')}.bc`, false], ['', false],
  ])('validates server name %s as %s', (name, valid) => {
    expect(validStreamServerName(name)).toBe(valid)
  })

  it('serializes independent precise filters without a broad search', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [], total: 0, page: 1, limit: 10 }), { status: 200 }))
	await streamsApi.list('token', { page: 1, limit: 10, listen_port: 18100, display_id: '9223372036854775807', owner_display_id: '9223372036854775806', publication_state: 'retrying', upstream: 'Origin_%', group_id: stream.id, cname_domain: 'edge.example.net', cname_hostname: 'tenant-edge' })
    const query = new URL(String(fetchSpy.mock.calls[0][0]), 'http://localhost').searchParams
	expect(Object.fromEntries(query)).toEqual({ page: '1', limit: '10', listen_port: '18100', display_id: '9223372036854775807', owner_display_id: '9223372036854775806', publication_state: 'retrying', upstream: 'Origin_%', group_id: stream.id, cname_domain: 'edge.example.net', cname_hostname: 'tenant-edge' })
  })

  it.each(['已购套餐名称', null, undefined])('accepts the optional persisted package name %s', async (packageName) => {
    const item = { ...stream, package_name: packageName }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      items: [item], total: 1, page: 1, limit: 20,
    }), { status: 200 }))
    const result = await streamsApi.list('token', { page: 1, limit: 20 })
    expect(result.items[0].package_name).toBe(packageName)
  })

  it.each([123, {}, []])('rejects malformed package name metadata %j', async (packageName) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      items: [{ ...stream, package_name: packageName }], total: 1, page: 1, limit: 20,
    }), { status: 200 }))
    await expect(streamsApi.list('token', { page: 1, limit: 20 })).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('parses exact modern source facts and immutable publication target identities', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({
        items: [modernStream], total: 1, page: 1, limit: 20,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        items: [{
          ...modernStream,
          publish_intent: {
            ...modernStream.publish_intent,
            // A runtime naming a website is not a 492 stream runtime.
            runtime_spec: { ...modernStream.publish_intent.runtime_spec, site_id: '88888888-8888-4888-8888-888888888888' },
          },
        }],
        total: 1,
        page: 1,
        limit: 20,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }))

    await expect(streamsApi.list('token', { page: 1, limit: 20 })).resolves.toMatchObject({
      items: [{
        package_subscription_id: modernStream.package_subscription_id,
        remark: modernStream.remark,
        upstream_host: modernStream.upstream_host,
        dns_policy: modernStream.dns_policy,
        geo_policy: modernStream.geo_policy,
        max_connections_per_client: 100,
        proxy_protocol_inbound: true,
        publish_intent: {
          id: stream.publish_intent.id,
          version: 4,
          resource_revision: 3,
          configuration_source_revision: 41,
          publication_id: modernStream.publish_intent.publication_id,
          rollout_id: modernStream.publish_intent.rollout_id,
          state: 'unknown',
          runtime_spec: {
            schema_version: 'cdnca.edge.l4/v2',
            tenant_id: modernStream.scope_id,
            stream_id: modernStream.id,
            revision: modernStream.revision,
          },
        },
      }],
    })
    await expect(streamsApi.list('token', { page: 1, limit: 20 })).rejects.toMatchObject({
      code: 'invalid_response',
      status: 502,
    })
  })

  it('encodes list filters', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ items: [stream], total: 1, page: 2, limit: 10 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const result = await streamsApi.list('token', { page: 2, limit: 10, search: 'gateway', protocol: 'tcp', enabled: true })

    expect(fetchSpy).toHaveBeenCalledWith(
      '/v1/streams?page=2&limit=10&search=gateway&protocol=tcp&enabled=true',
      expect.objectContaining({ credentials: 'include' }),
    )
    expect(result.items[0].publish_intent.state).toBe('unknown')
  })

  it.each(['unknown', 'pending', 'leased', 'retrying', 'reconciling', 'succeeded', 'failed', 'superseded'] as const)(
    'accepts the public delivery state %s',
    async (state) => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
        items: [{ ...stream, publish_intent: { ...stream.publish_intent, state } }],
        total: 1, page: 1, limit: 20,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }))

      await expect(streamsApi.list('token', { page: 1, limit: 20 }))
        .resolves.toMatchObject({ items: [{ publish_intent: { state } }] })
    },
  )

  it.each([undefined, null, '2027-07-22T08:00:00Z'])('reads an individual rule with the compatible expiry projection %s', async (expiry) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...stream, package_expires_at: expiry }), { status: 200 }))
    await expect(streamsApi.get('token', stream.id)).resolves.toMatchObject({ id: stream.id })
    expect(fetchSpy).toHaveBeenCalledWith(`/v1/streams/${stream.id}`, expect.objectContaining({ credentials: 'include', headers: expect.objectContaining({ Authorization: 'Bearer token' }) }))
  })

  it.each([123, false, '', 'not-a-date', '2027-07-22', '2027-13-40T08:00:00Z'])('rejects invalid subscription expiry %s', async (expiry) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...stream, package_expires_at: expiry }), { status: 200 }))
    await expect(streamsApi.get('token', stream.id)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('rejects detail facts for another forwarding rule', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(stream), { status: 200 }))
    await expect(streamsApi.get('token', '99999999-9999-4999-8999-999999999999')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('sends idempotency and revision headers for writes', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_, init) =>
      Promise.resolve(
        init?.method === 'DELETE'
          ? new Response(null, { status: 204 })
          : new Response(JSON.stringify(stream), { status: 201, headers: { 'Content-Type': 'application/json' } }),
      ),
    )

    await streamsApi.create('token', fields, 'create-key')
    const update: UpdateStreamRequest = { ...fields, expected_revision: stream.revision }
    await streamsApi.update('token', stream.id, update, 'update-key')
    await streamsApi.remove('token', stream, 'delete-key')

    expect(fetchSpy.mock.calls[0][1]).toEqual(expect.objectContaining({
      method: 'POST',
      headers: expect.objectContaining({ 'Idempotency-Key': 'create-key' }),
      body: JSON.stringify(fields),
    }))
    expect(fetchSpy.mock.calls[1][1]).toEqual(expect.objectContaining({
      method: 'PATCH',
      headers: expect.objectContaining({ 'Idempotency-Key': 'update-key', 'If-Match': '"3"' }),
      body: JSON.stringify(update),
    }))
    expect(fetchSpy.mock.calls[2][1]).toEqual(expect.objectContaining({
      method: 'DELETE',
      headers: expect.objectContaining({ 'Idempotency-Key': 'delete-key', 'If-Match': '"3"' }),
    }))
  })

  it('fails closed on unknown public delivery state or malformed success JSON', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({
        items: [{ ...stream, publish_intent: { ...stream.publish_intent, state: 'private_state' } }],
        total: 1,
        page: 1,
        limit: 20,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(new Response('{', { status: 200, headers: { 'Content-Type': 'application/json' } }))

    await expect(streamsApi.list('token', { page: 1, limit: 20 })).rejects.toMatchObject({
      code: 'invalid_response',
      status: 502,
    })
    await expect(streamsApi.list('token', { page: 1, limit: 20 })).rejects.toMatchObject({
      code: 'invalid_response',
      status: 502,
    })
  })
})
