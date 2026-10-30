import {
  systemConfigurationApi,
  type DefaultConfiguration,
  type NodeMonitoringConfiguration,
  type ResourceConfiguration,
  type SystemConfigurationDocument,
} from './systemConfiguration'

const value: NodeMonitoringConfiguration = {
  port_mode: 'default',
  probe_interval_ms: 10_000,
  probe_timeout_ms: 3_000,
  failure_threshold: 3,
  recovery_threshold: 3,
  failure_debounce_ms: 0,
  recovery_debounce_ms: 0,
  recovery_notification_enabled: true,
}

const document: SystemConfigurationDocument<'node_monitoring'> = {
  schema: 'cdnca.system-configuration/v2',
  category: 'node_monitoring',
  head_revision: 4,
  active_revision: 3,
  revision: 3,
  status: 'active',
  snapshot_sha256: 'a'.repeat(64),
  pending_categories: [],
  value,
}

const recommendedCipherSuites = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'

const defaults: DefaultConfiguration = {
  website: {
    http: { listen_ports: [80] },
    https: {
      listen_ports: [443],
      hsts_enabled: false,
      http2_enabled: false,
      http3_enabled: false,
      force_https: false,
      ssl: {
        mode: 'recommended',
        protocols: ['TLSv1.2', 'TLSv1.3'],
        cipher_suites: recommendedCipherSuites,
        prefer_server_ciphers: false,
      },
      ocsp_stapling_enabled: true,
    },
    origin: {
      scheme: 'http',
      http_port: 80,
      https_port: 443,
      response_timeout_seconds: 60,
      connect_timeout_seconds: 10,
      ssl_protocols: ['TLSv1', 'TLSv1.1', 'TLSv1.2'],
      http_version: '1.1',
      keepalive_enabled: true,
      post_body_limit_bytes: 104_857_600,
    },
    cache_rules: [{
      id: 'cache001',
      match: 'suffix',
      content: '.css',
      ttl_seconds: 86_400,
      ignore_query: true,
      force_cache: false,
      range: true,
      ignore_vary: false,
      no_cache: [{ variable: '$http_cookie', string: 'session=' }],
      enabled: true,
      position: 0,
    }],
    origin_request_headers: [{
      id: 'header01',
      name: 'X-CDN-Origin',
      value: 'cdnca',
      action: 'set',
      allow_duplicate: false,
      enabled: true,
      position: 0,
    }],
    access_log: {
      capture_request_headers: true,
      capture_response_headers: false,
      capture_request_body: false,
      request_body_limit_kb: 16,
    },
    security: {
      default_cc_policy_id: null,
      waf_enabled: false,
      waf_auto_block: { enabled: false, window_seconds: 60, hit_threshold: 20, block_seconds: 600 },
      waf_modules: {
        sqli: 'off', xss: 'off', upload: 'off', fi: 'off', cmdi: 'off',
        java: 'off', jdeser: 'off', php: 'off', phpdeser: 'off', ssti: 'off',
      },
    },
    other: {
      load_balancing: 'round_robin',
      gzip_enabled: true,
      gzip_types: ['application/json', 'text/css', 'text/plain'],
      websocket_enabled: false,
    },
  },
  stream: { protocol: 'tcp', load_balancing: 'round_robin', proxy_protocol_enabled: false },
  certificate: { issuer: 'lets_encrypt' },
  overrides: [{
    id: 'default1',
    scope: 'region',
    scope_id: 'east',
    values: { website: { other: {
      load_balancing: 'round_robin',
      gzip_enabled: true,
      gzip_types: ['text/css'],
      websocket_enabled: false,
    } } },
  }],
}

const resources: ResourceConfiguration = {
  site: {
    related_config_min_limit: 1_000,
    related_config_max_times_limit: 200,
    black_ip_limit: 50,
    white_ip_limit: 50,
    daily_clean_url_limit: 2_000,
    daily_clean_dir_limit: 500,
    daily_pre_cache_url_limit: 2_000,
    daily_ip_unlock_limit: 1_000,
    ip_unlock_per_request_limit: 50,
    cc_rule_max_limit: 5,
    max_domains_per_site: 100,
    listen_default_http_80: true,
    daily_access_log_download_limit: 10,
    access_log_tmp_dir: '/data/download-temp/',
    access_log_retain_hours: 12,
  },
  stream: {
    custom_port_not_allow: [{ from: 1, to: 79 }],
    related_config_min_limit: 10,
    related_config_max_times_limit: 10,
    acl_max_limit: 1_000,
  },
  site_stream: {
    custom_port_not_allow: [{ from: 1, to: 79 }],
    custom_port_allow: [{ from: 8_080, to: 8_090 }],
  },
  overrides: [],
}

const defaultsDocument: SystemConfigurationDocument<'defaults'> = {
  ...document,
  category: 'defaults',
  value: defaults,
}

const resourcesDocument: SystemConfigurationDocument<'resources'> = {
  ...document,
  category: 'resources',
  value: resources,
}

function response(body: unknown, etag = '"4"') {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json', ETag: etag },
  })
}

describe('systemConfigurationApi node monitoring', () => {
  it('strictly parses the effective node monitoring document and matching ETag', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(document))

    await expect(systemConfigurationApi.get('access-token', 'node_monitoring')).resolves.toEqual(document)

    expect(fetchSpy).toHaveBeenCalledWith(
      expect.stringContaining('/v1/admin/system-configuration/categories/node_monitoring'),
      expect.objectContaining({ credentials: 'include', headers: expect.objectContaining({ Authorization: 'Bearer access-token' }) }),
    )
  })

  it('accepts the fresh-install revision zero document and first write CAS', async () => {
    const fresh: SystemConfigurationDocument<'node_monitoring'> = {
      ...document,
      head_revision: 0,
      active_revision: 0,
      revision: 0,
      status: 'draft',
    }
    const saved: SystemConfigurationDocument<'node_monitoring'> = {
      ...fresh,
      head_revision: 1,
      revision: 1,
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(response(fresh, '"0"'))
      .mockResolvedValueOnce(response(saved, '"1"'))

    await expect(systemConfigurationApi.get('access-token', 'node_monitoring')).resolves.toEqual(fresh)
    await systemConfigurationApi.put(
      'access-token',
      'node_monitoring',
      value,
      0,
      'node-monitoring-first-write',
      'node-monitoring-first-request',
    )

    const [, init] = fetchSpy.mock.calls[1]
    expect(new Headers(init?.headers).get('If-Match')).toBe('"0"')
  })

  it('aborts a stalled category read instead of leaving the settings page pending forever', async () => {
    vi.useFakeTimers()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true })
    }))

    const pending = systemConfigurationApi.get('access-token', 'resources')
    const outcome = expect(pending).rejects.toMatchObject({ code: 'network_error', status: 0 })
    await vi.advanceTimersByTimeAsync(15_000)

    await outcome
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    vi.useRealTimers()
  })

  it.each([
    ['legacy schema', { ...document, schema: 'cdnca.system-configuration/v1' }],
    ['extra document field', { ...document, extra: true }],
    ['wrong category', { ...document, category: 'resources' }],
    ['extra value field', { ...document, value: { ...value, extra: true } }],
    ['unknown mode', { ...document, value: { ...value, port_mode: 'automatic' } }],
    ['default carries custom port', { ...document, value: { ...value, custom_port: 8443 } }],
    ['custom lacks port', { ...document, value: { ...value, port_mode: 'custom' } }],
    ['timeout exceeds interval', { ...document, value: { ...value, probe_interval_ms: 1_000, probe_timeout_ms: 1_001 } }],
    ['threshold outside range', { ...document, value: { ...value, failure_threshold: 21 } }],
  ])('rejects %s', async (_name, body) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(body))
    await expect(systemConfigurationApi.get('access-token', 'node_monitoring'))
      .rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('sends an exact frozen value, CAS revision, idempotency key, and request ID', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({
      ...document,
      head_revision: 5,
      revision: 5,
      status: 'draft',
    }, '"5"'))
    const custom: NodeMonitoringConfiguration = { ...value, port_mode: 'custom', custom_port: 9443 }

    await systemConfigurationApi.put(
      'write-token',
      'node_monitoring',
      custom,
      4,
      'node-monitoring-key',
      'node-monitoring-request',
    )

    const [, init] = fetchSpy.mock.calls[0]
    expect(init).toMatchObject({
      method: 'PUT',
      headers: expect.objectContaining({
        Authorization: 'Bearer write-token',
        'If-Match': '"4"',
        'Idempotency-Key': 'node-monitoring-key',
        'X-Request-ID': 'node-monitoring-request',
      }),
    })
    expect(JSON.parse(String(init?.body))).toEqual({ value: custom })
  })

  it.each([
    ['defaults', defaultsDocument],
    ['resources', resourcesDocument],
  ] as const)('strictly parses the nested %s v2 document', async (category, expectedDocument) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(expectedDocument))

    await expect(systemConfigurationApi.get('access-token', category)).resolves.toEqual(expectedDocument)
  })

  it.each([
    ['legacy flat defaults', 'defaults', { ...defaultsDocument, value: { listen_port: 80, origin_scheme: 'http' } }],
    ['defaults missing stream', 'defaults', {
      ...defaultsDocument,
      value: { website: defaults.website, certificate: defaults.certificate, overrides: defaults.overrides },
    }],
    ['defaults nested extra field', 'defaults', {
      ...defaultsDocument,
      value: { ...defaults, website: { ...defaults.website, http: { ...defaults.website.http, fallback_port: 8080 } } },
    }],
    ['legacy flat resources', 'resources', { ...resourcesDocument, value: { max_domains_per_site: 100 } }],
    ['resources missing site stream', 'resources', {
      ...resourcesDocument,
      value: { site: resources.site, stream: resources.stream, overrides: resources.overrides },
    }],
    // 区域覆盖收窄（region-trim）：默认配置只认 website.other（GZIP），资源配置不再有区域覆盖。
    ['defaults region override of a build-time setting', 'defaults', {
      ...defaultsDocument,
      value: { ...defaults, overrides: [{ id: 'default1', scope: 'region', scope_id: 'east', values: { website: { origin: { response_timeout_seconds: 90 } } } }] },
    }],
    ['defaults region override mixing gzip with another setting', 'defaults', {
      ...defaultsDocument,
      value: { ...defaults, overrides: [{ ...defaults.overrides[0]!, values: { website: { ...defaults.overrides[0]!.values.website, hsts_enabled: true } } }] },
    }],
    ['defaults region override of stream settings', 'defaults', {
      ...defaultsDocument,
      value: { ...defaults, overrides: [{ ...defaults.overrides[0]!, values: { ...defaults.overrides[0]!.values, stream: { protocol: 'udp' } } }] },
    }],
    ['resources region override', 'resources', {
      ...resourcesDocument,
      value: { ...resources, overrides: [{ id: 'resource1', scope: 'region', scope_id: 'east', values: { site: { black_ip_limit: 100 } } }] },
    }],
    ['resources nested extra field', 'resources', {
      ...resourcesDocument,
      value: { ...resources, site: { ...resources.site, max_sites_per_tenant: 100 } },
    }],
  ] as const)('rejects %s', async (_name, category, body) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(body))

    await expect(systemConfigurationApi.get('access-token', category))
      .rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('sends the exact nested defaults value with CAS and caller request metadata', async () => {
    const saved: SystemConfigurationDocument<'defaults'> = {
      ...defaultsDocument,
      head_revision: 5,
      revision: 5,
      status: 'draft',
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(saved, '"5"'))

    await systemConfigurationApi.put(
      'defaults-write-token',
      'defaults',
      defaults,
      4,
      'defaults-save-key',
      'defaults-save-request',
    )

    const [url, init] = fetchSpy.mock.calls[0]!
    expect(url).toContain('/v1/admin/system-configuration/categories/defaults')
    expect(init).toMatchObject({
      method: 'PUT',
      headers: expect.objectContaining({
        Authorization: 'Bearer defaults-write-token',
        'If-Match': '"4"',
        'Idempotency-Key': 'defaults-save-key',
        'X-Request-ID': 'defaults-save-request',
      }),
    })
    expect(JSON.parse(String(init?.body))).toEqual({ value: defaults })
  })

  it('rejects an ETag that does not match the document head revision', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(document, '"3"'))
    await expect(systemConfigurationApi.get('access-token', 'node_monitoring'))
      .rejects.toMatchObject({ code: 'invalid_response' })
  })
})

describe('systemConfigurationApi lifecycle', () => {
  const lifecycle = {
    revision: 5,
    status: 'validated' as const,
    snapshot_sha256: 'b'.repeat(64),
    replayed: false,
  }
  const publication = {
    tenant_scope_id: '11111111-1111-4111-8111-111111111111',
    tenant_source_revision: 9,
    publication_id: '22222222-2222-4222-8222-222222222222',
    config_version_id: '33333333-3333-4333-8333-333333333333',
    rollout_id: '44444444-4444-4444-8444-444444444444',
    rollout_state: 'queued' as const,
    artifact_sha256: 'c'.repeat(64),
    reason_code: 'system_configuration_activated' as const,
    created_at: '2026-09-15T08:00:00Z',
  }

  it('preflights and activates with exact frozen request metadata', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(lifecycle), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ...lifecycle, status: 'active' }), { status: 200 }))

    await expect(systemConfigurationApi.preflight(
      'lifecycle-token', 5, lifecycle.snapshot_sha256, 'preflight-key', 'preflight-request',
    )).resolves.toEqual(lifecycle)
    await expect(systemConfigurationApi.activate(
      'lifecycle-token', 5, 3, 'activate-key', 'activate-request',
    )).resolves.toEqual({ ...lifecycle, status: 'active' })

    const [preflightURL, preflightInit] = fetchSpy.mock.calls[0]!
    expect(preflightURL).toContain('/v1/admin/system-configuration/revisions/5/preflight')
    expect(preflightInit).toMatchObject({ method: 'POST', credentials: 'include' })
    expect(new Headers(preflightInit?.headers)).toMatchObject(expect.any(Headers))
    expect(new Headers(preflightInit?.headers).get('Authorization')).toBe('Bearer lifecycle-token')
    expect(new Headers(preflightInit?.headers).get('Idempotency-Key')).toBe('preflight-key')
    expect(new Headers(preflightInit?.headers).get('X-Request-ID')).toBe('preflight-request')
    expect(JSON.parse(String(preflightInit?.body))).toEqual({ snapshot_sha256: lifecycle.snapshot_sha256 })

    const [activateURL, activateInit] = fetchSpy.mock.calls[1]!
    expect(activateURL).toContain('/v1/admin/system-configuration/revisions/5/activate')
    expect(new Headers(activateInit?.headers).get('If-Match')).toBe('"3"')
    expect(new Headers(activateInit?.headers).get('Idempotency-Key')).toBe('activate-key')
    expect(activateInit?.body).toBeUndefined()
  })

  it('strictly parses activation publications for the requested revision', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      revision: 5,
      publications: [publication],
    }), { status: 200 }))

    await expect(systemConfigurationApi.listPublications('read-token', 5)).resolves.toEqual({
      revision: 5,
      publications: [publication],
    })
    const [url, init] = fetchSpy.mock.calls[0]!
    expect(url).toContain('/v1/admin/system-configuration/revisions/5/publications')
    expect(init?.method).toBeUndefined()
    expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer read-token')
  })

  it.each([
    ['wrong requested revision', { revision: 6, publications: [publication] }],
    ['unknown rollout state', { revision: 5, publications: [{ ...publication, rollout_state: 'done' }] }],
    ['extra publication field', { revision: 5, publications: [{ ...publication, internal_error: 'private' }] }],
  ])('rejects %s in lifecycle publication responses', async (_name, body) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body), { status: 200 }))
    await expect(systemConfigurationApi.listPublications('read-token', 5))
      .rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('rolls back a target revision with exact CAS, body, and response headers', async () => {
    const rollback = {
      revision: 6, status: 'draft' as const, snapshot_sha256: 'd'.repeat(64),
      source_revision: 2, replayed: false,
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(rollback), {
      status: 200,
      headers: { 'Content-Type': 'application/json', ETag: '"6"' },
    }))

    await expect(systemConfigurationApi.rollback(
      'rollback-token', 2, 5, 4, 'rollback-key', 'rollback-request',
    )).resolves.toEqual(rollback)

    const [url, init] = fetchSpy.mock.calls[0]!
    expect(url).toContain('/v1/admin/system-configuration/revisions/2/rollback')
    expect(init).toMatchObject({ method: 'POST', credentials: 'include' })
    const headers = new Headers(init?.headers)
    expect(headers.get('Authorization')).toBe('Bearer rollback-token')
    expect(headers.get('Content-Type')).toBe('application/json')
    expect(headers.get('If-Match')).toBe('"5"')
    expect(headers.get('Idempotency-Key')).toBe('rollback-key')
    expect(headers.get('X-Request-ID')).toBe('rollback-request')
    expect(JSON.parse(String(init?.body))).toEqual({ expected_active_revision: 4 })
  })

  it.each([
    ['wrong source revision', { revision: 6, status: 'draft', snapshot_sha256: 'd'.repeat(64), source_revision: 3, replayed: false }, '"6"'],
    ['wrong status', { revision: 6, status: 'active', snapshot_sha256: 'd'.repeat(64), source_revision: 2, replayed: false }, '"6"'],
    ['extra field', { revision: 6, status: 'draft', snapshot_sha256: 'd'.repeat(64), source_revision: 2, replayed: false, internal: true }, '"6"'],
    ['missing ETag', { revision: 6, status: 'draft', snapshot_sha256: 'd'.repeat(64), source_revision: 2, replayed: false }, null],
  ])('rejects rollback response with %s', async (_name, body, etag) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(body), {
      status: 200,
      headers: etag ? { 'Content-Type': 'application/json', ETag: etag } : { 'Content-Type': 'application/json' },
    }))
    await expect(systemConfigurationApi.rollback('token', 2, 5, 4, 'key', 'request'))
      .rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('accepts an exact idempotency replay header for rollback', async () => {
    const rollback = {
      revision: 6, status: 'draft', snapshot_sha256: 'd'.repeat(64), source_revision: 2, replayed: true,
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(rollback), {
      status: 200,
      headers: { 'Content-Type': 'application/json', ETag: '"6"', 'Idempotency-Replayed': 'true' },
    }))
    await expect(systemConfigurationApi.rollback('token', 2, 5, 4, 'key', 'request')).resolves.toEqual(rollback)
  })

  it('rejects invalid lifecycle metadata before issuing a request', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(systemConfigurationApi.preflight('token', 0, 'bad', 'key', 'request'))
      .rejects.toMatchObject({ code: 'validation_error' })
    await expect(systemConfigurationApi.activate('token', 1, -1, 'key', 'request'))
      .rejects.toMatchObject({ code: 'validation_error' })
    await expect(systemConfigurationApi.rollback('token', 0, 1, 1, 'key', 'request'))
      .rejects.toMatchObject({ code: 'validation_error' })
    await expect(systemConfigurationApi.rollback('token', 1, 0, 1, 'key', 'request'))
      .rejects.toMatchObject({ code: 'validation_error' })
    await expect(systemConfigurationApi.rollback('token', 1, 2, 3, 'key', 'request'))
      .rejects.toMatchObject({ code: 'validation_error' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
