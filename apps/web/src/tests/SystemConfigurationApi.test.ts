import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import {
  systemConfigurationApi,
  type NginxConfiguration,
  type SystemConfigurationDocument,
} from '../api/systemConfiguration'

const nginx: NginxConfiguration = {
  worker: {
    worker_processes: 4,
    worker_connections: 4_096,
    worker_rlimit_nofile: 65_536,
    worker_shutdown_timeout_ms: 10_000,
    logs_dir: '/var/log/cdnca/nginx',
  },
  http: {
    gzip_comp_level: 5,
    gzip_http_version: '1.1',
    gzip_min_length_bytes: 1_024,
    gzip_vary: true,
    server_addr_outgoing: false,
    proxy_request_buffering: true,
    proxy_buffering: true,
    proxy_cache_min_free_bytes: 5_368_709_120,
    proxy_cache_max_size_bytes: 107_374_182_400,
    proxy_cache_methods: ['GET', 'HEAD'],
    proxy_http_version: '1.1',
    proxy_max_temp_file_size_bytes: 1_073_741_824,
    proxy_next_upstream: ['error', 'timeout', 'invalid_header', 'http_500', 'http_502', 'http_503', 'http_504'],
    proxy_connect_timeout_ms: 5_000,
    proxy_send_timeout_ms: 60_000,
    proxy_read_timeout_ms: 60_000,
    client_body_buffer_size_bytes: 16_384,
    server: 'CDNCA',
    client_max_body_size_bytes: 104_857_600,
    default_type: 'text/plain',
    keepalive_requests: 1_000,
    keepalive_timeout_ms: 75_000,
    log_not_found: false,
    server_tokens: false,
    large_client_header_buffers: { count: 4, size_bytes: 8_192 },
    server_names_hash_max_size: 4_096,
    server_names_hash_bucket_size: 64,
  },
  stream: {
    proxy_connect_timeout_ms: 5_000,
    proxy_timeout_ms: 300_000,
  },
  overrides: [{
    id: 'region01',
    scope: 'region',
    scope_id: 'east',
    values: { http: { proxy_read_timeout_ms: 90_000 } },
  }],
}

const document: SystemConfigurationDocument<'nginx'> = {
  schema: 'cdnca.system-configuration/v2',
  category: 'nginx',
  head_revision: 2,
  active_revision: 1,
  revision: 2,
  status: 'draft',
  snapshot_sha256: 'a'.repeat(64),
  pending_categories: ['nginx'],
  value: nginx,
}

function jsonResponse(value: unknown, status = 200, etag = '"2"'): Promise<Response> {
  return Promise.resolve(new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json', ETag: etag },
  }))
}

describe('systemConfigurationApi', () => {
  it('gets an exact category path with the access token and validates ETag', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(() => jsonResponse(document))

    await expect(systemConfigurationApi.get('access-token', 'nginx')).resolves.toEqual(document)

    const [url, init] = fetch.mock.calls[0]!
    expect(url).toBe('/v1/admin/system-configuration/categories/nginx')
    expect(init?.credentials).toBe('include')
    expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer access-token')
    expect(init?.method).toBeUndefined()
  })

  it('puts the exact body with quoted CAS and caller-owned request metadata', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(() => jsonResponse(document))

    await systemConfigurationApi.put(
      'access-token',
      'nginx',
      nginx,
      2,
      'save-nginx-1',
      'system-configuration-nginx-request-1',
    )

    const [url, init] = fetch.mock.calls[0]!
    expect(url).toBe('/v1/admin/system-configuration/categories/nginx')
    expect(init?.method).toBe('PUT')
    expect(init?.credentials).toBe('include')
    const headers = new Headers(init?.headers)
    expect(headers.get('Authorization')).toBe('Bearer access-token')
    expect(headers.get('Content-Type')).toBe('application/json')
    expect(headers.get('Idempotency-Key')).toBe('save-nginx-1')
    expect(headers.get('X-Request-ID')).toBe('system-configuration-nginx-request-1')
    expect(headers.get('If-Match')).toBe('"2"')
    expect(init?.body).toBe(JSON.stringify({ value: nginx }))
  })

  it('rejects legacy flat values, missing or extra nested fields, category drift, unsafe secrets, and stale ETags', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch')
    fetch.mockImplementationOnce(() => jsonResponse({
      ...document,
      value: { worker_processes: 4, worker_connections: 4_096 },
    }))
    await expect(systemConfigurationApi.get('token', 'nginx')).rejects.toMatchObject({ code: 'invalid_response' })

    const missingStream = { worker: nginx.worker, http: nginx.http, overrides: nginx.overrides }
    fetch.mockImplementationOnce(() => jsonResponse({ ...document, value: missingStream }))
    await expect(systemConfigurationApi.get('token', 'nginx')).rejects.toMatchObject({ code: 'invalid_response' })

    fetch.mockImplementationOnce(() => jsonResponse({
      ...document,
      value: { ...nginx, http: { ...nginx.http, resolver_timeout_ms: 5_000 } },
    }))
    await expect(systemConfigurationApi.get('token', 'nginx')).rejects.toMatchObject({ code: 'invalid_response' })

    fetch.mockImplementationOnce(() => jsonResponse({ ...document, unexpected: true }))
    await expect(systemConfigurationApi.get('token', 'nginx')).rejects.toMatchObject({ code: 'invalid_response' })

    fetch.mockImplementationOnce(() => jsonResponse({ ...document, category: 'resources' }))
    await expect(systemConfigurationApi.get('token', 'nginx')).rejects.toMatchObject({ code: 'invalid_response' })

    fetch.mockImplementationOnce(() => jsonResponse({
      ...document,
      category: 'secrets',
      value: {
        error_page_storage: {
          provider: 'vault',
          reference: 'unmasked/reference',
          key_id: 'key-1',
          algorithm: 'aes-256-gcm',
          ciphertext_sha256: 'b'.repeat(64),
          masked: false,
        },
      },
    }))
    await expect(systemConfigurationApi.get('token', 'secrets')).rejects.toMatchObject({ code: 'invalid_response' })

    fetch.mockImplementationOnce(() => jsonResponse(document, 200, '"1"'))
    await expect(systemConfigurationApi.get('token', 'nginx')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('never exposes a server error message to consumers', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => jsonResponse({
      error: { code: 'system_configuration_permission_denied', message: 'private SQL and credential detail', request_id: 'safe-request-1' },
    }, 403, ''))

    const error = await systemConfigurationApi.get('token', 'nginx').catch((reason: unknown) => reason)

    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status: 403, code: 'system_configuration_permission_denied', requestId: 'safe-request-1' })
    expect((error as Error).message).not.toContain('private SQL')
  })

  it('rejects invalid CAS metadata before issuing a request', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch')

    await expect(systemConfigurationApi.put('token', 'nginx', nginx, -1, 'valid-key', 'valid-request'))
      .rejects.toMatchObject({ code: 'validation_error' })
    await expect(systemConfigurationApi.put('token', 'nginx', nginx, 2, 'contains spaces', 'valid-request'))
      .rejects.toMatchObject({ code: 'validation_error' })
    await expect(systemConfigurationApi.put('token', 'nginx', nginx, 2, 'valid-key', 'contains spaces'))
      .rejects.toMatchObject({ code: 'validation_error' })
    expect(fetch).not.toHaveBeenCalled()
  })
})
