import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom'
import { vi } from 'vitest'

import { ApiError, type Principal } from '../api/auth'
import { nodesApi, regionsApi } from '../api/nodes'
import { securityPoliciesApi } from '../api/securityPolicies'
import {
  systemConfigurationApi,
  type DefaultConfiguration,
  type NginxConfiguration,
  type ResourceConfiguration,
  type SystemConfigurationDocument,
} from '../api/systemConfiguration'
import { useSessionStore } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import SystemSettingsPage from '../pages/SystemSettingsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

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

const defaults: DefaultConfiguration = {
  website: {
    http: { listen_ports: [80] },
    https: {
      listen_ports: [443], hsts_enabled: false, http2_enabled: false, http3_enabled: false, force_https: false,
      ssl: {
        mode: 'recommended', protocols: ['TLSv1.2', 'TLSv1.3'],
        cipher_suites: 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256',
        prefer_server_ciphers: false,
      },
      ocsp_stapling_enabled: true,
    },
    origin: {
      scheme: 'http', http_port: 80, https_port: 443, response_timeout_seconds: 60, connect_timeout_seconds: 10,
      ssl_protocols: ['TLSv1', 'TLSv1.1', 'TLSv1.2'], http_version: '1.1', keepalive_enabled: true,
      post_body_limit_bytes: 104_857_600,
    },
    cache_rules: [{
      id: 'cache001', match: 'suffix', content: '.css', ttl_seconds: 86_400, ignore_query: true,
      force_cache: false, range: true, ignore_vary: false,
      no_cache: [{ variable: '$http_cookie', string: 'session=' }], enabled: true, position: 0,
    }],
    origin_request_headers: [{
      id: 'header01', name: 'X-CDN-Origin', value: '', action: 'set', allow_duplicate: false, enabled: true, position: 0,
    }],
    access_log: {
      capture_request_headers: true, capture_response_headers: false, capture_request_body: false, request_body_limit_kb: 16,
    },
    security: {
      default_cc_policy_id: null, waf_enabled: false,
      waf_auto_block: { enabled: false, window_seconds: 60, hit_threshold: 20, block_seconds: 600 },
      waf_modules: {
        sqli: 'off', xss: 'off', upload: 'off', fi: 'off', cmdi: 'off', java: 'off', jdeser: 'off', php: 'off', phpdeser: 'off', ssti: 'off',
      },
    },
    other: {
      load_balancing: 'round_robin', gzip_enabled: true,
      gzip_types: ['application/json', 'text/css', 'text/plain'], websocket_enabled: false,
    },
  },
  stream: { protocol: 'tcp', load_balancing: 'round_robin', proxy_protocol_enabled: false },
  certificate: { issuer: 'lets_encrypt' },
  overrides: [{ id: 'default1', scope: 'region', scope_id: 'east', values: { website: { other: { load_balancing: 'round_robin', gzip_enabled: false, gzip_types: [], websocket_enabled: false } } } }],
}

const resources: ResourceConfiguration = {
  site: {
    related_config_min_limit: 1_000, related_config_max_times_limit: 200, black_ip_limit: 50, white_ip_limit: 50,
    daily_clean_url_limit: 2_000, daily_clean_dir_limit: 500, daily_pre_cache_url_limit: 2_000,
    daily_ip_unlock_limit: 1_000, ip_unlock_per_request_limit: 50, cc_rule_max_limit: 5,
    max_domains_per_site: 100, listen_default_http_80: true, daily_access_log_download_limit: 10,
    access_log_tmp_dir: '/data/download-temp/', access_log_retain_hours: 12,
  },
  stream: {
    custom_port_not_allow: [{ from: 1, to: 79 }], related_config_min_limit: 10,
    related_config_max_times_limit: 10, acl_max_limit: 1_000,
  },
  site_stream: {
    custom_port_not_allow: [{ from: 1, to: 79 }], custom_port_allow: [{ from: 8_080, to: 8_090 }],
  },
  overrides: [],
}

function nginxDocument(headRevision = 2, value: NginxConfiguration = nginx): SystemConfigurationDocument<'nginx'> {
  return {
    schema: 'cdnca.system-configuration/v2', category: 'nginx', head_revision: headRevision,
    active_revision: 1, revision: headRevision, status: 'draft', snapshot_sha256: 'a'.repeat(64), pending_categories: [], value,
  }
}

function resourcesDocument(headRevision = 2): SystemConfigurationDocument<'resources'> {
  return {
    ...nginxDocument(headRevision), category: 'resources', value: resources,
  }
}

function defaultsDocument(headRevision = 2, value: DefaultConfiguration = defaults): SystemConfigurationDocument<'defaults'> {
  return {
    ...nginxDocument(headRevision), category: 'defaults', value,
  }
}

function authenticate(permissions = ['system_configuration.read', 'system_configuration.manage']) {
  const actor = principal({
    scope_kind: 'platform',
    tenant_id: null,
    roles: ['platform_owner'],
    permissions,
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}



function systemPrincipal(overrides: Partial<Principal> = {}): Principal {
  return principal({
    user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    scope_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    scope_kind: 'platform',
    tenant_id: null,
    username: 'platform-a',
    display_name: 'Platform A',
    roles: ['platform_admin'],
    permissions: ['system_configuration.read', 'system_configuration.manage'],
    ...overrides,
  })
}

function setSystemSession(
  actor: Principal,
  accessToken: string,
  update: 'new' | 'refresh' = 'new',
): number {
  useSessionStore.getState().setSession(
    { ...authResponse(actor), access_token: accessToken },
    actor,
    update,
  )
  return useSessionStore.getState().sessionEpoch
}

function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: Infinity },
      mutations: { retry: false },
    },
  })
}

function renderSettings(queryClient: QueryClient, initialCategory: 'nginx' | 'resources' | 'defaults' = 'nginx') {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter>
            <SystemSettingsPage initialCategory={initialCategory} />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

function configurationKey(
  actor: Principal,
  sessionEpoch: number,
  category: 'nginx' | 'resources' | 'defaults',
) {
  return [
    'system-configuration',
    actor.scope_kind,
    actor.scope_id,
    actor.tenant_id,
    actor.user_id,
    sessionEpoch,
    category,
  ] as const
}


function serializedConfigurationCaches(queryClient: QueryClient): string {
  const serializedError = (error: unknown) => error instanceof Error
    ? {
        ...error,
        name: error.name,
        message: error.message,
      }
    : error
  return JSON.stringify({
    queries: queryClient.getQueryCache().getAll().map((query) => ({
      key: query.queryKey,
      options: {
        queryKey: query.options.queryKey,
        meta: query.options.meta,
      },
      state: { ...query.state, error: serializedError(query.state.error) },
    })),
    mutations: queryClient.getMutationCache().getAll().map((mutation) => ({
      key: mutation.options.mutationKey,
      options: {
        mutationKey: mutation.options.mutationKey,
        meta: mutation.options.meta,
        scope: mutation.options.scope,
      },
      variables: mutation.state.variables,
      state: { ...mutation.state, error: serializedError(mutation.state.error) },
    })),
  })
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

describe('SystemSettingsPage', () => {
  it('fails closed before reading for a non-platform or unprivileged session', () => {
    authenticate([])
    const get = vi.spyOn(systemConfigurationApi, 'get')

    renderWithProviders(<SystemSettingsPage />)

    expect(screen.getByText('无权访问系统配置')).toBeInTheDocument()
    expect(get).not.toHaveBeenCalled()
  })

  it('renders the observed Nginx route structure from the nested v2 document', async () => {
    authenticate()
    const pending = deferred<SystemConfigurationDocument<'nginx'>>()
    vi.spyOn(systemConfigurationApi, 'get').mockReturnValue(pending.promise)

    renderWithProviders(<SystemSettingsPage />)

    expect(screen.getByLabelText('正在加载系统配置')).toBeInTheDocument()
    await act(async () => pending.resolve(nginxDocument()))

    expect(await screen.findByRole('tab', { name: '全局配置' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: '区域及节点配置' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Worker' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: 'Http' })).toBeInTheDocument()
    // 日志目录与 Stream 超时不下发到节点，界面不再提供
    expect(screen.queryByRole('tab', { name: 'Stream' })).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: '日志目录' })).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Worker 运行参数' })).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'worker_processes' })).toHaveValue('4')
    expect(screen.queryByText('系统配置')).not.toBeInTheDocument()
    expect(screen.queryByText(/头版本/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '刷新' })).not.toBeInTheDocument()
  })

  it('shows a banner when the shared head carries other categories that are not active yet', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue({
      ...nginxDocument(), pending_categories: ['nginx', 'node_monitoring', 'ddos_protection'],
    })

    renderWithProviders(<SystemSettingsPage />)

    const notice = await screen.findByTestId('pending-categories-notice')
    expect(notice).toHaveTextContent('一并生效：节点监控、连接防护')
    expect(screen.getByText('去查看：节点监控')).toBeInTheDocument()
    expect(screen.getByText('去查看：连接防护')).toBeInTheDocument()
  })

  it('shows no pending banner when only the current category is pending', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue({ ...nginxDocument(), pending_categories: ['nginx'] })

    renderWithProviders(<SystemSettingsPage />)

    expect(await screen.findByRole('tab', { name: '全局配置' })).toBeInTheDocument()
    expect(screen.queryByTestId('pending-categories-notice')).not.toBeInTheDocument()
  })

  it('loads only the route-selected category and renders its own secondary tabs', async () => {
    authenticate()
    const get = vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(resourcesDocument())

    renderWithProviders(<SystemSettingsPage initialCategory="resources" />)

    expect(await screen.findByRole('heading', { name: '网站资源限制' })).toBeInTheDocument()
    expect(get).toHaveBeenCalledWith('memory-only-access-token', 'resources')
    expect(get).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('tab', { name: '网站' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: '转发' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '公共' })).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Nginx' })).not.toBeInTheDocument()
    expect(screen.queryByText('充值实名策略')).not.toBeInTheDocument()
  })

  it('renders the public resource port limits and saves edited ranges', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(resourcesDocument())
    const put = vi.spyOn(systemConfigurationApi, 'put').mockResolvedValue(resourcesDocument(3))
    const user = userEvent.setup()

    renderWithProviders(<SystemSettingsPage initialCategory="resources" />)

    await user.click(await screen.findByRole('tab', { name: '公共' }))
    // 资源配置没有可按节点生效的项：不提供区域配置
    expect(screen.queryByRole('tab', { name: '区域配置' })).not.toBeInTheDocument()
    const denied = screen.getByRole('textbox', { name: '禁止使用的自定义端口' })
    const allowed = screen.getByRole('textbox', { name: '允许使用的自定义端口' })
    expect(denied).toHaveValue('1-79')
    expect(allowed).toHaveValue('8080-8090')

    await user.clear(denied)
    await user.type(denied, '1000-1002, 900')
    await user.tab()
    await user.clear(allowed)
    await user.type(allowed, '8080-8090')
    await user.tab()
    await user.click(screen.getByRole('button', { name: '保存' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0]?.[2]).toEqual(expect.objectContaining({
      site_stream: {
        custom_port_not_allow: [{ from: 900, to: 900 }, { from: 1000, to: 1002 }],
        custom_port_allow: [{ from: 8080, to: 8090 }],
      },
    }))
  })

  describe('SystemSettingsPageResourceBounds', () => {
    const bounds = [
      { tab: '网站', section: 'site', field: 'ip_unlock_per_request_limit', label: '每次解锁 IP 个数', maximum: 100_000 },
      { tab: '网站', section: 'site', field: 'max_domains_per_site', label: '单站最大域名数', maximum: 100 },
      { tab: '网站', section: 'site', field: 'access_log_retain_hours', label: '日志文件存放时长', maximum: 720 },
      { tab: '转发', section: 'stream', field: 'related_config_max_times_limit', label: '相关配置最大倍数', maximum: 100 },
    ] as const

    it.each(bounds)('sends the exact legal maximum for $label through the API client', async ({ tab, section, field, label, maximum }) => {
      authenticate()
      const value = { ...resources, [section]: { ...resources[section], [field]: maximum } }
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
        const revision = init?.method === 'PUT' ? 3 : 2
        return new Response(JSON.stringify({
          ...resourcesDocument(revision), value: revision === 3 ? value : resources,
        }), { status: 200, headers: { ETag: `"${revision}"` } })
      })
      const user = userEvent.setup()
      renderWithProviders(<SystemSettingsPage initialCategory="resources" />)

      await user.click(await screen.findByRole('tab', { name: tab }))
      const input = screen.getByRole('spinbutton', { name: label })
      await user.clear(input)
      await user.type(input, String(maximum))
      await user.click(screen.getByRole('button', { name: '保存' }))

      await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1))
      const [url, init] = fetchSpy.mock.calls.find(([, request]) => request?.method === 'PUT')!
      expect(url).toBe('/v1/admin/system-configuration/categories/resources')
      expect(JSON.parse(String(init?.body))).toEqual({ value })
      expect(new Headers(init?.headers).get('If-Match')).toBe('"2"')
      expect(new Headers(init?.headers).get('Idempotency-Key')).toMatch(/^system-configuration-resources-/)
      expect(await screen.findByText('系统配置已保存为新草稿')).toBeInTheDocument()
      expect(input).toHaveValue(String(maximum))
    })

    it.each(bounds)('rejects maximum plus one for $label without sending or clamping it', async ({ tab, section, field, label, maximum }) => {
      authenticate()
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
        const revision = init?.method === 'PUT' ? 3 : 2
        return new Response(JSON.stringify(resourcesDocument(revision)), {
          status: 200, headers: { ETag: `"${revision}"` },
        })
      })
      const user = userEvent.setup()
      renderWithProviders(<SystemSettingsPage initialCategory="resources" />)

      await user.click(await screen.findByRole('tab', { name: tab }))
      const input = screen.getByRole('spinbutton', { name: label })
      await user.clear(input)
      await user.type(input, String(maximum + 1))
      await user.click(screen.getByRole('button', { name: '保存' }))

      const writes = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')
      expect(writes.map(([, init]) => JSON.parse(String(init?.body)).value[section][field])).toEqual([])
      await waitFor(() => expect(input.closest('.ant-form-item')?.querySelector('.ant-form-item-explain-error'))
        .toHaveTextContent(i18n.t('validation.integerRange', { ns: 'systemSettings', minimum: 1, maximum })))
      expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(0)
      expect(input).toHaveValue(String(maximum + 1))
    })

    it('preserves the existing clamp behavior for other number fields', async () => {
      authenticate()
      vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(resourcesDocument())
      const user = userEvent.setup()
      renderWithProviders(<SystemSettingsPage initialCategory="resources" />)

      const input = await screen.findByRole('spinbutton', { name: '相关配置最大倍数' })
      await user.clear(input)
      await user.type(input, '1001')
      await user.tab()

      expect(input).toHaveValue('1000')
    })
  })

  it('allows a read-only session to inspect configuration without exposing a save action', async () => {
    authenticate(['system_configuration.read'])
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(nginxDocument())
    const put = vi.spyOn(systemConfigurationApi, 'put')

    renderWithProviders(<SystemSettingsPage />)

    expect(await screen.findByText('只读模式')).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'worker_processes' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: '保存' })).not.toBeInTheDocument()
    expect(put).not.toHaveBeenCalled()
  })

  it('saves the exact nested category with CAS and request metadata after a real edit', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(nginxDocument())
    const put = vi.spyOn(systemConfigurationApi, 'put').mockResolvedValue(nginxDocument(3, {
      ...nginx,
      worker: { ...nginx.worker, worker_processes: 6 },
    }))
    const user = userEvent.setup()

    renderWithProviders(<SystemSettingsPage />)

    const workers = await screen.findByRole('textbox', { name: 'worker_processes' })
    await user.clear(workers)
    await user.type(workers, '6')
    await user.click(screen.getByRole('button', { name: '保存' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put).toHaveBeenCalledWith(
      'memory-only-access-token',
      'nginx',
      expect.objectContaining({
        worker: expect.objectContaining({ worker_processes: 6 }),
        http: expect.objectContaining({ proxy_cache_methods: ['GET', 'HEAD'] }),
        stream: nginx.stream,
        overrides: nginx.overrides,
      }),
      2,
      expect.stringMatching(/^system-configuration-nginx-/),
      expect.stringMatching(/^system-configuration-nginx-request-/),
    )
    expect(await screen.findByText('系统配置已保存为新草稿')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '保存' })).not.toBeInTheDocument()
  })

  it('exposes all supported default load balancing modes on website and stream tabs', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(defaultsDocument())
    const user = userEvent.setup()

    renderWithProviders(<SystemSettingsPage initialCategory="defaults" />)

    const websiteLabels = ['轮循', '定源', 'URL 哈希', '最少连接', '随机']
    for (const label of websiteLabels) expect(await screen.findByRole('radio', { name: label })).toBeInTheDocument()

    await user.click(await screen.findByRole('tab', { name: '转发' }))
    expect(screen.getByRole('radio', { name: '轮循' })).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: '定源' })).toBeInTheDocument()
    expect(screen.queryByRole('radio', { name: 'URL 哈希' })).not.toBeInTheDocument()
    expect(screen.queryByRole('radio', { name: '最少连接' })).not.toBeInTheDocument()
    expect(screen.queryByRole('radio', { name: '随机' })).not.toBeInTheDocument()
  })

  it('accepts a nullable default CC policy while preserving a valid v2 header action', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(defaultsDocument())
    const put = vi.spyOn(systemConfigurationApi, 'put').mockResolvedValue(defaultsDocument(3))
    const user = userEvent.setup()

    renderWithProviders(<SystemSettingsPage initialCategory="defaults" />)

    await user.click(await screen.findByRole('switch', { name: '开启HTTP2' }))
    await user.click(screen.getByRole('button', { name: '保存' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0]?.[2]).toEqual(expect.objectContaining({
      website: expect.objectContaining({
        https: expect.objectContaining({ http2_enabled: true }),
        security: expect.objectContaining({ default_cc_policy_id: null }),
        origin_request_headers: [expect.objectContaining({ value: '', action: 'set', position: 0 })],
      }),
    }))
  })

  it('reindexes cache and header rules after remove/add and normalizes delete header values', async () => {
    authenticate()
    const value = structuredClone(defaults)
    value.website.cache_rules = [
      { ...value.website.cache_rules[0], id: 'cache001', position: 0 },
      { ...value.website.cache_rules[0], id: 'cache002', content: '.js', position: 1 },
      { ...value.website.cache_rules[0], id: 'cache003', content: '.png', position: 2 },
    ]
    value.website.origin_request_headers = [
      { ...value.website.origin_request_headers[0], id: 'header01', value: 'first', position: 0 },
      { ...value.website.origin_request_headers[0], id: 'header02', value: 'second', position: 1 },
      { ...value.website.origin_request_headers[0], id: 'header03', value: 'third', position: 2 },
    ]
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(defaultsDocument(2, value))
    const put = vi.spyOn(systemConfigurationApi, 'put').mockResolvedValue(defaultsDocument(3, value))
    const user = userEvent.setup()

    renderWithProviders(<SystemSettingsPage initialCategory="defaults" />)

    const cacheCard = (await screen.findByRole('heading', { name: '缓存' })).closest('section')!
    await user.click(within(cacheCard).getAllByRole('button', { name: '删除' })[1])
    await user.click(within(cacheCard).getByRole('button', { name: '快速设置缓存' }))
    await user.click(await screen.findByRole('menuitem', { name: '静态资源缓存一天' }))

    const headerCard = screen.getByRole('heading', { name: '源站请求头' }).closest('section')!
    await user.click(within(headerCard).getAllByRole('button', { name: '删除' })[1])
    await user.click(within(headerCard).getByRole('button', { name: '新增请求头' }))
    await user.click(within(headerCard).getAllByRole('combobox', { name: '动作' })[0])
    await user.click(await screen.findByText('删除', { selector: '.ant-select-item-option-content' }))
    await user.click(screen.getByRole('button', { name: '保存' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const written = put.mock.calls[0]?.[2] as DefaultConfiguration
    expect(written.website.cache_rules.map((rule) => rule.position)).toEqual([0, 1, 2])
    expect(written.website.cache_rules[2]).toEqual(expect.objectContaining({
      content: '.css .js .jpg .jpeg .png .gif .svg .webp .woff .woff2',
      ttl_seconds: 86_400,
      position: 2,
    }))
    expect(written.website.origin_request_headers.map((header) => header.position)).toEqual([0, 1, 2])
    expect(written.website.origin_request_headers[0]).toEqual(expect.objectContaining({ action: 'delete', value: null }))
    expect(written.website.origin_request_headers[2]).toEqual(expect.objectContaining({ action: 'set', value: '', position: 2 }))
  })

  it('serializes every cache/header schema field and restores them from the saved document', async () => {
    authenticate()
    const value = structuredClone(defaults)
    value.website.cache_rules = [{
      ...value.website.cache_rules[0], content: null, ignore_query: false, force_cache: false,
      range: false, ignore_vary: false, no_cache: [], enabled: true, position: 0,
    }]
    value.website.origin_request_headers = [{
      ...value.website.origin_request_headers[0], value: '', allow_duplicate: false, enabled: true, position: 0,
    }]
    const get = vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(defaultsDocument(2, value))
    let saved: DefaultConfiguration | undefined
    const put = vi.spyOn(systemConfigurationApi, 'put').mockImplementation(async (_token, _category, next) => {
      saved = structuredClone(next as DefaultConfiguration)
      return defaultsDocument(3, saved)
    })
    const user = userEvent.setup()

    const rendered = renderWithProviders(<SystemSettingsPage initialCategory="defaults" />)
    const cacheCard = (await screen.findByRole('heading', { name: '缓存' })).closest('section')!
    await user.type(within(cacheCard).getByRole('textbox', { name: '匹配内容' }), '/assets/')
    await user.click(within(cacheCard).getByRole('switch', { name: '忽略查询参数' }))
    await user.click(within(cacheCard).getByRole('switch', { name: '强制缓存' }))
    await user.click(within(cacheCard).getByRole('switch', { name: '支持 Range' }))
    await user.click(within(cacheCard).getByRole('switch', { name: '忽略 Vary' }))
    await user.click(within(cacheCard).getByRole('button', { name: '新增不缓存条件' }))
    await user.type(within(cacheCard).getByRole('textbox', { name: '变量' }), '$http_cookie')
    await user.type(within(cacheCard).getByRole('textbox', { name: '匹配字符串' }), 'session=')

    const headerCard = screen.getByRole('heading', { name: '源站请求头' }).closest('section')!
    await user.type(within(headerCard).getByRole('textbox', { name: '请求头值' }), 'origin.example')
    await user.click(within(headerCard).getByRole('switch', { name: '允许重复请求头' }))
    await user.click(screen.getByRole('button', { name: '保存' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(saved?.website.cache_rules[0]).toEqual(expect.objectContaining({
      content: '/assets/', ignore_query: true, force_cache: true, range: true, ignore_vary: true,
      no_cache: [{ variable: '$http_cookie', string: 'session=' }], enabled: true, position: 0,
    }))
    expect(saved?.website.origin_request_headers[0]).toEqual(expect.objectContaining({
      value: 'origin.example', allow_duplicate: true, enabled: true, position: 0,
    }))

    rendered.unmount()
    get.mockResolvedValue(defaultsDocument(3, saved!))
    renderWithProviders(<SystemSettingsPage initialCategory="defaults" />)
    const restoredCacheCard = (await screen.findByRole('heading', { name: '缓存' })).closest('section')!
    expect(within(restoredCacheCard).getByRole('textbox', { name: '匹配内容' })).toHaveValue('/assets/')
    expect(within(restoredCacheCard).getByRole('switch', { name: '忽略查询参数' })).toBeChecked()
    expect(within(restoredCacheCard).getByRole('switch', { name: '强制缓存' })).toBeChecked()
    expect(within(restoredCacheCard).getByRole('switch', { name: '支持 Range' })).toBeChecked()
    expect(within(restoredCacheCard).getByRole('switch', { name: '忽略 Vary' })).toBeChecked()
    expect(within(restoredCacheCard).getByRole('textbox', { name: '变量' })).toHaveValue('$http_cookie')
    const restoredHeaderCard = screen.getByRole('heading', { name: '源站请求头' }).closest('section')!
    expect(within(restoredHeaderCard).getByRole('textbox', { name: '请求头值' })).toHaveValue('origin.example')
    expect(within(restoredHeaderCard).getByRole('switch', { name: '允许重复请求头' })).toBeChecked()
  })

  it('loads real CC options and applies SSL and WAF batch defaults through the visible controls', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage', 'security_policies.read'])
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(defaultsDocument())
    vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({
      items: [{
        id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
        scope_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        kind: 'cc',
        name: '登录保护',
        description: '',
        enabled: true,
        default_action: 'allow',
        rules: [],
        owner: { id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', display_name: '平台' },
        version: 1,
        created_at: '2026-09-01T00:00:00Z',
        updated_at: '2026-09-01T00:00:00Z',
      }],
      total: 1,
      page: 1,
      limit: 100,
    })
    const put = vi.spyOn(systemConfigurationApi, 'put').mockResolvedValue(defaultsDocument(3))
    const user = userEvent.setup()

    renderWithProviders(<SystemSettingsPage initialCategory="defaults" />)

    // Three presets only (new sites inherit one as their TLS
    // versions and cipher preset); no free cipher string.
    expect(screen.queryByRole('radio', { name: /自定义/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: '加密套件' })).not.toBeInTheDocument()
    await user.click(await screen.findByRole('radio', { name: /极限兼容/ }))

    const ccPolicySelect = screen.getByRole('combobox', { name: '默认CC规则' })
    fireEvent.mouseDown(ccPolicySelect)
    fireEvent.click(await screen.findByText('登录保护 · 平台', { selector: '.ant-select-item-option-content' }))
    await waitFor(() => expect(ccPolicySelect.closest('.ant-select')).toHaveTextContent('登录保护 · 平台'))
    await user.click(screen.getByRole('button', { name: '批量配置为' }))
    await user.click(await screen.findByRole('menuitem', { name: '仅观察' }))
    await user.click(screen.getByRole('button', { name: '保存' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const written = put.mock.calls[0]?.[2] as DefaultConfiguration
    expect(written.website.https.ssl).toEqual({ mode: 'legacy_full', protocols: ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'],
      cipher_suites: 'DEFAULT:@SECLEVEL=0', prefer_server_ciphers: true })
    expect(written.website.security.default_cc_policy_id).toBe('cccccccc-cccc-4ccc-8ccc-cccccccccccc')
    expect(Object.values(written.website.security.waf_modules)).toEqual(Array(10).fill('detect'))
    expect(securityPoliciesApi.list).toHaveBeenCalledWith('memory-only-access-token', {
      page: 1,
      limit: 100,
      kind: 'cc',
      status: 'enabled',
    })
  })

  it('uses button dropdowns for WAF modules and saves the selected protection mode', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(defaultsDocument())
    const put = vi.spyOn(systemConfigurationApi, 'put').mockResolvedValue(defaultsDocument(3))
    const user = userEvent.setup()

    renderWithProviders(<SystemSettingsPage initialCategory="defaults" />)

    const moduleButton = await screen.findByRole('button', { name: 'SQL 注入检测：禁用' })
    expect(screen.getByRole('spinbutton', { name: '统计窗口（秒）' })).toBeInTheDocument()
    expect(screen.getByRole('spinbutton', { name: '命中阈值（次）' })).toBeInTheDocument()
    expect(screen.getByRole('spinbutton', { name: '封禁时长（秒）' })).toBeInTheDocument()
    expect([...document.querySelectorAll('.configuration-waf-modules .ant-form-item-label label')].map((label) => label.textContent)).toEqual([
      'SQL 注入检测', 'XSS 检测', '文件上传检测', '文件包含检测', '命令注入检测',
      'JAVA 代码注入检测', 'JAVA 反序列化检测', 'PHP 代码注入检测', 'PHP 反序列化检测', 'SSTI 模板注入检测',
    ])
    expect(screen.queryByRole('combobox', { name: 'SQL 注入检测' })).not.toBeInTheDocument()
    expect(moduleButton).toHaveClass('configuration-waf-mode-button--off')
    expect(moduleButton.querySelector('.configuration-waf-mode-dot')).not.toBeInTheDocument()
    expect(moduleButton.querySelector('.configuration-waf-mode-chevron')).toBeInTheDocument()

    await user.click(moduleButton)
    await user.click(await screen.findByRole('menuitem', { name: '防护' }))

    const protectedButton = screen.getByRole('button', { name: 'SQL 注入检测：防护' })
    expect(protectedButton).toHaveClass('configuration-waf-mode-button--on')
    await user.click(screen.getByRole('button', { name: '保存' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const written = put.mock.calls[0]?.[2] as DefaultConfiguration
    expect(written.website.security.waf_modules.sqli).toBe('on')
    expect(written.website.security.waf_modules.xss).toBe('off')
  })

  it('covers the regional, forwarding, and certificate secondary tabs with add/delete interactions', async () => {
    authenticate()
    const value = structuredClone(defaults)
    value.overrides = []
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(defaultsDocument(2, value))
    // 区域来自区域目录（nginx-region：不再允许手填任意文本）
    vi.spyOn(regionsApi, 'list').mockResolvedValue({ count: 1, data: [{ id: '7', name: 'east', code: 'east', country_code: '', province_code: '', description: '', l2_check_port: 80, sort: 1, revision: 1, created_at: '', updated_at: '' }] })
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [] })
    const user = userEvent.setup()

    renderWithProviders(<SystemSettingsPage initialCategory="defaults" />)

    await user.click(await screen.findByRole('tab', { name: '区域配置' }))
    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '新增设置' }))
    const region = await screen.findByRole('combobox', { name: '区域选择' })
    fireEvent.mouseDown(region)
    await user.click(await screen.findByText('east', { selector: '.ant-select-item-option-content' }))
    const setting = screen.getByRole('combobox', { name: '设置项' })
    fireEvent.mouseDown(setting)
    // 区域覆盖只有节点渲染的 GZIP 两项；建站时取值的项不出现
    // 区域下拉的弹层仍在文档里，取最后打开的「设置项」弹层
    const settingOptions = () => Array.from(Array.from(document.querySelectorAll('.configuration-select-popup')).at(-1)
      ?.querySelectorAll('.ant-select-item-option-content') ?? []).map((item) => item.textContent)
    await waitFor(() => expect(settingOptions()).toEqual(['开启Gzip', 'Gzip 压缩类型']))
    for (const removed of ['HTTP监听端口', 'HTTPS监听端口', '开启HSTS', '回源协议', '默认证书类型', '默认CC规则', '转发监听协议']) {
      expect(screen.queryByText(removed, { selector: '.ant-select-item-option-content' })).not.toBeInTheDocument()
    }
    await user.click(await screen.findByText('Gzip 压缩类型', { selector: '.ant-select-item-option-content' }))
    expect(screen.getByRole('textbox', { name: 'Gzip 压缩类型' })).toHaveValue('application/json text/css text/plain')
    expect(Array.from(document.querySelectorAll('.configuration-override-modal .ant-modal-footer .ant-btn')).map((button) => button.textContent?.trim()))
      .toEqual(['取消', '确定'])
    await user.click(screen.getByRole('button', { name: '确定' }))
    expect(await screen.findByText('east')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '删除' }))
    await user.click(await screen.findByRole('button', { name: '确定' }))
    expect(await screen.findByText('暂无数据')).toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: '全局配置' }))
    await user.click(screen.getByRole('tab', { name: '转发' }))
    expect(screen.getByRole('radio', { name: 'TCP' })).toBeChecked()
    await user.click(screen.getByRole('radio', { name: 'UDP' }))
    expect(screen.getByRole('radio', { name: 'UDP' })).toBeChecked()

    await user.click(screen.getByRole('tab', { name: '证书' }))
    expect(screen.getByRole('radio', { name: "Let's Encrypt" })).toBeChecked()
    await user.click(screen.getByRole('radio', { name: 'ZeroSSL' }))
    expect(screen.getByRole('radio', { name: 'ZeroSSL' })).toBeChecked()
    // Google Trust Services is an issuer too (needs EAB).
    expect(screen.getByRole('radio', { name: 'Google Trust Services' })).toBeInTheDocument()
  })

  it('distinguishes empty, generic error, and server-side 403 states without leaking messages', async () => {
    authenticate()
    const get = vi.spyOn(systemConfigurationApi, 'get')
      .mockRejectedValueOnce(new ApiError('private missing detail', 404, 'active_not_found'))

    const first = renderWithProviders(<SystemSettingsPage />)
    expect(await screen.findByText('暂无此类配置')).toBeInTheDocument()
    expect(screen.queryByText(/private missing/)).not.toBeInTheDocument()
    first.unmount()

    get.mockRejectedValueOnce(new ApiError('private database detail', 500, 'internal_error', 'safe-request'))
    const second = renderWithProviders(<SystemSettingsPage />)
    expect(await screen.findByText('系统配置加载失败')).toBeInTheDocument()
    expect(screen.getByText('系统配置服务暂不可用')).toBeInTheDocument()
    expect(screen.getByText('请求 ID：safe-request')).toBeInTheDocument()
    expect(screen.queryByText(/private database/)).not.toBeInTheDocument()
    second.unmount()

    get.mockRejectedValueOnce(new ApiError('private policy detail', 403, 'system_configuration_permission_denied'))
    renderWithProviders(<SystemSettingsPage />)
    expect(await screen.findByText('无权访问系统配置')).toBeInTheDocument()
    expect(screen.queryByText(/private policy/)).not.toBeInTheDocument()
  })

  it('shows a retryable load error after one failed request', async () => {
    authenticate()
    const get = vi.spyOn(systemConfigurationApi, 'get').mockRejectedValue(
      new ApiError('private upstream detail', 503, 'system_configuration_unavailable'),
    )
    const queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: true, gcTime: Infinity },
        mutations: { retry: false },
      },
    })

    renderSettings(queryClient)

    expect(await screen.findByText('系统配置加载失败')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重试' })).toBeInTheDocument()
    expect(get).toHaveBeenCalledTimes(1)
  })

  it('refreshes a confirmed conflict and requires a fresh revision and idempotency key', async () => {
    authenticate()
    const refreshed = nginxDocument(3, { ...nginx, worker: { ...nginx.worker, worker_processes: 7 } })
    const saved = nginxDocument(4, { ...nginx, worker: { ...nginx.worker, worker_processes: 8 } })
    const get = vi.spyOn(systemConfigurationApi, 'get')
      .mockResolvedValueOnce(nginxDocument(2))
      .mockResolvedValueOnce(refreshed)
    const put = vi.spyOn(systemConfigurationApi, 'put')
      .mockRejectedValueOnce(new ApiError('private conflict', 409, 'system_configuration_revision_conflict'))
      .mockResolvedValueOnce(saved)
    const user = userEvent.setup()

    renderWithProviders(<SystemSettingsPage />)

    const workers = await screen.findByRole('textbox', { name: 'worker_processes' })
    await user.clear(workers)
    await user.type(workers, '6')
    await user.click(screen.getByRole('button', { name: '保存' }))
    expect(await screen.findByText('配置已被其他管理员更新，已刷新最新版本')).toBeInTheDocument()
    expect(await screen.findByRole('textbox', { name: 'worker_processes' })).toHaveValue('7')

    await user.clear(screen.getByRole('textbox', { name: 'worker_processes' }))
    await user.type(screen.getByRole('textbox', { name: 'worker_processes' }), '8')
    await user.click(screen.getByRole('button', { name: '保存' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(2))
    expect(put.mock.calls[0]?.[3]).toBe(2)
    expect(put.mock.calls[1]?.[3]).toBe(3)
    expect(put.mock.calls[0]?.[4]).not.toBe(put.mock.calls[1]?.[4])
    expect(get).toHaveBeenCalledTimes(2)
  })

  it('retries a network-unknown save with the exact request ID, idempotency key, CAS, and body', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(nginxDocument())
    const put = vi.spyOn(systemConfigurationApi, 'put')
      .mockRejectedValueOnce(new ApiError('network detail', 0, 'network_error'))
      .mockResolvedValueOnce(nginxDocument(3))
    const user = userEvent.setup()

    renderWithProviders(<SystemSettingsPage />)

    const workers = await screen.findByRole('textbox', { name: 'worker_processes' })
    await user.clear(workers)
    await user.type(workers, '6')
    await user.click(screen.getByRole('button', { name: '保存' }))
    expect(await screen.findByText('保存结果待确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    const original = put.mock.calls[0]
    expect(original?.[2]).toEqual(expect.objectContaining({ worker: expect.objectContaining({ worker_processes: 6 }) }))
    expect(original?.[3]).toBe(2)
    expect(original?.[4]).toMatch(/^system-configuration-nginx-/)
    expect(original?.[5]).toMatch(/^system-configuration-nginx-request-/)
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(2))
    expect(put.mock.calls[1]).toEqual(original)
  })

  it('keeps pseudo-locale controls shrinkable without an overflow-producing root width', async () => {
    await changeLocale('qps-ploc')
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(nginxDocument())

    const { container } = renderWithProviders(<SystemSettingsPage />)
    const pseudoGlobal = i18n.getResource('qps-ploc', 'systemSettings', 'parity.tabs.global') as string
    const zhGlobal = i18n.getResource('zh-CN', 'systemSettings', 'parity.tabs.global') as string

    expect(pseudoGlobal).not.toBe(zhGlobal)
    expect(pseudoGlobal).toMatch(/^［.+~.+］$/)
    expect(await screen.findByRole('tab', { name: pseudoGlobal })).toBeInTheDocument()
    const page = within(container).getByTestId('system-settings-page')
    expect(page).toHaveStyle({ minWidth: 0 })
    expect(page.style.width).toBe('')
  })
})

describe('SystemSettingsPage session and cache lineage', () => {
  it.each([
    ['nginx', 'resources'],
    ['resources', 'defaults'],
    ['defaults', 'resources'],
  ] as const)('keeps the new %s → %s request subscribed during route cleanup', async (from, to) => {
    const actor = systemPrincipal()
    const epoch = setSystemSession(actor, 'configuration-navigation-token')
    const queryClient = createQueryClient()
    const documents = { nginx: nginxDocument(), resources: resourcesDocument(), defaults: defaultsDocument() }
    const pending = deferred<SystemConfigurationDocument<typeof to>>()
    vi.spyOn(systemConfigurationApi, 'get').mockImplementation((_token, category) => (
      category === to ? pending.promise : Promise.resolve(documents[from])
    ))
    render(<QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/${from}`]}>
        <Link to={`/${to}`}>切换配置</Link>
        <Routes>
          <Route path={`/${from}`} element={<SystemSettingsPage initialCategory={from} />} />
          <Route path={`/${to}`} element={<SystemSettingsPage initialCategory={to} />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>)
    await waitFor(() => expect(screen.queryByLabelText('正在加载系统配置')).not.toBeInTheDocument())

    fireEvent.click(screen.getByRole('link', { name: '切换配置' }))
    await act(async () => { await Promise.resolve() })
    expect(screen.getByLabelText('正在加载系统配置')).toBeInTheDocument()
    expect(queryClient.getQueryState(configurationKey(actor, epoch, to))?.fetchStatus).toBe('fetching')

    await act(async () => pending.resolve(documents[to]))
    await waitFor(() => expect(screen.queryByLabelText('正在加载系统配置')).not.toBeInTheDocument())
    expect(queryClient.getQueryData(configurationKey(actor, epoch, to))).toEqual(documents[to])
    expect(queryClient.getQueryData(configurationKey(actor, epoch, from))).toBeUndefined()
  })

  it.each([
    ['a tenant carrying fake platform.admin', principal({ permissions: ['platform.admin'] })],
    ['a platform manage-only principal without read', systemPrincipal({ permissions: ['system_configuration.manage'] })],
    ['a malformed platform principal bound to another tenant', systemPrincipal({
      tenant_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      permissions: ['platform.admin'],
    })],
  ])('rejects %s locally without a configuration GET', async (_case, actor) => {
    setSystemSession(actor, 'forbidden-system-token')
    const get = vi.spyOn(systemConfigurationApi, 'get')

    renderWithProviders(<SystemSettingsPage />)

    expect(await screen.findByText('无权访问系统配置')).toBeInTheDocument()
    expect(screen.getByText('权限不足')).toBeInTheDocument()
    expect(get).not.toHaveBeenCalled()
  })

  it('allows platform.admin and keys the category by full identity without storing tokens', async () => {
    const actor = systemPrincipal({ permissions: ['platform.admin'] })
    const token = 'real-platform-admin-token'
    const sessionEpoch = setSystemSession(actor, token)
    const queryClient = createQueryClient()
    const get = vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(nginxDocument())

    renderSettings(queryClient)

    expect(await screen.findByRole('heading', { name: 'Worker 运行参数' })).toBeInTheDocument()
    expect(get).toHaveBeenCalledWith(token, 'nginx')
    const key = configurationKey(actor, sessionEpoch, 'nginx')
    expect(queryClient.getQueryData(key)).toEqual(nginxDocument())
    const serialized = serializedConfigurationCaches(queryClient)
    expect(serialized).not.toContain(token)
  })

  it('uses a refreshed token for the PUT and its revision-conflict refetch without changing the epoch', async () => {
    const actor = systemPrincipal()
    const oldToken = 'system-conflict-token-a'
    const newToken = 'system-conflict-token-b'
    const sessionEpoch = setSystemSession(actor, oldToken)
    const queryClient = createQueryClient()
    const get = vi.spyOn(systemConfigurationApi, 'get')
      .mockResolvedValueOnce(nginxDocument(2))
      .mockResolvedValueOnce(nginxDocument(3, { ...nginx, worker: { ...nginx.worker, worker_processes: 7 } }))
    const put = vi.spyOn(systemConfigurationApi, 'put').mockRejectedValue(
      new ApiError('private refreshed-token conflict', 409, 'system_configuration_revision_conflict'),
    )
    const user = userEvent.setup()

    renderSettings(queryClient)
    const workers = await screen.findByRole('textbox', { name: 'worker_processes' })
    await user.clear(workers)
    await user.type(workers, '6')
    act(() => setSystemSession(actor, newToken, 'refresh'))

    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    await user.click(screen.getByRole('button', { name: '保存' }))

    expect(await screen.findByText('配置已被其他管理员更新，已刷新最新版本')).toBeInTheDocument()
    expect(await screen.findByRole('textbox', { name: 'worker_processes' })).toHaveValue('7')
    expect(put).toHaveBeenCalledWith(
      newToken,
      'nginx',
      expect.objectContaining({ worker: expect.objectContaining({ worker_processes: 6 }) }),
      2,
      expect.any(String),
      expect.any(String),
    )
    expect(get).toHaveBeenNthCalledWith(2, newToken, 'nginx')
    expect(screen.queryByText('private refreshed-token conflict')).not.toBeInTheDocument()
    const serialized = serializedConfigurationCaches(queryClient)
    expect(serialized).not.toContain(oldToken)
    expect(serialized).not.toContain(newToken)
  })

  it('drops a delayed old-session read and removes the old owner cache when another admin becomes active', async () => {
    const actorA = systemPrincipal()
    const actorB = systemPrincipal({
      user_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      scope_id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
      username: 'platform-b',
      display_name: 'Platform B',
    })
    const tokenA = 'system-delayed-get-token-a'
    const tokenB = 'system-delayed-get-token-b'
    const epochA = setSystemSession(actorA, tokenA)
    const pendingA = deferred<SystemConfigurationDocument<'nginx'>>()
    const documentB = nginxDocument(7, { ...nginx, worker: { ...nginx.worker, worker_processes: 9 } })
    const queryClient = createQueryClient()
    const get = vi.spyOn(systemConfigurationApi, 'get').mockImplementation((token) => {
      if (token === tokenA) return pendingA.promise
      if (token === tokenB) return Promise.resolve(documentB)
      throw new Error(`unexpected system token ${token}`)
    })

    renderSettings(queryClient)
    expect(screen.getByLabelText('正在加载系统配置')).toBeInTheDocument()
    act(() => setSystemSession(actorB, tokenB))
    expect(await screen.findByRole('textbox', { name: 'worker_processes' })).toHaveValue('9')

    await act(async () => pendingA.resolve(nginxDocument(9, {
      ...nginx,
      worker: { ...nginx.worker, worker_processes: 2 },
    })))

    expect(screen.getByRole('textbox', { name: 'worker_processes' })).toHaveValue('9')
    expect(queryClient.getQueryData(configurationKey(actorA, epochA, 'nginx'))).toBeUndefined()
    expect(get).toHaveBeenCalledWith(tokenB, 'nginx')
  })

  it('reconciles a known in-flight success when the same owner retains read but loses manage', async () => {
    const actor = systemPrincipal()
    const sessionEpoch = setSystemSession(actor, 'system-known-success-token-a')
    const pending = deferred<SystemConfigurationDocument<'nginx'>>()
    const queryClient = createQueryClient()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(nginxDocument())
    const put = vi.spyOn(systemConfigurationApi, 'put').mockReturnValue(pending.promise)
    const user = userEvent.setup()

    renderSettings(queryClient)
    const workers = await screen.findByRole('textbox', { name: 'worker_processes' })
    await user.clear(workers)
    await user.type(workers, '6')
    await user.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))

    act(() => setSystemSession({ ...actor, permissions: ['system_configuration.read'] }, 'system-known-success-token-b', 'refresh'))
    expect(useSessionStore.getState().sessionEpoch).toBe(sessionEpoch)
    expect(await screen.findByText('只读模式')).toBeInTheDocument()

    await act(async () => pending.resolve(nginxDocument(5, {
      ...nginx,
      worker: { ...nginx.worker, worker_processes: 6 },
    })))

    expect(screen.getByRole('textbox', { name: 'worker_processes' })).toHaveValue('6')
    expect(screen.queryByRole('button', { name: '保存' })).not.toBeInTheDocument()
    expect(put).toHaveBeenCalledTimes(1)
  })
})
