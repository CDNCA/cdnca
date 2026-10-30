import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen } from '@testing-library/react'
import type { TFunction } from 'i18next'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../../api/auth'
import {
  canonicalSiteTLSProtocolSelection,
  sitesApi,
  type PatchSiteBasicRequest,
  type SiteOriginPool,
  type SiteBasicConfig,
  type SiteDetail,
  type SiteTLSProtocol,
} from '../../api/sites'
import i18n from '../../i18n'
import '../../i18n/cnameAllocations'
import { renderWithProviders } from '../../test/render'
import BasicSiteTab from './BasicSiteTab'
import HttpsSiteTab from './HttpsSiteTab'
import { validateBasicConfig } from './siteEditValidation'

const siteID = '55555555-5555-4555-8555-555555555555'

// BasicSiteTab's edge options section reads the L2 configurations (useQuery).
function testQueryClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function basic(tlsProtocols: SiteTLSProtocol[]): SiteBasicConfig {
  return {
    package_id: null,
    package_name: null,
    group_id: null,
    group_name: null,
    domains: ['example.com'],
    http_enabled: true,
    http_listen_ports: ['80'],
    https_listen_ports: ['443'],
    ipv6_enabled: false,
    tls_protocols: tlsProtocols,
    origins: ['192.0.2.10'],
    cname: '',
    https_enabled: true,
    enabled: true,
    status: 'active',
    sync_status: 'synced',
    is_default: false,
  }
}

function renderHttpsTab(value: SiteBasicConfig, onChange: (next: SiteBasicConfig) => void, errors = {}) {
  // 不给证书权限，避免证书资产查询；只验证 TLS 协议区块。
  return renderWithProviders(
    <HttpsSiteTab
      siteId={siteID}
      siteScopeId="66666666-6666-4666-8666-666666666666"
      accessToken="tls-token"
      scopeKind="tenant"
      principalScopeId="66666666-6666-4666-8666-666666666666"
      permissions={[]}
      sessionEpoch={1}
      value={{ ...value, https_enabled: true }}
      errors={errors}
      readOnly={false}
     
      onChange={onChange}
    />,
  )
}

function detail(tlsProtocols: SiteTLSProtocol[]): SiteDetail {
  return {
    id: siteID,
    version: 7,
    owner: null,
    created_at: '2026-08-08T00:00:00Z',
    updated_at: '2026-08-08T00:00:00Z',
    lock: { locked: false, reason: null, locked_at: null, operator: null },
    listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' },
    basic: basic(tlsProtocols),
    origin_pool: {
      origins: [{ host: '192.0.2.10', port: 80, weight: 1, enabled: true }],
      balance_method: 'round_robin',
      failover_tries: 1,
      connect_timeout_ms: 1_000,
      read_timeout_ms: 5_000,
    },
  }
}

function createdDetail(tlsProtocols: SiteTLSProtocol[]): SiteDetail {
  const saved = detail(tlsProtocols)
  saved.basic = {
    ...saved.basic,
    package_subscription_id: null,
    cname_mode: '',
    cname_domain: '',
    cname_hostname: '',
    cname_state: null,
    cname_task_id: null,
    cname_current_revision: null,
    cname_lkg_revision: null,
  }
  return saved
}

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const translate = ((key: string) => key) as unknown as TFunction<['sites', 'siteTLS']>

beforeEach(async () => {
  vi.restoreAllMocks()
  await i18n.changeLanguage('zh-CN')
})

describe('site TLS protocol contract', () => {
  it('preserves legacy and future protocol facts up to the frozen limit', async () => {
    const maximumFacts: SiteTLSProtocol[] = [
      'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3', 'TLSv1.4', 'TLSv2.0',
    ]
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(detail(['SSLv3', 'TLSv1.2'])))
      .mockResolvedValueOnce(response(detail(['TLSv1.4'])))
      .mockResolvedValueOnce(response(detail(maximumFacts)))
    vi.stubGlobal('fetch', fetchMock)

    await expect(sitesApi.detail('token', siteID)).resolves.toMatchObject({
      basic: { tls_protocols: ['SSLv3', 'TLSv1.2'] },
    })
    await expect(sitesApi.detail('token', siteID)).resolves.toMatchObject({
      basic: { tls_protocols: ['TLSv1.4'] },
    })
    await expect(sitesApi.detail('token', siteID)).resolves.toMatchObject({
      basic: { tls_protocols: maximumFacts },
    })
  })

  it('rejects missing, empty, duplicate, malformed, and over-limit protocol facts', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response({ ...detail(['TLSv1.2']), basic: { ...basic(['TLSv1.2']), tls_protocols: undefined } }))
      .mockResolvedValueOnce(response(detail([])))
      .mockResolvedValueOnce(response(detail(['TLSv1.2', 'TLSv1.2'])))
      .mockResolvedValueOnce(response(detail(['unknown'])))
      .mockResolvedValueOnce(response(detail([
        'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3', 'TLSv1.4', 'TLSv2.0', 'TLSv2.1',
      ])))
    vi.stubGlobal('fetch', fetchMock)

    for (let index = 0; index < 5; index += 1) {
      await expect(sitesApi.detail('token', siteID)).rejects.toMatchObject({ code: 'invalid_response' })
    }
  })

  it('rejects legacy writes before network I/O and sends a safe frozen body and key unchanged', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response(detail(['TLSv1.2', 'TLSv1.3'])))
    vi.stubGlobal('fetch', fetchMock)

    // TLSv1.1 needs the legacy cipher preset.
    const unsafe: PatchSiteBasicRequest = {
      expected_version: 7,
      section: 'basic',
      changes: { ...basic(['TLSv1.1', 'TLSv1.2', 'TLSv1.3']), tls_cipher_preset: 'modern' },
    }
    await expect(sitesApi.patchBasic('token', siteID, unsafe, 'unsafe-key'))
      .rejects.toMatchObject({ status: 400, code: 'validation_error' })
    expect(fetchMock).not.toHaveBeenCalled()

    // PJ-C02: sync_status is response-only and the community edition binds no
    // package; writeBody drops those, so a write without them is what reaches
    // the network byte-for-byte.
    const { sync_status: _readOnly, package_id: _packageID, package_name: _packageName, ...changes } = basic(['TLSv1.2', 'TLSv1.3'])
    const safe = {
      expected_version: 7,
      section: 'basic',
      changes,
    } as PatchSiteBasicRequest
    const frozenBody = JSON.stringify(safe, null, 2)
    await sitesApi.patchBasic('token', siteID, safe, 'fixed-key', frozenBody)

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining(`/v1/sites/${siteID}`),
      expect.objectContaining({
        body: frozenBody,
        headers: expect.objectContaining({ 'Idempotency-Key': 'fixed-key' }),
      }),
    )
  })

  it('allows omitted protocols as the canonical default for create and patch responses', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(createdDetail(['TLSv1.2', 'TLSv1.3']), 201))
      .mockResolvedValueOnce(response(detail(['TLSv1.2', 'TLSv1.3'])))
    vi.stubGlobal('fetch', fetchMock)
    const omitted = basic(['TLSv1.2', 'TLSv1.3'])
    delete omitted.tls_protocols

    await expect(sitesApi.create('token', { basic: omitted }, 'create-key')).resolves.toMatchObject({
      basic: { tls_protocols: ['TLSv1.2', 'TLSv1.3'] },
    })
    await expect(sitesApi.patchBasic('token', siteID, {
      expected_version: 7,
      section: 'basic',
      changes: omitted,
    }, 'patch-key')).resolves.toMatchObject({
      basic: { tls_protocols: ['TLSv1.2', 'TLSv1.3'] },
    })

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(String(fetchMock.mock.calls[0]?.[1]?.body)).not.toContain('tls_protocols')
    expect(String(fetchMock.mock.calls[1]?.[1]?.body)).not.toContain('tls_protocols')
  })

  it('requires create responses to echo the exact requested origin pool', async () => {
	const pool: SiteOriginPool = {
	  origins: [
		{ host: 'origin.example', port: 8080, weight: 75, enabled: true },
		{ host: '2001:db8::1', port: 443, weight: 25, enabled: true },
	  ],
	  balance_method: 'least_conn',
	  failover_tries: 2,
	  connect_timeout_ms: 500,
	  read_timeout_ms: 5000,
	}
	const input = {
	  basic: { ...basic(['TLSv1.2', 'TLSv1.3']), origins: ['origin.example:8080', '[2001:db8::1]:443'] },
	  origin_pool: pool,
	}
	const saved = createdDetail(['TLSv1.2', 'TLSv1.3'])
	saved.basic.origins = input.basic.origins
	saved.origin_pool = pool
	const mismatched = { ...saved, origin_pool: { ...pool, balance_method: 'random' as const } }
	const fetchMock = vi.fn()
	  .mockResolvedValueOnce(response(saved, 201))
	  .mockResolvedValueOnce(response(mismatched, 201))
	vi.stubGlobal('fetch', fetchMock)

	await expect(sitesApi.create('token', input, 'create-rich')).resolves.toMatchObject({ origin_pool: pool })
	await expect(sitesApi.create('token', input, 'create-rich-mismatch')).rejects.toMatchObject({
	  status: 502,
	  code: 'invalid_response',
	})
  })

  // TLS 协议选择与旧版/未知协议提示已从「基本信息」移到「HTTPS」标签（2026-09-21）。
  it('renders SSL protocols as blocked facts and requires an explicit replacement', () => {
    const value = basic(['SSLv2', 'TLSv1.3'])
    const onChange = vi.fn()
    renderHttpsTab(value, onChange, { tls_protocols: '请选择一组连续的 TLS 版本' })

    expect(screen.getByText('检测到不受支持的 SSL 协议')).toBeInTheDocument()
    expect(screen.getByText(/当前保存值包含 SSLv2/)).toBeInTheDocument()
    expect(screen.getByText('请选择一组连续的 TLS 版本')).toBeInTheDocument()
    expect(onChange).not.toHaveBeenCalled()

    const combobox = screen.getByRole('combobox', { name: 'TLS协议' })
    fireEvent.mouseDown(combobox)
    fireEvent.click(screen.getByText('TLS 1.2 + 1.3（推荐）'))
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({
      tls_protocols: ['TLSv1.2', 'TLSv1.3'], tls_cipher_preset: 'modern',
    }))
  })

  it('TLS 1.3 only, legacy clients force the legacy cipher preset, OCSP and mTLS', () => {
    const value = basic(['TLSv1.2', 'TLSv1.3'])
    const onChange = vi.fn()
    renderHttpsTab(value, onChange)
    fireEvent.mouseDown(screen.getByRole('combobox', { name: 'TLS协议' }))
    fireEvent.click(screen.getByText('兼容旧客户端（TLS 1.0 – 1.3）'))
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({
      tls_protocols: ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'], tls_cipher_preset: 'legacy',
    }))
    fireEvent.click(screen.getByRole('switch', { name: 'OCSP Stapling' }))
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ tls_ocsp_stapling: true }))
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '客户端证书校验（mTLS）' }))
    fireEvent.click(screen.getByText('必须'))
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ tls_client_auth: 'required', tls_client_ca_pem: '' }))
  })

  it('a legacy range with TLS 1.0 disables the narrower cipher presets', () => {
    renderHttpsTab({ ...basic(['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']), tls_cipher_preset: 'legacy' }, vi.fn())
    expect(screen.getByText(/TLS 1.0\/1.1 已被主流浏览器淘汰/)).toBeInTheDocument()
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '加密套件' }))
    const modern = screen.getByText('现代（仅 ECDHE + AEAD）').closest('.ant-select-item')
    expect(modern).toHaveClass('ant-select-item-option-disabled')
  })

  it('keeps basic status and CNAME controls in the reference density', () => {
    const value = { ...basic(['TLSv1.2', 'TLSv1.3']), cname: 'edge.example.test' }
    const current = detail(value.tls_protocols!)
    current.basic = value
    const onBlockedAction = vi.fn()

    // BasicSiteTab 会通过 useSearchParams 切换到监听域名弹窗，需要路由上下文。
    render(
      <QueryClientProvider client={testQueryClient()}>
      <MemoryRouter>
      <BasicSiteTab
        detail={current}
        role="admin"
        value={value}
        originPool={current.origin_pool}
        errors={{}}
        canManageDNS
        onChange={vi.fn()}
        onOriginChange={vi.fn()}
        onBlockedAction={onBlockedAction}
      />
      </MemoryRouter>
      </QueryClientProvider>,
    )

    expect(screen.getByText('正常', { selector: '.ant-tag' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '复制 CNAME' })).not.toBeInTheDocument()
    // 「更改CNAME」已是真实的 CNAME 修改弹窗（需要 DNS 管理权限），不再走 onBlockedAction 占位。
    const changeButton = screen.getByRole('button', { name: '更改CNAME' })
    expect(changeButton).not.toHaveClass('ant-btn-primary')
    expect(changeButton).toBeEnabled()
    fireEvent.click(changeButton)
    expect(screen.getByRole('dialog', { name: '更改CNAME' })).toBeInTheDocument()
    expect(onBlockedAction).not.toHaveBeenCalled()
  })

  it('renders unknown protocols as distinct read-only facts with localized remediation', () => {
    const value = basic(['TLSv1.4'])
    const onChange = vi.fn()
    renderHttpsTab(value, onChange)

    expect(screen.getByText('检测到未知 TLS 协议')).toBeInTheDocument()
    expect(screen.getByText(/当前保存值包含 TLSv1.4/)).toBeInTheDocument()
    expect(screen.queryByText('检测到不受支持的 SSL 协议')).not.toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'TLS协议' })).toHaveTextContent('')
    expect(onChange).not.toHaveBeenCalled()
  })

  it('blocks SSL, empty, duplicate, gapped and unknown write sets while accepting contiguous ranges', () => {
    expect(validateBasicConfig(basic(['TLSv1.2', 'TLSv1.3']), translate).tls_protocols).toBeUndefined()
    const omitted = basic(['TLSv1.2', 'TLSv1.3'])
    delete omitted.tls_protocols
    expect(validateBasicConfig(omitted, translate).tls_protocols).toBeUndefined()
    expect(validateBasicConfig(basic(['TLSv1.2']), translate).tls_protocols).toBeUndefined()
    expect(validateBasicConfig(basic(['TLSv1.3']), translate).tls_protocols).toBeUndefined()
    expect(validateBasicConfig({ ...basic(['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']), tls_cipher_preset: 'legacy' },
      translate).tls_protocols).toBeUndefined()
    // TLS 1.0/1.1 without the legacy cipher preset.
    expect(validateBasicConfig(basic(['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']), translate).tls_protocols)
      .toBe('siteTLS:validation.safeOnly')
    expect(validateBasicConfig(basic([]), translate).tls_protocols).toBe('siteTLS:validation.safeOnly')
    expect(validateBasicConfig(basic(['TLSv1.3', 'TLSv1.2']), translate).tls_protocols)
      .toBe('siteTLS:validation.safeOnly')
    expect(validateBasicConfig(basic(['TLSv1.2', 'TLSv1.2']), translate).tls_protocols)
      .toBe('siteTLS:validation.safeOnly')
    expect(validateBasicConfig({ ...basic(['TLSv1', 'TLSv1.3']), tls_cipher_preset: 'legacy' }, translate).tls_protocols)
      .toBe('siteTLS:validation.safeOnly')
    expect(canonicalSiteTLSProtocolSelection(['TLSv1.3', 'TLSv1.2']))
      .toEqual(['TLSv1.2', 'TLSv1.3'])
    expect(validateBasicConfig(basic(['SSLv3', 'TLSv1.2']), translate).tls_protocols).toBe('siteTLS:validation.safeOnly')
    expect(validateBasicConfig(basic(['TLSv1.4' as SiteTLSProtocol]), translate).tls_protocols)
      .toBe('siteTLS:validation.safeOnly')
    expect(validateBasicConfig({ ...basic(['TLSv1.2', 'TLSv1.3']), tls_client_auth: 'required', tls_client_ca_pem: '' },
      translate).tls_client_ca_pem).toBe('siteTLS:validation.clientCA')
  })

  it('uses stable API errors rather than leaking a server body for invalid TLS responses', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(detail(['SSLv3', 'unknown' as SiteTLSProtocol]))))
    const error = await sitesApi.detail('token', siteID).catch((reason: unknown) => reason)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('所有域名共用缓存 defaults off, toggles in basic and is accepted in a create response', async () => {
    const current = detail(['TLSv1.2', 'TLSv1.3'])
    const onChange = vi.fn()
    render(
      <QueryClientProvider client={testQueryClient()}>
      <MemoryRouter>
        <BasicSiteTab detail={current} role="admin" value={current.basic} originPool={current.origin_pool} errors={{}}
          canManageDNS onChange={onChange} onOriginChange={vi.fn()} onBlockedAction={vi.fn()} />
      </MemoryRouter>
      </QueryClientProvider>,
    )
    const toggle = screen.getByRole('switch', { name: '所有域名共用缓存开关' })
    expect(toggle).not.toBeChecked()
    fireEvent.click(toggle)
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ cache_shared_across_domains: true }))

    const saved = createdDetail(['TLSv1.2', 'TLSv1.3'])
    saved.basic = { ...saved.basic, cache_shared_across_domains: false }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response(saved, 201)))
    await expect(sitesApi.create('token', { basic: basic(['TLSv1.2', 'TLSv1.3']) }, 'create-shared'))
      .resolves.toMatchObject({ basic: { cache_shared_across_domains: false } })
  })
  // PJ-C03: the service rejects http_enabled=false, so the HTTP switch is fixed
  // on (with the reason) instead of offering a choice that can never save.
  it('PJ-C03: the HTTP switch is on and not operable; HTTP ports stay editable', () => {
    const current = detail(['TLSv1.2', 'TLSv1.3'])
    const onChange = vi.fn()
    render(
      <QueryClientProvider client={testQueryClient()}>
      <MemoryRouter>
        <BasicSiteTab detail={current} role="admin" value={current.basic} originPool={current.origin_pool} errors={{}}
          canManageDNS onChange={onChange} onOriginChange={vi.fn()} onBlockedAction={vi.fn()} />
      </MemoryRouter>
      </QueryClientProvider>,
    )
    const toggle = screen.getByRole('switch', { name: 'HTTP开关' })
    expect(toggle).toBeChecked()
    expect(toggle).toBeDisabled()
    fireEvent.click(toggle)
    expect(onChange).not.toHaveBeenCalledWith(expect.objectContaining({ http_enabled: false }))
    expect(screen.getByLabelText('HTTP监听端口')).toBeEnabled()
  })

  it('be-gap-2: the basic HTTPS card cannot turn HTTPS on without a bound certificate, and says why', () => {
    const base = detail(['TLSv1.2', 'TLSv1.3'])
    const renderCard = (current: SiteDetail, onChange = vi.fn()) => {
      const view = render(
        <QueryClientProvider client={testQueryClient()}>
        <MemoryRouter>
          <BasicSiteTab detail={current} role="admin" value={current.basic} originPool={current.origin_pool} errors={{}}
            canManageDNS onChange={onChange} onOriginChange={vi.fn()} onBlockedAction={vi.fn()} />
        </MemoryRouter>
        </QueryClientProvider>,
      )
      return { view, onChange }
    }
    const unbound = { ...base, https_certificate_bound: false, basic: { ...base.basic, https_enabled: false } }
    const { view, onChange } = renderCard(unbound)
    const toggle = screen.getByRole('switch', { name: 'HTTPS开关' })
    expect(toggle).toBeDisabled()
    fireEvent.click(toggle)
    expect(onChange).not.toHaveBeenCalled()
    expect(screen.getByText('还没有绑定证书，暂不能开启 HTTPS：请先到 HTTPS 设置中绑定证书。')).toBeInTheDocument()
    view.unmount()

    // Already on (certificate unbound later): it can still be turned off.
    const on = { ...unbound, basic: { ...unbound.basic, https_enabled: true } }
    const second = renderCard(on)
    const onToggle = screen.getByRole('switch', { name: 'HTTPS开关' })
    expect(onToggle).toBeEnabled()
    fireEvent.click(onToggle)
    expect(second.onChange).toHaveBeenLastCalledWith(expect.objectContaining({ https_enabled: false }))
    second.view.unmount()

    renderCard({ ...base, https_certificate_bound: true, basic: { ...base.basic, https_enabled: false } })
    expect(screen.getByRole('switch', { name: 'HTTPS开关' })).toBeEnabled()
  })
})
