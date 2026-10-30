import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { certificatesApi } from '../api/certificates'
import { sitesApi, type SiteDetail } from '../api/sites'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import '../i18n/siteListenerDomains'
import SiteEditPage from '../pages/SiteEditPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const scopeID = '22222222-2222-4222-8222-222222222222'
const userID = '11111111-1111-4111-8111-111111111111'
const siteID = '33333333-3333-4333-8333-333333333333'

const detail: SiteDetail = {
  id: siteID,
  scope_id: scopeID,
  version: 1,
  owner: { id: userID, display_name: 'jason' },
  created_at: '2026-09-15T00:00:00Z',
  updated_at: '2026-09-15T00:00:00Z',
  lock: { locked: false, reason: null, locked_at: null, operator: null },
  listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' },
  origin_pool: {
    origins: [{ host: '192.0.2.10', port: 80, weight: 1, enabled: true }],
    balance_method: 'round_robin',
    failover_tries: 1,
    connect_timeout_ms: 3000,
    read_timeout_ms: 30000,
  },
  basic: {
    package_id: null,
    package_name: null,
    group_id: null,
    group_name: null,
    domains: ['www.example.com'],
    http_enabled: true,
    http_listen_ports: ['80'],
    https_listen_ports: [],
    ipv6_enabled: false,
    tls_protocols: ['TLSv1.2', 'TLSv1.3'],
    origins: ['192.0.2.10:80'],
    cname: 'edge.example.com',
    https_enabled: false,
    enabled: true,
    status: 'active',
    sync_status: 'synced',
    is_default: false,
  },
}

function authenticate(permissions = ['sites.read', 'sites.manage']) {
  const actor = principal({
    user_id: userID,
    scope_id: scopeID,
    tenant_id: scopeID,
    scope_kind: 'tenant',
    username: 'jason',
    display_name: 'jason',
    roles: ['tenant_owner'],
    permissions,
  })
  useSessionStore.getState().setSession(
    { ...authResponse(actor), access_token: 'site-token' },
    actor,
  )
}

function LocationProbe() {
  const location = useLocation()
  return <span data-testid="location">{`${location.pathname}${location.search}`}</span>
}

function renderHttpsPage() {
  return renderWithProviders(
    <Routes>
      <Route path="/site/list/:id" element={<SiteEditPage />} />
      <Route path="/site/cert" element={<LocationProbe />} />
    </Routes>,
    [`/site/list/${siteID}?tab=https`],
  )
}

describe('SiteEditPage HTTPS workflow', () => {
  beforeEach(async () => {
    vi.restoreAllMocks()
    sessionStorage.clear()
    await i18n.changeLanguage('zh-CN')
    authenticate()
    vi.spyOn(sitesApi, 'detail').mockResolvedValue(detail)
    vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [], total: 0, counts: { all: 0, normal: 0, expiring: 0, expired: 0, auto_renew: 0, manual_renew: 0 } })
    vi.spyOn(certificatesApi, 'getSiteBinding').mockRejectedValue(
      new ApiError('API request failed', 404, 'certificate_site_binding_not_found'),
    )
  })

  it('saves the HTTPS switch and listen ports through the real basic PATCH contract', async () => {
    const saved: SiteDetail = {
      ...detail,
      version: 2,
      basic: { ...detail.basic, https_enabled: true, https_listen_ports: ['443', '8443'] },
    }
    const patch = vi.spyOn(sitesApi, 'patchBasic').mockResolvedValue(saved)
    const user = userEvent.setup()
    renderHttpsPage()

    await user.click(await screen.findByRole('switch', { name: 'HTTPS访问' }))
    const ports = await screen.findByRole('textbox', { name: 'HTTPS监听端口' })
    await user.clear(ports)
    await user.type(ports, '443 8443')
    // fix-siteinstant: no save button; the ports save on blur (the switch alone has no port yet and is not sent)
    expect(screen.queryByRole('button', { name: '保存更改' })).toBeNull()
    fireEvent.blur(ports)

    await waitFor(() => expect(patch).toHaveBeenCalledTimes(1))
    expect(patch.mock.calls[0][0]).toBe('site-token')
    expect(patch.mock.calls[0][1]).toBe(siteID)
    expect(patch.mock.calls[0][2]).toMatchObject({
      expected_version: 1,
      section: 'basic',
      changes: {
        https_enabled: true,
        https_listen_ports: ['443', '8443'],
        tls_protocols: ['TLSv1.2', 'TLSv1.3'],
      },
    })
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
  })

  it('rejects an HTTPS port that conflicts with the HTTP listener before sending a write', async () => {
    vi.mocked(sitesApi.detail).mockResolvedValue({
      ...detail,
      basic: { ...detail.basic, http_listen_ports: ['443'] },
    })
    const patch = vi.spyOn(sitesApi, 'patchBasic')
    const user = userEvent.setup()
    renderHttpsPage()

    await user.click(await screen.findByRole('switch', { name: 'HTTPS访问' }))
    const ports = await screen.findByRole('textbox', { name: 'HTTPS监听端口' })
    await user.type(ports, '443')
    fireEvent.blur(ports)

    expect(await screen.findByText('HTTP 与 HTTPS 监听端口不能重复。')).toBeInTheDocument()
    expect(patch).not.toHaveBeenCalled()
  })

  it('retries an unknown HTTPS save with the exact frozen body and idempotency key', async () => {
    const saved: SiteDetail = {
      ...detail,
      version: 2,
      basic: { ...detail.basic, https_enabled: true, https_listen_ports: ['443'] },
    }
    const patch = vi.spyOn(sitesApi, 'patchBasic')
      .mockRejectedValueOnce(new ApiError('private transport detail', 0, 'network_error'))
      .mockResolvedValueOnce(saved)
    const user = userEvent.setup()
    renderHttpsPage()

    await user.click(await screen.findByRole('switch', { name: 'HTTPS访问' }))
    const ports = await screen.findByRole('textbox', { name: 'HTTPS监听端口' })
    await user.type(ports, '443')
    fireEvent.blur(ports)
    expect(await screen.findByRole('button', { name: '使用同一请求重试' })).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('private transport detail')
    const firstCall = patch.mock.calls[0]

    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(patch).toHaveBeenCalledTimes(2))
    expect(patch.mock.calls[1]).toEqual(firstCall)
  })

  // P3：从 HTTPS 页去证书管理带 site=，证书页按网站所属用户带入。
  it('opens certificate management with the site so the owner is carried over', async () => {
    authenticate(['sites.read', 'sites.manage', 'certificates.read'])
    renderHttpsPage()
    await userEvent.setup().click(await screen.findByRole('button', { name: '证书管理' }))
    expect(await screen.findByTestId('location')).toHaveTextContent(`/site/cert?domains=www.example.com&site=${siteID}`)
  })

  it('keeps the HTTPS controls read-only without sites.manage', async () => {
    authenticate(['sites.read', 'certificates.read'])
    renderHttpsPage()

    expect(await screen.findByRole('switch', { name: 'HTTPS访问' })).toBeDisabled()
    expect(screen.getByText('当前账号缺少网站管理权限，只能查看配置')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '保存更改' })).not.toBeInTheDocument()
  })
})
