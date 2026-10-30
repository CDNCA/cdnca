import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import { fireEvent, screen } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { SiteDetail } from '../api/sites'
import { resetSessionStore, useSessionStore } from '../auth/session'
import i18n from '../i18n'
import SiteEditPage from '../pages/SiteEditPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const scopeID = '22222222-2222-4222-8222-222222222222'
const userID = '11111111-1111-4111-8111-111111111111'
const detail: SiteDetail = {
  id: 'site-1', version: 1, owner: { id: scopeID, display_name: 'owner' },
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
  lock: { locked: false, reason: null, locked_at: null, operator: null },
  listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' },
  origin_pool: { origins: [{ host: '192.0.2.1', port: 80, weight: 1, enabled: true }], balance_method: 'round_robin', failover_tries: 1, connect_timeout_ms: 3000, read_timeout_ms: 30000 },
  basic: { package_id: 'package-1', package_name: 'package', group_id: 'group-1', group_name: 'group', domains: ['www.example.com'], http_enabled: true, http_listen_ports: ['80'], https_listen_ports: ['443'], ipv6_enabled: false, tls_protocols: ['TLSv1.2', 'TLSv1.3'], origins: ['192.0.2.1:80'], cname: 'edge.example.com', https_enabled: true, enabled: true, status: 'active', sync_status: 'synced', is_default: false },
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

// ge-access 起高级页挂载站点访问控制卡片（GET /v1/sites/:id/access）、302 调度与流量上限卡片，夹具各给一份未设置的状态。
const accessState = {
  site_id: 'site-1', version: 1, https_enabled: true, force_https: false, domains: ['www.example.com'], updated_at: null,
  settings: { host_redirects: [], hsts: null, compression: null, limits: null, basic_auth: null, maintenance: null,
    force_https: { status: 301, exclude_hosts: [] } },
}
const schedule302State = { site_id: 'site-1', version: 1, plain_http: true, updated_at: null, settings: {
  enabled: false, target: 'address', keep_path: true, keep_query: true, signature_ttl_seconds: 60,
  https_to_http: false, extensions: [], path_prefixes: [], min_size_bytes: 0 } }
const trafficLimitState = { site_id: 'site-1', version: 1, total_since: null, exceeded_period: '', exceeded_at: null,
  evaluated_at: null, updated_at: null, setting: { enabled: false, daily_bytes: null, monthly_bytes: null,
    total_bytes: null, time_zone: 'Asia/Shanghai', notice_html: '' } }

function authenticate() {
  const actor = principal({
    scope_kind: 'tenant', scope_id: scopeID, tenant_id: scopeID, user_id: userID,
    permissions: ['sites.read', 'sites.manage', 'http_policies.read', 'http_policies.manage', 'error_pages.read', 'error_pages.manage'],
  })
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'policy-token' }, actor)
}

function QueryCapture({ capture }: { capture: (client: QueryClient) => void }) {
  capture(useQueryClient())
  return null
}

function renderAdvanced() {
  let client: QueryClient | undefined
  renderWithProviders(<><QueryCapture capture={(value) => { client = value }} /><Routes><Route path="/site/:id/edit" element={<SiteEditPage />} /></Routes></>, ['/site/site-1/edit?tab=advanced'])
  if (!client) throw new Error('query client unavailable')
  return client
}

function renderAccess() {
  renderWithProviders(<Routes><Route path="/site/:id/edit" element={<SiteEditPage />} /></Routes>, ['/site/site-1/edit?tab=access'])
}

beforeEach(async () => {
  vi.restoreAllMocks()
  resetSessionStore()
  await i18n.changeLanguage('zh-CN')
})

describe('SiteEdit policy tabs integration', () => {
  it('opens 高级设置 from the retired ?tab=access link, with CORS in place', async () => {
    authenticate()
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/v1/sites/site-1')) return Promise.resolve(json(detail))
      if (url.endsWith('/v1/sites/site-1/access')) return Promise.resolve(json(accessState))
      if (url.endsWith('/v1/sites/site-1/schedule302')) return Promise.resolve(json(schedule302State))
      if (url.endsWith('/v1/sites/site-1/traffic-limit')) return Promise.resolve(json(trafficLimitState))
      return Promise.resolve(json({ items: [] }))
    })
    renderAccess()

    expect(await screen.findByRole('heading', { name: '跨域 CORS' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '高级设置' })).toHaveAttribute('aria-selected', 'true')
    expect(fetchMock.mock.calls.map(([input]) => String(input)))
      .toContain(`/v1/tenant-scopes/${scopeID}/http-policies?site_id=site-1`)
  })

  it('loads real owner/session-scoped policy and error-page requests without token-bearing keys', async () => {
    authenticate()
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/v1/sites/site-1')) return Promise.resolve(json(detail))
      if (url.endsWith('/v1/sites/site-1/access')) return Promise.resolve(json(accessState))
      if (url.endsWith('/v1/sites/site-1/schedule302')) return Promise.resolve(json(schedule302State))
      if (url.endsWith('/v1/sites/site-1/traffic-limit')) return Promise.resolve(json(trafficLimitState))
      return Promise.resolve(json({ items: [] }))
    })
    const client = renderAdvanced()

    expect(await screen.findByRole('heading', { name: '上传大小限制' })).toBeInTheDocument()
    const urls = fetchMock.mock.calls.map(([input]) => String(input))
    expect(urls).toContain(`/v1/tenant-scopes/${scopeID}/http-policies?site_id=site-1`)
    expect(urls).toContain(`/v1/error-pages/assets?scope_id=${scopeID}&status=ready`)
    expect(urls).toContain(`/v1/error-pages/rules?scope_id=${scopeID}&site_id=site-1`)
    const keys = JSON.stringify(client.getQueryCache().getAll().map((query) => query.queryKey))
    expect(keys).toContain(scopeID)
    expect(keys).toContain(userID)
    expect(keys).toContain('site-1')
    expect(keys).not.toContain('policy-token')
  })

  it('recovers a localized ordinary error through retry without exposing server text', async () => {
    authenticate()
    let policyAttempts = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/v1/sites/site-1')) return Promise.resolve(json(detail))
      if (url.endsWith('/v1/sites/site-1/access')) return Promise.resolve(json(accessState))
      if (url.endsWith('/v1/sites/site-1/schedule302')) return Promise.resolve(json(schedule302State))
      if (url.endsWith('/v1/sites/site-1/traffic-limit')) return Promise.resolve(json(trafficLimitState))
      if (url === `/v1/tenant-scopes/${scopeID}/http-policies?site_id=site-1`) {
        policyAttempts += 1
        return Promise.resolve(policyAttempts === 1
          ? json({ error: { code: 'service_unavailable', message: 'raw server message' } }, 503)
          : json({ items: [] }))
      }
      return Promise.resolve(json({ items: [] }))
    })
    renderAdvanced()

    expect(await screen.findByText('HTTP 策略加载失败')).toBeInTheDocument()
    expect(screen.queryByText('raw server message')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无 HTTP 策略')).toBeInTheDocument()
    expect(policyAttempts).toBe(2)
  })
})
