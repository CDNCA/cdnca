import { fireEvent, screen, waitFor } from '@testing-library/react'
import { Route, Routes, useSearchParams } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { SiteDetail } from '../api/sites'
import { resetSessionStore, useSessionStore } from '../auth/session'
import { RouteErrorBoundary } from '../components/RouteErrorBoundary'
import { retryableLazy, SiteEditTabBoundary } from '../pages/site-edit/SiteEditTabBoundary'
import i18n from '../i18n'
import SiteEditPage from '../pages/SiteEditPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { useNavigationGuardStore } from '../routes/navigationGuard'

// 站点编辑页来回切标签会卡在一个转圈上，必须整页刷新。
// 本地 vite preview 复现：基本配置 → 回源设置 → HTTPS设置 后整页只剩 EditLoading、标签栏消失。

const scopeID = '22222222-2222-4222-8222-222222222222'
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

function authenticate() {
  const actor = principal({ scope_kind: 'tenant', scope_id: scopeID, tenant_id: scopeID, permissions: ['sites.read', 'sites.manage'] })
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'tab-token' }, actor)
}

beforeEach(async () => {
  vi.restoreAllMocks()
  sessionStorage.clear()
  resetSessionStore()
  await i18n.changeLanguage('zh-CN')
})

describe('SiteEdit tab switching', () => {
  it('keeps the page mounted when tabs change under the route error boundary', async () => {
    authenticate()
    let detailCalls = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/v1/sites/site-1')) {
        detailCalls += 1
        return Promise.resolve(json(detail))
      }
      return Promise.resolve(json({ items: [] }))
    })
    renderWithProviders(
      <RouteErrorBoundary>
        <Routes><Route path="/site/:id/edit" element={<SiteEditPage />} /></Routes>
      </RouteErrorBoundary>,
      ['/site/site-1/edit'],
    )
    await screen.findByRole('heading', { name: 'www.example.com' })

    for (const label of ['回源设置', 'HTTPS设置', '缓存设置', 'CC防护', '基本配置']) {
      fireEvent.click(await screen.findByRole('tab', { name: label }, { timeout: 3000 }))
      await waitFor(() => expect(screen.getByRole('tab', { name: label })).toHaveAttribute('aria-selected', 'true'))
    }
    // 切标签只改 ?tab=，不得重挂载页面、重新拉站点详情。
    expect(screen.getByRole('heading', { name: 'www.example.com' })).toBeInTheDocument()
    expect(detailCalls).toBe(1)
  })

  // 基本配置 HTTPS 卡片「HTTPS设置」跳到 ?tab=https 后内容区空白。
  // 根因：该按钮直接改 ?tab=，绕过 setTab，HTTPS 面板的“已访问”标记没置位，面板不挂载。
  it('shows the HTTPS panel after the basic tab HTTPS settings button changes ?tab=', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/v1/sites/site-1')) return Promise.resolve(json({ ...detail, basic: { ...detail.basic, https_enabled: false }, https_certificate_bound: false }))
      return Promise.resolve(json({ items: [] }))
    })
    renderWithProviders(
      <RouteErrorBoundary>
        <Routes><Route path="/site/:id/edit" element={<SiteEditPage />} /></Routes>
      </RouteErrorBoundary>,
      ['/site/site-1/edit'],
    )
    fireEvent.click(await screen.findByRole('button', { name: 'HTTPS设置' }, { timeout: 5000 }))
    await waitFor(() => expect(screen.getByRole('tab', { name: 'HTTPS设置' })).toHaveAttribute('aria-selected', 'true'))
    expect(await screen.findByRole('heading', { name: 'HTTPS证书' }, { timeout: 5000 })).toBeInTheDocument()
  })

  it.each([
    ['basic', '站点与监听'],
    ['origin', '回源协议与端口'],
    ['https', 'HTTPS证书'],
    ['cache', '缓存规则'],
    ['cc', 'CC防护'],
    ['waf', 'WAF防护'],
    ['autodefense', 'CC 自动切换'],
    ['advanced', '性能与协议'],
  ])('renders the %s panel when opened directly with ?tab=', async (tab, heading) => {
    const actor = principal({ scope_kind: 'tenant', scope_id: scopeID, tenant_id: scopeID, permissions: [
      'sites.read', 'sites.manage', 'certificates.read', 'security_policies.read', 'http_policies.read',
    ] })
    useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'tab-token' }, actor)
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/v1/sites/site-1')) return Promise.resolve(json(detail))
      // 站点尚无缓存策略：服务返回 404，面板按空策略展示。
      if (url.includes('/cache-policies/')) return Promise.resolve(json({ error: { code: 'cache_policy_not_found', message: 'x' } }, 404))
      if (url.endsWith('/v1/sites/site-1/access')) return Promise.resolve(json({
        site_id: 'site-1', version: 1, https_enabled: true, force_https: false, domains: ['www.example.com'], updated_at: null,
        settings: { host_redirects: [], hsts: null, compression: null, limits: null, basic_auth: null, maintenance: null, webp: null, response_rules: [], force_https: { status: 301, exclude_hosts: [] } },
      }))
      return Promise.resolve(json({ items: [] }))
    })
    renderWithProviders(
      <RouteErrorBoundary>
        <Routes><Route path="/site/:id/edit" element={<SiteEditPage />} /></Routes>
      </RouteErrorBoundary>,
      [tab === 'basic' ? '/site/site-1/edit' : `/site/site-1/edit?tab=${tab}`],
    )
    expect(await screen.findByRole('heading', { name: heading }, { timeout: 5000 })).toBeInTheDocument()
  })

  // CC/WAF 页里“到自动防御标签设置”切到 ?tab=autodefense，自动防御面板挂载并选中。
  it('the CC tab note opens the 自动防御 tab in place', async () => {
    const actor = principal({ scope_kind: 'tenant', scope_id: scopeID, tenant_id: scopeID, permissions: ['sites.read', 'sites.manage', 'security_policies.read'] })
    useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'tab-token' }, actor)
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/v1/sites/site-1')) return Promise.resolve(json(detail))
      return Promise.resolve(json({ items: [] }))
    })
    renderWithProviders(
      <RouteErrorBoundary>
        <Routes><Route path="/site/:id/edit" element={<SiteEditPage />} /></Routes>
      </RouteErrorBoundary>,
      ['/site/site-1/edit?tab=cc'],
    )
    fireEvent.click(await screen.findByRole('button', { name: '到自动防御标签设置' }, { timeout: 5000 }))
    await waitFor(() => expect(screen.getByRole('tab', { name: '自动防御' })).toHaveAttribute('aria-selected', 'true'))
    expect(await screen.findByRole('heading', { name: 'CC 自动切换' }, { timeout: 5000 })).toBeInTheDocument()
  })

  it('confines a failed lazy tab to its own panel and retries only that tab', async () => {
    let attempts = 0
    // React.lazy 会永久缓存失败结果，标签内重试必须换一个新的 lazy 才会重新 import。
    const Flaky = retryableLazy(async () => {
      attempts += 1
      if (attempts === 1) throw new Error('Failed to fetch dynamically imported module')
      return { default: () => <div>flaky loaded</div> }
    })
    function Harness() {
      const [params, setParams] = useSearchParams()
      const tab = params.get('tab') ?? 'a'
      return (
        <>
          <button type="button" onClick={() => setParams({ tab: 'a' })}>to a</button>
          <button type="button" onClick={() => setParams({ tab: 'b' })}>to b</button>
          {tab === 'a' ? <SiteEditTabBoundary fallback={<div>loading</div>}><div>tab a</div></SiteEditTabBoundary> : null}
          {tab === 'b' ? <SiteEditTabBoundary fallback={<div>loading</div>}><Flaky /></SiteEditTabBoundary> : null}
        </>
      )
    }
    const reload = vi.fn()
    renderWithProviders(<RouteErrorBoundary reload={reload}><Harness /></RouteErrorBoundary>, ['/x'])

    fireEvent.click(screen.getByRole('button', { name: 'to b' }))
    expect(await screen.findByText('该设置页加载失败')).toBeInTheDocument()
    // 别的标签仍可切换显示，不刷新整页。
    fireEvent.click(screen.getByRole('button', { name: 'to a' }))
    expect(await screen.findByText('tab a')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'to b' }))
    fireEvent.click(await screen.findByRole('button', { name: '重试' }))
    expect(await screen.findByText('flaky loaded')).toBeInTheDocument()
    expect(attempts).toBe(2)
    expect(reload).not.toHaveBeenCalled()
  })

  it('keeps the conditional origin draft across tab switches and guards leaving (SITE-CURRENT-02)', async () => {
    authenticate()
    const routing = {
      site_id: 'site-1', version: 3, updated_at: '2026-01-01T00:00:00Z',
      document: {
        schema: 'cdnca.edge.origin-route/v1', ingress_source_enabled: false, default_pool_id: 'pool-a', routes: [],
        pools: [{ id: 'pool-a', balance_method: 'round_robin', endpoints: [{ id: 'origin-a', host: '192.0.2.10', port: 443, weight: 100 }] }],
        retry: { methods: ['GET', 'HEAD'], max_attempts: 2, connect_timeout_ms: 100, read_timeout_ms: 100, total_budget_ms: 300 },
      },
    }
    let routingCalls = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.endsWith('/v1/sites/site-1')) return Promise.resolve(json(detail))
      // The switch saves at once; the save stays in flight, so the page keeps it as unsaved
      if (url.includes('origin-routing') && init?.method && init.method !== 'GET') return new Promise<Response>(() => undefined)
      if (url.includes('origin-routing')) {
        routingCalls += 1
        return Promise.resolve(json(routing))
      }
      return Promise.resolve(json({ items: [] }))
    })
    renderWithProviders(
      <RouteErrorBoundary>
        <Routes><Route path="/site/:id/edit" element={<SiteEditPage />} /></Routes>
      </RouteErrorBoundary>,
      ['/site/site-1/edit?tab=origin&conditional=1'],
    )
    const toggle = await screen.findByRole('switch', { name: '使用入口 IP 回源' }, { timeout: 5000 })
    fireEvent.click(toggle)
    await waitFor(() => expect(useNavigationGuardStore.getState().dirty).toBe(true))
    fireEvent.click(screen.getByRole('tab', { name: '基本配置' }))
    await waitFor(() => expect(screen.getByRole('tab', { name: '基本配置' })).toHaveAttribute('aria-selected', 'true'))
    expect(useNavigationGuardStore.getState().dirty).toBe(true)
    fireEvent.click(screen.getByRole('tab', { name: '回源设置' }))
    await waitFor(() => expect(toggle).toHaveAttribute('aria-checked', 'true'))
    expect(routingCalls).toBe(1)
  })
})
