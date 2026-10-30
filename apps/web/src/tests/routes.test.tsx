import { screen } from '@testing-library/react'
import { afterEach, vi } from 'vitest'
import { useLocation } from 'react-router-dom'

import { AppRoutes } from '../App'
import { dashboardApi } from '../api/dashboard'
import { identityVerificationReviewCaseApi } from '../api/identityVerificationReviewCase'
import { identityVerificationReviewDecisionApi } from '../api/identityVerificationReviewDecision'
import { identityVerificationReviewQueueApi } from '../api/identityVerificationReviewQueue'
import { nodesApi } from '../api/nodes'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const siteDetail = {
  id: 'site-1',
  version: 1,
  owner: { id: 'tenant-1', display_name: 'jason' },
  created_at: '2026-07-21T08:00:00Z',
  updated_at: '2026-07-22T08:00:00Z',
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
    https_listen_ports: ['443'],
    ipv6_enabled: false,
    tls_protocols: ['TLSv1.2', 'TLSv1.3'],
    origins: ['192.0.2.10:80'],
    cname: 'edge.example.net',
    https_enabled: true,
    enabled: true,
    status: 'active',
    sync_status: 'synced',
    is_default: false,
  },
}

const tenantDashboardPermissions = [
  'sites.read',
  'certificates.read',
  'billing.account.read',
  'package_subscriptions.read',
  'traffic_packages.read',
  'announcements.read',
  'jobs.read',
]

const identityReviewPermissions = [
  'identity_verification.read',
  'identity_verification.review',
]
const identityReviewCaseID = '33333333-3333-4333-8333-333333333333'

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="location">{location.pathname}</output>
}

afterEach(() => {
  sessionStorage.clear()
  return i18n.changeLanguage('zh-CN')
})

describe('role routes', () => {
  it.each([
    [
      '/admin-home',
      principal({
        scope_kind: 'platform', tenant_id: null, username: 'admin', display_name: 'admin',
        roles: ['platform_admin'], permissions: ['platform.admin'],
      }),
    ],
    ['/home', principal({ permissions: tenantDashboardPermissions })],
  ])('keeps %s role routing functional in the pseudo locale', async (path, actor) => {
    await i18n.changeLanguage('qps-ploc')
    useSessionStore.getState().setSession(authResponse(actor), actor)

    renderWithProviders(<AppRoutes />, [path])

    expect(
      (await screen.findAllByRole('region', { name: /^［.+］$/ }, { timeout: 5_000 })).length,
    ).toBeGreaterThan(0)
  })

  it('redirects a platform principal away from the user home', async () => {
    const admin = principal({
      scope_kind: 'platform',
      tenant_id: null,
      username: 'admin',
      display_name: 'admin',
      roles: ['platform_admin'],
      permissions: ['platform.admin'],
    })
    useSessionStore.getState().setSession(authResponse(admin), admin)

    renderWithProviders(<AppRoutes />, ['/home'])

    expect(await screen.findByRole('heading', { name: '运营数据' })).toBeInTheDocument()
  })

  it('redirects a tenant principal away from the administrator home', async () => {
    const user = principal({ permissions: tenantDashboardPermissions })
    useSessionStore.getState().setSession(authResponse(user), user)
    const dashboardSpy = vi.spyOn(dashboardApi, 'tenant')
      .mockImplementation(() => new Promise<never>(() => undefined))
    const adminDashboardSpy = vi.spyOn(dashboardApi, 'admin')

    renderWithProviders(<><AppRoutes /><LocationProbe /></>, ['/admin-home'])

    expect(await screen.findByTestId('location')).toHaveTextContent('/home')
    expect(await screen.findByRole('region', { name: '服务概览' }, { timeout: 5_000 })).toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: '服务概览' })).toHaveClass('ant-menu-item-selected')
    expect(screen.getByText('jason')).toBeInTheDocument()
    expect(adminDashboardSpy).not.toHaveBeenCalled()
    expect(dashboardSpy).toHaveBeenCalledOnce()
    expect(dashboardSpy).toHaveBeenCalledWith(
      'memory-only-access-token', 'today', 'Asia/Shanghai', expect.any(AbortSignal), {},
    )
  })

  it('lazy-loads the website list with its dynamic breadcrumb', async () => {
    const user = principal({ permissions: ['identity.self.read', 'sites.read'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ items: [], total: 0, page: 1, limit: 10 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    renderWithProviders(<AppRoutes />, ['/site/list'])

    expect(
      await screen.findByRole('heading', { name: '网站列表' }, { timeout: 5_000 }),
    ).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/网站管理/网站列表')
  })

  it.each([
    ['tenant', principal({ permissions: ['sites.read'] }), '/v1/site-publications?limit=20'],
    [
      'platform',
      principal({
        scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
        permissions: ['edge_publications.read'],
      }),
      `/v1/admin/site-publications?scope_id=018cc251-f400-7def-8000-000000000050&limit=20`,
    ],
  ])('protects and loads the %s publication route with audience-specific permission', async (_, actor, expectedURL) => {
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      items: [], current_source_revision: 1,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    const path = actor.scope_kind === 'platform'
      ? '/site/publications?target_scope_id=018cc251-f400-7def-8000-000000000050'
      : '/site/publications'

    renderWithProviders(<AppRoutes />, [path])

    expect(await screen.findByRole('heading', { name: '站点与四层发布' }, { timeout: 5_000 })).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/网站管理/配置发布')
    expect(fetchSpy.mock.calls.some(([url]) => String(url) === expectedURL)).toBe(true)
  })

  it.each(['/site/site-1/edit', '/site/list/site-1'])(
    'loads the website editor through %s with its dynamic breadcrumb',
    async (path) => {
      const user = principal({ permissions: ['identity.self.read', 'sites.read'] })
      useSessionStore.getState().setSession(authResponse(user), user)
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
        new Response(JSON.stringify(siteDetail), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )

      renderWithProviders(<AppRoutes />, [path])

      expect(
        await screen.findByRole('heading', { name: 'www.example.com' }, { timeout: 5_000 }),
      ).toBeInTheDocument()
      expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/网站管理/网站列表')
      expect(fetchSpy).toHaveBeenCalledWith(
        '/v1/sites/site-1',
        expect.objectContaining({ credentials: 'include' }),
      )
    },
  )

  it.each([
    [
      'valid',
      JSON.stringify({
        action: 'disable',
        targets: [{ id: 'site-1', domain: 'www.example.com', version: 1 }],
        input: { action: 'disable', items: [{ id: 'site-1', expected_version: 1 }] },
        body: JSON.stringify({
          action: 'disable',
          items: [{ id: 'site-1', expected_version: 1 }],
        }),
        key: 'site-batch-disable-pending',
      }),
      '批量操作结果待确认',
    ],
    ['corrupted', JSON.stringify({ action: 'disable', key: 'damaged' }), '待确认批量操作无法恢复'],
  ])(
    'keeps the direct legacy site editor route read-only for a %s batch retry lock',
    async (_, storedLock, warning) => {
      const user = principal({ permissions: ['identity.self.read', 'sites.read'] })
      useSessionStore.getState().setSession(authResponse(user), user)
      sessionStorage.setItem(
        `cdnca:site-batch-retry:${user.scope_kind}:${user.scope_id}:${user.tenant_id}:${user.user_id}`,
        storedLock,
      )
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
        new Response(JSON.stringify(siteDetail), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )

      renderWithProviders(<AppRoutes />, ['/site/list/site-1'])

      expect(
        await screen.findByRole('heading', { name: 'www.example.com' }, { timeout: 5_000 }),
      ).toBeInTheDocument()
      expect(screen.getByText(warning, { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
      expect((await screen.findAllByLabelText('域名'))[0]).toBeDisabled()
      expect(screen.getByRole('button', { name: '新增源站信息' })).toBeDisabled()
      // fix-siteinstant：网站编辑改为即改即生效，没有保存条；锁定时控件禁用且不发 PATCH。
      expect(screen.queryByRole('button', { name: '保存更改' })).toBeNull()
      expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(false)
    },
  )

  it('lazy-loads the forwarding list with its dynamic breadcrumb', async () => {
    const user = principal({ permissions: ['identity.self.read', 'streams.read'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ items: [], total: 0, page: 1, limit: 20 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    renderWithProviders(<AppRoutes />, ['/stream/list'])

    expect(await screen.findByRole('heading', { name: '转发列表' }, { timeout: 5_000 })).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/四层转发/转发列表')
  })

  it('treats the removed billing and package routes as missing pages', async () => {
    const admin = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'],
    })
    useSessionStore.getState().setSession(authResponse(admin), admin)
    for (const path of ['/package/basic', '/finance/order', '/account/balance', '/user-package/usage', '/sys/themes']) {
      const view = renderWithProviders(<AppRoutes />, [path])
      expect(await screen.findByText('页面不存在')).toBeInTheDocument()
      view.unmount()
    }
  })

  it('lazy-loads node realtime status for an authorized administrator', async () => {
    const admin = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
      permissions: ['nodes.read'],
    })
    useSessionStore.getState().setSession(authResponse(admin), admin)
    vi.spyOn(nodesApi, 'list').mockImplementation(() => new Promise<never>(() => undefined))

    renderWithProviders(<AppRoutes />, ['/node/realtime'])

    expect(await screen.findByRole('heading', { name: '节点实时监控' }, { timeout: 5_000 })).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/节点管理/实时监控')
  })

  it('lazy-loads self identity verification for an authorized tenant', async () => {
    const user = principal({ permissions: ['identity_verification.self.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)

    renderWithProviders(<AppRoutes />, ['/account/verification'])

    expect(await screen.findByRole('heading', { name: '实名认证' })).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/账户中心/实名认证')
  })

  it('lazy-loads the identity verification review queue for an authorized tenant', async () => {
    const user = principal({ permissions: identityReviewPermissions })
    useSessionStore.getState().setSession(authResponse(user), user)
    vi.spyOn(identityVerificationReviewQueueApi, 'list')
      .mockImplementation(() => new Promise<never>(() => undefined))

    renderWithProviders(<AppRoutes />, ['/sys/identity-verification'])

    expect(await screen.findByRole('heading', { name: '实名认证审核' })).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/系统管理/实名认证审核')
  })

  it.each([
    [`/sys/identity-verification/${identityReviewCaseID}`, '实名认证案件', 'case'],
    [`/sys/identity-verification/${identityReviewCaseID}/decision`, '实名认证审批', 'decision'],
  ] as const)('lazy-loads %s for an authorized tenant', async (path, heading, kind) => {
    const user = principal({ permissions: identityReviewPermissions })
    useSessionStore.getState().setSession(authResponse(user), user)
    if (kind === 'case') {
      vi.spyOn(identityVerificationReviewCaseApi, 'getCase')
        .mockImplementation(() => new Promise<never>(() => undefined))
    } else {
      vi.spyOn(identityVerificationReviewDecisionApi, 'getCase')
        .mockImplementation(() => new Promise<never>(() => undefined))
    }

    renderWithProviders(<AppRoutes />, [path])

    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/系统管理/实名认证审核')
  })

  it.each([
    ['missing read permission', ['identity_verification.review']],
    ['missing review permission', ['identity_verification.read']],
  ])('denies identity review locally with zero requests when %s', async (_name, permissions) => {
    const user = principal({ permissions })
    useSessionStore.getState().setSession(authResponse(user), user)
    const listSpy = vi.spyOn(identityVerificationReviewQueueApi, 'list')
    const caseSpy = vi.spyOn(identityVerificationReviewCaseApi, 'getCase')
    const decisionSpy = vi.spyOn(identityVerificationReviewDecisionApi, 'getCase')

    renderWithProviders(<AppRoutes />, ['/sys/identity-verification'])

    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(listSpy).not.toHaveBeenCalled()
    expect(caseSpy).not.toHaveBeenCalled()
    expect(decisionSpy).not.toHaveBeenCalled()
  })

  it('keeps the identity review workflow tenant-only with zero requests', async () => {
    const admin = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
      permissions: identityReviewPermissions,
    })
    useSessionStore.getState().setSession(authResponse(admin), admin)
    const listSpy = vi.spyOn(identityVerificationReviewQueueApi, 'list')

    renderWithProviders(<AppRoutes />, ['/sys/identity-verification'])

    expect(await screen.findByText('页面不存在')).toBeInTheDocument()
    expect(listSpy).not.toHaveBeenCalled()
  })

  it('protects and lazy-loads the administrator node inventory', async () => {
    const admin = principal({
      scope_kind: 'platform', tenant_id: null, username: 'admin', display_name: 'admin',
      roles: ['platform_owner'], permissions: ['nodes.read', 'nodes.manage'],
    })
    useSessionStore.getState().setSession(authResponse(admin), admin)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ items: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    renderWithProviders(<AppRoutes />, ['/node/list'])

    expect(await screen.findByRole('heading', { name: '节点列表' }, { timeout: 5_000 })).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/节点管理/节点列表')
  })

  it('redirects a tenant away from the administrator node inventory', async () => {
    const user = principal({ permissions: tenantDashboardPermissions })
    useSessionStore.getState().setSession(authResponse(user), user)
    const dashboardSpy = vi.spyOn(dashboardApi, 'tenant')
      .mockImplementation(() => new Promise<never>(() => undefined))
    const nodesSpy = vi.spyOn(nodesApi, 'list')

    renderWithProviders(<><AppRoutes /><LocationProbe /></>, ['/node/list'])

    expect(await screen.findByTestId('location')).toHaveTextContent('/home')
    expect(await screen.findByRole('region', { name: '服务概览' }, { timeout: 5_000 })).toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: '服务概览' })).toHaveClass('ant-menu-item-selected')
    expect(nodesSpy).not.toHaveBeenCalled()
    expect(dashboardSpy).toHaveBeenCalledOnce()
    expect(dashboardSpy).toHaveBeenCalledWith(
      'memory-only-access-token', 'today', 'Asia/Shanghai', expect.any(AbortSignal), {},
    )
  })
})
