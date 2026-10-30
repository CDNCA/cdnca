import { lazy, Suspense, useEffect } from 'react'
import { Button, Result, Spin } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { Navigate, Outlet, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import './i18n/dnsConfig'

import {
  homeForPrincipal,
  principalJustTransitioned,
  roleForPrincipal,
  useSessionStore,
  type AppRole,
} from './auth/session'
import { loginDestination, safeLoginReturnTo } from './auth/loginNavigation'
import { loadFullResources } from './i18n'
import type { SystemConfigurationCategory } from './api/systemConfiguration'
import { marketAccess } from './api/marketAccess'
import { fetchRuntimeFeatures, type RuntimeFeature } from './api/runtimeFeatures'
import { runtimeFeaturesQueryKey } from './components/useRuntimeFeatures'
import { RouteErrorBoundary, RouteStatusPage } from './components/RouteErrorBoundary'
import type { SystemGlobalSettingsTab } from './pages/SystemGlobalSettingsPage'
import {
  adminObservedUserBlockedPaths,
  controlUpgradesReadPermission,
  firewallReadPermission,
  jobsReadPermission,
  nodeSchedulingReadPermission,
  observedRouteAliases,
} from './routes/routePolicy'
import { useFeedback } from '@cdnca/ui'

// 首包只留会话恢复与路由：控制台壳（菜单及其各页命名空间、全部 i18n 资源）、首页、
// 登录/找回密码/注册页和横幅都按需加载。进入受保护页面时提前拉壳、落在登录或找回密码
// 路径上时提前拉对应页面，避免等会话恢复完、路由渲染后才开始下载。
let appShellLoad: Promise<typeof import('./components/AppShell')> | undefined
const loadAppShell = () => {
  appShellLoad ??= Promise.all([import('./components/AppShell'), loadFullResources()]).then(([module]) => module)
  appShellLoad.catch(() => { appShellLoad = undefined })
  return appShellLoad
}
const AppShell = lazy(() => loadAppShell().then((module) => ({ default: module.AppShell })))
const loadLoginPage = () => import('./pages/LoginPage')
const loadRecoveryRequestPage = () => import('./pages/account-recovery/RequestPage')
const loadRecoveryResetPage = () => import('./pages/account-recovery/ResetPage')
const LoginPage = lazy(() => loadLoginPage().then((module) => ({ default: module.LoginPage })))
const AccountRecoveryRequestPage = lazy(() => loadRecoveryRequestPage().then((module) => ({ default: module.AccountRecoveryRequestPage })))
const AccountRecoveryResetPage = lazy(() => loadRecoveryResetPage().then((module) => ({ default: module.AccountRecoveryResetPage })))
const shellFreePages: Record<string, (() => Promise<unknown>) | undefined> = {
  '/login': loadLoginPage,
  '/register': undefined,
  '/forgot-password': loadRecoveryRequestPage,
  '/reset-password': loadRecoveryResetPage,
  '/forget-password': undefined,
}
if (typeof window !== 'undefined') {
  const initialPath = window.location.pathname.replace(/^\/dashboard(?=\/|$)/, '') || '/'
  if (!Object.hasOwn(shellFreePages, initialPath)) void loadAppShell()
  else void shellFreePages[initialPath]?.()?.catch(() => undefined)
}
const AdminHomePage = lazy(() => import('./pages/AdminHomePage').then((module) => ({ default: module.AdminHomePage })))
const UserHomePage = lazy(() => import('./pages/UserHomePage').then((module) => ({ default: module.UserHomePage })))
const RegisterPage = lazy(() => import('./pages/RegisterPage').then((module) => ({ default: module.RegisterPage })))
const ImpersonationStatusBanner = lazy(() => import('./components/ImpersonationStatusBanner').then((module) => ({ default: module.ImpersonationStatusBanner })))
const InstallationLockBanner = lazy(() => import('./components/InstallationLockBanner').then((module) => ({ default: module.InstallationLockBanner })))

const SiteListPage = lazy(() => import('./pages/SiteListPage'))
const SitePublicationsPage = lazy(() => import('./pages/SitePublicationsPage'))
const SiteProtocolBatchPage = lazy(() => import('./pages/site-protocols/SiteProtocolBatchPage'))
const SiteEditPage = lazy(() => import('./pages/SiteEditPage'))
const UserListPage = lazy(() => import('./pages/UserListPage'))
const AccountUserPage = lazy(() => import('./pages/AccountUserPage'))
const StreamListPage = lazy(() => import('./pages/StreamListPage'))
const StreamDetailPage = lazy(() => import('./pages/StreamDetailPage'))
const AccountIdentityVerificationPage = lazy(() => import('./pages/AccountIdentityVerificationPage'))
const AccountMessagesPage = lazy(() => import('./pages/AccountMessagesPage'))
const AccountSubscriptionsPage = lazy(() => import('./pages/AccountSubscriptionsPage'))
const AccountLogPage = lazy(() => import('./pages/AccountLogPage'))
const IdentitySessionsPage = lazy(() => import('./pages/IdentitySessionsPage'))
const LogCenterPage = lazy(() => import('./pages/LogCenterPage'))
const FrontendLogPage = lazy(() => import('./pages/FrontendLogPage'))
const AdminMessageQueryPage = lazy(() => import('./pages/AdminMessageQueryPage'))
const NodeListPage = lazy(() => import('./pages/NodeListPage'))
const NodeInventoryDetailPage = lazy(() => import('./pages/NodeInventoryDetailPage'))
const NodeIsolationPage = lazy(() => import('./pages/NodeIsolationPage'))
const NodeLineGroupsPage = lazy(() => import('./pages/NodeLineGroupsPage'))
const NodeL2TopologyPage = lazy(() => import('./pages/NodeL2TopologyPage'))
const NodeL2TopologyDetailPage = lazy(() => import('./pages/NodeL2TopologyDetailPage'))
const AccountApiKeysPage = lazy(() => import('./pages/AccountApiKeysPage'))
const SecurityPoliciesPage = lazy(() => import('./pages/SecurityPoliciesPage'))
const RulePacksPage = lazy(() => import('./pages/RulePacksPage'))
const FirewallPoliciesPage = lazy(() => import('./pages/FirewallPoliciesPage'))
const FirewallActionPoliciesPage = lazy(() => import('./pages/FirewallActionPoliciesPage'))
const UrlAuthPoliciesPage = lazy(() => import('./pages/UrlAuthPoliciesPage'))
const NodeDnsPage = lazy(() => import('./pages/NodeDnsPage'))
const CertificateListPage = lazy(() => import('./pages/CertificateListPage'))
const CacheOperationsPage = lazy(() => import('./pages/CacheOperationsPage'))
const SiteRealtimeMonitorPage = lazy(() => import('./pages/SiteRealtimeMonitorPage'))
const L4RealtimeMonitorPage = lazy(() => import('./pages/L4RealtimeMonitorPage'))
const L4AccessLogPage = lazy(() => import('./pages/L4SessionPanels').then((module) => ({ default: module.L4AccessLogPage })))
const L4LiveConnectionsPage = lazy(() => import('./pages/L4SessionPanels').then((module) => ({ default: module.L4LiveConnectionsPage })))
const SiteAnalysisPage = lazy(() => import('./pages/SiteAnalysisPage'))
const JA4BlockWorkflowsPage = lazy(() => import('./pages/JA4BlockWorkflowsPage'))
const SiteAccessLogPage = lazy(() => import('./pages/SiteAccessLogPage'))
const SiteBlockLogPage = lazy(() => import('./pages/SiteBlockLogPage'))
const SecurityBansPage = lazy(() => import('./pages/SecurityBansPage'))
const SecurityIPListsPage = lazy(() => import('./pages/SecurityIPListsPage'))
const SiteBlockEventLogPage = lazy(() => import('./pages/SiteBlockEventLogPage'))
const CCCoordinationPage = lazy(() => import('./pages/CCCoordinationPage'))
const WafLogsPage = lazy(() => import('./pages/WafLogsPage'))
const AdminTasksPage = lazy(() => import('./pages/AdminTasksPage'))
const SystemSettingsPage = lazy(() => import('./pages/SystemSettingsPage'))
const SystemGlobalSettingsPage = lazy(() => import('./pages/SystemGlobalSettingsPage'))
const systemSettingsTabs = ['system', 'cleanup', 'account', 'payment', 'mail', 'notification', 'other'] as const satisfies readonly SystemGlobalSettingsTab[]
const ErrorPagesPage = lazy(() => import('./pages/ErrorPagesPage'))
const DnsReconcilePage = lazy(() => import('./pages/DnsReconcilePage'))
const AnnouncementManagementPage = lazy(() => import('./pages/AnnouncementManagementPage'))
const CertificateOrdersPage = lazy(() => import('./pages/CertificateOrdersPage'))
const CachePolicyHistoryPage = lazy(() => import('./pages/CachePolicyHistoryPage'))
const IdentityVerificationReviewQueuePage = lazy(() => import('./pages/IdentityVerificationReviewQueuePage'))
const AdminIdentityReviewPage = lazy(() => import('./pages/AdminIdentityReviewPage'))
const IdentityVerificationReviewCasePage = lazy(() => import('./pages/IdentityVerificationReviewCasePage'))
const IdentityVerificationReviewDecisionPage = lazy(() => import('./pages/IdentityVerificationReviewDecisionPage'))
const CnameAllocationsPage = lazy(() => import('./pages/CnameAllocationsPage'))
const DnsHubPage = lazy(() => import('./pages/dns-hub/DnsHubPage'))
const OriginAuthCredentialsPage = lazy(() => import('./pages/OriginAuthCredentialsPage'))
const OriginAuthRulesPage = lazy(() => import('./pages/OriginAuthRulesPage'))
const OriginAuthPublicationsPage = lazy(() => import('./pages/OriginAuthPublicationsPage'))
const PluginWebhooksPage = lazy(() => import('./pages/plugin-webhooks/PluginWebhooksRoute'))
const PluginMarketPage = lazy(() => import('./pages/plugin-market/PluginMarketPage'))
const ControlUpgradesPage = lazy(() => import('./pages/ControlUpgradesPage'))
const NodeRealtimePage = lazy(() => import('./pages/NodeRealtimePage'))
const NodeMonitorSettingsPage = lazy(() => import('./pages/NodeMonitorSettingsPage'))
const DDoSProtectionSettingsPage = lazy(() => import('./pages/DDoSProtectionSettingsPage'))
const AccessLogFieldsSettingsPage = lazy(() => import('./pages/AccessLogFieldsSettingsPage'))
const GatewayManagementPage = lazy(() => import('./pages/GatewayManagementPage'))
const NodeMarketPage = lazy(() => import('./pages/node-market/NodeMarketPage'))
const PluginStorePage = lazy(() => import('./pages/market/MarketStorePage'))
const PluginUIPage = lazy(() => import('./pluginui/PluginPage'))
const AdminAccessPage = lazy(() => import('./pages/AdminAccessPage'))
const AdminInboxPage = lazy(() => import('./pages/AdminInboxPage'))
const IPIntelUpdatesPage = lazy(() => import('./pages/ip-intel-updates/IPIntelUpdatesPage'))
const ProbeDNSPupPage = lazy(() => import('./pages/probe-dnspup/ProbeDNSPupPage'))
const PluginProvidersPage = lazy(() => import('./pages/plugin-providers/PluginProvidersPage'))
const DomainSecurityPage = lazy(() => import('./pages/domain-trust/DomainSecurityPage'))
const AccountDomainsPage = lazy(() => import('./pages/domain-trust/AccountDomainsPage'))
const TicketsPage = lazy(() => import('./pages/tickets/TicketsPage'))
const ApprovalCenterPage = lazy(() => import('./pages/ApprovalCenterPage'))

const systemConfigurationRoutes = [
  { path: '/config/nginx', category: 'nginx' },
  { path: '/config/res', category: 'resources' },
  { path: '/config/default', category: 'defaults' },
  { path: '/config/error', category: 'error_pages' },
] satisfies Array<{ path: string; category: SystemConfigurationCategory }>

function RouteFallback() {
  const { t } = useTranslation('common')
  return (
    <div className="route-loading" aria-label={t('pageLoading')}>
      <Spin size="small" />
    </div>
  )
}

function ProtectedRoute() {
  const status = useSessionStore((state) => state.status)
  const location = useLocation()
  const returnTo = `${location.pathname}${location.search}${location.hash}`
  return status === 'authenticated'
    ? <Outlet />
    : <Navigate to="/login" replace state={{ returnTo }} />
}

function PublicOnlyRoute() {
  const principal = useSessionStore((state) => state.principal)
  const location = useLocation()
  const passwordChanged = (location.state as { passwordChanged?: boolean } | null)?.passwordChanged
  const returnTo = safeLoginReturnTo(location.state)
  return principal && !passwordChanged
    ? <Navigate to={loginDestination(returnTo, homeForPrincipal(principal))} replace />
    : <Outlet />
}

// fp-role ID-01：另一角色的首页（旧书签）静默换成自己的首页；真正越过角色边界才提示。
function RoleMismatchRedirect({ role, to }: { role: AppRole; to: string }) {
  const feedback = useFeedback()
  const { t } = useTranslation('common')
  const { pathname } = useLocation()
  const roleHome = pathname === '/home' || pathname === '/admin-home'

  const impersonating = useSessionStore((state) => Boolean(state.principal?.impersonation))
  useEffect(() => {
    // 代登录中、或刚进入/退出代登录时换了身份：静默回自己的首页。
    if (!roleHome && !impersonating && !principalJustTransitioned()) {
      void feedback.error(t(role === 'admin' ? 'adminPermissionRequired' : 'userPermissionRequired'))
    }
  }, [feedback, impersonating, role, roleHome, t])

  return <Navigate to={to} replace />
}

function RoleRoute({
  role,
  mismatch = 'redirect',
  children,
}: {
  role: AppRole
  mismatch?: 'redirect' | 'not-found'
  children?: React.ReactNode
}) {
  const principal = useSessionStore((state) => state.principal)
  if (!principal) return <Navigate to="/login" replace />
  if (roleForPrincipal(principal) !== role) {
    return mismatch === 'not-found'
      ? <NotFoundPage />
      : <RoleMismatchRedirect role={role} to={homeForPrincipal(principal)} />
  }
  return children ?? <Outlet />
}

function PermissionRoute({
  permission,
  platformAdminFallback = true,
  children,
}: {
  permission: string
  platformAdminFallback?: boolean
  children: React.ReactNode
}) {
  const principal = useSessionStore((state) => state.principal)
  if (!principal) return <Navigate to="/login" replace />
  return principal.permissions.includes(permission) ||
    (platformAdminFallback && principal.permissions.includes('platform.admin'))
    ? children
    : <RouteStatusPage status="403" />
}

// InstallationDNSRoute (RB-U01 子项，审测卡 11): 节点管理 > DNS配置 is the
// installation-wide platform DNS (platform scope only). A tenant who types the
// URL gets a no-permission page with the way to their own DNS API; the page
// and its platform requests are never mounted.
function InstallationDNSRoute({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation('dnsConfig')
  const principal = useSessionStore((state) => state.principal)
  const navigate = useNavigate()
  if (!principal) return <Navigate to="/login" replace />
  if (principal.scope_kind !== 'platform') {
    return <Result status="403" title="403" subTitle={t('installationOnly.description')} extra={
      principal.permissions.includes('dns.read')
        ? <Button type="primary" onClick={() => navigate('/site/list', { state: { siteSubnav: 'dnsApi' } })}>{t('installationOnly.ownDnsApi')}</Button>
        : <Button type="primary" onClick={() => navigate('/')}>{t('installationOnly.home')}</Button>
    } />
  }
  return <PermissionRoute permission="dns.read" platformAdminFallback={false}>{children}</PermissionRoute>
}

// RuntimeRoute applies the menu's requiredRuntime gate to a typed URL: when
// GET /v1/runtime-features does not report the runtime (or fails, which the
// menu also treats as off) the page is replaced by "feature not enabled"
// instead of mounting a page whose API answers 404.
function RuntimeRoute({ feature, detailKey = 'featureNotEnabledDetail', children }: {
  feature: RuntimeFeature, detailKey?: 'featureNotEnabledDetail' | 'originAuthNotEnabledDetail', children: React.ReactNode
}) {
  const { t } = useTranslation('common')
  const accessToken = useSessionStore((state) => state.accessToken)
  const features = useQuery({
    queryKey: runtimeFeaturesQueryKey,
    queryFn: () => fetchRuntimeFeatures(accessToken ?? ''),
    enabled: Boolean(accessToken),
    staleTime: Infinity,
    retry: false,
  })
  if (features.isPending && accessToken) return <RouteFallback />
  if (features.data?.includes(feature)) return children
  return <Result status="info" title={t('featureNotEnabled')} subTitle={t(detailKey)} />
}

// MarketRoute admits any marketplace code (migration 296) or, for one release,
// the old sites.manage / platform.admin gate (api/marketAccess.ts).
function MarketRoute({ children }: { children: React.ReactNode }) {
  const principal = useSessionStore((state) => state.principal)
  if (!principal) return <Navigate to="/login" replace />
  return marketAccess(principal).browse ? children : <RouteStatusPage status="403" />
}

function RolePermissionRoute({
  adminPermission,
  userPermission,
  children,
}: {
  adminPermission: string
  userPermission: string
  children: React.ReactNode
}) {
  const principal = useSessionStore((state) => state.principal)
  if (!principal) return <Navigate to="/login" replace />
  const admin = roleForPrincipal(principal) === 'admin'
  const requiredPermission = admin ? adminPermission : userPermission
  const allowed = principal.permissions.includes(requiredPermission) ||
    (admin && principal.permissions.includes('platform.admin'))
  return allowed ? children : <RouteStatusPage status="403" />
}

function IdentitySessionOwnerRoute({ children }: { children: React.ReactNode }) {
  const principal = useSessionStore((state) => state.principal)
  if (!principal) return <Navigate to="/login" replace />
  const validOwner = principal.scope_kind === 'tenant'
    ? Boolean(principal.scope_id) && Boolean(principal.tenant_id)
    : Boolean(principal.scope_id) && principal.tenant_id === null
  return validOwner ? children : <RouteStatusPage status="403" />
}

// ADMIN-CURRENT-08: the adaptive WAF budget moved to 防火墙配置 → WAF全局配置; the old
// combined "user" tab split into 账号与安全 / 认证与支付.
const retiredSystemSettingsTabs: Readonly<Record<string, string>> = {
  wafAdapt: '/config/waf',
  user: '/sys/setting?tab=account',
}

function SystemGlobalSettingsRoute() {
  const [searchParams] = useSearchParams()
  const tab = searchParams.get('tab')
  const retired = tab ? retiredSystemSettingsTabs[tab] : undefined
  if (retired) return <Navigate to={retired} replace />
  return <SystemGlobalSettingsPage initialTab={systemSettingsTabs.find((item) => item === tab)} />
}

function HomeRedirect() {
  const principal = useSessionStore((state) => state.principal)
  return <Navigate to={principal ? homeForPrincipal(principal) : '/login'} replace />
}

function NotFoundPage() {
  return <RouteStatusPage status="404" />
}

function LegacySiteEditRedirect() {
  const { id } = useParams()
  return <Navigate to={id ? `/site/${encodeURIComponent(id)}/edit` : '/site/list'} replace />
}

// Account pages removed from the tenant console. Old links land on the
// closest remaining page: the log centre
// moves into 日志查询; members, custom roles and the theme page go to the
// account home. Their back ends stay; the admin
// log centre is /sys/log-center.
const retiredAccountRoutes: readonly { from: string; to: string }[] = [
  { from: '/account/log-center', to: '/account/log' },
  { from: '/account/members', to: '/account/user' },
  { from: '/account/custom-roles', to: '/account/user' },
  { from: '/account/theme', to: '/account/user' },
]

function AliasRedirect({ to }: { to: string }) {
  const location = useLocation()
  return <Navigate to={`${to}${location.search}${location.hash}`} replace />
}

function LegacyRecoveryRedirect() {
  const location = useLocation()
  const target = location.hash === '' ? '/forgot-password' : '/reset-password'
  return <Navigate to={`${target}${location.search}${location.hash}`} replace />
}

function ImpersonationRouteBoundary() {
  return (
    <>
      <Suspense fallback={null}>
        <ImpersonationStatusBanner />
        <InstallationLockBanner />
      </Suspense>
      <Outlet />
    </>
  )
}

export function AppRoutes() {
  return (
    <RouteErrorBoundary>
      <Routes>
      <Route element={<PublicOnlyRoute />}>
        <Route path="/login" element={<Suspense fallback={<RouteFallback />}><LoginPage /></Suspense>} />
        <Route path="/register" element={<Suspense fallback={<RouteFallback />}><RegisterPage /></Suspense>} />
      </Route>
      <Route path="/forgot-password" element={<Suspense fallback={<RouteFallback />}><AccountRecoveryRequestPage /></Suspense>} />
      <Route path="/reset-password" element={<Suspense fallback={<RouteFallback />}><AccountRecoveryResetPage /></Suspense>} />
      <Route path="/forget-password" element={<LegacyRecoveryRedirect />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<Suspense fallback={<RouteFallback />}><AppShell /></Suspense>}>
          <Route element={<ImpersonationRouteBoundary />}>
          <Route index element={<HomeRedirect />} />
          {observedRouteAliases
            .filter((alias) => alias.role === undefined)
            .map((alias) => (
              <Route key={alias.from} path={alias.from} element={<AliasRedirect to={alias.to} />} />
            ))}
          {retiredAccountRoutes.map((route) => (
            <Route key={route.from} path={route.from} element={<AliasRedirect to={route.to} />} />
          ))}
          <Route
            path="/node/list/:id"
            element={
              <RoleRoute role="admin" mismatch="not-found">
                <PermissionRoute permission="nodes.read">
                  <Suspense fallback={<RouteFallback />}>
                    <NodeInventoryDetailPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/node/line-group"
            element={
              <RoleRoute role="admin" mismatch="not-found">
                <PermissionRoute permission={nodeSchedulingReadPermission} platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <NodeLineGroupsPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route element={<RoleRoute role="admin" />}>
            {observedRouteAliases
              .filter((alias) => alias.role === 'admin')
              .map((alias) => (
                <Route key={alias.from} path={alias.from} element={<AliasRedirect to={alias.to} />} />
              ))}
            <Route path="/admin-home" element={<Suspense fallback={<RouteFallback />}><AdminHomePage /></Suspense>} />
            <Route
              path="/sys/user"
              element={
                <Suspense fallback={<RouteFallback />}>
                  <UserListPage />
                </Suspense>
              }
            />
            {/* Custom roles are tenant-only (/v1/custom-rbac rejects platform sessions);
                platform administrator types are fixed and shown on the user list. */}
            <Route path="/sys/custom-roles" element={<Navigate to="/sys/user" replace />} />
            <Route
              path="/sys/task"
              element={
                <Suspense fallback={<RouteFallback />}>
                  <AdminTasksPage />
                </Suspense>
              }
            />
            <Route
              path="/sys/node-market"
              element={
                <MarketRoute>
                  <RuntimeRoute feature="market">
                    <Suspense fallback={<RouteFallback />}>
                      <NodeMarketPage />
                    </Suspense>
                  </RuntimeRoute>
                </MarketRoute>
              }
            />
            <Route
              path="/sys/plugin-store"
              element={
                <MarketRoute>
                  <RuntimeRoute feature="market">
                    <Suspense fallback={<RouteFallback />}>
                      <PluginStorePage />
                    </Suspense>
                  </RuntimeRoute>
                </MarketRoute>
              }
            />
            <Route
              path="/sys/inbox"
              element={
                <Suspense fallback={<RouteFallback />}>
                  <AdminInboxPage />
                </Suspense>
              }
            />
            <Route
              path="/sys/admin-access"
              element={
                <PermissionRoute permission="system_configuration.read" platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <AdminAccessPage />
                  </Suspense>
                </PermissionRoute>
              }
            />
            {/* The standalone notification page became the notification tab of /sys/setting. */}
            <Route path="/sys/notification" element={<Navigate to="/sys/setting?tab=notification" replace />} />
            <Route
              path="/sys/message"
              element={
                <PermissionRoute permission="system_configuration.read" platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <AdminMessageQueryPage />
                  </Suspense>
                </PermissionRoute>
              }
            />
            {/* log-merge: 系统日志 merged into the log center; old links keep their query and hash. */}
            <Route path="/sys/log" element={<AliasRedirect to="/sys/log-center" />} />
            <Route path="/sys/identity-review" element={<PermissionRoute permission="platform.admin" platformAdminFallback={false}><Suspense fallback={<RouteFallback />}><AdminIdentityReviewPage /></Suspense></PermissionRoute>} />
            <Route path="/sys/log-center" element={<PermissionRoute permission="platform.admin" platformAdminFallback={false}><Suspense fallback={<RouteFallback />}><LogCenterPage /></Suspense></PermissionRoute>} />
            <Route path="/log" element={<PermissionRoute permission="platform.admin" platformAdminFallback={false}><Suspense fallback={<RouteFallback />}><FrontendLogPage /></Suspense></PermissionRoute>} />
            <Route
              path="/sys/op"
              element={
                <PermissionRoute permission={controlUpgradesReadPermission}>
                  <Suspense fallback={<RouteFallback />}>
                    <ControlUpgradesPage />
                  </Suspense>
                </PermissionRoute>
              }
            />
            <Route
              path="/sys/approvals"
              element={
                <PermissionRoute permission="approvals.read" platformAdminFallback={false}>
                  <RuntimeRoute feature="approval_center">
                    <Suspense fallback={<RouteFallback />}>
                      <ApprovalCenterPage />
                    </Suspense>
                  </RuntimeRoute>
                </PermissionRoute>
              }
            />
            <Route
              path="/node/list"
              element={
                <Suspense fallback={<RouteFallback />}>
                  <NodeListPage />
                </Suspense>
              }
            />
            <Route
              path="/node/isolation"
              element={
                <PermissionRoute permission="nodes.read" platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <NodeIsolationPage />
                  </Suspense>
                </PermissionRoute>
              }
            />
            <Route
              path="/node/realtime"
              element={
                <PermissionRoute permission="nodes.read">
                  <Suspense fallback={<RouteFallback />}>
                    <NodeRealtimePage />
                  </Suspense>
                </PermissionRoute>
              }
            />
            <Route
              path="/node/monitor-setting"
              element={
                <PermissionRoute permission="system_configuration.read">
                  <Suspense fallback={<RouteFallback />}>
                    <NodeMonitorSettingsPage />
                  </Suspense>
                </PermissionRoute>
              }
            />
            <Route
              path="/config/access-log"
              element={
                <PermissionRoute permission="system_configuration.read">
                  <Suspense fallback={<RouteFallback />}>
                    <AccessLogFieldsSettingsPage />
                  </Suspense>
                </PermissionRoute>
              }
            />
            <Route
              path="/node/ddos-protection"
              element={
                <PermissionRoute permission="system_configuration.read">
                  <Suspense fallback={<RouteFallback />}>
                    <DDoSProtectionSettingsPage />
                  </Suspense>
                </PermissionRoute>
              }
            />
            <Route
              path="/node/cname-allocations"
              element={
                <PermissionRoute permission="platform.admin" platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <CnameAllocationsPage />
                  </Suspense>
                </PermissionRoute>
              }
            />
            <Route
              path="/node/l2-config"
              element={
                <PermissionRoute permission={nodeSchedulingReadPermission} platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <NodeL2TopologyPage />
                  </Suspense>
                </PermissionRoute>
              }
            />
            <Route
              path="/node/l2-config/node/:id"
              element={
                <PermissionRoute permission={nodeSchedulingReadPermission} platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <NodeL2TopologyDetailPage />
                  </Suspense>
                </PermissionRoute>
              }
            />
            <Route
              path="/node/line-group/line/:id"
              element={
                <PermissionRoute permission={nodeSchedulingReadPermission} platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <NodeL2TopologyDetailPage />
                  </Suspense>
                </PermissionRoute>
              }
            />
            {adminObservedUserBlockedPaths
              .filter((path) => ![
                '/admin-home',
                '/node',
                '/node/l2-config',
                '/node/list',
                '/node/monitor-setting',
                '/node/realtime',
                '/sys/anno',
                '/sys/message',
                '/sys/op',
                '/sys/task',
                '/sys/user',
              ].includes(path))
              .map((path) => <Route key={path} path={path} element={<NotFoundPage />} />)}
          </Route>
          <Route
            path="/sys/setting"
            element={
              <RoleRoute role="admin" mismatch="not-found">
                <PermissionRoute permission="system_configuration.read">
                  <Suspense fallback={<RouteFallback />}>
                    <SystemGlobalSettingsRoute />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/sys/gateways"
            element={
              <RoleRoute role="admin" mismatch="not-found">
                <PermissionRoute permission="system.gateway.manage">
                  <Suspense fallback={<RouteFallback />}>
                    <GatewayManagementPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          {systemConfigurationRoutes.map(({ path, category }) => (
            <Route
              key={path}
              path={path}
              element={
                <RoleRoute role="admin" mismatch="not-found">
                  <PermissionRoute permission={category === 'error_pages' ? 'error_pages.read' : 'system_configuration.read'}>
                    <Suspense fallback={<RouteFallback />}>
                      {category === 'error_pages' ? <ErrorPagesPage /> : (
                        <SystemSettingsPage
                          key={`system-configuration-${category}`}
                          initialCategory={category}
                        />
                      )}
                    </Suspense>
                  </PermissionRoute>
                </RoleRoute>
              }
            />
          ))}
          <Route
            path="/sys/plugin-webhooks"
            element={
              <PermissionRoute permission="plugin_webhooks.read">
                <Suspense fallback={<RouteFallback />}>
                  <PluginWebhooksPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/sys/anno"
            element={
              <PermissionRoute permission="announcements.manage" platformAdminFallback={false}>
                <Suspense fallback={<RouteFallback />}>
                  <AnnouncementManagementPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/sys/plugin-market"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute permission="plugin_installations.read" platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <PluginMarketPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/home"
            element={
              <RoleRoute role="user">
                <Suspense fallback={<RouteFallback />}>
                  <UserHomePage />
                </Suspense>
              </RoleRoute>
            }
          />
          <Route
            path="/task"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute permission={jobsReadPermission} platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <AdminTasksPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/sys/identity-verification"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute permission="identity_verification.read" platformAdminFallback={false}>
                  <PermissionRoute permission="identity_verification.review" platformAdminFallback={false}>
                    <Suspense fallback={<RouteFallback />}>
                      <IdentityVerificationReviewQueuePage />
                    </Suspense>
                  </PermissionRoute>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/sys/identity-verification/:caseId"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute permission="identity_verification.read" platformAdminFallback={false}>
                  <PermissionRoute permission="identity_verification.review" platformAdminFallback={false}>
                    <Suspense fallback={<RouteFallback />}>
                      <IdentityVerificationReviewCasePage />
                    </Suspense>
                  </PermissionRoute>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/sys/identity-verification/:caseId/decision"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute permission="identity_verification.read" platformAdminFallback={false}>
                  <PermissionRoute permission="identity_verification.review" platformAdminFallback={false}>
                    <Suspense fallback={<RouteFallback />}>
                      <IdentityVerificationReviewDecisionPage />
                    </Suspense>
                  </PermissionRoute>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/site/list"
            element={
              <PermissionRoute permission="sites.read">
                <Suspense fallback={<RouteFallback />}>
                  <SiteListPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/site/groups"
            element={
              // SITE-CURRENT-07：网站分组只有网站列表里这一套二级导航（默认设置、DNS API、解析检测同一权限门控）。
              <Navigate to="/site/list" replace state={{ siteSubnav: 'groups' }} />
            }
          />
          <Route
            path="/site/dns-hub"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute permission="dns.read" platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <DnsHubPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/site/cname-allocations"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute permission="dns.read" platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <CnameAllocationsPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/site/origin-auth/credentials"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute permission="origin_auth.read" platformAdminFallback={false}>
                  <RuntimeRoute feature="origin_auth" detailKey="originAuthNotEnabledDetail">
                    <Suspense fallback={<RouteFallback />}>
                      <OriginAuthCredentialsPage />
                    </Suspense>
                  </RuntimeRoute>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/site/origin-auth/rules"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute permission="origin_auth.read" platformAdminFallback={false}>
                  <RuntimeRoute feature="origin_auth" detailKey="originAuthNotEnabledDetail">
                    <Suspense fallback={<RouteFallback />}>
                      <OriginAuthRulesPage />
                    </Suspense>
                  </RuntimeRoute>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/site/origin-auth/publications"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute permission="origin_auth.read" platformAdminFallback={false}>
                  <RuntimeRoute feature="origin_auth" detailKey="originAuthNotEnabledDetail">
                    <Suspense fallback={<RouteFallback />}>
                      <OriginAuthPublicationsPage />
                    </Suspense>
                  </RuntimeRoute>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/site/publications"
            element={
              <RolePermissionRoute adminPermission="edge_publications.read" userPermission="sites.read">
                <Suspense fallback={<RouteFallback />}>
                  <SitePublicationsPage />
                </Suspense>
              </RolePermissionRoute>
            }
          />
          <Route
            path="/site/protocols"
            element={
              <RoleRoute role="admin" mismatch="not-found">
                <PermissionRoute permission="sites.manage" platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <SiteProtocolBatchPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/account/sessions"
            element={
              <IdentitySessionOwnerRoute>
                <Suspense fallback={<RouteFallback />}>
                  <IdentitySessionsPage />
                </Suspense>
              </IdentitySessionOwnerRoute>
            }
          />
          <Route
            path="/account/user"
            element={
              <PermissionRoute permission="identity.self.read" platformAdminFallback={false}>
                <Suspense fallback={<RouteFallback />}>
                  <AccountUserPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/stream/list"
            element={
              <Suspense fallback={<RouteFallback />}>
                <StreamListPage />
              </Suspense>
            }
          />
          <Route
            path="/stream/list/:id"
            element={
              <Suspense fallback={<RouteFallback />}>
                <StreamDetailPage />
              </Suspense>
            }
          />
          <Route
            path="/node/dns"
            element={
              <InstallationDNSRoute>
                <Suspense fallback={<RouteFallback />}>
                  <NodeDnsPage />
                </Suspense>
              </InstallationDNSRoute>
            }
          />
          <Route
            path="/site/cert"
            element={
              <PermissionRoute permission="certificates.read" platformAdminFallback={false}>
                <Suspense fallback={<RouteFallback />}>
                  <CertificateListPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/site/cert/orders"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute permission="certificates.read" platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <CertificateOrdersPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/site/cache-clean"
            element={
              <PermissionRoute permission="sites.read">
                <Suspense fallback={<RouteFallback />}>
                  <CacheOperationsPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/site/cache-clean/history"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute permission="sites.read" platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <CachePolicyHistoryPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/monitor/stream/realtime"
            element={
              <PermissionRoute permission="sites.read">
                <Suspense fallback={<RouteFallback />}>
                  <L4RealtimeMonitorPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/monitor/stream/access-log"
            element={
              <PermissionRoute permission="sites.read">
                <Suspense fallback={<RouteFallback />}>
                  <L4AccessLogPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/monitor/stream/live-connections"
            element={
              <PermissionRoute permission="streams.read">
                <Suspense fallback={<RouteFallback />}>
                  <L4LiveConnectionsPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/monitor/site/realtime"
            element={
              <PermissionRoute permission="sites.read">
                <Suspense fallback={<RouteFallback />}>
                  <SiteRealtimeMonitorPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/monitor/site/analysis"
            element={
              <PermissionRoute permission="sites.read">
                <Suspense fallback={<RouteFallback />}>
                  <SiteAnalysisPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/monitor/site/analysis/ja4-blocks"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute permission="sites.read" platformAdminFallback={false}>
                  <PermissionRoute permission="security_policies.read" platformAdminFallback={false}>
                    <PermissionRoute permission="security_policies.manage" platformAdminFallback={false}>
                      <Suspense fallback={<RouteFallback />}>
                        <JA4BlockWorkflowsPage />
                      </Suspense>
                    </PermissionRoute>
                  </PermissionRoute>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/monitor/site/access-log"
            element={
              <PermissionRoute permission="sites.read">
                <Suspense fallback={<RouteFallback />}>
                  <SiteAccessLogPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/monitor/site/block-log"
            element={
              <PermissionRoute permission="sites.read">
                <Suspense fallback={<RouteFallback />}>
                  <SiteBlockLogPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/monitor/site/block-event-log"
            element={
              <PermissionRoute permission="sites.read">
                <Suspense fallback={<RouteFallback />}>
                  <SiteBlockEventLogPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/monitor/site/cc-coordination"
            element={
              <RoleRoute role="admin" mismatch="not-found">
                <PermissionRoute permission="sites.read">
                  <Suspense fallback={<RouteFallback />}>
                    <CCCoordinationPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/monitor/site/attack-log"
            element={
              <PermissionRoute permission="sites.read">
                <Suspense fallback={<RouteFallback />}>
                  <WafLogsPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/site/domain-security"
            element={
              <RoleRoute role="admin" mismatch="not-found">
                <PermissionRoute permission="domains.security.manage">
                  <Suspense fallback={<RouteFallback />}>
                    <DomainSecurityPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/account/domains"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute permission="sites.read">
                  <Suspense fallback={<RouteFallback />}>
                    <AccountDomainsPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/sys/tickets"
            element={
              <RoleRoute role="admin" mismatch="not-found">
                <PermissionRoute permission="tickets.read">
                  <Suspense fallback={<RouteFallback />}>
                    <TicketsPage mode="admin" />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/account/tickets"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <Suspense fallback={<RouteFallback />}>
                  <TicketsPage mode="user" />
                </Suspense>
              </RoleRoute>
            }
          />
          <Route
            path="/sys/plugin-providers"
            element={
              <RoleRoute role="admin" mismatch="not-found">
                <PermissionRoute permission="plugin_installations.read">
                  <Suspense fallback={<RouteFallback />}>
                    <PluginProvidersPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/sys/probe-dnspup"
            element={
              <RoleRoute role="admin" mismatch="not-found">
                <PermissionRoute permission="system.probe_dnspup.manage">
                  <Suspense fallback={<RouteFallback />}>
                    <ProbeDNSPupPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/sys/ip-intel-updates"
            element={
              <RoleRoute role="admin" mismatch="not-found">
                <PermissionRoute permission="system.ip_intel_updates.manage">
                  <Suspense fallback={<RouteFallback />}>
                    <IPIntelUpdatesPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/account/verification"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute
                  permission="identity_verification.self.manage"
                  platformAdminFallback={false}
                >
                  <Suspense fallback={<RouteFallback />}>
                    <AccountIdentityVerificationPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          {/* 平台管理员可直接打开这四个页面。原先固定 role="user" 会把平台管理员
              挡在门外，改为按权限放行。 */}
          <Route
            path="/account/log"
            element={
              <PermissionRoute permission="identity.self.read">
                <Suspense fallback={<RouteFallback />}>
                  <AccountLogPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/account/message"
            element={
              <PermissionRoute permission="announcements.read">
                <Suspense fallback={<RouteFallback />}>
                  <AccountMessagesPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/account/inbox"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <Suspense fallback={<RouteFallback />}>
                  <AdminInboxPage scope="account" />
                </Suspense>
              </RoleRoute>
            }
          />
          <Route
            path="/account/subscribe"
            element={
              <PermissionRoute permission="announcements.read">
                <Suspense fallback={<RouteFallback />}>
                  <AccountSubscriptionsPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/account/api-key"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <Suspense fallback={<RouteFallback />}>
                  <AccountApiKeysPage />
                </Suspense>
              </RoleRoute>
            }
          />
          <Route
            path="/site/cc-rule"
            element={
              <PermissionRoute permission="security_policies.read">
                <Suspense fallback={<RouteFallback />}>
                  <SecurityPoliciesPage kind="cc" referenceLayout />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/site/waf-rule"
            element={
              <PermissionRoute permission="security_policies.read">
                <Suspense fallback={<RouteFallback />}>
                  <SecurityPoliciesPage kind="waf" referenceLayout />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/site/security-bans"
            element={
              <PermissionRoute permission="security_policies.read">
                <Suspense fallback={<RouteFallback />}>
                  <SecurityBansPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/site/ip-lists"
            element={
              <PermissionRoute permission="security_policies.read">
                <Suspense fallback={<RouteFallback />}>
                  <SecurityIPListsPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/site/rule-packs"
            element={
              <PermissionRoute permission="security_policies.read">
                <Suspense fallback={<RouteFallback />}>
                  <RulePacksPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/site/acl"
            element={
              <PermissionRoute permission="security_policies.read">
                <Suspense fallback={<RouteFallback />}>
                  <SecurityPoliciesPage kind="acl" />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/site/url-auth"
            element={
              <PermissionRoute permission="url_auth_policies.read">
                <Suspense fallback={<RouteFallback />}>
                  <UrlAuthPoliciesPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/config/waf"
            element={
              <RoleRoute role="admin" mismatch="not-found">
                <PermissionRoute permission={firewallReadPermission} platformAdminFallback>
                  <Suspense fallback={<RouteFallback />}>
                    <FirewallPoliciesPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          <Route
            path="/config/firewall-action"
            element={
              <RoleRoute role="admin" mismatch="not-found">
                <PermissionRoute permission={firewallReadPermission} platformAdminFallback>
                  <Suspense fallback={<RouteFallback />}>
                    <FirewallActionPoliciesPage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          {/* PA-19 ui_page plugin pages; the page list is already filtered for this principal. */}
          <Route
            path="/plugin-ui/:pluginId/:pageId"
            element={
              <Suspense fallback={<RouteFallback />}>
                <PluginUIPage />
              </Suspense>
            }
          />
          <Route path="/site/list/:id" element={<LegacySiteEditRedirect />} />
          <Route
            path="/site/:id/edit"
            element={
              <PermissionRoute permission="sites.read">
                <Suspense fallback={<RouteFallback />}>
                  <SiteEditPage />
                </Suspense>
              </PermissionRoute>
            }
          />
          <Route
            path="/site/:id/dns-reconcile"
            element={
              <RoleRoute role="user" mismatch="not-found">
                <PermissionRoute permission="dns.read" platformAdminFallback={false}>
                  <Suspense fallback={<RouteFallback />}>
                    <DnsReconcilePage />
                  </Suspense>
                </PermissionRoute>
              </RoleRoute>
            }
          />
          </Route>
        </Route>
      </Route>
      <Route path="/403" element={<RouteStatusPage status="403" />} />
      <Route path="/500" element={<RouteStatusPage status="500" />} />
      <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </RouteErrorBoundary>
  )
}
