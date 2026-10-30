import type { AppRole } from '../auth/session'
import type { RuntimeFeature } from '../api/runtimeFeatures'
import i18n from '../i18n'
import '../i18n/accountIdentityVerification'
import '../i18n/cachePolicyHistory'
import '../i18n/certificateOrderStatus'
import '../i18n/cnameAllocations'
import '../i18n/customRolesPage'
import '../i18n/adminAccess'
import '../i18n/adminInbox'
import '../i18n/dnsReconcilePage'
import '../i18n/errorPagesPage'
import '../i18n/identityVerificationReviewQueue'
import '../i18n/adminIdentityReview'
import '../i18n/identitySessions'
import '../i18n/approvalCenter'
import '../i18n/nodeIsolation'
import '../i18n/nodeL2Topology'
import '../i18n/nodeMarket'
import '../i18n/pluginStore'
import '../i18n/ipIntelUpdates'
import '../i18n/probeDNSPup'
import '../i18n/pluginProviders'
import '../i18n/tickets'
import '../i18n/logCenter'
import '../i18n/originAuthCredentials'
import '../i18n/originAuthPublications'
import '../i18n/originAuthRules'
import '../pages/site-protocols/i18n'
import {
  controlUpgradesReadPermission,
  firewallReadPermission,
  jobsReadPermission,
  nodeSchedulingReadPermission,
} from './routePolicy'

export type NavIcon =
  | 'overview'
  | 'analytics'
  | 'nodes'
  | 'sites'
  | 'stream'
  | 'config'
  | 'system'
  | 'account'
  | 'edge'
  | 'market'

export interface NavigationItem {
  key: string
  label: string
  icon?: NavIcon
  implemented?: boolean
  children?: NavigationItem[]
}

export interface NavigationDefinition extends Omit<NavigationItem, 'label' | 'children'> {
  labelKey: string
  // requiredModule is a module/pack/theme feature code (GET /v1/modules).
  // Unlike permissions it has no platform-admin fallback: the lease, not
  // RBAC, decides it, and the API entry gate refuses it the same way.
  requiredModule?: string
  // requiredRuntime is an optional control-plane runtime (GET
  // /v1/runtime-features); the item is hidden when it is not mounted, since its
  // routes would answer 404. No platform-admin fallback either.
  requiredRuntime?: RuntimeFeature
  requiredPermission?: string
  requiredPermissions?: readonly string[]
  // anyPermission: at least one of these codes (after requiredPermission(s)).
  anyPermission?: readonly string[]
  platformAdminFallback?: boolean
  children?: NavigationDefinition[]
}

interface DirectRouteDefinition {
  path: string
  labelKey: string
  parentKey?: string
  roles: readonly AppRole[]
  implemented?: boolean
  requiredModule?: string
  requiredRuntime?: RuntimeFeature
  requiredPermission?: string
  requiredPermissions?: readonly string[]
  platformAdminFallback?: boolean
  selectionKey?: string
  breadcrumbKeys?: readonly string[]
}

type Translate = (key: string) => string

// C24: the same any-of rule as MarketRoute / marketAccess().browse (migration
// 296 codes, plus the one-release legacy sites.manage; platform.admin falls back).
const marketGate = {
  implemented: true,
  anyPermission: ['marketplace.browse', 'marketplace.purchase', 'marketplace.sell', 'sites.manage'],
  requiredRuntime: 'market',
  platformAdminFallback: true,
} as const

const adminNavigation: NavigationDefinition[] = [
  { key: '/admin-home', labelKey: 'navigation:overview', icon: 'overview', implemented: true, requiredPermission: 'platform.admin', platformAdminFallback: false },
  {
    key: 'monitor',
    labelKey: 'navigation:analytics',
    icon: 'analytics',
    children: [
      { key: '/monitor/site/realtime', labelKey: 'navigation:realtime', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/site/analysis', labelKey: 'navigation:dataAnalysis', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/site/block-log', labelKey: 'navigation:blockLog', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/site/block-event-log', labelKey: 'navigation:blockEventLog', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/site/cc-coordination', labelKey: 'navigation:ccCoordination', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/site/access-log', labelKey: 'navigation:accessLog', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/site/attack-log', labelKey: 'navigation:wafLog', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/stream/realtime', labelKey: 'navigation:streamRealtime', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/stream/access-log', labelKey: 'navigation:streamAccessLog', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/stream/live-connections', labelKey: 'navigation:streamLiveConnections', implemented: true, requiredPermission: 'streams.read' },
    ],
  },
  {
    key: 'node',
    labelKey: 'navigation:nodes',
    icon: 'nodes',
    children: [
      { key: '/node/list', labelKey: 'navigation:nodeList', implemented: true, requiredPermission: 'nodes.read' },
      {
        key: '/node/line-group',
        labelKey: 'navigation:lineGroups',
        implemented: true,
        requiredPermission: nodeSchedulingReadPermission,
        platformAdminFallback: false,
      },
      {
        key: '/node/l2-config',
        labelKey: 'navigation:l2Configuration',
        implemented: true,
        requiredPermission: nodeSchedulingReadPermission,
        platformAdminFallback: false,
      },
      {
        key: '/node/dns',
        labelKey: 'navigation:dnsConfiguration',
        implemented: true,
        requiredPermission: 'dns.read',
        platformAdminFallback: false,
      },
      {
        key: '/node/monitor-setting',
        labelKey: 'navigation:monitorConfiguration',
        implemented: true,
        requiredPermission: 'system_configuration.read',
      },
      {
        key: '/node/ddos-protection',
        labelKey: 'navigation:ddosProtection',
        implemented: true,
        requiredPermission: 'system_configuration.read',
      },
      { key: '/node/realtime', labelKey: 'navigation:realtime', implemented: true, requiredPermission: 'nodes.read' },
    ],
  },
  {
    // C24: the marketplace is its own group beside node operations;
    // the market runtime off hides the whole group.
    key: 'market',
    labelKey: 'navigation:market',
    icon: 'market',
    children: [
      { key: '/sys/node-market', labelKey: 'nodeMarket:title', ...marketGate },
      { key: '/sys/plugin-store', labelKey: 'pluginStore:title', ...marketGate },
    ],
  },
  {
    key: 'site',
    labelKey: 'navigation:sites',
    icon: 'sites',
    children: [
      { key: '/site/list', labelKey: 'navigation:siteList', implemented: true, requiredPermission: 'sites.read' },
      {
        key: '/site/cert',
        labelKey: 'navigation:certificates',
        implemented: true,
        requiredPermission: 'certificates.read',
        platformAdminFallback: false,
      },
      { key: '/site/cache-clean', labelKey: 'navigation:cacheRefresh', implemented: true, requiredPermission: 'sites.read', requiredRuntime: 'cache_control' },
      { key: '/site/cc-rule', labelKey: 'navigation:ccRules', implemented: true, requiredPermission: 'security_policies.read' },
      { key: '/site/waf-rule', labelKey: 'navigation:wafRules', implemented: true, requiredPermission: 'security_policies.read' },
      { key: '/site/rule-packs', labelKey: 'navigation:rulePacks', implemented: true, requiredPermission: 'security_policies.read' },
      { key: '/site/security-bans', labelKey: 'navigation:securityBans', implemented: true, requiredPermission: 'security_policies.read' },
      { key: '/site/ip-lists', labelKey: 'navigation:securityIPLists', implemented: true, requiredPermission: 'security_policies.read' },
    ],
  },
  {
    key: 'stream',
    labelKey: 'navigation:streams',
    icon: 'stream',
    children: [{ key: '/stream/list', labelKey: 'navigation:streamList', implemented: true }],
  },
  {
    key: 'config',
    labelKey: 'navigation:globalConfiguration',
    icon: 'config',
    children: [
      {
        key: '/config/waf',
        labelKey: 'navigation:firewallConfiguration',
        implemented: true,
        requiredPermission: firewallReadPermission,
        platformAdminFallback: true,
      },
      {
        key: '/config/firewall-action',
        labelKey: 'navigation:firewallActionPolicy',
        implemented: true,
        requiredPermission: firewallReadPermission,
        platformAdminFallback: true,
      },
      { key: '/config/nginx', labelKey: 'navigation:nginxConfiguration', implemented: true, requiredPermission: 'system_configuration.read' },
      { key: '/config/res', labelKey: 'navigation:resourceConfiguration', implemented: true, requiredPermission: 'system_configuration.read' },
      { key: '/config/default', labelKey: 'navigation:defaultConfiguration', implemented: true, requiredPermission: 'system_configuration.read' },
      { key: '/config/error', labelKey: 'navigation:errorPages', implemented: true, requiredPermission: 'error_pages.read' },
      { key: '/config/access-log', labelKey: 'navigation:accessLogFields', implemented: true, requiredPermission: 'system_configuration.read' },
    ],
  },
  {
    key: 'system',
    labelKey: 'navigation:system',
    icon: 'system',
    children: [
      { key: '/sys/setting', labelKey: 'navigation:systemConfiguration', implemented: true, requiredPermission: 'system_configuration.read' },
      { key: '/sys/task', labelKey: 'navigation:backgroundTasks', implemented: true },
      { key: '/sys/user', labelKey: 'navigation:userList', implemented: true, requiredPermission: 'identity.users.manage' },
      { key: '/sys/log-center', labelKey: 'logCenter:title', implemented: true, requiredPermission: 'platform.admin', platformAdminFallback: false },
      {
        key: '/sys/op',
        labelKey: 'navigation:maintenanceUpgrade',
        implemented: true,
        requiredPermission: controlUpgradesReadPermission,
      },
      { key: '/sys/anno', labelKey: 'navigation:announcements', implemented: true, requiredPermission: 'announcements.manage' },
      { key: '/sys/message', labelKey: 'navigation:messageQuery', implemented: true, requiredPermission: 'system_configuration.read', platformAdminFallback: false },
      { key: '/sys/tickets', labelKey: 'tickets:adminTitle', implemented: true, requiredPermission: 'tickets.read' },
      { key: '/sys/identity-review', labelKey: 'adminIdentityReview:title', implemented: true, requiredPermission: 'platform.admin', platformAdminFallback: false },
      { key: '/sys/gateways', labelKey: 'navigation:gateways', implemented: true, requiredPermission: 'system.gateway.manage' },
      // fz-x10: shown only while the approval center is on (runtime approval_center).
      { key: '/sys/approvals', labelKey: 'approvalCenter:title', implemented: true, requiredPermission: 'approvals.read', requiredRuntime: 'approval_center', platformAdminFallback: false },
    ],
  },
]

const userNavigation: NavigationDefinition[] = [
  { key: '/home', labelKey: 'navigation:overview', icon: 'overview', implemented: true },
  {
    key: 'monitor',
    labelKey: 'navigation:analytics',
    icon: 'analytics',
    // tp-b1: the six reference entries first; our additions
    // follow. Cross-node CC state is an operator page (admin menu only).
    children: [
      { key: '/monitor/site/realtime', labelKey: 'navigation:realtime', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/site/analysis', labelKey: 'navigation:dataAnalysis', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/site/block-log', labelKey: 'navigation:blockLog', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/site/access-log', labelKey: 'navigation:accessLog', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/site/attack-log', labelKey: 'navigation:wafLog', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/stream/realtime', labelKey: 'navigation:streamRealtime', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/site/block-event-log', labelKey: 'navigation:blockEventLog', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/stream/access-log', labelKey: 'navigation:streamAccessLog', implemented: true, requiredPermission: 'sites.read' },
      { key: '/monitor/stream/live-connections', labelKey: 'navigation:streamLiveConnections', implemented: true, requiredPermission: 'streams.read' },
    ],
  },
  {
    key: 'site',
    labelKey: 'navigation:sites',
    icon: 'sites',
    children: [
      // The website sidebar contains the five current baseline entries.
      { key: '/site/list', labelKey: 'navigation:siteList', implemented: true, requiredPermission: 'sites.read' },
      { key: '/site/cert', labelKey: 'navigation:certificates', implemented: true, requiredPermission: 'certificates.read', platformAdminFallback: false },
      { key: '/site/cache-clean', labelKey: 'navigation:cacheRefresh', implemented: true, requiredPermission: 'sites.read', requiredRuntime: 'cache_control' },
      { key: '/site/cc-rule', labelKey: 'navigation:ccRules', implemented: true, requiredPermission: 'security_policies.read' },
      { key: '/site/waf-rule', labelKey: 'navigation:wafRules', implemented: true, requiredPermission: 'security_policies.read' },
      { key: '/site/rule-packs', labelKey: 'navigation:rulePacks', implemented: true, requiredPermission: 'security_policies.read' },
      { key: '/site/security-bans', labelKey: 'navigation:securityBans', implemented: true, requiredPermission: 'security_policies.read' },
      { key: '/site/ip-lists', labelKey: 'navigation:securityIPLists', implemented: true, requiredPermission: 'security_policies.read' },
      // ADR 0020 §3.4：用户自有多家 DNS 账号的域名解析统一管理（只用户端；平台副本账号不出现）。
      { key: '/site/dns-hub', labelKey: 'navigation:dnsHub', implemented: true, requiredPermission: 'dns.read', platformAdminFallback: false },
    ],
  },
  {
    key: 'stream',
    labelKey: 'navigation:streams',
    icon: 'stream',
    children: adminNavigation.find((item) => item.key === 'stream')?.children,
  },
  {
    key: 'account',
    labelKey: 'navigation:accountCenter',
    icon: 'account',
    // tp-b1: the seven reference entries in order, then our tickets.
    children: [
      { key: '/account/user', labelKey: 'navigation:profile', implemented: true, requiredPermission: 'identity.self.read', platformAdminFallback: false },
      {
        key: '/account/log',
        labelKey: 'navigation:logQuery',
        implemented: true,
        requiredPermission: 'identity.self.read',
        platformAdminFallback: false,
      },
      { key: '/account/message', labelKey: 'navigation:messageQuery', implemented: true, requiredPermission: 'announcements.read' },
      { key: '/account/subscribe', labelKey: 'navigation:messageSubscription', implemented: true },
      { key: '/account/api', labelKey: 'navigation:apiKeys', implemented: true },
      { key: '/account/tickets', labelKey: 'tickets:title', implemented: true },
    ],
  },
]

const directRouteDefinitions: DirectRouteDefinition[] = [
  { path: '/node/isolation', labelKey: 'nodeIsolation:title', parentKey: 'node', roles: ['admin'], implemented: true, requiredPermission: 'nodes.read', platformAdminFallback: false, selectionKey: '/node/list' },
  { path: '/node/cname-allocations', labelKey: 'cnameAllocations:title', parentKey: 'node', roles: ['admin'], implemented: true, requiredPermission: 'platform.admin', platformAdminFallback: false, selectionKey: '/node/list' },
  { path: '/site/publications', labelKey: 'navigation:sitePublications', parentKey: 'site', roles: ['admin'], implemented: true, requiredPermission: 'edge_publications.read', selectionKey: '/site/list' },
  { path: '/site/publications', labelKey: 'navigation:sitePublications', parentKey: 'site', roles: ['user'], implemented: true, requiredPermission: 'sites.read', selectionKey: '/site/list' },
  { path: '/site/groups', labelKey: 'navigation:siteGroups', parentKey: 'site', roles: ['admin', 'user'], implemented: true, requiredPermission: 'sites.read', selectionKey: '/site/list', breadcrumbKeys: ['navigation:home', 'navigation:sites', 'navigation:siteGroups'] },
  { path: '/site/protocols', labelKey: 'siteProtocols:title', parentKey: 'site', roles: ['admin'], implemented: true, requiredPermission: 'sites.manage', platformAdminFallback: false, selectionKey: '/site/list' },
  { path: '/site/acl', labelKey: 'navigation:aclRules', parentKey: 'site', roles: ['admin', 'user'], implemented: true, requiredPermission: 'security_policies.read', selectionKey: '/site/list' },
  { path: '/site/url-auth', labelKey: 'navigation:urlAuthPolicies', parentKey: 'site', roles: ['admin', 'user'], implemented: true, requiredPermission: 'url_auth_policies.read', selectionKey: '/site/list' },
  { path: '/site/cert/orders', labelKey: 'certificateOrderStatus:title', parentKey: 'site', roles: ['user'], implemented: true, requiredPermission: 'certificates.read', platformAdminFallback: false, selectionKey: '/site/cert', breadcrumbKeys: ['navigation:home', 'navigation:sites', 'navigation:certificates', 'certificateOrderStatus:title'] },
  { path: '/site/cache-clean/history', labelKey: 'cacheOperations:history.title', parentKey: 'site', roles: ['user'], implemented: true, requiredPermission: 'sites.read', requiredRuntime: 'cache_control', platformAdminFallback: false, selectionKey: '/site/cache-clean', breadcrumbKeys: ['navigation:home', 'navigation:sites', 'navigation:cacheRefresh'] },
  { path: '/site/cname-allocations', labelKey: 'cnameAllocations:title', parentKey: 'site', roles: ['user'], implemented: true, requiredPermission: 'dns.read', platformAdminFallback: false, selectionKey: '/site/list' },
  { path: '/site/origin-auth/credentials', requiredRuntime: 'origin_auth', labelKey: 'originAuthCredentials:title', parentKey: 'site', roles: ['user'], implemented: true, requiredPermission: 'origin_auth.read', platformAdminFallback: false, selectionKey: '/site/list' },
  { path: '/site/origin-auth/rules', requiredRuntime: 'origin_auth', labelKey: 'originAuthRules:title', parentKey: 'site', roles: ['user'], implemented: true, requiredPermission: 'origin_auth.read', platformAdminFallback: false, selectionKey: '/site/list' },
  { path: '/site/origin-auth/publications', requiredRuntime: 'origin_auth', labelKey: 'originAuthPublications:title', parentKey: 'site', roles: ['user'], implemented: true, requiredPermission: 'origin_auth.read', platformAdminFallback: false, selectionKey: '/site/list' },
  { path: '/monitor/site/analysis/ja4-blocks', labelKey: 'navigation:dataAnalysis', parentKey: 'monitor', roles: ['user'], implemented: true, requiredPermissions: ['sites.read', 'security_policies.read', 'security_policies.manage'], platformAdminFallback: false, selectionKey: '/monitor/site/analysis' },
  { path: '/account/verification', labelKey: 'accountIdentityVerification:title', parentKey: 'account', roles: ['user'], implemented: true, requiredPermission: 'identity_verification.self.manage', platformAdminFallback: false, selectionKey: '/account/user' },
  // fp-role ID-03：管理员自己的个人资料（顶部账号菜单、概览「编辑个人资料」进入），不进侧栏。
  { path: '/account/user', labelKey: 'accountProfile:title', roles: ['admin'], implemented: true, requiredPermission: 'identity.self.read', platformAdminFallback: false },
  { path: '/account/sessions', labelKey: 'identitySessions:title', parentKey: 'system', roles: ['admin'], implemented: true, selectionKey: '/sys/setting' },
  { path: '/account/sessions', labelKey: 'identitySessions:title', parentKey: 'account', roles: ['user'], implemented: true, selectionKey: '/account/user' },
  { path: '/task', labelKey: 'navigation:backgroundTasks', parentKey: 'system', roles: ['user'], implemented: true, requiredPermission: jobsReadPermission },
  { path: '/account/domains', labelKey: 'navigation:verifiedDomains', parentKey: 'account', roles: ['user'], implemented: true, requiredPermission: 'sites.read', platformAdminFallback: false, selectionKey: '/account/user' },
  { path: '/site/domain-security', labelKey: 'navigation:domainSecurity', parentKey: 'site', roles: ['admin'], implemented: true, requiredPermission: 'domains.security.manage', platformAdminFallback: true, selectionKey: '/site/list' },
  { path: '/sys/plugin-providers', labelKey: 'pluginProviders:title', parentKey: 'system', roles: ['admin'], implemented: true, requiredPermission: 'plugin_installations.read', platformAdminFallback: true, selectionKey: '/sys/setting' },
  { path: '/sys/ip-intel-updates', labelKey: 'ipIntelUpdates:title', parentKey: 'system', roles: ['admin'], implemented: true, requiredPermission: 'system.ip_intel_updates.manage', requiredModule: 'module.ipintel.dnspup', platformAdminFallback: true, selectionKey: '/sys/setting' },
  { path: '/sys/probe-dnspup', labelKey: 'probeDNSPup:title', parentKey: 'system', roles: ['admin'], implemented: true, requiredPermission: 'system.probe_dnspup.manage', requiredModule: 'module.probe.dnspup', platformAdminFallback: true, selectionKey: '/sys/setting' },
  { path: '/sys/inbox', labelKey: 'adminInbox:title', parentKey: 'system', roles: ['admin'], implemented: true, selectionKey: '/sys/setting' },
  { path: '/account/inbox', labelKey: 'adminInbox:title', parentKey: 'account', roles: ['user'], implemented: true, selectionKey: '/account/message' },
  { path: '/sys/admin-access', labelKey: 'adminAccess:title', parentKey: 'system', roles: ['admin'], implemented: true, requiredPermission: 'system_configuration.read', platformAdminFallback: false, selectionKey: '/sys/setting' },
  { path: '/sys/plugin-webhooks', labelKey: 'navigation:pluginWebhooks', parentKey: 'system', roles: ['admin'], implemented: true, requiredPermission: 'plugin_webhooks.read', requiredRuntime: 'plugin_webhooks', selectionKey: '/sys/setting' },
  { path: '/sys/plugin-webhooks', labelKey: 'navigation:pluginWebhooks', parentKey: 'system', roles: ['user'], implemented: true, requiredPermission: 'plugin_webhooks.read', requiredRuntime: 'plugin_webhooks' },
  { path: '/sys/identity-verification', labelKey: 'identityVerificationReviewQueue:title', parentKey: 'system', roles: ['user'], implemented: true, requiredPermissions: ['identity_verification.read', 'identity_verification.review'], platformAdminFallback: false },
  { path: '/sys/plugin-market', labelKey: 'navigation:pluginMarketplace', parentKey: 'system', roles: ['user'], implemented: true, requiredPermission: 'plugin_installations.read', platformAdminFallback: false },
  { path: '/log', labelKey: 'navigation:frontendLog', roles: ['admin'], implemented: true, requiredPermission: 'platform.admin', platformAdminFallback: false },
]

const hiddenPaths = [
  '/site/list/:id',
  '/site/:id/edit',
  '/site/:id/dns-reconcile',
  '/node/list/:id',
  '/stream/list/:id',
  '/node/l2-config/node/:id',
  '/node/line-group/line/:id',
  '/monitor/site/analysis/ja4-blocks',
  '/site/cert/orders',
  '/site/cache-clean/history',
  '/sys/identity-verification/:caseId',
  '/sys/identity-verification/:caseId/decision',
]

const publicPaths = [
  '/login',
  '/register',
  '/forget-password',
  '/forgot-password',
  '/reset-password',
  '/403',
  '/500',
]

function defaultTranslate(key: string): string {
  return i18n.t(key)
}

// localizeNavigation filters by permissions (undefined = unfiltered), by
// granted modules (undefined = none granted: a gated item never shows before
// GET /v1/modules answers) and by mounted runtimes (undefined = unfiltered).
export function localizeNavigation(
  definitions: NavigationDefinition[],
  translate: Translate,
  permissions?: readonly string[],
  modules?: readonly string[],
  runtimes?: readonly RuntimeFeature[],
): NavigationItem[] {
  return definitions.flatMap(({
    labelKey,
    children,
    requiredModule,
    requiredRuntime,
    requiredPermission,
    requiredPermissions,
    anyPermission,
    platformAdminFallback,
    ...item
  }) => {
    if (requiredModule && !modules?.includes(requiredModule)) return []
    if (requiredRuntime && runtimes && !runtimes.includes(requiredRuntime)) return []
    const permissionRequirements = [
      ...(requiredPermission ? [requiredPermission] : []),
      ...(requiredPermissions ?? []),
    ]
    const hasRequiredPermissions = permissions === undefined ||
      (permissionRequirements.every((permission) => permissions.includes(permission)) &&
        (!anyPermission || anyPermission.some((permission) => permissions.includes(permission))))
    if (!hasRequiredPermissions &&
      (platformAdminFallback === false || !permissions?.includes('platform.admin'))) {
      return []
    }
    const visibleChildren = children
      ? localizeNavigation(children, translate, permissions, modules, runtimes)
      : undefined
    if (children && visibleChildren?.length === 0) return []
    return [{ ...item, label: translate(labelKey), children: visibleChildren }]
  })
}

function getNavigationDefinitions(role: AppRole): NavigationDefinition[] {
  return role === 'admin' ? adminNavigation : userNavigation
}

function getDirectRouteDefinition(role: AppRole, path: string): DirectRouteDefinition | undefined {
  return directRouteDefinitions.find((route) => route.path === path && route.roles.includes(role))
}

function parentLabelKey(parentKey: string): string {
  const labels: Record<string, string> = {
    account: 'navigation:accountCenter',
    config: 'navigation:globalConfiguration',
    market: 'navigation:market',
    monitor: 'navigation:analytics',
    node: 'navigation:nodes',
    site: 'navigation:sites',
    stream: 'navigation:streams',
    system: 'navigation:system',
  }
  return labels[parentKey] ?? parentKey
}

export function hasRoutePermission(
  route: Pick<DirectRouteDefinition, 'requiredModule' | 'requiredRuntime' | 'requiredPermission' | 'requiredPermissions' | 'platformAdminFallback'>,
  permissions?: readonly string[],
  modules?: readonly string[],
  runtimes?: readonly RuntimeFeature[],
): boolean {
  if (route.requiredModule && !modules?.includes(route.requiredModule)) return false
  if (route.requiredRuntime && runtimes && !runtimes.includes(route.requiredRuntime)) return false
  const required = [
    ...(route.requiredPermission ? [route.requiredPermission] : []),
    ...(route.requiredPermissions ?? []),
  ]
  const hasRequired = permissions === undefined || required.every((permission) => permissions.includes(permission))
  return hasRequired || (route.platformAdminFallback !== false && permissions?.includes('platform.admin') === true)
}

export function getNavigation(
  role: AppRole,
  translate: Translate = defaultTranslate,
  permissions?: readonly string[],
  modules?: readonly string[],
  runtimes?: readonly RuntimeFeature[],
): NavigationItem[] {
  return localizeNavigation(getNavigationDefinitions(role), translate, permissions, modules, runtimes)
}

// withPluginPages (PA-19) adds the enabled ui_page plugin menu pages under
// their declared parent group. The server already filtered them by role,
// permission and granted module; a page whose parent group is not visible
// to this principal is not shown.
export function withPluginPages(
  items: NavigationItem[],
  pages: readonly { parentKey: string; key: string; label: string }[],
): NavigationItem[] {
  if (pages.length === 0) return items
  return items.map((item) => {
    const extra = pages.filter((page) => page.parentKey === item.key)
    if (extra.length === 0 || !item.children) return item
    return { ...item, children: [...item.children, ...extra.map((page) => ({ key: page.key, label: page.label, implemented: true }))] }
  })
}

/** pluginPageRoute matches /plugin-ui/<plugin id>/<page id>. */
export const pluginPageRoute = /^\/plugin-ui\/[a-z0-9]+(?:[.-][a-z0-9]+)+\/[a-z][a-z0-9-]{0,31}$/

export function getDeclaredPaths(): string[] {
  // The parent is an actual redirect route (not merely a menu group), so keep
  // it in the declared-path contract for route coverage and bookmark checks.
  const paths = new Set<string>([...publicPaths, ...hiddenPaths, '/config'])
  for (const item of [...adminNavigation, ...userNavigation]) {
    if (item.key.startsWith('/')) paths.add(item.key)
    for (const child of item.children ?? []) paths.add(child.key)
  }
  for (const route of directRouteDefinitions) paths.add(route.path)
  return [...paths]
}

export function isImplementedPath(
  role: AppRole,
  path: string,
  permissions?: readonly string[],
  modules?: readonly string[],
  runtimes?: readonly RuntimeFeature[],
): boolean {
  if (/^\/node\/line-group\/line\/[^/]+$/.test(path)) {
    return role === 'admin' && (permissions === undefined || permissions.includes(nodeSchedulingReadPermission))
  }
  const visible = getNavigation(role, defaultTranslate, permissions, modules, runtimes).some(
    (item) =>
      (item.key === path && item.implemented) ||
      item.children?.some((child) => child.key === path && child.implemented),
  )
  if (visible) return true

  const direct = getDirectRouteDefinition(role, path)
  return direct?.implemented !== false && direct !== undefined && hasRoutePermission(direct, permissions, modules, runtimes)
}

export function getParentNavigationKey(role: AppRole, path: string): string | undefined {
  if (/^\/site\/(?:list\/[^/]+|[^/]+\/(?:edit|dns-reconcile))$/.test(path)) return 'site'
  if (/^\/node\/list\/[^/]+$/.test(path)) return 'node'
  if (/^\/node\/l2-config\/node\/[^/]+$/.test(path)) return 'node'
  if (/^\/stream\/list(?:\/[^/]+)?$/.test(path)) return 'stream'
  if (role === 'admin' && /^\/node\/line-group\/line\/[^/]+$/.test(path)) return 'node'
  if (path === '/site/cert/orders' || path === '/site/cache-clean/history') return 'site'
  if (path === '/monitor/site/analysis/ja4-blocks') return 'monitor'
  if (/^\/sys\/identity-verification(?:\/[^/]+(?:\/decision)?)?$/.test(path)) return 'system'
  const direct = getDirectRouteDefinition(role, path)
  if (direct?.parentKey) return direct.parentKey
  return getNavigationDefinitions(role).find((item) =>
    item.children?.some((child) => child.key === path),
  )?.key
}

export function getNavigationSelectionKey(role: AppRole, path: string): string {
  if (/^\/site\/(?:list\/[^/]+|[^/]+\/(?:edit|dns-reconcile))$/.test(path)) return '/site/list'
  if (/^\/node\/list\/[^/]+$/.test(path)) return '/node/list'
  if (/^\/node\/l2-config\/node\/[^/]+$/.test(path)) return '/node/l2-config'
  if (role === 'admin' && /^\/node\/line-group\/line\/[^/]+$/.test(path)) return '/node/line-group'
  if (/^\/stream\/list\/[^/]+$/.test(path)) return '/stream/list'
  if (path === '/site/cert/orders') return '/site/cert'
  if (path === '/site/cache-clean/history') return '/site/cache-clean'
  if (path === '/monitor/site/analysis/ja4-blocks') return '/monitor/site/analysis'
  if (/^\/sys\/identity-verification\/[^/]+(?:\/decision)?$/.test(path)) {
    return '/sys/identity-verification'
  }

  const direct = getDirectRouteDefinition(role, path)
  if (direct?.selectionKey) return direct.selectionKey
  if (direct?.parentKey) {
    const children = getNavigationDefinitions(role).find((item) => item.key === direct.parentKey)?.children
    // A route that is also a menu entry selects itself (收款通道).
    if (children?.some((child) => child.key === path)) return path
    const baseline = children?.find((child) => child.implemented !== false)
    if (baseline) return baseline.key
  }
  return path
}

export function getBreadcrumbLabels(
  role: AppRole,
  path: string,
  translate: Translate = defaultTranslate,
): string[] {
  if (/^\/node\/list\/[^/]+$/.test(path)) {
    return [
      translate('navigation:home'),
      translate('navigation:nodes'),
      translate('navigation:nodeList'),
    ]
  }
  if (/^\/node\/l2-config\/node\/[^/]+$/.test(path)) {
    return [
      translate('navigation:home'),
      translate('navigation:nodes'),
      translate('navigation:l2Configuration'),
    ]
  }
  if (path === '/node/isolation') {
    return [
      translate('navigation:home'),
      translate('navigation:nodes'),
      translate('nodeIsolation:title'),
    ]
  }
  if (path === '/node/cname-allocations') {
    return [
      translate('navigation:home'),
      translate('navigation:nodes'),
      translate('cnameAllocations:title'),
    ]
  }
  if (path === '/site/cert/orders') {
    return [
      translate('navigation:home'),
      translate('navigation:sites'),
      translate('navigation:certificates'),
      translate('certificateOrderStatus:title'),
    ]
  }
  if (path === '/monitor/site/analysis/ja4-blocks') {
    return [
      translate('navigation:home'),
      translate('navigation:analytics'),
      translate('navigation:dataAnalysis'),
    ]
  }
  if (role === 'admin' && /^\/node\/line-group\/line\/[^/]+$/.test(path)) {
    return [
      translate('navigation:home'),
      translate('navigation:nodes'),
      translate('nodeL2Topology:line.title'),
    ]
  }
  if (/^\/site\/[^/]+\/dns-reconcile$/.test(path)) {
    return [
      translate('navigation:home'),
      translate('navigation:sites'),
      translate('dnsReconcilePage:title'),
    ]
  }
  if (/^\/site\/(?:list\/[^/]+|[^/]+\/edit)$/.test(path)) {
    return [
      translate('navigation:home'),
      translate('navigation:sites'),
      translate('navigation:siteList'),
    ]
  }
  if (/^\/stream\/list\/[^/]+$/.test(path)) {
    return [
      translate('navigation:home'),
      translate('navigation:streams'),
      translate('streams:detail.title'),
    ]
  }
  if (path === '/site/cache-clean' || path === '/site/cache-clean/history') {
    return [
      translate('navigation:home'),
      translate('navigation:sites'),
      translate('navigation:cacheRefresh'),
    ]
  }
  if (path === '/monitor/site/attack-log') {
    return [
      translate('navigation:home'),
      translate('navigation:analytics'),
      translate('navigation:wafLog'),
    ]
  }
  if (path === '/monitor/site/realtime' && role === 'user') {
    return [
      translate('navigation:home'),
      translate('navigation:analytics'),
      translate('navigation:realtime'),
    ]
  }
  // 顶部条只显示当前页面标题。管理员侧边栏没有账户中心分组，
  // 兜底返回「首页」会让标题渲染成「首页」；这里给出真正的页面标题。
  if (path === '/account/user' && role === 'admin') {
    return [translate('accountProfile:title')]
  }
  if (/^\/sys\/identity-verification(?:\/[^/]+(?:\/decision)?)?$/.test(path)) {
    return [
      translate('navigation:home'),
      translate('navigation:system'),
      translate('identityVerificationReviewQueue:title'),
    ]
  }
  const direct = getDirectRouteDefinition(role, path)
  if (direct) {
    if (direct.breadcrumbKeys) return direct.breadcrumbKeys.map((key) => translate(key))
    const parent = direct.parentKey
      ? getNavigationDefinitions(role).find((item) => item.key === direct.parentKey)
      : undefined
    return direct.parentKey
      ? [
          translate('navigation:home'),
          translate(parent?.labelKey ?? parentLabelKey(direct.parentKey)),
          translate(direct.labelKey),
        ]
      : [translate('navigation:home'), translate(direct.labelKey)]
  }
  for (const item of getNavigationDefinitions(role)) {
    if (item.key === path) return [translate('navigation:home'), translate(item.labelKey)]
    const child = item.children?.find((candidate) => candidate.key === path)
    if (child) return [translate('navigation:home'), translate(item.labelKey), translate(child.labelKey)]
  }
  return [translate('navigation:home')]
}
