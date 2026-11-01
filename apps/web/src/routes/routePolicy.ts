import type { AppRole } from '../auth/session'

export interface RouteAlias {
  from: string
  to: string
  role?: AppRole
}

export const nodeSchedulingReadPermission = 'node_scheduling.read'
export const jobsReadPermission = 'jobs.read'
export const controlUpgradesReadPermission = 'control.upgrades.read'
export const controlUpgradesManagePermission = 'control.upgrades.manage'
export const firewallReadPermission = 'firewall.read'
// /config/waf 只调 /v1/openresty-security/* 与 /v1/cc-rule-groups，后端认这个码（openrestysecurity.PermissionRead）。
export const openrestySecurityReadPermission = 'openresty_security.read'

export const observedRouteAliases: readonly RouteAlias[] = [
  { from: '/site', to: '/site/list' },
  { from: '/stream', to: '/stream/list' },
  { from: '/node', to: '/node/list', role: 'admin' },
  { from: '/config', to: '/config/waf' },
  { from: '/monitor', to: '/monitor/site/realtime' },
  { from: '/account', to: '/account/user' },
  { from: '/sys', to: '/sys/setting' },
  { from: '/account/api', to: '/account/api-key' },
]

export const adminObservedUserBlockedPaths = [
  '/admin-home',
  '/node',
  '/node/l2-config',
  '/node/list',
  '/node/monitor-setting',
  '/node/realtime',
  '/sys/op',
  '/sys/task',
  '/sys/user',
] as const
