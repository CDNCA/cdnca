import { useQuery } from '@tanstack/react-query'

import { ApiError } from '../../api/auth'
import { firewallActionApi } from '../../api/firewallAction'

// fix-siteautodef：网站编辑「自动防御」标签的读取。查询键与原 CC/WAF 页卡片相同，
// 顶部状态总览和各分区卡片共用同一份缓存（不多发请求）。

interface SiteScope {
  siteId: string
  scopeKind: 'platform' | 'tenant'
  scopeId: string
  siteScopeId?: string
  accessToken: string
  permissions: readonly string[]
}

const has = (permissions: readonly string[], code: string) => permissions.includes(code) || permissions.includes('platform.admin')

/** 攻击自动封禁阈值：本站防火墙动作策略（null = 本站没有，按防火墙动作页的“未配置”）。 */
export function useSiteFirewallAction({ siteId, scopeKind, scopeId, siteScopeId, accessToken, permissions }: SiteScope) {
  const targetScopeId = scopeKind === 'platform' ? siteScopeId : scopeId
  const canRead = Boolean(targetScopeId) && has(permissions, 'firewall.read')
  const query = useQuery({
    queryKey: ['site-protection', scopeId, siteId, 'waf-firewall-action'],
    enabled: canRead,
    retry: false,
    queryFn: async () => {
      try { return await firewallActionApi.get(accessToken, targetScopeId ?? '', siteId) }
      catch (error) {
        if (error instanceof ApiError && (error.status === 404 || error.code === 'firewall_action_not_found')) return null
        throw error
      }
    },
  })
  return { query, canRead, targetScopeId }
}
