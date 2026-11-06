import { useQuery } from '@tanstack/react-query'

import type { MarketPlugin } from '../../api/market'
import { platformPluginInstallationsApi, type PluginInstallation } from '../../api/pluginInstallations'
import { probeDNSPupApi, probeDNSPupModule, probeDNSPupPermission } from '../../api/probeDNSPup'
import { useSessionStore } from '../../auth/session'
import { usePluginUIPages } from '../../pluginui/usePluginUIPages'
import { isImplementedPath } from '../../routes/navigation'
import { configPath } from './marketModel'

const readPermission = 'plugin_installations.platform.read'

// Platform installation records of this controller (themes, rule packs, page plugins, external services), only for a
// platform session that may read them; undefined until read or when it may not. Under ['marketStore', …] so writes
// there and in 安装记录 refresh it as well.
export function usePlatformInstallations(): readonly PluginInstallation[] | undefined {
  const token = useSessionStore((s) => s.accessToken) ?? ''
  const principal = useSessionStore((s) => s.principal)
  const allowed = principal?.scope_kind === 'platform' && principal.permissions.includes(readPermission)
  const query = useQuery({
    queryKey: ['marketStore', 'library', 'platformInstallations'], enabled: Boolean(token && allowed), retry: false,
    queryFn: async () => {
      // 100 per page (the API maximum), at most 10 pages: one record per plugin, far below that.
      const items: PluginInstallation[] = []
      let cursor: string | undefined
      for (let page = 0; page < 10; page++) {
        const result = await platformPluginInstallationsApi.list(token, '', { limit: 100, ...(cursor ? { cursor } : {}) })
        items.push(...result.items)
        cursor = result.next_cursor
        if (!cursor) break
      }
      return items
    },
  })
  return allowed ? query.data : undefined
}

// The configuration page of a plugin this account can open (same rule as 我的插件 去配置): plugin pages are already
// filtered by the server, every other path by the menu rule.
export function useConfigPath(modules: readonly string[]): (plugin: MarketPlugin) => string | null {
  const token = useSessionStore((s) => s.accessToken)
  const permissions = useSessionStore((s) => s.principal?.permissions)
  const uiPages = usePluginUIPages(token)
  return (plugin) => {
    const path = configPath(plugin, uiPages)
    return path && (path.startsWith('/plugin-ui/') || isImplementedPath('admin', path.split('?')[0], permissions, modules)) ? path : null
  }
}

// dnspup 拨测 status (same query as its settings page), read only when the feature is granted and the page is open
// to this account: it is the only setup the store can tell (moduleSetup).
export function useDNSPupStatus(modules: readonly string[]) {
  const token = useSessionStore((s) => s.accessToken) ?? ''
  const principal = useSessionStore((s) => s.principal)
  const allowed = principal?.scope_kind === 'platform' && modules.includes(probeDNSPupModule) &&
    (principal.permissions.includes(probeDNSPupPermission) || principal.permissions.includes('platform.admin'))
  return useQuery({ queryKey: ['probe-dnspup'], queryFn: () => probeDNSPupApi.status(token), enabled: Boolean(token && allowed),
    retry: false }).data
}
