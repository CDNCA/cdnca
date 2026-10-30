import { useQuery } from '@tanstack/react-query'

import { fetchPluginUIPages, type PluginUIPage } from '../api/pluginUI'

export const pluginUIPagesQueryKey = ['plugin-ui', 'pages'] as const

const none: readonly PluginUIPage[] = []

// usePluginUIPages lists the ui_page plugin pages this principal may open
// (the server filters by role, permission and granted module). Until the
// answer arrives (or when it fails) there are none, so no plugin menu item
// flashes in.
// With cachedOnly the hook never requests: it reads (and follows) the list
// the app shell loaded, so a page inside the shell adds no request.
export function usePluginUIPages(accessToken: string | null, { cachedOnly = false } = {}): readonly PluginUIPage[] {
  const pages = useQuery({
    queryKey: pluginUIPagesQueryKey,
    queryFn: () => fetchPluginUIPages(accessToken ?? ''),
    enabled: Boolean(accessToken) && !cachedOnly,
    refetchInterval: 5 * 60_000,
    refetchIntervalInBackground: false,
    retry: false,
  })
  return pages.data ?? none
}

/** pluginPagePath is the in-app route of a menu page. */
export function pluginPagePath(page: Pick<PluginUIPage, 'plugin_id' | 'page_id'>): string {
  return `/plugin-ui/${page.plugin_id}/${page.page_id}`
}

export function pluginPageTitle(page: PluginUIPage, locale: string): string {
  return locale.startsWith('en') && page.title['en-US'] ? page.title['en-US'] : page.title['zh-CN']
}
