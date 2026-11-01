import { useQuery } from '@tanstack/react-query'

import { marketApi, type MarketPlugin } from '../../api/market'

const none = new Map<string, MarketPlugin>()

// The control-api proxy caps one query value at 1024 bytes and the market one lookup at 200 ids.
const maxBatchBytes = 1000
const maxBatchIDs = 200

/** idBatches splits plugin ids into comma-joined lookups within the proxy and market limits. */
export function idBatches(ids: readonly string[]): string[][] {
  const batches: string[][] = []
  let current: string[] = []
  let bytes = 0
  for (const id of [...new Set(ids)].sort()) {
    // +1 for the comma before every id but the first
    if (current.length && (bytes + 1 + id.length > maxBatchBytes || current.length === maxBatchIDs)) {
      batches.push(current)
      current = []
      bytes = 0
    }
    bytes += (current.length ? 1 : 0) + id.length
    current.push(id)
  }
  if (current.length) batches.push(current)
  return batches
}

/**
 * usePluginCatalog names the plugins a table shows (已购、我的插件、安全公告、安装记录): the market entries of
 * exactly these plugin_ids (GET /v1/admin/market/plugins?plugin_ids=, batched, delisted ones included), so the
 * size of the market catalog never matters. An id the market does not know, or a failed read, falls back to the
 * plugin_id.
 */
export function usePluginCatalog(token: string | null | undefined, pluginIDs: readonly string[]): Map<string, MarketPlugin> {
  const batches = idBatches(pluginIDs)
  const query = useQuery({
    queryKey: ['pluginStore', 'catalogNames', batches.map((b) => b.join(','))],
    queryFn: async () => {
      const pages = await Promise.all(batches.map((ids) => marketApi.pluginsByID(token ?? '', ids)))
      return new Map(pages.flat().map((p) => [p.plugin_id, p]))
    },
    enabled: Boolean(token) && batches.length > 0,
    staleTime: 5 * 60_000,
    retry: false,
  })
  return query.data ?? none
}

const english = (language: string | undefined) => language === 'en-US'

/** pluginTitle is the entry's name in the interface language: the English name in en-US when it has one. */
export function pluginTitle(plugin: Pick<MarketPlugin, 'title' | 'title_en'>, language: string | undefined): string {
  return (english(language) && plugin.title_en) || plugin.title
}

/** pluginSummary is the entry's summary in the interface language, falling back to the Chinese one. */
export function pluginSummary(plugin: Pick<MarketPlugin, 'summary' | 'summary_en'>, language: string | undefined): string {
  return (english(language) && plugin.summary_en) || plugin.summary || ''
}

/** pluginDescription is the entry's description in the interface language, falling back to the Chinese one. */
export function pluginDescription(plugin: Pick<MarketPlugin, 'description_md' | 'description_md_en'>, language: string | undefined): string {
  return (english(language) && plugin.description_md_en) || plugin.description_md || ''
}

/** pluginName is the catalog name of pluginID in the interface language, or the ID itself when not known. */
export function pluginName(catalog: Map<string, MarketPlugin>, pluginID: string, language: string | undefined): string {
  const plugin = catalog.get(pluginID)
  return (plugin && pluginTitle(plugin, language)) || pluginID
}
