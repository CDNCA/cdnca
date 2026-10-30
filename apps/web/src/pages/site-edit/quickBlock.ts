import type { QuickBlockCrawler, SecurityPolicyQuickBlock } from '../../api/securityPolicies'

export const maxQuickBlockCrawlerNetworks = 32

/** One "network,User-Agent prefix" line per network × prefix of the stored crawlers. */
export function crawlersToText(crawlers: QuickBlockCrawler[] | undefined): string {
  return (crawlers ?? []).flatMap((crawler) => crawler.networks.flatMap((network) =>
    crawler.user_agent_prefixes.map((prefix) => `${network},${prefix}`))).join('\n')
}

export type CrawlerParse = { crawlers: QuickBlockCrawler[]; networks: number } | { invalidLine: number }

/**
 * Parses "network,User-Agent prefix" lines (the prefix may contain commas;
 * only the first one separates). Lines of one network become one crawler
 * contract with all its prefixes, which is one quick block allow rule.
 */
export function parseCrawlers(text: string): CrawlerParse {
  const byNetwork = new Map<string, string[]>()
  const lines = text.split('\n')
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!.trim()
    if (!line) continue
    const separator = line.indexOf(',')
    const network = separator > 0 ? line.slice(0, separator).trim() : ''
    const prefix = separator > 0 ? line.slice(separator + 1).trim() : ''
    if (!network || !prefix || /\s/.test(network)) return { invalidLine: index + 1 }
    const prefixes = byNetwork.get(network) ?? []
    if (!prefixes.includes(prefix)) prefixes.push(prefix)
    byNetwork.set(network, prefixes)
  }
  const crawlers = [...byNetwork.entries()].map(([network, prefixes]) => ({ networks: [network], user_agent_prefixes: prefixes }))
  return { crawlers, networks: crawlers.length }
}

export function quickBlockActive(block: Pick<SecurityPolicyQuickBlock, 'block_idc_cn' | 'block_idc_global' | 'carriers'> | undefined): boolean {
  return Boolean(block && (block.block_idc_cn || block.block_idc_global || block.carriers.length > 0))
}
