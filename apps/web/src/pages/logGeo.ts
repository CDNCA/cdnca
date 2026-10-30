import type { ObservabilityLogFact } from '../api/observabilityLogs'

function countryName(code: string, locale: string): string {
  try {
    return new Intl.DisplayNames([locale], { type: 'region' }).of(code) ?? code
  } catch {
    return code
  }
}

/**
 * B6：日志行的地理位置，显示为「国家-省-市」（如 中国-山东省-潍坊市）。
 * 国家用当前语言的名称；省、市来自主控 IP 库（查询时按来源 IP 补），缺哪段就省哪段。
 * 没有国家（IP 库未加载或未命中）时返回 undefined，由调用方显示占位。
 */
export function factRegion(fact: Pick<ObservabilityLogFact, 'geo_code' | 'geo_region' | 'geo_city'>, locale: string): string | undefined {
  if (!fact.geo_code || fact.geo_code === 'unknown') return undefined
  return [countryName(fact.geo_code, locale), fact.geo_region, fact.geo_city].filter(Boolean).join('-')
}
