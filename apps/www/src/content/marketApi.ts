// 浏览器端读取市场公开只读接口（services/market-service/internal/httpapi/public_listing.go）。
// 不带凭据；字段与服务端白名单一致。接口不可用（网络错误、非 2xx、格式不对）一律抛错，
// 页面显示“暂无公开数据”与授权门户链接，不影响其他页面。
import type { Lang } from '../i18n'
import { MARKET_PUBLIC_API } from '../site'

export interface PublicOffer {
  id: string
  name: string
  seller_name: string
  regions: string[]
  carriers: string[]
  line_class?: string
  // The seller's own feature words (self-declared).
  custom?: string[]
  billing_model: string
  pricing: {
    currency: string
    daily_minor?: number
    min_days?: number
    max_days?: number
    tiers?: { up_to_gb: number; price_per_gb_minor: number }[]
    per_mbps_month_minor?: number
    per_mbps_day_minor?: number
  }
  trial_days: number
  serving_nodes: string
  quality_tier: string
}

export interface PublicPlugin {
  id: string
  plugin_id: string
  title: string
  summary: string
  kind: string
  publisher_kind: 'official' | 'certified' | 'third_party'
  categories: string[]
  latest_version?: string
  price_models: string[]
}

export interface Page<T> {
  items: T[]
  page: number
  has_more: boolean
}

async function getPage<T>(path: string, signal?: AbortSignal): Promise<Page<T>> {
  const res = await fetch(`${MARKET_PUBLIC_API}${path}`, { credentials: 'omit', signal, headers: { Accept: 'application/json' } })
  if (!res.ok) throw new Error(`market ${res.status}`)
  const body = (await res.json()) as Page<T>
  if (!body || !Array.isArray(body.items)) throw new Error('market: bad body')
  return body
}

export const marketApi = {
  nodeOffers: (signal?: AbortSignal) => getPage<PublicOffer>('/node-offers', signal),
  plugins: (signal?: AbortSignal) => getPage<PublicPlugin>('/plugins', signal),
}

function money(minor: number, currency: string) {
  return `${(minor / 100).toFixed(2).replace(/\.00$/, '')} ${currency}`
}

/** 供货方报价原样展示：只格式化单位，不计算、不评论。 */
export function offerPrice(o: PublicOffer, lang: Lang): string {
  const p = o.pricing
  const zh = lang === 'zh'
  switch (o.billing_model) {
    case 'daily_bundle':
      return p.daily_minor != null ? `${money(p.daily_minor, p.currency)} ${zh ? '/ 天' : '/ day'}` : '—'
    case 'traffic':
      return p.tiers?.length ? `${money(p.tiers[0].price_per_gb_minor, p.currency)} ${zh ? '/ GB 起' : '/ GB from'}` : '—'
    case 'bandwidth_95':
      return p.per_mbps_month_minor != null ? `${money(p.per_mbps_month_minor, p.currency)} ${zh ? '/ Mbps·月' : '/ Mbps·month'}` : '—'
    case 'bandwidth_daily_peak':
      return p.per_mbps_day_minor != null ? `${money(p.per_mbps_day_minor, p.currency)} ${zh ? '/ Mbps·天' : '/ Mbps·day'}` : '—'
  }
  return '—'
}
