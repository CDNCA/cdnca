import type { TFunction } from 'i18next'

import type { MarketOfferListing } from '../../api/market'
import { formatYuan } from '@cdnca/ui/offer-terms'

// The price each billing model charges, in its own unit (market-service
// quality.go unitPrice: what the max_price filter compares).
export function offerUnitPrice(o: MarketOfferListing): number | undefined {
  const p = o.pricing
  switch (o.billing_model) {
    case 'daily_bundle': return p?.daily_minor ?? 0
    case 'traffic': return p?.tiers?.[0]?.price_per_gb_minor
    case 'bandwidth_95': return p?.per_mbps_month_minor
    case 'bandwidth_daily_peak': return p?.per_mbps_day_minor
  }
  return undefined
}

/** "1.00 元 / 天", "0.30 元 / GB 起" (prices are stored in minor units); unknown models show —. */
export function offerPriceText(t: TFunction, o: MarketOfferListing): string {
  const value = offerUnitPrice(o)
  return value === undefined ? '—' : t(`priceUnits.${o.billing_model}`, { value: formatYuan(value) })
}

/** Not yet evaluated, too few samples, or the score (0 included). */
export function offerQualityText(t: TFunction, o: MarketOfferListing): string {
  const q = o.quality
  if (!q) return t('quality.none')
  if (q.tier === 'insufficient') return t('quality.insufficient')
  return q.score.toFixed(2)
}
