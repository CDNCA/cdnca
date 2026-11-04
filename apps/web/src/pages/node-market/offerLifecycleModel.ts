import type { MarketLimit, MarketOfferListing, MarketPricing } from '../../api/market'
import { formatDateTime } from '../../i18n/formatters'
import { defaultRows, ruleOf, type LimitRow } from './limitsModel'
import { minorToYuan, yuanToMinor } from '@cdnca/ui/offer-terms'

// the pure parts of 我的上架's per-row 修改报价 / 下架 / 删除
// (OfferTermsModal.tsx, OfferLifecycle.tsx).

export type Action = 'delist' | 'delete'
export interface Gate { ok: boolean; why?: string }

// gates says which actions an offer allows and, when not, why (t: nodeMarket).
export function gates(o: MarketOfferListing, t: (key: string, values?: Record<string, unknown>) => string): Record<Action, Gate> {
  const l = o.lifecycle
  const at = l?.completes_at ? formatDateTime(l.completes_at) : ''
  const state = l?.state ?? o.status
  const delist: Gate = state === 'draft' ? { ok: false, why: t('life.why.delistDraft') }
    : state === 'listed' || state === 'pending_review' || (l ? l.renewing_subscriptions > 0 : false) ? { ok: true }
      : { ok: false, why: t('life.why.delistDone') }
  const del: Gate = !l ? { ok: false, why: t('life.why.deleteUnknown') }
    : l.deletable ? { ok: true }
      : state === 'delisting' ? { ok: false, why: t('life.why.deleteBuyers', { count: l.active_subscriptions, at }) }
        : { ok: false, why: t('life.why.deleteListed') }
  return { delist, delete: del }
}

// rowsOf opens the limit rows on the offer's limits, in each metric's base unit so a cap reads back exactly.
export function rowsOf(limits: MarketLimit[] | undefined): LimitRow[] {
  return defaultRows().map((row) => {
    const l = limits?.find((x) => x.metric === row.metric)
    if (!l) return row
    const unit = ruleOf(row.metric).units[0]
    const factor = unit === 'Mbps' ? 1e6 : unit === 'GB' ? 1024 ** 3 : 1
    return { ...row, enabled: true, value: l.cap / factor, unit, action: l.action, throttleMbps: l.throttle_bps ? l.throttle_bps / 1e6 : null }
  })
}

// withSustain keeps each metric's sustain_buckets (not edited here) on the new limits.
export function withSustain(next: MarketLimit[], current: MarketLimit[] | undefined): MarketLimit[] {
  return next.map((l) => {
    const sustain = current?.find((c) => c.metric === l.metric)?.sustain_buckets
    return sustain ? { ...l, sustain_buckets: sustain } : l
  })
}

export type Yuan = number | null
export interface PriceForm { main: Yuan; minDays: number | null; maxDays: number | null; deposit: Yuan; tiers: Yuan[] }

const mainField = { daily_bundle: 'daily_minor', bandwidth_95: 'per_mbps_month_minor', bandwidth_daily_peak: 'per_mbps_day_minor' } as const

export function priceFormOf(o: MarketOfferListing): PriceForm {
  const p = o.pricing
  const field = mainField[o.billing_model as keyof typeof mainField]
  const main = field ? p[field] : undefined
  return { main: main === undefined ? null : minorToYuan(main), minDays: p.min_days ?? null, maxDays: p.max_days ?? null,
    deposit: p.deposit_minor === undefined ? null : minorToYuan(p.deposit_minor), tiers: (p.tiers ?? []).map((t) => minorToYuan(t.price_per_gb_minor)) }
}

// pricingOf rebuilds the offer's pricing with the edited figures; null when one is not a valid yuan amount.
export function pricingOf(o: MarketOfferListing, f: PriceForm): MarketPricing | null {
  const p: MarketPricing = { ...o.pricing }
  const minor = (v: Yuan) => (v === null ? null : yuanToMinor(v))
  if (o.billing_model === 'traffic') {
    const tiers = (o.pricing.tiers ?? []).map((t, i) => ({ ...t, price_per_gb_minor: minor(f.tiers[i] ?? null) }))
    if (tiers.some((t) => t.price_per_gb_minor === null)) return null
    p.tiers = tiers as MarketPricing['tiers']
  } else {
    const field = mainField[o.billing_model as keyof typeof mainField]
    const main = minor(f.main)
    if (!field || main === null) return null
    p[field] = main
  }
  if (o.billing_model === 'daily_bundle') {
    if (!f.minDays || !f.maxDays || f.minDays > f.maxDays) return null
    p.min_days = f.minDays
    p.max_days = f.maxDays
  } else if (o.pricing.deposit_minor !== undefined) {
    const deposit = minor(f.deposit)
    if (deposit === null) return null
    p.deposit_minor = deposit
  }
  return p
}

