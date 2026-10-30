// Free / 限免 badges for plugin price plans: one component for the store
// card and detail, "my plugins", the seller centre listing and the operator entry lists. Design
// choice: soft pill with an icon, so free and promo differ by shape and
// word, not by color alone. No motion: it shows up dozens of times per page (emil-design-eng §1).
import { useContext, type ReactNode } from 'react'
import { ConfigProvider } from 'antd'

/** The price plan fields the badge reads (market PricePlan, active revision). */
export interface PriceBadgePlan {
  kind: 'free' | 'one_time' | 'subscription'
  interval?: 'month' | 'year' | null
  price_minor: number
  currency: string
  promo_until?: string | null
  promo_then_kind?: 'one_time' | 'subscription' | null
  promo_then_interval?: 'month' | null
  promo_then_price_minor?: number | null
}

export type PriceBadgeState =
  | { kind: 'free' }
  | { kind: 'promo'; unit: 'day' | 'hour'; amount: number; then: PricedPlan }
  | { kind: 'paid'; price: PricedPlan }

export interface PricedPlan { kind: 'one_time' | 'subscription'; interval?: 'month' | 'year' | null; price_minor: number; currency: string }

const HOUR = 3_600_000
const DAY = 24 * HOUR

/**
 * What the badge shows at now: a live promo counts down in whole days (rounded up), in hours under
 * 24 hours (at least 1); a promo past its deadline shows the price it turned into, before the
 * market's expiry job has repriced the plan.
 */
export function priceBadgeState(plan: PriceBadgePlan, now: number = Date.now()): PriceBadgeState {
  if (plan.kind !== 'free') {
    return { kind: 'paid', price: { kind: plan.kind, interval: plan.interval, price_minor: plan.price_minor, currency: plan.currency } }
  }
  if (!plan.promo_until || !plan.promo_then_kind || !plan.promo_then_price_minor) return { kind: 'free' }
  const then: PricedPlan = { kind: plan.promo_then_kind, interval: plan.promo_then_interval ?? null,
    price_minor: plan.promo_then_price_minor, currency: plan.currency }
  const left = Date.parse(plan.promo_until) - now
  if (!(left > 0)) return { kind: 'paid', price: then }
  if (left < DAY) return { kind: 'promo', unit: 'hour', amount: Math.max(1, Math.ceil(left / HOUR)), then }
  return { kind: 'promo', unit: 'day', amount: Math.ceil(left / DAY), then }
}

const texts = {
  'zh-CN': {
    free: '免费', promo: (n: number, unit: 'day' | 'hour') => `限免 ${n} ${unit === 'day' ? '天' : '小时'}`,
    promoTitle: (price: string) => `限时免费，到期后 ${price}`,
    once: '一次性', month: '/月', year: '/年',
  },
  'zh-TW': {
    free: '免費', promo: (n: number, unit: 'day' | 'hour') => `限免 ${n} ${unit === 'day' ? '天' : '小時'}`,
    promoTitle: (price: string) => `限時免費，到期後 ${price}`,
    once: '一次性', month: '/月', year: '/年',
  },
  'en-US': {
    free: 'Free', promo: (n: number, unit: 'day' | 'hour') => `Free for ${n} ${unit === 'day' ? (n === 1 ? 'day' : 'days') : (n === 1 ? 'hour' : 'hours')}`,
    promoTitle: (price: string) => `Free for a limited time, then ${price}`,
    once: ' once', month: '/month', year: '/year',
  },
}

function useTexts() {
  const locale = useContext(ConfigProvider.ConfigContext).locale?.locale
  return texts[locale === 'en' ? 'en-US' : locale === 'zh-tw' ? 'zh-TW' : 'zh-CN']
}

/** "¥9.90/月", "¥29.00 一次性" in the badge's locale. */
export function formatPlanPrice(price: PricedPlan, t: (typeof texts)['zh-CN'] = texts['zh-CN']): string {
  const amount = (price.price_minor / 100).toFixed(2)
  const money = price.currency === 'CNY' ? `¥${amount}` : `${amount} ${price.currency}`
  if (price.kind === 'one_time') return t === texts['en-US'] ? `${money}${t.once}` : `${money} ${t.once}`
  return `${money}${price.interval === 'year' ? t.year : t.month}`
}

// lucide "gift" and "clock" (stroke icons, same drawings as the apps' lucide-react ones).
const gift = (
  <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M20 12v9H4v-9M2 7h20v5H2zM12 21V7M12 7H7.5a2.5 2.5 0 0 1 0-5C11 2 12 7 12 7zM12 7h4.5a2.5 2.5 0 0 0 0-5C13 2 12 7 12 7z" /></svg>
)
const clock = (
  <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></svg>
)

/**
 * Free / 限免 badge, or the price once nothing is free. paid renders the price as plain text
 * (className cdnca-price-badge-price) unless showPrice is false.
 */
export function PriceBadge({ plan, now, showPrice = true, className }: {
  plan: PriceBadgePlan; now?: number; showPrice?: boolean; className?: string
}): ReactNode {
  const t = useTexts()
  const state = priceBadgeState(plan, now)
  const cls = (name: string) => ['cdnca-price-badge', name, className].filter(Boolean).join(' ')
  if (state.kind === 'free') {
    return <span className={cls('is-free')} data-price-badge="free">{gift}{t.free}</span>
  }
  if (state.kind === 'promo') {
    const then = formatPlanPrice(state.then, t)
    return (
      <span className={cls('is-promo')} data-price-badge="promo" title={t.promoTitle(then)} aria-label={t.promoTitle(then).replace(/^[^，,]+/, t.promo(state.amount, state.unit))}>
        {clock}{t.promo(state.amount, state.unit)}
      </span>
    )
  }
  if (!showPrice) return null
  return <span className={['cdnca-price-badge-price', className].filter(Boolean).join(' ')} data-price-badge="paid">{formatPlanPrice(state.price, t)}</span>
}

const notes = {
  'zh-CN': {
    one_time: (price: string) => `到期后新用户按 ${price} 购买；限免期间已领取的用户继续免费使用，不再收费。永久免费期间领取的用户始终免费。`,
    subscription: (price: string) => `到期后转为按月收费 ${price}：限免期间已领取的用户从到期日起按月扣费（到期前 7 天、1 天提醒，未付按按月插件欠费规则处理）。永久免费期间领取的用户始终免费。`,
  },
  'zh-TW': {
    one_time: (price: string) => `到期後新使用者按 ${price} 購買；限免期間已領取的使用者繼續免費使用，不再收費。永久免費期間領取的使用者始終免費。`,
    subscription: (price: string) => `到期後轉為按月收費 ${price}：限免期間已領取的使用者從到期日起按月扣費（到期前 7 天、1 天提醒，未付按按月外掛欠費規則處理）。永久免費期間領取的使用者始終免費。`,
  },
  'en-US': {
    one_time: (price: string) => `After the deadline new buyers pay ${price}; whoever claimed it during the promo keeps using it free. Whoever claimed it while it was free for good stays free.`,
    subscription: (price: string) => `After the deadline it becomes ${price}: whoever claimed it during the promo is billed monthly from the deadline (reminders 7 days and 1 day before; unpaid follows the monthly arrears rules). Whoever claimed it while it was free for good stays free.`,
  },
}

/** One sentence for the publish form: how holders are billed once the promo ends. */
export function PromoBillingNote({ thenKind, priceMinor, currency = 'CNY' }: {
  thenKind: 'one_time' | 'subscription'; priceMinor?: number; currency?: string
}): ReactNode {
  const locale = useContext(ConfigProvider.ConfigContext).locale?.locale
  const key = locale === 'en' ? 'en-US' : locale === 'zh-tw' ? 'zh-TW' : 'zh-CN'
  const price = priceMinor && priceMinor > 0
    ? formatPlanPrice({ kind: thenKind, interval: thenKind === 'subscription' ? 'month' : null, price_minor: priceMinor, currency }, texts[key])
    : '—'
  return <span className="cdnca-promo-note" data-promo-note={thenKind}>{notes[key][thenKind](price)}</span>
}
