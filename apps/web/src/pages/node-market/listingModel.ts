import type {
  MarketListingBatchItem, MarketListingOffer, MarketOfferListing, MarketPrepaidAction, MarketPricing, MarketTags,
} from '../../api/market'
import type { NodeInventoryItem, NodeListResponse } from '../../api/nodes'
import { minorToYuan, yuanToMinor } from '@cdnca/ui/offer-terms'
import { defaultRows, metricRules, toLimits, type LimitRow, type LoadFloor } from './limitsModel'

// Batch listing (ML-11b): one template, many nodes. Pure helpers of the
// listing form, the batch result page and the batch operations on own offers.

export type BillingModel = 'daily_bundle' | 'traffic' | 'bandwidth_95' | 'bandwidth_daily_peak'
export const billingModels: BillingModel[] = ['daily_bundle', 'traffic', 'bandwidth_95', 'bandwidth_daily_peak']

// The form values a template saves (everything but the node selection).
export interface ListingValues {
  name: string
  billing_model: BillingModel
  // Price and deposit in yuan (元, at most 2 decimals; fix-offerform): the form
  // edits yuan, pricingOf sends minor units (分). Saved templates keep minor.
  price: number
  deposit: number
  minDays: number
  maxDays: number
  // Free trial days (0 = none); daily_bundle only, 1–30 (market offers.go:177).
  trialDays: number
  icp: boolean
  prepaid: MarketPrepaidAction
  cc: MarketTags['cc_protection']
  ddos: number
  tenancy: MarketTags['tenancy']
  lineClass?: string
  complaint: boolean
  mobile: boolean
  regionBlock: boolean
  plugins: string[]
  // The seller's own feature words (Tags.custom): ≤ 10, each ≤ 16 characters.
  custom: string[]
}

export const defaultValues: ListingValues = {
  name: '', billing_model: 'daily_bundle', price: 1, deposit: 10, minDays: 1, maxDays: 365, trialDays: 0, icp: false, prepaid: 'pause',
  cc: 'none', ddos: 0, tenancy: 'shared', complaint: false, mobile: false, regionBlock: false, plugins: [], custom: [],
}

// moneyProblems: the yuan fields that cannot be sent exactly (more than 2
// decimals, negative, empty); checked before submit so nothing is rounded.
export function moneyProblems(v: Pick<ListingValues, 'billing_model' | 'price' | 'deposit'>): Array<'price' | 'deposit'> {
  const out: Array<'price' | 'deposit'> = []
  if (yuanToMinor(v.price) === null) out.push('price')
  if (v.billing_model !== 'daily_bundle' && !((yuanToMinor(v.deposit) ?? 0) > 0)) out.push('deposit')
  return out
}

const minor = (yuan: number): number => {
  const value = yuanToMinor(yuan)
  if (value === null) throw new Error('invalid yuan amount')
  return value
}

export function pricingOf(v: Pick<ListingValues, 'billing_model' | 'price' | 'deposit' | 'minDays' | 'maxDays'>): MarketPricing {
  const base = { currency: 'CNY' }
  switch (v.billing_model) {
    case 'daily_bundle': return { ...base, daily_minor: minor(v.price), min_days: v.minDays, max_days: v.maxDays }
    case 'traffic': return { ...base, tiers: [{ up_to_gb: 0, price_per_gb_minor: minor(v.price) }], deposit_minor: minor(v.deposit) }
    case 'bandwidth_95': return { ...base, per_mbps_month_minor: minor(v.price), deposit_minor: minor(v.deposit) }
    case 'bandwidth_daily_peak': return { ...base, per_mbps_day_minor: minor(v.price), deposit_minor: minor(v.deposit) }
  }
}

// examplePrice: what one subscriber pays at the given price (yuan), for the
// live example under the price: 100 Mbps for a month, 100 GB, or one day.
export function exampleCharge(model: BillingModel, price: number): { quantity: number; total: number } | null {
  const unit = yuanToMinor(price)
  if (unit === null) return null
  const quantity = model === 'daily_bundle' ? 30 : 100
  return { quantity, total: unit * quantity }
}

// offerOf builds the offer body every item shares; the controller adds each
// item's own pool (and node name in single-node mode).
export function offerOf(v: ListingValues, rows: LimitRow[], floor: LoadFloor | null): MarketListingOffer {
  const { limits } = toLimits(rows, floor)
  return {
    name: v.name.trim(), billing_model: v.billing_model, allocation: { http_ports: 2 }, limits,
    tags: {
      cc_protection: v.cc, ddos_protection_gbps: v.ddos, complaint_resistant: v.complaint, tenancy: v.tenancy,
      mobile_reachable: v.mobile, region_block: v.regionBlock, ...(v.lineClass?.trim() ? { line_class: v.lineClass.trim() } : {}),
      ...(v.plugins?.length ? { plugins: [...v.plugins].sort() } : {}), ...customOf(v),
    },
    prepaid_exhausted_action: v.prepaid, compliance: { require_icp: v.icp }, pricing: pricingOf(v),
    trial_days: trialDaysOf(v),
  }
}

export const maxCustomTags = 10
export const maxCustomTagLength = 16

// normalizeCustom mirrors spec.Tags.Normalize: trim, drop blanks and repeats.
export function normalizeCustom(custom: string[] | undefined): string[] {
  const out: string[] = []
  for (const raw of custom ?? []) {
    const c = raw.trim()
    if (c && !out.includes(c)) out.push(c)
  }
  return out
}

// customProblem: why the custom tags would be refused (spec.Tags.Validate).
export function customProblem(custom: string[] | undefined): 'tooMany' | 'tooLong' | 'control' | null {
  const list = normalizeCustom(custom)
  if (list.length > maxCustomTags) return 'tooMany'
  // eslint-disable-next-line no-control-regex
  if (list.some((c) => /[\u0000-\u001f\u007f-\u009f]/.test(c))) return 'control'
  if (list.some((c) => [...c].length > maxCustomTagLength)) return 'tooLong'
  return null
}

export function customOf(v: Pick<ListingValues, 'custom'>): { custom?: string[] } {
  const list = normalizeCustom(v.custom)
  return list.length ? { custom: list } : {}
}

// The market refuses a trial on metered offers: only a daily bundle keeps it.
export function trialDaysOf(v: Pick<ListingValues, 'billing_model' | 'trialDays'>): number {
  return v.billing_model === 'daily_bundle' ? Math.min(Math.max(Math.trunc(v.trialDays || 0), 0), 30) : 0
}

// Templates store the form as is; reading one back keeps only known keys and
// valid limit rows, so an edited or older template cannot break the form.
export function templateBody(v: ListingValues, rows: LimitRow[]): Record<string, unknown> {
  // Stored in minor units as before, so templates saved earlier read back unchanged.
  return { values: { ...v, price: yuanToMinor(v.price) ?? 0, deposit: yuanToMinor(v.deposit) ?? 0 }, limits: rows.filter((r) => r.enabled) }
}

export function fromTemplate(body: Record<string, unknown>): { values: ListingValues; rows: LimitRow[] } {
  const raw = (body.values ?? {}) as Partial<Record<keyof ListingValues, unknown>>
  const values = { ...defaultValues }
  for (const key of Object.keys(defaultValues) as Array<keyof ListingValues>) {
    const value = raw[key]
    const expected = Array.isArray(defaultValues[key]) ? 'array' : typeof defaultValues[key]
    if (value !== undefined && (expected === 'array' ? Array.isArray(value) : typeof value === expected)) {
      (values as Record<string, unknown>)[key] = value
    }
  }
  if (typeof raw.lineClass === 'string') values.lineClass = raw.lineClass
  if (typeof raw.price === 'number') values.price = minorToYuan(raw.price)
  if (typeof raw.deposit === 'number') values.deposit = minorToYuan(raw.deposit)
  values.custom = values.custom.filter((c): c is string => typeof c === 'string')
  if (!billingModels.includes(values.billing_model)) values.billing_model = 'daily_bundle'
  const saved = Array.isArray(body.limits) ? (body.limits as Array<Partial<LimitRow>>) : []
  const rows = defaultRows().map((row) => {
    const s = saved.find((r) => r.metric === row.metric)
    const rule = metricRules.find((r) => r.metric === row.metric)!
    if (!s) return row
    return {
      ...row, enabled: true, value: typeof s.value === 'number' ? s.value : null,
      unit: s.unit && rule.units.includes(s.unit) ? s.unit : row.unit,
      action: s.action && rule.actions.includes(s.action) ? s.action : row.action,
      throttleMbps: typeof s.throttleMbps === 'number' ? s.throttleMbps : null,
    }
  })
  return { values, rows }
}

// allNodes reads the whole node inventory along the server cursor (B21): the
// selection, filters and batch removals cover every node, not the first page.
export async function allNodes(page: (cursor?: string) => Promise<NodeListResponse>, maxPages = 500): Promise<NodeInventoryItem[]> {
  const out: NodeInventoryItem[] = []
  let cursor: string | undefined
  for (let i = 0; i < maxPages; i++) {
    const next = await page(cursor)
    out.push(...next.items)
    if (!next.next_cursor) return out
    cursor = next.next_cursor
  }
  return out
}

// Node filters: region / carrier / line grade, and a keyword over name,
// description and display id (nodes carry no separate tags).
export interface NodeFilter { region?: string; carrier?: string; grade?: string; keyword?: string; onlineOnly?: boolean }

export const regionOf = (n: NodeInventoryItem) => n.management_settings.ip_location.country_code || n.region || ''
export const carrierOf = (n: NodeInventoryItem) => n.management_settings.ip_location.isp || ''

export function filterNodes(nodes: NodeInventoryItem[], f: NodeFilter, grades: Record<string, string>): NodeInventoryItem[] {
  const keyword = f.keyword?.trim().toLowerCase() ?? ''
  return nodes.filter((n) => (!f.region || regionOf(n) === f.region) && (!f.carrier || carrierOf(n) === f.carrier) &&
    (!f.grade || (grades[n.id] ?? '') === f.grade) && (!f.onlineOnly || n.presence?.status === 'online') &&
    (!keyword || [n.name, n.description, n.display_id].some((s) => (s ?? '').toLowerCase().includes(keyword))))
}

// unpublished: offers made (now drafts) whose publish failed (B19).
export function unpublished(items: MarketListingBatchItem[]): MarketListingBatchItem[] {
  return items.filter((i) => (i.status === 'created' || i.status === 'existing') && !!i.error?.startsWith('publish_'))
}

// retryNodes: the node ids of failed and unpublished items, for resubmitting
// only those. The controller returns what was made for the others, and
// publishes an unpublished item's own offer again instead of creating one.
export function retryNodes(items: MarketListingBatchItem[]): string[] {
  const again = new Set(unpublished(items))
  return items.filter((i) => i.status === 'failed' || i.status === 'in_progress' || again.has(i)).flatMap((i) => i.node_ids)
}

// mergeResults replaces the results of the resubmitted items.
export function mergeResults(previous: MarketListingBatchItem[], next: MarketListingBatchItem[]): MarketListingBatchItem[] {
  const key = (i: MarketListingBatchItem) => [...i.node_ids].sort().join(',')
  const fresh = new Map(next.map((i) => [key(i), i]))
  const out = previous.map((i) => fresh.get(key(i)) ?? i)
  for (const i of next) if (!previous.some((p) => key(p) === key(i))) out.push(i)
  return out
}

// Batch price change of own offers: set the main price, or change it by a
// percentage; the billing model and currency stay (PUT terms checks both).
export type PriceChange = { kind: 'set'; value: number } | { kind: 'percent'; value: number }

const mainPrice = (p: MarketPricing, model: string): number | undefined => {
  switch (model) {
    case 'daily_bundle': return p.daily_minor
    case 'traffic': return p.tiers?.[0]?.price_per_gb_minor
    case 'bandwidth_95': return p.per_mbps_month_minor
    case 'bandwidth_daily_peak': return p.per_mbps_day_minor
  }
  return undefined
}

export function repriced(offer: MarketOfferListing, change: PriceChange): MarketPricing | null {
  const current = mainPrice(offer.pricing, offer.billing_model)
  if (current === undefined) return null
  const next = change.kind === 'set' ? change.value : Math.round(current * (1 + change.value / 100))
  if (!Number.isInteger(next) || next < 0) return null
  const p = { ...offer.pricing }
  switch (offer.billing_model) {
    case 'daily_bundle': p.daily_minor = next; break
    case 'traffic': p.tiers = [{ ...p.tiers![0], price_per_gb_minor: next }, ...p.tiers!.slice(1)]; break
    case 'bandwidth_95': p.per_mbps_month_minor = next; break
    case 'bandwidth_daily_peak': p.per_mbps_day_minor = next; break
  }
  return p
}

export function priceOf(offer: MarketOfferListing): number | undefined {
  return mainPrice(offer.pricing, offer.billing_model)
}

// poolsOf: the own pools (hidden supply groups of this controller) behind an offer.
export function poolsOf(offer: MarketOfferListing): string[] {
  return (offer.components ?? []).filter((c) => c.kind === 'own_pool' && c.node_pool_ref).map((c) => c.node_pool_ref!)
}

// runLimited runs task over items with at most limit in flight, keeping order.
export async function runLimited<T, R>(items: T[], limit: number, task: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length)
  let next = 0
  const worker = async () => {
    while (next < items.length) {
      const i = next++
      out[i] = await task(items[i])
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
  return out
}
