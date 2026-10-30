import { ApiError } from './auth'
import { call, pageOf, query, type MarketPage } from './market'

// ADR 0012 ML-28 supplier and subscriber pages. Shapes follow the market
// endpoints that serve them:
// ML-16 subscribers/holds, ML-17 stop complaints, ML-19 resale switch,
// ML-23/24 same-site pauses, ML-27 commission prepaid, ML-31 outage cancel.

export type SupplyState = 'serving' | 'paused' | 'stopped' | 'overloaded' | 'no_supply'
export type ResumeCondition = 'limit_below_80pct_two_buckets' | 'balance_non_negative' | 'platform_review'

export interface SubscriberHold {
  reason: string
  metric: string | null
  action: 'throttle' | 'pause' | 'stop'
  observed: number
  cap: number
  since: string
  leaf_member_id: string | null
  node_pool_ref: string | null
  resume_condition: ResumeCondition | string
}

// One row of GET /v1/seller/subscribers: identity on direct rows only,
// downstream rows carry downstream_ref and the direct buyer they come through.
export interface SupplierSubscriber {
  relation: 'direct' | 'downstream'
  subscription_id: string
  offer_id: string
  status: string
  paid_through: string
  buyer_id?: string
  buyer_name?: string
  downstream_ref?: string
  via_member_id?: string
  via_name?: string
  supply_state: SupplyState | string
  domains: string[]
  pools: string[]
  traffic: { last_24h_bytes: number; month_bytes: number }
  holds: SubscriberHold[]
  note: string
  // The stop of the seller's own hop subscription and its compensation rule version.
  renewal_stop?: { code: number; reason: string; initiator: string; since: string } | null
  compensation_policy?: string
}

// One suspended (pause/stop) slot, GET /v1/holds (buyer) or /v1/seller/holds.
export interface HoldRow {
  subscription_id: string
  leaf_member_id: string
  node_pool_ref: string
  reason: string
  metric: string | null
  action: 'pause' | 'stop'
  observed: number
  cap: number
  since: string
  resume_condition: ResumeCondition | string
  relation?: 'direct' | 'downstream'
  buyer_name?: string
  downstream_ref?: string
  via_name?: string
}

export const complaintCategories = ['illegal', 'node_blocked', 'abuse_complaint', 'attack_source', 'seller_exit', 'other'] as const
export type ComplaintCategory = typeof complaintCategories[number]
export type ComplaintState = 'open' | 'reviewing' | 'actioned' | 'rejected' | 'withdrawn'
export interface ComplaintEvidence {
  domains?: string[]
  from?: string
  to?: string
  attachments?: Array<{ name: string; url: string }>
}
export interface ComplaintInput {
  offer_id: string
  // A direct subscriber's subscription id, or a downstream row's downstream_ref.
  target_ref: string
  category: ComplaintCategory
  detail: string
  evidence: ComplaintEvidence
}
export interface Complaint {
  id: string
  offer_id: string
  target_ref: string
  category: ComplaintCategory
  detail: string
  evidence: ComplaintEvidence
  state: ComplaintState
  action: string | null
  created_at: string
  resolved_at: string | null
  released_at: string | null
  revision: number
}

export interface SitePause {
  id: string
  root_subscription: string
  leaf_member_id: string
  node_pool_ref: string
  leaf_site_id: string
  count: number
  after_actions: number
  since: string
  released_at?: string | null
  released_by?: string
}

export interface CommissionPrepaid {
  customer_id: string
  enabled: boolean
  currency: string
  balance_minor: number
  threshold_minor: number
  exhausted_since: string | null
  due_minor: number
  last_7_days_minor: number
}
export interface CommissionDeduction {
  id: number
  member_id: string
  currency: string
  period_start: string
  amount_minor: number
  due_minor: number
  idempotency_key: string
  created_at: string
}

export interface SupplyOutage { id: string; since: string; cancel_available_at?: string | null }
// B26: what a liability-free outage cancel booked (market SubscriptionView.outage_settlement).
export interface OutageSettlement { billing_model: string; currency: string; credit_minor: number; refund_minor: number }

// Refusal bodies the pages explain (marketsubscribehttp writeSupplyInUse,
// node API error.details, market offerRefusal).
export interface SupplyInUse { online_available: number; normal_subscriptions: number }
export function supplyInUse(error: unknown): SupplyInUse | null {
  if (!(error instanceof ApiError) || error.code !== 'supply_in_use') return null
  const raw = (error as ApiError & { refusal?: unknown }).refusal as Record<string, unknown> | undefined
  const details = (raw?.error && typeof raw.error === 'object' ? (raw.error as Record<string, unknown>).details : raw) as
    Record<string, unknown> | undefined
  const online = Number(details?.online_available)
  const normal = Number(details?.normal_subscriptions)
  return Number.isSafeInteger(online) && Number.isSafeInteger(normal) ? { online_available: online, normal_subscriptions: normal } : null
}
export function resaleForbiddenBy(error: unknown): string | null {
  if (!(error instanceof ApiError) || error.code !== 'resale_forbidden') return null
  const ref = ((error as ApiError & { refusal?: unknown }).refusal as Record<string, unknown> | undefined)?.forbidden_by
  return typeof ref === 'string' && /^r-[0-9a-f]{1,32}$/.test(ref) ? ref : ''
}

const id = (value: string) => encodeURIComponent(value)
const put = (body: unknown): RequestInit => ({ method: 'PUT', body: JSON.stringify(body) })
const post = (body: unknown): RequestInit => ({ method: 'POST', body: JSON.stringify(body) })

// Rows per server page of the cursor-paged supplier lists (market clamps to 200).
export const supplierPageSize = 100

export const marketSupplierApi = {
  subscribers: (token: string, offerID?: string, cursor?: string) =>
    call<unknown>(token, `/v1/admin/market/seller/subscribers${query({ offer_id: offerID, cursor, limit: supplierPageSize })}`)
      .then((v) => pageOf<SupplierSubscriber>(v)),
  setNote: (token: string, row: Pick<SupplierSubscriber, 'subscription_id' | 'downstream_ref'>, note: string) =>
    call<unknown>(token, '/v1/admin/market/seller/subscribers/note',
      put({ subscription_id: row.subscription_id, downstream_ref: row.downstream_ref ?? '', note })),
  sellerHolds: (token: string, cursor?: string): Promise<MarketPage<HoldRow>> =>
    call<unknown>(token, `/v1/admin/market/seller/holds${query({ cursor, limit: 100 })}`).then((v) => pageOf<HoldRow>(v)),
  buyerHolds: (token: string, cursor?: string): Promise<MarketPage<HoldRow>> =>
    call<unknown>(token, `/v1/admin/market/holds${query({ cursor, limit: 100 })}`).then((v) => pageOf<HoldRow>(v)),

  fileComplaint: (token: string, input: ComplaintInput) =>
    call<Complaint>(token, '/v1/admin/market/supply-complaints', post(input)),
  complaints: (token: string, cursor?: string) =>
    call<unknown>(token, `/v1/admin/market/supply-complaints${query({ cursor, limit: supplierPageSize })}`).then((v) => pageOf<Complaint>(v)),
  complaint: (token: string, complaintID: string) =>
    call<Complaint>(token, `/v1/admin/market/supply-complaints/${id(complaintID)}`),
  withdrawComplaint: (token: string, complaintID: string) =>
    call<Complaint>(token, `/v1/admin/market/supply-complaints/${id(complaintID)}/withdraw`, post({})),

  sitePauses: (token: string, open: boolean) =>
    call<{ items: SitePause[] }>(token, `/v1/admin/market/site-pauses${query({ open: open ? 'true' : undefined })}`).then((v) => v.items ?? []),
  resumeSitePause: (token: string, pauseID: string) =>
    call<SitePause>(token, `/v1/admin/market/site-pauses/${id(pauseID)}/resume`, post({})),

  commissionPrepaid: (token: string, currency?: string) =>
    call<CommissionPrepaid>(token, `/v1/admin/market/commission/prepaid${query({ currency })}`),
  setCommissionPrepaid: (token: string, enabled: boolean, currency: string) =>
    call<CommissionPrepaid>(token, '/v1/admin/market/commission/prepaid', put({ enabled, currency })),
  setCommissionAlert: (token: string, currency: string, thresholdMinor: number) =>
    call<unknown>(token, '/v1/admin/market/commission/prepaid/alert', put({ currency, threshold_minor: thresholdMinor })),
  // Newest first by cursor (the market's default window: the last 31 days).
  commissionDeductions: (token: string, cursor?: string) =>
    call<unknown>(token, `/v1/admin/market/commission/prepaid/deductions${query({ cursor, limit: supplierPageSize })}`)
      .then((v) => pageOf<CommissionDeduction>(v)),
  commissionTopup: (token: string, amountMinor: number, currency: string, key: string) =>
    call<{ order: { order_no: number }; checkout_url?: string | null }>(token, '/v1/admin/market/orders',
      post({ kind: 'commission_topup', amount_minor: amountMinor, currency }), key),

  // Seller switches on an offer (PUT terms carries the current pricing back unchanged).
  setOfferSwitches: (token: string, offerID: string, pricing: unknown, switches: { resale_allowed?: boolean; site_auto_pause?: boolean }, key: string, expectedRevision?: number) =>
    call<unknown>(token, `/v1/admin/market/offers/${id(offerID)}/terms`, put({ pricing, ...(expectedRevision ? { expected_revision: expectedRevision } : {}), ...switches }), key),

  outageCancel: (token: string, subscriptionID: string, key: string) =>
    call<{ outage_settlement?: OutageSettlement | null }>(token, `/v1/admin/market/subscriptions/${id(subscriptionID)}/outage-cancel`, { method: 'POST' }, key),
}
