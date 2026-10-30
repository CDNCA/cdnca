import pluginKinds from '../../../../libs/marketproto/pluginkind/kinds.json'

import { ApiError, networkApiError } from './auth'

// Node market, as seen by this controller's platform administrators. The
// controller relays member calls to the market with its own installation
// certificate (control-api internal/marketsubscribehttp).
const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

/** 节点供货资格（fix-sellerqual）：由所属授权客户的节点供应商入驻审核决定，不看授权功能码。
 *  status：none 未申请 / awaiting_payment 待付开通费 / pending_review 审核中 / rejected 被驳回 /
 *  suspended 已停用 / terminated 已终止 / active 已开通；can_sell 为 true 才显示供货管理。
 *  apply_url：无资格时去卖方站点申请的地址（卖方站点未配置时缺省）。 */
export interface MarketSupplierQualification {
  status: 'none' | 'awaiting_payment' | 'pending_review' | 'rejected' | 'suspended' | 'terminated' | 'active' | 'applying'
  can_sell: boolean
  review_note?: string
  apply_url?: string
}

export interface MarketMember {
  id: string; display_name: string; status: string; features: string[]; offers_quota: number
  /** 已占用的报价数（除已下架外全部计入，同市场 CreateOffer）；旧市场不返回。 */
  offers_used?: number
  /** 旧市场版本不返回；缺省时按 features 是否含 market.sell 判断。 */
  supplier?: MarketSupplierQualification
  /** 卖家站地址（fix-sellersite）；市场未配置卖家站时缺省。 */
  seller_site_url?: string
}
// MARKET-03: one published agreement (latest version with its markdown text); unpublished kinds are absent.
export type MarketAgreementKind = 'seller_terms' | 'plugin_developer_terms' | 'node_supplier_terms' | 'privacy'
export interface MarketAgreement { kind: MarketAgreementKind; version: string; body: string; note: string; published_at: string }
export interface MarketOfferListing {
  id: string
  seller_id: string
  name: string
  description: string
  billing_model: string
  status: string
  revision?: number
  category?: string
  pricing: MarketPricing
  allocation: { http_ports?: number; stream_ports?: number; websocket?: boolean; http3?: boolean }
  compliance: { require_icp: boolean }
  // Own offers only (the market hides them from buyers): own_pool = a supply group of this controller.
  components?: Array<{ kind: string; node_pool_ref?: string; subscription_id?: string }> | null
  // ADR 0012 (ML-02): limits (empty = unlimited), self-declared tags, prepaid exhaustion action and
  // the tagged plugins no node behind the offer still has.
  limits?: MarketLimit[]
  tags?: MarketTags
  prepaid_exhausted_action?: MarketPrepaidAction
  plugins_unavailable?: string[] | null
  settlement_mode?: 'direct' | 'escrow'
  sla?: MarketSlaPolicy | null
  // market-service OfferFacets: absent before the first quality refresh.
  // Shape pinned by src/test/contracts/offer_listing_contract.json (copied from the market-service contract test).
  quality?: MarketOfferQuality
  // ADR 0015 §11.4 on the buyer listing.
  seller_credit?: MarketSellerCredit
  // Free trial days, once per buyer customer (daily_bundle only; 0 = no trial). market offers.go TrialDays.
  trial_days?: number
}
export interface MarketOfferQuality {
  /** 0–3; 0 is a real score. */
  score: number
  /** libs/marketproto/quality tiers; insufficient = too few probe rounds (score is the neutral 1.5). */
  tier: 'insufficient' | 'low' | 'standard' | 'high' | string
  regions: string[] | null
  carriers: string[] | null
  serving_nodes: number
  /** The billing model's own unit price (minor units), the max_price filter compares it. */
  unit_price: number | null
  computed_at: string
}
export interface MarketPricing {
  currency: string
  daily_minor?: number
  min_days?: number
  max_days?: number
  deposit_minor?: number
  tiers?: Array<{ up_to_gb: number; price_per_gb_minor: number }>
  per_mbps_month_minor?: number
  per_mbps_day_minor?: number
}
// libs/marketproto/spec limits.go / tags.go (docs/marketplace/11-limits-contract.md).
export type MarketLimitMetric = 'domains' | 'bandwidth_peak_bps' | 'monthly_traffic_bytes' | 'concurrent_connections' |
  'new_connections_per_second' | 'qps' | 'node_cpu_percent' | 'node_memory_percent'
export type MarketLimitAction = 'throttle' | 'pause' | 'stop' | 'reject_new' | 'remove_node'
export type MarketPrepaidAction = 'pause' | 'stop'
export interface MarketLimit { metric: MarketLimitMetric; cap: number; action: MarketLimitAction; throttle_bps?: number; sustain_buckets?: number }
export interface MarketTags {
  cc_protection: 'none' | 'basic' | 'advanced'
  ddos_protection_gbps: number
  complaint_resistant: boolean
  tenancy: 'shared' | 'dedicated'
  mobile_reachable: boolean
  region_block: boolean
  line_class?: string
  plugins?: string[]
  // The seller's own feature words (self-declared, display only).
  custom?: string[]
}
export interface MarketOfferInput {
  name: string
  billing_model: string
  allocation: MarketOfferListing['allocation']
  limits: MarketLimit[]
  tags: MarketTags
  prepaid_exhausted_action: MarketPrepaidAction
  compliance: { require_icp: boolean; require_kyc?: boolean }
  // own_pool = my node group; upstream = resell one of my subscriptions (ADR 0012 §17.1).
  components: Array<{ kind: 'own_pool'; node_pool_ref: string } | { kind: 'upstream'; subscription_id: string }>
  pricing: MarketPricing
  // 0–30, daily_bundle only (market offers.go:177).
  trial_days?: number
}
// ML-11b batch listing: the offer body without components; each item adds its own pool.
export type MarketListingOffer = Omit<MarketOfferInput, 'components'>
export interface MarketListingBatchInput { mode: 'single' | 'multi'; node_ids: string[]; offer: MarketListingOffer; publish: boolean }
export interface MarketListingBatchItem {
  node_ids: string[]
  status: 'created' | 'existing' | 'failed' | 'in_progress'
  group_id?: string
  offer_id?: string
  published?: string
  removed_plugins: string[]
  error?: string
  detail?: { error?: string; metric?: MarketLimitMetric; floor?: number; plugins?: string[] }
}
// Saved template body: the listing form as the console fills it (stored opaque on this controller).
export type MarketListingTemplateBody = Record<string, unknown>
export interface MarketListingTemplate { id: string; name: string; body: MarketListingTemplateBody; revision: number; updated_at: string }
// Platform floor as members read it (ML-13 GET /v1/supply-limits-policy).
export interface MarketSupplyLimitsPolicy {
  version: number
  policy: { load_floor: { cpu_percent: number; memory_percent: number } } & Record<string, unknown>
}
// Hidden market-supply line group on this controller (ML-09 marketsubscribehttp/supply.go).
export interface MarketSupplyPlugin { code: string; name_zh: string; name_en: string }
export interface MarketSupplyGroup {
  id: string
  revision: number
  name: string
  nodes: Array<{ node_id: string; name: string; address: string; region: string; carrier: string }>
  node_pool_ref: string
  plugins: MarketSupplyPlugin[]
}
// This controller's nodes as the market admitted them (benchmark_grade s/a/b/c is the line grade).
export interface MarketNodeAdmission { node_pool_ref: string; node_id: string; benchmark_grade?: string; status: string; region?: string; carrier?: string }
export type MarketHoldReason = 'limit' | 'prepaid' | 'overdraft_cap' | 'operator'
export type MarketSupplyState = 'serving' | 'paused' | 'stopped' | 'overloaded'
export type MarketSupplyAvailability = 'serving' | 'degraded' | 'unavailable' | 'no_supply' | 'cancelled'
// One limit with its latest evaluated value (market GET /v1/subscriptions/{id}/limits, ADR 0012 ML-12).
export interface MarketLimitUsage {
  metric: MarketLimitMetric
  cap: number
  action: MarketLimitAction
  throttle_bps?: number
  value: number
  stage: 'ok' | 'warn80' | 'warn95' | 'reached'
  evaluated_through: string | null
}
export interface MarketHold {
  subscription_id: string
  leaf_member_id: string | null
  node_pool_ref: string | null
  reason: MarketHoldReason
  metric: MarketLimitMetric | null
  action: 'throttle' | 'pause' | 'stop'
  observed: number
  cap: number
  since: string
  // A hold on another hop of the resale path (the upstream reached its own limit).
  upstream?: boolean
}
// Seller view of one offer's subscribers (ADR 0012 §9.4, §18.2 visibility a): a direct buyer shows identity;
// further downstream only a reference, the direct buyer it comes through, domains, traffic and state.
export interface MarketOfferSubscriber {
  relation: 'direct' | 'downstream'
  subscription_id: string
  buyer_id?: string
  buyer_name?: string
  downstream_ref?: string
  via_name?: string
  status: string
  paid_through?: string | null
  // Worst slot reached through this hop; no_supply when no active grant runs through it (MC08).
  state: MarketSupplyState | 'no_supply'
  usage: MarketLimitUsage[]
  holds: MarketHold[]
  domains: string[]
  domain_count: number
  bytes_24h: number
  bytes_month: number
}
export interface MarketNodeOverload { node_pool_ref?: string; node_id: string; state: 'normal' | 'overloaded' | 'unknown'; since: string; cpu_threshold: number; memory_threshold: number }
// One page of an offer's subscribers (next_cursor null on the last page); overloads come whole with the first page only (empty later).
export interface MarketOfferSubscribers { subscribers: MarketOfferSubscriber[]; overloads: MarketNodeOverload[]; next_cursor: string | null }
export interface MarketLoadThresholds { cpu_percent: number; memory_percent: number }
// Buyer-side node composition of an offer (§9.2): platform-observed groups, no node IDs.
export interface MarketOfferNodes {
  offer_id: string
  nodes: number
  groups: Array<{ region: string; carrier: string; benchmark_grade: string; nodes: number }>
  load_thresholds: MarketLoadThresholds
  load_floor: MarketLoadThresholds
}
export interface MarketUsageSample {
  bucket_start: string
  bytes_out: number
  requests: number
  peak_bps: number
  max_concurrent: number
  max_qps: number
  max_new_cps: number
}
// One subscription's limits, usage, holds and slot states (§9.3).
export interface MarketSubscriptionLimits {
  subscription_id: string
  offer_id: string
  status: string
  billing_model: string
  currency: string
  prepaid_exhausted_action: MarketPrepaidAction
  limits: MarketLimitUsage[]
  load_thresholds: MarketLoadThresholds
  holds: MarketHold[]
  supplies: Array<{ leaf_member_id: string; node_pool_ref: string; state: MarketSupplyState }>
  // A12: sum of supplies; no_supply = no active grant (never "serving").
  availability?: MarketSupplyAvailability
  series: MarketUsageSample[]
  report_lag_seconds: number
}
// Nodes out of scheduling (ML-06 GET /v1/supply-unscheduled).
export interface MarketUnscheduledNode {
  subscription_id: string
  leaf_member_id: string
  node_pool_ref: string
  label: string
  node_id: string
  ip: string
  region: string
  carrier: string
  state: 'paused' | 'stopped' | 'overloaded'
  overloaded_since?: string
  holds: Array<{ subscription_id: string; reason: MarketHoldReason; metric?: string; action: 'throttle' | 'pause' | 'stop'; observed: number; cap: number; since: string }>
}
// Escrow prepaid balance, arrears and the subscriber's alert line (ML-04, ADR 0012 §5.4/§5.6).
export interface MarketPrepaid {
  currency: string
  balance_minor: number
  arrears_minor: number
  overdraft_cap_minor: number
  alert_minor: number | null
  // Spend over the last 24 hours, for the "lasts about" estimate.
  spent_24h_minor: number
  // ADR 0015 §12: one row per direct seller balance (absent on older markets).
  sellers?: MarketPrepaidSeller[]
}
// Seller deposit and record shown to buyers (ADR 0015 §11.4); deposit_* only while the deposit applies to the seller.
export interface MarketSellerCredit {
  deposit_effective: boolean
  deposit_minor?: number
  required_minor?: number
  sufficient?: boolean
  defaults_count: number
  absconded: boolean
  faults_30d: number
}
export interface MarketPrepaidSeller {
  seller_member_id: string
  display_name: string
  balance_minor: number
  overdraft_minor: number
  credit_limit_minor: number
  below_alert: boolean
  spent_24h_minor: number
  spent_by_day: number[]
  by_subscription: Array<{ subscription_id: string; offer_name: string; spent_7d_minor: number }>
  seller_credit: MarketSellerCredit
}
// Direct top-ups (ADR 0015 §3.4): paid into the seller's own merchant account.
export type MarketDirectMethod = 'alipay' | 'wxpay'
export interface MarketDirectSeller {
  seller_id: string
  display_name: string
  currency: string
  balance_minor: number
  credit_limit_minor: number
  online: boolean
  methods: Array<{ method: MarketDirectMethod; display_name: string; min_minor: number; max_minor: number }>
  unavailable?: 'not_enabled' | 'seller_offline' | 'seller_not_selling' | 'no_direct_offer' | 'method_unavailable'
  seller_credit?: MarketSellerCredit
}
export type MarketDirectTopupState = 'requested' | 'awaiting_payment' | 'paid' | 'refused' | 'unreachable' | 'expired'
export interface MarketDirectTopup {
  id: string
  buyer_member_id: string
  seller_member_id: string
  peer_display_name: string
  amount_minor: number
  currency: string
  method: MarketDirectMethod
  state: MarketDirectTopupState
  refusal_code?: string
  action?: { kind: 'redirect' | 'qr_code' | 'form_post'; url?: string; qr_content?: string; method?: string; form?: Record<string, string> }
  channel_display_name?: string
  paid_minor: number
  expires_at: string
  created_at: string
}
export interface MarketSupply {
  id: string
  name: string
  market_subscription_id: string
  target: string
  status: string
  leaves: Array<{ leaf_member_id: string; node_pool_ref: string; grant_id: string }>
}
export interface MarketRollout {
  revision: number
  digest: string
  applied: boolean
  // receipt_pending (HTTP 202): some leaf answered but its result was not saved; apply the same revision again.
  reason?: 'receipt_pending'
  leaves: Array<{ leaf: { leaf_member_id: string; node_pool_ref: string }; state: string; error?: string; leaf_site_id?: string; blockers?: Array<{ code: string; detail?: string }> }>
}

// MC12 E2: a revision compiled by the server from the saved site.
export interface MarketSitePlan {
  site_id: string
  domain: string
  site_version: number
  revision: number
  digest: string
  config: Record<string, unknown>
  unsupported: Array<{ code: string; detail?: string }>
}
export interface MarketSiteRollout { plan: MarketSitePlan; result?: MarketRollout }
// fix-mktsiteconf7: a leaf's saved receipt and node delivery (the subscriber
// asks each applied leaf now and then). node.state '' = not tracked.
export interface MarketLeafStatus {
  supply_id: string
  leaf: { leaf_member_id: string; node_pool_ref: string }
  state: string
  revision: number
  error?: string
  node: { state: '' | 'delivering' | 'effective' | 'failed'; reason?: string; detail?: string; checked_at?: string; next_check_at?: string }
  updated_at: string
}
export interface MarketSiteBinding { supply_id: string; name: string; role: 'primary' | 'backup'; priority: number; status: string; leaves: number }

// Plugin market (marketplace-openapi buyer.yaml, components/plugin.yaml). Kinds: market 030, single source
// libs/marketproto/pluginkind/kinds.json (Go pluginkind.All checks it).
export const marketPluginKinds = pluginKinds.kinds as readonly MarketPluginKind[]
export type MarketPluginKind = 'module' | 'rule_pack' | 'dataset' | 'engine_module' | 'theme' | 'provider' | 'external_service' | 'ui_page'
export interface MarketPlugin {
  id: string
  plugin_id: string
  namespace: string
  seller_id?: string
  kind: MarketPluginKind
  risk_class: 'sandboxed' | 'privileged'
  title: string
  summary?: string
  description_md?: string
  homepage?: string
  support_url?: string
  license_spdx?: string
  screenshots?: string[]
  categories?: string[]
  /** Theme plugins: the latest published version's package carries a preview (GET …/plugins/{id}/preview). */
  has_preview?: boolean
  status: string
  latest_version?: string | null
  installs?: number
  // PA-27: derived from the seller (market 027); feature_code is the lease code an official entry unlocks.
  publisher_kind?: 'official' | 'certified' | 'third_party'
  feature_code?: string | null
  /** Theme entries: the scopes (admin, user, site) of the latest published version. */
  applies_to?: string[]
  // Buyer catalog cards carry the sellable plans (free/paid and price).
  price_plans?: MarketPricePlan[]
}
// A ui_page version's signed page origin and mounted pages (PA-19 manifest).
export interface MarketUIPage {
  origin: string
  api_base_url?: string
  pages: Array<{ id: string; path: string; mount: 'menu' | 'site_tab'; menu_parent?: string; role: 'admin' | 'user';
    title: { 'zh-CN': string; 'en-US'?: string }; required_permission?: string; required_module?: string }>
}
// This controller's local state of a market plugin (GET /v1/admin/market/plugin-library).
export interface MarketLibraryItem { plugin_id: string; installed: boolean; enabled: boolean; withdrawn: boolean }
export interface MarketDownload { plugin_id: string; publisher_kind: string; source: 'licensed' | 'free'; license: MarketLicense }
export interface MarketPluginVersion {
  id: string
  plugin_id: string
  version: string
  status: string
  manifest_sha256: string
  permissions: string[]
  permissions_changed: boolean
  compat?: { control_api?: string; edge_agent?: string }
  changelog_md?: string
  channel: 'stable' | 'beta'
  created_at?: string
  ui_page?: MarketUIPage
}
export interface MarketPricePlan {
  id: string
  plugin_id: string
  revision: number
  kind: 'free' | 'one_time' | 'subscription'
  interval?: 'month' | 'year' | null
  price_minor: number
  currency: string
  trial_days: number
  // 限免 (fix-plugpromo, market 066): a free plan free until promo_until, then promo_then_* pricing.
  promo_until?: string | null
  promo_then_kind?: 'one_time' | 'subscription' | null
  promo_then_interval?: 'month' | null
  promo_then_price_minor?: number | null
  status: string
  // The revision on sale (M2); null while the first price is still under review.
  active_revision?: number | null
}
export interface MarketPluginDetail { plugin: MarketPlugin; versions: MarketPluginVersion[]; price_plans: MarketPricePlan[] }
export interface MarketPage<T> { items: T[]; next_cursor: string | null }
export interface MarketOrder {
  id: string
  order_no: number
  // platform: prepaid top-up orders (no seller, no commission).
  market: 'plugin' | 'node' | 'platform'
  kind: string
  seller_id: string | null
  amount_minor: number
  currency: string
  settlement_mode: 'direct' | 'escrow'
  status: string
  ref_kind?: string
  ref_id?: string
  expires_at?: string | null
  created_at: string
}
export interface MarketLicense {
  id: string
  plugin_id: string
  plan_id?: string
  plan_revision?: number
  installation_id: string
  kind: 'trial' | 'one_time' | 'subscription' | 'free'
  status: string
  trial_ends_at?: string | null
  current_period_end?: string | null
  cancel_at_period_end?: boolean
  fallback_version?: string | null
  order_id?: string | null
  // Pricing when claimed (fixed): decides the rights when the plan is repriced (market 064).
  claim_pricing?: 'free_permanent' | 'free_promo' | 'paid_once' | 'paid_monthly' | 'paid_yearly'
  promo_first_charge_at?: string | null
}
export interface MarketUsageStatement {
  id: string
  subscription_id: string
  period_start: string
  period_end: string
  bytes_out?: number
  requests?: number
  p95_mbps?: number
  amount_minor: number
  // direct: the parties settle off-platform, a dispute only marks the statement (MKT-RESP-02).
  settlement_mode?: 'direct' | 'escrow'
  status: string
  accept_deadline?: string | null
  flagged?: boolean
}
export type MarketDisputeState = 'awaiting_seller' | 'under_review' | 'resolved_buyer' | 'resolved_seller' | 'resolved_split' | 'withdrawn' | 'closed'
export interface MarketDispute {
  id: string
  order_id?: string | null
  // Plugin order disputes are stored as "order"; market tells the two apart.
  subject_kind: 'order' | 'usage_statement' | 'sla_breach'
  subject_id: string
  market?: 'plugin' | 'node'
  seller_id?: string
  held_minor?: number
  buyer_share_minor?: number
  refund_id?: string | null
  escalations?: number
  opened_at?: string
  opened_by?: string
  state: MarketDisputeState | string
  amount_minor: number
  reason_code: string
  waiting_on?: string | null
  deadline?: string | null
}
export interface DisputeFilters { status?: MarketDisputeState; subject_kind?: 'order' | 'plugin_order' | 'usage_statement' | 'sla_breach'; cursor?: string }
export type PluginDisputeOpen = { subject_kind: 'plugin_order'; reason_code: string; note?: string; amount_minor?: number } &
  ({ order_id: string; license_id?: never } | { license_id: string; order_id?: never })
export interface MarketAdvisory {
  id: string
  plugin_id: string
  affected_versions: string
  fixed_version: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  action: 'notify' | 'disable' | 'uninstall_recommended'
  title: string
  body: string
  published_at: string
  acknowledgement: { disposition: string; note: string; acknowledged_by: string; acknowledged_at: string } | null
}
export type AdvisoryDisposition = 'disabled' | 'upgraded' | 'uninstalled' | 'accepted_risk' | 'not_affected'
export interface MarketRenewalStop {
  code: number
  reason: 'buyer_frozen' | 'seller_frozen' | 'upstream_lost' | 'no_grant' | 'upstream_paused'
  initiator: 'buyer' | 'seller' | 'system' | 'operator'
  since: string
}

// One upstream commercial pause of every supply (upstream-pause/v1): ended once,
// extended (seconds added to paid_through), refunded (closed during it) or superseded.
export interface MarketUpstreamPause {
  id: string
  policy_version: 'upstream-pause/v1'
  started_at: string
  ended_at?: string | null
  outcome?: 'extended' | 'refunded' | 'superseded' | null
  extended_seconds: number
  refund_minor: number
}

// Subscription terms as the market keeps them (buyer.yaml SubscriptionTerms, M4).
export interface MarketSubscriptionTerms {
  id: string
  buyer_id: string
  seller_id: string
  offer_id: string
  status: 'active' | 'cancelled'
  paid_through?: string
  settlement_mode: 'direct' | 'escrow'
  renewal_price_policy: RenewalPricePolicy
  cancel_at_period_end: boolean
  close_code?: number | null
  closed_at?: string | null
  close_initiator?: 'buyer' | 'seller' | 'system' | 'operator'
  renewal_stop?: MarketRenewalStop
  // fix-nm03 (market 063): upstream pause compensation rule version and the open or last pause.
  compensation_policy?: 'upstream-pause/v1'
  upstream_pause?: MarketUpstreamPause | null
  max_unit_price_minor?: number | null
  min_quality_score?: number | null
  // ML-31: open zero-online outage (cancel_available_at set once T1 passed).
  outage?: { id: string; since: string; cancel_available_at?: string | null } | null
  // Frozen in the purchase snapshot: whether this subscription may be resold (B22).
  resale_allowed?: boolean
  // MC10 (B22): whether a new resale of it may be listed today (every hop's snapshot and live switch, the
  // market's own CreateOffer rule); buyer's view of an active subscription only; older markets omit it.
  resale_now?: { allowed: boolean; reason?: 'resale_forbidden' | 'upstream_inactive'; ref?: string }
  // C16: the supply terms frozen at purchase; a resale inherits them and may only tighten them.
  frozen_terms?: MarketFrozenTerms
}
export interface MarketFrozenTerms {
  name: string
  billing_model: string
  allocation: MarketOfferListing['allocation']
  limits: MarketLimit[]
  tags: Partial<MarketTags>
  compliance: { require_icp?: boolean; require_kyc?: boolean }
  prepaid_exhausted_action: MarketPrepaidAction
}
// market internal/sla.Policy (buyer.yaml SlaPolicy): ratios, not percentages.
export interface MarketSlaPolicy {
  availability_target: number
  measure_window: 'day' | 'month'
  credit_schedule: Array<{ below: number; credit_percent: number }>
  daily_penalty_minor: number
  max_credit_percent: number
  terminate_after: number
}
export interface MarketSelectionLimits { max_unit_price_minor: number | null; min_quality_score: number | null }
export type RenewalPricePolicy = 'always' | 'if_lesser' | 'if_lesser_or_equal' | 'if_equal' | 'never'
export interface PluginFilters { q?: string; kind?: MarketPluginKind; price?: 'free' | 'paid'; sort?: 'popular' | 'newest' | 'name'; allVersions?: boolean; cursor?: string; appliesTo?: 'user' | 'site' }
export interface OfferFilters { region?: string; carrier?: string; billing_model?: string; max_price?: number; min_score?: number; settlement_mode?: 'direct' | 'escrow' }
export type OrderInput =
  | { market: 'plugin'; price_plan_id: string; plan_revision: number; trial?: boolean }
  | { market: 'node'; offer_id: string; offer_revision: number; settlement_mode: 'direct' | 'escrow'; quantity?: number }
  | { kind: 'prepaid_topup'; amount_minor: number; currency: string }

// Subscription feedback tickets (u4d, C22; market httpapi feedback.go): the buyer
// reports a fault to the seller, both answer, an overdue one escalates to a dispute.
export type MarketFeedbackState = 'open' | 'in_progress' | 'resolved' | 'closed'
export type MarketFeedbackCategory = 'outage' | 'degraded' | 'config' | 'billing' | 'other'
export type MarketFeedbackRole = 'buyer' | 'seller'
export interface MarketFeedbackMessage {
  seq: number
  author_role: 'buyer' | 'seller' | 'operator' | 'system'
  kind: 'reply' | 'state' | 'escalated'
  body: string
  to_state?: MarketFeedbackState
  created_at: string
}
export interface MarketFeedbackTicket {
  id: string
  subscription_id: string
  offer_name: string
  category: MarketFeedbackCategory
  title: string
  state: MarketFeedbackState
  respond_by: string
  seller_responded_at: string | null
  /** The buyer may escalate now: respond_by passed, not resolved or closed, not escalated yet. */
  escalable: boolean
  dispute_id: string | null
  /** The escalated dispute's ruling once resolved (u4g); the ticket is then closed. */
  decision: MarketFeedbackDecision | null
  created_at: string
  updated_at: string
  revision: number
  messages?: MarketFeedbackMessage[]
}
export interface MarketFeedbackDecision {
  outcome: 'resolved_buyer' | 'resolved_seller' | 'resolved_split' | 'withdrawn'
  amount_minor: number
  buyer_share_minor?: number
  currency: string
  decided_at: string
}
export interface MarketFeedbackFilters { state?: MarketFeedbackState; subscription?: string; cursor?: string }

export async function call<T>(accessToken: string, path: string, init: RequestInit = {}, idempotencyKey?: string): Promise<T> {
  if (!accessToken) throw new ApiError('Not signed in', 401, 'unauthenticated')
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}),
      },
    })
  } catch {
    throw networkApiError()
  }
  const text = await response.text()
  let body: unknown
  try { body = text ? JSON.parse(text) : undefined } catch { throw new ApiError('Invalid market response', 502, 'response_invalid') }
  if (!response.ok) {
    // control-api writes {"error": code}; the market writes {"error": reason}.
    const raw = (body as { error?: unknown } | undefined)?.error
    const code = typeof raw === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(raw) ? raw : 'request_failed'
    const error = new ApiError('Market request failed', response.status, code)
    // Refusal details the pages show (supply_in_use counts, resale_forbidden ref): see marketRefusal.
    if (body && typeof body === 'object' && !Array.isArray(body)) (error as ApiError & { refusal?: unknown }).refusal = body
    // fix-fielderr-be5: the market's field refusal {"error":"invalid","field","reason"} marks the form field.
    if (code === 'invalid' && body && typeof body === 'object') {
      const { field, reason } = body as { field?: unknown; reason?: unknown }
      if (typeof field === 'string' && field.length <= 256 && /^[a-z][a-z0-9_]{0,63}(?:\.[a-z0-9_]{1,64}|\[\d{1,4}\])*$/.test(field)) {
        error.field = field
        if (typeof reason === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(reason)) { error.reason = reason; error.fieldReason = reason }
      }
    }
    throw error
  }
  return body as T
}

function list<T>(value: unknown): T[] {
  const items = (value as { items?: unknown } | undefined)?.items
  if (!Array.isArray(items)) throw new ApiError('Invalid market response', 502, 'response_invalid')
  return items as T[]
}

const json = (method: string, body: unknown): RequestInit => ({ method, body: JSON.stringify(body) })

export function query(values: Record<string, string | number | undefined>): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== '') params.set(key, String(value))
  }
  const text = params.toString()
  return text ? `?${text}` : ''
}

export function pageOf<T>(value: unknown): MarketPage<T> {
  const items = list<T>(value)
  const next = (value as { next_cursor?: unknown }).next_cursor
  return { items, next_cursor: typeof next === 'string' && next ? next : null }
}

const id = (value: string) => encodeURIComponent(value)

// checkoutURL returns the portal checkout link only when it is a plain https
// URL; anything else (javascript:, data:, relative) is dropped.
export function checkoutURL(raw: unknown): string | null {
  if (typeof raw !== 'string' || !raw) return null
  try {
    const url = new URL(raw)
    return url.protocol === 'https:' && !url.username && !url.password ? url.toString() : null
  } catch {
    return null
  }
}

// marketUnavailable: the market has not mounted this entry yet (control-api 501).
export function marketUnavailable(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 501 || error.code === 'market_feature_unavailable')
}

// marketForbidden: the licence lease or the role lacks this market function (403);
// pages explain it in place instead of an error dialog (fix-mktui).
export function marketForbidden(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403
}

// marketConnected probes the member route once. Without MARKET_RUNTIME_ENABLED
// control-api never mounts /v1/admin/market/*, so the mux answers a plain-text
// 404; a JSON answer of any status (including the market's own errors) means
// the routes exist. Network failures count as connected so pages keep their
// own error handling.
export async function marketConnected(accessToken: string): Promise<boolean> {
  try {
    const response = await fetch(`${apiRoot}/v1/admin/market/member`, {
      credentials: 'include', headers: { Authorization: `Bearer ${accessToken}` },
    })
    if (response.status !== 404) return true
    const text = await response.text()
    try { JSON.parse(text); return true } catch { return false }
  } catch {
    return true
  }
}

export const marketApi = {
  member: (token: string) => call<MarketMember>(token, '/v1/admin/market/member'),
  agreements: (token: string) => call<unknown>(token, '/v1/admin/market/agreements').then((v) => list<MarketAgreement>(v)),
  // Keyset page of the buyer listing (C17); next_cursor is null on the last page.
  offers: (token: string, filters: OfferFilters = {}, cursor?: string) =>
    call<unknown>(token, `/v1/admin/market/offers${query({ ...filters, cursor, limit: 50 })}`).then((v) => pageOf<MarketOfferListing>(v)),
  plugins: (token: string, f: PluginFilters = {}) =>
    call<unknown>(token, `/v1/admin/market/plugins${query({ q: f.q, kind: f.kind, price: f.price, sort: f.sort, applies_to: f.appliesTo,
      all_versions: f.allVersions ? 1 : undefined, cursor: f.cursor, limit: 50 })}`).then((v) => pageOf<MarketPlugin>(v)),
  plugin: (token: string, pluginID: string) => call<MarketPluginDetail>(token, `/v1/admin/market/plugins/${id(pluginID)}`),
  /**
   * A theme plugin's package preview, relayed same-origin by control-api (checked png/jpeg/webp ≤ 512 KiB).
   * The route needs the session token, so it is fetched and shown as a blob: URL; null when there is none.
   */
  async pluginPreview(token: string, pluginRow: string): Promise<Blob | null> {
    const response = await fetch(`${apiRoot}/v1/admin/market/plugins/${id(pluginRow)}/preview`, {
      headers: { Authorization: `Bearer ${token}` }, credentials: 'include',
    })
    const type = response.headers.get('Content-Type') ?? ''
    if (!response.ok || !/^image\/(png|jpeg|webp)$/.test(type)) return null
    const blob = await response.blob()
    return blob.size > 0 && blob.size <= 512 * 1024 ? blob : null
  },
  createOrder: (token: string, input: OrderInput, key: string) =>
    call<{ order: MarketOrder; checkout_url?: string | null }>(token, '/v1/admin/market/orders', json('POST', input), key),
  order: (token: string, orderID: string) => call<MarketOrder>(token, `/v1/admin/market/orders/${id(orderID)}`),
  licenses: (token: string, cursor?: string) =>
    call<unknown>(token, `/v1/admin/market/licenses${query({ cursor, limit: 50 })}`).then((v) => pageOf<MarketLicense>(v)),
  cancelLicense: (token: string, licenseID: string, key: string) =>
    call<MarketLicense>(token, `/v1/admin/market/licenses/${id(licenseID)}/cancel`, { method: 'POST' }, key),
  resumeLicense: (token: string, licenseID: string, key: string) =>
    call<MarketLicense>(token, `/v1/admin/market/licenses/${id(licenseID)}/resume`, { method: 'POST' }, key),
  // PL-RENEWAL-01: a past-due or expired subscription renews on the same licence from the prepaid balance.
  renewLicense: (token: string, licenseID: string, key: string) =>
    call<MarketLicense>(token, `/v1/admin/market/licenses/${id(licenseID)}/renew`, { method: 'POST' }, key),
  setRenewalPolicy: (token: string, subscriptionID: string, policy: RenewalPricePolicy, key: string) =>
    call<unknown>(token, `/v1/admin/market/subscriptions/${id(subscriptionID)}/renewal-policy`,
      json('PUT', { renewal_price_policy: policy }), key),
  cancelSubscription: (token: string, subscriptionID: string, key: string) =>
    call<unknown>(token, `/v1/admin/market/subscriptions/${id(subscriptionID)}/cancel`, { method: 'POST' }, key),
  usageStatements: (token: string, status?: string, cursor?: string) =>
    call<unknown>(token, `/v1/admin/market/usage-statements${query({ status, cursor, limit: 50 })}`).then((v) => pageOf<MarketUsageStatement>(v)),
  acceptStatement: (token: string, statementID: string, key: string) =>
    call<MarketUsageStatement>(token, `/v1/admin/market/usage-statements/${id(statementID)}/accept`, { method: 'POST' }, key),
  disputeStatement: (token: string, statementID: string, note: string, key: string) =>
    call<MarketUsageStatement>(token, `/v1/admin/market/usage-statements/${id(statementID)}/dispute`, json('POST', { note }), key),
  disputes: (token: string, f: DisputeFilters = {}) =>
    call<unknown>(token, `/v1/admin/market/disputes${query({ status: f.status, subject_kind: f.subject_kind, cursor: f.cursor, limit: 50 })}`)
      .then((v) => pageOf<MarketDispute>(v)),
  openDispute: (token: string, input: PluginDisputeOpen, key: string) =>
    call<MarketDispute>(token, '/v1/admin/market/disputes', json('POST', input), key),
  withdrawDispute: (token: string, disputeID: string, key: string) =>
    call<MarketDispute>(token, `/v1/admin/market/disputes/${id(disputeID)}/withdraw`, json('POST', {}), key),
  library: (token: string) => call<unknown>(token, '/v1/admin/market/plugin-library').then((v) => list<MarketLibraryItem>(v)),
  download: (token: string, pluginID: string) =>
    call<MarketDownload>(token, '/v1/admin/market/plugin-downloads', json('POST', { plugin_id: pluginID })),
  purchaseFromPrepaid: (token: string, input: { price_plan_id: string; plan_revision: number; trial?: boolean }, key: string) =>
    call<MarketLicense>(token, '/v1/admin/market/plugin-purchases', json('POST', input), key),
  updateOfferTerms: (token: string, offerID: string,
    body: { pricing: MarketOfferListing['pricing']; sla?: MarketSlaPolicy; remove_sla?: boolean; expected_revision?: number }, key: string) =>
    call<MarketOfferListing>(token, `/v1/admin/market/offers/${id(offerID)}/terms`, json('PUT', body), key),
  openFeedback: (token: string, subscriptionID: string, input: { category: MarketFeedbackCategory; title: string; body: string }, key: string) =>
    call<MarketFeedbackTicket>(token, `/v1/admin/market/subscriptions/${id(subscriptionID)}/feedback`, json('POST', input), key),
  feedbackList: (token: string, role: MarketFeedbackRole, f: MarketFeedbackFilters = {}) =>
    call<unknown>(token, `/v1/admin/market/${role}/feedback${query({ state: f.state, subscription: f.subscription, cursor: f.cursor, limit: 50 })}`)
      .then((v) => pageOf<MarketFeedbackTicket>(v)),
  feedback: (token: string, role: MarketFeedbackRole, ticketID: string) =>
    call<MarketFeedbackTicket>(token, `/v1/admin/market/${role}/feedback/${id(ticketID)}`),
  answerFeedback: (token: string, role: MarketFeedbackRole, ticketID: string, input: { body?: string; state?: MarketFeedbackState }, key: string) =>
    call<MarketFeedbackTicket>(token, `/v1/admin/market/${role}/feedback/${id(ticketID)}/messages`, json('POST', input), key),
  escalateFeedback: (token: string, ticketID: string, input: { amount_minor: number; note: string }, key: string) =>
    call<MarketFeedbackTicket>(token, `/v1/admin/market/buyer/feedback/${id(ticketID)}/escalate`, json('POST', input), key),
  subscription: (token: string, subscriptionID: string) =>
    call<MarketSubscriptionTerms>(token, `/v1/admin/market/subscriptions/${id(subscriptionID)}`),
  setSelectionLimits: (token: string, subscriptionID: string, limits: MarketSelectionLimits, key: string) =>
    call<unknown>(token, `/v1/admin/market/subscriptions/${id(subscriptionID)}/selection`, json('PUT', limits), key),
  advisories: (token: string, pluginID?: string) =>
    call<unknown>(token, `/v1/admin/market/advisories${query({ plugin_id: pluginID })}`).then((v) => list<MarketAdvisory>(v)),
  acknowledgeAdvisory: (token: string, advisoryID: string, disposition: AdvisoryDisposition, note: string) =>
    call<MarketAdvisory['acknowledgement']>(token, `/v1/admin/market/advisories/${id(advisoryID)}/acknowledge`,
      json('POST', { disposition, note })),
  myOffers: (token: string) => call<unknown>(token, '/v1/admin/market/offers?mine=1').then((v) => list<MarketOfferListing>(v)),
  createOffer: (token: string, input: MarketOfferInput) =>
    call<{ id: string }>(token, '/v1/admin/market/offers', json('POST', input)),
  supplyLimitsPolicy: (token: string) => call<MarketSupplyLimitsPolicy>(token, '/v1/admin/market/supply-limits-policy'),
  supplyPlugins: (token: string, nodeIDs: string[]) =>
    call<unknown>(token, '/v1/admin/market/supply-plugins', json('POST', { node_ids: nodeIDs })).then((v) => list<MarketSupplyPlugin>(v)),
  // u4g: display names of plugin codes from this controller's catalogue; unknown codes are left out.
  pluginNames: (token: string, codes: string[]) =>
    call<unknown>(token, '/v1/admin/market/plugin-names', json('POST', { codes })).then((v) => list<MarketSupplyPlugin>(v)),
  createSupplyGroup: (token: string, name: string, nodeIDs: string[], key: string) =>
    call<MarketSupplyGroup>(token, '/v1/admin/market/supply-groups', json('POST', { name, node_ids: nodeIDs }), key),
  // Every admission of this controller: walks all pages (200 each) by next_cursor.
  async nodeAdmissions(token: string): Promise<MarketNodeAdmission[]> {
    const out: MarketNodeAdmission[] = []
    let cursor: string | undefined
    for (let i = 0; i < 500; i++) {
      const page = pageOf<MarketNodeAdmission>(await call<unknown>(token, `/v1/admin/market/node-admissions${query({ cursor, limit: 200 })}`))
      out.push(...page.items)
      if (!page.next_cursor) break
      cursor = page.next_cursor
    }
    return out
  },
  offerSubscribers: (token: string, offerID: string, cursor?: string, limit = 100) =>
    call<MarketOfferSubscribers>(token, `/v1/admin/market/offers/${id(offerID)}/subscribers${query({ cursor, limit })}`)
      .then((v) => ({ ...v, next_cursor: typeof v.next_cursor === 'string' && v.next_cursor ? v.next_cursor : null })),
  offerNodes: (token: string, offerID: string) =>
    call<MarketOfferNodes>(token, `/v1/admin/market/offers/${id(offerID)}/nodes`),
  subscriptionLimits: (token: string, subscriptionID: string, hours = 24) =>
    call<MarketSubscriptionLimits>(token, `/v1/admin/market/subscriptions/${id(subscriptionID)}/limits${query({ hours })}`),
  unscheduled: (token: string) =>
    call<unknown>(token, '/v1/admin/market/supply-unscheduled').then((v) => list<MarketUnscheduledNode>(v)),
  prepaid: (token: string, currency: string) =>
    call<MarketPrepaid>(token, `/v1/admin/market/prepaid${query({ currency })}`),
  directSellers: (token: string, sellerID?: string) =>
    call<unknown>(token, `/v1/admin/market/direct-pay/sellers${query({ seller_id: sellerID })}`).then((v) => list<MarketDirectSeller>(v)),
  createDirectTopup: (token: string, sellerID: string, amountMinor: number, method: MarketDirectMethod, key: string) =>
    call<MarketDirectTopup>(token, '/v1/admin/market/direct-topups',
      json('POST', { seller_member_id: sellerID, amount_minor: amountMinor, currency: 'CNY', method }), key),
  directTopup: (token: string, topupID: string) => call<MarketDirectTopup>(token, `/v1/admin/market/direct-topups/${id(topupID)}`),
  directTopups: (token: string, as: 'buyer' | 'seller', cursor?: string, limit = 50) =>
    call<unknown>(token, `/v1/admin/market/direct-topups${query({ as, cursor, limit })}`).then((v) => pageOf<MarketDirectTopup>(v)),
  setPrepaidAlert: (token: string, currency: string, thresholdMinor: number | null) =>
    call<unknown>(token, '/v1/admin/market/prepaid/alert', json('PUT', { currency, threshold_minor: thresholdMinor })),
  // ML-11b batch listing (control-api marketsubscribehttp/listing.go).
  listingBatch: (token: string, input: MarketListingBatchInput) =>
    call<unknown>(token, '/v1/admin/market/listing-batches', json('POST', input)).then((v) => list<MarketListingBatchItem>(v)),
  listingTemplates: (token: string) =>
    call<unknown>(token, '/v1/admin/market/listing-templates').then((v) => list<MarketListingTemplate>(v)),
  saveListingTemplate: (token: string, t: { id?: string; name: string; body: MarketListingTemplateBody; revision?: number }) =>
    call<MarketListingTemplate>(token, t.id ? `/v1/admin/market/listing-templates/${id(t.id)}` : '/v1/admin/market/listing-templates',
      json(t.id ? 'PUT' : 'POST', { name: t.name, body: t.body, ...(t.id ? { revision: t.revision } : {}) })),
  deleteListingTemplate: (token: string, templateID: string, revision: number) =>
    call<void>(token, `/v1/admin/market/listing-templates/${id(templateID)}?revision=${revision}`, { method: 'DELETE' }),
  delistOffer: (token: string, offerID: string, key: string) =>
    call<unknown>(token, `/v1/admin/market/offers/${id(offerID)}/delist`, json('POST', {}), key),
  removeSupplyNodes: (token: string, groupIDs: string[], nodeIDs: string[]) =>
    call<unknown>(token, '/v1/admin/market/supply-node-removals', json('POST', { group_ids: groupIDs, node_ids: nodeIDs }))
      .then((v) => list<{ group_id: string; status: 'updated' | 'unchanged' | 'failed'; removed: string[]; error?: string }>(v)),
  updateOfferLimits: (token: string, offerID: string, body: { limits: MarketLimit[]; prepaid_exhausted_action: MarketPrepaidAction }, key: string) =>
    call<MarketOfferListing>(token, `/v1/admin/market/offers/${id(offerID)}/limits`, json('PUT', body), key),
  publishOffer: (token: string, id: string) =>
    call<{ status: string }>(token, `/v1/admin/market/offers/${encodeURIComponent(id)}/publish`, { method: 'POST' }),
  // trial takes the offer's trial days free of charge (market purchase.go; 409 trial_used once taken).
  // expectedRevision: the offer revision the buyer confirmed; the market answers
  // 409 offer_changed (nothing charged) when the seller changed it since (C17).
  purchase: (token: string, offerID: string, days: number, idempotencyKey: string, trial = false, expectedRevision?: number) =>
    call<{ id: string; grants: number }>(token, '/v1/admin/market/subscriptions',
      json('POST', { offer_id: offerID, days, idempotency_key: idempotencyKey, ...(trial ? { trial: true } : {}), expected_revision: expectedRevision })),
  balance: (token: string, buyerID: string, sellerID: string, currency: string) =>
    call<{ balance_minor: number }>(token,
      `/v1/admin/market/ledger/balance?${new URLSearchParams({ buyer_id: buyerID, seller_id: sellerID, currency })}`),
  supplies: (token: string) => call<unknown>(token, '/v1/admin/market/supplies').then((v) => list<MarketSupply>(v)),
  bind: (token: string, siteID: string, supplyID: string, role: 'primary' | 'backup', priority: number) =>
    call<void>(token, `/v1/admin/sites/${encodeURIComponent(siteID)}/market-supplies/${encodeURIComponent(supplyID)}`,
      json('PUT', { role, priority })),
  unbind: (token: string, siteID: string, supplyID: string) =>
    call<void>(token, `/v1/admin/sites/${encodeURIComponent(siteID)}/market-supplies/${encodeURIComponent(supplyID)}`, { method: 'DELETE' }),
  rollout: (token: string, siteID: string, apply: boolean, revision: number, config: Record<string, unknown>) =>
    call<MarketRollout>(token, `/v1/admin/sites/${encodeURIComponent(siteID)}/market-rollout/${apply ? 'apply' : 'preview'}`,
      json('POST', { revision, config })),
  // MC12 E2: the server compiles the revision from the saved site.
  siteBindings: (token: string, siteID: string) =>
    call<unknown>(token, `/v1/admin/sites/${encodeURIComponent(siteID)}/market-supplies`).then((v) => list<MarketSiteBinding>(v)),
  sitePreview: (token: string, siteID: string) =>
    call<MarketSiteRollout>(token, `/v1/admin/sites/${encodeURIComponent(siteID)}/market-rollout/site-preview`, json('POST', {})),
  siteLeaves: (token: string, siteID: string) =>
    call<unknown>(token, `/v1/admin/sites/${encodeURIComponent(siteID)}/market-rollout/leaves`).then((v) => list<MarketLeafStatus>(v)),
  siteApply: (token: string, siteID: string, siteVersion: number, digest: string) =>
    call<MarketSiteRollout>(token, `/v1/admin/sites/${encodeURIComponent(siteID)}/market-rollout/site-apply`,
      json('POST', { site_version: siteVersion, digest })),
}

export function newIdempotencyKey(prefix: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `${prefix}-${suffix}`
}
