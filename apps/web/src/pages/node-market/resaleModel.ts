import type { MarketFrozenTerms, MarketLimit, MarketLimitMetric, MarketOfferInput, MarketTags } from '../../api/market'
import { capOf, defaultRows, floorOf, ruleOf, toLimits, type LimitRow, type LimitUnit, type LoadFloor } from './limitsModel'
import { customOf, pricingOf, trialDaysOf, type ListingValues } from './listingModel'

// C16: a resale offer inherits the terms frozen in the upstream subscription's
// purchase snapshot (market frozen_terms) and may only tighten them; the market
// refuses anything looser (400 upstream_terms_exceeded, resale_terms.go).

export interface ResaleAllocation { httpPorts: number; streamPorts: number; websocket: boolean; http3: boolean }

const unitFactor: Record<LimitUnit, number> = {
  count: 1, perSecond: 1, percent: 1, Mbps: 1e6, Gbps: 1e9, GB: 1024 ** 3, TB: 1024 ** 4,
}

export const upstreamCap = (up: MarketFrozenTerms, metric: MarketLimitMetric): MarketLimit | undefined =>
  up.limits.find((l) => l.metric === metric)

// rowsFromUpstream starts the limit rows at the upstream caps, in the largest
// unit that holds the cap exactly (so the figure converts back to the same cap).
export function rowsFromUpstream(up: MarketFrozenTerms): LimitRow[] {
  return defaultRows().map((row) => {
    const l = upstreamCap(up, row.metric)
    if (!l) return row
    const units = ruleOf(row.metric).units
    const unit = [...units].reverse().find((u) => l.cap % unitFactor[u] === 0) ?? units[0]
    return {
      ...row, enabled: true, value: l.cap / unitFactor[unit], unit,
      action: ruleOf(row.metric).actions.includes(l.action) ? l.action : row.action,
      throttleMbps: l.throttle_bps ? l.throttle_bps / 1e6 : null,
    }
  })
}

// maxIn is the highest figure a row may hold in its unit: the upstream cap
// (and the platform floor for node rows); undefined = no bound.
export function maxIn(row: LimitRow, up: MarketFrozenTerms | null, floor: LoadFloor | null): number | undefined {
  const bounds = [floorOf(row.metric, floor), up ? upstreamCap(up, row.metric)?.cap : undefined]
    .filter((v): v is number => v !== undefined)
  return bounds.length ? Math.min(...bounds) / unitFactor[row.unit] : undefined
}

// overUpstream lists the rows above the upstream cap (checked before submit,
// the market checks again).
export function overUpstream(rows: LimitRow[], up: MarketFrozenTerms): MarketLimitMetric[] {
  return rows.filter((row) => {
    const l = upstreamCap(up, row.metric)
    const cap = capOf(row)
    return row.enabled && l !== undefined && cap !== null && cap > l.cap
  }).map((row) => row.metric)
}

const ccRank: Record<MarketTags['cc_protection'], number> = { none: 0, basic: 1, advanced: 2 }
export const ccOptions = (up: MarketFrozenTerms): Array<MarketTags['cc_protection']> =>
  (['none', 'basic', 'advanced'] as const).filter((v) => ccRank[v] <= ccRank[up.tags.cc_protection ?? 'none'])

// valuesFromUpstream: the tag, compliance and prepaid fields the form starts at.
export function valuesFromUpstream(up: MarketFrozenTerms): Partial<ListingValues> & ResaleAllocation {
  const t = up.tags
  return {
    cc: t.cc_protection ?? 'none', ddos: t.ddos_protection_gbps ?? 0, tenancy: t.tenancy ?? 'shared', lineClass: t.line_class ?? '',
    complaint: !!t.complaint_resistant, mobile: !!t.mobile_reachable, regionBlock: !!t.region_block, plugins: [...(t.plugins ?? [])],
    icp: !!up.compliance.require_icp, prepaid: up.prepaid_exhausted_action ?? 'pause',
    httpPorts: up.allocation.http_ports ?? 0, streamPorts: up.allocation.stream_ports ?? 0,
    websocket: !!up.allocation.websocket, http3: !!up.allocation.http3,
  }
}

// resaleOfferOf builds the createOffer body: one upstream component, terms as
// tightened in the form (each bounded by the upstream again, so a stale form
// cannot loosen them).
export function resaleOfferOf(v: ListingValues & ResaleAllocation, rows: LimitRow[], floor: LoadFloor | null, subscription: string,
  up: MarketFrozenTerms): MarketOfferInput {
  const t = up.tags
  const a = up.allocation
  return {
    name: v.name.trim(), billing_model: v.billing_model,
    allocation: {
      http_ports: Math.min(v.httpPorts ?? 0, a.http_ports ?? 0), stream_ports: Math.min(v.streamPorts ?? 0, a.stream_ports ?? 0),
      websocket: !!a.websocket && !!v.websocket, http3: !!a.http3 && !!v.http3,
    },
    limits: toLimits(rows, floor).limits,
    tags: {
      cc_protection: ccOptions(up).includes(v.cc) ? v.cc : 'none', ddos_protection_gbps: Math.min(v.ddos ?? 0, t.ddos_protection_gbps ?? 0),
      complaint_resistant: !!t.complaint_resistant && v.complaint, tenancy: t.tenancy === 'dedicated' ? v.tenancy : 'shared',
      mobile_reachable: !!t.mobile_reachable && v.mobile, region_block: !!t.region_block && v.regionBlock,
      ...(t.line_class && v.lineClass?.trim() === t.line_class ? { line_class: t.line_class } : {}),
      ...(v.plugins?.length ? { plugins: v.plugins.filter((p) => (t.plugins ?? []).includes(p)).sort() } : {}),
      // Custom tags are the reseller's own words: not inherited, not bounded.
      ...customOf(v),
    },
    prepaid_exhausted_action: v.prepaid,
    compliance: { require_icp: !!up.compliance.require_icp || v.icp, ...(up.compliance.require_kyc ? { require_kyc: true } : {}) },
    components: [{ kind: 'upstream', subscription_id: subscription }],
    pricing: pricingOf(v), trial_days: trialDaysOf(v),
  }
}

// u4g: a combined offer (my nodes plus subscriptions, or several
// subscriptions). The market does not bound it by any one upstream: each
// upstream leaf is tightened along its path (graph Min), so the totals here
// are the sum over the components, for display.
export interface ComboTotals {
  httpPorts: number; streamPorts: number
  // Per metric: the summed cap, or null when a component leaves it unlimited.
  limits: Partial<Record<MarketLimitMetric, number | null>>
}

export function comboTotals(ups: MarketFrozenTerms[], ownNodes: boolean): ComboTotals {
  const limits: ComboTotals['limits'] = {}
  for (const row of defaultRows()) {
    const caps = ups.map((up) => upstreamCap(up, row.metric)?.cap)
    if (!ups.length || caps.some((c) => c === undefined)) continue
    // My nodes carry no frozen cap: with them in, the sum is unlimited.
    limits[row.metric] = ownNodes ? null : caps.reduce<number>((sum, c) => sum + (c ?? 0), 0)
  }
  return {
    httpPorts: ups.reduce((sum, up) => sum + (up.allocation.http_ports ?? 0), 0),
    streamPorts: ups.reduce((sum, up) => sum + (up.allocation.stream_ports ?? 0), 0),
    limits,
  }
}

// comboPlugins: the plugins every component has (the market intersects over
// the leaves); ownPlugins is null without own nodes.
export function comboPlugins(ups: MarketFrozenTerms[], ownPlugins: string[] | null): string[] {
  const lists = [...ups.map((up) => up.tags.plugins ?? []), ...(ownPlugins ? [ownPlugins] : [])]
  if (!lists.length) return []
  return [...new Set(lists[0])].filter((code) => lists.every((l) => l.includes(code))).sort()
}

// comboOfferOf builds the createOffer body: the own pool (when nodes were
// picked) and each subscription as components; terms as in the form.
export function comboOfferOf(v: ListingValues & ResaleAllocation, rows: LimitRow[], floor: LoadFloor | null,
  poolRef: string | null, subscriptions: string[], allowedPlugins: string[]): MarketOfferInput {
  return {
    name: v.name.trim(), billing_model: v.billing_model,
    allocation: { http_ports: v.httpPorts ?? 0, stream_ports: v.streamPorts ?? 0, websocket: !!v.websocket, http3: !!v.http3 },
    limits: toLimits(rows, floor).limits,
    tags: {
      cc_protection: v.cc, ddos_protection_gbps: v.ddos, complaint_resistant: v.complaint, tenancy: v.tenancy,
      mobile_reachable: v.mobile, region_block: v.regionBlock, ...(v.lineClass?.trim() ? { line_class: v.lineClass.trim() } : {}),
      ...(v.plugins?.length ? { plugins: v.plugins.filter((p) => allowedPlugins.includes(p)).sort() } : {}), ...customOf(v),
    },
    prepaid_exhausted_action: v.prepaid, compliance: { require_icp: v.icp },
    components: [...(poolRef ? [{ kind: 'own_pool' as const, node_pool_ref: poolRef }] : []),
      ...[...subscriptions].sort().map((id) => ({ kind: 'upstream' as const, subscription_id: id }))],
    pricing: pricingOf(v), trial_days: trialDaysOf(v),
  }
}

// pluginLabel: the local catalogue name of a code, else the code itself.
export function pluginLabel(code: string, names: Map<string, { name_zh: string; name_en: string }>, english: boolean): string {
  const n = names.get(code)
  return n ? (english ? n.name_en : n.name_zh) || code : code
}
