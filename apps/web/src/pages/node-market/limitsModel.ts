import type { MarketLimit, MarketLimitAction, MarketLimitMetric } from '../../api/market'

// Limit rows of the listing page (ADR 0012 §3.1, docs/marketplace/11-limits-contract.md §1).
// The first action is the default; units convert the seller's figure to the
// contract unit (bit/s, bytes, counts, percent).
export type LimitUnit = 'count' | 'Mbps' | 'Gbps' | 'GB' | 'TB' | 'perSecond' | 'percent'
export interface MetricRule {
  metric: MarketLimitMetric
  actions: MarketLimitAction[]
  units: LimitUnit[]
  // Realtime caps are the whole supply's total, split ceil(cap / nodes) per node (Q1).
  realtime: boolean
  // node_cpu_percent / node_memory_percent are judged per node, never split.
  perNode?: boolean
  maxCap: number
}

export const metricRules: MetricRule[] = [
  { metric: 'domains', actions: ['reject_new'], units: ['count'], realtime: false, maxCap: 1_000_000 },
  { metric: 'bandwidth_peak_bps', actions: ['throttle', 'pause', 'stop'], units: ['Mbps', 'Gbps'], realtime: true, maxCap: 1e13 },
  { metric: 'monthly_traffic_bytes', actions: ['pause', 'throttle', 'stop'], units: ['GB', 'TB'], realtime: false, maxCap: 2 ** 60 },
  { metric: 'concurrent_connections', actions: ['throttle', 'pause', 'stop'], units: ['count'], realtime: true, maxCap: 1e9 },
  { metric: 'new_connections_per_second', actions: ['throttle', 'pause', 'stop'], units: ['perSecond'], realtime: true, maxCap: 1e8 },
  { metric: 'qps', actions: ['throttle', 'pause', 'stop'], units: ['perSecond'], realtime: true, maxCap: 1e9 },
  { metric: 'node_cpu_percent', actions: ['remove_node'], units: ['percent'], realtime: false, perNode: true, maxCap: 100 },
  { metric: 'node_memory_percent', actions: ['remove_node'], units: ['percent'], realtime: false, perNode: true, maxCap: 100 },
]

const unitFactor: Record<LimitUnit, number> = {
  count: 1, perSecond: 1, percent: 1, Mbps: 1e6, Gbps: 1e9, GB: 1024 ** 3, TB: 1024 ** 4,
}

export interface LimitRow {
  metric: MarketLimitMetric
  enabled: boolean
  value: number | null
  unit: LimitUnit
  action: MarketLimitAction
  // Only monthly_traffic_bytes + throttle: the throttled rate, in Mbps.
  throttleMbps: number | null
}

export interface LoadFloor { cpu_percent: number; memory_percent: number }

export function defaultRows(): LimitRow[] {
  return metricRules.map((r) => ({ metric: r.metric, enabled: false, value: null, unit: r.units[0], action: r.actions[0], throttleMbps: null }))
}

export function ruleOf(metric: MarketLimitMetric): MetricRule {
  return metricRules.find((r) => r.metric === metric)!
}

// floorOf is the platform's upper bound on a node row; undefined for others.
export function floorOf(metric: MarketLimitMetric, floor: LoadFloor | null): number | undefined {
  if (metric === 'node_cpu_percent') return floor?.cpu_percent
  if (metric === 'node_memory_percent') return floor?.memory_percent
  return undefined
}

export function capOf(row: LimitRow): number | null {
  if (row.value === null || !(row.value > 0)) return null
  return Math.round(row.value * unitFactor[row.unit])
}

// shareOf previews what each node enforces: realtime caps split over the
// nodes, node_* rows per node, totals (domains, monthly traffic) not split.
export function shareOf(row: LimitRow, nodes: number): { kind: 'split'; value: number } | { kind: 'perNode' } | { kind: 'total' } | null {
  const rule = ruleOf(row.metric)
  if (rule.perNode) return { kind: 'perNode' }
  if (!rule.realtime) return { kind: 'total' }
  const cap = capOf(row)
  if (cap === null || nodes < 1) return null
  return { kind: 'split', value: Math.ceil(cap / nodes) / unitFactor[row.unit] }
}

export type LimitProblem = { metric: MarketLimitMetric; code: 'cap' | 'floor' | 'throttle'; floor?: number }

// toLimits builds the offer's limits from the checked rows; unchecked = unlimited.
export function toLimits(rows: LimitRow[], floor: LoadFloor | null): { limits: MarketLimit[]; problems: LimitProblem[] } {
  const limits: MarketLimit[] = []
  const problems: LimitProblem[] = []
  for (const row of rows) {
    if (!row.enabled) continue
    const rule = ruleOf(row.metric)
    const cap = capOf(row)
    if (cap === null || cap < 1 || cap > rule.maxCap) {
      problems.push({ metric: row.metric, code: 'cap' })
      continue
    }
    const max = floorOf(row.metric, floor)
    if (rule.perNode && (max === undefined || cap > max)) {
      problems.push({ metric: row.metric, code: 'floor', floor: max })
      continue
    }
    const limit: MarketLimit = { metric: row.metric, cap, action: rule.actions.includes(row.action) ? row.action : rule.actions[0] }
    if (row.metric === 'monthly_traffic_bytes' && limit.action === 'throttle') {
      const bps = row.throttleMbps === null ? 0 : Math.round(row.throttleMbps * 1e6)
      if (!(bps >= 1 && bps <= 1e13)) {
        problems.push({ metric: row.metric, code: 'throttle' })
        continue
      }
      limit.throttle_bps = bps
    }
    limits.push(limit)
  }
  return { limits, problems }
}

// overriddenBy reports the node rows of a listed offer the platform floor now
// tightens (§3.4 "已被平台底线覆盖"): effective = min(seller, floor).
export function overriddenBy(limits: MarketLimit[] | undefined, floor: LoadFloor | null): Array<{ metric: MarketLimitMetric; effective: number }> {
  if (!floor) return []
  return (limits ?? []).flatMap((l) => {
    const max = floorOf(l.metric, floor)
    return max !== undefined && l.cap > max ? [{ metric: l.metric, effective: max }] : []
  })
}

// Spec plugin codes (spec.ValidPlugin): module.* / pack.* feature codes and
// rule_pack:<pack id> (a bought rule pack every node applied) may go into tags.plugins.
const pluginCode = /^(module|pack)\.[a-z0-9]+([._-][a-z0-9]+)*$/
const rulePackCode = /^rule_pack:(system\/[a-z0-9][a-z0-9-]{0,63}|dev\/[a-z0-9]+(?:[.-][a-z0-9]+)*\/[a-z0-9][a-z0-9-]{0,63}|user\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/[a-z0-9][a-z0-9-]{0,63})$/
export function offerablePlugin(code: string): boolean {
  if (rulePackCode.test(code)) return code.length <= 180
  return code.length <= 96 && pluginCode.test(code)
}

// formatCap renders a contract cap in the largest unit it reaches (rounded to 2 decimals).
export function formatCap(metric: MarketLimitMetric, cap: number): { value: number; unit: LimitUnit } {
  const units = ruleOf(metric).units
  const unit = [...units].reverse().find((u) => cap >= unitFactor[u]) ?? units[0]
  return { value: Math.round((cap / unitFactor[unit]) * 100) / 100, unit }
}
