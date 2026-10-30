import type {
  MarketHold, MarketLimitMetric, MarketPrepaid, MarketSubscriptionLimits, MarketSupplyAvailability, MarketSupplyState, MarketUsageSample,
} from '../../api/market'

// Subscriber-side helpers of ADR 0012 §9.2/§9.3 (ML-12).

// Tags the seller declares itself (§3.2); shown apart from platform-measured facts.
export const declaredTagKeys = ['cc_protection', 'ddos_protection_gbps', 'complaint_resistant', 'tenancy', 'mobile_reachable',
  'region_block', 'line_class'] as const

// Percent of cap used, clamped to 0..100 for the bar.
export function usagePercent(value: number, cap: number): number {
  if (!(cap > 0) || !(value > 0)) return 0
  return Math.min(100, Math.round((value / cap) * 100))
}

// Bar status: 95% and above = at the limit, 80% and above = warning.
export function usageStatus(percent: number): 'exception' | 'active' | 'normal' {
  if (percent >= 95) return 'exception'
  if (percent >= 80) return 'active'
  return 'normal'
}

// Column of a 5-minute sample that carries each metric (monthly traffic plots bytes per bucket).
const seriesColumn: Partial<Record<MarketLimitMetric, keyof MarketUsageSample>> = {
  bandwidth_peak_bps: 'peak_bps',
  monthly_traffic_bytes: 'bytes_out',
  concurrent_connections: 'max_concurrent',
  new_connections_per_second: 'max_new_cps',
  qps: 'max_qps',
}

export function seriesOf(samples: MarketUsageSample[], metric: MarketLimitMetric): number[] {
  const column = seriesColumn[metric]
  return column ? samples.map((s) => Number(s[column]) || 0) : []
}

// Recovery condition key per hold reason (ADR 0012 §15): limit → back under
// 80% for two buckets, or next month for monthly traffic; prepaid and the
// overdraft cap → top up to a non-negative balance; operator → wait for the platform.
export function recoveryKey(hold: Pick<MarketHold, 'reason' | 'metric'>): string {
  if (hold.reason === 'limit') return hold.metric === 'monthly_traffic_bytes' ? 'limitMonthly' : 'limitRealtime'
  if (hold.reason === 'prepaid' || hold.reason === 'overdraft_cap') return 'topUp'
  return 'operator'
}

// Worst state across slots: stopped > paused > overloaded > serving.
const rank: Record<MarketSupplyState, number> = { serving: 0, overloaded: 1, paused: 2, stopped: 3 }
export function worstState(states: MarketSupplyState[]): MarketSupplyState {
  return states.reduce<MarketSupplyState>((worst, s) => (rank[s] > rank[worst] ? s : worst), 'serving')
}

export const stateColor: Record<MarketSupplyState, string> = { serving: 'success', overloaded: 'warning', paused: 'orange', stopped: 'error' }

// A12/MSTATE-01: the subscription's availability; an empty supply list is
// no_supply, never serving. Older markets without the field: from the slots.
export function supplyAvailability(l: Pick<MarketSubscriptionLimits, 'status' | 'supplies' | 'availability'>): MarketSupplyAvailability {
  if (l.availability) return l.availability
  if (l.status !== 'active') return 'cancelled'
  if (!l.supplies.length) return 'no_supply'
  const serving = l.supplies.filter((s) => s.state === 'serving').length
  return serving === l.supplies.length ? 'serving' : serving === 0 ? 'unavailable' : 'degraded'
}

export const availabilityColor: Record<MarketSupplyAvailability, string> = {
  serving: 'success', degraded: 'warning', unavailable: 'error', no_supply: 'error', cancelled: 'default',
}

// Hours the balance lasts at the last 24 hours' spend; null when nothing was spent.
export function hoursLeft(p: Pick<MarketPrepaid, 'balance_minor' | 'spent_24h_minor'>): number | null {
  if (!(p.spent_24h_minor > 0)) return null
  if (p.balance_minor <= 0) return 0
  return Math.floor((p.balance_minor / p.spent_24h_minor) * 24)
}
