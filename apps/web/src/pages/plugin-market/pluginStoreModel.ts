import type { MarketPlugin, MarketPricePlan } from '../../api/market'

// Permissions a buyer should look at twice: anything that manages, writes,
// executes or reaches secrets, plus every permission of a privileged
// (controller extension) plugin. Shown in red in the detail drawer.
const highRiskPattern = /(^|\.)(manage|write|delete|exec|execute|admin|secrets?|credentials?|keys?|shell)($|\.)/

export function highRiskPermission(plugin: Pick<MarketPlugin, 'risk_class'>, permission: string): boolean {
  return plugin.risk_class === 'privileged' || highRiskPattern.test(permission)
}

export function formatMinor(amount: number, currency: string): string {
  return `${(amount / 100).toFixed(2)} ${currency}`
}

// safeLink keeps only https links from seller-provided metadata.
export function safeLink(raw: string | undefined): string | null {
  if (!raw) return null
  try {
    const url = new URL(raw)
    return url.protocol === 'https:' && !url.username && !url.password ? url.toString() : null
  } catch {
    return null
  }
}

// A plan is on sale at its active_revision (M2: a price change waits in
// pending_review while the old revision keeps selling).
export function activePlans(plans: MarketPricePlan[]): MarketPricePlan[] {
  return plans.filter((plan) => plan.status !== 'retired' && typeof saleRevision(plan) === 'number')
}

export function saleRevision(plan: MarketPricePlan): number | null {
  if (plan.active_revision !== undefined) return plan.active_revision ?? null
  return plan.status === 'active' ? plan.revision : null
}

export const terminalOrderStates = new Set(['fulfilled', 'cancelled', 'expired', 'refunded', 'partially_refunded'])
