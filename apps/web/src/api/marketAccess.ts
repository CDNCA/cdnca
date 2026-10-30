import type { Principal } from './auth'

// Marketplace permission codes (control-api migration 296). The old platform
// gate (sites.manage / platform.admin) keeps every market action for one release;
// control-api enforces the same rules (marketsubscribehttp access.allows).
export const marketPermissions = {
  browse: 'marketplace.browse',
  purchase: 'marketplace.purchase',
  sell: 'marketplace.sell',
} as const

export interface MarketAccess {
  browse: boolean
  purchase: boolean
  sell: boolean
  // Supply/site binding edits sites, so it keeps the old gate only.
  sites: boolean
}

export function marketAccess(principal: Principal | null | undefined): MarketAccess {
  if (!principal || principal.scope_kind !== 'platform') return { browse: false, purchase: false, sell: false, sites: false }
  const has = (code: string) => principal.permissions.includes(code)
  const legacy = has('sites.manage') || has('platform.admin')
  const purchase = legacy || has(marketPermissions.purchase)
  const sell = legacy || has(marketPermissions.sell)
  return { browse: legacy || purchase || sell || has(marketPermissions.browse), purchase, sell, sites: legacy }
}
