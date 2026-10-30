import type { MarketOfferListing } from '../../api/market'
import type { Principal } from '../../api/auth'

// MC01 (NM02): a purchase whose answer is not known yet (sent, or lost on the
// way back) is kept per account in sessionStorage, so leaving the section or
// reloading the page still offers "check result" for that exact request: the
// same offer, days, revision and idempotency key. It holds only the public
// catalogue entry and the key, no token or payment secret. Another account in
// the same tab has its own slot and never sees it.
export interface PendingPurchase { offer: MarketOfferListing; days: number; trial: boolean; key: string }

const prefix = 'cdnca.market.pendingPurchase:'

export function pendingAccount(principal: Principal | null): string {
  return principal ? `${principal.scope_kind}:${principal.scope_id}:${principal.user_id}` : ''
}

export function loadPending(account: string): PendingPurchase | null {
  if (!account) return null
  try {
    const raw = window.sessionStorage.getItem(prefix + account)
    const value = raw ? (JSON.parse(raw) as PendingPurchase) : null
    return value && typeof value.key === 'string' && value.offer?.id ? value : null
  } catch {
    return null
  }
}

export function savePending(account: string, value: PendingPurchase) {
  if (!account) return
  try {
    window.sessionStorage.setItem(prefix + account, JSON.stringify(value))
  } catch {
    // Storage full or disabled: the in-page state still guards this visit.
  }
}

// clearPending removes the record only while it is still the one for key, so
// a late answer to an older request cannot drop a newer pending one.
export function clearPending(account: string, key: string) {
  if (!account || loadPending(account)?.key !== key) return
  try {
    window.sessionStorage.removeItem(prefix + account)
  } catch {
    // ignore
  }
}
