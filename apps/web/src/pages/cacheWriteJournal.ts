// CACHE-ADD-05 (P2-09): the identity of a cache write whose outcome is unknown
// (network loss, timeout, 5xx). Every entry that can send the same write (row,
// batch, detail, group dialog, after leaving or reloading the page) reuses the
// key recorded here, so closing a view never mints a new identity for it.
//
// Kept in sessionStorage (this tab only), per principal and scope, and holds
// only the action, the operation ID or a hash of the request body, the key and
// the time: never URLs or tokens. A definite answer (success or a refusal)
// clears the entry, and only for the key that answered, so a late response of
// an older attempt cannot clear a newer one.
//
// fix-cacheflow5: the entry only says the outcome is unknown here; the server
// holds the truth. Before a recorded key is sent again, cacheWriteOutcome asks
// GET .../cache-operation-requests/{key} what happened to it.

import { ApiError } from '../api/auth'
import {
  cacheOperationsApi,
  type CacheOperation,
  type CacheOperationScope,
  type CacheWriteRef,
} from '../api/cacheOperations'

const storageKey = 'cdnca.cache-pending-writes.v1'
const maxAgeMs = 24 * 60 * 60 * 1000
const maxEntries = 200

export type CacheWriteAction = 'create' | 'retry' | 'cancel' | 'resubmit'

interface PendingWrite {
  owner: string
  identity: string
  key: string
  at: number
}

function read(now: number): PendingWrite[] {
  try {
    const value: unknown = JSON.parse(window.sessionStorage.getItem(storageKey) ?? '[]')
    if (!Array.isArray(value)) return []
    return value.filter((item): item is PendingWrite =>
      typeof item === 'object' && item !== null &&
      typeof item.owner === 'string' && typeof item.identity === 'string' &&
      typeof item.key === 'string' && typeof item.at === 'number' && now - item.at < maxAgeMs)
  } catch {
    return []
  }
}

function write(entries: PendingWrite[]) {
  try {
    window.sessionStorage.setItem(storageKey, JSON.stringify(entries.slice(-maxEntries)))
  } catch {
    // Storage unavailable: the in-page lock still holds the key.
  }
}

/** Principal and scope the write belongs to (no epoch: it survives a reload). */
export function cacheWriteOwner(scopeID: string, userID: string, scope: string): string {
  return `${scopeID}|${userID}|${scope}`
}

/** cyrb53: a short stable digest, so the journal never stores the targets. */
function digest(text: string): string {
  let h1 = 0xdeadbeef
  let h2 = 0x41c6ce57
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index)
    h1 = Math.imul(h1 ^ code, 2654435761)
    h2 = Math.imul(h2 ^ code, 1597334677)
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909)
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909)
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36)
}

/** A create is identified by its exact body; the other writes by their operation. */
export function cacheWriteIdentity(action: CacheWriteAction, subject: string | object): string {
  return action === 'create'
    ? `create:${digest(JSON.stringify(subject, Object.keys(subject).sort()))}`
    : `${action}:${String(subject)}`
}

export function pendingCacheWriteKey(owner: string, identity: string, now = Date.now()): string | undefined {
  return read(now).find((item) => item.owner === owner && item.identity === identity)?.key
}

/** Records an attempt whose outcome is unknown. */
export function rememberCacheWrite(owner: string, identity: string, key: string, now = Date.now()) {
  write([...read(now).filter((item) => item.owner !== owner || item.identity !== identity), { owner, identity, key, at: now }])
}

/** A definite answer for `key`: clears the entry only if it still holds that key. */
export function settleCacheWrite(owner: string, identity: string, key: string, now = Date.now()) {
  const entries = read(now)
  const next = entries.filter((item) => item.owner !== owner || item.identity !== identity || item.key !== key)
  if (next.length !== entries.length) write(next)
}

// The status the write itself was answered with, so a refusal read from its
// receipt is handled like the original response.
const rejectionStatus: Record<string, number> = {
  invalid_request: 400, wildcard_target_host: 400, entitlement_denied: 403, daily_limit_exceeded: 429,
}

/**
 * The server's answer for a write whose earlier attempt with `ref.key` has an
 * unknown outcome: the operation when it was accepted, an ApiError (a definite
 * refusal) when it was refused, null when it was never received or the receipt
 * cannot be read now (then the same request with the same key is safe to send).
 */
export async function cacheWriteOutcome(
  accessToken: string,
  scope: CacheOperationScope,
  ref: CacheWriteRef,
): Promise<CacheOperation | ApiError | null> {
  let receipt
  try {
    receipt = await cacheOperationsApi.writeReceipt(accessToken, scope, ref)
  } catch {
    return null
  }
  if (!receipt) return null
  if (receipt.status === 'accepted') return receipt.operation
  const { code, details } = receipt.rejection
  const error = new ApiError('Cache write was refused', rejectionStatus[code] ?? 409, code)
  if (details) error.targetRejection = { ordinal: details.target_ordinal, reason: details.reason }
  return error
}

/**
 * Sends a cache write, the server's receipt deciding when its outcome is
 * unknown. `recorded`: an earlier attempt with this key has an unknown outcome
 * (journal entry), so the receipt is read first and the request is sent only
 * when the server never received it. After a send whose outcome is unknown
 * the receipt is read once more. A refusal read from a receipt is thrown as
 * the ApiError the write would have been answered with.
 */
export async function sendCacheWrite(
  accessToken: () => string,
  scope: CacheOperationScope,
  ref: CacheWriteRef,
  recorded: boolean,
  send: () => Promise<CacheOperation>,
  outcomeUnknown: (error: unknown) => boolean,
): Promise<CacheOperation> {
  const decided = async () => {
    const outcome = await cacheWriteOutcome(accessToken(), scope, ref)
    if (outcome instanceof ApiError) throw outcome
    return outcome
  }
  if (recorded) {
    const accepted = await decided()
    if (accepted) return accepted
  }
  try {
    return await send()
  } catch (error) {
    if (!outcomeUnknown(error)) throw error
    const accepted = await decided()
    if (accepted) return accepted
    throw error
  }
}
