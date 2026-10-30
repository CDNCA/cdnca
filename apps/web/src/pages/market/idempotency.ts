import { useCallback, useRef } from 'react'

import { ApiError } from '../../api/auth'
import { marketUnavailable, newIdempotencyKey } from '../../api/market'

// One Idempotency-Key per purchase attempt (market-buy-idem): the same payload
// reuses the key, so a retry after a timeout replays on the market (it keys
// purchases, top-ups and orders by buyer + key) instead of charging again. A
// changed payload, a success or a definite refusal starts a new key.
export function useIdempotencyKey(prefix: string) {
  const state = useRef<{ fingerprint: string; key: string } | null>(null)
  const keyFor = useCallback((payload: unknown) => {
    const fingerprint = JSON.stringify(payload)
    if (!state.current || state.current.fingerprint !== fingerprint) {
      state.current = { fingerprint, key: newIdempotencyKey(prefix) }
    }
    return state.current.key
  }, [prefix])
  // 卡 7：complete(key) 只清还是这把键的状态；一个迟到的响应（另一份内容的请求）不能清掉当前键。
  const complete = useCallback((key?: string) => {
    if (key === undefined || state.current?.key === key) state.current = null
  }, [])
  return { keyFor, complete }
}

// outcomeUnknown: the write may have happened (network error, timeout, 5xx).
// Such an attempt is only replayed with its own key, never re-bought. A 501 /
// unmounted market route means nothing was written.
export function outcomeUnknown(error: unknown): boolean {
  if (marketUnavailable(error)) return false
  if (!(error instanceof ApiError)) return true
  // The market's own 503 refusals (finance_admin.go tradingStatus: escrow off,
  // httpapi.go: purchases paused) are definite: nothing was written.
  if (error.status === 503 && definiteRefusals.has(error.code)) return false
  return error.status === 0 || error.status === 408 || error.status >= 500
}

const definiteRefusals = new Set(['unavailable', 'purchases_paused'])
