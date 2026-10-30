// Live filters: a filter bar applies as the user types.
// The page keeps a draft and the applied filters; this hook applies the draft
// 400ms after the last change, never while an input method is composing
// (pinyin "zhang" before it becomes 张) and never while the page says the
// draft is invalid. Selects, switches and dates apply on change in the page
// itself; that makes draft equal applied, so the pending timer is dropped.
// Late results of an older query are dropped by keying the query on the
// applied filters (react-query) or by the caller's own request counter.
import { useEffect, useRef, useState } from 'react'

export const liveFilterDelay = 400

export interface LiveApplyOptions {
  /** False while the draft fails validation: nothing is applied. */
  valid?: boolean
  delay?: number
}

function same(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right)
}

/** True while any text field on the page has an open IME composition. */
export function useComposing(): boolean {
  const [composing, setComposing] = useState(false)
  useEffect(() => {
    const start = () => setComposing(true)
    const end = () => setComposing(false)
    document.addEventListener('compositionstart', start, true)
    document.addEventListener('compositionend', end, true)
    return () => {
      document.removeEventListener('compositionstart', start, true)
      document.removeEventListener('compositionend', end, true)
    }
  }, [])
  return composing
}

export function useLiveApply<T>(draft: T, applied: T, apply: (next: T) => void, options: LiveApplyOptions = {}) {
  const { valid = true, delay = liveFilterDelay } = options
  const composing = useComposing()
  const applyRef = useRef(apply)
  applyRef.current = apply
  const latest = useRef(draft)
  latest.current = draft
  const key = JSON.stringify(draft)
  const pending = !same(draft, applied)
  useEffect(() => {
    if (!pending || !valid || composing) return
    const timer = window.setTimeout(() => applyRef.current(latest.current), delay)
    return () => window.clearTimeout(timer)
  }, [key, pending, valid, composing, delay])
}
