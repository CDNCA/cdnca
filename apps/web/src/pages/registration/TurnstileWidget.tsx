import { useEffect, useRef } from 'react'

import type { TurnstileAdapter, TurnstileMountOptions } from './turnstileAdapter'

interface TurnstileWidgetProps extends TurnstileMountOptions {
  adapter: TurnstileAdapter
  label: string
  resetKey: number
}

export function TurnstileWidget({
  adapter,
  label,
  language,
  onError,
  onExpired,
  onToken,
  resetKey,
  siteKey,
}: TurnstileWidgetProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const callbacksRef = useRef({ onError, onExpired, onToken })
  callbacksRef.current = { onError, onExpired, onToken }

  useEffect(() => {
    const container = containerRef.current
    if (!container || !siteKey) {
      callbacksRef.current.onError()
      return
    }
    let disposed = false
    let unmount: (() => void) | undefined
    void adapter.mount(container, {
      siteKey,
      language,
      onToken: (token) => callbacksRef.current.onToken(token),
      onExpired: () => callbacksRef.current.onExpired(),
      onError: () => callbacksRef.current.onError(),
    }).then((cleanup) => {
      if (disposed) cleanup()
      else unmount = cleanup
    }).catch(() => callbacksRef.current.onError())
    return () => {
      disposed = true
      unmount?.()
    }
  }, [adapter, language, resetKey, siteKey])

  return <div ref={containerRef} aria-label={label} />
}
