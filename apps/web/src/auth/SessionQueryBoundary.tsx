import { useEffect, type PropsWithChildren } from 'react'
import { useQueryClient } from '@tanstack/react-query'

import { useSessionStore } from './session'

export function SessionQueryBoundary({ children }: PropsWithChildren) {
  const queryClient = useQueryClient()

  useEffect(() => useSessionStore.subscribe((state, previous) => {
    if (state.sessionEpoch === previous.sessionEpoch) return
    void queryClient.cancelQueries()
    queryClient.clear()
  }), [queryClient])

  return children
}
