import { useQuery } from '@tanstack/react-query'

import { ApiError } from '../../api/auth'
import { marketApi } from '../../api/market'

// useAdvisories loads plugin security advisories for the signed-in scope.
// The routes exist only while the market runtime is on: a 404/501 means "no
// advisory channel here" and is shown as an empty list, not an error.
export function useAdvisories(token: string, enabled: boolean) {
  const query = useQuery({
    queryKey: ['marketAdvisories', token ? 'session' : 'none'],
    queryFn: async () => {
      try {
        return await marketApi.advisories(token)
      } catch (error) {
        if (error instanceof ApiError && (error.status === 404 || error.status === 501)) return []
        throw error
      }
    },
    enabled: enabled && !!token,
    staleTime: 60_000,
  })
  const items = query.data ?? []
  const pending = new Set(items.filter((a) => !a.acknowledgement).map((a) => a.plugin_id))
  return { query, items, pending }
}
