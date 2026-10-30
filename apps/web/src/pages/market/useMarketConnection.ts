import { useQuery } from '@tanstack/react-query'

import { marketConnected } from '../../api/market'

// useMarketConnection reports whether this controller mounted the market
// routes: connected is undefined while probing, then true/false. Pages render
// only the "not connected" notice when false so their tabs send no requests
// (W3). The routes are mounted by the server deployment (optional.env,
// MARKET_RUNTIME_ENABLED, restart), so recheck probes again once the server
// administrator fixed it (Codex 复查卡 47).
export function useMarketConnection(token: string): { connected: boolean | undefined; recheck: () => void; rechecking: boolean } {
  const query = useQuery({
    queryKey: ['marketConnection', token ? 'session' : 'none'],
    queryFn: () => marketConnected(token),
    enabled: !!token,
    staleTime: Infinity,
    retry: false,
  })
  return { connected: query.data, recheck: () => void query.refetch(), rechecking: query.isFetching }
}
