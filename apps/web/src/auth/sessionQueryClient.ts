import { MutationCache, QueryClient, type Query, type QueryFunctionContext } from '@tanstack/react-query'

import { ApiError } from '../api/auth'
import { refreshSession, useSessionStore } from './session'

// A query replayed after a refresh that is refused again within this window is
// not refreshed a second time (the refusal is not about an expired token).
const replayWindowMilliseconds = 30_000

// 401s that are about the request, not an expired access token.
const notExpiry = new Set(['invalid_credentials', 'session_region_changed', 'login_verification_required',
  'login_captcha_required', 'login_captcha_invalid', 'account_login_verification_invalid', 'invalid_api_key'])

function expiredAccess(error: unknown): boolean {
  return error instanceof ApiError && error.status === 401 && !notExpiry.has(error.code)
}

// createSessionQueryClient: a 401 from an API call while signed in means the
// short-lived access token ran out (sleeping laptop, background tab, a poll
// that fired just before the renewal timer). Renew once — concurrent 401s
// share one refresh (refreshSession is single-flight) — and replay the failed
// query with the new token instead of dropping the user to the login page.
// B16: the replay runs inside the same fetch, so the page stays loading (or
// keeps its previous data) and only sees an error when the renewal or the
// replay itself fails. Mutations are not replayed (writes are not repeated
// behind the user's back); the refresh makes the user's next attempt succeed.
function infinite(query: Query): boolean {
  return 'getNextPageParam' in query.options && typeof query.options.getNextPageParam === 'function'
}

export function createSessionQueryClient(): QueryClient {
  const replayedAt = new Map<string, number>()

  const renew = async (): Promise<void> => {
    await refreshSession()
    // Next task: components re-render with the new token first, so the query
    // function that is replayed reads the renewed access token.
    await new Promise((resolve) => window.setTimeout(resolve, 0))
  }

  // persister is TanStack's per-fetch wrapper around the query function; it
  // is used here only to wait for the renewal and replay the exact query.
  const replayAfterRenewal = async (
    queryFn: (context: QueryFunctionContext) => unknown,
    context: QueryFunctionContext,
    query: Query,
  ): Promise<unknown> => {
    try {
      return await queryFn(context)
    } catch (error) {
      if (!expiredAccess(error) || useSessionStore.getState().status !== 'authenticated') throw error
      const now = Date.now()
      const previous = replayedAt.get(query.queryHash)
      // A replay refused again within the window is not about an expired
      // token: do not refresh a second time.
      if (previous !== undefined && now - previous < replayWindowMilliseconds) throw error
      replayedAt.set(query.queryHash, now)
      try {
        await renew()
      } catch {
        throw error
      }
      // The replay must read the renewed token: call the query function of
      // the latest render, not the closure this fetch started with.
      const latest = query.options.queryFn
      if (typeof latest === 'function' && !infinite(query)) return latest(context)
      // Infinite queries page through their own fetch function; let the
      // failure through and refetch the whole query once renewed.
      window.setTimeout(() => void client.refetchQueries({ queryKey: query.queryKey, exact: true }), 0)
      throw error
    }
  }

  const client: QueryClient = new QueryClient({
    mutationCache: new MutationCache({
      onError: (error) => {
        if (expiredAccess(error) && useSessionStore.getState().status === 'authenticated') void renew().catch(() => undefined)
      },
    }),
    defaultOptions: {
      // networkMode stays 'online' (a persister would default it to offlineFirst).
      queries: { retry: false, refetchOnWindowFocus: false, networkMode: 'online', persister: replayAfterRenewal },
      mutations: { retry: false },
    },
  })
  return client
}
