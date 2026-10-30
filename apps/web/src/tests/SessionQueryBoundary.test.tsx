import { act, render, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

import { SessionQueryBoundary } from '../auth/SessionQueryBoundary'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}

function renderBoundary(queryClient: QueryClient) {
  return render(
    <QueryClientProvider client={queryClient}>
      <SessionQueryBoundary><div>child</div></SessionQueryBoundary>
    </QueryClientProvider>,
  )
}

describe('SessionQueryBoundary', () => {
  it('does not clear existing cache on initial mount or same-epoch token refresh', async () => {
    const actor = principal()
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const epoch = useSessionStore.getState().sessionEpoch
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity } },
    })
    const queryKey = ['owner-cache', actor.scope_id, epoch]
    queryClient.setQueryData(queryKey, { value: 'retained' })

    renderBoundary(queryClient)
    act(() => {
      useSessionStore.getState().setSession(
        { ...authResponse(actor), access_token: 'refreshed-token' },
        actor,
        'refresh',
      )
    })

    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(queryClient.getQueryData(queryKey)).toEqual({ value: 'retained' })
  })

  it('clears prior queries and mutations and fences a late response on epoch change', async () => {
    const actorA = principal()
    const actorB = principal({
      user_id: '33333333-3333-4333-8333-333333333333',
      username: 'new-owner',
    })
    useSessionStore.getState().setSession(authResponse(actorA), actorA)
    const oldEpoch = useSessionStore.getState().sessionEpoch
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity } },
    })
    const late = deferred<{ owner: string }>()
    const lateQuery = queryClient.fetchQuery({
      queryKey: ['late-owner-query', actorA.scope_id, oldEpoch],
      queryFn: () => late.promise,
    })
    queryClient.setQueryData(['old-owner-secret'], { token: 'old-query-secret' })
    queryClient.getMutationCache().build(queryClient, {
      mutationKey: ['old-owner-write'],
      mutationFn: async () => undefined,
    }, {
      context: undefined,
      data: undefined,
      error: null,
      failureCount: 0,
      failureReason: null,
      isPaused: false,
      status: 'pending',
      variables: { password: 'old-mutation-secret' },
      submittedAt: 1,
    })
    renderBoundary(queryClient)

    act(() => {
      useSessionStore.getState().setSession(authResponse(actorB), actorB)
    })

    expect(useSessionStore.getState().sessionEpoch).not.toBe(oldEpoch)
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0)
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0)

    late.resolve({ owner: 'old-owner' })
    await lateQuery.catch(() => undefined)
    await waitFor(() => expect(queryClient.getQueryCache().getAll()).toHaveLength(0))
  })
})
