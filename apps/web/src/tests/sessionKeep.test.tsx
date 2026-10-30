import { QueryClientProvider, useQuery } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ticketsApi } from '../api/tickets'
import { refreshSession, useSessionStore } from '../auth/session'
import { createSessionQueryClient } from '../auth/sessionQueryClient'
import { authResponse, principal } from '../test/fixtures'

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

function signIn(token: string) {
  const user = principal({ scope_kind: 'platform', tenant_id: null, permissions: ['platform.admin'] })
  useSessionStore.getState().setSession({ ...authResponse(user), access_token: token }, user)
  return user
}

function urlOf(input: RequestInfo | URL): string {
  return typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
}

function authorization(init?: RequestInit): string | undefined {
  return (init?.headers as Record<string, string> | undefined)?.Authorization
}

// Polls like useTicketMenuBadge / any page query: reads the token at render time.
function Summary({ name }: { name: string }) {
  const accessToken = useSessionStore((state) => state.accessToken)
  const query = useQuery({
    queryKey: ['tickets', 'admin', 'summary', name],
    queryFn: () => ticketsApi.summary(accessToken ?? '', 'admin'),
    retry: false,
  })
  return <div>{query.data ? `${name}:${query.data.pending}` : `${name}:loading`}</div>
}

describe('session keep', () => {
  it('renews once for concurrent 401s and replays the queries without signing out', async () => {
    const user = signIn('expired-access-token')
    let refreshCalls = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = urlOf(input)
      if (url === '/v1/auth/refresh') {
        refreshCalls += 1
        return json({ ...authResponse(user), access_token: 'renewed-access-token' })
      }
      if (url === '/v1/auth/me') return json(user)
      if (url.startsWith('/v1/admin/tickets/summary')) {
        return authorization(init) === 'Bearer renewed-access-token'
          ? json({ unread: 0, pending: 3 })
          : json({ code: 'invalid_session' }, 401)
      }
      throw new Error(`unexpected ${url}`)
    })

    render(
      <QueryClientProvider client={createSessionQueryClient()}>
        <Summary name="a" /><Summary name="b" /><Summary name="c" />
      </QueryClientProvider>,
    )

    for (const name of ['a', 'b', 'c']) expect(await screen.findByText(`${name}:3`)).toBeInTheDocument()
    expect(refreshCalls).toBe(1)
    expect(useSessionStore.getState()).toMatchObject({ status: 'authenticated', accessToken: 'renewed-access-token' })
  })

  it('stays signed in when the renewal fails transiently', async () => {
    signIn('current-access-token')
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ error: { code: 'service_unavailable' } }, 503))
    await expect(refreshSession()).rejects.toMatchObject({ status: 503 })
    expect(useSessionStore.getState()).toMatchObject({ status: 'authenticated', accessToken: 'current-access-token' })

    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new TypeError('Failed to fetch'))
    await expect(refreshSession()).rejects.toMatchObject({ status: 0 })
    expect(useSessionStore.getState().status).toBe('authenticated')
  })

  it('signs out when the server refuses the renewal', async () => {
    signIn('current-access-token')
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ error: { code: 'invalid_session' } }, 401))
    await expect(refreshSession()).rejects.toMatchObject({ status: 401 })
    await waitFor(() => expect(useSessionStore.getState().status).toBe('anonymous'))
  })

  it('does not loop when the replayed query is refused again', async () => {
    const user = signIn('expired-access-token')
    let refreshCalls = 0
    let summaryCalls = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = urlOf(input)
      if (url === '/v1/auth/refresh') {
        refreshCalls += 1
        return json({ ...authResponse(user), access_token: `renewed-${refreshCalls}` })
      }
      if (url === '/v1/auth/me') return json(user)
      summaryCalls += 1
      return json({ code: 'invalid_session' }, 401)
    })
    render(<QueryClientProvider client={createSessionQueryClient()}><Summary name="x" /></QueryClientProvider>)
    await waitFor(() => expect(summaryCalls).toBe(2))
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(refreshCalls).toBe(1)
    expect(summaryCalls).toBe(2)
  })

  // B16: a page read that hits an expired access token waits for the one
  // renewal and is replayed in the same fetch; the page never sees the 401 as
  // a failure (TicketsPage would pop its error feedback). A mutation is still
  // never replayed.
  it('never exposes a renewed 401 as a query failure and does not replay mutations', async () => {
    const user = signIn('expired-access-token')
    const seen: string[] = []
    let writes = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = urlOf(input)
      if (url === '/v1/auth/refresh') return json({ ...authResponse(user), access_token: 'renewed-access-token' })
      if (url === '/v1/auth/me') return json(user)
      if (init?.method === 'POST') {
        writes += 1
        return json({ code: 'invalid_session' }, 401)
      }
      return authorization(init) === 'Bearer renewed-access-token'
        ? json({ unread: 0, pending: 5 })
        : json({ code: 'invalid_session' }, 401)
    })
    function Watched() {
      const accessToken = useSessionStore((state) => state.accessToken)
      const query = useQuery({
        queryKey: ['tickets', 'admin', 'summary', 'watched'],
        queryFn: () => ticketsApi.summary(accessToken ?? '', 'admin'),
      })
      seen.push(query.status)
      return <div>{query.data ? `watched:${query.data.pending}` : query.isError ? 'watched:error' : 'watched:loading'}</div>
    }
    const client = createSessionQueryClient()
    render(<QueryClientProvider client={client}><Watched /></QueryClientProvider>)
    expect(await screen.findByText('watched:5')).toBeInTheDocument()
    expect(seen).not.toContain('error')

    await expect(client.getMutationCache().build(client, {
      mutationFn: () => fetch('/v1/admin/tickets', { method: 'POST' }).then(async (response) => {
        if (response.status === 401) throw Object.assign(new Error('expired'), { status: 401 })
        return response
      }),
    }).execute(undefined)).rejects.toThrow('expired')
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(writes).toBe(1)
  })
})
