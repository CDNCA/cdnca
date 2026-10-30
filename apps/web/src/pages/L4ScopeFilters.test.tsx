import { screen, waitFor } from '@testing-library/react'

import * as session from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { L4NodeSelect } from './L4ScopeFilters'

// ui-route-cov: GET /v1/nodes needs nodes.read. A platform role that opens the
// 四层 pages with sites.read / streams.read only gets no node filter and no 403.
function json(body: unknown) {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

function signIn(permissions: string[]) {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions })
  session.useSessionStore.getState().setSession(authResponse(actor), actor)
}

describe('L4NodeSelect', () => {
  const nodeCalls = (spy: { mock: { calls: unknown[][] } }) => spy.mock.calls.filter(([url]) => String(url).startsWith('/v1/nodes'))

  it('stays hidden and silent without nodes.read', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [] }))
    signIn(['sites.read', 'streams.read'])
    renderWithProviders(<L4NodeSelect ownerKey="t" onChange={() => {}} />)
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(screen.queryByLabelText('节点')).not.toBeInTheDocument()
    expect(nodeCalls(fetchSpy)).toHaveLength(0)
  })

  it('lists nodes with nodes.read', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [], next_cursor: null }))
    signIn(['sites.read', 'nodes.read'])
    renderWithProviders(<L4NodeSelect ownerKey="t" onChange={() => {}} />)
    await waitFor(() => expect(nodeCalls(fetchSpy).length).toBeGreaterThan(0))
  })
})
