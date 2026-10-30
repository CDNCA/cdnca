import { waitFor } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import * as session from '../auth/session'
import { AppShell } from '../components/AppShell'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

afterEach(() => vi.unstubAllGlobals())

describe('AppShell granted modules (PA-15)', () => {
  it('loads GET /v1/modules with the session token for requiredModule menu items', async () => {
    const fetchMock = vi.fn(async (path: string) => path.endsWith('/v1/modules')
      ? json({ status: 'valid', lease_serial: 1, modules: ['module.escalate'] })
      : json({ code: 'not_found' }, 404))
    vi.stubGlobal('fetch', fetchMock)
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['sites.read'] })
    session.useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'modules-token' }, actor)
    renderWithProviders(
      <Routes><Route element={<AppShell />}><Route path="*" element={<span />} /></Route></Routes>,
      ['/admin-home'],
    )
    await waitFor(() => expect(fetchMock.mock.calls.some(([path]) => String(path).endsWith('/v1/modules'))).toBe(true))
    const call = fetchMock.mock.calls.find(([path]) => String(path).endsWith('/v1/modules')) as unknown as [string, RequestInit]
    expect((call[1].headers as Record<string, string>).Authorization).toBe('Bearer modules-token')
  })
})
