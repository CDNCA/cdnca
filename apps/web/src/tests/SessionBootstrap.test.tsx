import { screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'

import { SessionBootstrap } from '../auth/SessionBootstrap'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

afterEach(() => vi.restoreAllMocks())

it.each(['/login', '/register'])('skips anonymous session refresh on %s', (path) => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
  renderWithProviders(<SessionBootstrap><div>public page</div></SessionBootstrap>, [path])

  expect(screen.getByText('public page')).toBeInTheDocument()
  expect(fetchSpy).not.toHaveBeenCalled()
})

it('keeps session refresh enabled on protected paths', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({
    error: { code: 'invalid_session' },
  }), { status: 401, headers: { 'Content-Type': 'application/json' } }))

  renderWithProviders(<SessionBootstrap><div>protected page</div></SessionBootstrap>, ['/site/list'])

  expect(await screen.findByText('protected page')).toBeInTheDocument()
  expect(fetchSpy).toHaveBeenCalledTimes(1)
  expect(fetchSpy.mock.calls[0]?.[0]).toBe('/v1/auth/refresh')
})

// a restored administrator session on the overview starts the
// dashboard read right after the refresh, before the console shell and page load.
const admin = principal({ scope_kind: 'platform', tenant_id: null, permissions: ['platform.admin'], roles: ['platform_owner'] })
const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })

it.each(['/admin-home', '/'])('starts the admin dashboard read right after restoring the session on %s', async (path) => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => (
    String(url) === '/v1/auth/refresh' ? ok(authResponse(admin)) : new Response('{}', { status: 503 })
  ))
  renderWithProviders(<SessionBootstrap><div>shell not loaded yet</div></SessionBootstrap>, [path])

  await waitFor(() => expect(fetchSpy.mock.calls.map(([url]) => String(url).replace(/\?.*/, ''))).toContain('/v1/admin/dashboard'))
  const dashboard = fetchSpy.mock.calls.find(([url]) => String(url).startsWith('/v1/admin/dashboard?'))
  expect(String(dashboard?.[0])).toContain('range=seven_days')
  expect(fetchSpy.mock.calls.map(([url]) => String(url))).not.toContain('/v1/auth/me')
})

it.each([
  ['a tenant user on /admin-home', principal(), '/admin-home'],
  ['an administrator on another page', admin, '/site/list'],
] as const)('does not start the admin dashboard read for %s', async (_case, user, path) => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => ok(authResponse(user)))
  renderWithProviders(<SessionBootstrap><div>restored</div></SessionBootstrap>, [path])

  expect(await screen.findByText('restored')).toBeInTheDocument()
  await new Promise((resolve) => setTimeout(resolve, 50))
  expect(fetchSpy.mock.calls.map(([url]) => String(url))).toEqual(['/v1/auth/refresh'])
})
