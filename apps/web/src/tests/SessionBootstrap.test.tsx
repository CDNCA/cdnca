import { screen } from '@testing-library/react'
import { afterEach, it, vi } from 'vitest'

import { SessionBootstrap } from '../auth/SessionBootstrap'
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
