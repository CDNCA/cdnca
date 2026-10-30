import { screen } from '@testing-library/react'
import { vi } from 'vitest'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

describe('cache operations route', () => {
  it('lazy-loads the authenticated tenant workflow with shell metadata', async () => {
    const actor = principal({ permissions: ['sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [] }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))

    renderWithProviders(<AppRoutes />, ['/site/cache-clean'])

    expect(await screen.findByRole('heading', { name: '刷新预热' }, { timeout: 5_000 })).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/网站管理/刷新预热')
  })
})
