import { screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const mounted = vi.hoisted(() => vi.fn())

vi.mock('../pages/node-market/NodeMarketPage', () => ({
  default: () => {
    mounted('node-market')
    return <h1>node-market-mounted</h1>
  },
}))

vi.mock('../pages/market/MarketStorePage', () => ({
  default: () => {
    mounted('plugin-store')
    return <h1>plugin-store-mounted</h1>
  },
}))

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function stubMarket(on: boolean) {
  vi.stubGlobal('fetch', vi.fn(async (path: string) => {
    if (String(path).endsWith('/v1/runtime-features')) {
      return json({ features: { cache_control: false, custom_rbac: false, plugin_webhooks: false, approval_center: false, market: on, package_auto_renew: false, origin_auth: false } })
    }
    if (String(path).endsWith('/v1/modules')) return json({ status: 'valid', lease_serial: 1, modules: [] })
    return json({ code: 'not_found' }, 404)
  }))
}

function signInPlatformAdmin() {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin', 'marketplace.browse'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

afterEach(() => {
  vi.unstubAllGlobals()
  mounted.mockReset()
})

// With the market runtime off a typed URL lands on
// "feature not enabled" (like /sys/approvals), never on the page.
describe('market routes follow the market runtime', () => {
  for (const path of ['/sys/node-market', '/sys/plugin-store']) {
    it(`${path} shows "feature not enabled" and never mounts the page while market is off`, async () => {
      stubMarket(false)
      signInPlatformAdmin()
      renderWithProviders(<AppRoutes />, [path])
      expect(await screen.findByText('功能未启用')).toBeInTheDocument()
      expect(mounted).not.toHaveBeenCalled()
    })

    it(`${path} mounts the page once market is on`, async () => {
      stubMarket(true)
      signInPlatformAdmin()
      renderWithProviders(<AppRoutes />, [path])
      expect(await screen.findByText(`${path.slice(5)}-mounted`)).toBeInTheDocument()
    })
  }
})
