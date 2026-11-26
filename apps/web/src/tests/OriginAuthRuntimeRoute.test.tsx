import { screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const mounted = vi.hoisted(() => vi.fn())

vi.mock('../pages/OriginAuthCredentialsPage', () => ({
  default: () => { mounted('credentials'); return <h1>credentials-mounted</h1> },
}))
vi.mock('../pages/OriginAuthRulesPage', () => ({
  default: () => { mounted('rules'); return <h1>rules-mounted</h1> },
}))
vi.mock('../pages/OriginAuthPublicationsPage', () => ({
  default: () => { mounted('publications'); return <h1>publications-mounted</h1> },
}))

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function stubOriginAuth(on: boolean) {
  vi.stubGlobal('fetch', vi.fn(async (path: string) => {
    if (String(path).endsWith('/v1/runtime-features')) {
      return json({ features: { cache_control: false, custom_rbac: false, plugin_webhooks: false, approval_center: false, market: false, package_auto_renew: false, origin_auth: on } })
    }
    if (String(path).endsWith('/v1/modules')) return json({ status: 'valid', lease_serial: 1, modules: [] })
    return json({ code: 'not_found' }, 404)
  }))
}

function signInTenant() {
  const actor = principal({ permissions: ['origin_auth.read', 'sites.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

afterEach(() => {
  vi.unstubAllGlobals()
  mounted.mockReset()
})

// fix-e1 #2: with ORIGIN_AUTH_RUNTIME_ENABLED off the pages said "credential
// not found in this tenant"; now they say the feature is off.
// the tenant sees no host recipe, only who to ask and one
// link back to the site list.
describe('origin authentication routes follow the origin_auth runtime', () => {
  for (const page of ['credentials', 'rules', 'publications']) {
    const path = `/site/origin-auth/${page}`
    it(`${path} shows "feature not enabled" and the way back to the site list while off`, async () => {
      stubOriginAuth(false)
      signInTenant()
      renderWithProviders(<AppRoutes />, [path])
      expect(await screen.findByRole('heading', { name: '功能未启用', level: 1 })).toBeInTheDocument()
      expect(screen.getByText('平台尚未启用源站鉴权，请联系平台管理员。')).toBeInTheDocument()
      expect(screen.queryByText(/ORIGIN_AUTH_RUNTIME_ENABLED|control\.env|control-api/)).not.toBeInTheDocument()
      const back = screen.getByRole('link', { name: '返回网站列表' })
      expect(back).toHaveAttribute('href', '/site/list')
      expect(back.querySelector('button')).toBeNull()
      expect(mounted).not.toHaveBeenCalled()
    })

    it(`${path} mounts the page once origin_auth is on`, async () => {
      stubOriginAuth(true)
      signInTenant()
      renderWithProviders(<AppRoutes />, [path])
      expect(await screen.findByText(`${page}-mounted`)).toBeInTheDocument()
    })
  }
})
