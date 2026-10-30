import { fireEvent, screen, waitFor } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { fetchRuntimeFeatures, type RuntimeFeature } from '../api/runtimeFeatures'
import * as session from '../auth/session'
import { AppShell } from '../components/AppShell'
import { getNavigation, isImplementedPath } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function menuKeys(role: 'admin' | 'user', permissions: string[], runtimes: RuntimeFeature[]): string[] {
  return getNavigation(role, undefined, permissions, [], runtimes).flatMap((item) => [item.key, ...(item.children ?? []).map((child) => child.key)])
}

afterEach(() => vi.unstubAllGlobals())

// F8 fallback: a control plane that did not mount an optional runtime must not
// show a menu entry whose page would answer 404.
describe('runtime feature menu gates (GET /v1/runtime-features)', () => {
  it('hides cache and system-operation entries until their runtime is mounted', () => {
    const user = ['sites.read', 'identity.roles.manage']
    expect(menuKeys('user', user, [])).not.toContain('/site/cache-clean')
    expect(menuKeys('user', user, ['cache_control'])).toEqual(expect.arrayContaining(['/site/cache-clean']))
    // tp-b1: custom roles are no longer a tenant menu entry, even with custom_rbac mounted.
    expect(menuKeys('user', user, ['cache_control', 'custom_rbac'])).not.toContain('/account/custom-roles')
    expect(isImplementedPath('user', '/site/cache-clean/history', ['sites.read'], [], [])).toBe(false)
    expect(isImplementedPath('user', '/site/cache-clean/history', ['sites.read'], [], ['cache_control'])).toBe(true)
    // approval center: hidden while off, needs approvals.read (platform.admin alone is not enough).
    expect(isImplementedPath('admin', '/sys/approvals', ['approvals.read'], [], [])).toBe(false)
    expect(isImplementedPath('admin', '/sys/approvals', ['approvals.read'], [], ['approval_center'])).toBe(true)
    expect(isImplementedPath('admin', '/sys/approvals', ['platform.admin'], [], ['approval_center'])).toBe(false)
    // fz-x10: the 系统管理 menu entry follows the same gate.
    expect(menuKeys('admin', ['approvals.read'], [])).not.toContain('/sys/approvals')
    expect(menuKeys('admin', ['approvals.read'], ['approval_center'])).toContain('/sys/approvals')
    expect(menuKeys('admin', ['platform.admin'], ['approval_center'])).not.toContain('/sys/approvals')
    expect(menuKeys('admin', ['sites.read', 'platform.admin'], [])).not.toContain('/site/cache-clean')
  })

  // The node market and plugin store menus are hidden while the market runtime is off.
  it('hides the node market and plugin store until the market runtime is on', () => {
    const admin = ['platform.admin', 'sites.manage', 'marketplace.browse']
    expect(menuKeys('admin', admin, [])).not.toEqual(expect.arrayContaining(['/sys/node-market']))
    expect(isImplementedPath('admin', '/sys/node-market', admin, [], [])).toBe(false)
    expect(isImplementedPath('admin', '/sys/plugin-store', admin, [], [])).toBe(false)
    expect(isImplementedPath('admin', '/sys/node-market', admin, [], ['market'])).toBe(true)
    expect(isImplementedPath('admin', '/sys/plugin-store', admin, [], ['market'])).toBe(true)
  })

  it('parses only the documented boolean flags', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ features: { cache_control: true, custom_rbac: false, plugin_webhooks: false, approval_center: true, market: true, package_auto_renew: false, origin_auth: false } })))
    await expect(fetchRuntimeFeatures('token')).resolves.toEqual(['cache_control', 'approval_center', 'market'])
    vi.stubGlobal('fetch', vi.fn(async () => json({ features: { cache_control: 'yes' } })))
    await expect(fetchRuntimeFeatures('token')).rejects.toMatchObject({ code: 'response_invalid' })
  })

  it('the shell shows the cache menu only after the runtime reports it mounted', async () => {
    let mounted = false
    const fetchMock = vi.fn(async (path: string) => {
      if (path.endsWith('/v1/runtime-features')) {
        return json({ features: { cache_control: mounted, custom_rbac: false, plugin_webhooks: false, approval_center: false, market: false, package_auto_renew: false, origin_auth: false } })
      }
      if (path.endsWith('/v1/modules')) return json({ status: 'valid', lease_serial: 1, modules: [] })
      return json({ code: 'not_found' }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)
    const actor = principal({ permissions: ['sites.read'] })
    session.useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'features-token' }, actor)
    const shell = <Routes><Route element={<AppShell />}><Route path="*" element={<span />} /></Route></Routes>
    const first = renderWithProviders(shell, ['/home'])
    await waitFor(() => expect(fetchMock.mock.calls.some(([path]) => String(path).endsWith('/v1/runtime-features'))).toBe(true))
    const call = fetchMock.mock.calls.find(([path]) => String(path).endsWith('/v1/runtime-features')) as unknown as [string, RequestInit]
    expect((call[1].headers as Record<string, string>).Authorization).toBe('Bearer features-token')
    fireEvent.click(await screen.findByText('网站管理'))
    expect(await screen.findByText('网站列表')).toBeInTheDocument()
    expect(screen.queryByText('刷新预热')).not.toBeInTheDocument()
    first.unmount()

    mounted = true
    renderWithProviders(shell, ['/home'])
    fireEvent.click(await screen.findByText('网站管理'))
    expect(await screen.findByText('刷新预热')).toBeInTheDocument()
  })
})
