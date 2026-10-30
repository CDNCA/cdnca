import { afterEach, describe, expect, it, vi } from 'vitest'

import { fetchGrantedModules } from '../api/modules'
import {
  getNavigation,
  hasRoutePermission,
  localizeNavigation,
  type NavigationDefinition,
} from '../routes/navigation'

const probe = 'module.pa15_probe'
const identity = (key: string) => key

const definitions: NavigationDefinition[] = [
  {
    key: 'system',
    labelKey: 'system',
    children: [
      { key: '/sys/setting', labelKey: 'settings', requiredPermission: 'system_configuration.read' },
      { key: '/sys/probe', labelKey: 'probe', requiredModule: probe, requiredPermission: 'system_configuration.read' },
    ],
  },
  { key: '/probe-only', labelKey: 'probeOnly', requiredModule: probe },
  {
    key: 'probe-group',
    labelKey: 'probeGroup',
    children: [{ key: '/probe-group/a', labelKey: 'a', requiredModule: probe }],
  },
]

const keys = (modules?: readonly string[], permissions?: readonly string[]) =>
  localizeNavigation(definitions, identity, permissions, modules)
    .flatMap((item) => [item.key, ...(item.children ?? []).map((child) => child.key)])

describe('requiredModule navigation (PA-15)', () => {
  it('hides module items when the module is not granted and shows them when it is', () => {
    expect(keys(['pack.crs'])).toEqual(['system', '/sys/setting'])
    expect(keys([probe])).toEqual(['system', '/sys/setting', '/sys/probe', '/probe-only', 'probe-group', '/probe-group/a'])
    // Revoking the module removes the items again; re-granting restores them.
    expect(keys([])).toEqual(['system', '/sys/setting'])
    expect(keys([probe])).toContain('/sys/probe')
  })

  it('treats unloaded modules as none granted (fail closed)', () => {
    expect(keys(undefined)).toEqual(['system', '/sys/setting'])
  })

  it('applies module and permission requirements together without a platform-admin fallback for modules', () => {
    expect(keys([probe], [])).toEqual(['/probe-only', 'probe-group', '/probe-group/a'])
    expect(keys([probe], ['platform.admin'])).toContain('/sys/probe')
    expect(keys([], ['platform.admin'])).toEqual(['system', '/sys/setting'])
    expect(hasRoutePermission({ requiredModule: probe }, ['platform.admin'], [])).toBe(false)
    expect(hasRoutePermission({ requiredModule: probe }, ['platform.admin'], [probe])).toBe(true)
    expect(hasRoutePermission({ requiredModule: probe, requiredPermission: 'x.read' }, [], [probe])).toBe(false)
  })

  it('leaves ungated navigation unchanged', () => {
    for (const role of ['admin', 'user'] as const) {
      expect(getNavigation(role, identity, undefined, [])).toEqual(getNavigation(role, identity))
    }
  })
})

describe('fetchGrantedModules', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('reads GET /v1/modules with the bearer token', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      status: 'valid', lease_serial: 3, modules: [probe, 'pack.crs'],
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    await expect(fetchGrantedModules('token-1')).resolves.toEqual({
      status: 'valid', lease_serial: 3, modules: [probe, 'pack.crs'],
    })
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(url.endsWith('/v1/modules')).toBe(true)
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer token-1')
  })

  it('rejects malformed bodies and non-module codes', async () => {
    for (const body of [{ status: 'valid', lease_serial: 1, modules: ['sites.manage'] }, { status: 'valid' }]) {
      vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(body), { status: 200 })))
      await expect(fetchGrantedModules('token')).rejects.toMatchObject({ code: 'response_invalid' })
    }
  })

  it('surfaces API errors and refuses without a token', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      error: { code: 'authentication_required', message: 'm', request_id: '00000000-0000-4000-8000-000000000000' },
    }), { status: 401 })))
    await expect(fetchGrantedModules('token')).rejects.toMatchObject({ status: 401, code: 'authentication_required' })
    await expect(fetchGrantedModules('')).rejects.toMatchObject({ status: 401 })
  })
})
