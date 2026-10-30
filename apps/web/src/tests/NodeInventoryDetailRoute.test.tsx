import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { AppRoutes } from '../App'
import type { Principal } from '../api/auth'
import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import { useSessionStore } from '../auth/session'
import { authResponse, nodeManagementSettingsFixture, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const nodeID = '018f0000-0000-7000-8000-000000000001'
const inventory: NodeInventoryItem = {
  id: nodeID, display_id: '1', name: '路由节点', description: '', region: 'CN-East', admin_state: 'active', revision: 4,
  management_settings: nodeManagementSettingsFixture(),
  created_at: '2026-08-01T08:00:00Z', updated_at: '2026-08-01T09:00:00Z',
  presence: { status: 'online', projection_freshness: 'fresh', lease_signal: 'present' },
}

function authenticate(permissions: string[], overrides: Partial<Principal> = {}) {
  const actor = principal({
    scope_kind: 'platform', scope_id: 'platform', tenant_id: null, roles: ['platform_owner'],
    permissions, ...overrides,
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

describe('node inventory detail route', () => {
  it.each([['nodes.read'], ['platform.admin']])('mounts for the %s permission', async (permission) => {
    authenticate([permission])
    const get = vi.spyOn(nodesApi, 'get').mockResolvedValue(inventory)

    renderWithProviders(<AppRoutes />, [`/node/list/${nodeID}`])

    expect(await screen.findByRole('heading', { name: inventory.name })).toBeInTheDocument()
    expect(get).toHaveBeenCalledWith('memory-only-access-token', nodeID)
  })

  it('denies a platform viewer without nodes.read before the page requests data', async () => {
    authenticate([])
    const get = vi.spyOn(nodesApi, 'get')

    renderWithProviders(<AppRoutes />, [`/node/list/${nodeID}`])

    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(get).not.toHaveBeenCalled()
  })

  it('keeps the node detail route unavailable to a tenant', async () => {
    authenticate(['nodes.read'], {
      scope_kind: 'tenant',
      scope_id: '22222222-2222-4222-8222-222222222222',
      tenant_id: '22222222-2222-4222-8222-222222222222',
      roles: ['tenant_owner'],
    })
    const get = vi.spyOn(nodesApi, 'get')

    renderWithProviders(<AppRoutes />, [`/node/list/${nodeID}`])

    expect(await screen.findByText('页面不存在')).toBeInTheDocument()
    expect(get).not.toHaveBeenCalled()
  })
})
