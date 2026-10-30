import { screen } from '@testing-library/react'
import { vi } from 'vitest'

import { AppRoutes } from '../App'
import * as runtimeFeaturesApi from '../api/runtimeFeatures'
import { cnameAllocationsApi } from '../api/cnameAllocations'
import { originAuthCredentialsApi } from '../api/originAuthCredentials'
import { originAuthPublicationsApi } from '../api/originAuthPublications'
import { originAuthRulesApi } from '../api/originAuthRules'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const tenantScopeID = '22222222-2222-4222-8222-222222222222'

function setTenant(permissions: string[]) {
  const actor = principal({ permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

describe('Batch K/L routes', () => {
  it('loads tenant CNAME allocation authority behind dns.read', async () => {
    setTenant(['dns.read'])
    vi.spyOn(cnameAllocationsApi, 'list').mockImplementation(() => new Promise<never>(() => undefined))

    renderWithProviders(<AppRoutes />, ['/site/cname-allocations'])

    expect(await screen.findByRole('heading', { name: 'CNAME 分配权威' })).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/网站管理/CNAME 分配权威')
  })

  it('loads platform CNAME allocation authority with an explicit tenant scope', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'],
      permissions: ['platform.admin'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(cnameAllocationsApi, 'list').mockImplementation(() => new Promise<never>(() => undefined))

    renderWithProviders(<AppRoutes />, [`/node/cname-allocations?scope_id=${tenantScopeID}`])

    expect(await screen.findByRole('heading', { name: 'CNAME 分配权威' })).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/节点管理/CNAME 分配权威')
  })

  it.each([
    ['/site/origin-auth/credentials', '源站鉴权凭据', 'credentials'],
    ['/site/origin-auth/rules', '源站鉴权规则', 'rules'],
    ['/site/origin-auth/publications', '回源鉴权发布', 'publications'],
  ] as const)('loads %s behind origin_auth.read', async (path, heading, kind) => {
    setTenant(['origin_auth.read'])
    // fix-e1 #2: the pages sit behind the origin_auth runtime flag.
    vi.spyOn(runtimeFeaturesApi, 'fetchRuntimeFeatures').mockResolvedValue(['origin_auth'])
    if (kind === 'credentials') {
      vi.spyOn(originAuthCredentialsApi, 'list').mockImplementation(() => new Promise<never>(() => undefined))
    } else if (kind === 'rules') {
      vi.spyOn(originAuthRulesApi, 'list').mockImplementation(() => new Promise<never>(() => undefined))
    } else {
      vi.spyOn(originAuthPublicationsApi, 'getLatest').mockImplementation(() => new Promise<never>(() => undefined))
    }

    renderWithProviders(<AppRoutes />, [path])

    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument()
    expect(screen.getByLabelText('面包屑')).toHaveTextContent(`首页/网站管理/${heading}`)
  })

  it('denies both domains locally before any API request', async () => {
    setTenant([])
    const cnameSpy = vi.spyOn(cnameAllocationsApi, 'list')
    const credentialsSpy = vi.spyOn(originAuthCredentialsApi, 'list')

    const cname = renderWithProviders(<AppRoutes />, ['/site/cname-allocations'])
    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(cnameSpy).not.toHaveBeenCalled()
    cname.unmount()

    renderWithProviders(<AppRoutes />, ['/site/origin-auth/credentials'])
    expect(await screen.findByText('无权访问')).toBeInTheDocument()
    expect(credentialsSpy).not.toHaveBeenCalled()
  })
})
