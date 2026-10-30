import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it } from 'vitest'

import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import type { RuntimeFeature } from '../api/runtimeFeatures'
import { runtimeFeaturesQueryKey } from './useRuntimeFeatures'
import { PurchaseModuleLink, purchasePath } from './PurchaseModuleLink'

function signIn(permissions: string[], scope: 'platform' | 'tenant' = 'platform') {
  const p = principal({ scope_kind: scope, tenant_id: scope === 'platform' ? null : 't1', roles: ['custom'], permissions })
  useSessionStore.getState().setSession({ ...authResponse(p), access_token: 'token' }, p)
}

beforeEach(async () => { await changeLocale('zh-CN') })

describe('PurchaseModuleLink', () => {
  it('links to the plugin store filtered by the feature code', () => {
    expect(purchasePath('module.autodefense.auto')).toBe('/sys/plugin-store?feature=module.autodefense.auto')
    signIn(['marketplace.browse'])
    renderWithProviders(<PurchaseModuleLink featureCode="module.autodefense.auto" />)
    expect(screen.getByRole('link')).toHaveAttribute('href', '/sys/plugin-store?feature=module.autodefense.auto')
    expect(screen.getByRole('button', { name: '去购买' })).toBeInTheDocument()
  })

  it('is hidden without marketplace access', () => {
    signIn(['security_policies.read'], 'tenant')
    renderWithProviders(<PurchaseModuleLink featureCode="module.aggregated_edge" />)
    expect(screen.queryByRole('link')).toBeNull()
  })

  // No "去购买" entry while the market runtime is off; shown once it is on.
  it('follows the market runtime flag', () => {
    signIn(['marketplace.browse'])
    const renderWith = (features: RuntimeFeature[]) => {
      const client = new QueryClient()
      client.setQueryData(runtimeFeaturesQueryKey, features)
      return render(<QueryClientProvider client={client}><MemoryRouter>
        <PurchaseModuleLink featureCode="module.autodefense.auto" /></MemoryRouter></QueryClientProvider>)
    }
    const off = renderWith([])
    expect(screen.queryByRole('link')).toBeNull()
    off.unmount()
    renderWith(['market'])
    expect(screen.getByRole('link')).toHaveAttribute('href', '/sys/plugin-store?feature=module.autodefense.auto')
  })
})
