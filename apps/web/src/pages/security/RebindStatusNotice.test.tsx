import { screen, waitFor } from '@testing-library/react'
import { vi } from 'vitest'

import { securityPoliciesApi } from '../../api/securityPolicies'
import { renderWithProviders } from '../../test/render'
import RebindStatusNotice from './RebindStatusNotice'

describe('RebindStatusNotice', () => {
  afterEach(() => vi.restoreAllMocks())

  it('shows how many sites were not published because the package lacks the feature', async () => {
    const status = vi.spyOn(securityPoliciesApi, 'getRebindStatus')
      .mockResolvedValue({ pending_sites: 5, package_denied_sites: 2 })
    renderWithProviders(<RebindStatusNotice accessToken="token" kind="cc" cacheKey="scope:1" />)
    expect(await screen.findByRole('status')).toHaveTextContent('2 个站点因套餐未开通未下发')
    expect(status).toHaveBeenCalledWith('token', 'cc', expect.anything())
  })

  it('shows nothing when every stale site is being published', async () => {
    const status = vi.spyOn(securityPoliciesApi, 'getRebindStatus')
      .mockResolvedValue({ pending_sites: 3, package_denied_sites: 0 })
    renderWithProviders(<RebindStatusNotice accessToken="token" kind="waf" cacheKey="scope:1" />)
    await waitFor(() => expect(status).toHaveBeenCalled())
    expect(screen.queryByRole('status')).toBeNull()
  })
})
