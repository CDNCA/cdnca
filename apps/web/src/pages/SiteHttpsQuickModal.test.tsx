import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { certificatesApi } from '../api/certificates'
import { sitesApi, type SiteDetail, type SiteListItem } from '../api/sites'
import i18n from '../i18n'
import { renderWithProviders } from '../test/render'
import SiteHttpsQuickModal from './SiteHttpsQuickModal'

const siteID = '33333333-3333-4333-8333-333333333333'
const detail = {
  id: siteID,
  version: 4,
  https_certificate_bound: true,
  basic: {
    domains: ['tenant.example.com'], http_enabled: true, http_listen_ports: ['80'], https_listen_ports: [],
    tls_protocols: ['TLSv1.2', 'TLSv1.3'], origins: ['192.0.2.10:80'], https_enabled: false,
  },
} as unknown as SiteDetail
const site = { id: siteID, domain: 'tenant.example.com', domains: ['tenant.example.com'] } as unknown as SiteListItem

function renderModal() {
  return renderWithProviders(
    <SiteHttpsQuickModal site={site} accessToken="site-token" platform={false} onClose={vi.fn()} onSaved={vi.fn()} />,
  )
}

// a site with HTTPS off keeps no HTTPS port; turning it on here sends 443
// and a refusal shows the field reason instead of 「API request failed」.
describe('SiteHttpsQuickModal', () => {
  beforeEach(async () => {
    vi.restoreAllMocks()
    await i18n.changeLanguage('zh-CN')
    vi.spyOn(sitesApi, 'detail').mockResolvedValue(detail)
    vi.spyOn(certificatesApi, 'getSiteBinding').mockResolvedValue({} as never)
  })

  it('turns HTTPS on with the default port 443 when the site has no HTTPS port', async () => {
    const patch = vi.spyOn(sitesApi, 'patchBasic').mockResolvedValue(detail)
    renderModal()
    expect(await screen.findByText(/监听端口 443/)).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: '开启' }))
    await waitFor(() => expect(patch).toHaveBeenCalledTimes(1))
    expect(patch.mock.calls[0][2]).toMatchObject({
      expected_version: 4,
      section: 'basic',
      changes: { https_enabled: true, https_listen_ports: ['443'] },
    })
  })

  it('shows the server field reason when the write is refused', async () => {
    vi.spyOn(sitesApi, 'patchBasic').mockRejectedValue(Object.assign(
      new ApiError('API request failed', 400, 'validation_error'), { field: 'https_listen_ports', reason: 'overlaps_http' }))
    renderModal()
    await userEvent.setup().click(await screen.findByRole('button', { name: '开启' }))
    expect(await screen.findByText(/开启失败：HTTPS 端口不正确/)).toBeInTheDocument()
    expect(screen.queryByText(/API request failed/)).toBeNull()
  })
})
