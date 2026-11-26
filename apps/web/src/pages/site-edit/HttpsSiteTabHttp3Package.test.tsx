import { useState } from 'react'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../../api/auth'
import { certificatesApi } from '../../api/certificates'
import type { SiteBasicConfig } from '../../api/sites'
import i18n from '../../i18n'
import { renderWithProviders } from '../../test/render'
import HttpsSiteTab from './HttpsSiteTab'

const scopeID = '22222222-2222-4222-8222-222222222222'
const siteID = '33333333-3333-4333-8333-333333333333'

const httpsConfig: SiteBasicConfig = {
  package_id: null,
  package_name: null,
  group_id: null,
  group_name: null,
  domains: ['www.example.com'],
  http_enabled: true,
  http_listen_ports: ['80'],
  https_listen_ports: ['443'],
  ipv6_enabled: false,
  tls_protocols: ['TLSv1.2', 'TLSv1.3'],
  origins: ['192.0.2.10:80'],
  cname: 'edge.example.com',
  https_enabled: true,
  enabled: true,
  status: 'active',
  sync_status: 'synced',
  is_default: false,
}

function Recorder({ initial, changes }: { initial: SiteBasicConfig; changes: SiteBasicConfig[] }) {
  const [value, setValue] = useState(initial)
  return (
    <HttpsSiteTab
      siteId={siteID} siteScopeId={scopeID} accessToken="certificate-token" scopeKind="tenant"
      principalScopeId={scopeID} permissions={['certificates.read']} sessionEpoch={1}
      value={value} errors={{}} readOnly={false}
      onChange={(next) => { changes.push(next); setValue(next) }}
    />
  )
}

// the site's current package leaves HTTP/3
// out (basic.http3_unavailable_reason): the switch shows off and is disabled,
// the summary does not say on, and the row names the state with the way to
// the package. http3_enabled (the saved choice) is never changed by the page.
describe('HttpsSiteTab HTTP/3 and the site package', () => {
  beforeEach(async () => {
    vi.restoreAllMocks()
    await i18n.changeLanguage('zh-CN')
    vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [], total: 0 })
    vi.spyOn(certificatesApi, 'getSiteBinding').mockRejectedValue(
      new ApiError('API request failed', 404, 'certificate_site_binding_not_found'))
  })

  it('shows HTTP/3 off and disabled when the package leaves it out, keeping the saved choice', async () => {
    const changes: SiteBasicConfig[] = []
    const user = userEvent.setup()
    renderWithProviders(<Recorder changes={changes} initial={{
      ...httpsConfig, http3_enabled: true, http3_effective: false, http3_unavailable_reason: 'package_feature_denied',
    }} />)

    const http3 = screen.getByRole('switch', { name: 'HTTP/3' })
    expect(http3).not.toBeChecked()
    expect(http3).toBeDisabled()
    expect(http3).toHaveAttribute('aria-checked', 'false')
    expect(http3).toHaveAccessibleDescription(/当前套餐不含 HTTP\/3/u)
    const note = screen.getByTestId('site-https-http3-package')
    expect(note).toHaveTextContent('当前套餐不含 HTTP/3')
    // 社区版没有套餐购买页：只说明，不给去管理套餐的链接。
    expect(screen.queryByRole('link', { name: '管理套餐' })).not.toBeInTheDocument()

    const summary = screen.getByTitle('跳到HTTP/3')
    expect(summary).toHaveTextContent('已关闭')
    expect(summary).not.toHaveTextContent('已开启')

    await user.click(http3)
    expect(changes).toHaveLength(0)
  })

  it('keeps HTTP/3 editable and on when the package allows it', async () => {
    const changes: SiteBasicConfig[] = []
    const user = userEvent.setup()
    renderWithProviders(<Recorder changes={changes} initial={{ ...httpsConfig, http3_enabled: true, http3_effective: true }} />)

    const http3 = screen.getByRole('switch', { name: 'HTTP/3' })
    expect(http3).toBeChecked()
    expect(http3).toBeEnabled()
    expect(screen.queryByTestId('site-https-http3-package')).toBeNull()
    expect(screen.queryByRole('link', { name: '管理套餐' })).toBeNull()
    expect(screen.getByTitle('跳到HTTP/3')).toHaveTextContent('已开启')

    await user.click(http3)
    expect(changes.at(-1)?.http3_enabled).toBe(false)
    expect(screen.getByTitle('跳到HTTP/3')).toHaveTextContent('已关闭')
  })
})
