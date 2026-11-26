import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { brandAssetApi } from '../api/brandAsset'
import { systemSettingsApi, type PlatformSystemSettingsDocument } from '../api/systemSettings'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import SystemGlobalSettingsPage from '../pages/SystemGlobalSettingsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const initial: PlatformSystemSettingsDocument = {
  schema: 'cdnca.platform-system-settings/v1',
  revision: 3,
  value: {
    system_name: 'CDNCA', user_title: '用户', admin_title: '管理员', footer_links: '', footer_text: '', global_js: '', bound_domains: '',
    expiry_close: false, traffic_close: false, allow_upgrade: true, allow_downgrade: false, maintenance: false,
    maintenance_message: '', auto_upgrade_node: false,
  },
}

describe('SystemGlobalSettingsPage collapsed tabs button', () => {
  it('names the overflow tabs button instead of exposing the icon name "ellipsis"', async () => {
    await changeLocale('zh-CN')
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'],
      permissions: ['system_configuration.read'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(systemSettingsApi, 'get').mockResolvedValue(initial)
    vi.spyOn(brandAssetApi, 'list').mockResolvedValue({ schema: 'cdnca.platform-brand-asset/v1', assets: [] })
    renderWithProviders(<SystemGlobalSettingsPage />)

    await screen.findAllByRole('tab', { hidden: true })
    // jsdom has no layout, so no tab overflows and antd keeps the button at visibility: hidden.
    // Show it as it is when the tabs overflow on a narrow screen, then read its accessible name.
    const more = document.querySelector<HTMLButtonElement>('.ant-tabs-nav-more')!
    more.style.visibility = 'visible'
    expect(screen.getByRole('button', { name: '更多配置标签' })).toBe(more)
    expect(screen.queryByRole('button', { name: 'ellipsis' })).toBeNull()
  })
})
