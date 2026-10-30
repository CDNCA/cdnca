import { fireEvent, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { brandAssetApi } from '../api/brandAsset'
import { systemSettingsApi, type PlatformSystemSettingsDocument } from '../api/systemSettings'
import { useSessionStore } from '../auth/session'
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

describe('SystemGlobalSettingsPage brand asset upload (fix-feedbackui2)', () => {
  it('says a wrong file type in that asset card, not in a dialog, and uploads nothing', async () => {
    const actor = principal({
      scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'],
      permissions: ['system_configuration.read', 'system_configuration.manage'],
    })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(systemSettingsApi, 'get').mockResolvedValue(initial)
    vi.spyOn(brandAssetApi, 'list').mockResolvedValue({ schema: 'cdnca.platform-brand-asset/v1', assets: [] })
    const get = vi.spyOn(brandAssetApi, 'get')
    renderWithProviders(<SystemGlobalSettingsPage />)
    await waitFor(() => expect(document.querySelector('.system-settings-brand-asset-preview--logo')).toBeTruthy())
    const card = document.querySelector('.system-settings-brand-asset-preview--logo')!.closest('.system-settings-brand-card')!
    fireEvent.change(card.querySelector('input[type=file]')!, { target: { files: [new File(['x'], 'logo.jpg', { type: 'image/jpeg' })] } })
    const notice = await screen.findByText('文件类型或大小不符合要求', { selector: '.cdnca-inline-notice-text' })
    expect(notice.closest('.system-settings-brand-card')).toBe(card)
    expect(notice.closest('[role=alert]')).toBeInTheDocument()
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
    expect(get).not.toHaveBeenCalled()
  })
})
