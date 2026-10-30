import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { brandAssetApi } from '../api/brandAsset'
import { systemSettingsApi, type PlatformSystemSettingsDocument } from '../api/systemSettings'
import { useSessionStore } from '../auth/session'
import SystemGlobalSettingsPage from '../pages/SystemGlobalSettingsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// MC01/B01（Codex 双角色审测 10-27）：保存在途时不能用普通刷新丢掉写入；结果未知只能原样重试或明确放弃；
// 已有草稿后的刷新失败保留草稿与原修订。

const initial: PlatformSystemSettingsDocument = {
  schema: 'cdnca.platform-system-settings/v1', revision: 3,
  value: { system_name: 'CDNCA', user_title: '用户', admin_title: '管理员', footer_links: '', footer_text: '', global_js: '', bound_domains: '',
    expiry_close: false, traffic_close: false, allow_upgrade: true, allow_downgrade: false, maintenance: false,
    maintenance_message: '', auto_upgrade_node: false },
}

function authenticate() {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['system_configuration.read', 'system_configuration.manage'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

describe('MC01/B01 系统设置刷新与在途写入', () => {
  it('a sent write disables refresh; its late unknown outcome keeps the exact retry, which resends the same request', async () => {
    authenticate()
    const get = vi.spyOn(systemSettingsApi, 'get').mockResolvedValue(initial)
    vi.spyOn(brandAssetApi, 'list').mockResolvedValue({ schema: 'cdnca.platform-brand-asset/v1', assets: [] })
    let rejectWrite!: (reason: unknown) => void
    const pending = new Promise<PlatformSystemSettingsDocument>((_, reject) => { rejectWrite = reject })
    const put = vi.spyOn(systemSettingsApi, 'put').mockReturnValueOnce(pending)
      .mockImplementationOnce(async (_token, revision, value) => ({ ...initial, revision: revision + 1, value }))
    renderWithProviders(<SystemGlobalSettingsPage />)
    const panel = await screen.findByTestId('system-settings-baseline-system')
    fireEvent.change(within(panel).getByLabelText('系统名称'), { target: { value: '待确认的新设置' } })
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1), { timeout: 3000 })
    const refresh = within(panel).getByRole('button', { name: '刷新' })
    expect(refresh).toBeDisabled()
    fireEvent.click(refresh)
    expect(get).toHaveBeenCalledTimes(1)
    await act(async () => { rejectWrite(new ApiError('lost response', 503, 'system_settings_unavailable')); await pending.catch(() => undefined) })
    expect(await within(panel).findByText('保存结果待确认')).toBeInTheDocument()
    expect(within(panel).getByLabelText('系统名称')).toHaveValue('待确认的新设置')
    // unknown outcome: plain refresh stays off; only the exact retry or the explicit abandonment
    expect(within(panel).getByRole('button', { name: '刷新' })).toBeDisabled()
    // OutcomeUnknown 弹窗打开时恢复按钮在弹窗里（f3f426931 起），关闭后回到面板旁的恢复条
    fireEvent.click(await screen.findByRole('button', { name: '知道了' }))
    fireEvent.click(await within(panel).findByRole('button', { name: /使用同一请求重试/ }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(2))
    const [first, second] = put.mock.calls
    expect(second![1]).toBe(first![1])
    expect(second![2]).toEqual(first![2])
    expect([second![3], second![4]]).toEqual([first![3], first![4]])
  })

  it('a failed refresh keeps the draft and the revision it was based on', async () => {
    authenticate()
    const get = vi.spyOn(systemSettingsApi, 'get').mockResolvedValueOnce(initial)
      .mockRejectedValueOnce(new ApiError('unavailable', 503, 'system_settings_unavailable'))
    vi.spyOn(brandAssetApi, 'list').mockResolvedValue({ schema: 'cdnca.platform-brand-asset/v1', assets: [] })
    const put = vi.spyOn(systemSettingsApi, 'put').mockRejectedValue(new ApiError('conflict', 409, 'system_settings_revision_conflict'))
    renderWithProviders(<SystemGlobalSettingsPage />)
    const panel = await screen.findByTestId('system-settings-baseline-system')
    fireEvent.change(within(panel).getByLabelText('系统名称'), { target: { value: '本地草稿' } })
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1), { timeout: 3000 })
    await waitFor(() => expect(within(panel).getByRole('button', { name: '刷新' })).toBeEnabled())
    fireEvent.click(within(panel).getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
    expect(await screen.findByText(/刷新失败/)).toBeInTheDocument()
    expect(within(panel).getByLabelText('系统名称')).toHaveValue('本地草稿')
    expect(within(panel).getByText(/修订版本|revision/i).parentElement).toHaveTextContent('3')
  })
})
