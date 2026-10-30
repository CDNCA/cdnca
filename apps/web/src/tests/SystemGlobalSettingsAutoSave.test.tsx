import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
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

function authenticate() {
  const actor = principal({
    scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'],
    permissions: ['system_configuration.read', 'system_configuration.manage'],
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise })
  return { promise, resolve }
}

describe('SystemGlobalSettingsPage auto-save', () => {
  it('saves the global JS report hosts as plain hostnames and never saves an invalid list', async () => {
    authenticate()
    vi.spyOn(systemSettingsApi, 'get').mockResolvedValue(initial)
    vi.spyOn(brandAssetApi, 'list').mockResolvedValue({ schema: 'cdnca.platform-brand-asset/v1', assets: [] })
    const put = vi.spyOn(systemSettingsApi, 'put').mockImplementation(async (_token, revision, value) => ({
      ...initial, revision: revision + 1, value,
    }))
    renderWithProviders(<SystemGlobalSettingsPage />)
    const panel = await screen.findByTestId('system-settings-baseline-system')
    const field = within(panel).getByLabelText('全站JS允许的上报/图片域名')
    fireEvent.change(field, { target: { value: 'https://hm.baidu.com' } })
    expect(await within(panel).findByText(/每行一个小写主机名/)).toBeInTheDocument()
    await new Promise((resolve) => setTimeout(resolve, 1_000))
    expect(put).not.toHaveBeenCalled()
    fireEvent.change(field, { target: { value: 'hm.baidu.com\nstats.example.com' } })
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1), { timeout: 2_000 })
    expect(put.mock.calls[0][2].global_js_report_hosts).toEqual(['hm.baidu.com', 'stats.example.com'])
    expect(within(panel).queryByText(/每行一个小写主机名/)).not.toBeInTheDocument()
  })

  it('debounces a changed system field and reports success without a save button', async () => {
    authenticate()
    vi.spyOn(systemSettingsApi, 'get').mockResolvedValue(initial)
    vi.spyOn(brandAssetApi, 'list').mockResolvedValue({ schema: 'cdnca.platform-brand-asset/v1', assets: [] })
    const put = vi.spyOn(systemSettingsApi, 'put').mockImplementation(async (_token, revision, value) => ({
      ...initial, revision: revision + 1, value,
    }))
    const user = userEvent.setup()

    renderWithProviders(<SystemGlobalSettingsPage />)
    const panel = await screen.findByTestId('system-settings-baseline-system')
    expect(within(panel).queryByRole('button', { name: '保存' })).not.toBeInTheDocument()
    const name = within(panel).getByLabelText('系统名称')
    await user.clear(name)
    await user.type(name, '自动保存平台')

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1), { timeout: 2_000 })
    expect(put).toHaveBeenCalledWith(
      'memory-only-access-token', 3,
      expect.objectContaining({ system_name: '自动保存平台' }),
      expect.any(String), expect.any(String),
    )
    expect(await within(panel).findByText('系统配置已保存')).toBeInTheDocument()
  })

  // fix-fielderr-be: a 400 naming value.system_name is shown under 系统名称, without the dialog.
  it('marks a server-refused setting under its field', async () => {
    authenticate()
    vi.spyOn(systemSettingsApi, 'get').mockResolvedValue(initial)
    vi.spyOn(brandAssetApi, 'list').mockResolvedValue({ schema: 'cdnca.platform-brand-asset/v1', assets: [] })
    vi.spyOn(systemSettingsApi, 'put').mockRejectedValue(Object.assign(
      new ApiError('API request failed', 400, 'system_settings_validation_error', 'req-sys'), { field: 'value.system_name', reason: 'too_long' }))
    const user = userEvent.setup()
    renderWithProviders(<SystemGlobalSettingsPage />)
    const panel = await screen.findByTestId('system-settings-baseline-system')
    const name = within(panel).getByLabelText('系统名称')
    await user.type(name, 'X')
    const item = (await within(panel).findByText('长度超过上限', {}, { timeout: 3_000 })).closest('.ant-form-item')
    expect(item?.textContent).toContain('系统名称')
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
  })

  it('queues a newer edit behind an in-flight save and persists the new revision', async () => {
    authenticate()
    vi.spyOn(systemSettingsApi, 'get').mockResolvedValue(initial)
    vi.spyOn(brandAssetApi, 'list').mockResolvedValue({ schema: 'cdnca.platform-brand-asset/v1', assets: [] })
    const firstSave = deferred<PlatformSystemSettingsDocument>()
    const put = vi.spyOn(systemSettingsApi, 'put')
      .mockReturnValueOnce(firstSave.promise)
      .mockImplementationOnce(async (_token, revision, value) => ({ ...initial, revision: revision + 1, value }))
    const user = userEvent.setup()

    renderWithProviders(<SystemGlobalSettingsPage />)
    const name = await screen.findByLabelText('系统名称')
    await user.clear(name)
    await user.type(name, '第一版')
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1), { timeout: 2_000 })

    await user.type(name, '更新')
    firstSave.resolve({ ...initial, revision: 4, value: put.mock.calls[0][2] })

    await waitFor(() => expect(put).toHaveBeenCalledTimes(2), { timeout: 2_000 })
    expect(put.mock.calls[1][1]).toBe(4)
    expect(put.mock.calls[1][2]).toEqual(expect.objectContaining({ system_name: '第一版更新' }))
    expect(name).toHaveValue('第一版更新')
  })

  it('flushes a pending edit before switching away from the system tab', async () => {
    authenticate()
    vi.spyOn(systemSettingsApi, 'get').mockResolvedValue(initial)
    vi.spyOn(brandAssetApi, 'list').mockResolvedValue({ schema: 'cdnca.platform-brand-asset/v1', assets: [] })
    const put = vi.spyOn(systemSettingsApi, 'put').mockImplementation(async (_token, revision, value) => ({
      ...initial, revision: revision + 1, value,
    }))
    const user = userEvent.setup()

    renderWithProviders(<SystemGlobalSettingsPage />)
    const panel = await screen.findByTestId('system-settings-baseline-system')
    const name = within(panel).getByLabelText('系统名称')
    await user.clear(name)
    await user.type(name, '切换前保存')
    await user.click(screen.getByRole('tab', { name: '数据清理' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1), { timeout: 2_000 })
    expect(put).toHaveBeenCalledWith(
      'memory-only-access-token', 3,
      expect.objectContaining({ system_name: '切换前保存' }),
      expect.any(String), expect.any(String),
    )
    expect(await screen.findByText('系统配置已保存')).toBeInTheDocument()
  })

  it('flushes an edit when switching tabs in the same event batch', async () => {
    authenticate()
    vi.spyOn(systemSettingsApi, 'get').mockResolvedValue(initial)
    vi.spyOn(brandAssetApi, 'list').mockResolvedValue({ schema: 'cdnca.platform-brand-asset/v1', assets: [] })
    const put = vi.spyOn(systemSettingsApi, 'put').mockImplementation(async (_token, revision, value) => ({
      ...initial, revision: revision + 1, value,
    }))

    renderWithProviders(<SystemGlobalSettingsPage />)
    const panel = await screen.findByTestId('system-settings-baseline-system')
    const name = within(panel).getByLabelText('系统名称')
    const cleanupTab = screen.getByRole('tab', { name: '数据清理' })

    act(() => {
      fireEvent.change(name, { target: { value: '同批次切换保存' } })
      fireEvent.click(cleanupTab)
    })

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1), { timeout: 2_000 })
    expect(put).toHaveBeenCalledWith(
      'memory-only-access-token', 3,
      expect.objectContaining({ system_name: '同批次切换保存' }),
      expect.any(String), expect.any(String),
    )
  })
})
