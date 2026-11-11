import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../../api/auth'
import { sitesApi, type SiteDetail } from '../../api/sites'
import i18n from '../../i18n'
import '../../i18n/siteEdgeOptions'
import { renderWithProviders } from '../../test/render'
import ServerTimingSwitch from './ServerTimingSwitch'

function site(serverTiming: boolean | undefined, version = 4): SiteDetail {
  return {
    id: 'site-1', version,
    basic: { domains: ['www.example.com'], ipv6_enabled: false, tls_protocols: ['TLSv1.2', 'TLSv1.3'], server_timing: serverTiming },
  } as unknown as SiteDetail
}

// 高级设置 → 性能与协议
// 「Server-Timing 响应头」, saved on its own through the site PATCH.
describe('ServerTimingSwitch', () => {
  afterEach(() => vi.restoreAllMocks())

  it('shows the label, the brief as its description and the server default (off when omitted)', async () => {
    await i18n.changeLanguage('zh-CN')
    renderWithProviders(<ServerTimingSwitch detail={site(undefined)} accessToken="t" disabled={false} onSaved={() => undefined} />)
    const toggle = screen.getByRole('switch', { name: 'Server-Timing 响应头' })
    expect(toggle).toHaveAttribute('aria-checked', 'false')
    expect(toggle).toHaveAccessibleDescription('在响应里加上缓存状态、命中的缓存层、回源建连和首包耗时，方便在浏览器开发者工具里排查。默认关闭')
  })

  it('saves server_timing through the site PATCH with the saved basic', async () => {
    await i18n.changeLanguage('zh-CN')
    const saved = site(true, 5)
    const patch = vi.spyOn(sitesApi, 'patchBasic').mockResolvedValue(saved)
    const onSaved = vi.fn()
    renderWithProviders(<ServerTimingSwitch detail={site(false)} accessToken="t" disabled={false} onSaved={onSaved} />)
    await userEvent.click(screen.getByRole('switch'))
    await waitFor(() => expect(onSaved).toHaveBeenCalledWith(saved))
    expect(patch).toHaveBeenCalledWith('t', 'site-1', {
      expected_version: 4, section: 'basic',
      changes: expect.objectContaining({ domains: ['www.example.com'], server_timing: true }),
    }, expect.any(String))
    expect(await screen.findByText('已保存，下次发布后生效')).toBeInTheDocument()
  })

  it('reports a failed save with the feedback dialog and keeps the stored value', async () => {
    await i18n.changeLanguage('zh-CN')
    vi.spyOn(sitesApi, 'patchBasic').mockRejectedValue(new ApiError('conflict', 409, 'version_conflict'))
    const onSaved = vi.fn()
    renderWithProviders(<ServerTimingSwitch detail={site(false)} accessToken="t" disabled={false} onSaved={onSaved} />)
    await userEvent.click(screen.getByRole('switch'))
    expect(await screen.findByText('Server-Timing 响应头保存失败')).toBeInTheDocument()
    expect(screen.getByText('网站配置已被其他操作修改，请刷新页面后重试。')).toBeInTheDocument()
    expect(onSaved).not.toHaveBeenCalled()
    expect(screen.getByRole('switch')).toHaveAttribute('aria-checked', 'false')
  })

  it('is read-only when disabled', async () => {
    await i18n.changeLanguage('zh-CN')
    renderWithProviders(<ServerTimingSwitch detail={site(true)} accessToken="t" disabled onSaved={() => undefined} />)
    const toggle = screen.getByRole('switch')
    expect(toggle).toBeDisabled()
    expect(toggle).toHaveAttribute('aria-checked', 'true')
  })

  it('has the English wording', async () => {
    await i18n.changeLanguage('en-US')
    renderWithProviders(<ServerTimingSwitch detail={site(false)} accessToken="t" disabled={false} onSaved={() => undefined} />)
    expect(screen.getByRole('switch', { name: 'Server-Timing header' })).toHaveAccessibleDescription(
      'Adds the cache status, the cache layer that served the response, and the origin connect and first-byte times, for debugging in browser developer tools. Off by default.')
    await i18n.changeLanguage('zh-CN')
  })
})
