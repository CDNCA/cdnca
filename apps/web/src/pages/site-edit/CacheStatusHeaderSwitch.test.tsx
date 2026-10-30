import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../../api/auth'
import { sitesApi, type SiteDetail } from '../../api/sites'
import i18n from '../../i18n'
import '../../i18n/cachePolicy'
import { renderWithProviders } from '../../test/render'
import CacheStatusHeaderSwitch from './CacheStatusHeaderSwitch'

function site(cacheStatusHeader: boolean | undefined, version = 4): SiteDetail {
  return {
    id: 'site-1', version,
    basic: { domains: ['www.example.com'], ipv6_enabled: false, tls_protocols: ['TLSv1.2', 'TLSv1.3'], cache_status_header: cacheStatusHeader },
  } as unknown as SiteDetail
}

describe('CacheStatusHeaderSwitch', () => {
  afterEach(() => vi.restoreAllMocks())

  it('shows the label, help and the server default (on when omitted)', async () => {
    await i18n.changeLanguage('zh-CN')
    renderWithProviders(<CacheStatusHeaderSwitch detail={site(undefined)} accessToken="t" disabled={false} onSaved={() => undefined} />)
    const toggle = screen.getByRole('switch', { name: '响应头显示缓存状态（X-CDN-Cache）' })
    expect(toggle).toHaveAttribute('aria-checked', 'true')
    expect(toggle).toHaveAttribute('aria-label', '响应头显示缓存状态（X-CDN-Cache）')
    expect(toggle).toHaveAccessibleDescription('便于在浏览器或 curl 中确认缓存是否生效；攻击升级到 B 级及以上时自动隐藏')
  })

  it('saves cache_status_header through the site PATCH with the saved basic', async () => {
    await i18n.changeLanguage('zh-CN')
    const saved = site(false, 5)
    const patch = vi.spyOn(sitesApi, 'patchBasic').mockResolvedValue(saved)
    const onSaved = vi.fn()
    renderWithProviders(<CacheStatusHeaderSwitch detail={site(true)} accessToken="t" disabled={false} onSaved={onSaved} />)
    await userEvent.click(screen.getByRole('switch'))
    await waitFor(() => expect(onSaved).toHaveBeenCalledWith(saved))
    expect(patch).toHaveBeenCalledWith('t', 'site-1', {
      expected_version: 4, section: 'basic',
      changes: expect.objectContaining({ domains: ['www.example.com'], cache_status_header: false }),
    }, expect.any(String))
  })

  it('reports a failed save with the feedback dialog and keeps the stored value', async () => {
    await i18n.changeLanguage('zh-CN')
    vi.spyOn(sitesApi, 'patchBasic').mockRejectedValue(new ApiError('conflict', 409, 'version_conflict'))
    const onSaved = vi.fn()
    renderWithProviders(<CacheStatusHeaderSwitch detail={site(true)} accessToken="t" disabled={false} onSaved={onSaved} />)
    await userEvent.click(screen.getByRole('switch'))
    expect(await screen.findByText('响应头显示缓存状态保存失败')).toBeInTheDocument()
    expect(screen.getByText('网站配置已被其他操作修改，请刷新页面后重试。')).toBeInTheDocument()
    expect(onSaved).not.toHaveBeenCalled()
    expect(screen.getByRole('switch')).toHaveAttribute('aria-checked', 'true')
  })

  it('is read-only when disabled', async () => {
    await i18n.changeLanguage('zh-CN')
    renderWithProviders(<CacheStatusHeaderSwitch detail={site(false)} accessToken="t" disabled onSaved={() => undefined} />)
    const toggle = screen.getByRole('switch')
    expect(toggle).toBeDisabled()
    expect(toggle).toHaveAttribute('aria-checked', 'false')
  })
})
