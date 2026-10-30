import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../../api/auth'
import { siteTrafficLimitApi, type SiteTrafficLimitState } from '../../api/siteTrafficLimit'
import i18n from '../../i18n'
import { renderWithProviders } from '../../test/render'
import { SiteTrafficLimitCard } from './SiteTrafficLimitCard'

// fix-siteinstant：网站流量上限改动即生效，没有保存按钮。
vi.mock('../../api/siteTrafficLimit', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/siteTrafficLimit')>()
  return { ...actual, siteTrafficLimitApi: { get: vi.fn(), put: vi.fn() } }
})

const siteId = '11111111-1111-4111-8111-111111111111'
const gib = 1024 ** 3

function state(overrides: Partial<SiteTrafficLimitState> = {}): SiteTrafficLimitState {
  return {
    site_id: siteId, version: 3, exceeded_period: '', exceeded_at: null, evaluated_at: null, total_since: null,
    setting: { enabled: true, daily_bytes: 10 * gib, monthly_bytes: null, total_bytes: null, time_zone: 'Asia/Shanghai', notice_html: '' },
    ...overrides,
  } as SiteTrafficLimitState
}

describe('SiteTrafficLimitCard 改动即生效', () => {
  beforeEach(async () => {
    vi.mocked(siteTrafficLimitApi.get).mockReset().mockResolvedValue(state())
    vi.mocked(siteTrafficLimitApi.put).mockReset().mockImplementation(async (_token, _site, version, setting) =>
      state({ version: version + 1, setting }))
    await i18n.changeLanguage('zh-CN')
  })

  it('has no save button; a switch change saves at once and shows 操作成功', async () => {
    renderWithProviders(<SiteTrafficLimitCard siteId={siteId} accessToken="token" canManage />)
    const toggle = await screen.findByRole('switch', { name: '启用' })
    expect(screen.queryByRole('button', { name: /保\s*存/u })).toBeNull()
    await userEvent.click(toggle)
    await waitFor(() => expect(siteTrafficLimitApi.put).toHaveBeenCalledTimes(1))
    expect(vi.mocked(siteTrafficLimitApi.put).mock.calls[0]![3]).toMatchObject({ enabled: false })
    expect(await screen.findByText('操作成功')).toBeTruthy()
  })

  it('a number saves on blur, not on every keystroke', async () => {
    renderWithProviders(<SiteTrafficLimitCard siteId={siteId} accessToken="token" canManage />)
    const monthly = await screen.findByRole('spinbutton', { name: '每月上限 (GB)' })
    await userEvent.type(monthly, '100')
    expect(siteTrafficLimitApi.put).not.toHaveBeenCalled()
    fireEvent.blur(monthly)
    await waitFor(() => expect(siteTrafficLimitApi.put).toHaveBeenCalledTimes(1))
    expect(vi.mocked(siteTrafficLimitApi.put).mock.calls[0]![3]).toMatchObject({ monthly_bytes: 100 * gib })
  })

  it('does not save an invalid value (no cap while on)', async () => {
    vi.mocked(siteTrafficLimitApi.get).mockResolvedValue(state({ setting: { enabled: false, daily_bytes: null, monthly_bytes: null,
      total_bytes: null, time_zone: 'Asia/Shanghai', notice_html: '' } }))
    renderWithProviders(<SiteTrafficLimitCard siteId={siteId} accessToken="token" canManage />)
    await userEvent.click(await screen.findByRole('switch', { name: '启用' }))
    expect(await screen.findByText(/至少/u)).toBeTruthy()
    expect(siteTrafficLimitApi.put).not.toHaveBeenCalled()
  })

  it('rolls the control back to the server value when the save fails', async () => {
    vi.mocked(siteTrafficLimitApi.put).mockRejectedValue(new ApiError('locked', 409, 'site_locked'))
    renderWithProviders(<SiteTrafficLimitCard siteId={siteId} accessToken="token" canManage />)
    const toggle = await screen.findByRole('switch', { name: '启用' })
    expect(toggle).toHaveAttribute('aria-checked', 'true')
    await userEvent.click(toggle)
    await waitFor(() => expect(siteTrafficLimitApi.put).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(toggle).toHaveAttribute('aria-checked', 'true'))
  })
})
