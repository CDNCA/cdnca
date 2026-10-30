import { screen } from '@testing-library/react'
import { vi } from 'vitest'

import { publicBranding } from '../api/publicBranding'
import { LoginPage } from '../pages/LoginPage'
import { renderWithProviders } from '../test/render'

// 登录页显示系统名称；主题设了名称以主题为准，否则用系统配置。
describe('sign-in page system name', () => {
  it('shows the system settings name when the theme sets none', async () => {
    vi.mocked(publicBranding).mockResolvedValue({ systemName: '云盾', userTitle: '云盾用户控制台', adminTitle: '云盾管理后台' })
    renderWithProviders(<LoginPage />, ['/login'])
    expect(await screen.findByRole('heading', { level: 1, name: '云盾' })).toBeInTheDocument()
  })

  it('keeps the built-in name when the anonymous read fails', async () => {
    vi.mocked(publicBranding).mockResolvedValue(null)
    renderWithProviders(<LoginPage />, ['/login'])
    expect(await screen.findByRole('heading', { level: 1, name: 'cdnca' })).toBeInTheDocument()
  })
})
