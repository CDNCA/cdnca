import { screen, waitFor } from '@testing-library/react'
import { vi } from 'vitest'

import { registrationAvailable } from '../api/registrationAvailability'
import { LoginPage } from '../pages/LoginPage'
import { renderWithProviders } from '../test/render'

// The sign-up link follows the server's
// registration_enabled; closed or unknown means no link.
describe('sign-in page sign-up link', () => {
  it('hides the link when registration is closed', async () => {
    vi.mocked(registrationAvailable).mockResolvedValue(false)
    renderWithProviders(<LoginPage />, ['/login'])
    await waitFor(() => expect(registrationAvailable).toHaveBeenCalled())
    expect(screen.getByRole('link', { name: '忘记密码？' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '注册账号' })).not.toBeInTheDocument()
  })

  it('shows the link when registration is open', async () => {
    vi.mocked(registrationAvailable).mockResolvedValue(true)
    renderWithProviders(<LoginPage />, ['/login'])
    expect(await screen.findByRole('link', { name: '注册账号' })).toHaveAttribute('href', '/register')
  })
})
