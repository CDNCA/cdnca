import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { AppRoutes } from '../App'
import { ApiError } from '../api/auth'
import { mfaApi } from '../api/mfa'
import { usersApi, type AccountProfile } from '../api/users'
import { useSessionStore } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import AccountUserPage from '../pages/AccountUserPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const profile: AccountProfile = {
  id: '11111111-1111-4111-8111-111111111111',
  username: 'jason',
  display_name: 'Jason',
  email: 'jason@example.com',
  phone: null,
  revision: 1,
  created_at: '2026-07-22T08:00:00Z',
  updated_at: '2026-07-22T08:00:00Z',
}

function authenticate() {
  const user = principal({
    display_name: 'Jason',
    permissions: ['identity.self.read', 'identity.self.update', 'identity.password.change'],
  })
  useSessionStore.getState().setSession(authResponse(user), user)
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('AccountUserPage internationalization', () => {
  it('keeps the complete qps-ploc loading, error, retry, and permission surface local', async () => {
    await changeLocale('qps-ploc')
    const t = i18n.getFixedT('qps-ploc', 'accountProfile')
    authenticate()
    let rejectInitial!: (reason: unknown) => void
    const initialRead = new Promise<AccountProfile>((_, reject) => { rejectInitial = reject })
    const profileRead = vi.spyOn(usersApi, 'profile')
      .mockImplementationOnce(() => initialRead)
      .mockResolvedValueOnce(profile)
    vi.spyOn(mfaApi, 'getStatus').mockResolvedValue({ status: 'inactive' })
    const user = userEvent.setup()

    const recoveryView = renderWithProviders(<AccountUserPage />, ['/account/user'])

    expect(screen.getByLabelText(t('loading'))).toHaveClass('account-profile-loading')
    await act(async () => {
      rejectInitial(new ApiError('private profile replica hostname', 503, 'profile_store_unavailable'))
      await initialRead.catch(() => undefined)
    })
    expect(await screen.findByText(t('errors.profileLoadFailed'))).toBeInTheDocument()
    expect(screen.getByText(t('errors.request_failed'))).toBeInTheDocument()
    expect(screen.queryByText('private profile replica hostname')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: t('actions.retry') }))
    expect(await screen.findByText(profile.username)).toBeInTheDocument()
    expect(profileRead).toHaveBeenCalledTimes(2)
    expect(screen.getByRole('heading', { name: t('title') })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: t('profile.sectionTitle') })).toBeInTheDocument()
    expect(screen.getByText(t('profile.username'))).toBeInTheDocument()
    expect(screen.getByRole('button', { name: t('profile.compatibility.emailRebind') })).toBeEnabled()
    expect(screen.getByRole('button', { name: t('actions.changePassword') })).toBeEnabled()
    expect(screen.queryByText(t('errors.profileLoadFailed'))).not.toBeInTheDocument()
    recoveryView.unmount()

    vi.restoreAllMocks()
    authenticate()
    const forbiddenProfile = vi.spyOn(usersApi, 'profile').mockRejectedValue(
      new ApiError('private profile permission policy', 403, 'permission_denied'),
    )
    const forbiddenMfa = vi.spyOn(mfaApi, 'getStatus').mockResolvedValue({ status: 'inactive' })
    const forbiddenFetch = vi.spyOn(globalThis, 'fetch')
    const apiForbiddenView = renderWithProviders(<AccountUserPage />, ['/account/user'])

    expect(await screen.findByText(t('errors.forbiddenTitle'))).toBeInTheDocument()
    expect(screen.getByText(t('errors.permission_denied'))).toBeInTheDocument()
    expect(screen.queryByText('private profile permission policy')).not.toBeInTheDocument()
    expect(forbiddenProfile).toHaveBeenCalledOnce()
    expect(forbiddenMfa).not.toHaveBeenCalled()
    expect(forbiddenFetch).not.toHaveBeenCalled()
    apiForbiddenView.unmount()

    vi.restoreAllMocks()
    const noReadPrincipal = principal({
      permissions: ['identity.self.update', 'identity.password.change'],
    })
    useSessionStore.getState().setSession(authResponse(noReadPrincipal), noReadPrincipal)
    const localProfile = vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    const localMfa = vi.spyOn(mfaApi, 'getStatus').mockResolvedValue({ status: 'inactive' })
    const localFetch = vi.spyOn(globalThis, 'fetch')

    renderWithProviders(<AccountUserPage />, ['/account/user'])

    expect(await screen.findByText(t('errors.forbiddenTitle'))).toBeInTheDocument()
    expect(screen.getByText(t('errors.permission_denied'))).toBeInTheDocument()
    expect(localProfile).not.toHaveBeenCalled()
    expect(localMfa).not.toHaveBeenCalled()
    expect(localFetch).not.toHaveBeenCalled()
  })

  it('opens the password form and localizes its validation in English', async () => {
    await changeLocale('en-US')
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => (
      String(url) === '/v1/account/mfa' ? json({ status: 'inactive' }) : json(profile)
    ))
    const user = userEvent.setup()
    renderWithProviders(<AccountUserPage />, ['/account/user'])

    expect(await screen.findByRole('heading', { name: 'Profile' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Security settings' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Change password' }))
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByText('Enter your current password')).toBeInTheDocument()
    await user.type(screen.getByLabelText('Current password'), 'current-password')
    await user.type(screen.getByLabelText('New password'), 'short')
    await user.type(screen.getByLabelText('Confirm password'), 'different-password')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByText('The password must contain 8–1024 characters')).toBeInTheDocument()
    expect(screen.getByText('The new passwords do not match')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PATCH' || init?.method === 'POST')).toBe(false)
  })

  it('localizes profile load and permission failures without server message leakage', async () => {
    await changeLocale('en-US')
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({
      error: { code: 'profile_store_unavailable', message: 'internal replica hostname' },
    }, 503))
    const first = renderWithProviders(<AccountUserPage />, ['/account/user'])
    expect(await screen.findByText('Failed to load the profile')).toBeInTheDocument()
    expect(screen.getByText('Request failed. Try again later.')).toBeInTheDocument()
    expect(screen.queryByText('internal replica hostname')).not.toBeInTheDocument()
    first.unmount()

    vi.restoreAllMocks()
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'permission_denied', message: 'internal permission name' },
    }, 403))
    renderWithProviders(<AccountUserPage />, ['/account/user'])
    expect(await screen.findByText('You cannot view the profile')).toBeInTheDocument()
    expect(screen.getByText('Your account does not have profile permission')).toBeInTheDocument()
    expect(screen.queryByText('internal permission name')).not.toBeInTheDocument()
  })

  it.each([
    ['HTTP 429', new ApiError('private limiter bucket', 429, 'request_failed')],
    ['explicit rate limit', new ApiError('private limiter shard', 503, 'rate_limited')],
  ])('treats a %s password failure as a localized terminal result', async (_case, failure) => {
    await changeLocale('en-US')
    const t = i18n.getFixedT('en-US', 'accountProfile')
    authenticate()
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    vi.spyOn(mfaApi, 'getStatus').mockResolvedValue({ status: 'inactive' })
    const changePassword = vi.spyOn(usersApi, 'changePassword').mockRejectedValue(failure)
    const user = userEvent.setup()
    renderWithProviders(<AccountUserPage />, ['/account/user'])

    await user.click(await screen.findByRole('button', { name: t('actions.changePassword') }))
    await user.type(screen.getByLabelText(t('password.current')), 'current-password')
    await user.type(screen.getByLabelText(t('password.new')), 'new-password-123')
    await user.type(screen.getByLabelText(t('password.confirm')), 'new-password-123')
    await user.click(screen.getByRole('button', { name: t('profile.compatibility.bindForm.submit') }))

    expect(await screen.findByText(t('errors.rate_limited'))).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(/private limiter/)
    expect(screen.getByLabelText(t('password.new'))).toBeEnabled()
    expect(changePassword).toHaveBeenCalledOnce()
  })

  it('maps password errors locally and still invalidates the old session after success', async () => {
    await changeLocale('en-US')
    authenticate()
    let posts = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      if (String(input) === '/v1/account/password' && init?.method === 'POST') {
        posts += 1
        if (posts === 1) {
          return Promise.resolve(json({
            error: { code: 'invalid_credentials', message: 'internal password hash detail' },
          }, 401))
        }
        return Promise.resolve(new Response(null, { status: 204 }))
      }
      if (String(input) === '/v1/account/mfa') return Promise.resolve(json({ status: 'inactive' }))
      return Promise.resolve(json(profile))
    })
    const user = userEvent.setup()
    renderWithProviders(<AppRoutes />, ['/account/user'])
    await user.click(await screen.findByRole('button', { name: 'Change password' }))

    await user.type(screen.getByLabelText('Current password'), 'current-password')
    await user.type(screen.getByLabelText('New password'), 'new-password-123')
    await user.type(screen.getByLabelText('Confirm password'), 'new-password-123')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByText('The current password is incorrect')).toBeInTheDocument()
    expect(screen.queryByText('internal password hash detail')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Current password')).toHaveValue('')

    await user.type(screen.getByLabelText('Current password'), 'current-password')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByText('Password changed. Please sign in again.')).toBeInTheDocument()
    expect(useSessionStore.getState()).toMatchObject({ status: 'anonymous', principal: null, accessToken: null })
  })

  it('keeps contact reauthentication operable at 390px in the pseudo locale', async () => {
    await changeLocale('qps-ploc')
    const t = i18n.getFixedT('qps-ploc', 'accountProfile')
    authenticate()
    vi.spyOn(usersApi, 'profile').mockResolvedValue(profile)
    const bindContact = vi.spyOn(usersApi, 'bindContact').mockResolvedValue({
      ...profile,
      email: 'narrow@example.com',
      revision: 2,
    })
    vi.spyOn(mfaApi, 'getStatus').mockResolvedValue({ status: 'inactive' })
    const previousWidth = window.innerWidth
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    window.dispatchEvent(new Event('resize'))
    const user = userEvent.setup()

    renderWithProviders(<AccountUserPage />, ['/account/user'])
    await user.click(await screen.findByRole('button', { name: t('profile.compatibility.emailRebind') }))
    const bindForm = within(document.querySelector('.account-user-bind-form') as HTMLElement)
    await user.type(bindForm.getByLabelText(t('profile.compatibility.emailBinding')), 'narrow@example.com')
    const currentPassword = bindForm.getByLabelText(t('password.current'))
    expect(currentPassword).toBeEnabled()
    await user.type(currentPassword, 'narrow-profile-password')
    const submit = bindForm.getByRole('button', { name: t('profile.compatibility.bindForm.submit') })
    expect(submit).toBeEnabled()
    await user.click(submit)

    await waitFor(() => expect(bindContact).toHaveBeenCalledOnce())
    expect(bindContact.mock.calls[0][1]).toEqual(expect.objectContaining({
      email: 'narrow@example.com',
      current_password: 'narrow-profile-password',
    }))
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: previousWidth })
    window.dispatchEvent(new Event('resize'))
  })
})
