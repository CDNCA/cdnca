import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import i18n, { localeStorageKey } from '../i18n'
import { LanguageMenu } from '../components/LanguageMenu'
import { renderWithProviders } from '../test/render'

describe('LanguageMenu', () => {
  it('switches the visible application locale and persists the selection', async () => {
    const user = userEvent.setup()
    renderWithProviders(<LanguageMenu />)

    await user.click(screen.getByRole('button', { name: '切换语言' }))
    await user.click(await screen.findByText('English'))

    await waitFor(() => expect(i18n.resolvedLanguage).toBe('en-US'))
    expect(document.documentElement.lang).toBe('en-US')
    expect(localStorage.getItem(localeStorageKey)).toBe('en-US')
    expect(screen.getByRole('button', { name: 'Change language' })).toBeInTheDocument()
    expect(screen.queryByText('Pseudo locale')).not.toBeInTheDocument()
  })

  it('switches to the real Traditional Chinese locale', async () => {
    const user = userEvent.setup()
    renderWithProviders(<LanguageMenu />)

    await user.click(screen.getByRole('button', { name: '切换语言' }))
    await user.click(await screen.findByText('繁體中文'))

    await waitFor(() => expect(i18n.resolvedLanguage).toBe('zh-TW'))
    expect(document.documentElement.lang).toBe('zh-TW')
    expect(localStorage.getItem(localeStorageKey)).toBe('zh-TW')
    expect(i18n.t('navigation:nodes')).toBe('節點管理')
  })
})
