import { fireEvent, screen, waitFor } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { AppShell } from '../components/AppShell'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// the header navigation toggle and refresh button keep their visible
// Tooltip, but the Tooltip text (the same as the button name) is not also
// linked as the description, so a screen reader reads the name once.

function installMatchMedia(mobile: boolean) {
  vi.stubGlobal('innerWidth', mobile ? 390 : 1280)
  vi.spyOn(window, 'matchMedia').mockImplementation((query) => ({
    matches: query === '(max-width: 767px)' && mobile,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }))
}

function renderShell() {
  const actor = principal({ permissions: ['identity.self.read', 'sites.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  return renderWithProviders(
    <Routes>
      <Route element={<AppShell />}>
        <Route path="/home" element={<section aria-label="tooltip-name-probe" />} />
      </Route>
    </Routes>,
    ['/home'],
  )
}

async function expectTooltipWithoutDescription(button: HTMLElement, text: string) {
  fireEvent.mouseEnter(button)
  fireEvent.focus(button)
  // the visible Tooltip still shows (an earlier one may still be closing)
  await waitFor(() => expect(screen.getAllByRole('tooltip').map((tooltip) => tooltip.textContent)).toContain(text))
  expect(button).not.toHaveAttribute('aria-describedby')
  expect(button).toHaveAccessibleDescription('')
  expect(screen.getAllByRole('button', { name: text })).toHaveLength(1)
  fireEvent.mouseLeave(button)
  fireEvent.blur(button)
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('AppShell header tooltip names', () => {
  it('names the desktop navigation toggle by its state without a repeated description', async () => {
    installMatchMedia(false)
    await i18n.changeLanguage('zh-CN')
    renderShell()

    const toggle = screen.getByRole('button', { name: '折叠导航' })
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    await expectTooltipWithoutDescription(toggle, '折叠导航')

    fireEvent.click(toggle)
    expect(toggle).toHaveAccessibleName('展开导航')
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('button', { name: '折叠导航' })).toBeNull()
    await expectTooltipWithoutDescription(toggle, '展开导航')

    const refresh = screen.getByRole('button', { name: i18n.t('common:refreshSession') })
    await expectTooltipWithoutDescription(refresh, i18n.t('common:refreshSession'))
  })

  it('names the mobile navigation toggle and keeps aria-expanded in step with the drawer', async () => {
    installMatchMedia(true)
    await i18n.changeLanguage('zh-CN')
    renderShell()

    const toggle = screen.getByRole('button', { name: '打开导航' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    await expectTooltipWithoutDescription(toggle, '打开导航')

    fireEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(toggle).not.toHaveAttribute('aria-describedby')
  })
})
