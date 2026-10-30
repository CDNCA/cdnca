import { fireEvent, screen } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { afterEach, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { AppShell } from '../components/AppShell'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const styles = Object.values(import.meta.glob('../styles.css', {
  eager: true,
  import: 'default',
  query: '?raw',
}))[0] as string

function stylesheetRules() {
  const style = document.createElement('style')
  style.textContent = styles
  document.head.append(style)
  const rules = [...(style.sheet?.cssRules ?? [])]
  style.remove()
  return rules
}

function mobileStyleRules() {
  return stylesheetRules()
    .filter((rule): rule is CSSMediaRule => 'conditionText' in rule && rule.conditionText === '(max-width: 767px)')
    .flatMap((rule) => [...rule.cssRules])
    .filter((rule): rule is CSSStyleRule => 'selectorText' in rule)
}

function installMobileMatchMedia(width = 390) {
  vi.stubGlobal('innerWidth', width)
  vi.spyOn(window, 'matchMedia').mockImplementation((query) => ({
    matches: query === '(max-width: 767px)' && width <= 767,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }))
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('AppShell mobile navigation trigger', () => {
  it('keeps header icon actions visible outside the mobile media query', () => {
    const desktopRule = stylesheetRules()
      .filter((rule): rule is CSSStyleRule => 'selectorText' in rule)
      .find((rule) => rule.selectorText.split(',').map((selector) => selector.trim()).includes('.header-icon-button'))

    expect(desktopRule?.style.getPropertyValue('display')).toBe('grid')
  })

  it('hides the refresh action with a semantic selector instead of button position', () => {
    const mobileRules = mobileStyleRules()
    const positionalRule = mobileRules.find(
      (rule) => rule.selectorText.includes('.header-icon-button') && rule.selectorText.includes('nth-of-type'),
    )
    const refreshRule = mobileRules.find(
      (rule) => rule.selectorText === '.header-icon-button:has(> .lucide-rotate-cw)',
    )

    expect(positionalRule).toBeUndefined()
    expect(refreshRule?.style.getPropertyValue('display')).toBe('none')
  })

  it('keeps the menu action operable at the mobile breakpoint', async () => {
    installMobileMatchMedia()
    await i18n.changeLanguage('zh-CN')
    const actor = principal({ permissions: ['identity.self.read', 'sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const rendered = renderWithProviders(
      <Routes>
        <Route element={<AppShell />}>
          <Route path="/home" element={<section aria-label="mobile-shell-probe" />} />
        </Route>
      </Routes>,
      ['/home'],
    )

    const menuAction = screen.getByRole('button', { name: i18n.t('common:openNavigation') })
    const refreshAction = screen.getByRole('button', { name: i18n.t('common:refreshSession') })

    expect(window.innerWidth).toBe(390)
    expect(menuAction.querySelector('svg')).not.toBeNull()
    expect(menuAction.matches('.header-icon-button:has(> .lucide-rotate-cw)')).toBe(false)
    expect(refreshAction.matches('.header-icon-button:has(> .lucide-rotate-cw)')).toBe(true)

    fireEvent.click(menuAction)
    expect(rendered.container.querySelector('.app-sidebar')).toHaveClass('is-mobile-open')
  })
})
