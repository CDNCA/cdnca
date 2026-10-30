import { act, fireEvent, screen } from '@testing-library/react'
import { Result } from 'antd'
import { Route, Routes, useLocation } from 'react-router-dom'
import { vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { AppShell } from '../components/AppShell'
import { defaultThemeLayout, ThemeRuntimeContext } from '../theme/runtime'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { defaultLookCSS } from '../test/defaultLookCSS'

const styles = defaultLookCSS(Object.values(import.meta.glob('../styles.css', {
  eager: true,
  import: 'default',
  query: '?raw',
}))[0] as string)

type ShellRoute = '/home' | '/site/url-auth' | '/site/list'

const shellRoutes: Array<{ path: ShellRoute; content: React.ReactNode }> = [
  { path: '/home', content: <section aria-label="home-responsive-probe" /> },
  {
    path: '/site/url-auth',
    content: <Result status="403" title="403" subTitle="forbidden-responsive-probe" />,
  },
  {
    path: '/site/list',
    content: (
      <div className="site-table-scroll" data-testid="site-table-scroll">
        <div style={{ minWidth: 1_200 }}>wide-table-responsive-probe</div>
      </div>
    ),
  },
]

function installMatchMedia(initialMatches: boolean) {
  let matches = initialMatches
  const listeners = new Set<EventListenerOrEventListenerObject>()
  const media = {
    get matches() {
      return matches
    },
    media: '(max-width: 767px)',
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: (_type: string, listener: EventListenerOrEventListenerObject) => {
      listeners.add(listener)
    },
    removeEventListener: (_type: string, listener: EventListenerOrEventListenerObject) => {
      listeners.delete(listener)
    },
    dispatchEvent: () => false,
  } as unknown as MediaQueryList

  vi.spyOn(window, 'matchMedia').mockImplementation(() => media)

  return {
    setMatches(next: boolean) {
      matches = next
      const event = { matches, media: media.media } as MediaQueryListEvent
      listeners.forEach((listener) => {
        if (typeof listener === 'function') listener.call(media, event)
        else listener.handleEvent(event)
      })
    },
  }
}

function stylesheetRules() {
  const style = document.createElement('style')
  style.textContent = styles
  document.head.append(style)
  const rules = [...(style.sheet?.cssRules ?? [])]
  style.remove()
  return rules
}

function styleRule(rules: CSSRule[], selector: string) {
  const normalizedSelector = (value: string) => value.split(',').map((part) => part.trim()).join(', ')
  const rule = rules.find((candidate) => {
    const candidateSelector = (candidate as CSSStyleRule).selectorText
    return typeof candidateSelector === 'string' && normalizedSelector(candidateSelector) === selector
  }) as CSSStyleRule | undefined
  expect(rule, `missing CSS rule ${selector}`).toBeDefined()
  return rule as CSSStyleRule
}

function mobileRules(rules: CSSRule[]) {
  const mediaRules = rules
    .filter((candidate): candidate is CSSMediaRule => 'conditionText' in candidate && candidate.conditionText === '(max-width: 767px)')
    .flatMap((media) => [...media.cssRules])
  expect(mediaRules.length, 'missing mobile application-shell media query').toBeGreaterThan(0)
  return mediaRules
}

function renderShell(path: ShellRoute, content: React.ReactNode, brandAssets?: { logo?: number; favicon?: number }) {
  const routes = (
    <Routes>
      <Route element={<AppShell />}>
        <Route path={path} element={content} />
      </Route>
    </Routes>
  )
  return renderWithProviders(
    brandAssets ? <ThemeRuntimeContext.Provider value={{ document: null, layout: defaultThemeLayout, scope: 'platform', brandAssets }}>{routes}</ThemeRuntimeContext.Provider> : routes,
    [path],
  )
}

function ShellLocationProbe() {
  const location = useLocation()
  return <output data-testid="shell-location">{location.pathname}</output>
}

describe('responsive application shell', () => {
  it('locks the observed 256px desktop shell, 44px menu and 64px header geometry', () => {
    const rules = stylesheetRules()
    const sidebar = styleRule(rules, '.app-sidebar')
    const brand = styleRule(rules, '.shell-brand')
    const brandCrop = styleRule(rules, '.shell-brand-crop')
    const brandImage = styleRule(rules, '.shell-brand img')
    const menu = styleRule(rules, '.shell-menu')
    const menuRows = styleRule(rules, '.shell-menu.ant-menu-inline > .ant-menu-item, .shell-menu.ant-menu-inline > .ant-menu-submenu > .ant-menu-submenu-title')
    const selectedMenuRow = styleRule(rules, '.shell-menu.ant-menu-inline .ant-menu-item-selected')
    const selectedMenuIndicator = styleRule(rules, '.shell-menu.ant-menu-inline .ant-menu-item-selected::before')
    const selectedTopLevelRow = styleRule(rules, '.shell-menu.ant-menu-inline > .ant-menu-item-selected')
    const submenuRow = styleRule(rules, '.shell-menu .ant-menu-submenu .ant-menu-item')
    const selectedSubmenuRow = styleRule(rules, '.shell-menu .ant-menu-submenu .ant-menu-item-selected')
    const menuIcon = styleRule(rules, '.shell-menu.ant-menu .shell-nav-icon.ant-menu-item-icon')
    const header = styleRule(rules, '.app-header')
    const headerButton = styleRule(rules, '.header-icon-button')
    const breadcrumb = styleRule(rules, '.shell-breadcrumb')
    const account = styleRule(rules, '.account-trigger')
    const headerBrand = styleRule(rules, '.mobile-header-brand')
    const main = styleRule(rules, '.app-main')

    expect(sidebar.style.getPropertyValue('z-index')).toBe('20')
    expect(sidebar.style.getPropertyValue('box-shadow')).toBe('1px 0 0 #edf1f6')
    expect(brand.style.getPropertyValue('width')).toBe('100%')
    expect(brand.style.getPropertyValue('justify-content')).toBe('center')
    expect(brandCrop.style.getPropertyValue('width')).toBe('160.234375px')
    expect(brandCrop.style.getPropertyValue('height')).toBe('51.1875px')
    expect(brandCrop.style.getPropertyValue('margin-left')).toBe('0')
    expect(brandImage.style.getPropertyValue('width')).toBe('160.234375px')
    expect(brandImage.style.getPropertyValue('height')).toBe('51.1875px')
    expect(menu.style.getPropertyValue('padding')).toBe('8px 10px 14px')
    // Only the menu scrolls: a scrollable sidebar too showed two side-by-side scrollbars.
    expect(sidebar.style.getPropertyValue('display')).toBe('flex')
    expect(sidebar.style.getPropertyValue('flex-direction')).toBe('column')
    expect(sidebar.style.getPropertyValue('overflow-y')).toBe('hidden')
    expect(menu.style.getPropertyValue('overflow-y')).toBe('auto')
    expect(menu.style.getPropertyValue('min-height')).toBe('0')
    expect(menu.style.getPropertyValue('height')).toBe('')
    expect(menuRows.style.getPropertyValue('height')).toBe('44px')
    expect(menuRows.style.getPropertyValue('margin')).toBe('2px 0px')
    expect(menuRows.style.getPropertyValue('padding-inline')).toBe('14px')
    expect(menuRows.style.getPropertyValue('font-size')).toBe('15px')
    expect(menuRows.style.getPropertyValue('font-weight')).toBe('500')
    expect(menuRows.style.getPropertyValue('border-radius')).toBe('8px')
    expect(selectedMenuRow.style.getPropertyValue('background')).toMatch(/45.*140.*240/)
    expect(selectedMenuRow.style.getPropertyValue('box-shadow')).toBe('inset 3px 0 0 var(--cdnca-color-primary)')
    expect(selectedMenuRow.style.getPropertyValue('font-weight')).toBe('600')
    expect(selectedMenuIndicator.style.getPropertyValue('display')).toBe('none')
    expect(selectedTopLevelRow.style.getPropertyValue('border-radius')).toBe('0px 8px 8px 0px')
    expect(submenuRow.style.getPropertyValue('height')).toBe('36px')
    expect(submenuRow.style.getPropertyValue('margin')).toBe('2px 4px 2px 22px')
    expect(submenuRow.style.getPropertyValue('padding-inline')).toBe('28px 12px')
    expect(submenuRow.style.getPropertyValue('border-radius')).toBe('8px')
    expect(submenuRow.style.getPropertyValue('font-weight')).toBe('400')
    expect(selectedSubmenuRow.style.getPropertyValue('border-radius')).toBe('0px 8px 8px 0px')
    expect(selectedSubmenuRow.style.getPropertyValue('background')).toMatch(/45.*140.*240/)
    expect(selectedSubmenuRow.style.getPropertyValue('font-weight')).toBe('500')
    expect(menuIcon.style.getPropertyValue('font-size')).toBe('16px')
    expect(header.style.getPropertyValue('z-index')).toBe('15')
    expect(header.style.getPropertyValue('left')).toBe('0')
    expect(header.style.getPropertyValue('height')).toBe('64px')
    expect(header.style.getPropertyValue('padding-left')).toBe('var(--sidebar-width)')
    expect(header.style.getPropertyValue('box-shadow')).toBe('none')
    expect(headerButton.style.getPropertyValue('margin')).toBe('12px 4px')
    expect(headerButton.style.getPropertyValue('border-radius')).toBe('8px')
    expect(breadcrumb.style.getPropertyValue('margin-left')).toBe('6px')
    expect(breadcrumb.style.getPropertyValue('line-height')).toBe('64px')
    expect(account.style.getPropertyValue('width')).toBe('60px')
    expect(account.style.getPropertyValue('margin')).toBe('12px 14px 12px 0')
    expect(account.style.getPropertyValue('background')).toBe('transparent')
    expect(account.style.getPropertyValue('border-radius')).toBe('8px')
    expect(headerBrand.style.getPropertyValue('display')).toBe('none')
    expect(main.style.getPropertyValue('padding-left')).toBe('var(--sidebar-width)')
    expect(main.style.getPropertyValue('background-color')).toBe('var(--cdnca-color-bg-page)')
    expect(main.style.getPropertyValue('background-image')).toBe('linear-gradient(135deg, #eaf1fb, #eef0f5)')
    expect(main.style.getPropertyValue('background-attachment')).toBe('fixed')
    expect(Number(sidebar.style.getPropertyValue('z-index'))).toBeGreaterThan(Number(header.style.getPropertyValue('z-index')))
  })

  it('matches the reference mobile header with menu and neutral account affordances only', () => {
    const mobile = mobileRules(stylesheetRules())
    const sidebar = styleRule(mobile, '.app-sidebar')
    const mobileBrand = styleRule(mobile, '.mobile-header-brand')
    const firstHeaderButton = styleRule(mobile, '.header-icon-button:first-of-type')
    const account = styleRule(mobile, '.account-trigger')

    expect(sidebar.style.getPropertyValue('width')).toBe('min(80vw, 320px)')
    expect(mobileBrand.style.getPropertyValue('display')).toBe('none')
    expect(firstHeaderButton.style.getPropertyValue('margin-left')).toBe('4px')
    expect(account.style.getPropertyValue('width')).toBe('44px')
    expect(account.style.getPropertyValue('margin')).toBe('12px 14px 12px 0')
  })

  it('exposes the observed theme toggle without adding a locale control', async () => {
    installMatchMedia(false)
    await i18n.changeLanguage('zh-CN')
    const actor = principal({ permissions: ['identity.self.read', 'sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const rendered = renderShell('/home', <section aria-label="theme-responsive-probe" />)

    expect(screen.queryByRole('button', { name: i18n.t('common:languageMenu') })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: i18n.t('common:switchToDarkTheme') })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: i18n.t('common:switchToLightTheme') })).not.toBeInTheDocument()
    rendered.unmount()
  })

  it('uses the public platform logo asset and falls back to the bundled logo when no asset is bound', async () => {
    installMatchMedia(false)
    const actor = principal({ permissions: ['identity.self.read', 'sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    renderShell('/home', <section aria-label="brand-asset-responsive-probe" />, { logo: 2 })

    const logos = screen.getAllByAltText('cdnca')
    expect(logos).toHaveLength(2)
    logos.forEach((logo) => expect(logo).toHaveAttribute('src', '/v1/brand-assets/logo?v=2'))

    await act(async () => { fireEvent.error(logos[0]) })
    expect(logos[0]).toHaveAttribute('src', '/dashboard/logo.png')
  })

  it('uses the dark logo on the dark chrome of dark mode (fix-brandkit)', () => {
    installMatchMedia(false)
    window.localStorage.setItem('cdnca.ui.theme', 'dark')
    try {
      const actor = principal({ permissions: ['identity.self.read', 'sites.read'] })
      useSessionStore.getState().setSession(authResponse(actor), actor)
      renderShell('/home', <section aria-label="dark-logo-probe" />)
      const logos = screen.getAllByAltText('cdnca')
      expect(logos).toHaveLength(2)
      logos.forEach((logo) => expect(logo).toHaveAttribute('src', '/dashboard/logo-dark.png'))
    } finally {
      window.localStorage.removeItem('cdnca.ui.theme')
    }
  })

  it('keeps the header brand actionable and routes to the principal overview', async () => {
    installMatchMedia(false)
    await i18n.changeLanguage('zh-CN')
    const actor = principal({ permissions: ['identity.self.read', 'sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const rendered = renderWithProviders(
      <Routes>
        <Route element={<AppShell />}>
          <Route path="/site/list" element={<><ShellLocationProbe /><section aria-label="site-list-probe" /></>} />
          <Route path="/home" element={<><ShellLocationProbe /><section aria-label="home-probe" /></>} />
        </Route>
      </Routes>,
      ['/site/list'],
    )

    const brand = rendered.container.querySelector<HTMLButtonElement>('.shell-brand')
    expect(brand).not.toBeNull()
    expect(brand).toHaveAttribute('aria-label', i18n.t('common:returnOverview'))
    fireEvent.click(brand as HTMLButtonElement)
    expect(screen.getByTestId('shell-location')).toHaveTextContent('/home')
    rendered.unmount()
  })

  it('uses the public favicon asset and falls back to the bundled favicon', () => {
    installMatchMedia(false)
    const actor = principal({ permissions: ['identity.self.read', 'sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const staticFavicon = document.createElement('link')
    staticFavicon.rel = 'icon'
    staticFavicon.href = '/dashboard/favicon.png'
    document.head.append(staticFavicon)

    const rendered = renderShell('/home', <section aria-label="favicon-responsive-probe" />, { favicon: 4 })
    expect(staticFavicon).toHaveAttribute('href', '/dashboard/favicon.png')
    const probe = document.querySelector<HTMLImageElement>('img[data-cdnca-favicon-probe="true"]')
    expect(probe).not.toBeNull()
    // The uploaded slot's revision is the cache key.
    expect(probe).toHaveAttribute('src', '/v1/brand-assets/favicon?v=4')
    probe?.dispatchEvent(new Event('load'))
    expect(staticFavicon).toHaveAttribute('href', '/v1/brand-assets/favicon?v=4')
    probe?.dispatchEvent(new Event('error'))
    expect(staticFavicon).toHaveAttribute('href', '/dashboard/favicon.png')
    rendered.unmount()
    expect(document.head.contains(staticFavicon)).toBe(true)
    expect(staticFavicon).toHaveAttribute('href', '/dashboard/favicon.png')
    staticFavicon.remove()
  })

  it('removes layout transitions across desktop-to-390/320 while preserving the mobile drawer transform', () => {
    const rules = stylesheetRules()
    const mobile = mobileRules(rules)
    const hidesAllMobileDocumentScrollbars = rules
      .filter((rule): rule is CSSMediaRule => 'conditionText' in rule && rule.conditionText === '(max-width: 767px)')
      .flatMap((rule) => [...rule.cssRules])
      .some((rule) => (rule as CSSStyleRule).selectorText === 'html, body' && (rule as CSSStyleRule).style?.scrollbarWidth === 'none')
    const sidebar = styleRule(mobile, '.app-sidebar')
    const header = styleRule(mobile, '.app-header')
    const main = styleRule(mobile, '.app-main')
    const root = styleRule(mobile, 'html, body, #root')

    expect(hidesAllMobileDocumentScrollbars).toBe(false)

    for (const { path } of shellRoutes) {
      for (const width of [390, 320]) {
        for (const phase of ['first-frame', '50ms', 'stable']) {
          const context = `${path} at ${width}px ${phase}`
          expect(root.style.getPropertyValue('min-width'), context).toBe('0')
          expect(root.style.getPropertyValue('height'), context).toBe('100%')
          expect(sidebar.style.getPropertyValue('transition'), context).toBe('transform 160ms ease')
          expect(header.style.getPropertyValue('transition'), context).toBe('none')
          expect(main.style.getPropertyValue('transition'), context).toBe('none')
        }
      }
    }
  })

  it.each(shellRoutes)('keeps $path inside the shared shell while the mobile drawer opens and closes', async ({ path, content }) => {
    const media = installMatchMedia(false)
    await i18n.changeLanguage('qps-ploc')
    const actor = principal({ permissions: ['identity.self.read', 'sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const rendered = renderShell(path, content)

    act(() => media.setMatches(true))

    const open = screen.getByRole('button', { name: i18n.t('common:openNavigation') })
    fireEvent.click(open)
    expect(rendered.container.querySelector('.app-sidebar')).toHaveClass('is-mobile-open')
    expect(document.body).toHaveStyle({ overflow: 'hidden' })

    fireEvent.click(screen.getByRole('button', { name: i18n.t('common:closeNavigation') }))
    expect(rendered.container.querySelector('.app-sidebar')).not.toHaveClass('is-mobile-open')
    expect(document.body.style.overflow).toBe('')
    rendered.unmount()
  })

  // 顶部条只显示当前页面标题，父级路径不出现在可见文本里。
  it('renders only the page title in the header trail while keeping the full path for assistive tech', async () => {
    await i18n.changeLanguage('qps-ploc')
    const actor = principal({ permissions: ['identity.self.read', 'sites.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const rendered = renderShell('/site/list', <div className="site-table-scroll" />)

    const trail = rendered.container.querySelector('.shell-breadcrumb')
    expect(trail).not.toBeNull()

    const current = trail?.querySelector('.shell-breadcrumb-current')
    expect(current).toHaveTextContent(i18n.t('navigation:siteList'))

    for (const class_ of ['shell-breadcrumb-parent', 'shell-breadcrumb-current-fallback', 'breadcrumb-divider']) {
      expect(rendered.container.querySelector(`.${class_}`)).toBeNull()
    }

    const a11y = trail?.querySelector('.shell-breadcrumb-a11y')
    expect(a11y?.textContent).toContain(i18n.t('navigation:home'))
    expect(a11y?.textContent).toContain(i18n.t('navigation:sites'))
    expect(a11y?.textContent).toContain(i18n.t('navigation:siteList'))

    rendered.unmount()
  })

  it('keeps the wide site table as the horizontal scroll owner', () => {
    const rules = stylesheetRules()
    const table = styleRule(rules, '.site-table-scroll')
    const shell = styleRule(rules, '.app-shell')
    const main = styleRule(rules, '.app-main')

    // fix-dblscroll：横滚归 antd Table（scroll.x → .ant-table-content），包装层不滚。
    expect(table.style.getPropertyValue('overflow-x')).toBe('')
    expect(shell.style.getPropertyValue('overflow-x')).not.toBe('clip')
    expect(shell.style.getPropertyValue('overflow-x')).not.toBe('hidden')
    expect(shell.style.getPropertyValue('min-height')).toBe('100vh')
    expect(main.style.getPropertyValue('min-height')).toBe('100vh')
    expect(main.style.getPropertyValue('flex')).toBe('')
  })
})

// C21：二级菜单只保留 ::before 一条选中标记；inset 竖条只给一级项（亮色主题、暗色同理）。
describe('selected menu mark (C21)', () => {
  it('keeps one mark per level in the themed light and dark shells', () => {
    const shellCSS = Object.values(import.meta.glob('../components/AppShell.css', { eager: true, import: 'default', query: '?raw' }))[0] as string
    const style = document.createElement('style')
    style.textContent = styles + shellCSS
    document.head.append(style)
    const rules = [...(style.sheet?.cssRules ?? [])] as CSSStyleRule[]
    style.remove()
    const insetSelectors = rules.filter((rule) => rule.style?.getPropertyValue('box-shadow').startsWith('inset 3px'))
      .flatMap((rule) => rule.selectorText.split(',').map((part) => part.trim()))
      .filter((selector) => selector.includes('ant-menu-item-selected') && !selector.includes('inline-collapsed'))
    for (const selector of insetSelectors) {
      // a bare descendant ".ant-menu-inline .ant-menu-item-selected" also hits submenu items
      if (selector === '.shell-menu.ant-menu-inline .ant-menu-item-selected') continue
      expect(selector, selector).toMatch(/\.ant-menu-inline > \.ant-menu-item-selected$/)
    }
    expect(styleRule(rules, '.app-shell.is-dark .shell-menu .ant-menu-submenu .ant-menu-item-selected').style.getPropertyValue('box-shadow')).toBe('none')
  })
})

